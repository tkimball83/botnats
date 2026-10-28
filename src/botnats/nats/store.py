# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""JetStream key-value stores for auth, channels, presence, and TOTP."""

import asyncio
import hmac
import json
import logging
import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from nats.errors import Error as NatsError
from nats.js.api import KeyValueConfig, StorageType
from nats.js.errors import (
    BadRequestError,
    KeyNotFoundError,
    KeyWrongLastSequenceError,
    NotFoundError,
)
from nats.js.kv import KV_DEL, KV_PURGE

from botnats import error_label
from botnats.irc.protocol import casefold
from botnats.nats.envelope import SIGNATURE_RE
from botnats.validators import IDENTIFIER_RE, parse_channel_record

if TYPE_CHECKING:
    from collections.abc import Callable

    from nats.js.client import JetStreamContext
    from nats.js.kv import KeyValue

    from botnats.validators import ChannelFields

LOGGER = logging.getLogger(__name__)


class StoreUnavailableError(Exception):
    """A durable write cannot proceed yet, though nothing is wrong with it.

    JetStream handles are reset or replaced while Core NATS reconnects, and a
    process writes only while it owns its bot ID's presence key.
    """


# Transport failures, and the error a store or presence claim raises when a
# write cannot proceed yet (store reconnecting, presence key not owned).
CONNECT_ERRORS = (NatsError, OSError)
PUBLISH_ERRORS = (*CONNECT_ERRORS, StoreUnavailableError)
DECODE_ERRORS = (RecursionError, TypeError, ValueError)

ATTEMPT_LIMIT = 3
ATTEMPT_TTL = 120.0
ATTEMPT_WINDOW = 60
CAS_ATTEMPT_LIMIT = 8
CLAIM_TTL = 300.0
DUPLICATE_WINDOW = 120.0
PRESENCE_DRIFT = 30.0
SESSION_EXPIRY_GRACE = 60.0


class KVStore:
    """Own a reconnectable file-backed JetStream key-value bucket."""

    def __init__(self, bucket: str, replicas: int, ttl: float) -> None:
        self.bucket = bucket
        self.js: JetStreamContext | None = None
        self.kv: KeyValue | None = None
        self.lock = asyncio.Lock()
        self.replicas = replicas
        self.ttl = ttl

    async def open(self, js: JetStreamContext | None = None) -> KeyValue:
        """Open or create the bucket."""
        async with self.lock:
            if js is not None and js is not self.js:
                self.js = js
                self.kv = None

            if self.kv is not None:
                return self.kv

            context = self.js
            if context is None:
                msg = "JetStream is unavailable"
                raise StoreUnavailableError(msg)

            config = KeyValueConfig(
                bucket=self.bucket,
                history=1,
                replicas=self.replicas,
                storage=StorageType.FILE,
                ttl=self.ttl,
            )
            try:
                kv = await context.create_key_value(config)
            except BadRequestError as error:
                # An earlier configuration may have created it with another TTL.
                try:
                    kv = await self.retune(context, config)
                except NotFoundError:
                    # No bucket to retune: report why creating it failed.
                    raise error from None

            if self.js is not context:
                msg = "JetStream changed while opening a bucket"
                raise StoreUnavailableError(msg)

            self.kv = kv
            return kv

    async def retune(
        self,
        context: JetStreamContext,
        config: KeyValueConfig,
    ) -> KeyValue:
        """Apply a changed TTL to an existing bucket, then create it again.

        Creating again succeeds only when nothing else differs; any other
        difference, such as the replica count, fails as it did the first time.
        """
        stream = (await context.stream_info(f"KV_{self.bucket}")).config
        if stream.max_age != self.ttl:
            # create_key_value's duplicate window, so creating again matches.
            window = min(DUPLICATE_WINDOW, self.ttl or DUPLICATE_WINDOW)
            await context.update_stream(
                stream.evolve(max_age=self.ttl, duplicate_window=window),
            )
            LOGGER.info("updated %s bucket TTL to %s seconds", self.bucket, self.ttl)

        return await context.create_key_value(config)

    @property
    def ready(self) -> bool:
        """Return whether the bucket is open."""
        return self.kv is not None

    def reset(self) -> None:
        """Discard handles tied to a disconnected NATS session."""
        self.js = None
        self.kv = None

    async def put_newer[T](
        self,
        key: str,
        data: dict[str, Any],
        written: T,
        standing: Callable[[dict[str, Any]], T | None],
    ) -> T:
        """Atomically store JSON unless the stored record stands; return the winner.

        standing parses the stored record and returns it when it outranks
        the write, or None when the write may replace it. Bounded like
        reclaim: repeatedly losing the CAS race against a handful of peers is
        transient, so exhaustion raises for the caller's retry path instead of
        spinning against the bucket.
        """
        kv = await self.open()
        encoded = json.dumps(data).encode()
        for _ in range(CAS_ATTEMPT_LIMIT):
            try:
                entry = await kv.get(key)
            except KeyNotFoundError:
                try:
                    await kv.create(key, encoded)
                except KeyWrongLastSequenceError:
                    continue

                return written

            current = decode_record(entry.value)
            winner = standing(current) if current is not None else None
            if winner is not None:
                return winner

            try:
                await kv.update(key, encoded, last=entry.revision)
            except KeyWrongLastSequenceError:
                continue

            return written

        msg = "durable write lost repeated update races"
        raise NatsError(msg)


class AttemptStore(KVStore):
    """Atomically limit authentication attempts across the bot mesh."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_auth_attempts", replicas, ATTEMPT_TTL)
        self.secret = secret

    async def allow(self, identity: str, *, now: float | None = None) -> bool:
        """Claim one attempt slot, failing closed when KV is unavailable."""
        current = time.time() if now is None else now
        cutoff = current - ATTEMPT_WINDOW
        encoded = float(current).hex().encode()
        try:
            kv = await self.open()
            for slot in range(ATTEMPT_LIMIT):
                key = self.key(identity, slot)
                try:
                    entry = await kv.get(key)
                except KeyNotFoundError:
                    try:
                        await kv.create(key, encoded)
                    except KeyWrongLastSequenceError:
                        continue

                    return True

                if entry.value is None:
                    continue

                try:
                    timestamp = float.fromhex(entry.value.decode())
                except OverflowError, ValueError:
                    continue

                if not math.isfinite(timestamp) or timestamp > cutoff:
                    continue

                try:
                    await kv.update(key, encoded, last=entry.revision)
                except KeyWrongLastSequenceError:
                    continue

                return True
        except PUBLISH_ERRORS as error:
            # Keep the handle: this attempt fails closed, and the next one
            # retries it. A Core NATS disconnect resets handles properly, and
            # dropping it here would leave the store unready with nothing
            # left to reopen it.
            LOGGER.warning(
                "authentication limit failed; denying: %s",
                error_label(error),
            )

        return False

    def key(self, identity: str, slot: int) -> str:
        """Derive an opaque key for one identity and attempt slot."""
        return _sign_fields(self.secret, "botnats-auth-attempt-v1", identity, str(slot))


class ChannelStore(KVStore):
    """Durable channel records in JetStream KV."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_channels", replicas, 0)
        self.network = network
        self.secret = secret

    def key(self, channel: str) -> str:
        """Derive an opaque key for a channel name."""
        folded = casefold(channel, "ascii")
        return _sign_fields(self.secret, "botnats-channel-v1", folded)

    def sign(self, fields: ChannelFields) -> dict[str, Any]:
        """Return the canonical, signed record of validated channel fields."""
        channel, channel_key, present, revision = fields
        record: dict[str, Any] = {
            "channel": channel,
            "key": channel_key,
            "present": present,
            "revision": revision,
        }
        record["signature"] = channel_signature(self.secret, self.network, record)
        return record

    def parse(self, key: str, record: dict[str, Any]) -> ChannelFields | None:
        """Validate a signed, key-bound channel record and return its fields.

        Unsigned or wrong-signature records are untrusted and treated as
        replaceable, like sessions and presence: honoring one would let a
        writer without the coordination secret have put() return its forged
        record as the winner.
        """
        try:
            fields = parse_channel_record(record)
        except TypeError, ValueError:
            return None

        signature = record.get("signature")
        if (
            self.key(fields[0]) != key
            or not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
        ):
            return None

        expected = channel_signature(self.secret, self.network, record)
        if not hmac.compare_digest(expected, signature):
            return None

        return fields

    async def put(
        self,
        data: dict[str, Any],
        *,
        after: str | None,
    ) -> ChannelFields:
        """Store a signed channel record and return the authoritative fields.

        after is the revision the record was written after (None when no
        record was known). The write lands only while the stored record is
        no newer than that, so a concurrent write from another bot wins
        cleanly instead of by the random revision suffix. An older stored
        record was rolled back, as when a NATS writer without the
        coordination secret replays a signed one; honoring it would supersede
        every later write.
        """
        fields = parse_channel_record(data)
        key = self.key(fields[0])

        def standing(current: dict[str, Any]) -> ChannelFields | None:
            stored = self.parse(key, current)
            # Revisions are fixed-width, so string order is revision order.
            if stored is None or (after is not None and stored[3] <= after):
                return None

            return stored

        return await self.put_newer(key, self.sign(fields), fields, standing)


class ClaimStore(KVStore):
    """Atomically records used TOTP counters in JetStream KV."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_used_totp", replicas, CLAIM_TTL)
        self.secret = secret

    async def claim(self, counter: int) -> bool:
        """Claim a counter once, failing closed when KV is unavailable."""
        try:
            kv = await self.open()
            await kv.create(self.key(counter), b"1")
        except KeyWrongLastSequenceError:
            return False
        except PUBLISH_ERRORS as error:
            # Keep the handle, as in AttemptStore.allow.
            LOGGER.warning(
                "TOTP claim failed; denying: %s",
                error_label(error),
            )
            return False

        return True

    def key(self, counter: int) -> str:
        """Derive an opaque KV key for a TOTP counter."""
        return _sign_fields(self.secret, "botnats-auth-claim-v1", str(counter))


class PresenceStore(KVStore):
    """Bot presence heartbeats in JetStream KV with TTL expiry."""

    def __init__(
        self,
        network: str,
        replicas: int,
        ttl: float,
        secret: bytes,
    ) -> None:
        super().__init__(f"botnats_v1_{network}_presence", replicas, ttl)
        self.network = network
        self.secret = secret

    def key(self, bot_id: str) -> str:
        """Return the presence key of a bot ID, which is case-insensitive."""
        return bot_id.casefold()

    async def create(self, bot_id: str, data: dict[str, Any]) -> int | None:
        """Atomically create a signed presence key and return its revision."""
        kv = await self.open()
        try:
            return await kv.create(self.key(bot_id), self.sign(data))
        except KeyWrongLastSequenceError:
            return None

    async def delete(self, bot_id: str, revision: int, instance_id: str) -> None:
        """Delete the presence key at its owned revision, if still this instance's.

        A heartbeat cancelled after its write reached the server leaves the
        owned revision stale. nats-py reports that delete's revision mismatch
        as a bare BadRequestError; the record is then deleted at its current
        revision if it is still this instance's.
        """
        kv = await self.open()
        key = self.key(bot_id)
        try:
            await kv.delete(key, last=revision)
        except BadRequestError:
            entry = await kv.get(key)
            record = decode_record(entry.value)
            if record and record.get("instance_id") == instance_id:
                await kv.delete(key, last=entry.revision)

    async def reclaim(
        self,
        bot_id: str,
        data: dict[str, Any],
        instance_id: str,
    ) -> int | None:
        """Reclaim an occupied presence key, re-reading after a lost race.

        Returns the current revision when this instance's own signed record
        still holds the key; overwrites an unsigned, forged, or misplaced
        clobber (written by a party without the coordination secret, or
        copied from another bot's key) to reclaim it; and returns None only
        when a validly signed record of this bot ID from another instance
        holds the key, which is a genuine duplicate this process must yield
        to. Repeated lost races prove nothing about ownership, so exhaustion
        raises for the caller's transient retry path instead of reporting a
        duplicate.
        """
        kv = await self.open()
        # Deliberately tighter than CAS_ATTEMPT_LIMIT: one create race plus
        # one update race already prove live contention, and the presence
        # heartbeat retries far sooner than eight rounds would resolve.
        for _ in range(2):
            try:
                entry = await kv.get(self.key(bot_id))
            except KeyNotFoundError:
                # The occupant expired between the failed create and this
                # read; the key is unowned, so claim it. On a lost create
                # race, re-read to evaluate the racing writer instead of
                # misreporting a forged occupant as a genuine duplicate.
                revision = await self.create(bot_id, data)
                if revision is not None:
                    return revision

                continue

            current = decode_record(entry.value)
            if current is not None and self.valid(self.key(bot_id), current):
                return (
                    entry.revision
                    if current.get("instance_id") == instance_id
                    else None
                )

            try:
                return await kv.update(
                    self.key(bot_id), self.sign(data), last=entry.revision
                )
            except KeyWrongLastSequenceError:
                # Lost the overwrite race; re-read to evaluate the racing
                # writer instead of misreporting a forged clobber as a
                # genuine duplicate.
                continue

        msg = "presence reclaim lost repeated update races"
        raise NatsError(msg)

    def sign(self, data: dict[str, Any]) -> bytes:
        """Serialize a freshly timestamped, signed presence record."""
        stamped = {**data, "timestamp": int(time.time())}
        stamped["signature"] = presence_signature(self.secret, self.network, stamped)
        return json.dumps(stamped).encode()

    async def update(
        self,
        bot_id: str,
        data: dict[str, Any],
        revision: int,
    ) -> int | None:
        """Refresh presence only while its last owned revision still matches."""
        kv = await self.open()
        try:
            return await kv.update(self.key(bot_id), self.sign(data), last=revision)
        except KeyWrongLastSequenceError:
            return None

    def valid(self, key: str, data: dict[str, Any], now: float | None = None) -> bool:
        """Return whether a presence record is fresh, signed, and bound to its key.

        The signature does not cover the KV key, so a record copied from
        another bot's key is valid only there.
        """
        bot_id = data.get("bot_id")
        signature = data.get("signature")
        timestamp = data.get("timestamp")
        if (
            not isinstance(bot_id, str)
            or IDENTIFIER_RE.fullmatch(bot_id) is None
            or self.key(bot_id) != key
            or not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
            or not isinstance(timestamp, int)
        ):
            return False

        current = time.time() if now is None else now
        if (
            not current - self.ttl - PRESENCE_DRIFT
            <= timestamp
            <= current + PRESENCE_DRIFT
        ):
            return False

        try:
            expected = presence_signature(self.secret, self.network, data)
        except KeyError, TypeError, UnicodeEncodeError:
            return False

        return hmac.compare_digest(expected, signature)


class SessionStore(KVStore):
    """Auth sessions in JetStream KV with TTL-based expiry."""

    def __init__(self, network: str, replicas: int, secret: bytes, ttl: float) -> None:
        super().__init__(f"botnats_v1_{network}_sessions", replicas, ttl)
        self.network = network
        self.secret = secret

    def key(self, identity: str) -> str:
        """Derive an opaque key independent of IRC casemapping."""
        folded = casefold(identity, "ascii")
        return _sign_fields(self.secret, "botnats-session-v1", folded)

    def parse(self, key: str, record: dict[str, Any]) -> Session | None:
        """Validate a signed session record held under a KV key, in horizon."""
        session = parse_session_record(self.secret, self.network, record)
        if (
            session is None
            or self.key(session.prefix) != key
            or not self.within_horizon(session)
        ):
            return None

        return session

    async def put(self, data: dict[str, Any]) -> Session:
        """Store a session or revocation and return the authoritative session.

        Only the future horizon is bounded: an already-expired record must
        stay writable so a near-expiry revocation is not rejected under
        clock skew, and consumers treat expired records as deletions.
        """
        session = parse_session_record(self.secret, self.network, data)
        if session is None or not self.within_horizon(session):
            msg = "session record is invalid"
            raise ValueError(msg)

        key = self.key(session.prefix)

        def standing(current: dict[str, Any]) -> Session | None:
            stored = self.parse(key, current)
            if stored is None or stored.order < session.order:
                return None

            return stored

        return await self.put_newer(key, data, session, standing)

    def within_horizon(self, session: Session) -> bool:
        """Return whether a session expires no later than one TTL plus grace away."""
        return session.expires_at <= time.time() + self.ttl + SESSION_EXPIRY_GRACE


@dataclass(frozen=True, slots=True)
class Session:
    """Represent an authenticated administrator session bound to an IRC prefix."""

    expires_at: float
    issuer: str
    prefix: str
    revoked: bool
    version: int
    signature: str

    @property
    def order(self) -> tuple[float, int, bool]:
        """Return the durable mutation order for this session."""
        return self.expires_at, self.version, self.revoked


def parse_session_record(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> Session | None:
    """Validate and extract a signed durable session record."""
    expires_at = record.get("expires_at")
    issuer = record.get("issuer")
    prefix = record.get("prefix")
    revoked = record.get("revoked")
    signature = record.get("signature")
    version = record.get("version")
    if (
        not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(issuer, str)
        or not issuer
        or not isinstance(prefix, str)
        or not prefix
        or not isinstance(revoked, bool)
        or not isinstance(signature, str)
        or SIGNATURE_RE.fullmatch(signature) is None
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version < 0
    ):
        return None

    try:
        issuer.encode()
        prefix.encode()
    except UnicodeEncodeError:
        return None

    try:
        expiry = float(expires_at)
    except OverflowError:
        return None

    if not math.isfinite(expiry) or not hmac.compare_digest(
        session_signature(secret, network, record),
        signature,
    ):
        return None

    return Session(
        expires_at=expiry,
        issuer=issuer,
        prefix=prefix,
        revoked=revoked,
        version=version,
        signature=signature,
    )


def decode_record(value: bytes | None) -> dict[str, Any] | None:
    """Decode a stored JSON object, or None when it is missing or malformed."""
    try:
        data = json.loads(value) if value is not None else None
    except DECODE_ERRORS:
        return None

    return data if isinstance(data, dict) else None


def _sign_fields(secret: bytes, *fields: str) -> str:
    """HMAC-SHA256 over null-joined fields, returned as hex."""
    return hmac.digest(secret, "\x00".join(fields).encode(), "sha256").hex()


def channel_signature(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> str:
    """Sign the durable fields that authorize a channel configuration record."""
    channel_key = record["key"]
    return _sign_fields(
        secret,
        "botnats-channel-record-v1",
        network,
        record["channel"],
        str(int(channel_key is not None)),
        channel_key or "",
        str(int(record["present"])),
        record["revision"],
    )


def session_signature(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> str:
    """Sign every authorization-relevant durable session field."""
    return _sign_fields(
        secret,
        "botnats-auth-v1",
        network,
        record["issuer"],
        record["prefix"],
        float(record["expires_at"]).hex(),
        str(record["version"]),
        str(int(record["revoked"])),
    )


def presence_signature(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> str:
    """Sign the identity fields and freshness that bind a presence record."""
    return _sign_fields(
        secret,
        "botnats-presence-v1",
        network,
        record["bot_id"],
        record["host"],
        record["instance_id"],
        record["nick"],
        record["user"],
        str(record["timestamp"]),
    )


def is_delete(operation: str | None) -> bool:
    """Return whether a KV watch operation is a deletion."""
    return operation in (KV_DEL, KV_PURGE)
