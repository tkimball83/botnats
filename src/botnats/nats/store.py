# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""JetStream key-value stores for auth, channels, presence, and TOTP."""

import asyncio
import hmac
import json
import logging
import math
import time
from typing import TYPE_CHECKING, Any, NamedTuple

from nats.errors import Error as NatsError
from nats.js.api import KeyValueConfig, StorageType
from nats.js.errors import KeyNotFoundError, KeyWrongLastSequenceError
from nats.js.kv import KV_DEL, KV_PURGE

from botnats import error_label
from botnats.irc.protocol import casefold
from botnats.nats.envelope import SIGNATURE_RE
from botnats.validators import parse_channel_record

if TYPE_CHECKING:
    from collections.abc import Callable

    from nats.js.client import JetStreamContext
    from nats.js.kv import KeyValue

LOGGER = logging.getLogger(__name__)

ATTEMPT_LIMIT = 3
ATTEMPT_TTL = 120.0
ATTEMPT_WINDOW = 60
CAS_ATTEMPT_LIMIT = 8
CLAIM_TTL = 300.0
PRESENCE_DRIFT = 30.0
SESSION_EXPIRY_GRACE = 60.0


class StoreUnavailableError(RuntimeError):
    """JetStream handles are reset or replaced while Core NATS reconnects.

    A RuntimeError subclass so every PUBLISH_ERRORS handler treats it as
    transient, while watches can distinguish it from a genuine RuntimeError
    programming failure.
    """


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
            kv = await context.create_key_value(
                KeyValueConfig(
                    bucket=self.bucket,
                    history=1,
                    replicas=self.replicas,
                    storage=StorageType.FILE,
                    ttl=self.ttl,
                ),
            )
            if self.js is not context:
                msg = "JetStream changed while opening a bucket"
                raise StoreUnavailableError(msg)
            self.kv = kv
            return kv

    @property
    def ready(self) -> bool:
        """Return whether the bucket is open."""
        return self.kv is not None

    def reset(self) -> None:
        """Discard handles tied to a disconnected NATS session."""
        self.js = None
        self.kv = None

    async def put_newer(
        self,
        key: str,
        data: dict[str, Any],
        newer: Callable[[dict[str, Any]], bool],
    ) -> dict[str, Any]:
        """Atomically store JSON and return the authoritative value.

        Bounded like reclaim: repeatedly losing the CAS race against a
        handful of peers is transient, so exhaustion raises for the caller's
        retry path instead of spinning against the bucket.
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
                return data
            try:
                current = json.loads(entry.value) if entry.value is not None else None
            except RecursionError, ValueError:
                current = None
            if isinstance(current, dict) and not newer(current):
                return current
            try:
                await kv.update(key, encoded, last=entry.revision)
            except KeyWrongLastSequenceError:
                continue
            return data
        msg = "durable write lost repeated update races"
        raise NatsError(msg)


class AttemptStore(KVStore):
    """Atomically limit authentication attempts across the bot mesh."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_auth_attempts", replicas, ATTEMPT_TTL)
        self.secret = secret

    async def allow(self, identity: str, *, now: float | None = None) -> bool:
        """Claim one attempt slot, failing closed when KV is unavailable."""
        if self.kv is None and self.js is None:
            return False
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
                except UnicodeDecodeError, ValueError:
                    continue
                if not math.isfinite(timestamp) or timestamp > cutoff:
                    continue
                try:
                    await kv.update(key, encoded, last=entry.revision)
                except KeyWrongLastSequenceError:
                    continue
                return True
        except (NatsError, OSError, RuntimeError) as error:
            self.kv = None
            LOGGER.warning(
                "authentication limit failed; denying: %s",
                error_label(error),
            )
        return False

    def key(self, identity: str, slot: int) -> str:
        """Derive an opaque key for one identity and attempt slot."""
        message = f"botnats-auth-attempt-v1\x00{identity}\x00{slot}".encode()
        return hmac.digest(self.secret, message, "sha256").hex()


class ChannelStore(KVStore):
    """Durable channel records in JetStream KV."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_channels", replicas, 0)
        self.network = network
        self.secret = secret

    def key(self, channel: str) -> str:
        """Derive an opaque key for a channel name."""
        message = f"botnats-channel-v1\x00{casefold(channel, 'ascii')}".encode()
        return hmac.digest(self.secret, message, "sha256").hex()

    def sign(self, data: dict[str, Any]) -> dict[str, Any]:
        """Return a canonical, signed copy of a valid channel record."""
        channel, channel_key, present, revision = parse_channel_record(data)
        record: dict[str, Any] = {
            "channel": channel,
            "key": channel_key,
            "present": present,
            "revision": revision,
        }
        record["signature"] = channel_signature(self.secret, self.network, record)
        return record

    def order(self, key: str, record: dict[str, Any]) -> str | None:
        """Validate a signed, key-bound channel record and return its revision.

        Unsigned or wrong-signature records are untrusted and treated as
        replaceable (revision ignored), like sessions and presence: honoring an
        unsigned record's revision would let a coordination-secret-less writer
        plant a high revision and wedge legitimate writes.
        """
        try:
            channel, channel_key, present, revision = parse_channel_record(record)
        except TypeError, ValueError:
            return None
        signature = record.get("signature")
        if (
            self.key(channel) != key
            or not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
        ):
            return None
        expected = channel_signature(
            self.secret,
            self.network,
            {
                "channel": channel,
                "key": channel_key,
                "present": present,
                "revision": revision,
            },
        )
        if not hmac.compare_digest(expected, signature):
            return None
        return revision

    async def put(self, channel: str, data: dict[str, Any]) -> dict[str, Any]:
        """Store a signed channel record and return the authoritative record."""
        signed = self.sign(data)
        key = self.key(channel)
        revision = self.order(key, signed)
        if revision is None:
            msg = "channel record is invalid"
            raise ValueError(msg)

        def newer(current: dict[str, Any]) -> bool:
            current_revision = self.order(key, current)
            return current_revision is None or revision > current_revision

        return await self.put_newer(key, signed, newer)


class ClaimStore(KVStore):
    """Atomically records used TOTP counters in JetStream KV."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        super().__init__(f"botnats_v1_{network}_used_totp", replicas, CLAIM_TTL)
        self.secret = secret

    async def claim(self, counter: int) -> bool:
        """Claim a counter once, failing closed when KV is unavailable."""
        if self.kv is None and self.js is None:
            return False
        try:
            kv = await self.open()
            await kv.create(self.key(counter), b"1")
        except KeyWrongLastSequenceError:
            return False
        except (NatsError, OSError, RuntimeError) as error:
            self.kv = None
            LOGGER.warning(
                "TOTP claim failed; denying: %s",
                error_label(error),
            )
            return False
        return True

    def key(self, counter: int) -> str:
        """Derive an opaque KV key for a TOTP counter."""
        message = f"botnats-auth-claim-v1\x00{counter}".encode()
        return hmac.digest(self.secret, message, "sha256").hex()


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

    async def create(self, bot_id: str, data: dict[str, Any]) -> int | None:
        """Atomically create a signed presence key and return its revision."""
        kv = await self.open()
        try:
            return await kv.create(bot_id.casefold(), self.sign(data))
        except KeyWrongLastSequenceError:
            return None

    async def delete(self, bot_id: str, revision: int) -> None:
        """Delete the presence key only while its owned revision still matches."""
        kv = await self.open()
        await kv.delete(bot_id.casefold(), last=revision)

    async def reclaim(
        self,
        bot_id: str,
        data: dict[str, Any],
        instance_id: str,
    ) -> int | None:
        """Reclaim an occupied presence key from a single read.

        Returns the current revision when this instance's own signed record
        still holds the key; overwrites an unsigned or forged clobber (written
        by a party without the coordination secret) to reclaim it; and returns
        None only when a validly signed record from another instance holds the
        key, which is a genuine duplicate this process must yield to. Repeated
        lost races prove nothing about ownership, so exhaustion raises for the
        caller's transient retry path instead of reporting a duplicate.
        """
        kv = await self.open()
        # Deliberately tighter than CAS_ATTEMPT_LIMIT: one create race plus
        # one update race already prove live contention, and the presence
        # heartbeat retries far sooner than eight rounds would resolve.
        for _ in range(2):
            try:
                entry = await kv.get(bot_id.casefold())
            except KeyNotFoundError:
                # The occupant expired between the failed create and this
                # read; the key is unowned, so claim it. On a lost create
                # race, re-read to evaluate the racing writer instead of
                # misreporting a forged occupant as a genuine duplicate.
                revision = await self.create(bot_id, data)
                if revision is not None:
                    return revision
                continue
            try:
                current = json.loads(entry.value) if entry.value is not None else None
            except RecursionError, TypeError, ValueError:
                current = None
            if isinstance(current, dict) and self.valid(current):
                return (
                    entry.revision
                    if current.get("instance_id") == instance_id
                    else None
                )
            try:
                return await kv.update(
                    bot_id.casefold(), self.sign(data), last=entry.revision
                )
            except KeyWrongLastSequenceError:
                # Lost the overwrite race; re-read to evaluate the racing
                # writer instead of misreporting a forged clobber as a
                # genuine duplicate.
                continue
        msg = "presence reclaim lost repeated update races"
        raise NatsError(msg)

    def sign(self, data: dict[str, Any], now: float | None = None) -> bytes:
        """Serialize a freshly timestamped, signed presence record."""
        current = time.time() if now is None else now
        stamped = {**data, "timestamp": int(current)}
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
            return await kv.update(bot_id.casefold(), self.sign(data), last=revision)
        except KeyWrongLastSequenceError:
            return None

    def valid(self, data: dict[str, Any], now: float | None = None) -> bool:
        """Return whether a presence record is fresh and correctly signed."""
        signature = data.get("signature")
        timestamp = data.get("timestamp")
        if (
            not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
            or not isinstance(timestamp, int)
            or isinstance(timestamp, bool)
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
        message = f"botnats-session-v1\x00{casefold(identity, 'ascii')}".encode()
        return hmac.digest(self.secret, message, "sha256").hex()

    def order(
        self,
        identity: str,
        record: dict[str, Any],
    ) -> tuple[float, int, bool] | None:
        """Validate a signed session record and return its durable order."""
        parsed = parse_session_record(self.secret, self.network, record)
        if parsed is None or casefold(parsed.prefix, "ascii") != casefold(
            identity,
            "ascii",
        ):
            return None
        return parsed.expires_at, parsed.version, parsed.revoked

    async def put(self, identity: str, data: dict[str, Any]) -> dict[str, Any]:
        """Store a session or revocation and return the authoritative record.

        Only the future horizon is bounded: an already-expired record must
        stay writable so a near-expiry revocation is not rejected under
        clock skew, and consumers treat expired records as deletions.
        """
        order = self.order(identity, data)
        if order is None or order[0] > time.time() + self.ttl + SESSION_EXPIRY_GRACE:
            msg = "session record is invalid"
            raise ValueError(msg)

        def newer(current: dict[str, Any]) -> bool:
            current_order = self.order(identity, current)
            now = time.time()
            return (
                current_order is None
                or current_order[0] <= now
                or current_order[0] > now + self.ttl + SESSION_EXPIRY_GRACE
                or current_order < order
            )

        return await self.put_newer(self.key(identity), data, newer)


class SessionRecord(NamedTuple):
    """Validated fields of a signed durable session record."""

    expires_at: float
    issuer: str
    prefix: str
    revoked: bool
    version: int
    signature: str


def parse_session_record(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> SessionRecord | None:
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
    return SessionRecord(expiry, issuer, prefix, revoked, version, signature)


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
