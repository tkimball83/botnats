# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""JetStream key-value stores for auth, channels, presence, and TOTP."""

import asyncio
import hmac
import json
import logging
import math
import time
from typing import TYPE_CHECKING, Any

from nats.errors import Error as NatsError
from nats.js.api import KeyValueConfig, StorageType
from nats.js.errors import KeyDeletedError, KeyNotFoundError, KeyWrongLastSequenceError
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
CLAIM_TTL = 300.0
SESSION_EXPIRY_GRACE = 60.0


class KVStore:
    """Own a reconnectable file-backed JetStream key-value bucket."""

    def __init__(self, bucket: str, replicas: int, ttl: float) -> None:
        """Set the bucket identity and storage policy."""
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
                raise RuntimeError(msg)
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
                raise RuntimeError(msg)
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
        """Atomically store JSON and return the authoritative value."""
        kv = await self.open()
        encoded = json.dumps(data).encode()
        while True:
            try:
                entry = await kv.get(key)
            except KeyDeletedError, KeyNotFoundError:
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


class AttemptStore(KVStore):
    """Atomically limit authentication attempts across the bot mesh."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        """Set the bucket identity and key derivation secret."""
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
                except KeyDeletedError, KeyNotFoundError:
                    try:
                        await kv.create(key, encoded)
                    except KeyWrongLastSequenceError:
                        continue
                    return True
                if entry.value is None:
                    continue
                try:
                    timestamp = float.fromhex(entry.value.decode())
                except AttributeError, UnicodeDecodeError, ValueError:
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
        """Set the bucket identity and key derivation secret."""
        super().__init__(f"botnats_v1_{network}_channels", replicas, 0)
        self.secret = secret

    def key(self, channel: str) -> str:
        """Derive an opaque key for a channel name."""
        message = f"botnats-channel-v1\x00{casefold(channel, 'ascii')}".encode()
        return hmac.digest(self.secret, message, "sha256").hex()

    def order(self, key: str, record: dict[str, Any]) -> str | None:
        """Validate a key-bound channel record and return its revision."""
        try:
            channel, _, _, revision = parse_channel_record(record)
        except TypeError, ValueError:
            return None
        return revision if self.key(channel) == key else None

    async def put(self, channel: str, data: dict[str, Any]) -> dict[str, Any]:
        """Store a channel record and return the authoritative record."""
        key = self.key(channel)
        revision = self.order(key, data)
        if revision is None:
            msg = "channel record is invalid"
            raise ValueError(msg)

        def newer(current: dict[str, Any]) -> bool:
            current_revision = self.order(key, current)
            return current_revision is None or revision > current_revision

        return await self.put_newer(key, data, newer)


class ClaimStore(KVStore):
    """Atomically records used TOTP counters in JetStream KV."""

    def __init__(self, network: str, replicas: int, secret: bytes) -> None:
        """Set the bucket identity and storage policy."""
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

    def __init__(self, network: str, replicas: int, ttl: float) -> None:
        """Set the bucket identity and presence TTL."""
        super().__init__(f"botnats_v1_{network}_presence", replicas, ttl)

    async def create(self, bot_id: str, data: dict[str, Any]) -> int | None:
        """Atomically create a presence key and return its revision."""
        kv = await self.open()
        try:
            return await kv.create(bot_id.casefold(), json.dumps(data).encode())
        except KeyWrongLastSequenceError:
            return None

    async def delete(self, bot_id: str, revision: int) -> None:
        """Delete the presence key only while its owned revision still matches."""
        kv = await self.open()
        await kv.delete(bot_id.casefold(), last=revision)

    async def update(
        self,
        bot_id: str,
        data: dict[str, Any],
        revision: int,
    ) -> int | None:
        """Refresh presence only while its last owned revision still matches."""
        kv = await self.open()
        try:
            return await kv.update(
                bot_id.casefold(),
                json.dumps(data).encode(),
                last=revision,
            )
        except KeyWrongLastSequenceError:
            return None


class SessionStore(KVStore):
    """Auth sessions in JetStream KV with TTL-based expiry."""

    def __init__(self, network: str, replicas: int, secret: bytes, ttl: float) -> None:
        """Set the bucket identity and key derivation secret."""
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
        if parsed is None or casefold(parsed[2], "ascii") != casefold(
            identity,
            "ascii",
        ):
            return None
        return parsed[0], parsed[4], parsed[3]

    async def put(self, identity: str, data: dict[str, Any]) -> dict[str, Any]:
        """Store a session or revocation and return the authoritative record."""
        order = self.order(identity, data)
        if order is None or order[0] > time.time() + self.ttl + SESSION_EXPIRY_GRACE:
            msg = "session record is invalid"
            raise ValueError(msg)

        def newer(current: dict[str, Any]) -> bool:
            current_order = self.order(identity, current)
            return (
                current_order is None
                or current_order[0] <= time.time()
                or current_order[0] > time.time() + self.ttl + SESSION_EXPIRY_GRACE
                or current_order < order
            )

        return await self.put_newer(self.key(identity), data, newer)


def parse_session_record(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> tuple[float, str, str, bool, int, str] | None:
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
    return expiry, issuer, prefix, revoked, version, signature


def session_signature(
    secret: bytes,
    network: str,
    record: dict[str, Any],
) -> str:
    """Sign every authorization-relevant durable session field."""
    message = "\x00".join(
        (
            "botnats-auth-v1",
            network,
            record["issuer"],
            record["prefix"],
            float(record["expires_at"]).hex(),
            str(record["version"]),
            str(int(record["revoked"])),
        ),
    ).encode()
    return hmac.digest(secret, message, "sha256").hex()


def is_delete(operation: str | None) -> bool:
    """Return whether a KV watch operation is a deletion."""
    return operation in (KV_DEL, KV_PURGE)
