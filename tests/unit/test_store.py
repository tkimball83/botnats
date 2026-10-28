# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for JetStream KV buckets: attempts, channels, claims, presence, sessions."""

import asyncio
import json
import math
import re
import time
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock, patch

from nats.errors import Error as NatsError
from nats.js.api import StreamConfig
from nats.js.errors import (
    BadRequestError,
    KeyNotFoundError,
    KeyWrongLastSequenceError,
    NotFoundError,
)

from botnats.auth import TOTP_PERIOD, TOTP_WINDOW
from botnats.nats.store import (
    ATTEMPT_LIMIT,
    ATTEMPT_WINDOW,
    CAS_ATTEMPT_LIMIT,
    PRESENCE_DRIFT,
    SESSION_EXPIRY_GRACE,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    KVStore,
    PresenceStore,
    Session,
    SessionStore,
    StoreUnavailableError,
    channel_signature,
    decode_record,
    parse_session_record,
    presence_signature,
    session_signature,
)
from tests.unit.helpers import COORDINATION_KEY as SECRET
from tests.unit.helpers import FakeKV, session_record

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

    from botnats.validators import ChannelFields

OTHER_SECRET = b"a-different-coordination-secret!"
SHA256_HEX_LENGTH = 64
SESSION_INVALID = "session record is invalid"


def signed_presence(instance_id: str) -> dict[str, object]:
    """Build a fresh, validly signed presence record for one instance."""
    data: dict[str, object] = {
        "bot_id": "Alpha",
        "host": "host",
        "instance_id": instance_id,
        "nick": "Alpha",
        "user": "user",
        "timestamp": int(time.time()),
    }
    data["signature"] = presence_signature(SECRET, "efnet", data)
    return data


class DeletableKV(FakeKV):
    """In-memory bucket whose delete checks the last revision as nats-py does."""

    async def delete(self, key: str, last: int) -> bool:
        """Delete a key at its revision; nats-py raises a bare BadRequestError."""
        if self.entries[key][0] != last:
            raise BadRequestError(code=400, err_code=10071)

        del self.entries[key]
        return True


async def stale_presence(instance_id: str) -> tuple[PresenceStore, DeletableKV]:
    """Store alpha's presence at revision 1, then a newer record by instance_id.

    A heartbeat cancelled after its write reached the server leaves its owner
    holding revision 1.
    """
    store = PresenceStore("efnet", 1, 15.0, SECRET)
    kv = DeletableKV()
    store.kv = cast("KeyValue", kv)
    revision = await kv.create("alpha", json.dumps(signed_presence("inst")).encode())
    newer = json.dumps(signed_presence(instance_id)).encode()
    await kv.update("alpha", newer, last=revision)
    return store, kv


class PresenceReclaimTests(unittest.IsolatedAsyncioTestCase):
    """Tests for reclaiming an occupied presence key after reconnect."""

    async def test_create_and_reclaim_sign_heartbeat(self) -> None:
        """Store the unsigned heartbeat a claim passes as a signed record."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        kv = FakeKV()
        store.kv = cast("KeyValue", kv)
        heartbeat = {
            "bot_id": "Alpha",
            "host": "host",
            "instance_id": "inst",
            "nick": "Alpha",
            "user": "user",
        }

        assert await store.create("Alpha", heartbeat) is not None
        assert store.valid("alpha", json.loads(kv.entries["alpha"][1]))

        kv.store("alpha", b'{"garbage": true}')
        assert await store.reclaim("Alpha", heartbeat, "inst") is not None
        assert store.valid("alpha", json.loads(kv.entries["alpha"][1]))

    async def test_reclaim_adopts_own_record(self) -> None:
        """Adopt the key without a write when this instance signed it."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        owned = signed_presence("inst")
        entry = SimpleNamespace(
            revision=8,
            value=json.dumps(owned).encode(),
        )
        kv = AsyncMock()
        kv.get = AsyncMock(return_value=entry)
        store.kv = kv

        assert await store.reclaim("Alpha", owned, "inst") == 8
        kv.get.assert_awaited_with("alpha")
        kv.update.assert_not_awaited()

    async def test_reclaim_yields_to_valid_foreign_record(self) -> None:
        """Never overwrite a validly signed record from another instance."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        foreign = signed_presence("other")
        kv = AsyncMock()
        kv.get = AsyncMock(
            return_value=SimpleNamespace(
                revision=5, value=json.dumps(foreign).encode()
            ),
        )
        store.kv = kv

        assert await store.reclaim("Alpha", signed_presence("inst"), "inst") is None
        kv.update.assert_not_awaited()

    async def test_reclaim_overwrites_forged_or_absent(self) -> None:
        """Overwrite a forged or misplaced clobber; claim when the key is gone."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        data = signed_presence("inst")
        reclaimed_revision = 6
        kv = AsyncMock()
        store.kv = kv

        kv.get = AsyncMock(
            return_value=SimpleNamespace(revision=5, value=b"not json"),
        )
        kv.update = AsyncMock(return_value=reclaimed_revision)
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision
        kv.update.assert_awaited_once()

        forged = {**data, "signature": "0" * SHA256_HEX_LENGTH}
        kv.get = AsyncMock(
            return_value=SimpleNamespace(revision=5, value=json.dumps(forged).encode()),
        )
        kv.update = AsyncMock(return_value=reclaimed_revision)
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision

        # Another bot's validly signed record, copied onto this bot's key, is
        # a clobber to overwrite, not a duplicate to yield to.
        copied: dict[str, object] = {**data, "bot_id": "beta", "instance_id": "other"}
        copied["signature"] = presence_signature(SECRET, "efnet", copied)
        assert store.valid("beta", copied)
        kv.get = AsyncMock(
            return_value=SimpleNamespace(revision=5, value=json.dumps(copied).encode()),
        )
        kv.update = AsyncMock(return_value=reclaimed_revision)
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision
        kv.update.assert_awaited_once()

        kv.get = AsyncMock(side_effect=KeyNotFoundError())
        kv.create = AsyncMock(return_value=reclaimed_revision)
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision
        kv.create.assert_awaited_once()

        # A lost create race against a forged occupant re-reads and overwrites
        # instead of misreporting a duplicate.
        kv.get = AsyncMock(
            side_effect=[
                KeyNotFoundError(),
                SimpleNamespace(revision=9, value=b'{"garbage": true}'),
            ],
        )
        kv.create = AsyncMock(side_effect=KeyWrongLastSequenceError())
        kv.update = AsyncMock(return_value=reclaimed_revision)
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision
        kv.update.assert_awaited_once()

        # A lost overwrite race against a forged occupant re-reads and retries
        # instead of misreporting a duplicate.
        forged_entry = SimpleNamespace(revision=5, value=b'{"garbage": true}')
        kv.get = AsyncMock(side_effect=[forged_entry, forged_entry])
        kv.update = AsyncMock(
            side_effect=[KeyWrongLastSequenceError(), reclaimed_revision],
        )
        assert await store.reclaim("Alpha", data, "inst") == reclaimed_revision

        # Exhausting the retries proves contention, not a duplicate: raise
        # into the caller's transient retry path instead of yielding None.
        kv.get = AsyncMock(side_effect=[forged_entry, forged_entry])
        kv.update = AsyncMock(side_effect=KeyWrongLastSequenceError())
        with self.assertRaisesRegex(NatsError, "repeated update races"):
            await store.reclaim("Alpha", data, "inst")


class PresenceValidTests(unittest.TestCase):
    """Tests for presence record freshness, signatures, and key binding."""

    def test_valid_binds_record_to_key(self) -> None:
        """Accept a signed record only under its own bot ID's key."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        now = 1_000_000.0

        def signed(bot_id: str) -> dict[str, object]:
            data: dict[str, object] = {
                "bot_id": bot_id,
                "host": "host",
                "instance_id": "inst",
                "nick": "nick",
                "user": "user",
                "timestamp": int(now),
            }
            data["signature"] = presence_signature(SECRET, "efnet", data)
            return data

        beta = signed("Beta")
        assert store.valid("beta", beta, now=now)
        assert not store.valid("alpha", beta, now=now)

        # A key the record names exactly is still refused for a bot ID that
        # is not an identifier.
        assert not store.valid("be.ta", signed("be.ta"), now=now)

    def test_presence_signature_covers_every_field(self) -> None:
        """Refuse a record whose signed fields or network changed after signing."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        now = 1_000_000.0
        valid: dict[str, object] = {
            "bot_id": "alpha",
            "host": "host",
            "instance_id": "inst",
            "nick": "nick",
            "user": "user",
            "timestamp": int(now),
        }
        valid["signature"] = presence_signature(SECRET, "efnet", valid)
        assert store.valid("alpha", valid, now=now)
        # Each change is well-formed, fresh, and keeps the "alpha" key, so
        # only the signature rejects it.
        changes: dict[str, dict[str, object]] = {
            "bot_id changed": {"bot_id": "Alpha"},
            "host changed": {"host": "other"},
            "instance_id changed": {"instance_id": "other"},
            "nick changed": {"nick": "other"},
            "user changed": {"user": "other"},
            "timestamp changed": {"timestamp": int(now) - 1},
        }
        for label, change in changes.items():
            record = {**valid, **change}
            resigned = {**record}
            resigned["signature"] = presence_signature(SECRET, "efnet", record)
            with self.subTest(label):
                assert not store.valid("alpha", record, now=now)
                assert store.valid("alpha", resigned, now=now)

        undernet = PresenceStore("undernet", 1, 15.0, SECRET)
        assert not undernet.valid("alpha", valid, now=now)
        other_network = {**valid}
        other_network["signature"] = presence_signature(SECRET, "undernet", valid)
        assert undernet.valid("alpha", other_network, now=now)

    def test_valid_rejects_stale_and_uncrashable(self) -> None:
        """Reject stale or future-dated replays and malformed fields without raising."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        now = 1_000_000.0

        def sign(data: dict[str, object]) -> dict[str, object]:
            data["signature"] = presence_signature(SECRET, "efnet", data)
            return data

        fresh = sign(
            {
                "bot_id": "alpha",
                "host": "host",
                "instance_id": "inst",
                "nick": "alpha",
                "user": "user",
                "timestamp": int(now),
            },
        )
        assert store.valid("alpha", fresh, now=now)

        # Fresh from one TTL plus drift ago to one drift ahead, inclusive.
        bounds = {
            PRESENCE_DRIFT: True,
            PRESENCE_DRIFT + 1: False,
            -store.ttl - PRESENCE_DRIFT: True,
            -store.ttl - PRESENCE_DRIFT - 1: False,
        }
        with patch("botnats.nats.store.time") as clock:
            clock.time.return_value = now
            for offset, fresh_at in bounds.items():
                record = sign({**fresh, "timestamp": int(now + offset)})
                with self.subTest(offset=offset):
                    assert store.valid("alpha", record) is fresh_at

        surrogate = {
            "bot_id": "alpha",
            "host": "\ud800",
            "instance_id": "inst",
            "nick": "alpha",
            "user": "user",
            "timestamp": int(now),
            "signature": "0" * SHA256_HEX_LENGTH,
        }
        assert not store.valid("alpha", surrogate, now=now)

        # A missing or mistyped signed field fails the signature, never raises.
        missing_host = {k: v for k, v in surrogate.items() if k != "host"}
        assert not store.valid("alpha", missing_host, now=now)
        assert not store.valid("alpha", {**surrogate, "host": 5}, now=now)

        # A string or missing timestamp is refused before the freshness
        # comparison, which raises on one; "1000000" even signs like int(now).
        assert not store.valid("alpha", {**fresh, "timestamp": "1000000"}, now=now)
        missing_timestamp = {k: v for k, v in fresh.items() if k != "timestamp"}
        assert not store.valid("alpha", missing_timestamp, now=now)

        # A signed boolean is an int only the freshness window refuses.
        for flag in (True, False):
            with self.subTest(timestamp=flag):
                record = sign({**fresh, "timestamp": flag})
                assert not store.valid("alpha", record, now=now)

        non_ascii_signature = {**fresh, "signature": "ñ" * SHA256_HEX_LENGTH}
        assert not store.valid("alpha", non_ascii_signature, now=now)


def channel_revision(number: int) -> str:
    """Return the sortable revision channel_record(number) carries."""
    return f"{number:020d}-{'0' * 32}"


def channel_fields(revision: int) -> ChannelFields:
    """Return the validated fields channel_record(revision) carries."""
    return "#test", None, True, channel_revision(revision)


def channel_record(revision: int) -> dict[str, object]:
    """Build a valid, signed durable channel record with a sortable revision."""
    record: dict[str, object] = {
        "channel": "#test",
        "key": None,
        "present": True,
        "revision": channel_revision(revision),
    }
    record["signature"] = channel_signature(SECRET, "efnet", record)
    return record


def parsed_session(record: dict[str, object]) -> Session:
    """Return the session a valid signed record holds."""
    session = parse_session_record(SECRET, "efnet", record)
    assert session is not None
    return session


class AttemptStoreTests(unittest.IsolatedAsyncioTestCase):
    """Tests for fail-closed mesh-wide authentication limits."""

    async def test_allows_available_slot(self) -> None:
        """Verify the first available atomic slot permits an attempt."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = [
            KeyWrongLastSequenceError(),
            1,
        ]

        assert await attempts.allow("host.example", now=60)
        assert attempts.kv.create.await_count == 2

    async def test_denies_after_limit(self) -> None:
        """Verify a full attempt window denies another authentication attempt."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = KeyWrongLastSequenceError()

        assert not await attempts.allow("host.example", now=60)
        assert attempts.kv.create.await_count == ATTEMPT_LIMIT

    async def test_error_fails_closed(self) -> None:
        """Deny during a JetStream error, then allow once it recovers."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = NatsError("unavailable")

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await attempts.allow("host.example", now=60)

        # One error must not leave the store unready: nothing would reopen it.
        assert attempts.ready
        attempts.kv.create.side_effect = None
        attempts.kv.create.return_value = 1
        assert await attempts.allow("host.example", now=61)

    async def test_keys_are_secret_derived(self) -> None:
        """Derive per-identity, per-slot attempt keys from the coordination secret.

        One key for every identity would let one guesser lock out every admin;
        an attempt expiring inside the window would free its slot early.
        """
        attempts = AttemptStore("efnet", 3, SECRET)

        key = attempts.key("host.example", 0)

        assert key == AttemptStore("efnet", 3, SECRET).key("host.example", 0)
        assert key != AttemptStore("efnet", 3, OTHER_SECRET).key("host.example", 0)
        assert key != attempts.key("host.example", 1)
        assert key != attempts.key("other.example", 0)
        assert len(key) == SHA256_HEX_LENGTH
        assert attempts.ttl >= ATTEMPT_WINDOW

    async def test_missing_store_fails_closed(self) -> None:
        """Verify authentication is denied until the bucket is open."""
        attempts = AttemptStore("efnet", 3, SECRET)

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await attempts.allow("host.example", now=60)

    async def test_sliding_window_reuses_expired_slot(self) -> None:
        """Verify an expired slot is atomically reused."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.return_value = MagicMock(
            revision=7,
            value=float(0).hex().encode(),
        )
        attempts.kv.update.return_value = 8

        assert await attempts.allow("host.example", now=61)
        attempts.kv.update.assert_awaited_once_with(
            attempts.key("host.example", 0),
            float(61).hex().encode(),
            last=7,
        )

    async def test_sliding_window_reuses_slot_at_cutoff(self) -> None:
        """Reuse a slot whose attempt sits exactly one window before now."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        now = 1_000.0
        attempts.kv.get.return_value = MagicMock(
            revision=7,
            value=(now - ATTEMPT_WINDOW).hex().encode(),
        )
        attempts.kv.update.return_value = 8

        assert await attempts.allow("host.example", now=now)
        attempts.kv.update.assert_awaited_once_with(
            attempts.key("host.example", 0),
            now.hex().encode(),
            last=7,
        )

    async def test_unreadable_attempts_fail_closed(self) -> None:
        """Count slots holding no value, non-hex, or non-UTF-8 bytes as taken."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(revision=1, value=None),
            MagicMock(revision=2, value=b"not-a-timestamp"),
            MagicMock(revision=3, value=b"\xff\xfe"),
        ]

        assert not await attempts.allow("host.example", now=60)

    async def test_overflowing_attempt_is_skipped(self) -> None:
        """Count a slot too large for a float as taken, and try the next one."""
        attempts = AttemptStore("efnet", 3, SECRET)
        kv = FakeKV()
        attempts.kv = cast("KeyValue", kv)
        slot = attempts.key("host.example", 0)
        kv.store(slot, b"0x1p+1024")

        assert await attempts.allow("host.example", now=60)
        assert kv.entries[slot] == (1, b"0x1p+1024")
        assert attempts.key("host.example", 1) in kv.entries

    async def test_sliding_window_update_conflict_does_not_overbook(self) -> None:
        """Deny when a peer claims the only expired slot first."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(revision=7, value=float(0).hex().encode()),
            MagicMock(value=float(60).hex().encode()),
            MagicMock(value=float(60).hex().encode()),
        ]
        attempts.kv.update.side_effect = KeyWrongLastSequenceError()

        assert not await attempts.allow("host.example", now=61)
        attempts.kv.update.assert_awaited_once()

    async def test_recent_attempts_deny(self) -> None:
        """Deny while every slot holds an attempt from within the window."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            # A second short of a full window old.
            MagicMock(value=float(1).hex().encode()),
            MagicMock(value=(59.5).hex().encode()),
            MagicMock(value=(59.9).hex().encode()),
        ]

        assert not await attempts.allow("host.example", now=60)

    async def test_future_attempts_deny(self) -> None:
        """Count attempts a faster peer stamped after this peer's now."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(value=float(61).hex().encode()),
            MagicMock(value=(61.1).hex().encode()),
            MagicMock(value=(61.2).hex().encode()),
        ]

        assert not await attempts.allow("host.example", now=59)

    async def test_non_finite_attempts_fail_closed(self) -> None:
        """Verify non-finite stored timestamps consume attempt slots."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(value=b"nan"),
            MagicMock(value=b"inf"),
            MagicMock(value=b"-inf"),
        ]

        assert not await attempts.allow("host.example", now=60)


class ClaimStoreTests(unittest.IsolatedAsyncioTestCase):
    """Tests for fail-closed JetStream TOTP claims."""

    async def test_claim(self) -> None:
        """Verify a counter's claim uses its own secret-derived key.

        One key for every counter would let a wrong code's claim block every
        AUTH; a claim expiring while its code is still accepted allows replay.
        """
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()
        claims.kv.create.return_value = 1

        assert await claims.claim(42)

        key = claims.key(42)
        assert key == ClaimStore("efnet", 3, SECRET).key(42)
        assert key != ClaimStore("efnet", 3, OTHER_SECRET).key(42)
        assert key != claims.key(43)
        assert len(key) == SHA256_HEX_LENGTH
        assert claims.ttl >= (2 * TOTP_WINDOW + 1) * TOTP_PERIOD
        assert claims.ready
        claims.kv.create.assert_awaited_once_with(key, b"1")

    async def test_duplicate(self) -> None:
        """Verify a duplicate counter fails closed."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()
        claims.kv.create.side_effect = KeyWrongLastSequenceError()

        assert not await claims.claim(42)

    async def test_error(self) -> None:
        """Fail closed during a JetStream error, then claim once it recovers."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()
        claims.kv.create.side_effect = NatsError("unavailable")

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await claims.claim(42)

        # One error must not leave the store unready: nothing would reopen it.
        assert claims.ready
        claims.kv.create.side_effect = None
        claims.kv.create.return_value = 1
        assert await claims.claim(42)

    async def test_missing_store(self) -> None:
        """Verify a claim is denied until the bucket is open."""
        claims = ClaimStore("efnet", 3, SECRET)

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await claims.claim(42)

        assert not claims.ready

    async def test_reopen_after_error(self) -> None:
        """Verify a claim retries opening KV after reconnect initialization fails."""
        claims = ClaimStore("efnet", 3, SECRET)
        js = AsyncMock()
        kv = AsyncMock()
        kv.create.return_value = 1
        js.create_key_value.side_effect = [NatsError("recovering"), kv]

        with self.assertRaisesRegex(NatsError, "recovering"):
            await claims.open(js)

        assert await claims.claim(42)
        assert js.create_key_value.await_count == 2

    async def test_reset(self) -> None:
        """Verify disconnect cleanup invalidates all JetStream handles."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.js = AsyncMock()
        claims.kv = AsyncMock()

        claims.reset()

        assert claims.js is None
        assert claims.kv is None
        assert not claims.ready


class KVStoreTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bucket handles and the channel, presence, and session stores."""

    async def test_open_reuses_bucket(self) -> None:
        """Reuse an open bucket when the JetStream context is unchanged."""
        store = KVStore("test", 1, 60)
        js = AsyncMock()
        kv = AsyncMock()
        js.create_key_value.return_value = kv

        assert await store.open(js) is kv
        assert await store.open(js) is kv
        js.create_key_value.assert_awaited_once()

    async def test_retune_matches_created_duplicate_window(self) -> None:
        """Retune a bucket to the duplicate window nats-py creates it with.

        That is two minutes, or the TTL when it is shorter.
        """
        for ttl, window in ((0, 120), (15, 15)):
            store = KVStore("test", 1, ttl)
            js = AsyncMock()
            kv = AsyncMock()
            js.create_key_value.side_effect = [BadRequestError(), kv]
            js.stream_info.return_value = SimpleNamespace(
                config=StreamConfig(name="KV_test", max_age=3600, duplicate_window=60),
            )

            with self.subTest(ttl=ttl):
                assert await store.open(js) is kv
                updated = js.update_stream.await_args.args[0]
                assert updated.max_age == ttl
                assert updated.duplicate_window == window

    async def test_retune_keeps_matching_ttl(self) -> None:
        """Leave a bucket whose TTL matches; creating it fails as it did first."""
        store = KVStore("test", 1, 60)
        js = AsyncMock()
        error = BadRequestError(description="replicas cannot be updated")
        js.create_key_value.side_effect = error
        js.stream_info.return_value = SimpleNamespace(
            config=StreamConfig(name="KV_test", max_age=60, duplicate_window=60),
        )

        with self.assertRaises(BadRequestError) as raised:
            await store.open(js)

        assert raised.exception is error
        assert js.create_key_value.await_count == 2
        js.update_stream.assert_not_awaited()
        assert not store.ready

    async def test_open_reports_create_failure_without_bucket(self) -> None:
        """Raise the creation error, not the lookup's, when no bucket exists."""
        store = KVStore("test", 1, 60)
        js = AsyncMock()
        error = BadRequestError(description="invalid stream configuration")
        js.create_key_value.side_effect = error
        js.stream_info.side_effect = NotFoundError()

        with self.assertRaises(BadRequestError) as raised:
            await store.open(js)

        assert raised.exception is error
        js.stream_info.assert_awaited_once_with("KV_test")
        assert not store.ready

    async def test_presence_delete_uses_owned_revision(self) -> None:
        """Delete only the case-insensitive presence revision this process owns."""
        presence = PresenceStore("efnet", 1, 15, SECRET)
        presence.kv = AsyncMock()
        presence.kv.delete.return_value = True

        await presence.delete("Alpha", 8, "one")

        presence.kv.delete.assert_awaited_once_with("alpha", last=8)

    async def test_presence_delete_retries_at_current_revision(self) -> None:
        """Delete this instance's newer record when the owned revision is stale."""
        presence, kv = await stale_presence("inst")

        await presence.delete("Alpha", 1, "inst")

        assert not kv.entries

    async def test_presence_delete_keeps_another_instance(self) -> None:
        """Leave the key to another instance whose record replaced this one."""
        presence, kv = await stale_presence("other")

        await presence.delete("Alpha", 1, "inst")

        assert "alpha" in kv.entries

    async def test_presence_update_uses_owned_revision(self) -> None:
        """Refresh presence under its owned revision and report a lost race."""
        presence = PresenceStore("efnet", 1, 15, SECRET)
        presence.kv = AsyncMock()
        presence.kv.update.return_value = 9
        data = {
            "bot_id": "Alpha",
            "host": "host",
            "instance_id": "one",
            "nick": "Alpha",
            "user": "user",
        }

        assert await presence.update("Alpha", data, 8) == 9
        key, value = presence.kv.update.await_args.args
        assert key == "alpha"
        assert presence.kv.update.await_args.kwargs == {"last": 8}
        assert presence.valid("alpha", json.loads(value))

        presence.kv.update.side_effect = KeyWrongLastSequenceError()
        assert await presence.update("Alpha", data, 8) is None

    async def test_channel_put_creates_missing_record(self) -> None:
        """Create the first record for a channel, signed, and return it as written."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.side_effect = KeyNotFoundError()
        channels.kv.create.return_value = 1
        record = channel_record(1)
        unsigned = {k: v for k, v in record.items() if k != "signature"}

        assert await channels.put(unsigned, after=None) == channel_fields(1)
        key, value = channels.kv.create.await_args.args
        assert key == channels.key("#test")
        assert json.loads(value) == record

    async def test_channel_put_rejects_injected_fields(self) -> None:
        """Refuse, before any write, a channel or key that could inject IRC."""
        channels = ChannelStore("efnet", 1, SECRET)
        kv = FakeKV()
        channels.kv = cast("KeyValue", kv)
        injected: dict[str, dict[str, object]] = {
            "CR in channel": {"channel": "#test\rQUIT"},
            "LF in channel": {"channel": "#test\nQUIT"},
            "space in channel": {"channel": "#test QUIT"},
            "NUL in channel": {"channel": "#test\x00"},
            "CR in key": {"key": "secret\rQUIT"},
            "LF in key": {"key": "secret\nQUIT"},
            "space in key": {"key": "secret QUIT"},
            "NUL in key": {"key": "secret\x00"},
        }
        for label, change in injected.items():
            with self.subTest(label), self.assertRaises(ValueError):
                await channels.put({**channel_record(1), **change}, after=None)

        assert kv.entries == {}

    async def test_channel_parse_binds_record_to_key(self) -> None:
        """Reject a valid channel record stored under another channel's key."""
        channels = ChannelStore("efnet", 1, SECRET)
        record = channel_record(1)

        assert channels.parse(channels.key("#test"), record) is not None
        assert channels.parse(channels.key("#other"), record) is None

    async def test_channel_parse_rejects_forged_and_unsigned(self) -> None:
        """Reject channel records lacking a valid coordination-secret signature."""
        channels = ChannelStore("efnet", 1, SECRET)
        key = channels.key("#test")
        record = channel_record(1)

        unsigned = {k: v for k, v in record.items() if k != "signature"}
        assert channels.parse(key, unsigned) is None

        forged = {**record, "signature": "0" * SHA256_HEX_LENGTH}
        assert channels.parse(key, forged) is None

        # Rejected by shape, before a non-ASCII signature can reach the digest
        # comparison, which raises on one.
        non_ascii = {**record, "signature": "é" * SHA256_HEX_LENGTH}
        assert channels.parse(key, non_ascii) is None

        # A record signed with a different coordination secret is rejected.
        attacker_record: dict[str, object] = {
            "channel": "#test",
            "key": "hijacked",
            "present": True,
            "revision": f"{9:020d}-{'0' * 32}",
        }
        attacker_record["signature"] = channel_signature(
            OTHER_SECRET,
            "efnet",
            attacker_record,
        )
        assert channels.parse(key, attacker_record) is None

    async def test_channel_parse_rejects_malformed_records(self) -> None:
        """Reject, without raising, records whose fields have the wrong shape."""
        channels = ChannelStore("efnet", 1, SECRET)
        key = channels.key("#test")
        # Signed with no key and present=True, so a dropped field or a 1 for
        # True would still match the signature.
        record = channel_record(1)
        assert channels.parse(key, record) is not None

        malformed: dict[str, dict[str, object]] = {
            "non-string channel": {**record, "channel": ["#test", "#other"]},
            "missing key": {k: v for k, v in record.items() if k != "key"},
            "non-string key": {**record, "key": 5},
            "non-boolean presence": {**record, "present": 1},
        }
        for label, value in malformed.items():
            with self.subTest(label):
                assert channels.parse(key, value) is None

    async def test_channel_parse_rejects_unusable_key(self) -> None:
        """Reject a correctly signed record whose channel key IRC cannot use."""
        channels = ChannelStore("efnet", 1, SECRET)
        record: dict[str, object] = {
            "channel": "#test",
            "key": "bad key",
            "present": True,
            "revision": f"{1:020d}-{'0' * 32}",
        }
        record["signature"] = channel_signature(SECRET, "efnet", record)

        assert channels.parse(channels.key("#test"), record) is None

    async def test_channel_signature_covers_every_field(self) -> None:
        """Detect tampering with any signed field or the network after signing."""
        channels = ChannelStore("efnet", 1, SECRET)
        key = channels.key("#test")
        signed = channels.sign(("#test", "secret", True, channel_revision(1)))
        assert channels.parse(key, signed) is not None
        assert channels.parse(key, {**signed, "key": "swapped"}) is None
        assert channels.parse(key, {**signed, "present": False}) is None
        assert channels.parse(key, {**signed, "revision": channel_revision(2)}) is None
        # Copied under the other channel's key, so key binding cannot mask it.
        moved = {**signed, "channel": "#other"}
        assert channels.parse(channels.key("#other"), moved) is None
        assert ChannelStore("undernet", 1, SECRET).parse(key, signed) is None

    async def test_channel_put_yields_to_concurrent_writer(self) -> None:
        """Return another bot's record when it lands between our read and write."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        concurrent = channel_record(2)
        channels.kv.get.side_effect = (
            SimpleNamespace(revision=7, value=json.dumps(channel_record(1)).encode()),
            SimpleNamespace(revision=8, value=json.dumps(concurrent).encode()),
        )
        channels.kv.update.side_effect = KeyWrongLastSequenceError()

        stored = await channels.put(
            channel_record(3),
            after=channel_revision(1),
        )

        assert stored == channel_fields(2)
        channels.kv.update.assert_awaited_once()

    async def test_channel_put_yields_to_racing_create(self) -> None:
        """Yield to a racing writer that created the record first."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        racer = channel_record(1)
        channels.kv.get.side_effect = (
            KeyNotFoundError(),
            SimpleNamespace(revision=7, value=json.dumps(racer).encode()),
        )
        channels.kv.create.side_effect = KeyWrongLastSequenceError()

        stored = await channels.put(channel_record(2), after=None)

        assert stored == channel_fields(1)
        channels.kv.create.assert_awaited_once()
        channels.kv.update.assert_not_awaited()

    async def test_channel_put_rejects_same_number_from_stale_base(self) -> None:
        """Keep another bot's same-numbered record whatever the random suffix."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        theirs = channel_record(2)
        channels.kv.get.return_value = SimpleNamespace(
            revision=7,
            value=json.dumps(theirs).encode(),
        )
        # Ours has the same counter and a suffix that sorts higher, so the old
        # revision tie-break would have let it overwrite theirs.
        ours = {**channel_record(2), "revision": f"{2:020d}-{'f' * 32}"}

        stored = await channels.put(
            ours,
            after=channel_revision(1),
        )

        assert stored == channel_fields(2)
        channels.kv.update.assert_not_awaited()

    async def test_channel_put_replaces_rolled_back_record(self) -> None:
        """Replace a signed record older than the one the write follows.

        A NATS writer without the coordination secret can replay an earlier
        signed record; honoring it would supersede every later write.
        """
        channels = ChannelStore("efnet", 1, SECRET)
        kv = FakeKV()
        channels.kv = cast("KeyValue", kv)
        key = channels.key("#test")
        kv.store(key, json.dumps(channel_record(1)).encode())

        stored = await channels.put(channel_record(3), after=channel_revision(2))

        assert stored == channel_fields(3)
        assert json.loads(kv.entries[key][1]) == channel_record(3)

    async def test_put_newer_bounds_lost_create_races(self) -> None:
        """Count lost create races toward the same CAS attempt bound."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.side_effect = KeyNotFoundError()
        channels.kv.create.side_effect = KeyWrongLastSequenceError()

        with self.assertRaisesRegex(NatsError, "update races"):
            await channels.put(channel_record(1), after=None)

        assert channels.kv.create.await_count == CAS_ATTEMPT_LIMIT

    async def test_put_newer_bounds_lost_cas_races(self) -> None:
        """Raise for the caller's retry path after repeated lost CAS races."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.return_value = SimpleNamespace(
            revision=7,
            value=json.dumps(channel_record(1)).encode(),
        )
        channels.kv.update.side_effect = KeyWrongLastSequenceError()

        with self.assertRaisesRegex(NatsError, "update races"):
            await channels.put(
                channel_record(2),
                after=channel_revision(1),
            )

        assert channels.kv.update.await_count == CAS_ATTEMPT_LIMIT

    async def test_session_revocation_wins_equal_expiry_and_version(self) -> None:
        """Order a revocation over an active session that ties on everything else."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        sessions.kv = AsyncMock()
        expires_at = time.time() + 40
        revocation = session_record(expires_at, 1, revoked=True)
        active = session_record(expires_at, 1, revoked=False)
        sessions.kv.get.return_value = SimpleNamespace(
            revision=7,
            value=json.dumps(revocation).encode(),
        )

        assert await sessions.put(active) == parsed_session(revocation)
        sessions.kv.update.assert_not_awaited()

        sessions.kv.get.return_value = SimpleNamespace(
            revision=8,
            value=json.dumps(active).encode(),
        )
        sessions.kv.update.return_value = 9

        assert await sessions.put(revocation) == parsed_session(revocation)

        sessions.kv.update.assert_awaited_once()

    async def test_session_horizon_ends_one_ttl_plus_grace_away(self) -> None:
        """Accept a record expiring exactly at the horizon and refuse a later one."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        kv = FakeKV()
        sessions.kv = cast("KeyValue", kv)
        key = sessions.key("owner!user@host")
        now = 1_000_000.0
        edge = session_record(now + 60 + SESSION_EXPIRY_GRACE)
        future = session_record(now + 60 + SESSION_EXPIRY_GRACE + 1)

        with patch("botnats.nats.store.time") as clock:
            clock.time.return_value = now
            assert sessions.parse(key, future) is None
            with self.assertRaisesRegex(ValueError, SESSION_INVALID):
                await sessions.put(future)

            assert kv.entries == {}
            assert sessions.parse(key, edge) == parsed_session(edge)
            assert await sessions.put(edge) == parsed_session(edge)

        assert list(kv.entries) == [key]

    async def test_session_signature_covers_every_field(self) -> None:
        """Refuse a record whose signed fields changed or whose signature is bad."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        kv = FakeKV()
        sessions.kv = cast("KeyValue", kv)
        expiry = time.time() + 30
        valid = session_record(expiry, 1, revoked=True)
        other_network = {k: v for k, v in valid.items() if k != "signature"}
        other_network["signature"] = session_signature(SECRET, "undernet", valid)
        assert parse_session_record(SECRET, "undernet", other_network) is not None
        # Each record differs from the valid revocation in one field alone, and
        # every changed value is well-formed, so only the signature rejects it.
        invalid: dict[str, dict[str, object]] = {
            "prefix changed": {**valid, "prefix": "other!user@host"},
            "issuer changed": {**valid, "issuer": "beta"},
            "expiry extended": {**valid, "expires_at": expiry + 10},
            "version raised": {**valid, "version": 2},
            "revoked flag removed": {k: v for k, v in valid.items() if k != "revoked"},
            "revoked flag changed": {**valid, "revoked": False},
            "signed for another network": other_network,
            "forged signature": {**valid, "signature": "0" * SHA256_HEX_LENGTH},
            # Rejected by shape, before a non-ASCII signature can reach the
            # digest comparison, which raises on one.
            "non-ASCII signature": {**valid, "signature": "é" * SHA256_HEX_LENGTH},
            "unsigned": {k: v for k, v in valid.items() if k != "signature"},
            # Too large for float(), so it cannot be signed or ordered.
            "overflowing expiry": {**valid, "expires_at": 10**400},
        }
        for label, record in invalid.items():
            # The record's own key, so key binding cannot mask a bad signature.
            key = sessions.key(str(record["prefix"]))
            with self.subTest(label):
                assert parse_session_record(SECRET, "efnet", record) is None
                assert sessions.parse(key, record) is None
                with self.assertRaisesRegex(ValueError, SESSION_INVALID):
                    await sessions.put(record)

        assert kv.entries == {}
        key = sessions.key("owner!user@host")
        assert sessions.parse(key, valid) == parsed_session(valid)
        assert await sessions.put(valid) == parsed_session(valid)

    async def test_session_parse_rejects_malformed_signed_fields(self) -> None:
        """Reject a correctly signed record whose fields have the wrong shape."""
        valid = session_record(time.time() + 30)
        malformed: dict[str, dict[str, object]] = {
            "negative version": {"version": -1},
            "boolean version": {"version": True},
            "boolean expiry": {"expires_at": True},
            "empty issuer": {"issuer": ""},
            "empty prefix": {"prefix": ""},
        }
        for label, change in malformed.items():
            record = {**valid, **change}
            record["signature"] = session_signature(SECRET, "efnet", record)
            with self.subTest(label):
                assert parse_session_record(SECRET, "efnet", record) is None

        # Values that cannot be signed keep the valid record's well-formed
        # signature, so only the type checks stand between them and a crash.
        mistyped: dict[str, dict[str, object]] = {
            "non-string issuer": {"issuer": 5},
            "non-string prefix": {"prefix": 5},
            "non-numeric expiry": {"expires_at": "soon"},
            "non-integer version": {"version": "1"},
        }
        for label, change in mistyped.items():
            record = {**valid, **change}
            with self.subTest(label):
                assert parse_session_record(SECRET, "efnet", record) is None

    async def test_session_parse_binds_record_to_key(self) -> None:
        """Reject a signed session stored under another identity's key."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        key = sessions.key("owner!user@host")
        current = session_record(time.time() + 60)

        assert sessions.parse(key, current) is not None
        assert sessions.parse(sessions.key("other!user@host"), current) is None

    async def test_session_parse_rejects_non_finite_expiry(self) -> None:
        """Reject a correctly signed record whose expiry is NaN or infinite."""
        sessions = SessionStore("efnet", 1, SECRET, 60)

        for expiry in (math.nan, math.inf, -math.inf):
            with self.subTest(expiry=expiry):
                record = session_record(expiry)
                assert sessions.parse(sessions.key("owner!user@host"), record) is None

        record = session_record(time.time() + 30)
        assert sessions.parse(sessions.key("owner!user@host"), record) is not None

    async def test_malformed_ordering_records_are_replaced(self) -> None:
        """Prevent malformed durable values from blocking valid replacements."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        malformed_channel = {**channel_record(1), "revision": "zzzz"}
        channels.kv.get.return_value = SimpleNamespace(
            revision=1,
            value=json.dumps(malformed_channel).encode(),
        )
        channels.kv.update.return_value = 2

        valid_channel = channel_record(2)
        assert await channels.put(valid_channel, after=None) == channel_fields(2)
        channels.kv.update.assert_awaited_once()

        sessions = SessionStore("efnet", 1, SECRET, 60)
        sessions.kv = AsyncMock()
        impossible = session_record(time.time() + 1_000_000, 1, revoked=True)
        sessions.kv.get.return_value = SimpleNamespace(
            revision=1,
            value=json.dumps(impossible).encode(),
        )
        sessions.kv.update.return_value = 2

        valid_session = session_record(time.time() + 40, 0, revoked=False)
        assert await sessions.put(valid_session) == parsed_session(valid_session)
        sessions.kv.update.assert_awaited_once()

    async def test_oversized_json_integer_is_replaced(self) -> None:
        """Prevent Python's integer limit from blocking valid replacements."""
        oversized = SimpleNamespace(
            revision=1,
            value=b'{"revision":' + b"9" * 5_000 + b"}",
        )
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.return_value = oversized
        channels.kv.update.return_value = 2

        valid_channel = channel_record(2)
        assert await channels.put(valid_channel, after=None) == channel_fields(2)
        channels.kv.update.assert_awaited_once()

        sessions = SessionStore("efnet", 1, SECRET, 60)
        sessions.kv = AsyncMock()
        sessions.kv.get.return_value = oversized
        sessions.kv.update.return_value = 2

        valid_session = session_record(time.time() + 40)
        assert await sessions.put(valid_session) == parsed_session(valid_session)
        sessions.kv.update.assert_awaited_once()

    async def test_decode_record_rejects_non_objects_and_deep_nesting(self) -> None:
        """Decode only JSON objects; nesting too deep to parse is malformed."""
        assert decode_record(b'{"present": true}') == {"present": True}
        assert decode_record(b"[1]") is None

        # The parser overflows only past the native stack, a depth that varies
        # by platform, so raise its RecursionError directly. Only the store's
        # binding is patched, not the process-wide json.loads.
        with patch("botnats.nats.store.json") as parser:
            parser.loads.side_effect = RecursionError(
                "maximum recursion depth exceeded"
            )
            assert decode_record(b"[[]]") is None

        parser.loads.assert_called_once_with(b"[[]]")

    async def test_state_keys_do_not_depend_on_irc_casemapping(self) -> None:
        """Keep RFC1459-only equivalents in distinct durable KV entries."""
        channels = ChannelStore("efnet", 1, SECRET)
        sessions = SessionStore("efnet", 1, SECRET, 60)

        assert channels.key("#room[") != channels.key("#room{")
        assert channels.key("#ROOM[") == channels.key("#room[")
        assert channels.key("#straße") != channels.key("#strasse")
        assert channels.key("#Été") != channels.key("#été")
        assert sessions.key("Nick[!user@host") != sessions.key("Nick{!user@host")
        assert sessions.key("NICK[!user@host") == sessions.key("nick[!user@host")
        assert sessions.key("Straße!user@host") != sessions.key(
            "strasse!user@host",
        )
        assert sessions.key("Été!user@host") != sessions.key("été!user@host")

    async def test_channel_and_session_keys_are_secret_derived(self) -> None:
        """Key records by a digest of the coordination secret, never the raw name."""
        channel_key = ChannelStore("efnet", 1, SECRET).key("#test")
        session_key = SessionStore("efnet", 1, SECRET, 60).key("owner!user@host")

        for key in (channel_key, session_key):
            assert re.fullmatch("[0-9a-f]{64}", key) is not None

        assert channel_key != ChannelStore("efnet", 1, OTHER_SECRET).key("#test")
        assert session_key != SessionStore("efnet", 1, OTHER_SECRET, 60).key(
            "owner!user@host",
        )

    async def test_session_parse_rejects_unencodable_identity(self) -> None:
        """Reject, without raising, a record with an unencodable prefix or issuer."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        prefix = "owner!user@" + chr(0xD800)
        record = {
            "expires_at": time.time() + 30,
            "issuer": "alpha",
            "prefix": prefix,
            "revoked": False,
            "signature": "0" * SHA256_HEX_LENGTH,
            "version": 0,
        }

        assert sessions.parse("opaque", record) is None
        bad_issuer = {**record, "prefix": "owner!user@host", "issuer": chr(0xD800)}
        assert sessions.parse("opaque", bad_issuer) is None

    async def test_reset_during_open(self) -> None:
        """Do not restore a stale bucket handle after a disconnect."""
        store = KVStore("test", 1, 60)
        started = asyncio.Event()
        release = asyncio.Event()

        async def create_key_value(config: object) -> AsyncMock:
            del config
            started.set()
            await release.wait()
            return AsyncMock()

        js = AsyncMock()
        js.create_key_value.side_effect = create_key_value
        task = asyncio.create_task(store.open(js))
        async with asyncio.timeout(1):
            await started.wait()

        store.reset()
        release.set()

        with self.assertRaisesRegex(StoreUnavailableError, "changed while opening"):
            async with asyncio.timeout(1):
                await task

        assert store.js is None
        assert store.kv is None
