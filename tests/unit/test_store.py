# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for JetStream key-value store lifecycle and TOTP counter claims."""

import asyncio
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from nats.errors import Error as NatsError
from nats.js.errors import KeyNotFoundError, KeyWrongLastSequenceError

from botnats.nats.store import (
    ATTEMPT_LIMIT,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    KVStore,
    PresenceStore,
    SessionStore,
    presence_signature,
    session_signature,
)
from tests.unit.helpers import COORDINATION_KEY as SECRET

EXPECTED_CREATE_CALLS = 2
EXPECTED_OPEN_CALLS = 2
LATEST_REVISION = 8
SHA256_HEX_LENGTH = 64


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


class PresenceReclaimTests(unittest.IsolatedAsyncioTestCase):
    """Tests for reclaiming an occupied presence key after reconnect."""

    async def test_reclaim_adopts_own_record(self) -> None:
        """Adopt the key without a write when this instance signed it."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        owned = signed_presence("inst")
        entry = SimpleNamespace(
            revision=LATEST_REVISION,
            value=json.dumps(owned).encode(),
        )
        kv = AsyncMock()
        kv.get = AsyncMock(return_value=entry)
        store.kv = kv

        assert await store.reclaim("Alpha", owned, "inst") == LATEST_REVISION
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
        """Overwrite an unsigned clobber; yield when the key is already gone."""
        store = PresenceStore("efnet", 1, 15.0, SECRET)
        data = signed_presence("inst")
        reclaimed_revision = 6
        kv = AsyncMock()
        store.kv = kv

        kv.get = AsyncMock(
            return_value=SimpleNamespace(revision=5, value=b'{"garbage": true}'),
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

        kv.get = AsyncMock(side_effect=KeyNotFoundError())
        assert await store.reclaim("Alpha", data, "inst") is None

    def test_valid_rejects_stale_and_uncrashable(self) -> None:
        """Reject stale replays and surrogate injection without raising."""
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
        assert store.valid(fresh, now=now)

        stale = dict(fresh)
        stale["timestamp"] = int(now - 1000)
        stale["signature"] = presence_signature(SECRET, "efnet", stale)
        assert not store.valid(stale, now=now)

        surrogate = {
            "bot_id": "alpha",
            "host": "\ud800",
            "instance_id": "inst",
            "nick": "alpha",
            "user": "user",
            "timestamp": int(now),
            "signature": "0" * SHA256_HEX_LENGTH,
        }
        assert not store.valid(surrogate, now=now)

        non_ascii_signature = {**fresh, "signature": "ñ" * SHA256_HEX_LENGTH}
        assert not store.valid(non_ascii_signature, now=now)


def channel_record(revision: int) -> dict[str, object]:
    """Build a valid durable channel record with a sortable revision."""
    return {
        "channel": "#test",
        "key": None,
        "present": True,
        "revision": f"{revision:020d}-{'0' * 32}",
    }


def session_record(
    expires_at: float,
    version: int,
    *,
    revoked: bool,
) -> dict[str, object]:
    """Build a valid signed durable session record."""
    record: dict[str, object] = {
        "expires_at": expires_at,
        "issuer": "alpha",
        "prefix": "owner!user@host",
        "revoked": revoked,
        "version": version,
    }
    record["signature"] = session_signature(SECRET, "efnet", record)
    return record


class AttemptStoreTests(unittest.IsolatedAsyncioTestCase):
    """Tests for fail-closed mesh-wide authentication limits."""

    async def test_allows_available_slot(self) -> None:
        """Verify the first available atomic slot permits an attempt."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = [
            KeyWrongLastSequenceError(),
            None,
        ]

        assert await attempts.allow("host.example", now=60)
        assert attempts.kv.create.await_count == EXPECTED_CREATE_CALLS

    async def test_denies_after_limit(self) -> None:
        """Verify a full attempt window denies another authentication attempt."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = KeyWrongLastSequenceError()

        assert not await attempts.allow("host.example", now=60)
        assert attempts.kv.create.await_count == ATTEMPT_LIMIT

    async def test_error_fails_closed(self) -> None:
        """Verify unavailable JetStream denies authentication."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = KeyNotFoundError()
        attempts.kv.create.side_effect = NatsError("unavailable")

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await attempts.allow("host.example", now=60)
        assert not attempts.ready

    async def test_keys_hide_identity(self) -> None:
        """Verify persisted attempt keys do not expose the IRC identity."""
        attempts = AttemptStore("efnet", 3, SECRET)

        key = attempts.key("host.example", 0)

        assert "host" not in key
        assert len(key) == SHA256_HEX_LENGTH

    async def test_missing_store_fails_closed(self) -> None:
        """Verify authentication is denied until the bucket is open."""
        attempts = AttemptStore("efnet", 3, SECRET)

        assert not await attempts.allow("host.example", now=60)

    async def test_sliding_window_reuses_expired_slot(self) -> None:
        """Verify an expired slot is atomically reused."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.return_value = MagicMock(
            revision=7,
            value=float(0).hex().encode(),
        )

        assert await attempts.allow("host.example", now=61)
        attempts.kv.update.assert_awaited_once_with(
            attempts.key("host.example", 0),
            float(61).hex().encode(),
            last=7,
        )

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

    async def test_sliding_window_denies_at_boundary(self) -> None:
        """Verify three recent attempts deny immediately across a boundary."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(value=float(59).hex().encode()),
            MagicMock(value=(59.5).hex().encode()),
            MagicMock(value=(59.9).hex().encode()),
        ]

        assert not await attempts.allow("host.example", now=60)
        attempts.kv.create.assert_not_awaited()

    async def test_clock_skew_counts_future_bucket(self) -> None:
        """Verify attempts by a faster peer count for a slower peer."""
        attempts = AttemptStore("efnet", 3, SECRET)
        attempts.kv = AsyncMock()
        attempts.kv.get.side_effect = [
            MagicMock(value=float(61).hex().encode()),
            MagicMock(value=(61.1).hex().encode()),
            MagicMock(value=(61.2).hex().encode()),
        ]

        assert not await attempts.allow("host.example", now=59)
        attempts.kv.create.assert_not_awaited()

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
        attempts.kv.create.assert_not_awaited()


class ClaimStoreTests(unittest.IsolatedAsyncioTestCase):
    """Tests for fail-closed JetStream TOTP claims."""

    async def test_claim(self) -> None:
        """Verify a valid counter uses a secret-derived key."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()

        assert await claims.claim(42)

        key = claims.key(42)
        assert key != "42"
        assert len(key) == SHA256_HEX_LENGTH
        assert claims.ready
        claims.kv.create.assert_awaited_once_with(key, b"1")

    async def test_duplicate(self) -> None:
        """Verify a duplicate counter fails closed."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()
        claims.kv.create.side_effect = KeyWrongLastSequenceError()

        assert not await claims.claim(42)

    async def test_error(self) -> None:
        """Verify unavailable JetStream fails closed."""
        claims = ClaimStore("efnet", 3, SECRET)
        claims.kv = AsyncMock()
        claims.kv.create.side_effect = NatsError("unavailable")

        with self.assertLogs("botnats.nats.store", level="WARNING"):
            assert not await claims.claim(42)
        assert not claims.ready

    async def test_missing_store(self) -> None:
        """Verify a claim is denied until the bucket is open."""
        claims = ClaimStore("efnet", 3, SECRET)

        assert not await claims.claim(42)
        assert not claims.ready

    async def test_reopen_after_error(self) -> None:
        """Verify a claim retries opening KV after reconnect initialization fails."""
        claims = ClaimStore("efnet", 3, SECRET)
        js = AsyncMock()
        js.create_key_value.side_effect = [NatsError("recovering"), AsyncMock()]

        with self.assertRaisesRegex(NatsError, "recovering"):
            await claims.open(js)

        assert await claims.claim(42)
        assert js.create_key_value.await_count == EXPECTED_OPEN_CALLS

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
    """Tests for KV handle reuse and disconnect races."""

    async def test_open_reuses_bucket(self) -> None:
        """Reuse an open bucket when the JetStream context is unchanged."""
        store = KVStore("test", 1, 60)
        js = AsyncMock()
        kv = AsyncMock()
        js.create_key_value.return_value = kv

        assert await store.open(js) is kv
        assert await store.open(js) is kv
        js.create_key_value.assert_awaited_once()

    async def test_presence_delete_uses_owned_revision(self) -> None:
        """Delete only the case-insensitive presence revision this process owns."""
        presence = PresenceStore("efnet", 1, 15, SECRET)
        presence.kv = AsyncMock()

        await presence.delete("Alpha", LATEST_REVISION)

        presence.kv.delete.assert_awaited_once_with("alpha", last=LATEST_REVISION)

    async def test_channel_put_keeps_highest_revision(self) -> None:
        """Prevent a delayed channel write from replacing newer durable state."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        current = channel_record(2)
        channels.kv.get.return_value = SimpleNamespace(
            revision=7,
            value=json.dumps(current).encode(),
        )

        stored = await channels.put("#test", channel_record(1))

        assert stored == current
        channels.kv.update.assert_not_awaited()

    async def test_channel_order_binds_record_to_key(self) -> None:
        """Reject a valid channel record stored under another channel's key."""
        channels = ChannelStore("efnet", 1, SECRET)
        record = channel_record(1)

        assert channels.order(channels.key("#test"), record) is not None
        assert channels.order(channels.key("#other"), record) is None

    async def test_channel_put_retries_cas_conflict(self) -> None:
        """Retry a newer channel write after another writer wins the CAS."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.side_effect = (
            SimpleNamespace(revision=7, value=json.dumps(channel_record(1)).encode()),
            SimpleNamespace(revision=8, value=json.dumps(channel_record(2)).encode()),
        )
        channels.kv.update.side_effect = (KeyWrongLastSequenceError(), None)

        incoming = channel_record(3)
        assert await channels.put("#test", incoming) == incoming

        assert channels.kv.update.await_count == EXPECTED_OPEN_CALLS
        assert channels.kv.update.await_args_list[1].kwargs["last"] == LATEST_REVISION

    async def test_session_revocation_wins_equal_expiry(self) -> None:
        """Prevent a delayed active session from replacing its revocation."""
        sessions = SessionStore("efnet", 1, SECRET, 60)
        sessions.kv = AsyncMock()
        expires_at = time.time() + 40
        revocation = session_record(expires_at, 1, revoked=True)
        sessions.kv.get.return_value = SimpleNamespace(
            revision=7,
            value=json.dumps(revocation).encode(),
        )

        stored = await sessions.put(
            "owner!user@host",
            session_record(expires_at, 0, revoked=False),
        )

        assert stored == revocation
        sessions.kv.update.assert_not_awaited()
        active = session_record(expires_at, 0, revoked=False)
        sessions.kv.get.return_value = SimpleNamespace(
            revision=8,
            value=json.dumps(active).encode(),
        )

        assert await sessions.put("owner!user@host", revocation) == revocation

        sessions.kv.update.assert_awaited_once()

    async def test_malformed_ordering_records_are_replaced(self) -> None:
        """Prevent malformed durable values from blocking valid replacements."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        malformed_channel = {**channel_record(1), "revision": "zzzz"}
        channels.kv.get.return_value = SimpleNamespace(
            revision=1,
            value=json.dumps(malformed_channel).encode(),
        )

        valid_channel = channel_record(2)
        assert await channels.put("#test", valid_channel) == valid_channel
        channels.kv.update.assert_awaited_once()

        sessions = SessionStore("efnet", 1, SECRET, 60)
        sessions.kv = AsyncMock()
        impossible = session_record(time.time() + 1_000_000, 1, revoked=True)
        sessions.kv.get.return_value = SimpleNamespace(
            revision=1,
            value=json.dumps(impossible).encode(),
        )

        valid_session = session_record(time.time() + 40, 0, revoked=False)
        assert await sessions.put("owner!user@host", valid_session) == valid_session
        sessions.kv.update.assert_awaited_once()

    async def test_oversized_json_integer_is_replaced(self) -> None:
        """Prevent Python's integer limit from blocking valid replacements."""
        channels = ChannelStore("efnet", 1, SECRET)
        channels.kv = AsyncMock()
        channels.kv.get.return_value = SimpleNamespace(
            revision=1,
            value=b'{"revision":' + b"9" * 5_000 + b"}",
        )

        valid_channel = channel_record(2)
        assert await channels.put("#test", valid_channel) == valid_channel
        channels.kv.update.assert_awaited_once()

    async def test_state_keys_do_not_depend_on_irc_casemapping(self) -> None:
        """Keep RFC1459-only equivalents in distinct durable KV entries."""
        channels = ChannelStore("efnet", 1, SECRET)
        sessions = SessionStore("efnet", 1, SECRET, 60)

        assert channels.key("#room[") != channels.key("#room{")
        assert channels.key("#ROOM[") == channels.key("#room[")
        assert channels.key("#straße") != channels.key("#strasse")
        assert sessions.key("Nick[!user@host") != sessions.key("Nick{!user@host")
        assert sessions.key("NICK[!user@host") == sessions.key("nick[!user@host")
        assert sessions.key("Straße!user@host") != sessions.key(
            "strasse!user@host",
        )

    async def test_session_order_rejects_unencodable_identity(self) -> None:
        """Reject malformed Unicode before deriving its durable session key."""
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

        assert sessions.order(prefix, record) is None

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
        await started.wait()

        store.reset()
        release.set()

        with self.assertRaisesRegex(RuntimeError, "changed while opening"):
            await task
        assert store.js is None
        assert store.kv is None
