# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for coordinator envelope security and NATS integration."""

import asyncio
import json
import os
import time
import unittest
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from functools import partial
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from nats.aio.msg import Msg
from nats.js.errors import KeyWrongLastSequenceError

from botnats.channel import ChannelRecord
from botnats.nats.coordinator import WATCH_NAMES, Coordinator, NATSConfig
from botnats.nats.envelope import Envelope
from botnats.nats.store import (
    ATTEMPT_LIMIT,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    PresenceStore,
    SessionStore,
    presence_signature,
    session_signature,
)
from tests.unit.helpers import COORDINATION_KEY

if TYPE_CHECKING:
    from botnats.bot import NATSCallbackHandler

BETA_PRESENCE = {
    "bot_id": "beta",
    "host": "host",
    "instance_id": "instance",
    "nick": "beta",
    "user": "user",
}
EXPECTED_WARNING_COUNT = 2
EXPECTED_WATCH_RESTARTS = 3
EXPECTED_WRITE_ATTEMPTS = 2
OLD_INIT_RETRY_LIMIT = 10
GRANT_TIMEOUT = 1
JETSTREAM_REPLICAS = int(os.environ.get("BOTNATS_TEST_JETSTREAM_REPLICAS", "1"))
NATS_TOKEN = os.environ.get("BOTNATS_TEST_NATS_TOKEN", "integration-token")
NATS_URL = os.environ.get("BOTNATS_TEST_NATS_URL")
SUBJECT = "botnats.v1.efnet.channel"
JsonCallback = Callable[[dict[str, Any]], Awaitable[None]]


class CoordinatorEnvelopeTests(unittest.TestCase):
    """Tests for envelope signing, replay protection, and nonce pruning."""

    def test_envelope_security(self) -> None:
        """Verify envelope signing, replay rejection, and tamper detection."""
        key = COORDINATION_KEY
        sender = Envelope("alpha", key)
        receiver = Envelope("beta", key)

        encoded = sender.encode(SUBJECT, {"channel": "#test"})
        assert receiver.decode(SUBJECT, encoded) == (
            "alpha",
            {"channel": "#test"},
        )
        with self.assertRaisesRegex(ValueError, "replayed"):
            receiver.decode(SUBJECT, encoded)

        forged = json.dumps({"payload": {"channel": "#owned"}}).encode()
        with self.assertRaisesRegex(ValueError, "malformed"):
            receiver.decode(SUBJECT, forged)

        tampered = json.loads(encoded)
        tampered["nonce"] = "f" * 32
        tampered["payload"] = {"channel": "#owned"}
        with self.assertRaisesRegex(ValueError, "signature"):
            receiver.decode(SUBJECT, json.dumps(tampered).encode())

    def test_nonce_pruning(self) -> None:
        """Verify expired nonces are pruned from the seen set."""
        receiver = Envelope("beta", COORDINATION_KEY)
        live = time.time() + 60
        receiver.seen_nonces["a" * 32] = 1.0
        receiver.seen_nonces["b" * 32] = 2.0
        receiver.seen_nonces["c" * 32] = live

        receiver.prune_nonces()

        assert receiver.seen_nonces == {"c" * 32: live}

    def test_subject_substitution(self) -> None:
        """Verify a signed message cannot be moved to another NATS subject."""
        key = COORDINATION_KEY
        sender = Envelope("alpha", key)
        receiver = Envelope("beta", key)
        encoded = sender.encode(SUBJECT, {"channel": "#test"})

        with self.assertRaisesRegex(ValueError, "subject"):
            receiver.decode("botnats.v1.efnet.auth.session", encoded)


def accept_offer(payload: dict[str, Any]) -> bool:
    """Accept all offer requests."""
    del payload
    return True


@dataclass
class Fixtures:
    """Shared mutable state for coordinator integration tests."""

    events: dict[str, asyncio.Event] = field(default_factory=dict)
    session_deletes: list[str] = field(default_factory=list)


def build_coordinator(
    bot_id: str,
    fixtures: Fixtures,
    network: str = "efnet",
) -> Coordinator:
    """Build a coordinator wired to shared test fixtures."""

    def on_session_delete(prefix: str) -> None:
        """Record session deletion events."""
        fixtures.session_deletes.append(prefix)

    is_alpha = bot_id == "alpha"
    callbacks = cast(
        "NATSCallbackHandler",
        SimpleNamespace(
            on_channel=noop_callback,
            on_invite_grant=noop_callback,
            on_invite_request=reject_offer,
            on_op_grant=event_callback(fixtures, "op") if is_alpha else noop_callback,
            on_op_request=accept_offer if is_alpha else reject_offer,
            on_presence=noop_sync,
            on_presence_delete=noop_sync,
            on_session_delete=on_session_delete,
            on_session_update=noop_sync,
            on_unban_grant=event_callback(fixtures, "unban")
            if is_alpha
            else noop_callback,
            on_unban_request=accept_offer if is_alpha else reject_offer,
        ),
    )
    return Coordinator(
        callbacks=callbacks,
        config=NATSConfig(
            instance_id=uuid.uuid4().hex,
            monitor_port=8222,
            network=network,
            presence_ttl=15.0,
            replicas=JETSTREAM_REPLICAS,
            servers=(NATS_URL or "",),
            session_ttl=300.0,
            token=NATS_TOKEN,
        ),
        envelope=Envelope(bot_id, COORDINATION_KEY),
    )


def event_callback(fixtures: Fixtures, name: str) -> JsonCallback:
    """Return a callback that sets the named event."""

    async def handler(payload: dict[str, Any]) -> None:
        """Signal the event."""
        del payload
        fixtures.events[name].set()

    return handler


async def noop_callback(payload: dict[str, Any]) -> None:
    """Accept and ignore any payload."""
    del payload


def noop_sync(value: object) -> None:
    """Synchronous no-op for KV watch callbacks."""
    del value


def presence_entry(*, signed: bool = True) -> SimpleNamespace:
    """Build a conflicting alpha presence watch entry."""
    record: dict[str, object] = {
        "bot_id": "alpha",
        "host": "host",
        "instance_id": "other-instance",
        "nick": "alpha",
        "user": "user",
        "timestamp": int(time.time()),
    }
    if signed:
        record["signature"] = presence_signature(COORDINATION_KEY, "efnet", record)
    return SimpleNamespace(
        key="alpha",
        operation="PUT",
        revision=1,
        value=json.dumps(record).encode(),
    )


def session_record(expires_at: float) -> dict[str, object]:
    """Build a signed session watch record."""
    record: dict[str, object] = {
        "expires_at": expires_at,
        "issuer": "alpha",
        "prefix": "owner!user@host",
        "revoked": False,
        "version": 0,
    }
    record["signature"] = session_signature(COORDINATION_KEY, "efnet", record)
    return record


def watcher(*entries: object) -> tuple[AsyncMock, AsyncMock]:
    """Build a KV handle and watcher yielding the given entries."""
    result = AsyncMock()
    result.__aiter__ = MagicMock(return_value=result)
    result.__anext__ = AsyncMock(side_effect=[*entries, StopAsyncIteration])
    kv = AsyncMock()
    kv.watchall = AsyncMock(return_value=result)
    return kv, result


def reject_offer(payload: dict[str, Any]) -> bool:
    """Reject all offer requests."""
    del payload
    return False


class CoordinatorUnitTests(unittest.IsolatedAsyncioTestCase):
    """Tests for coordinator boundaries that do not require live NATS."""

    async def test_offer_routes_current_response_sender(self) -> None:
        """Grant the signed sender of a current empty offer response."""
        coordinator = build_coordinator("beta", Fixtures())
        coordinator.nc = AsyncMock()
        coordinator.owns_presence = True
        reply = "_INBOX.reply"
        coordinator.nc.request.return_value = Msg(
            MagicMock(),
            subject=reply,
            data=Envelope("alpha", COORDINATION_KEY).encode(reply, {}),
        )

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            selected = await coordinator.request_offer(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

        assert selected
        subject = coordinator.nc.publish.await_args.args[0]
        assert subject.endswith(".op.grant.alpha")

    async def test_offer_response_rejects_legacy_payload(self) -> None:
        """Require the current empty offer-response payload."""
        coordinator = build_coordinator("beta", Fixtures())
        coordinator.nc = AsyncMock()
        reply = "_INBOX.reply"
        response = Msg(
            MagicMock(),
            subject=reply,
            data=Envelope("alpha", COORDINATION_KEY).encode(
                reply,
                {"bot_id": "spoofed"},
            ),
        )
        coordinator.nc.request.return_value = response

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            selected = await coordinator.request_offer(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

        assert not selected
        coordinator.nc.publish.assert_not_awaited()

    async def test_offer_grant_conflict_returns_false(self) -> None:
        """Return False when presence uniqueness is lost during the grant."""
        coordinator = build_coordinator("beta", Fixtures())
        coordinator.nc = AsyncMock()
        reply = "_INBOX.reply"
        coordinator.nc.request.return_value = Msg(
            MagicMock(),
            subject=reply,
            data=Envelope("alpha", COORDINATION_KEY).encode(reply, {}),
        )
        error = RuntimeError("duplicate bot ID: beta")

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(coordinator, "publish", AsyncMock(side_effect=error)),
        ):
            selected = await coordinator.request_offer(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

        assert not selected

    async def test_action_rejects_mismatched_sender(self) -> None:
        """Reject action payloads whose presence does not own the envelope."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = AsyncMock()
        subject = f"{coordinator.ns}.op.grant.alpha"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {
                    "channel": "#test",
                    "presence": {**BETA_PRESENCE, "bot_id": "spoofed"},
                },
            ),
        )

        with self.assertLogs("botnats.nats.coordinator", level="WARNING"):
            await coordinator.dispatch(callback, message)

        callback.assert_not_awaited()

    async def test_outgoing_action_requires_owned_presence(self) -> None:
        """Reject outgoing action and presence writes for another bot ID."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = AsyncMock()

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            selected = await coordinator.request_offer(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            await coordinator.put_presence(BETA_PRESENCE)

        assert not selected
        coordinator.nc.request.assert_not_awaited()

    async def test_callback_error_surfaces(self) -> None:
        """Verify callback defects are not mislabeled as malformed input."""
        coordinator = build_coordinator("alpha", Fixtures())
        message = Msg(
            MagicMock(),
            subject="botnats.v1.efnet.channel",
            data=coordinator.envelope.encode(
                "botnats.v1.efnet.channel",
                {
                    "channel": "#test",
                    "presence": {
                        **BETA_PRESENCE,
                        "bot_id": "alpha",
                        "nick": "alpha",
                    },
                },
            ),
        )

        async def fail(payload: dict[str, Any]) -> None:
            del payload
            msg = "callback failed"
            raise ValueError(msg)

        with self.assertRaisesRegex(ValueError, "callback failed"):
            await coordinator.dispatch(fail, message)

    async def test_close_releases_connection(self) -> None:
        """Verify shutdown releases owned presence, connection, and KV handles."""
        coordinator = build_coordinator("alpha", Fixtures())
        nc = MagicMock(is_closed=False)
        nc.close = AsyncMock()
        coordinator.nc = nc
        coordinator.owns_presence = True
        coordinator.presence_revision = 7
        for store in coordinator.stores:
            store.js = MagicMock()
            store.kv = MagicMock()

        with patch.object(
            coordinator.presence_store,
            "delete",
            AsyncMock(),
        ) as delete:
            await coordinator.close()
            await coordinator.close()

        assert coordinator.nc is None
        assert not coordinator.owns_presence
        assert coordinator.presence_revision is None
        assert not coordinator.attempts.ready
        assert not coordinator.channels_store.ready
        assert not coordinator.claims.ready
        assert not coordinator.presence_store.ready
        assert not coordinator.sessions.ready
        delete.assert_awaited_once_with("alpha", 7)
        nc.close.assert_awaited_once_with()

    async def test_disconnect_resets_stores(self) -> None:
        """Verify a Core NATS disconnect clears all store readiness."""
        coordinator = build_coordinator("alpha", Fixtures())
        for store in coordinator.stores:
            store.js = MagicMock()
            store.kv = MagicMock()

        await coordinator.on_disconnected()

        assert not coordinator.attempts.ready
        assert coordinator.attempts.js is None
        assert not coordinator.channels_store.ready
        assert coordinator.channels_store.js is None
        assert not coordinator.claims.ready
        assert coordinator.claims.js is None
        assert not coordinator.presence_store.ready
        assert coordinator.presence_store.js is None
        assert not coordinator.sessions.ready
        assert coordinator.sessions.js is None

    async def test_auth_and_claim_fail_closed_when_not_ready(self) -> None:
        """Deny attempts and claims whenever the coordinator is not ready."""
        coordinator = build_coordinator("alpha", Fixtures())
        allow = AsyncMock(return_value=True)
        claim = AsyncMock(return_value=True)

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=False)),
            patch.object(coordinator.attempts, "allow", allow),
            patch.object(coordinator.claims, "claim", claim),
        ):
            assert not await coordinator.request_auth("host.example")
            assert not await coordinator.request_claim(1)

        allow.assert_not_awaited()
        claim.assert_not_awaited()

    async def test_transient_warnings_are_rate_limited_per_context(self) -> None:
        """Throttle each context independently so a second failure still logs."""
        coordinator = build_coordinator("alpha", Fixtures())

        with self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs:
            coordinator.warn_transient("watch watch-channels failed", OSError("a"))
            coordinator.warn_transient("watch watch-channels failed", OSError("b"))
            coordinator.warn_transient("watch watch-presence failed", OSError("c"))
        # watch-channels logs once (second suppressed); watch-presence's first
        # failure is not starved by the channels throttle.
        assert len(logs.output) == EXPECTED_WARNING_COUNT
        assert any("watch-channels" in line for line in logs.output)
        assert any("watch-presence" in line for line in logs.output)

        coordinator.transient_warnings["watch watch-channels failed"] = (
            float("-inf"),
            coordinator.transient_warnings["watch watch-channels failed"][1],
        )
        with self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs:
            coordinator.warn_transient("watch watch-channels failed", OSError("d"))
        assert "suppressed 1 similar warning(s)" in logs.output[0]

    async def test_duplicate_bot_id_blocks_coordination(self) -> None:
        """Prevent a conflicting bot ID from publishing, offering, or granting."""
        coordinator = build_coordinator("alpha", Fixtures())
        # Own the presence key so the grant leg is sensitive to the unique
        # flag alone rather than being blocked by unowned presence.
        coordinator.owns_presence = True
        coordinator.unique = False
        callback = AsyncMock(return_value=True)
        subject = f"{coordinator.ns}.op.request"
        message = Msg(
            MagicMock(),
            subject=subject,
            reply="_INBOX.reply",
            data=coordinator.envelope.encode(subject, {}),
        )

        with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
            await coordinator.publish("channel", {})
        await coordinator.offer(callback, message)
        await coordinator.grant(callback, message)

        callback.assert_not_awaited()

    def test_unowned_presence_blocks_coordination(self) -> None:
        """Prevent writes until this process owns its presence key."""
        coordinator = build_coordinator("alpha", Fixtures())

        with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
            coordinator.require_unique()

        coordinator.owns_presence = True
        coordinator.require_unique()

    async def test_init_stores_generation_guard(self) -> None:
        """Verify a newer init_stores call cancels the previous retry loop."""
        coordinator = build_coordinator("alpha", Fixtures())
        nc = MagicMock(is_connected=True)
        nc.jetstream.return_value = MagicMock()
        coordinator.nc = nc
        attempts = 0

        async def fail_then_supersede(*arguments: object) -> None:
            del arguments
            nonlocal attempts
            attempts += 1
            coordinator.store_generation += 1
            msg = "unavailable"
            raise OSError(msg)

        with (
            patch.object(AttemptStore, "open", fail_then_supersede),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.init_stores()

        assert attempts == 1

    async def test_init_stores_does_not_abandon_recovery(self) -> None:
        """Keep retrying JetStream initialization beyond the former limit."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        coordinator.nc.jetstream.return_value = MagicMock()
        failures = [OSError("unavailable")] * (OLD_INIT_RETRY_LIMIT + 1)
        open_attempt = AsyncMock(side_effect=[*failures, None])
        open_store = AsyncMock()

        with (
            patch.object(AttemptStore, "open", open_attempt),
            patch.object(ChannelStore, "open", open_store),
            patch.object(ClaimStore, "open", open_store),
            patch.object(PresenceStore, "open", open_store),
            patch.object(SessionStore, "open", open_store),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()) as sleep,
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.init_stores()

        assert open_attempt.await_count == OLD_INIT_RETRY_LIMIT + 2
        assert sleep.await_count == OLD_INIT_RETRY_LIMIT + 1

    async def test_init_stores_surfaces_programming_errors(self) -> None:
        """Do not retry a programming error as though it were an outage."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        coordinator.nc.jetstream.return_value = MagicMock()

        with (
            patch.object(
                AttemptStore,
                "open",
                AsyncMock(side_effect=ValueError("bad config")),
            ),
            self.assertRaisesRegex(ValueError, "bad config"),
        ):
            await coordinator.init_stores()

    async def test_malformed_message_is_ignored(self) -> None:
        """Verify malformed wire data never reaches its callback."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = AsyncMock()
        message = Msg(MagicMock(), subject="bad", data=b"not-json")

        with self.assertLogs("botnats.nats.coordinator", level="WARNING"):
            await coordinator.dispatch(callback, message)

        callback.assert_not_awaited()

    async def test_malformed_warning_is_throttled(self) -> None:
        """Verify malformed traffic cannot flood the warning log."""
        coordinator = build_coordinator("alpha", Fixtures())

        with (
            patch(
                "botnats.nats.coordinator.time.monotonic",
                side_effect=(10.0, 11.0, 16.0),
            ),
            self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs,
        ):
            coordinator.warn_decode("message", SUBJECT, ValueError("bad"))
            coordinator.warn_decode("message", SUBJECT, ValueError("bad"))
            coordinator.warn_decode("message", SUBJECT, ValueError("bad"))

        assert len(logs.output) == EXPECTED_WARNING_COUNT
        assert "suppressed 1 similar warning(s)" in logs.output[-1]

    async def test_network_namespaces(self) -> None:
        """Verify separate network groups do not share subjects or auth buckets."""
        first = build_coordinator("alpha", Fixtures(), "efnet")
        second = build_coordinator("alpha", Fixtures(), "undernet")

        assert first.ns != second.ns
        assert first.attempts.bucket != second.attempts.bucket
        assert first.claims.bucket != second.claims.bucket

    async def test_reconnect_retries_stores(self) -> None:
        """Verify reconnect restores all stores before starting watches."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock()
        steps: list[str] = []

        async def open_store(*arguments: object) -> None:
            del arguments
            steps.append("open")
            if steps.count("open") == 1:
                msg = "unavailable"
                raise OSError(msg)

        async def sleep(delay: float) -> None:
            del delay
            steps.append("sleep")

        with (
            patch.object(AttemptStore, "open", open_store),
            patch.object(ChannelStore, "open", open_store),
            patch.object(ClaimStore, "open", open_store),
            patch.object(PresenceStore, "open", open_store),
            patch.object(SessionStore, "open", open_store),
            patch("botnats.nats.coordinator.asyncio.sleep", sleep),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.on_reconnected()
            await coordinator.cancel_watches()

        assert steps == ["open", "sleep", "open", "open", "open", "open", "open"]

    async def test_ready_waits_for_watch_replay(self) -> None:
        """Keep readiness false until every KV watch reaches its sentinel."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        for store in coordinator.stores:
            store.kv = MagicMock()

        assert not coordinator.ready
        coordinator.synced_watches.update(WATCH_NAMES)
        assert not coordinator.ready
        coordinator.owns_presence = True
        assert coordinator.ready

    async def test_watch_channel_rejects_mismatched_key(self) -> None:
        """Ignore a valid channel record stored under the wrong opaque key."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = AsyncMock()
        record = ChannelRecord.new("#test", None, present=True)
        entry = SimpleNamespace(
            key=coordinator.channels_store.key("#other"),
            operation="PUT",
            value=json.dumps(record.to_dict()).encode(),
        )
        kv, _ = watcher(entry, None)
        coordinator.channels_store.kv = kv

        with patch.object(coordinator.callbacks, "on_channel", callback):
            await coordinator.watch_channels()

        callback.assert_not_awaited()

    async def test_watch_channel_ignores_deeply_nested_json(self) -> None:
        """Skip malformed JSON without trapping the channel watch in replay."""
        coordinator = build_coordinator("alpha", Fixtures())
        entry = SimpleNamespace(
            operation="PUT",
            value=b"[" * 2_000 + b"]" * 2_000,
        )
        kv, _ = watcher(entry, None)
        coordinator.channels_store.kv = kv

        await coordinator.watch_channels()

        assert "watch-channels" in coordinator.synced_watches

    async def test_watch_presence_binds_key_and_applies_delete(self) -> None:
        """Reject misplaced presence values and apply peer deletion events."""
        coordinator = build_coordinator("alpha", Fixtures())
        update = MagicMock()
        delete = MagicMock()
        misplaced = SimpleNamespace(
            key="beta",
            operation="PUT",
            revision=1,
            value=presence_entry().value,
        )
        removed = SimpleNamespace(key="beta", operation="DEL", value=None)
        kv, _ = watcher(misplaced, removed, None)
        coordinator.presence_store.kv = kv

        with (
            patch.object(coordinator.callbacks, "on_presence", update),
            patch.object(coordinator.callbacks, "on_presence_delete", delete),
        ):
            await coordinator.watch_presence()

        assert coordinator.unique
        update.assert_not_called()
        delete.assert_called_once_with("beta")

    async def test_reclaims_presence_during_heartbeat(self) -> None:
        """Retry atomic presence reclaim when TTL expiry emits no watch event."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.unique = False
        presence = {"bot_id": "alpha", "instance_id": coordinator.instance_id}

        with (
            patch.object(
                coordinator.presence_store,
                "create",
                AsyncMock(side_effect=(None, 1)),
            ) as create,
            patch.object(
                coordinator.presence_store,
                "update",
                AsyncMock(return_value=2),
            ) as update,
            patch.object(
                coordinator.presence_store,
                "reclaim",
                AsyncMock(return_value=None),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
                await coordinator.put_presence(presence)
            await coordinator.put_presence(presence)

        assert coordinator.unique
        assert create.await_count == EXPECTED_WRITE_ATTEMPTS
        update.assert_not_awaited()

    async def test_reclaim_claims_occupied_key(self) -> None:
        """Claim an occupied key via a single reclaim on the heartbeat path."""
        coordinator = build_coordinator("alpha", Fixtures())
        reclaimed_revision = 7
        presence = {
            "bot_id": "alpha",
            "host": "host",
            "instance_id": coordinator.instance_id,
            "nick": "alpha",
            "user": "user",
        }

        with (
            patch.object(
                coordinator.presence_store,
                "create",
                AsyncMock(return_value=None),
            ),
            patch.object(
                coordinator.presence_store,
                "reclaim",
                AsyncMock(return_value=reclaimed_revision),
            ) as reclaim,
        ):
            await coordinator.put_presence(presence)

        assert coordinator.owns_presence
        assert coordinator.unique
        assert coordinator.presence_revision == reclaimed_revision
        reclaim.assert_awaited_once_with("alpha", presence, coordinator.instance_id)

    async def test_transient_reclaim_error_is_not_a_duplicate(self) -> None:
        """Propagate a transient reclaim failure without marking a duplicate."""
        coordinator = build_coordinator("alpha", Fixtures())
        presence = {"bot_id": "alpha", "instance_id": coordinator.instance_id}

        with (
            patch.object(
                coordinator.presence_store,
                "create",
                AsyncMock(return_value=None),
            ),
            patch.object(
                coordinator.presence_store,
                "reclaim",
                AsyncMock(side_effect=OSError("blip")),
            ),
            self.assertRaises(OSError),
        ):
            await coordinator.put_presence(presence)

        assert coordinator.unique
        assert not coordinator.owns_presence

    async def test_grant_dispatches_during_watch_resync(self) -> None:
        """Deliver a grant while watches replay once presence is owned."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.owns_presence = True
        callback = AsyncMock()
        subject = f"{coordinator.ns}.op.grant.alpha"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        assert not coordinator.ready
        await coordinator.grant(callback, message)

        callback.assert_awaited_once()

    async def test_stale_presence_owner_cannot_overwrite_new_owner(self) -> None:
        """Fail closed when a heartbeat loses its owned KV revision."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.owns_presence = True
        coordinator.presence_revision = 1
        presence = {"bot_id": "alpha", "instance_id": coordinator.instance_id}

        with (
            patch.object(
                coordinator.presence_store,
                "update",
                AsyncMock(return_value=None),
            ),
            patch.object(
                coordinator.presence_store,
                "create",
                AsyncMock(return_value=None),
            ),
            patch.object(
                coordinator.presence_store,
                "reclaim",
                AsyncMock(return_value=None),
            ),
            self.assertRaisesRegex(RuntimeError, "duplicate bot ID"),
        ):
            await coordinator.put_presence(presence)

        assert not coordinator.owns_presence
        assert not coordinator.unique

    async def test_expired_presence_owner_reclaims_id(self) -> None:
        """Reclaim an expired owned key without reporting a duplicate."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.owns_presence = True
        coordinator.presence_revision = 1
        reclaimed_revision = 2
        presence = {"bot_id": "alpha", "instance_id": coordinator.instance_id}

        with (
            patch.object(
                coordinator.presence_store,
                "update",
                AsyncMock(return_value=None),
            ),
            patch.object(
                coordinator.presence_store,
                "create",
                AsyncMock(return_value=reclaimed_revision),
            ),
        ):
            await coordinator.put_presence(presence)

        assert coordinator.owns_presence
        assert coordinator.unique
        assert coordinator.presence_revision == reclaimed_revision

    async def test_session_replay_removes_missing_cached_session(self) -> None:
        """Remove a cached session absent from a restarted watch replay."""
        fixtures = Fixtures()
        coordinator = build_coordinator("alpha", fixtures)
        coordinator.session_identities["opaque"] = (
            "owner!user@host",
            time.time() + 60,
        )
        kv, _ = watcher(None)
        coordinator.sessions.kv = kv
        coordinator.sessions.js = MagicMock()

        await coordinator.watch_sessions()

        assert fixtures.session_deletes == ["owner!user@host"]
        assert not coordinator.session_identities

    async def test_session_identity_cache_skips_expired_updates(self) -> None:
        """Discard an expired update arriving after the initial replay."""
        coordinator = build_coordinator("alpha", Fixtures())
        record = session_record(time.time() - 1)
        entry = SimpleNamespace(
            key=coordinator.sessions.key("owner!user@host"),
            operation="PUT",
            value=json.dumps(record).encode(),
        )
        kv, _ = watcher(None, entry)
        coordinator.sessions.kv = kv
        coordinator.sessions.js = MagicMock()

        with patch.object(
            coordinator,
            "observe_session",
            wraps=coordinator.observe_session,
        ) as observe:
            await coordinator.watch_sessions()

        assert not coordinator.session_identities
        assert observe.call_args.args[2] is None

    async def test_session_identity_cache_prunes_during_updates(self) -> None:
        """Prune expired key mappings during normal watch traffic."""
        coordinator = build_coordinator("alpha", Fixtures())
        now = time.time()
        coordinator.session_identities["expired"] = (
            "expired!user@host",
            now - 1,
        )
        expiry = now + 60
        record = session_record(expiry)
        key = coordinator.sessions.key("owner!user@host")

        coordinator.observe_session(key, record, None)

        assert coordinator.session_identities == {
            key: ("owner!user@host", expiry),
        }

    def test_session_identity_cache_does_not_prune_during_replay(self) -> None:
        """Avoid rescanning the growing cache for every replayed session."""
        coordinator = build_coordinator("alpha", Fixtures())
        now = time.time()
        record = session_record(now + 60)
        key = coordinator.sessions.key("owner!user@host")

        with patch.object(
            coordinator,
            "prune_session_identities",
            wraps=coordinator.prune_session_identities,
        ) as prune:
            coordinator.observe_session(key, record, set())

        prune.assert_not_called()

    async def test_session_identity_cache_validates_before_updates(self) -> None:
        """Reject malformed session updates before changing key mappings."""
        fixtures = Fixtures()
        coordinator = build_coordinator("alpha", fixtures)
        record = session_record(time.time() + 60)
        key = coordinator.sessions.key("owner!user@host")
        replayed: set[str] = set()

        coordinator.observe_session(key, record, replayed)
        mapped = coordinator.session_identities[key]
        for expires_at in (float("nan"), 10**400):
            coordinator.observe_session(
                key,
                {"prefix": "owner!user@host", "expires_at": expires_at},
                replayed,
            )
        coordinator.observe_session(
            key,
            {"prefix": "owner!user@" + chr(0xD800)},
            replayed,
        )

        assert coordinator.session_identities[key] == mapped
        assert replayed == {key}
        assert not fixtures.session_deletes

    async def test_watch_presence_keeps_conflict_during_replay(self) -> None:
        """Verify a duplicate detected during replay is not resolved by the sentinel."""
        coordinator = build_coordinator("alpha", Fixtures())
        kv, _ = watcher(presence_entry(), None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert not coordinator.unique

    async def test_watch_presence_ignores_unsigned_record(self) -> None:
        """Verify an unsigned presence record cannot demote the owner."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.owns_presence = True
        coordinator.unique = True
        kv, _ = watcher(presence_entry(signed=False), None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert coordinator.unique
        assert coordinator.owns_presence

    async def test_watch_presence_reclaim_loser_stays_conflicted(self) -> None:
        """Verify the loser of atomic presence reclaim stays unique=False."""
        coordinator = build_coordinator("alpha", Fixtures())
        delete_entry = SimpleNamespace(
            key="alpha",
            operation="DEL",
            value=None,
        )
        kv, _ = watcher(presence_entry(), None, delete_entry)
        kv.create = AsyncMock(
            side_effect=KeyWrongLastSequenceError,
        )
        # A valid signed record from another instance holds the key, so the
        # reclaim finds a genuine duplicate and must not overwrite it.
        kv.get = AsyncMock(
            return_value=SimpleNamespace(revision=1, value=presence_entry().value),
        )
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert not coordinator.unique

    async def test_watch_presence_resolves_absent_conflict(self) -> None:
        """Verify a conflict is resolved when the duplicate is gone on replay."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.unique = False
        kv, _ = watcher(None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert coordinator.unique

    async def test_watch_presence_resolves_on_delete(self) -> None:
        """Verify a live conflict resolves when the presence entry expires."""
        coordinator = build_coordinator("alpha", Fixtures())
        delete_entry = SimpleNamespace(
            key="alpha",
            operation="DEL",
            value=None,
        )
        kv, _ = watcher(presence_entry(), None, delete_entry)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert coordinator.unique

    async def test_watch_restarts_on_transient_error(self) -> None:
        """Verify a watch task restarts after a transient JetStream error."""
        coordinator = build_coordinator("alpha", Fixtures())
        nc = MagicMock(is_connected=True)
        coordinator.nc = nc
        coordinator.synced_watches.update(WATCH_NAMES)
        calls = 0
        real_sleep = asyncio.sleep

        async def fail_once(*arguments: object) -> None:
            del arguments
            nonlocal calls
            calls += 1
            if calls == 1:
                msg = "transient"
                raise OSError(msg)
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", fail_once),
            patch.object(coordinator, "watch_presence", fail_once),
            patch.object(coordinator, "watch_sessions", fail_once),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator"),
        ):
            await coordinator.start_watches()
            async with asyncio.timeout(5):
                while calls <= EXPECTED_WATCH_RESTARTS:
                    await real_sleep(0.001)
            assert not coordinator.synced_watches
            await coordinator.cancel_watches()

        assert calls > EXPECTED_WATCH_RESTARTS

    async def test_concurrent_start_watches_keeps_single_watcher_set(self) -> None:
        """Verify overlapping start_watches calls leave exactly one watcher set."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)

        async def hang(*arguments: object) -> None:
            del arguments
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", hang),
            patch.object(coordinator, "watch_presence", hang),
            patch.object(coordinator, "watch_sessions", hang),
        ):
            await coordinator.start_watches()
            await asyncio.gather(
                coordinator.start_watches(),
                coordinator.start_watches(),
            )
            assert len(coordinator.watch_tasks) == len(WATCH_NAMES)
            await coordinator.cancel_watches()

        assert not coordinator.watch_tasks

    async def test_superseded_watcher_surviving_cancellation_exits(self) -> None:
        """Eject a watcher whose cleanup replaced its CancelledError."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        real_sleep = asyncio.sleep

        async def swallow_cancel(*arguments: object) -> None:
            del arguments
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # Mimic a watch body whose `finally: await watcher.stop()`
                # raises a transport error, replacing the cancellation.
                coordinator.mark_watch_synced("watch-channels")
                msg = "connection closed"
                raise OSError(msg) from None

        async def hang(*arguments: object) -> None:
            del arguments
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", swallow_cancel),
            patch.object(coordinator, "watch_presence", swallow_cancel),
            patch.object(coordinator, "watch_sessions", swallow_cancel),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.start_watches()
            await real_sleep(0)
            old_tasks = list(coordinator.watch_tasks)
            with (
                patch.object(coordinator, "watch_channels", hang),
                patch.object(coordinator, "watch_presence", hang),
                patch.object(coordinator, "watch_sessions", hang),
            ):
                async with asyncio.timeout(2):
                    await coordinator.start_watches()
                assert all(task.done() for task in old_tasks)
                assert not coordinator.synced_watches
                await coordinator.cancel_watches()

    async def test_stale_watcher_cancellation_keeps_new_sync_markers(self) -> None:
        """Verify a slowly dying superseded watcher cannot wedge readiness."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        real_sleep = asyncio.sleep

        async def hang_slow_cancel(*arguments: object) -> None:
            del arguments
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await real_sleep(0.01)
                raise

        async def sync_and_hang(name: str) -> None:
            coordinator.mark_watch_synced(name)
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", hang_slow_cancel),
            patch.object(coordinator, "watch_presence", hang_slow_cancel),
            patch.object(coordinator, "watch_sessions", hang_slow_cancel),
        ):
            await coordinator.start_watches()
        with (
            patch.object(
                coordinator,
                "watch_channels",
                partial(sync_and_hang, "watch-channels"),
            ),
            patch.object(
                coordinator,
                "watch_presence",
                partial(sync_and_hang, "watch-presence"),
            ),
            patch.object(
                coordinator,
                "watch_sessions",
                partial(sync_and_hang, "watch-sessions"),
            ),
        ):
            await asyncio.gather(
                coordinator.start_watches(),
                coordinator.start_watches(),
            )
            async with asyncio.timeout(5):
                while coordinator.synced_watches != set(WATCH_NAMES):
                    await real_sleep(0.005)
            await coordinator.cancel_watches()

    async def test_watch_stops_watcher_on_error(self) -> None:
        """Verify a crashed watch coroutine stops its KV watcher subscription."""
        coordinator = build_coordinator("alpha", Fixtures())
        watcher = AsyncMock()
        watcher.__aiter__ = MagicMock(return_value=watcher)
        watcher.__anext__ = AsyncMock(side_effect=OSError("disconnected"))
        kv = AsyncMock()
        kv.watchall = AsyncMock(return_value=watcher)
        coordinator.channels_store.kv = kv
        coordinator.channels_store.js = MagicMock()

        with self.assertRaises(OSError):
            await coordinator.watch_channels()

        watcher.stop.assert_awaited_once()

    async def test_watch_surfaces_programming_errors(self) -> None:
        """Verify a programming error in a watch is logged at ERROR and retried."""
        coordinator = build_coordinator("alpha", Fixtures())
        nc = MagicMock(is_connected=True)
        coordinator.nc = nc
        calls = 0
        real_sleep = asyncio.sleep

        async def crash_once(*arguments: object) -> None:
            del arguments
            nonlocal calls
            calls += 1
            if calls <= EXPECTED_WATCH_RESTARTS:
                msg = "missing attribute"
                raise RuntimeError(msg)
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", crash_once),
            patch.object(coordinator, "watch_presence", crash_once),
            patch.object(coordinator, "watch_sessions", crash_once),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="ERROR") as logs,
        ):
            await coordinator.start_watches()
            async with asyncio.timeout(5):
                while calls <= EXPECTED_WATCH_RESTARTS:
                    await real_sleep(0.001)
            await coordinator.cancel_watches()

        assert any("crashed" in line for line in logs.output)
        assert calls > EXPECTED_WATCH_RESTARTS


@unittest.skipUnless(NATS_URL, "BOTNATS_TEST_NATS_URL is not configured")
class CoordinatorIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Tests for live NATS state exchange and grant coordination."""

    async def asyncSetUp(self) -> None:
        """Connect two coordinators wired to shared test fixtures."""
        self.fixtures = Fixtures(
            events={
                "op": asyncio.Event(),
                "unban": asyncio.Event(),
            },
        )
        network = f"test{uuid.uuid4().hex}"
        self.alpha = build_coordinator("alpha", self.fixtures, network)
        self.beta = build_coordinator("beta", self.fixtures, network)
        ready = asyncio.Event()

        def mark_synced(coordinator: Coordinator, name: str) -> None:
            coordinator.synced_watches.add(name)
            if self.alpha.ready and self.beta.ready:
                ready.set()

        with (
            patch.object(
                self.alpha,
                "mark_watch_synced",
                partial(mark_synced, self.alpha),
            ),
            patch.object(
                self.beta,
                "mark_watch_synced",
                partial(mark_synced, self.beta),
            ),
        ):
            await self.alpha.start()
            await self.beta.start()
            async with asyncio.timeout(GRANT_TIMEOUT):
                await ready.wait()
        assert self.alpha.ready
        assert self.beta.ready

    async def asyncTearDown(self) -> None:
        """Close both coordinators."""
        await self.beta.close()
        await self.alpha.close()

    async def test_auth_claim_dedup(self) -> None:
        """Verify a TOTP counter can be claimed once across the whole mesh."""
        counter = 123
        assert self.alpha.claims.kv is not None
        with suppress(Exception):
            await self.alpha.claims.kv.delete(self.alpha.claims.key(counter))

        assert await self.alpha.request_claim(counter)
        assert not await self.beta.request_claim(counter)

    async def test_auth_claim_replica_count(self) -> None:
        """Verify the claim bucket uses the configured replica count."""
        assert self.alpha.claims.kv is not None
        status = await self.alpha.claims.kv.status()

        assert status.stream_info.config.num_replicas == JETSTREAM_REPLICAS

    async def test_auth_rate_limit(self) -> None:
        """Verify authentication attempts are limited across the mesh."""
        identity = f"rate-{time.time_ns()}.example"
        attempts = [
            await coordinator.request_auth(identity)
            for coordinator in (self.alpha, self.beta, self.alpha, self.beta)
        ]

        assert attempts == [True] * ATTEMPT_LIMIT + [False]

    async def test_auth_rate_limit_boundary(self) -> None:
        """Verify the mesh limit does not reset at a fixed-window boundary."""
        identity = f"boundary-{time.time_ns()}.example"
        for coordinator in (self.alpha, self.beta, self.alpha):
            assert await coordinator.attempts.allow(identity, now=59.9)

        assert not await self.beta.attempts.allow(identity, now=60)

    async def test_op_grant(self) -> None:
        """Verify op offer and grant flow."""
        selected = await self.beta.request_offer(
            "op",
            {"channel": "#shared", "presence": BETA_PRESENCE},
        )
        assert selected
        await asyncio.wait_for(self.fixtures.events["op"].wait(), timeout=GRANT_TIMEOUT)

    async def test_unban_grant(self) -> None:
        """Verify unban offer and grant flow."""
        selected = await self.beta.request_offer(
            "unban",
            {"channel": "#shared", "presence": BETA_PRESENCE},
        )
        assert selected
        await asyncio.wait_for(
            self.fixtures.events["unban"].wait(),
            timeout=GRANT_TIMEOUT,
        )
