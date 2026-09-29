# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for coordinator boundaries, watches, and help requests without live NATS."""

import asyncio
import json
import os
import time
import unittest
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from functools import partial
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from nats.aio.msg import Msg
from nats.errors import Error as NatsError
from nats.js.errors import KeyWrongLastSequenceError
from nats.js.kv import KV_DEL

from botnats import Tasks
from botnats.auth import SessionSync
from botnats.channel import ChannelRecord
from botnats.nats.claim import PresenceState
from botnats.nats.coordinator import WATCH_NAMES, Coordinator, NATSConfig
from botnats.nats.envelope import Envelope
from botnats.nats.store import (
    AttemptStore,
    ChannelStore,
    ClaimStore,
    PresenceStore,
    SessionStore,
    StoreUnavailableError,
    presence_signature,
)
from tests.unit.helpers import COORDINATION_KEY, FakeCoordinator, session_record

if TYPE_CHECKING:
    from collections.abc import Callable

    from botnats.auth import TotpAuthorizer
    from botnats.bot import NATSCallbackHandler
    from botnats.presence import BotPresence

BETA_PRESENCE = {
    "bot_id": "beta",
    "host": "host",
    "instance_id": "instance",
    "nick": "beta",
    "user": "user",
}
JETSTREAM_REPLICAS = int(os.environ.get("BOTNATS_TEST_JETSTREAM_REPLICAS", "1"))
NATS_TOKEN = os.environ.get("BOTNATS_TEST_NATS_TOKEN", "integration-token")
NATS_URL = os.environ.get("BOTNATS_TEST_NATS_URL")
SUBJECT = "botnats.v1.efnet.channel"


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


@dataclass
class Fixtures:
    """Shared mutable state for coordinator integration tests.

    Session watch callbacks go to a real SessionSync whose authorizer only
    records what it is told to import and drop.
    """

    events: dict[str, asyncio.Event] = field(default_factory=dict)
    session_deletes: list[str] = field(default_factory=list)
    session_imports: list[dict[str, Any]] = field(default_factory=list)
    sessions: SessionSync = field(init=False)

    def __post_init__(self) -> None:
        """Wire the session owner to the recording authorizer."""
        authorizer = SimpleNamespace(
            drop_session=self.session_deletes.append,
            import_session=self.session_imports.append,
        )
        self.sessions = SessionSync(
            cast("TotpAuthorizer", authorizer), FakeCoordinator(), Tasks()
        )


def build_coordinator(
    bot_id: str,
    fixtures: Fixtures,
    network: str = "efnet",
) -> Coordinator:
    """Build a coordinator wired to shared test fixtures."""
    is_alpha = bot_id == "alpha"
    callbacks = cast(
        "NATSCallbackHandler",
        SimpleNamespace(
            on_channel=AsyncMock(),
            on_help=help_callback(fixtures) if is_alpha else noop_help,
            on_presence=noop_presence,
            on_presence_delete=noop_presence_delete,
            on_session_delete=fixtures.sessions.forget,
            on_session_update=fixtures.sessions.observe,
            on_sessions_replayed=fixtures.sessions.replayed,
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


def help_callback(fixtures: Fixtures) -> Callable[[str, dict[str, Any]], None]:
    """Return a help callback that sets the event named for the request kind."""

    def handler(kind: str, payload: dict[str, Any]) -> None:
        """Signal the kind's event."""
        del payload
        fixtures.events[kind].set()

    return handler


def noop_help(kind: str, payload: dict[str, Any]) -> None:
    """Accept and ignore any help request."""
    del kind, payload


def noop_presence(presence: BotPresence) -> None:
    """Accept and ignore a presence update."""
    del presence


def noop_presence_delete(bot_id: str) -> None:
    """Accept and ignore a presence deletion."""
    del bot_id


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


def watcher(*entries: object) -> tuple[AsyncMock, AsyncMock]:
    """Build a KV handle and watcher yielding the given entries."""
    result = AsyncMock()
    result.__aiter__ = MagicMock(return_value=result)
    result.__anext__ = AsyncMock(side_effect=[*entries, StopAsyncIteration])
    kv = AsyncMock()
    kv.watchall = AsyncMock(return_value=result)
    return kv, result


class CoordinatorUnitTests(unittest.IsolatedAsyncioTestCase):
    """Tests for coordinator boundaries that do not require live NATS."""

    async def test_help_request_broadcasts_signed_message(self) -> None:
        """Publish one signed request on the kind's subject, with no reply inbox."""
        coordinator = build_coordinator("beta", Fixtures())
        coordinator.nc = AsyncMock()
        coordinator.claim.state = PresenceState.OWNED
        payload = {"channel": "#test", "presence": BETA_PRESENCE}

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.request_help("op", payload)

        subject, data = coordinator.nc.publish.await_args.args
        assert subject == f"{coordinator.ns}.op"
        assert Envelope("alpha", COORDINATION_KEY).decode(subject, data) == (
            "beta",
            payload,
        )
        coordinator.nc.request.assert_not_awaited()

    async def test_help_request_publish_failure_is_contained(self) -> None:
        """Drop a request whose publish fails; the next tick asks again."""
        coordinator = build_coordinator("beta", Fixtures())
        coordinator.nc = AsyncMock()

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(
                coordinator.help_requests,
                "publish",
                AsyncMock(side_effect=RuntimeError("duplicate bot ID: beta")),
            ),
        ):
            await coordinator.request_help(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

    async def test_peer_help_request_reaches_callback(self) -> None:
        """Hand a peer's signed request to the bot with the kind its subject names."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = MagicMock()
        subject = f"{coordinator.ns}.unban"
        payload = {"channel": "#test", "presence": BETA_PRESENCE}
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                payload,
            ),
        )

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.help_requests.deliver(callback, message)

        callback.assert_called_once_with("unban", payload)

    async def test_help_subscription_covers_every_kind(self) -> None:
        """Subscribe once to the namespace, so every help kind is delivered."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = AsyncMock()

        await coordinator.help_requests.subscribe()

        coordinator.nc.subscribe.assert_awaited_once()
        assert coordinator.nc.subscribe.await_args.args == (f"{coordinator.ns}.*",)

    async def test_own_help_request_is_skipped(self) -> None:
        """Ignore this bot's own broadcast, which NATS echoes back to it."""
        coordinator = build_coordinator("beta", Fixtures())
        callback = MagicMock()
        subject = f"{coordinator.ns}.op"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.help_requests.deliver(callback, message)

        callback.assert_not_called()

    async def test_action_rejects_mismatched_sender(self) -> None:
        """Reject action payloads whose presence does not own the envelope."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = MagicMock()
        subject = f"{coordinator.ns}.op"
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

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.help_requests.deliver(callback, message)

        callback.assert_not_called()

    async def test_outgoing_action_requires_owned_presence(self) -> None:
        """Reject outgoing action and presence writes for another bot ID."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = AsyncMock()

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.request_help(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

        with self.assertRaisesRegex(ValueError, "does not match"):
            await coordinator.put_presence(BETA_PRESENCE)

        coordinator.nc.publish.assert_not_awaited()

    async def test_callback_error_surfaces(self) -> None:
        """Verify callback defects are not mislabeled as malformed input."""
        coordinator = build_coordinator("alpha", Fixtures())
        subject = f"{coordinator.ns}.op"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        def fail(kind: str, payload: dict[str, Any]) -> None:
            del kind, payload
            msg = "callback failed"
            raise ValueError(msg)

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            self.assertRaisesRegex(ValueError, "callback failed"),
        ):
            await coordinator.help_requests.deliver(fail, message)

    async def test_close_releases_connection(self) -> None:
        """Verify shutdown releases owned presence, connection, and KV handles."""
        coordinator = build_coordinator("alpha", Fixtures())
        nc = MagicMock(is_closed=False)
        nc.close = AsyncMock()
        coordinator.nc = nc
        coordinator.claim.state = PresenceState.OWNED
        coordinator.claim.revision = 7
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
        assert not coordinator.claim.owned
        assert coordinator.claim.revision is None
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
        assert len(logs.output) == 2
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
        """Prevent a conflicting bot ID from publishing or acting on requests."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.claim.state = PresenceState.DUPLICATE
        callback = MagicMock()
        subject = f"{coordinator.ns}.op"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
            await coordinator.help_requests.publish("channel", {})

        await coordinator.help_requests.deliver(callback, message)

        callback.assert_not_called()

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
        failures = [OSError("unavailable")] * 11
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

        assert open_attempt.await_count == 12
        assert sleep.await_count == 11

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
        callback = MagicMock()
        message = Msg(MagicMock(), subject="bad", data=b"not-json")

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.help_requests.deliver(callback, message)

        callback.assert_not_called()

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
            coordinator.help_requests.warn_decode("message", SUBJECT, ValueError("bad"))
            coordinator.help_requests.warn_decode("message", SUBJECT, ValueError("bad"))
            coordinator.help_requests.warn_decode("message", SUBJECT, ValueError("bad"))

        assert len(logs.output) == 2
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

        async def start_watches() -> None:
            steps.append("watches")

        with (
            patch.object(AttemptStore, "open", open_store),
            patch.object(ChannelStore, "open", open_store),
            patch.object(ClaimStore, "open", open_store),
            patch.object(PresenceStore, "open", open_store),
            patch.object(SessionStore, "open", open_store),
            patch.object(coordinator, "start_watches", start_watches),
            patch("botnats.nats.coordinator.asyncio.sleep", sleep),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.on_reconnected()
            # Resynchronization runs as a background task so a JetStream
            # outage cannot park the nats-py reconnected callback.
            task = coordinator.resync_task
            assert task is not None
            await task

        assert steps == [
            "open",
            "sleep",
            "open",
            "open",
            "open",
            "open",
            "open",
            "watches",
        ]

    async def test_resync_failure_is_logged(self) -> None:
        """Log a failed resynchronization instead of losing it to GC."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock()

        resync = AsyncMock(side_effect=TypeError("bug"))
        with (
            patch.object(coordinator, "resync", resync),
            self.assertLogs("botnats.nats.coordinator", level="ERROR") as logs,
        ):
            await coordinator.on_reconnected()
            task = coordinator.resync_task
            assert task is not None
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.sleep(0)

        assert coordinator.resync_task is None
        assert any("resynchronization failed" in line for line in logs.output)

    async def test_crash_logs_are_rate_limited(self) -> None:
        """Throttle repeated crash tracebacks from one watch."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        calls = 0
        real_sleep = asyncio.sleep

        async def crash_twice(*arguments: object) -> None:
            del arguments
            nonlocal calls
            calls += 1
            if calls <= 2:
                msg = "boom"
                raise ValueError(msg)

            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", crash_twice),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="ERROR") as logs,
        ):
            coordinator.watch_generation += 1
            task = asyncio.create_task(
                coordinator.run_watch(
                    "watch-channels",
                    coordinator.watch_channels,
                    coordinator.watch_generation,
                ),
            )
            async with asyncio.timeout(5):
                while calls <= 2:
                    await real_sleep(0.001)

            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert sum("crashed" in line for line in logs.output) == 1

    async def test_replaced_resync_keeps_new_task(self) -> None:
        """Keep the new resync task when a superseded one finishes."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock()
        hang = asyncio.Event()

        async def hang_resync() -> None:
            await hang.wait()

        with patch.object(coordinator, "resync", hang_resync):
            await coordinator.on_reconnected()
            first = coordinator.resync_task
            await coordinator.on_reconnected()
            second = coordinator.resync_task
            assert first is not None
            assert first is not second
            await asyncio.gather(first, return_exceptions=True)
            await asyncio.sleep(0)

            assert coordinator.resync_task is second
            await coordinator.cancel_resync()
            assert second is not None
            await asyncio.gather(second, return_exceptions=True)

    async def test_disconnect_cancels_resync(self) -> None:
        """Cancel an in-flight resynchronization when Core NATS drops."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock()
        hang = asyncio.Event()

        async def hang_resync() -> None:
            await hang.wait()

        with patch.object(coordinator, "resync", hang_resync):
            await coordinator.on_reconnected()
            task = coordinator.resync_task
            assert task is not None
            await coordinator.on_disconnected()
            await asyncio.gather(task, return_exceptions=True)

        assert task.cancelled()
        assert coordinator.resync_task is None

    async def test_ready_waits_for_watch_replay(self) -> None:
        """Keep readiness false until every KV watch reaches its sentinel."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.nc = MagicMock(is_connected=True)
        for store in coordinator.stores:
            store.kv = MagicMock()

        assert not coordinator.ready
        coordinator.synced_watches.update(WATCH_NAMES)
        assert not coordinator.ready
        coordinator.claim.state = PresenceState.OWNED
        assert coordinator.ready

    async def test_watch_channel_rejects_mismatched_key(self) -> None:
        """Ignore a valid channel record stored under the wrong opaque key."""
        coordinator = build_coordinator("alpha", Fixtures())
        callback = AsyncMock()
        record = ChannelRecord.new("#test", None, present=True)
        entry = SimpleNamespace(
            key=coordinator.channels_store.key("#other"),
            operation="PUT",
            value=json.dumps(asdict(record)).encode(),
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

        assert not coordinator.claim.duplicate
        update.assert_not_called()
        delete.assert_called_once_with("beta")

    async def test_watch_survives_lost_reclaim_races(self) -> None:
        """Contain reclaim exhaustion to the key instead of the whole watch."""
        coordinator = build_coordinator("alpha", Fixtures())
        entry = SimpleNamespace(key="alpha", operation=KV_DEL, value=None)
        kv, _ = watcher(entry, None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        with (
            patch.object(
                coordinator.claim,
                "claim",
                AsyncMock(side_effect=NatsError("lost repeated update races")),
            ),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.watch_presence()

        assert "watch-presence" in coordinator.synced_watches

    async def test_expired_session_update_fires_delete_only(self) -> None:
        """Drop, and do not import, a session whose record has already expired."""
        fixtures = Fixtures()
        coordinator = build_coordinator("alpha", fixtures)
        key = coordinator.sessions.key("owner!user@host")
        fixtures.sessions.watched[key] = ("owner!user@host", time.time() + 60)
        entry = SimpleNamespace(
            key=key,
            operation="PUT",
            value=json.dumps(session_record(time.time() - 1)).encode(),
        )
        kv, _ = watcher(entry, None)
        coordinator.sessions.kv = kv
        coordinator.sessions.js = MagicMock()

        await coordinator.watch_sessions()

        assert fixtures.session_deletes == ["owner!user@host"]
        assert fixtures.session_imports == []

    async def test_help_ignored_until_watches_replay(self) -> None:
        """Ignore peer requests while watches replay, even with presence owned."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.claim.state = PresenceState.OWNED
        callback = MagicMock()
        subject = f"{coordinator.ns}.op"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        assert not coordinator.ready
        await coordinator.help_requests.deliver(callback, message)

        callback.assert_not_called()

    async def test_disconnect_does_not_wait_for_presence_write(self) -> None:
        """Reset at once during a slow write, which then records no ownership."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.claim.adopt(1)
        presence = {"bot_id": "alpha", "instance_id": coordinator.claim.instance_id}
        writing = asyncio.Event()
        release = asyncio.Event()

        async def slow_update(*arguments: object) -> int:
            del arguments
            writing.set()
            await release.wait()
            return 2

        with patch.object(coordinator.presence_store, "update", slow_update):
            write = asyncio.create_task(coordinator.put_presence(presence))
            async with asyncio.timeout(1):
                await writing.wait()
                await coordinator.on_disconnected()
            release.set()
            with suppress(RuntimeError):
                await write

        assert coordinator.claim.state is PresenceState.UNCLAIMED
        assert coordinator.claim.revision is None

    async def test_session_replay_removes_missing_cached_session(self) -> None:
        """Remove a cached session absent from a restarted watch replay."""
        fixtures = Fixtures()
        coordinator = build_coordinator("alpha", fixtures)
        fixtures.sessions.watched["opaque"] = ("owner!user@host", time.time() + 60)
        kv, _ = watcher(None)
        coordinator.sessions.kv = kv
        coordinator.sessions.js = MagicMock()

        await coordinator.watch_sessions()

        assert fixtures.session_deletes == ["owner!user@host"]
        assert not fixtures.sessions.watched

    async def test_session_identity_cache_validates_before_updates(self) -> None:
        """Reject malformed session records before they change any state."""
        fixtures = Fixtures()
        coordinator = build_coordinator("alpha", fixtures)
        key = coordinator.sessions.key("owner!user@host")
        valid = session_record(time.time() + 60)
        invalid = [
            {"prefix": "owner!user@host", "expires_at": float("nan")},
            {"prefix": "owner!user@host", "expires_at": 10**400},
            {"prefix": "owner!user@" + chr(0xD800)},
        ]
        entries = [
            SimpleNamespace(key=key, operation="PUT", value=json.dumps(record).encode())
            for record in (valid, *invalid)
        ]
        kv, _ = watcher(*entries, None)
        coordinator.sessions.kv = kv
        coordinator.sessions.js = MagicMock()

        await coordinator.watch_sessions()

        assert fixtures.sessions.watched == {
            key: ("owner!user@host", valid["expires_at"]),
        }
        assert fixtures.session_imports == [valid]
        assert not fixtures.session_deletes

    async def test_watch_presence_keeps_conflict_during_replay(self) -> None:
        """Verify a duplicate detected during replay is not resolved by the sentinel."""
        coordinator = build_coordinator("alpha", Fixtures())
        kv, _ = watcher(presence_entry(), None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence()

        assert coordinator.claim.duplicate

    async def test_watch_presence_ignores_unsigned_record(self) -> None:
        """Verify an unsigned presence record cannot demote the owner."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.claim.state = PresenceState.OWNED
        kv, _ = watcher(presence_entry(signed=False), None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert not coordinator.claim.duplicate
        assert coordinator.claim.owned

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

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence()

        assert coordinator.claim.duplicate

    async def test_watch_presence_resolves_absent_conflict(self) -> None:
        """Verify a conflict is resolved when the duplicate is gone on replay."""
        coordinator = build_coordinator("alpha", Fixtures())
        coordinator.claim.state = PresenceState.DUPLICATE
        kv, _ = watcher(None)
        coordinator.presence_store.kv = kv
        coordinator.presence_store.js = MagicMock()

        await coordinator.watch_presence()

        assert not coordinator.claim.duplicate

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

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence()

        assert not coordinator.claim.duplicate

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

            if calls == 2:
                # KVStore.open raises this while JetStream handles are
                # reset; a watch must treat it as transient, not a crash.
                msg = "JetStream is unavailable"
                raise StoreUnavailableError(msg)

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
                while calls <= 3:
                    await real_sleep(0.001)

            assert not coordinator.synced_watches
            await coordinator.cancel_watches()

        assert calls > 3

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

            assert coordinator.synced_watches == set(WATCH_NAMES)
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
            if calls <= 3:
                # A bare RuntimeError is a programming failure, unlike the
                # StoreUnavailableError subclass watches treat as transient.
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
                while calls <= 3:
                    await real_sleep(0.001)

            await coordinator.cancel_watches()

        assert any("crashed" in line for line in logs.output)
        assert calls > 3
