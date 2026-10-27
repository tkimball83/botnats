# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for coordinator boundaries, watches, and help requests without live NATS."""

import asyncio
import json
import time
import unittest
import uuid
from dataclasses import asdict, astuple
from functools import partial
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock, PropertyMock, call, patch

from nats.aio.msg import Msg
from nats.errors import ConnectionClosedError
from nats.errors import Error as NatsError
from nats.js.errors import KeyWrongLastSequenceError
from nats.js.kv import KV_DEL

from botnats.channel import ChannelRecord
from botnats.nats.claim import PresenceState
from botnats.nats.coordinator import RECONNECT_WAIT, Coordinator, NATSConfig
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
from botnats.presence import BotPresence
from tests.unit.helpers import (
    COORDINATION_KEY,
    NATS_CREDENTIAL,
    FakeKV,
    hang,
    session_record,
    session_value,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from nats.js.kv import KeyValue

    from botnats.bot import NATSCallbackHandler

BETA_PRESENCE = {
    "bot_id": "beta",
    "host": "host",
    "instance_id": "instance",
    "nick": "beta",
    "user": "user",
}
CREATED_REVISION = 2
NOT_OWNED = "bot ID alpha does not own its presence key"
SUBJECT = "botnats.v1.efnet.channel"


def build_coordinator(bot_id: str, network: str = "efnet") -> Coordinator:
    """Build a coordinator whose callbacks accept and ignore every event."""
    callbacks = cast(
        "NATSCallbackHandler",
        SimpleNamespace(
            on_channel=MagicMock(),
            on_help=noop_help,
            on_presence=noop_presence,
            on_presence_delete=noop_presence_delete,
            on_session_delete=MagicMock(),
            on_session_update=MagicMock(),
            on_sessions_replayed=MagicMock(),
        ),
    )
    return Coordinator(
        callbacks=callbacks,
        config=NATSConfig(
            instance_id=uuid.uuid4().hex,
            monitor_port=8222,
            network=network,
            presence_ttl=20.0,
            replicas=3,
            servers=("nats://localhost:4222",),
            session_ttl=600.0,
            token=NATS_CREDENTIAL,
        ),
        envelope=Envelope(bot_id, COORDINATION_KEY),
    )


def noop_help(kind: str, channel: str, presence: BotPresence) -> None:
    """Accept and ignore any help request."""
    del kind, channel, presence


def noop_presence(presence: BotPresence) -> None:
    """Accept and ignore a presence update."""
    del presence


def noop_presence_delete(bot_id: str) -> None:
    """Accept and ignore a presence deletion."""
    del bot_id


def connect_owned(coordinator: Coordinator) -> AsyncMock:
    """Connect a coordinator with open stores and owned presence.

    Every readiness condition then holds except the watch replay, which each
    test completes or withholds itself. Returns the connected client mock.
    """
    nc = AsyncMock(is_connected=True)
    coordinator.nc = nc
    for store in coordinator.stores:
        store.kv = MagicMock()

    coordinator.claim.state = PresenceState.OWNED
    return nc


def closing_client(coordinator: Coordinator) -> MagicMock:
    """Build a connected client whose close() runs callbacks as nats-py does.

    nats-py awaits the disconnected and then the closed callback from inside
    close(), so the coordinator sees its own close as it happens.
    """
    nc = MagicMock(is_closed=False, is_connected=True)

    async def close() -> None:
        nc.is_closed = True
        nc.is_connected = False
        await coordinator.on_disconnected()
        await coordinator.on_closed()

    nc.close = AsyncMock(side_effect=close)
    return nc


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
        operation=None,
        revision=1,
        value=json.dumps(record).encode(),
    )


def watcher(*entries: object) -> tuple[AsyncMock, AsyncMock]:
    """Build a KV handle and watcher yielding the given entries.

    Creating a key returns its revision, CREATED_REVISION, as JetStream does.
    """
    result = AsyncMock()
    result.__aiter__ = MagicMock(return_value=result)
    result.__anext__ = AsyncMock(side_effect=[*entries, StopAsyncIteration])
    result.stop = AsyncMock(return_value=None)
    kv = AsyncMock()
    kv.create = AsyncMock(return_value=CREATED_REVISION)
    kv.watchall = AsyncMock(return_value=result)
    return kv, result


class CoordinatorUnitTests(unittest.IsolatedAsyncioTestCase):
    """Tests for coordinator boundaries that do not require live NATS."""

    async def test_help_request_broadcasts_signed_message(self) -> None:
        """Publish one signed request on the kind's subject, with no reply inbox."""
        coordinator = build_coordinator("beta")
        coordinator.nc = AsyncMock()
        payload = {"channel": "#test", "presence": BETA_PRESENCE}

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.request_help("op", payload)

        coordinator.nc.publish.assert_awaited_once()
        assert coordinator.nc.publish.await_args.kwargs == {}
        subject, data = coordinator.nc.publish.await_args.args
        assert subject == f"{coordinator.ns}.op"
        assert Envelope("alpha", COORDINATION_KEY).decode(subject, data) == (
            "beta",
            payload,
        )

    async def test_help_request_publish_failure_is_contained(self) -> None:
        """Drop a request whose publish fails; the next tick asks again."""
        coordinator = build_coordinator("beta")
        coordinator.nc = AsyncMock()

        coordinator.nc.publish.side_effect = NatsError("connection closed")

        with patch.object(Coordinator, "ready", PropertyMock(return_value=True)):
            await coordinator.request_help(
                "op",
                {"channel": "#test", "presence": BETA_PRESENCE},
            )

        coordinator.nc.publish.assert_awaited_once()

    async def test_peer_help_request_reaches_callback(self) -> None:
        """Hand a peer's signed request to the bot with the kind its subject names."""
        coordinator = build_coordinator("alpha")
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

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(coordinator.callbacks, "on_help", callback),
        ):
            await coordinator.deliver_help(message)

        callback.assert_called_once_with("unban", "#test", BotPresence(**BETA_PRESENCE))

    async def test_help_subscription_covers_every_kind(self) -> None:
        """Subscribe once to the namespace, so every help kind is delivered."""
        coordinator = build_coordinator("alpha")
        nc = AsyncMock()

        await coordinator.subscribe_help(nc)

        nc.subscribe.assert_awaited_once_with(
            f"{coordinator.ns}.*",
            cb=coordinator.deliver_help,
        )

    async def test_own_help_request_is_skipped(self) -> None:
        """Ignore this bot's own broadcast, which NATS echoes back to it."""
        coordinator = build_coordinator("beta")
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

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(coordinator.callbacks, "on_help", callback),
        ):
            await coordinator.deliver_help(message)

        callback.assert_not_called()

    async def test_decode_help_rejects_malformed_requests(self) -> None:
        """Warn about and drop a signed request with a malformed channel or presence."""
        sender = Envelope("beta", COORDINATION_KEY)

        def decode(payload: dict[str, object]) -> tuple[str, BotPresence] | None:
            # A fresh coordinator, so no earlier warning throttles this one.
            coordinator = build_coordinator("alpha")
            subject = f"{coordinator.ns}.op"
            data = sender.encode(subject, payload)
            return coordinator.decode_help(Msg(MagicMock(), subject=subject, data=data))

        malformed: dict[str, dict[str, object]] = {
            "missing channel": {"presence": BETA_PRESENCE},
            "missing presence": {"channel": "#test"},
            "non-string channel": {"channel": 7, "presence": BETA_PRESENCE},
            "string presence": {"channel": "#test", "presence": "beta"},
            "empty host": {
                "channel": "#test",
                "presence": {**BETA_PRESENCE, "host": ""},
            },
            "presence of another bot": {
                "channel": "#test",
                "presence": {**BETA_PRESENCE, "bot_id": "spoofed"},
            },
        }
        for label, payload in malformed.items():
            with (
                self.subTest(label),
                self.assertLogs("botnats.nats.coordinator", level="WARNING"),
            ):
                assert decode(payload) is None

        well_formed: dict[str, object] = {"channel": "#test", "presence": BETA_PRESENCE}
        assert decode(well_formed) == ("#test", BotPresence(**BETA_PRESENCE))

    async def test_callback_error_surfaces(self) -> None:
        """Verify callback defects are not mislabeled as malformed input."""
        coordinator = build_coordinator("alpha")
        subject = f"{coordinator.ns}.op"
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(
                subject,
                {"channel": "#test", "presence": BETA_PRESENCE},
            ),
        )

        def fail(kind: str, channel: str, presence: BotPresence) -> None:
            del kind, channel, presence
            msg = "callback failed"
            raise ValueError(msg)

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(coordinator.callbacks, "on_help", fail),
            self.assertRaisesRegex(ValueError, "callback failed"),
        ):
            await coordinator.deliver_help(message)

    async def test_close_releases_connection(self) -> None:
        """Cancel watches and release owned presence, KV handles, and the connection."""
        coordinator = build_coordinator("alpha")
        nc = MagicMock(is_closed=False)
        nc.close = AsyncMock()
        coordinator.nc = nc
        coordinator.claim.adopt(7)
        for store in coordinator.stores:
            store.js = MagicMock()
            store.kv = MagicMock()

        # The presence key is deleted through the open bucket, so releasing
        # it after the stores reset would delete nothing.
        presence_kv = AsyncMock()
        presence_kv.delete = AsyncMock(return_value=True)
        coordinator.presence_store.kv = presence_kv
        watch = asyncio.create_task(hang())
        coordinator.watch_tasks.append(watch)

        async with asyncio.timeout(5):
            await coordinator.close()
            await coordinator.close()

        assert watch.cancelled()
        assert coordinator.nc is None
        assert not coordinator.claim.owned
        assert coordinator.claim.revision is None
        assert not coordinator.attempts.ready
        assert not coordinator.channels_store.ready
        assert not coordinator.claims.ready
        assert not coordinator.presence_store.ready
        assert not coordinator.sessions.ready
        presence_kv.delete.assert_awaited_once_with("alpha", last=7)
        nc.close.assert_awaited_once_with()

    async def test_close_completes_when_presence_release_fails(self) -> None:
        """Finish shutdown when deleting the owned presence key fails."""
        coordinator = build_coordinator("alpha")
        nc = MagicMock(is_closed=False)
        nc.close = AsyncMock()
        coordinator.nc = nc
        coordinator.claim.adopt(7)
        presence_kv = AsyncMock()
        presence_kv.delete.side_effect = NatsError("timeout")
        coordinator.presence_store.kv = presence_kv

        await coordinator.close()

        presence_kv.delete.assert_awaited_once_with("alpha", last=7)
        assert not coordinator.claim.owned
        assert not coordinator.presence_store.ready
        nc.close.assert_awaited_once_with()

    async def test_deliberate_close_does_not_restart(self) -> None:
        """Leave the client closed when nats-py reports the close close() asked for."""
        coordinator = build_coordinator("alpha")
        nc = closing_client(coordinator)
        coordinator.nc = nc

        with patch("botnats.nats.coordinator.nats.connect", AsyncMock()) as connect:
            await coordinator.close()
            # nats-py ran on_closed inside close(); clean up any restart first.
            restart = coordinator.resync_task
            await coordinator.cancel_resync()

        assert restart is None
        connect.assert_not_awaited()
        nc.close.assert_awaited_once_with()
        assert coordinator.nc is None

    async def test_closed_client_restarts(self) -> None:
        """Drop a client nats-py closed for good and connect again in the background."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_closed=True)
        nc = MagicMock(is_connected=True)
        nc.subscribe = AsyncMock()
        connect = AsyncMock(return_value=nc)

        with (
            patch("botnats.nats.coordinator.nats.connect", connect),
            patch.object(coordinator, "init_stores", AsyncMock()),
            patch.object(coordinator, "start_watches", AsyncMock()) as start_watches,
        ):
            await coordinator.on_closed()
            restart = coordinator.resync_task
            assert restart is not None
            assert coordinator.nc is None
            async with asyncio.timeout(5):
                await restart

        connect.assert_awaited_once()
        assert connect.await_args is not None
        assert connect.await_args.kwargs["closed_cb"] == coordinator.on_closed
        assert coordinator.nc is nc
        nc.subscribe.assert_awaited_once()
        start_watches.assert_awaited_once_with()

    async def test_restart_survives_closing_its_failed_client(self) -> None:
        """Keep restarting after the restart closes a client whose setup failed."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_closed=True)
        # Closing it runs the disconnect callback, which cancels the resync
        # slot, from inside the restart that slot holds.
        failed = closing_client(coordinator)
        failed.subscribe = AsyncMock(side_effect=ConnectionClosedError)
        nc = MagicMock(is_connected=True)
        nc.subscribe = AsyncMock()
        connect = AsyncMock(side_effect=[failed, nc])
        watching = asyncio.Event()
        start_watches = AsyncMock(side_effect=watching.set)

        with (
            patch("botnats.nats.coordinator.nats.connect", connect),
            patch.object(coordinator, "init_stores", AsyncMock()),
            patch.object(coordinator, "start_watches", start_watches),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.on_closed()
            restart = coordinator.resync_task
            assert restart is not None
            async with asyncio.timeout(5):
                # Wait for the outcome, not the task: a restart stuck
                # cancelling itself cannot be awaited or cancelled.
                await watching.wait()
                await restart

        failed.close.assert_awaited_once_with()
        assert connect.await_count == 2
        assert coordinator.nc is nc
        start_watches.assert_awaited_once_with()

    async def test_cancelled_restart_keeps_help_subscription(self) -> None:
        """Subscribe to help requests before a restart waits for JetStream.

        A drop of the new client cancels the restart from nats-py's disconnect
        callback, and the reconnect replays only subscriptions the client holds.
        """
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_closed=True)
        nc = MagicMock(is_connected=True)
        nc.subscribe = AsyncMock()
        connect = AsyncMock(return_value=nc)
        opening = asyncio.Event()

        async def open_stores() -> None:
            # JetStream is still down.
            opening.set()
            await asyncio.Event().wait()

        with (
            patch("botnats.nats.coordinator.nats.connect", connect),
            patch.object(coordinator, "init_stores", open_stores),
        ):
            async with asyncio.timeout(5):
                await coordinator.on_closed()
                restart = coordinator.resync_task
                assert restart is not None
                await opening.wait()
                await coordinator.on_disconnected()
                await asyncio.gather(restart, return_exceptions=True)

        assert restart.cancelled()
        assert coordinator.nc is nc
        nc.subscribe.assert_awaited_once_with(
            f"{coordinator.ns}.*",
            cb=coordinator.deliver_help,
        )

    async def test_restart_behind_connected_start_does_nothing(self) -> None:
        """Leave the watches to a start that reconnected while a restart waited.

        nats-py closed the start's first client while its stores opened; the
        start connects again itself and the restart queues on its lock.
        """
        coordinator = build_coordinator("alpha")
        first = MagicMock(is_closed=False, is_connected=True, subscribe=AsyncMock())
        second = MagicMock(is_closed=False, is_connected=True, subscribe=AsyncMock())
        connect = AsyncMock(side_effect=[first, second])
        opening = asyncio.Event()
        replaced = asyncio.Event()

        async def open_stores() -> None:
            # init_stores returns once its client is no longer the current one.
            if coordinator.nc is first:
                opening.set()
                await replaced.wait()

        with (
            patch("botnats.nats.coordinator.nats.connect", connect),
            patch.object(coordinator, "init_stores", open_stores),
            patch.object(coordinator, "start_watches", AsyncMock()) as start_watches,
        ):
            initial = asyncio.create_task(coordinator.start())
            async with asyncio.timeout(5):
                await opening.wait()
                first.is_closed = True
                first.is_connected = False
                await coordinator.on_closed()
                restart = coordinator.resync_task
                assert restart is not None
                replaced.set()
                await initial
                await restart

        assert coordinator.nc is second
        assert connect.await_count == 2
        start_watches.assert_awaited_once_with()

    async def test_close_cancels_restart(self) -> None:
        """Stop a restart that is still connecting when the bot shuts down."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_closed=True)
        connecting = asyncio.Event()

        async def connect(**options: object) -> None:
            del options
            connecting.set()
            await asyncio.Event().wait()

        with patch("botnats.nats.coordinator.nats.connect", connect):
            # Without the cancel, the restart never finishes: fail, not hang.
            async with asyncio.timeout(5):
                await coordinator.on_closed()
                restart = coordinator.resync_task
                assert restart is not None
                await connecting.wait()
                await coordinator.close()
                await asyncio.gather(restart, return_exceptions=True)

        assert restart.cancelled()
        assert coordinator.resync_task is None

    async def test_disconnect_resets_stores(self) -> None:
        """Verify a Core NATS disconnect cancels watches and clears store readiness."""
        coordinator = build_coordinator("alpha")
        for store in coordinator.stores:
            store.js = MagicMock()
            store.kv = MagicMock()

        watch = asyncio.create_task(hang())
        coordinator.watch_tasks.append(watch)
        async with asyncio.timeout(5):
            await coordinator.on_disconnected()

        assert watch.cancelled()
        assert not coordinator.watch_tasks
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
        coordinator = build_coordinator("alpha")
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
        coordinator = build_coordinator("alpha")

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

    async def test_nats_errors_are_rate_limited(self) -> None:
        """Log one warning for transport errors that repeat during an outage."""
        coordinator = build_coordinator("alpha")

        with self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs:
            await coordinator.on_error(OSError("connection reset"))
            await coordinator.on_error(OSError("connection reset"))

        assert [log.getMessage() for log in logs.records] == [
            "NATS error: connection reset",
        ]

    async def test_duplicate_bot_id_blocks_coordination(self) -> None:
        """Prevent a conflicting bot ID from publishing or acting on requests."""
        coordinator = build_coordinator("alpha")
        nc = connect_owned(coordinator)
        coordinator.synced_watches.update(coordinator.watches())
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
        # The duplicate claim is the only thing standing between it and ready.
        assert coordinator.ready
        coordinator.claim.state = PresenceState.DUPLICATE

        await coordinator.request_help(
            "op",
            {"channel": "#test", "presence": {**BETA_PRESENCE, "bot_id": "alpha"}},
        )
        nc.publish.assert_not_awaited()

        with patch.object(coordinator.callbacks, "on_help", callback):
            await coordinator.deliver_help(message)

        callback.assert_not_called()

    async def test_init_stores_generation_guard(self) -> None:
        """Verify a newer init_stores call cancels the previous retry loop."""
        coordinator = build_coordinator("alpha")
        nc = MagicMock(is_connected=True)
        nc.jetstream.return_value = MagicMock()
        coordinator.nc = nc
        attempts = 0

        async def fail_then_supersede(*arguments: object) -> None:
            del arguments
            nonlocal attempts
            attempts += 1
            if attempts > 1:
                # Escapes the retry loop, which only absorbs transient errors.
                self.fail("superseded initialization retried")

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
        """Keep retrying JetStream initialization for as long as it fails."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        js = coordinator.nc.jetstream.return_value
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

        # Every store opens on the client's JetStream context.
        assert open_attempt.await_args_list == [call(js)] * 12
        assert open_store.await_args_list == [call(js)] * 4
        assert sleep.await_count == 11

    async def test_init_stores_surfaces_programming_errors(self) -> None:
        """Do not retry a programming error as though it were an outage."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        coordinator.nc.jetstream.return_value = MagicMock()
        open_store = AsyncMock()

        # A bare RuntimeError is a bug too, unlike StoreUnavailableError.
        for error in (ValueError("bad config"), RuntimeError("bug")):
            # A retry would succeed, so only surfacing the error raises.
            open_attempt = AsyncMock(side_effect=[error, None])
            with (
                self.subTest(error=error),
                patch.object(AttemptStore, "open", open_attempt),
                patch.object(ChannelStore, "open", open_store),
                patch.object(ClaimStore, "open", open_store),
                patch.object(PresenceStore, "open", open_store),
                patch.object(SessionStore, "open", open_store),
                patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
                self.assertRaisesRegex(type(error), str(error)),
            ):
                await coordinator.init_stores()

    async def test_malformed_message_is_ignored(self) -> None:
        """Verify malformed wire data never reaches its callback."""
        coordinator = build_coordinator("alpha")
        callback = MagicMock()
        message = Msg(MagicMock(), subject="bad", data=b"not-json")

        with (
            patch.object(Coordinator, "ready", PropertyMock(return_value=True)),
            patch.object(coordinator.callbacks, "on_help", callback),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.deliver_help(message)

        callback.assert_not_called()

    async def test_malformed_warning_is_throttled(self) -> None:
        """Verify malformed traffic cannot flood the warning log."""
        coordinator = build_coordinator("alpha")

        # The module's binding only: time.monotonic itself drives the loop.
        with (
            patch("botnats.nats.coordinator.time") as clock,
            self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs,
        ):
            clock.monotonic.return_value = 10.0
            coordinator.warn_decode(SUBJECT, ValueError("bad"))
            clock.monotonic.return_value = 11.0
            coordinator.warn_decode(SUBJECT, ValueError("bad"))
            clock.monotonic.return_value = 16.0
            coordinator.warn_decode(SUBJECT, ValueError("bad"))

        assert len(logs.output) == 2
        assert "suppressed 1 similar warning(s)" in logs.output[-1]

    async def test_network_namespaces(self) -> None:
        """Verify separate network groups share no subjects or KV buckets."""
        first = build_coordinator("alpha", "efnet")
        second = build_coordinator("alpha", "undernet")

        assert first.ns != second.ns
        assert {store.bucket for store in first.stores}.isdisjoint(
            store.bucket for store in second.stores
        )

    async def test_stores_use_configured_retention(self) -> None:
        """Open every bucket with the configured replicas and record TTLs."""
        coordinator = build_coordinator("alpha")
        config = coordinator.config

        assert {store.replicas for store in coordinator.stores} == {config.replicas}
        assert coordinator.presence_store.ttl == config.presence_ttl
        assert coordinator.sessions.ttl == config.session_ttl

    async def test_reconnect_retries_stores(self) -> None:
        """Verify reconnect restores all stores before starting watches."""
        coordinator = build_coordinator("alpha")
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
            async with asyncio.timeout(5):
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
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock()

        resync = AsyncMock(side_effect=TypeError("bug"))
        with (
            patch.object(coordinator, "resync", resync),
            self.assertLogs("botnats.nats.coordinator", level="ERROR") as logs,
        ):
            await coordinator.on_reconnected()
            task = coordinator.resync_task
            assert task is not None
            async with asyncio.timeout(5):
                await asyncio.gather(task, return_exceptions=True)

        assert coordinator.resync_task is None
        assert any("resynchronization failed" in line for line in logs.output)

    async def test_crash_logs_are_rate_limited(self) -> None:
        """Throttle repeated crash tracebacks from one watch."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        crashes = [ValueError("boom"), ValueError("boom")]
        recovered = asyncio.Event()

        async def crash_twice(*arguments: object) -> None:
            del arguments
            if crashes:
                raise crashes.pop()

            recovered.set()
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
                await recovered.wait()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        assert sum("crashed" in line for line in logs.output) == 1

    async def test_replaced_resync_keeps_new_task(self) -> None:
        """Keep the new resync task when a superseded one finishes after it."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock()
        stopping = asyncio.Event()
        release = asyncio.Event()

        async def slow_to_stop() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                stopping.set()
                async with asyncio.timeout(5):
                    await release.wait()

                raise

        with patch.object(coordinator, "resync", slow_to_stop):
            async with asyncio.timeout(5):
                await coordinator.on_reconnected()
                first = coordinator.resync_task
                # A disconnect cancels the first resync, which is slow to stop,
                # and a reconnect starts the second before the first finishes.
                disconnect = asyncio.create_task(coordinator.on_disconnected())
                await stopping.wait()
                await coordinator.on_reconnected()
                second = coordinator.resync_task
                release.set()
                await disconnect

            assert first is not None
            assert first.cancelled()
            assert second is not None
            assert coordinator.resync_task is second
            await coordinator.cancel_resync()

    async def test_disconnect_cancels_resync(self) -> None:
        """Cancel an in-flight resynchronization when Core NATS drops."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock()

        with patch.object(coordinator, "resync", hang):
            # Without the cancel, the resync never finishes: fail, not hang.
            async with asyncio.timeout(5):
                await coordinator.on_reconnected()
                task = coordinator.resync_task
                assert task is not None
                await coordinator.on_disconnected()
                await asyncio.gather(task, return_exceptions=True)

        assert task.cancelled()
        assert coordinator.resync_task is None

    async def test_ready_waits_for_watch_replay(self) -> None:
        """Keep readiness false until every KV watch reaches its sentinel."""
        coordinator = build_coordinator("alpha")
        nc = connect_owned(coordinator)
        *replayed, last = sorted(coordinator.watches())

        coordinator.synced_watches.update(replayed)
        assert not coordinator.ready

        coordinator.synced_watches.add(last)
        assert coordinator.ready

        # A closed store, a dropped connection, or an unclaimed presence key
        # still withholds it.
        coordinator.attempts.kv = None
        assert not coordinator.ready

        coordinator.attempts.kv = MagicMock()
        nc.is_connected = False
        assert not coordinator.ready

        nc.is_connected = True
        assert coordinator.ready
        coordinator.claim.state = PresenceState.UNCLAIMED
        assert not coordinator.ready

    async def test_watch_channel_applies_valid_record(self) -> None:
        """Hand a signed, key-bound channel record to the bot as a ChannelRecord."""
        coordinator = build_coordinator("alpha")
        callback = MagicMock()
        record = ChannelRecord.new("#test", "key", present=True)
        signed = coordinator.channels_store.sign(astuple(record))
        entry = SimpleNamespace(
            key=coordinator.channels_store.key("#test"),
            operation=None,
            value=json.dumps(signed).encode(),
        )
        kv, _ = watcher(entry, None)
        coordinator.channels_store.kv = kv
        synced = MagicMock()

        with patch.object(coordinator.callbacks, "on_channel", callback):
            await coordinator.watch_channels(synced)

        callback.assert_called_once_with(astuple(record))
        synced.assert_called_once_with()

    async def test_watch_channel_rejects_mismatched_key(self) -> None:
        """Ignore a valid channel record stored under the wrong opaque key."""
        coordinator = build_coordinator("alpha")
        callback = MagicMock()
        record = ChannelRecord.new("#test", None, present=True)
        signed = coordinator.channels_store.sign(astuple(record))
        entry = SimpleNamespace(
            key=coordinator.channels_store.key("#other"),
            operation=None,
            value=json.dumps(signed).encode(),
        )
        kv, _ = watcher(entry, None)
        coordinator.channels_store.kv = kv

        with patch.object(coordinator.callbacks, "on_channel", callback):
            await coordinator.watch_channels(MagicMock())

        callback.assert_not_called()

    async def test_watch_presence_binds_key_and_applies_delete(self) -> None:
        """Reject misplaced or undecodable values; a peer's delete keeps the claim."""
        coordinator = build_coordinator("alpha")
        coordinator.claim.adopt(5)
        update = MagicMock()
        delete = MagicMock()
        misplaced = SimpleNamespace(
            key="beta",
            operation=None,
            revision=1,
            value=presence_entry().value,
        )
        undecodable = SimpleNamespace(
            key="beta",
            operation=None,
            revision=2,
            value=b"x",
        )
        removed = SimpleNamespace(key="beta", operation="DEL", value=None)
        kv, _ = watcher(misplaced, undecodable, removed, None)
        coordinator.presence_store.kv = kv

        with (
            patch.object(coordinator.callbacks, "on_presence", update),
            patch.object(coordinator.callbacks, "on_presence_delete", delete),
        ):
            await coordinator.watch_presence(MagicMock())

        update.assert_not_called()
        delete.assert_called_once_with("beta")
        # Only a delete of this bot's own key expires its claim.
        kv.create.assert_not_awaited()
        assert coordinator.claim.owned
        assert coordinator.claim.revision == 5

    async def test_watch_presence_applies_valid_peer_record(self) -> None:
        """Hand a peer's signed, key-bound presence record to the bot."""
        coordinator = build_coordinator("alpha")
        update = MagicMock()
        record: dict[str, object] = {**BETA_PRESENCE, "timestamp": int(time.time())}
        record["signature"] = presence_signature(COORDINATION_KEY, "efnet", record)
        entry = SimpleNamespace(
            key="beta",
            operation=None,
            revision=1,
            value=json.dumps(record).encode(),
        )
        kv, _ = watcher(None, entry)
        coordinator.presence_store.kv = kv

        with patch.object(coordinator.callbacks, "on_presence", update):
            await coordinator.watch_presence(MagicMock())

        update.assert_called_once_with(BotPresence(**BETA_PRESENCE))
        # Another instance's record on a peer's key is no duplicate of ours.
        assert coordinator.claim.owned

    async def test_watch_presence_detects_starting_duplicate(self) -> None:
        """Yield to another instance's placeholder claim, which is not yet a peer."""
        # Differs from the record's bot ID in case only: claims ignore case.
        coordinator = build_coordinator("Alpha")
        update = MagicMock()
        # A starting process claims its key before it knows its IRC identity.
        record: dict[str, object] = {
            "bot_id": "alpha",
            "host": "",
            "instance_id": "other-instance",
            "nick": "",
            "user": "",
            "timestamp": int(time.time()),
        }
        record["signature"] = presence_signature(COORDINATION_KEY, "efnet", record)
        entry = SimpleNamespace(
            key="alpha",
            operation=None,
            revision=1,
            value=json.dumps(record).encode(),
        )
        kv, _ = watcher(None, entry)
        coordinator.presence_store.kv = kv

        with (
            patch.object(coordinator.callbacks, "on_presence", update),
            self.assertLogs("botnats.nats.claim", level="ERROR"),
        ):
            await coordinator.watch_presence(MagicMock())

        assert coordinator.claim.duplicate
        update.assert_not_called()

    async def test_watch_presence_ignores_record_copied_to_own_key(self) -> None:
        """Ignore a peer's signed record copied onto this bot's presence key."""
        coordinator = build_coordinator("alpha")
        update = MagicMock()
        record: dict[str, object] = {**BETA_PRESENCE, "timestamp": int(time.time())}
        record["signature"] = presence_signature(COORDINATION_KEY, "efnet", record)
        assert coordinator.presence_store.valid("beta", record)
        entry = SimpleNamespace(
            key="alpha",
            operation=None,
            revision=1,
            value=json.dumps(record).encode(),
        )
        kv, _ = watcher(None, entry)
        coordinator.presence_store.kv = kv

        with patch.object(coordinator.callbacks, "on_presence", update):
            await coordinator.watch_presence(MagicMock())

        update.assert_not_called()
        assert coordinator.claim.owned

    async def test_watch_survives_lost_reclaim_races(self) -> None:
        """Contain reclaim exhaustion to the key instead of the whole watch."""
        coordinator = build_coordinator("alpha")
        entry = SimpleNamespace(key="alpha", operation=KV_DEL, value=None)
        kv, _ = watcher(entry, None)
        coordinator.presence_store.kv = kv
        synced = MagicMock()

        with (
            patch.object(
                coordinator.claim,
                "claim",
                AsyncMock(side_effect=NatsError("lost repeated update races")),
            ),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.watch_presence(synced)

        synced.assert_called_once_with()

    async def test_session_delete_event_reports_key(self) -> None:
        """Report a live session delete by its opaque key."""
        coordinator = build_coordinator("alpha")
        key = coordinator.sessions.key("owner!user@host")
        deleted = SimpleNamespace(key=key, operation=KV_DEL, value=None)
        kv, _ = watcher(None, deleted)
        coordinator.sessions.kv = kv
        delete = MagicMock()

        with patch.object(coordinator.callbacks, "on_session_delete", delete):
            await coordinator.watch_sessions(MagicMock())

        delete.assert_called_once_with(key)

    async def test_expired_session_update_reaches_owner(self) -> None:
        """Hand an expired session record to its owner, which drops it."""
        coordinator = build_coordinator("alpha")
        key = coordinator.sessions.key("owner!user@host")
        expiry = time.time() - 1
        entry = SimpleNamespace(
            key=key,
            operation=None,
            value=json.dumps(session_record(expiry)).encode(),
        )
        kv, _ = watcher(entry, None)
        coordinator.sessions.kv = kv
        update = MagicMock()

        with patch.object(coordinator.callbacks, "on_session_update", update):
            await coordinator.watch_sessions(MagicMock())

        update.assert_called_once_with(key, session_value(expiry), replaying=True)

    async def test_live_session_update_is_not_replaying(self) -> None:
        """Report records after the replay sentinel as live, not replayed."""
        coordinator = build_coordinator("alpha")
        key = coordinator.sessions.key("owner!user@host")
        expiry = time.time() + 60
        entry = SimpleNamespace(
            key=key,
            operation=None,
            value=json.dumps(session_record(expiry)).encode(),
        )
        kv, _ = watcher(entry, None, entry)
        coordinator.sessions.kv = kv
        update = MagicMock()

        with patch.object(coordinator.callbacks, "on_session_update", update):
            await coordinator.watch_sessions(MagicMock())

        session = session_value(expiry)
        assert update.call_args_list == [
            call(key, session, replaying=True),
            call(key, session, replaying=False),
        ]

    async def test_help_ignored_until_watches_replay(self) -> None:
        """Ignore peer requests while watches replay, even with presence owned."""
        coordinator = build_coordinator("alpha")
        connect_owned(coordinator)
        callback = MagicMock()
        subject = f"{coordinator.ns}.op"
        payload = {"channel": "#test", "presence": BETA_PRESENCE}
        message = Msg(
            MagicMock(),
            subject=subject,
            data=Envelope("beta", COORDINATION_KEY).encode(subject, payload),
        )

        with patch.object(coordinator.callbacks, "on_help", callback):
            await coordinator.deliver_help(message)
            callback.assert_not_called()

            # The same request is accepted once the replay completes.
            coordinator.synced_watches.update(coordinator.watches())
            await coordinator.deliver_help(message)

        callback.assert_called_once_with("op", "#test", BotPresence(**BETA_PRESENCE))

    async def test_disconnect_does_not_wait_for_presence_write(self) -> None:
        """Reset at once during a slow write, which then records no ownership."""
        coordinator = build_coordinator("alpha")
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
                await write

        assert coordinator.claim.state is PresenceState.UNCLAIMED
        assert coordinator.claim.revision is None

    async def test_empty_session_replay_reports_no_keys(self) -> None:
        """Report an empty replay, so the owner drops every cached session."""
        coordinator = build_coordinator("alpha")
        kv, _ = watcher(None)
        coordinator.sessions.kv = kv
        replayed = MagicMock()
        synced = MagicMock()

        with patch.object(coordinator.callbacks, "on_sessions_replayed", replayed):
            await coordinator.watch_sessions(synced)

        replayed.assert_called_once_with(set())
        synced.assert_called_once_with()

    async def test_session_watch_skips_misplaced_record(self) -> None:
        """Skip an undecodable or misplaced session record before the owner sees it."""
        coordinator = build_coordinator("alpha")
        key = coordinator.sessions.key("owner!user@host")
        expiry = time.time() + 60
        valid = session_record(expiry)
        undecodable = SimpleNamespace(key=key, operation=None, value=b"not json")
        # Correctly signed, but held under another identity's key. The store
        # tests cover every other way SessionStore.parse rejects a record.
        entries = [
            SimpleNamespace(
                key=record_key,
                operation=None,
                value=json.dumps(valid).encode(),
            )
            for record_key in (key, coordinator.sessions.key("other!user@host"))
        ]
        kv, _ = watcher(undecodable, *entries, None)
        coordinator.sessions.kv = kv
        update = MagicMock()
        replayed = MagicMock()

        with (
            patch.object(coordinator.callbacks, "on_session_update", update),
            patch.object(coordinator.callbacks, "on_sessions_replayed", replayed),
        ):
            await coordinator.watch_sessions(MagicMock())

        update.assert_called_once_with(key, session_value(expiry), replaying=True)
        replayed.assert_called_once_with({key})

    async def test_watch_presence_keeps_conflict_during_replay(self) -> None:
        """Verify a duplicate detected during replay is not resolved by the sentinel."""
        # Differs from the record's bot ID in case only: claims ignore case.
        coordinator = build_coordinator("Alpha")
        entry = presence_entry()
        kv, _ = watcher(entry, None)
        # The occupant still holds the key when the replay ends.
        kv.create = AsyncMock(side_effect=KeyWrongLastSequenceError)
        kv.get = AsyncMock(return_value=entry)
        coordinator.presence_store.kv = kv

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence(MagicMock())

        assert coordinator.claim.duplicate

    async def test_watch_presence_reclaims_key_expired_after_replay(self) -> None:
        """Resolve a replayed duplicate whose record expired before the replay ended."""
        coordinator = build_coordinator("alpha")
        # TTL expiry emits no watch event; creating the free key succeeds.
        kv, _ = watcher(presence_entry(), None)
        coordinator.presence_store.kv = kv

        with self.assertLogs("botnats.nats.claim", level="INFO") as logs:
            await coordinator.watch_presence(MagicMock())

        assert [log.getMessage() for log in logs.records] == [
            "duplicate bot ID detected: alpha",
            "duplicate bot ID conflict resolved: alpha",
        ]
        assert coordinator.claim.owned
        assert coordinator.claim.revision == CREATED_REVISION

    async def test_watch_presence_ignores_unsigned_record(self) -> None:
        """Verify an unsigned presence record cannot demote the owner."""
        coordinator = build_coordinator("alpha")
        coordinator.claim.state = PresenceState.OWNED
        kv, _ = watcher(None, presence_entry(signed=False))
        coordinator.presence_store.kv = kv

        await coordinator.watch_presence(MagicMock())

        assert coordinator.claim.owned

    async def test_watch_presence_reclaim_loser_stays_conflicted(self) -> None:
        """Verify the loser of atomic presence reclaim stays a duplicate."""
        coordinator = build_coordinator("alpha")
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

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence(MagicMock())

        assert coordinator.claim.duplicate

    async def test_watch_presence_resolves_absent_conflict(self) -> None:
        """Verify a conflict is resolved when the duplicate is gone on replay."""
        coordinator = build_coordinator("alpha")
        coordinator.claim.state = PresenceState.DUPLICATE
        kv, _ = watcher(None)
        coordinator.presence_store.kv = kv

        await coordinator.watch_presence(MagicMock())

        assert not coordinator.claim.duplicate
        assert coordinator.claim.revision == CREATED_REVISION

    async def test_watch_presence_resolves_on_delete(self) -> None:
        """Verify a live conflict resolves when the presence entry expires."""
        coordinator = build_coordinator("alpha")
        delete_entry = SimpleNamespace(
            key="alpha",
            operation="DEL",
            value=None,
        )
        entry = presence_entry()
        kv, _ = watcher(entry, None, delete_entry)
        # The occupant holds the key until it is deleted.
        kv.create = AsyncMock(
            side_effect=[KeyWrongLastSequenceError, CREATED_REVISION],
        )
        kv.get = AsyncMock(return_value=entry)
        coordinator.presence_store.kv = kv

        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            await coordinator.watch_presence(MagicMock())

        assert not coordinator.claim.duplicate
        assert coordinator.claim.revision == CREATED_REVISION

    async def test_watch_presence_keeps_own_heartbeat(self) -> None:
        """Keep owning the key at the revision of this instance's own heartbeat."""
        coordinator = build_coordinator("alpha")
        record: dict[str, object] = {
            "bot_id": "alpha",
            "host": "host",
            "instance_id": coordinator.config.instance_id,
            "nick": "alpha",
            "user": "user",
            "timestamp": int(time.time()),
        }
        record["signature"] = presence_signature(COORDINATION_KEY, "efnet", record)
        heartbeat = SimpleNamespace(
            key="alpha",
            operation=None,
            revision=CREATED_REVISION + 1,
            value=json.dumps(record).encode(),
        )
        kv, _ = watcher(None, heartbeat)
        coordinator.presence_store.kv = kv

        await coordinator.watch_presence(MagicMock())

        assert coordinator.claim.owned
        assert coordinator.claim.revision == CREATED_REVISION + 1

    async def test_watch_presence_recreates_own_deleted_key(self) -> None:
        """Stop owning this bot's deleted key and create it again."""
        # Differs from the deleted key in case only: claims ignore case.
        coordinator = build_coordinator("Alpha")
        coordinator.claim.adopt(5)
        deleted = SimpleNamespace(key="alpha", operation=KV_DEL, value=None)
        kv, _ = watcher(None, deleted)
        coordinator.presence_store.kv = kv

        await coordinator.watch_presence(MagicMock())

        kv.create.assert_awaited_once()
        assert coordinator.claim.owned
        assert coordinator.claim.revision == CREATED_REVISION

    async def test_watch_restarts_on_transient_error(self) -> None:
        """Restart a watch after a transient JetStream error, requiring a new replay."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        failures = {
            "watch-channels": OSError("transient"),
            # KVStore.open raises this while JetStream handles are reset; a
            # watch must treat it as transient, not a crash.
            "watch-presence": StoreUnavailableError("JetStream is unavailable"),
        }
        restarted = {name: asyncio.Event() for name in failures}
        # Whether each restarted watch still found its failed run's marker.
        stale_markers: dict[str, bool] = {}

        async def fail_once(name: str, synced: Callable[[], None]) -> None:
            error = failures.pop(name, None)
            if error is not None:
                # The failed run had completed its replay.
                synced()
                raise error

            stale_markers[name] = name in coordinator.synced_watches
            restarted[name].set()
            await asyncio.Event().wait()

        with (
            patch.object(
                coordinator,
                "watch_channels",
                partial(fail_once, "watch-channels"),
            ),
            patch.object(
                coordinator,
                "watch_presence",
                partial(fail_once, "watch-presence"),
            ),
            patch.object(coordinator, "watch_sessions", hang),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()) as sleep,
            self.assertLogs("botnats.nats.coordinator", level="DEBUG") as logs,
        ):
            async with asyncio.timeout(5):
                await coordinator.start_watches()
                for event in restarted.values():
                    await event.wait()

                await coordinator.cancel_watches()

        # Each failed watch waits before its one restart instead of spinning.
        assert sleep.await_args_list == [call(RECONNECT_WAIT)] * len(restarted)
        # A restarted watch must replay again before readiness returns.
        assert stale_markers == {"watch-channels": False, "watch-presence": False}
        # Each failure is a rate-limited warning, never a crash traceback.
        assert sorted((log.levelname, log.getMessage()) for log in logs.records) == [
            ("WARNING", "watch watch-channels failed: transient"),
            ("WARNING", "watch watch-presence failed: JetStream is unavailable"),
        ]

    async def test_concurrent_start_watches_keeps_single_watcher_set(self) -> None:
        """Verify overlapping start_watches calls leave exactly one watcher set."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)

        with (
            patch.object(coordinator, "watch_channels", hang),
            patch.object(coordinator, "watch_presence", hang),
            patch.object(coordinator, "watch_sessions", hang),
        ):
            async with asyncio.timeout(5):
                await coordinator.start_watches()
                await asyncio.gather(
                    coordinator.start_watches(),
                    coordinator.start_watches(),
                )

            assert len(coordinator.watch_tasks) == len(coordinator.watches())
            assert {task.get_name() for task in coordinator.watch_tasks} == {
                "watch-channels",
                "watch-presence",
                "watch-sessions",
            }
            await coordinator.cancel_watches()

        assert not coordinator.watch_tasks

    async def test_superseded_watcher_surviving_cancellation_exits(self) -> None:
        """Eject a watcher whose cleanup replaced its CancelledError."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        watch_count = len(coordinator.watches())
        started = asyncio.Event()
        runs = 0

        async def swallow_cancel(synced: Callable[[], None]) -> None:
            nonlocal runs
            runs += 1
            if runs > watch_count:
                # Only a superseded watcher that failed to exit runs again;
                # end it so the regression fails below instead of hanging.
                raise asyncio.CancelledError

            synced()
            if runs == watch_count:
                started.set()

            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # Mimic a watch body whose `finally: await watcher.stop()`
                # raises a transport error, replacing the cancellation.
                msg = "connection closed"
                raise OSError(msg) from None

        with (
            patch.object(coordinator, "watch_channels", swallow_cancel),
            patch.object(coordinator, "watch_presence", swallow_cancel),
            patch.object(coordinator, "watch_sessions", swallow_cancel),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            async with asyncio.timeout(5):
                await coordinator.start_watches()
                old_tasks = list(coordinator.watch_tasks)
                with (
                    patch.object(coordinator, "watch_channels", hang),
                    patch.object(coordinator, "watch_presence", hang),
                    patch.object(coordinator, "watch_sessions", hang),
                ):
                    await started.wait()
                    await coordinator.start_watches()

                assert all(task.done() for task in old_tasks)
                assert not coordinator.synced_watches
                await coordinator.cancel_watches()

        assert runs == watch_count

    async def test_stale_watcher_cancellation_keeps_new_sync_markers(self) -> None:
        """Verify a slowly dying superseded watcher cannot wedge readiness."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        names = coordinator.watches().keys()
        started = asyncio.Event()
        replayed = asyncio.Event()
        runs = 0

        async def hang_slow_cancel(*arguments: object) -> None:
            del arguments
            nonlocal runs
            runs += 1
            if runs == len(names):
                started.set()

            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                # Die only after the newest watches replay, so this stale
                # watcher's cleanup runs after their sync markers are set.
                await replayed.wait()
                raise

        async def sync_and_hang(synced: Callable[[], None]) -> None:
            synced()
            if coordinator.synced_watches == names:
                replayed.set()

            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", hang_slow_cancel),
            patch.object(coordinator, "watch_presence", hang_slow_cancel),
            patch.object(coordinator, "watch_sessions", hang_slow_cancel),
        ):
            async with asyncio.timeout(5):
                await coordinator.start_watches()
                await started.wait()

        with (
            patch.object(coordinator, "watch_channels", sync_and_hang),
            patch.object(coordinator, "watch_presence", sync_and_hang),
            patch.object(coordinator, "watch_sessions", sync_and_hang),
        ):
            # The first call supersedes the stale watchers and waits for them
            # to die, which they do only after the second call's watches sync.
            async with asyncio.timeout(5):
                await asyncio.gather(
                    coordinator.start_watches(),
                    coordinator.start_watches(),
                )

            assert coordinator.synced_watches == names
            await coordinator.cancel_watches()

    async def test_watch_stops_watcher_on_error(self) -> None:
        """Verify a crashed watch coroutine stops its KV watcher subscription."""
        coordinator = build_coordinator("alpha")
        kv, subscription = watcher(OSError("disconnected"))
        coordinator.channels_store.kv = kv

        with self.assertRaises(OSError):
            await coordinator.watch_channels(MagicMock())

        subscription.stop.assert_awaited_once()

    async def test_cancelled_watch_setup_stops_its_watcher(self) -> None:
        """Stop a watcher whose setup finishes after its watch was cancelled.

        nats-py subscribes before its setup round trip and keeps the
        subscription if cancelled there; the watch must not wait for it either.
        """
        coordinator = build_coordinator("alpha")
        kv, subscription = watcher()
        setting_up = asyncio.Event()
        release = asyncio.Event()
        stopped = asyncio.Event()
        subscription.stop = AsyncMock(side_effect=stopped.set)

        async def watchall() -> AsyncMock:
            setting_up.set()
            await release.wait()
            return subscription

        kv.watchall = watchall
        coordinator.channels_store.kv = kv
        watch = asyncio.create_task(coordinator.watch_channels(MagicMock()))
        async with asyncio.timeout(5):
            await setting_up.wait()
            watch.cancel()
            await asyncio.gather(watch, return_exceptions=True)
            release.set()
            await stopped.wait()

        assert watch.cancelled()
        subscription.stop.assert_awaited_once_with()

    async def test_watch_surfaces_programming_errors(self) -> None:
        """Verify a programming error in a watch is logged at ERROR and retried."""
        coordinator = build_coordinator("alpha")
        coordinator.nc = MagicMock(is_connected=True)
        # A bare RuntimeError is a programming failure, unlike the
        # StoreUnavailableError watches treat as transient.
        crashes = [RuntimeError("missing attribute")]
        retried = asyncio.Event()

        async def crash_once(*arguments: object) -> None:
            del arguments
            if crashes:
                raise crashes.pop()

            retried.set()
            await asyncio.Event().wait()

        with (
            patch.object(coordinator, "watch_channels", crash_once),
            patch.object(coordinator, "watch_presence", hang),
            patch.object(coordinator, "watch_sessions", hang),
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="ERROR") as logs,
        ):
            async with asyncio.timeout(5):
                await coordinator.start_watches()
                await retried.wait()
                await coordinator.cancel_watches()

        assert any("watch watch-channels crashed" in line for line in logs.output)

    async def test_durable_writes_require_owned_presence(self) -> None:
        """Refuse channel and session writes until this process owns its bot ID."""
        coordinator = build_coordinator("alpha")
        channels = FakeKV()
        sessions = FakeKV()
        coordinator.channels_store.kv = cast("KeyValue", channels)
        coordinator.sessions.kv = cast("KeyValue", sessions)
        channel = asdict(ChannelRecord.new("#test", None, present=True))
        session = session_record(time.time() + 60)

        for state in (PresenceState.UNCLAIMED, PresenceState.DUPLICATE):
            coordinator.claim.state = state
            with self.subTest(state=state):
                with self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED):
                    await coordinator.put_channel(channel, after=None)

                with self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED):
                    await coordinator.put_session(session)

        assert not channels.entries
        assert not sessions.entries

        # The same writes land once the claim is owned.
        coordinator.claim.state = PresenceState.OWNED
        await coordinator.put_channel(channel, after=None)
        await coordinator.put_session(session)

        assert len(channels.entries) == 1
        assert len(sessions.entries) == 1

    async def test_presence_heartbeat_reclaims_unowned_key(self) -> None:
        """Reclaim a free presence key on a heartbeat, which needs no ownership.

        A duplicate's record expiring by TTL emits no watch event, and a
        failed watch reclaim waits for this heartbeat to retry it.
        """
        coordinator = build_coordinator("alpha")
        instance_id = coordinator.claim.instance_id
        presence = asdict(BotPresence("alpha", "host", instance_id, "alpha", "user"))

        for state in (PresenceState.UNCLAIMED, PresenceState.DUPLICATE):
            coordinator.presence_store.kv = cast("KeyValue", FakeKV())
            coordinator.claim.state = state
            with self.subTest(state=state):
                await coordinator.put_presence(presence)

                assert coordinator.claim.owned

    async def test_start_retries_failed_connection(self) -> None:
        """Close and retry a connection whose setup failed, even if closing fails."""
        coordinator = build_coordinator("alpha")
        steps: list[str] = []

        def step(name: str, error: Exception | None = None) -> AsyncMock:
            """Return a coroutine mock that records its step, then may raise."""

            def effect(*arguments: object, **options: object) -> None:
                del arguments, options
                steps.append(name)
                if error is not None:
                    raise error

            return AsyncMock(side_effect=effect)

        # nats-py retries the connect itself; a closed connection fails setup.
        failed = MagicMock(
            close=step("close", OSError("connection reset")),
            is_connected=True,
            subscribe=step("subscribe", ConnectionClosedError()),
        )
        nc = MagicMock(is_connected=True, subscribe=step("subscribe"))
        clients = [failed, nc]

        def connect(**options: object) -> MagicMock:
            del options
            steps.append("connect")
            return clients.pop(0)

        with (
            patch(
                "botnats.nats.coordinator.nats.connect",
                AsyncMock(side_effect=connect),
            ),
            patch.object(coordinator, "init_stores", step("stores")),
            patch.object(coordinator, "start_watches", step("watches")),
            patch("botnats.nats.coordinator.asyncio.sleep", step("sleep")),
            self.assertLogs("botnats.nats.coordinator", level="WARNING") as logs,
        ):
            await coordinator.start()

        assert coordinator.nc is nc
        assert steps == [
            "connect",
            "subscribe",
            "close",
            "sleep",
            "connect",
            "subscribe",
            "stores",
            "watches",
        ]
        assert [log.getMessage() for log in logs.records] == [
            "NATS connection failed; retrying: nats: connection closed",
        ]

    async def test_failed_start_closes_client_without_restart(self) -> None:
        """Drop a half-open client before closing it, so its close starts nothing."""
        coordinator = build_coordinator("alpha")
        half_open = closing_client(coordinator)
        half_open.subscribe = AsyncMock(side_effect=ConnectionClosedError)
        nc = MagicMock(is_connected=True)
        nc.subscribe = AsyncMock()
        connect = AsyncMock(side_effect=[half_open, nc])

        with (
            patch("botnats.nats.coordinator.nats.connect", connect),
            patch.object(coordinator, "init_stores", AsyncMock()),
            patch.object(coordinator, "start_watches", AsyncMock()) as start_watches,
            patch("botnats.nats.coordinator.asyncio.sleep", AsyncMock()),
            self.assertLogs("botnats.nats.coordinator", level="WARNING"),
        ):
            await coordinator.start()
            # nats-py ran on_closed inside close(); only start() reconnects.
            restart = coordinator.resync_task
            await coordinator.cancel_resync()

        assert restart is None
        half_open.close.assert_awaited_once_with()
        assert connect.await_count == 2
        assert coordinator.nc is nc
        nc.subscribe.assert_awaited_once()
        start_watches.assert_awaited_once_with()
