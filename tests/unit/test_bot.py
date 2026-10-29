# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for core bot behavior, callbacks, and periodic maintenance."""

import asyncio
import time
import unittest
from dataclasses import astuple, replace
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats.bot import Bot
from botnats.channel import ChannelRecord, JoinState
from botnats.irc.client import IRCClient, IRCClientConfig, IRCServer
from botnats.irc.protocol import IRCMessage, Prefix, casefold
from botnats.nats.coordinator import Coordinator, NATSConfig
from botnats.presence import BotPresence
from tests.unit.helpers import (
    AUTH_KEY,
    COORDINATION_KEY,
    NATS_CREDENTIAL,
    FailingWriteCoordinator,
    FakeCoordinator,
    FakeIRC,
    bot_with_channel,
    bot_with_coordinator,
    config,
    drain_session_writes,
    make_bot,
    session_value,
)

if TYPE_CHECKING:
    from botnats.nats.store import Session


class BotTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bot wiring, readiness, startup, shutdown, and NATS callbacks."""

    async def test_channel_record_applies_key(self) -> None:
        """Apply the key carried by a watched channel record."""
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        current = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]

        record = ChannelRecord.new(
            "#test",
            "good-key",
            present=True,
            after=current.revision,
        )
        bot.callbacks.on_channel(astuple(record))
        assert runtime.key == "good-key"

    async def test_irc_client_from_config(self) -> None:
        """Build the IRC client from configuration on the bot's caps and events."""
        server = IRCServer("irc.example.test", 6697, tls=True)
        for verify in (True, False):
            with self.subTest(verify=verify):
                bot = Bot(
                    replace(
                        config(),
                        irc_connect_timeout=45,
                        irc_servers=(server,),
                        irc_verify_tls=verify,
                    ),
                )

                assert isinstance(bot.irc, IRCClient)
                assert bot.irc.config == IRCClientConfig(
                    connect_timeout=45,
                    nickname="alpha",
                    servers=(server,),
                    verify_tls=verify,
                )
                assert bot.irc.caps is bot.caps
                assert bot.irc.on_message == bot.events.on_irc_message
                assert bot.irc.on_disconnect == bot.events.on_irc_disconnect

    async def test_components_from_config(self) -> None:
        """Build auth, presence, health, and NATS components from configuration."""
        bot = Bot(
            replace(
                config(),
                health_port=9080,
                jetstream_replicas=3,
                nats_monitor_port=9222,
                network="libera",
                presence_ttl=10,
            ),
        )

        # The secrets differ, so a swap of the two cannot pass.
        assert bot.authorizer.secret == AUTH_KEY
        assert bot.authorizer.coordination_key == COORDINATION_KEY
        assert bot.authorizer.issuer == "alpha-id"
        assert bot.authorizer.network == "libera"
        # Only the nick folds under the server casemapping: rfc1459 folding
        # of user@host would merge nick!~user@host and nick!^user@host.
        assert bot.authorizer.identity_fold == bot.caps.fold_identity
        assert bot.presence.ttl == 10
        assert bot.health_check.port == 9080
        assert bot.health_check.ready == bot.ready
        assert isinstance(bot.coordinator, Coordinator)
        assert bot.coordinator.config == NATSConfig(
            instance_id=bot.identity.instance_id,
            monitor_port=9222,
            network="libera",
            presence_ttl=10,
            replicas=3,
            servers=("nats://nats.internal:4222",),
            token=NATS_CREDENTIAL,
        )
        assert bot.coordinator.envelope.bot_id == "alpha-id"
        assert bot.coordinator.envelope.coordination_key == COORDINATION_KEY

    async def test_close_reaps_task_spawned_during_shutdown(self) -> None:
        """Drain a task a coordinator callback spawns mid-shutdown."""
        started = asyncio.Event()

        async def slow_task() -> None:
            started.set()
            await asyncio.sleep(0)

        class SpawningCoordinator(FakeCoordinator):
            async def close(self) -> None:
                bot.tasks.spawn(slow_task(), "late-spawn")
                async with asyncio.timeout(1):
                    await started.wait()

        bot, _, _ = bot_with_coordinator(SpawningCoordinator())

        async with asyncio.timeout(5):
            await bot.close()

        assert not bot.tasks

    async def test_close_cancels_tasks_before_closing_coordinator(self) -> None:
        """Cancel tracked tasks before coordinator.close so a lock cannot stall."""
        order: list[str] = []
        running = asyncio.Event()

        async def long_task() -> None:
            running.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                order.append("task-cancelled")
                raise

        class OrderingCoordinator(FakeCoordinator):
            async def close(self) -> None:
                order.append("coordinator-closed")

        bot, _, _ = bot_with_coordinator(OrderingCoordinator())
        bot.tasks.spawn(long_task(), "long")
        async with asyncio.timeout(1):
            await running.wait()

        async with asyncio.timeout(5):
            await bot.close()

        assert order == ["task-cancelled", "coordinator-closed"]
        assert not bot.tasks

    async def test_close_is_atomic_when_coordinator_close_raises(self) -> None:
        """Close IRC and health even if coordinator.close raises."""

        class RaisingCoordinator(FakeCoordinator):
            async def close(self) -> None:
                msg = "connection reset"
                raise OSError(msg)

        bot, _, _ = bot_with_coordinator(RaisingCoordinator())
        # TimeoutError is an OSError: bound the close outside assertRaises.
        async with asyncio.timeout(5):
            with (
                patch.object(bot.irc, "close") as irc_close,
                patch.object(bot.health_check, "close") as health_close,
                self.assertRaises(OSError),
            ):
                await bot.close()

        irc_close.assert_awaited_once()
        health_close.assert_awaited_once()

    async def test_close_writes_queued_revocation(self) -> None:
        """Write a revocation still queued at shutdown before closing NATS."""
        coordinator = FailingWriteCoordinator()
        bot, _, _ = bot_with_coordinator(coordinator)
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())
        bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
        await drain_session_writes(bot)
        assert bot.sessions.pending
        # JetStream recovers, but no maintenance tick retries before shutdown.
        coordinator.failing = False

        async def disconnect() -> None:
            coordinator.connected = False

        with patch.object(coordinator, "close", disconnect):
            async with asyncio.timeout(5):
                await bot.close()

        puts = [(put["prefix"], put["revoked"]) for put in coordinator.session_puts]
        assert puts == [(prefix.render(), True)]
        assert not bot.sessions.pending

    async def test_close_bounds_queued_revocation_write(self) -> None:
        """Finish shutdown when the queued revocation's write hangs."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())
        bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
        writing = asyncio.Event()

        async def hang(record: dict[str, Any]) -> Session:
            del record
            writing.set()
            never: asyncio.Future[Session] = asyncio.get_running_loop().create_future()
            return await never

        with (
            patch.object(coordinator, "put_session", hang),
            patch.object(coordinator, "close", AsyncMock()) as coordinator_close,
            patch("botnats.bot.SHUTDOWN_SYNC_TIMEOUT", 0),
        ):
            async with asyncio.timeout(1):
                await bot.close()

        assert writing.is_set()
        assert bot.sessions.pending
        coordinator_close.assert_awaited_once()
        assert not fake_irc.connected

    async def test_nats_callbacks_reach_their_owners(self) -> None:
        """Route presence and session watch callbacks to the owners that hold them."""
        bot = Bot(config())
        peer = BotPresence("beta", "beta.host", "two", "beta", "~beta")
        session = session_value(time.time() + 60)

        bot.callbacks.on_presence(peer)
        bot.callbacks.on_session_update("opaque", session, replaying=False)

        assert bot.presence.has(peer)
        assert bot.sessions.watched == {"opaque": (session.prefix, session.expires_at)}
        assert bot.authorizer.authorized(session.prefix)

        bot.callbacks.on_presence_delete("BETA")
        bot.callbacks.on_session_delete("opaque")

        assert not bot.presence.has(peer)
        assert not bot.sessions.watched
        assert not bot.authorizer.authorized(session.prefix)

        bot.callbacks.on_session_update("opaque", session, replaying=False)
        bot.callbacks.on_sessions_replayed({"opaque"})

        assert bot.sessions.watched == {"opaque": (session.prefix, session.expires_at)}
        assert bot.authorizer.authorized(session.prefix)

        bot.callbacks.on_sessions_replayed(set())

        assert not bot.sessions.watched
        assert not bot.authorizer.authorized(session.prefix)

    async def test_maintenance_tick_before_coordinator_connects(self) -> None:
        """Leave pending durable writes queued until the coordinator is ready."""
        bot, _, coordinator = bot_with_coordinator()
        coordinator.connected = False
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "irc-key"
        runtime.key_pending = True
        prefix = "owner!user@host.example"
        bot.sessions.queue(bot.authorizer.grant(prefix))
        outage = NatsError("NATS unavailable")

        with (
            patch.object(
                coordinator, "put_session", AsyncMock(side_effect=outage)
            ) as put_session,
            patch.object(
                coordinator, "put_channel", AsyncMock(side_effect=outage)
            ) as put_channel,
        ):
            async with asyncio.timeout(1):
                await bot.maintenance_tick()

            put_session.assert_not_awaited()
            put_channel.assert_not_awaited()

            # Once ready, the same tick retries both queued writes.
            coordinator.connected = True
            async with asyncio.timeout(1):
                await bot.maintenance_tick()

            put_session.assert_awaited_once()
            put_channel.assert_awaited_once()

    async def test_run_does_not_wait_for_coordinator(self) -> None:
        """Serve IRC while coordinator startup blocks on an outage, then close."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator_started = asyncio.Event()

        async def blocked_start() -> None:
            coordinator_started.set()
            await asyncio.Event().wait()

        async def run_forever() -> None:
            await coordinator_started.wait()

        with (
            patch.object(coordinator, "start", blocked_start),
            patch.object(fake_irc, "run_forever", run_forever),
            patch.object(bot.health_check, "start", AsyncMock()) as health_start,
            patch.object(bot.health_check, "close", AsyncMock()),
        ):
            # run() returns only once run_forever has run beside the blocked start.
            async with asyncio.timeout(5):
                await bot.run()

        health_start.assert_awaited_once()
        # close() cancelled the blocked start and both maintenance loops.
        assert not bot.tasks

    async def test_run_closes_when_cancelled(self) -> None:
        """Close every service when SIGTERM cancels the IRC loop.

        IRCClient.run_forever never returns: it ends by an exception, or by
        the cancellation SIGTERM delivers.
        """
        bot, fake_irc, _ = bot_with_coordinator()

        async def cancelled() -> None:
            raise asyncio.CancelledError

        with (
            patch.object(fake_irc, "run_forever", cancelled),
            patch.object(bot.health_check, "start", AsyncMock()),
            patch.object(bot.health_check, "close", AsyncMock()) as health_close,
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await bot.run()

        health_close.assert_awaited_once()
        assert not bot.tasks
        assert not fake_irc.connected

    async def test_ready(self) -> None:
        """Verify readiness requires IRC registration, connection, and NATS."""
        fake_irc = FakeIRC()
        coordinator = FakeCoordinator()
        bot = make_bot(irc=fake_irc, coordinator=coordinator)

        assert not bot.ready()
        bot.identity.registered = True
        assert bot.ready()
        fake_irc.connected = False
        assert not bot.ready()
        fake_irc.connected = True
        coordinator.connected = False
        assert not bot.ready()


class MaintenanceTests(unittest.IsolatedAsyncioTestCase):
    """Tests for the maintenance loops and the upkeep each tick performs."""

    async def test_loop_continues_after_tick_error(self) -> None:
        """Verify the maintenance loop waits its interval and survives tick errors."""
        bot = Bot(config())
        calls = 0
        delays: list[float] = []
        real_sleep = asyncio.sleep

        async def counting_tick() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                msg = "transient failure"
                raise RuntimeError(msg)

            # Yield, so the timeout can end a loop that stops sleeping.
            await real_sleep(0)

        async def immediate(delay: float) -> None:
            delays.append(delay)
            # Stop on a sleep count, not a tick count, so a loop that stops
            # ticking fails the assertion below instead of spinning forever.
            if len(delays) == 3:
                msg = "stop"
                raise asyncio.CancelledError(msg)

            await real_sleep(0)

        with (
            patch("asyncio.sleep", immediate),
            self.assertLogs("botnats.bot", level="ERROR"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await bot.maintenance_loop(counting_tick, "maintenance tick")

        assert calls == 2
        # The presence heartbeat runs on this loop too; waiting the presence
        # TTL instead would let presence lapse every cycle.
        assert delays == [bot.config.maintenance_interval] * 3

    async def test_heartbeat_continues_while_retries_stall(self) -> None:
        """Keep refreshing presence while a durable-state retry hangs."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        stalled = asyncio.Event()
        real_sleep = asyncio.sleep

        async def stall() -> None:
            stalled.set()
            await asyncio.Event().wait()

        async def yield_once(delay: float) -> None:
            del delay
            await real_sleep(0)

        async def run_until_heartbeats() -> None:
            # Bounded by event-loop turns, not wall-clock time: each turn lets
            # every loop take one step, so a stalled heartbeat fails here.
            for _ in range(100):
                if stalled.is_set() and len(coordinator.presence_puts) >= 3:
                    return

                await real_sleep(0)

            self.fail("presence heartbeat stalled behind the maintenance tick")

        with (
            patch.object(bot.channel_mgr, "retry_pending_keys", stall),
            patch.object(bot.health_check, "start", AsyncMock()),
            patch.object(fake_irc, "run_forever", run_until_heartbeats),
            patch("asyncio.sleep", yield_once),
        ):
            async with asyncio.timeout(5):
                await bot.run()

    async def test_requests_missing_op(self) -> None:
        """Ask peers again for op in a joined channel where this bot lacks it."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha")
        runtime.member("beta").prefix = peer.to_prefix()
        runtime.member("beta").modes.add("o")

        async with asyncio.timeout(1):
            await bot.maintenance_tick()

        assert [kind for kind, _ in coordinator.help_requests] == ["op"]

    async def test_prunes_expired_sessions_while_disconnected(self) -> None:
        """Remove expired auth sessions even while IRC is disconnected."""
        bot = Bot(config())
        bot.authorizer.grant("owner!user@host.example", now=0)

        async with asyncio.timeout(1):
            await bot.maintenance_tick()

        assert not bot.authorizer.records
