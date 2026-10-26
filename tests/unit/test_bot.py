# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for core bot behavior, callbacks, and periodic maintenance."""

import asyncio
import ssl
import time
import unittest
from dataclasses import astuple
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats import error_label
from botnats.bot import Bot
from botnats.channel import JoinState
from botnats.irc.client import IRCClient
from botnats.irc.protocol import (
    Prefix,
    casefold,
)
from botnats.presence import BotPresence
from tests.unit.helpers import (
    FakeCoordinator,
    FakeIRC,
    bot_with_channel,
    bot_with_coordinator,
    bot_with_irc,
    config,
    make_bot,
    session_value,
)


class BotTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bot wiring, readiness, shutdown, and NATS callbacks."""

    async def test_channel_record_applies_key(self) -> None:
        """Apply the key carried by a watched channel record."""
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        current = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]

        record = bot.channel_mgr.new_record(
            "#test",
            "good-key",
            present=True,
            after=current.revision,
        )
        bot.callbacks.on_channel(astuple(record))
        assert runtime.key == "good-key"

    async def test_disconnect_clears_runtime(self) -> None:
        """Clear server-specific state on disconnect, keeping lookups valid.

        The channel and the session identity fold differently under ascii and
        rfc1459, so both are found again only if disconnect rekeys them onto
        the default casemapping it restores.
        """
        bot = make_bot()
        bot.channel_mgr.set_casemapping("ascii")
        channel = "#te[st"
        bot.channel_mgr.apply_record(
            bot.channel_mgr.new_record(channel, None, present=True),
        )
        identity = "owner[!user@host.example"
        bot.authorizer.grant(identity)
        runtime = bot.channel_mgr.runtime(channel)
        assert runtime is not None
        bot.caps.parse_chanmodes("b,k,l,imn")
        bot.caps.parse_prefix("(yov)@%+")
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.modes = "+nstl"
        runtime.limit = 3
        bot.identity.current = BotPresence("alpha", "host", "one", "alpha", "user")
        bot.identity.registered = True
        generation = bot.identity.generation

        bot.on_irc_disconnect()

        assert bot.identity.current is None
        assert bot.identity.generation == generation + 1
        assert not bot.identity.registered
        assert bot.caps.casemapping == "rfc1459"
        assert bot.caps.chanmodes == ("beI", "k", "l", "imnst")
        assert bot.caps.member_prefixes == {
            "%": "h",
            "&": "a",
            "+": "v",
            "@": "o",
            "~": "q",
        }
        assert bot.caps.membership_modes == "qaohv"
        assert bot.caps.op_mode == "o"
        assert bot.channel_mgr.runtime(channel) is runtime
        assert not runtime.joined
        assert not runtime.members
        assert runtime.modes == ""
        assert runtime.limit is None
        assert bot.authorizer.authorized(identity)

    async def test_irc_client_verifies_tls(self) -> None:
        """Build the IRC client from configuration with verified TLS."""
        bot = Bot(config())

        assert isinstance(bot.irc, IRCClient)
        assert bot.irc.config.nickname == "alpha"
        assert bot.irc.tls_context is not None
        assert bot.irc.tls_context.check_hostname
        assert bot.irc.tls_context.verify_mode == ssl.CERT_REQUIRED

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

        bot, _ = bot_with_irc(coordinator=SpawningCoordinator())

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

        bot, _ = bot_with_irc(coordinator=OrderingCoordinator())
        bot.tasks.spawn(long_task(), "long")
        async with asyncio.timeout(1):
            await running.wait()

        await bot.close()

        assert order == ["task-cancelled", "coordinator-closed"]
        assert not bot.tasks

    async def test_close_is_atomic_when_coordinator_close_raises(self) -> None:
        """Close IRC and health even if coordinator.close raises."""

        class RaisingCoordinator(FakeCoordinator):
            async def close(self) -> None:
                msg = "connection reset"
                raise OSError(msg)

        bot, _ = bot_with_irc(coordinator=RaisingCoordinator())
        with (
            patch.object(bot.irc, "close") as irc_close,
            patch.object(bot.health_check, "close") as health_close,
            self.assertRaises(OSError),
        ):
            await bot.close()

        irc_close.assert_awaited_once()
        health_close.assert_awaited_once()

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
        bot.callbacks.on_sessions_replayed(set())

        assert not bot.presence.has(peer)
        assert not bot.sessions.watched
        assert not bot.authorizer.authorized(session.prefix)

    async def test_maintenance_tick_before_coordinator_connects(self) -> None:
        """Leave pending durable writes queued until the coordinator is ready."""
        bot, _, coordinator = bot_with_coordinator()
        coordinator.connected = False
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "irc-key"
        bot.channel_mgr.pending_keys[casefold("#test", "ascii")] = "#test"
        prefix = "owner!user@host.example"
        bot.sessions.queue(prefix, bot.authorizer.grant(prefix))
        outage = NatsError("NATS unavailable")

        with (
            patch.object(
                coordinator, "put_session", AsyncMock(side_effect=outage)
            ) as put_session,
            patch.object(
                coordinator, "put_channel", AsyncMock(side_effect=outage)
            ) as put_channel,
        ):
            await bot.maintenance_tick()
            put_session.assert_not_awaited()
            put_channel.assert_not_awaited()

            # Once ready, the same tick retries both queued writes.
            coordinator.connected = True
            await bot.maintenance_tick()
            put_session.assert_awaited_once()
            put_channel.assert_awaited_once()

    async def test_run_does_not_wait_for_coordinator(self) -> None:
        """Serve IRC while coordinator startup blocks on an outage."""
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
            patch.object(bot.health_check, "start", AsyncMock()),
            patch.object(bot.health_check, "close", AsyncMock()),
        ):
            # run() returns only once run_forever has run beside the blocked start.
            await asyncio.wait_for(bot.run(), timeout=5)

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

    async def test_session_delete_keeps_colliding_live_identity(self) -> None:
        """Delete only the ASCII durable identity represented by a KV key."""
        bot, _ = bot_with_irc()
        first = "Owner[!user@host"
        second = "Owner{!user@host"
        # The prefixes collide under the IRC fold but not under the ASCII fold.
        assert bot.caps.fold_identity(first) == bot.caps.fold_identity(second)
        assert casefold(first, "ascii") != casefold(second, "ascii")
        now = time.time()
        bot.authorizer.grant(first, now=now)
        bot.authorizer.grant(second, now=now + 1)
        # Each prefix has its own ASCII-folded KV key; deletes arrive by key.
        expiry = now + 60
        bot.sessions.watched["first-key"] = (first, expiry)
        bot.sessions.watched["second-key"] = (second, expiry)

        bot.callbacks.on_session_delete("first-key")

        assert [s.prefix for s in bot.authorizer.records.values()] == [second]
        assert bot.authorizer.authorized(second)

        bot.callbacks.on_session_delete("second-key")
        assert not bot.authorizer.records


class ErrorLabelTests(unittest.TestCase):
    """Tests for the error_label helper."""

    def test_error_with_message(self) -> None:
        """Verify error_label returns the message when present."""
        assert error_label(ValueError("boom")) == "boom"

    def test_error_without_message(self) -> None:
        """Verify error_label falls back to the type name."""
        assert error_label(RuntimeError()) == "RuntimeError"


class MaintenanceTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bounded long-lived maintenance state."""

    async def test_loop_continues_after_tick_error(self) -> None:
        """Verify the maintenance loop survives a tick exception."""
        bot = Bot(config())
        calls = 0

        async def counting_tick() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                msg = "transient failure"
                raise RuntimeError(msg)

        async def immediate(delay: float) -> None:
            del delay
            if calls >= 2:
                msg = "stop"
                raise asyncio.CancelledError(msg)

        with (
            patch("botnats.bot.asyncio.sleep", immediate),
            self.assertLogs("botnats.bot", level="ERROR"),
            self.assertRaises(asyncio.CancelledError),
        ):
            await bot.maintenance_loop(counting_tick, "maintenance tick")

        assert calls == 2

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
            patch.object(bot.sessions, "retry", stall),
            patch.object(bot.health_check, "start", AsyncMock()),
            patch.object(fake_irc, "run_forever", run_until_heartbeats),
            patch("botnats.bot.asyncio.sleep", yield_once),
        ):
            await bot.run()

    async def test_prunes_expired_sessions_while_disconnected(self) -> None:
        """Remove expired auth sessions even while IRC is disconnected."""
        bot = Bot(config())
        bot.authorizer.grant("owner!user@host.example", now=0)

        await bot.maintenance_tick()

        assert not bot.authorizer.records

    async def test_requests_op_before_who_replies(self) -> None:
        """Verify op request proceeds when opped members lack prefixes."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("beta").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 1

    async def test_requests_op_for_unopped_channels(self) -> None:
        """Request op only in joined channels where this bot lacks it.

        A peer bot is opped in every channel, so only this bot's own state
        decides: #opped needs no op, and #waiting is not joined yet.
        """
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        peer = BotPresence("beta", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        for channel in ("#opped", "#waiting"):
            record = bot.channel_mgr.new_record(channel, None, present=True)
            bot.channel_mgr.apply_record(record)

        for channel, state in (
            ("#test", JoinState.JOINED),
            ("#opped", JoinState.JOINED),
            ("#waiting", JoinState.JOINING),
        ):
            runtime = bot.channel_mgr.channels[casefold(channel, "rfc1459")]
            runtime.join = state
            runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
            runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
            runtime.member("beta").modes.add("o")

        bot.channel_mgr.channels["#opped"].member("alpha").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert [payload["channel"] for _, payload in op_requests] == ["#test"]

    async def test_skips_op_request_when_no_peer_opped(self) -> None:
        """Verify maintenance tick skips op request when no peer has op."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0

    async def test_skips_op_request_when_only_user_opped(self) -> None:
        """Verify opped non-peer users do not trigger op requests."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("stranger").prefix = Prefix("stranger", "user", "other.host")
        runtime.member("stranger").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0
