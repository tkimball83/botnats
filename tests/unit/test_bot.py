# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for core bot behavior, callbacks, and periodic maintenance."""

import asyncio
import ssl
import time
import unittest
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

from botnats import error_label
from botnats.bot import Bot
from botnats.channel import JOIN_REPLY_TIMEOUT, JoinState
from botnats.irc.client import IRCClient
from botnats.irc.protocol import MAX_IRC_MESSAGE_BYTES, IRCMessage, Prefix, casefold
from botnats.presence import BotPresence
from tests.unit.helpers import (
    FakeCoordinator,
    FakeIRC,
    bot_with_channel,
    bot_with_coordinator,
    bot_with_irc,
    config,
    send_command,
)


class BotTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bot identity, op grants, rate limiting, and channel keys."""

    async def test_reply_drops_unsendable_message(self) -> None:
        """Drop an oversized PRIVMSG instead of raising into the handler."""
        bot, _ = bot_with_irc()
        error = ValueError("message exceeds 512 bytes")

        with (
            patch.object(bot.irc, "send", side_effect=error),
            self.assertLogs("botnats.commands", level="WARNING"),
        ):
            await bot.commands.reply("nick", "x" * 600)

    async def test_channel_record_key_validation(self) -> None:
        """Verify channel records reject invalid keys."""
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        current = bot.channel_mgr.channel_records[casefold("#test")]

        invalid = asdict(
            bot.channel_mgr.new_record(
                "#test",
                None,
                present=True,
                after=current.revision,
            ),
        )
        invalid["key"] = "bad key"
        await bot.callbacks.on_channel(invalid)
        assert runtime.key is None

        record = bot.channel_mgr.new_record(
            "#test",
            "good-key",
            present=True,
            after=current.revision,
        )
        await bot.callbacks.on_channel(asdict(record))
        assert runtime.key == "good-key"

    async def test_disconnect_clears_runtime(self) -> None:
        """Verify IRC disconnect clears channel and server-specific state."""
        bot = bot_with_channel()
        bot.channel_mgr.set_casemapping("ascii")
        runtime = bot.channel_mgr.runtime("#test")
        assert runtime is not None
        bot.caps.parse_chanmodes("b,k,l,imn")
        bot.caps.parse_modes("6")
        bot.caps.parse_prefix("(yov)@%+")
        bot.irc.set_nickname_length(12)
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
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
        assert bot.caps.mode_limit == 1
        assert bot.caps.op_mode == "o"
        assert bot.irc.casemapping == "rfc1459"
        assert bot.irc.nickname_length == 9
        runtime = bot.channel_mgr.runtime("#test")
        assert runtime is not None
        assert runtime.casemapping == "rfc1459"
        assert not runtime.joined
        assert not runtime.members

    async def test_identity_discovery_accepts_final_response(self) -> None:
        """Allow the final identity query time to receive its response."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)

        async def receive_identity(delay: float) -> None:
            del delay
            bot.identity.current = BotPresence("alpha", "host", "one", "alpha", "user")

        with (
            patch("botnats.presence.IDENTITY_RETRY_ATTEMPTS", 1),
            patch("botnats.bot.asyncio.sleep", receive_identity),
        ):
            await bot.identity.discover(bot.identity.generation)

        assert fake_irc.reconnects == 0

    async def test_identity_discovery_reconnects(self) -> None:
        """Verify bot reconnects when identity discovery exhausts retries."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        with (
            patch("botnats.presence.IDENTITY_RETRY_ATTEMPTS", 1),
            patch("botnats.presence.IDENTITY_RETRY_DELAY", 0),
            self.assertLogs("botnats.presence", level="WARNING"),
        ):
            await bot.events.handle_welcome(IRCMessage("001", ("alpha", "welcome")))
            tasks = tuple(bot.tasks)
            await asyncio.gather(*tasks)

        assert fake_irc.sent == [("USERHOST", ("alpha",))]
        assert fake_irc.reconnects == 1

    async def test_identity_fold(self) -> None:
        """Fold only protocol-defined identity equivalents."""
        bot = Bot(config())
        caret_prefix = "Nick!^user@host.example"
        tilde_prefix = "Nick!~user@host.example"

        folded_caret = bot.caps.fold_identity(caret_prefix)
        folded_tilde = bot.caps.fold_identity(tilde_prefix)

        assert folded_caret != folded_tilde
        assert bot.caps.fold_identity(
            "Nick!user@straße.example"
        ) != bot.caps.fold_identity(
            "Nick!user@strasse.example",
        )

    async def test_irc_identity_fields(self) -> None:
        """Verify IRC client identity fields match configuration."""
        bot = Bot(config())

        assert isinstance(bot.irc, IRCClient)
        assert bot.irc.desired_nick == "alpha"
        assert bot.irc.tls_context is not None
        assert bot.irc.tls_context.check_hostname
        assert bot.irc.tls_context.verify_mode == ssl.CERT_REQUIRED

    async def test_mode_batching_respects_message_bytes(self) -> None:
        """Split MODE batches that exceed the IRC byte limit."""
        bot, fake_irc = bot_with_irc()
        bot.caps.mode_limit = 16
        targets = [f"n{index:029d}" for index in range(16)]

        await bot.channel_mgr.batch_mode("#test", "+", "o", targets, "opped")

        assert [len(arguments) for _, _, arguments in fake_irc.modes] == [15, 1]

    async def test_batch_mode_skips_single_oversized_target(self) -> None:
        """Skip one un-encodable target and still apply the rest of the batch."""
        bot, fake_irc = bot_with_irc()
        bot.caps.mode_limit = 4
        oversized = "n" * (MAX_IRC_MESSAGE_BYTES + 1)
        targets = ["alpha", oversized, "gamma"]

        with self.assertLogs("botnats.channel", level="WARNING"):
            await bot.channel_mgr.batch_mode("#test", "+", "o", targets, "opped")

        applied = [arg for _, _, arguments in fake_irc.modes for arg in arguments]
        assert applied == ["alpha", "gamma"]

    async def test_close_reaps_task_spawned_during_shutdown(self) -> None:
        """Drain a task a coordinator callback spawns mid-shutdown."""
        started = asyncio.Event()

        async def slow_task() -> None:
            started.set()
            await asyncio.sleep(0)

        class SpawningCoordinator(FakeCoordinator):
            async def close(self) -> None:
                bot.tasks.spawn(slow_task(), "late-spawn")
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

    async def test_rate_limiting(self) -> None:
        """Verify command rate limiting caps replies per user."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc, coordinator=FakeCoordinator())
        prefix = Prefix("owner", "user", "host.example")

        for _ in range(5):
            await send_command(bot, prefix, "AUTH 000000")

        assert len(fake_irc.privmsgs) == 3

        another_irc = FakeIRC()
        another = Bot(config(), irc=another_irc)
        for _ in range(20):
            await send_command(another, prefix, "AUTH")

        assert len(another_irc.privmsgs) == 8

    async def test_prefix_without_op_mode_fails_closed(self) -> None:
        """Never count a sub-operator PREFIX rank as channel operator."""
        bot = Bot(config())

        bot.caps.parse_prefix("(v)+")
        assert bot.caps.op_mode == "o"
        assert not bot.caps.is_opped({"v"})

        bot.caps.parse_prefix("(qv)~+")
        assert bot.caps.op_mode == "q"
        assert bot.caps.is_opped({"q"})
        assert not bot.caps.is_opped({"v"})

    async def test_wrong_auth_code_still_claims(self) -> None:
        """Deny an unmatched code, but still perform the claim round trip."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")

        with patch.object(bot.authorizer, "match", return_value=None):
            await bot.commands.dispatch(prefix, "AUTH 000000")

        assert coordinator.claim_requests == [-1]
        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_rate_limited_admin_is_silent(self) -> None:
        """Silently drop an authenticated admin's commands over the limit."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        for _ in range(20):
            await send_command(bot, prefix, "BOGUS")

        assert len(fake_irc.privmsgs) == 8
        assert all(text == "Unknown command" for _, text in fake_irc.privmsgs)

    async def test_maintenance_tick_before_coordinator_connects(self) -> None:
        """Stay quiet when maintenance runs before NATS has ever connected."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        bot.identity.registered = True
        bot.identity.current = BotPresence(
            "alpha",
            "host.example",
            bot.instance_id,
            "alpha",
            "~alpha",
        )

        await bot.maintenance_tick()

        assert fake_irc.sent == []

    async def test_unauthenticated_commands_are_silent(self) -> None:
        """Drop parse errors and non-AUTH commands from unauthenticated users."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        prefix = Prefix("owner", "user", "host.example")

        for text in (" ", "OP #alpha owner", "BOGUS"):
            await bot.commands.dispatch(prefix, text)

        assert fake_irc.privmsgs == []

    async def test_rate_limiting_ignores_nick_change(self) -> None:
        """Verify the command limiter keys on host so nick cycling cannot bypass it."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)

        for index in range(20):
            prefix = Prefix(f"nick{index}", "user", "host.example")
            await send_command(bot, prefix, "AUTH")

        assert len(fake_irc.privmsgs) == 8

    async def test_run_does_not_wait_for_coordinator(self) -> None:
        """Serve IRC while coordinator startup blocks on an outage."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator_started = asyncio.Event()
        irc_ran = asyncio.Event()

        async def blocked_start() -> None:
            coordinator_started.set()
            await asyncio.Event().wait()

        async def run_forever() -> None:
            await coordinator_started.wait()
            irc_ran.set()

        with (
            patch.object(coordinator, "start", blocked_start),
            patch.object(fake_irc, "run_forever", run_forever),
            patch.object(bot.health_check, "start", AsyncMock()),
            patch.object(bot.health_check, "close", AsyncMock()),
        ):
            await asyncio.wait_for(bot.run(), timeout=5)

        assert irc_ran.is_set()

    async def test_ready(self) -> None:
        """Verify readiness requires IRC registration and NATS connectivity."""
        fake_irc = FakeIRC()
        coordinator = FakeCoordinator()
        bot = Bot(config(), irc=fake_irc, coordinator=coordinator)

        assert not bot.ready()
        bot.identity.registered = True
        assert bot.ready()
        coordinator.connected = False
        assert not bot.ready()

    async def test_set_identity_dedup(self) -> None:
        """Verify redundant identity updates do not re-send JOINs."""
        bot, fake_irc = bot_with_irc()
        prefix = Prefix("alpha", "~alpha", "real.host")

        await bot.events.set_identity(prefix)
        assert bot.identity.current is not None

        joins = [cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]
        assert len(joins) == 1

        # A redundant self-identity event must not re-sweep pending joins;
        # otherwise a burst of WHO/USERHOST replies re-sends JOIN per channel.
        await bot.events.set_identity(prefix)
        joins = [cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]
        assert len(joins) == 1

        # A real identity change still refreshes presence, but the JOIN already
        # sent is still in flight, so it is not queued again.
        await bot.events.set_identity(Prefix("alpha", "~alpha", "new.host"))
        assert bot.identity.current.host == "new.host"
        joins = [cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]
        assert len(joins) == 1

    async def test_join_state_transitions(self) -> None:
        """Send JOIN only when idle: not while in flight, again after refusal."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test")]

        await bot.channel_mgr.join_desired()
        assert runtime.join is JoinState.JOINING
        await bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 1

        await bot.events.on_irc_message(
            IRCMessage("473", ("alpha", "#test", "Cannot join channel (+i)")),
        )
        assert runtime.join is JoinState.IDLE
        await bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

        await bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "alpha.host")),
        )
        assert runtime.join is JoinState.JOINED

    async def test_join_without_reply_is_retried(self) -> None:
        """Resend a JOIN that got neither an echo nor a refusal in time."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test")]

        await bot.channel_mgr.join_desired()
        runtime.join_sent_at -= JOIN_REPLY_TIMEOUT
        await bot.channel_mgr.join_desired()

        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

    async def test_session_delete_keeps_colliding_live_identity(self) -> None:
        """Delete only the ASCII durable identity represented by a KV key."""
        bot, _ = bot_with_irc()
        first = "Owner[!user@host"
        second = "Owner{!user@host"
        bot.authorizer.grant(first, now=10)
        bot.authorizer.grant(second, now=11)
        # Each prefix has its own ASCII-folded KV key; deletes arrive by key.
        expiry = time.time() + 60
        bot.sessions.watched["first-key"] = (first, expiry)
        bot.sessions.watched["second-key"] = (second, expiry)

        bot.callbacks.on_session_delete("first-key")

        session = next(iter(bot.authorizer.records.values()))
        assert session.prefix == second

        bot.callbacks.on_session_delete("second-key")
        assert not bot.authorizer.records

    async def test_set_identity_dedups_presence_publish(self) -> None:
        """Verify redundant identity updates do not re-publish presence."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        prefix = Prefix("alpha", "~alpha", "real.host")

        await bot.events.set_identity(prefix)
        await bot.events.set_identity(prefix)
        await asyncio.gather(*bot.tasks)
        assert len(coordinator.presence_puts) == 1

        await bot.events.set_identity(Prefix("alpha", "~alpha", "new.host"))
        await asyncio.gather(*bot.tasks)
        assert bot.identity.current is not None
        assert bot.identity.current.host == "new.host"
        assert len(coordinator.presence_puts) == 2

    async def test_unban_request_identity(self) -> None:
        """Verify unban request includes the bot identity in the payload."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        bot.identity.current = BotPresence(
            "alpha", "bot.host", "one", "alpha", "~alpha"
        )

        await bot.channel_mgr.request_peer("unban", "#test")

        assert coordinator.help_requests == [
            ("unban", {"channel": "#test", "presence": asdict(bot.identity.current)}),
        ]

    async def test_unknown_channel_does_not_request_peer(self) -> None:
        """Do not send help requests for untracked channels."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        bot.identity.current = BotPresence(
            "alpha", "bot.host", "one", "alpha", "~alpha"
        )

        await bot.channel_mgr.request_peer("unban", "#unknown")

        assert coordinator.help_requests == []


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

        async def counting_tick(self: Bot) -> None:
            del self
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
            patch.object(Bot, "maintenance_tick", counting_tick),
            patch("botnats.bot.asyncio.sleep", immediate),
            self.assertLogs("botnats.bot", level="ERROR"),
            self.assertRaises(asyncio.CancelledError),
        ):
            await bot.maintenance_loop()

        assert calls == 2

    async def test_heartbeat_precedes_pending_state_retries(self) -> None:
        """Refresh presence before potentially slow durable-state retries."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        calls: list[str] = []

        async def heartbeat(*arguments: object) -> None:
            del arguments
            calls.append("heartbeat")

        async def retry_sessions() -> None:
            calls.append("sessions")

        async def retry_records() -> None:
            calls.append("records")

        with (
            patch.object(coordinator, "put_presence", heartbeat),
            patch.object(bot.sessions, "retry", retry_sessions),
            patch.object(bot.channel_mgr, "retry_pending_keys", retry_records),
        ):
            await bot.maintenance_tick()

        assert calls == ["heartbeat", "sessions", "records"]

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
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("beta").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 1

    async def test_requests_op_for_unopped_channels(self) -> None:
        """Verify maintenance tick requests op when a peer bot is opped."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        peer = BotPresence("beta", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
        runtime.member("beta").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 1
        assert op_requests[0][1]["channel"] == "#test"

    async def test_skips_op_request_when_no_peer_opped(self) -> None:
        """Verify maintenance tick skips op request when no peer has op."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        runtime = bot.channel_mgr.channels[casefold("#test")]
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
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("stranger").prefix = Prefix("stranger", "user", "other.host")
        runtime.member("stranger").modes.add("o")

        await bot.maintenance_tick()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0
