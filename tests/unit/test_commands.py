# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for admin command parsing, dispatch, replies, and rate limiting."""

import asyncio
import unittest
from collections import deque
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, call, patch

from botnats.channel import ChannelRecord, ChannelRuntime, JoinState
from botnats.commands import RELAY_SOURCE_BYTES, RateLimiter, parse_command
from botnats.irc.protocol import MAX_IRC_MESSAGE_BYTES, IRCMessage, Prefix, casefold
from botnats.presence import BotPresence
from tests.unit.helpers import (
    OWNER,
    FailingWriteCoordinator,
    FakeIRC,
    bot_with_coordinator,
    bot_with_irc,
    bounded,
    drain_session_writes,
    make_bot,
    send_command,
    settle,
)

if TYPE_CHECKING:
    from botnats.nats.status import NATSStatus
    from botnats.validators import ChannelFields


class CommandTests(unittest.TestCase):
    """Tests for command parsing."""

    def test_parse_preserves_backslash(self) -> None:
        """Verify backslashes in arguments are preserved, not shell-escaped."""
        name, arguments = parse_command("deop #chan Evil\\dude")

        assert name == "DEOP"
        assert arguments == ("#chan", "Evil\\dude")


class RateLimitTests(unittest.IsolatedAsyncioTestCase):
    """Tests for rate limiter windowing and bucket eviction."""

    async def test_bucket_eviction(self) -> None:
        """Evict only expired buckets at capacity; deny new keys otherwise."""
        limiter = RateLimiter(limit=10, window=60)
        with patch("botnats.commands.MAX_RATE_BUCKETS", 2):
            assert limiter.check("a")
            assert limiter.check("b")
            assert limiter.check("a")
            # Every bucket is fresh: a new key is denied instead of evicting
            # one, which would reset an actively limited key's budget.
            assert not limiter.check("c")
            assert "c" not in limiter.buckets
            assert "b" in limiter.buckets
            # A zero window expires the LRU bucket, so eviction proceeds.
            limiter.window = 0
            assert limiter.check("c")

        assert "a" in limiter.buckets
        assert "b" not in limiter.buckets
        assert "c" in limiter.buckets

    async def test_evict_stale_boundary(self) -> None:
        """Treat a bucket whose newest entry sits exactly at the cutoff as stale."""
        limiter = RateLimiter()
        limiter.buckets["old"] = deque([5.0])

        assert not limiter.evict_stale(4.9)
        assert "old" in limiter.buckets
        assert limiter.evict_stale(5.0)
        assert "old" not in limiter.buckets

    async def test_independent_keys(self) -> None:
        """Verify rate limits are tracked independently per key."""
        limiter = RateLimiter(limit=1, window=60)
        assert limiter.check("alice")
        assert limiter.check("bob")
        assert not limiter.check("alice")

    async def test_command_window(self) -> None:
        """Verify the command limiter forgets commands after the 10-second window."""
        limiter = make_bot().commands.command_limiter
        # A full budget spent exactly one window ago no longer counts.
        spent = asyncio.get_running_loop().time() - 10
        limiter.buckets["host.example"] = deque([spent] * 8)

        assert limiter.check("host.example")

    async def test_window_expiry(self) -> None:
        """Verify rate limit resets after window expires."""
        limiter = RateLimiter(limit=1, window=0.0)
        assert limiter.check("user")
        assert limiter.check("user")

    async def test_within_limit(self) -> None:
        """Verify requests within limit are allowed and excess is denied."""
        limiter = RateLimiter(limit=3, window=60)
        for _ in range(3):
            assert limiter.check("user")

        assert not limiter.check("user")

    async def test_rate_limiting_ignores_nick_change(self) -> None:
        """Verify the command limiter keys on host so nick cycling cannot bypass it."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)

        for index in range(20):
            prefix = Prefix(f"nick{index}", "user", "host.example")
            bot.authorizer.grant(prefix.render())
            await send_command(bot, prefix, "BOGUS")

        assert len(fake_irc.privmsgs) == 8
        assert all(text == "Unknown command" for _, text in fake_irc.privmsgs)


class AdminCommandTests(unittest.IsolatedAsyncioTestCase):
    """Tests for admin ban, op, deop, invite, and status commands."""

    async def test_admin_ban(self) -> None:
        """Verify BAN command sets a channel mode when bot is opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "BAN #test *!*@bad.host"))

        assert fake_irc.modes == [("#test", "+b", ("*!*@bad.host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Banned *!*@bad.host on #test"),
        ]

    async def test_join_part_nats_failure(self) -> None:
        """Verify join and part commands report NATS write failures."""
        bot, fake_irc, _ = bot_with_coordinator(FailingWriteCoordinator())
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "JOIN #new"))
        await bounded(bot.commands.dispatch(OWNER, "PART #test"))

        assert casefold("#new", "rfc1459") not in bot.channel_mgr.channels
        assert casefold("#test", "rfc1459") in bot.channel_mgr.channels
        # Each reply is the write's own error, so each command attempted one.
        assert fake_irc.privmsgs == [
            ("owner", "NATS disconnected: channel #new"),
            ("owner", "NATS disconnected: channel #test"),
        ]

    async def test_failure_reply_needs_live_session(self) -> None:
        """Send no write error once the admin quit while the write was in flight.

        Another user may hold the admin's old nick by the time the write fails.
        """
        coordinator = FailingWriteCoordinator()
        bot, fake_irc, _ = bot_with_coordinator(coordinator)
        bot.authorizer.grant(OWNER.render())
        put_channel = coordinator.put_channel

        async def put_after_quit(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            bot.events.on_irc_message(IRCMessage("QUIT", ("Quit",), OWNER))
            return await put_channel(record, after=after)

        with patch.object(coordinator, "put_channel", put_after_quit):
            await bounded(bot.commands.dispatch(OWNER, "JOIN #new"))

        await drain_session_writes(bot)
        assert casefold("#new", "rfc1459") not in bot.channel_mgr.channels
        assert fake_irc.privmsgs == []

    async def test_join_reports_superseded_update(self) -> None:
        """Tell the admin when another bot's newer record wins the write."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())
        # Stored by a peer, but not yet watched here.
        winner = ChannelRecord.new("#new", None, present=False)
        await bounded(coordinator.channels.put(asdict(winner), after=None))

        await bounded(bot.commands.dispatch(OWNER, "JOIN #new"))

        assert fake_irc.privmsgs == [("owner", "Update superseded for #new")]

    async def test_part_reports_parting(self) -> None:
        """Tell the admin a PART whose write won is under way."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].key = "live-key"
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "PART #test"))

        assert fake_irc.privmsgs == [("owner", "Parting #test")]
        # Unlike a JOIN's record, the PART's keeps no live key.
        assert coordinator.channel_puts[-1]["key"] is None

    async def test_part_waits_for_a_key_write_in_flight(self) -> None:
        """Part once this bot's own key write, stored but unanswered, returns.

        Written against the record before it, the PART would lose to that
        write's compare-and-set.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
        bot.authorizer.grant(OWNER.render())
        put_channel = coordinator.put_channel
        stored = asyncio.Event()
        release = asyncio.Event()

        async def unanswered_key_write(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            fields = await put_channel(record, after=after)
            if record["key"] == "k":
                stored.set()
                await release.wait()

            return fields

        with patch.object(coordinator, "put_channel", unanswered_key_write):
            bot.events.on_irc_message(
                IRCMessage("MODE", ("#test", "+k", "k"), Prefix("op", "~op", "h")),
            )
            await bounded(stored.wait())
            part = asyncio.create_task(bot.commands.cmd_part(OWNER, ("#test",)))
            # Let the PART run until it waits for its turn.
            await asyncio.sleep(0)
            release.set()
            await bounded(part)
            await settle(bot)

        assert fake_irc.privmsgs == [("owner", "Parting #test")]
        assert fake_irc.sent == [("PART", ("#test",))]

    async def test_join_keeps_the_key_written_before_it(self) -> None:
        """Store an admin JOIN with the key this bot's own key writes left.

        Read before its turn, the key would be one that a key write ahead of
        the JOIN replaced, and the JOIN would put it back.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        mgr = bot.channel_mgr
        mgr.apply_record(mgr.new_record("#other", "old", present=True))
        for runtime in mgr.channels.values():
            runtime.join = JoinState.JOINED

        bot.authorizer.grant(OWNER.render())
        op = Prefix("op", "~op", "h")
        put_channel = coordinator.put_channel
        stored = asyncio.Event()
        release = asyncio.Event()

        async def unanswered_test_write(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            fields = await put_channel(record, after=after)
            if record["channel"] == "#test":
                stored.set()
                await release.wait()

            return fields

        with patch.object(coordinator, "put_channel", unanswered_test_write):
            # One turn writes the keys pending in #test, then in #other.
            bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+k", "k"), op))
            await bounded(stored.wait())
            join = asyncio.create_task(bot.commands.cmd_join(OWNER, ("#other",)))
            # Let the JOIN run until it waits for its turn.
            await asyncio.sleep(0)
            bot.events.on_irc_message(IRCMessage("MODE", ("#other", "+k", "new"), op))
            release.set()
            await bounded(join)
            await settle(bot)

        assert fake_irc.privmsgs == [("owner", "Joining #other")]
        assert mgr.channel_records[casefold("#other", "rfc1459")].key == "new"

    async def test_join_reply_needs_live_session(self) -> None:
        """Send no JOIN reply once the admin quit while its write was in flight.

        Another user may hold the admin's old nick by the time the write lands.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())
        put_channel = coordinator.put_channel

        async def put_after_quit(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            bot.events.on_irc_message(IRCMessage("QUIT", ("Quit",), OWNER))
            return await put_channel(record, after=after)

        with patch.object(coordinator, "put_channel", put_after_quit):
            await bounded(bot.commands.dispatch(OWNER, "JOIN #new"))

        await drain_session_writes(bot)
        assert casefold("#new", "rfc1459") in bot.channel_mgr.channels
        assert fake_irc.privmsgs == []

    async def test_parse_error_reaches_authenticated_admin(self) -> None:
        """Explain an unparseable command to a sender who is authenticated."""
        bot, fake_irc = bot_with_irc()
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "   "))

        assert fake_irc.privmsgs == [("owner", "empty command")]

    async def test_list_commands_report_unknown_channel(self) -> None:
        """Answer list commands for an untracked channel with no record."""
        bot, fake_irc = bot_with_irc()
        bot.authorizer.grant(OWNER.render())

        for command in ("GETBANS", "GETMODES", "GETUSERS"):
            await bounded(bot.commands.dispatch(OWNER, f"{command} #missing"))

        assert fake_irc.privmsgs == [("owner", "No record for #missing")] * 3

    async def test_admin_commands_not_opped(self) -> None:
        """Refuse BAN, DEOP, OP, and UNBAN on a channel where the bot is not opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        # Each command would act here if the bot were opped.
        runtime.member("Chanop").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.add_ban("*!*@bad.host")
        bot.authorizer.grant(OWNER.render())

        for text in (
            "BAN #test *!*@bad.host",
            "DEOP #test Chanop",
            "OP #test Target",
            "UNBAN #test *!*@bad.host",
        ):
            with self.subTest(text=text):
                fake_irc.privmsgs.clear()

                await bounded(bot.commands.dispatch(OWNER, text))

                assert fake_irc.privmsgs == [("owner", "Not opped on #test")]

        assert fake_irc.modes == []

    async def test_admin_getbans(self) -> None:
        """Verify GETBANS command lists tracked channel bans."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "GETBANS #test"))
        assert fake_irc.privmsgs == [("owner", "No bans tracked for #test")]

        fake_irc.privmsgs.clear()
        for mask in ("*!*@bad.host", "*!*@evil.host"):
            runtime.add_ban(mask)

        await bounded(bot.commands.dispatch(OWNER, "GETBANS #test"))
        assert fake_irc.privmsgs == [("owner", "#test +b *!*@bad.host *!*@evil.host")]

    async def test_reply_list_drops_items_too_long_to_relay(self) -> None:
        """Drop an item too long to relay whole, never sending a bare header."""
        bot, fake_irc = bot_with_irc()
        # The shorter mask fits the line the bot sends, but not the line the
        # server relays with the bot's source in front.
        for mask in ("*!*@" + "h" * 400, "*!*@" + "h" * 495):
            with self.subTest(length=len(mask)):
                fake_irc.privmsgs.clear()
                with self.assertLogs("botnats.commands", level="WARNING"):
                    bot.commands.reply_list("owner", "#test +b", [mask, "ok"])
                    bot.commands.reply_list("owner", "#test +b", [mask])

                assert fake_irc.privmsgs == [("owner", "#test +b ok")]

    async def test_reply_drops_unsendable_line(self) -> None:
        """Log and drop a reply too long to send instead of raising."""
        bot, fake_irc = bot_with_irc()

        with self.assertLogs("botnats.commands", level="WARNING") as logs:
            bot.commands.reply("owner", "x" * MAX_IRC_MESSAGE_BYTES)

        assert fake_irc.privmsgs == []
        assert len(logs.output) == 1
        assert "dropped PRIVMSG to owner: IRC message exceeds" in logs.output[0]

    async def test_getbans_packs_long_ban_lists(self) -> None:
        """Pack a long ban list many masks to a line, not one line per mask."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())
        masks = [f"*!*@host{number:03d}.example" for number in range(100)]
        for mask in masks:
            runtime.add_ban(mask)

        await bounded(bot.commands.dispatch(OWNER, "GETBANS #test"))

        assert len(fake_irc.privmsgs) <= 6
        listed = [word for _, text in fake_irc.privmsgs for word in text.split()[2:]]
        assert listed == masks

    async def test_admin_getmodes(self) -> None:
        """Verify GETMODES reports tracked modes, with "*" for unknown values."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "GETMODES #test"))
        assert fake_irc.privmsgs == [("owner", "No modes tracked for #test")]

        fake_irc.privmsgs.clear()
        runtime.modes = "+nst"
        await bounded(bot.commands.dispatch(OWNER, "GETMODES #test"))
        assert fake_irc.privmsgs == [("owner", "#test +nst")]

        fake_irc.privmsgs.clear()
        runtime.modes = "+nstlk"
        runtime.key = "secret"
        runtime.limit = 5
        await bounded(bot.commands.dispatch(OWNER, "GETMODES #test"))
        assert fake_irc.privmsgs == [("owner", "#test +nstlk 5 secret")]

        fake_irc.privmsgs.clear()
        runtime.modes = "+nstkl"
        await bounded(bot.commands.dispatch(OWNER, "GETMODES #test"))
        assert fake_irc.privmsgs == [("owner", "#test +nstkl secret 5")]

        fake_irc.privmsgs.clear()
        # As tracked from RPL_CHANNELMODEIS "+ntkl * 10": the server hid the key.
        runtime.modes = "+ntkl"
        runtime.key = None
        runtime.limit = 10
        await bounded(bot.commands.dispatch(OWNER, "GETMODES #test"))
        assert fake_irc.privmsgs == [("owner", "#test +ntkl * 10")]

    async def test_admin_getusers(self) -> None:
        """Verify GETUSERS command lists channel members with op prefixes."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "GETUSERS #test"))
        assert fake_irc.privmsgs == [("owner", "No users tracked for #test")]

        fake_irc.privmsgs.clear()
        runtime.member("alpha").modes.add("o")
        runtime.member("beta")
        runtime.member("gamma").modes.add("o")
        await bounded(bot.commands.dispatch(OWNER, "GETUSERS #test"))
        assert fake_irc.privmsgs == [
            ("owner", "#test @alpha beta @gamma"),
        ]

    async def test_admin_getchans(self) -> None:
        """List tracked channels, marking opped ones @ and those not joined -."""
        bot, fake_irc = bot_with_irc()
        bot.authorizer.grant(OWNER.render())
        bot.channel_mgr.channels.clear()

        await bounded(bot.commands.dispatch(OWNER, "GETCHANS"))
        assert fake_irc.privmsgs == [("owner", "No channels tracked")]

        for name, state in (
            ("#Zeta", JoinState.JOINED),
            ("#alpha", JoinState.JOINED),
            ("#beta", JoinState.JOINING),
            ("#gamma", JoinState.IDLE),
        ):
            runtime = ChannelRuntime(bot.caps, channel=name, join=state)
            bot.channel_mgr.channels[casefold(name, "rfc1459")] = runtime

        bot.channel_mgr.channels[casefold("#alpha", "rfc1459")].member(
            "alpha"
        ).modes.add("o")
        fake_irc.privmsgs.clear()
        await bounded(bot.commands.dispatch(OWNER, "GETCHANS"))
        assert fake_irc.privmsgs == [("owner", "Channels @#alpha -#beta -#gamma #Zeta")]

    async def test_admin_getusers_chunked(self) -> None:
        """Verify GETUSERS splits long nick lists across multiple messages."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())

        for i in range(80):
            runtime.member(f"longernickname{i:03d}")

        await bounded(bot.commands.dispatch(OWNER, "GETUSERS #test"))
        assert len(fake_irc.privmsgs) > 1
        all_nicks = []
        for _, text in fake_irc.privmsgs:
            assert text.startswith("#test ")
            # The server puts the bot's own source in front when it relays.
            line = f"PRIVMSG owner :{text}\r\n".encode()
            assert RELAY_SOURCE_BYTES + len(line) <= MAX_IRC_MESSAGE_BYTES
            all_nicks.extend(text.split()[1:])

        assert all_nicks == [f"longernickname{i:03d}" for i in range(80)]

    async def test_admin_commands_with_disconnected_irc(self) -> None:
        """Report a command's failed send, and swallow the undeliverable reply."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())
        fake_irc.connected = False

        with patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send:
            await bounded(bot.commands.dispatch(OWNER, "BAN #test *!*@bad.host"))

        assert send.call_args_list == [
            call("MODE", "#test", "+b", "*!*@bad.host"),
            call("PRIVMSG", "owner", trailing="IRC is not connected"),
        ]

    async def test_admin_commands_always_queue(self) -> None:
        """Ask IRC to queue every admin command, even a copy of one waiting.

        A skipped copy could leave a ban, unban, and ban again unbanned.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.add_ban("*!*@bad.host")
        bot.authorizer.grant(OWNER.render())

        with patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send:
            for text in (
                "BAN #test *!*@bad.host",
                "UNBAN #test *!*@bad.host",
                "OP #test Target",
                "INVITE #test guest",
            ):
                await bounded(bot.commands.dispatch(OWNER, text))

        commands = [
            entry for entry in send.call_args_list if entry.args[0] != "PRIVMSG"
        ]
        assert commands == [
            call("MODE", "#test", "+b", "*!*@bad.host"),
            call("MODE", "#test", "-b", "*!*@bad.host"),
            call("MODE", "#test", "+o", "Target"),
            call("INVITE", "guest", "#test"),
        ]

    async def test_admin_deop(self) -> None:
        """Verify DEOP command removes operator mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.member("Target").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "DEOP #test Target"))

        assert fake_irc.modes == [("#test", "-o", ("Target",))]
        assert fake_irc.privmsgs == [("owner", "Deopped Target on #test")]

    async def test_admin_deop_removes_hidden_lower_modes(self) -> None:
        """Verify DEOP removes lower operator modes hidden by the highest one."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.caps.parse_prefix("(qao)~&@")
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").modes.add("q")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "DEOP #test Target"))

        assert fake_irc.modes == [
            ("#test", "-q", ("Target",)),
            ("#test", "-a", ("Target",)),
            ("#test", "-o", ("Target",)),
        ]

    async def test_admin_deop_not_opped_target(self) -> None:
        """Verify DEOP reports when target is not opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "DEOP #test Target"))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "Target is not opped on #test")]

    async def test_admin_invite(self) -> None:
        """Send IRC INVITE directly, only while opped in the channel."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "INVITE #test guest"))
        assert fake_irc.sent == []
        assert fake_irc.privmsgs == [("owner", "Not opped on #test")]

        runtime.member("alpha").modes.add("o")
        fake_irc.privmsgs.clear()
        await bounded(bot.commands.dispatch(OWNER, "INVITE #test guest"))

        assert fake_irc.sent == [("INVITE", ("guest", "#test"))]
        assert fake_irc.privmsgs == [("owner", "Invited guest to #test")]

    async def test_admin_kick(self) -> None:
        """Kick a member, with or without a reason, only while opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("Target")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "KICK #test target"))
        assert fake_irc.privmsgs == [("owner", "Not opped on #test")]

        runtime.member("alpha").modes.add("o")
        fake_irc.privmsgs.clear()
        with patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send:
            await bounded(bot.commands.dispatch(OWNER, "KICK #test ghost"))
            await bounded(bot.commands.dispatch(OWNER, "KICK #test TARGET"))
            await bounded(bot.commands.dispatch(OWNER, "KICK #test TARGET go  away"))

        kicks = [c for c in send.call_args_list if c.args[0] == "KICK"]
        assert kicks == [
            call("KICK", "#test", "Target", trailing=None),
            call("KICK", "#test", "Target", trailing="go away"),
        ]
        assert fake_irc.privmsgs == [
            ("owner", "ghost not found on #test"),
            ("owner", "Kicked Target from #test"),
            ("owner", "Kicked Target from #test"),
        ]

    async def test_admin_op(self) -> None:
        """Verify OP command grants operator mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "OP #test Target"))

        assert fake_irc.modes == [("#test", "+o", ("Target",))]
        assert fake_irc.privmsgs == [("owner", "Opped Target on #test")]

    async def test_admin_op_already_opped(self) -> None:
        """Verify OP reports when target is already opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.member("Target").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "OP #test Target"))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "Target is already opped on #test"),
        ]

    async def test_admin_op_unknown_target(self) -> None:
        """Verify OP reports when target is not found on channel."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "OP #test ghost"))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "ghost not found on #test")]

    async def test_admin_op_refuses_unidentified_member(self) -> None:
        """Refuse OP for a member whose full nick!user@host is not yet known."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Unseen")
        runtime.member("Partial").prefix = Prefix("Partial", "user")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "OP #test Unseen"))
        await bounded(bot.commands.dispatch(OWNER, "OP #test Partial"))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "Unseen not found on #test"),
            ("owner", "Partial not found on #test"),
        ]

    async def test_unauthenticated_commands_are_ignored(self) -> None:
        """Drop commands from a sender without a session, without replying."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant("other!user@real.host")

        for text in ("BAN #test *!*@bad.host", "XYZZY", "   "):
            await bounded(bot.commands.dispatch(OWNER, text))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == []
        assert fake_irc.sent == []

    async def test_admin_unban_case_insensitive(self) -> None:
        """Verify UNBAN matches ban masks case-insensitively."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.add_ban("*!*@Bad.Host")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "UNBAN #test *!*@BAD.host"))

        assert fake_irc.modes == [("#test", "-b", ("*!*@Bad.Host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Unbanned *!*@Bad.Host on #test"),
        ]

    async def test_admin_unban_unknown_mask(self) -> None:
        """Verify UNBAN reports when mask is not in the ban list."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "UNBAN #test *!*@unknown.host"))

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "No matching ban for *!*@unknown.host on #test"),
        ]

    async def test_cmd_status(self) -> None:
        """Verify STATUS command returns bot identity and channel count."""
        bot, fake_irc, _ = bot_with_coordinator()
        # Registered under a fallback nick, unlike the configured one.
        fake_irc.current_nick = "alpha_"
        bot.authorizer.grant(OWNER.render())
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
        # A channel still joining is desired but not counted.
        bot.channel_mgr.channels[casefold("#other", "rfc1459")] = ChannelRuntime(
            bot.caps, channel="#other", join=JoinState.JOINING
        )
        bot.presence.update(
            BotPresence("Alpha-ID", "host.example", "inst", "alpha_", "~alpha"),
        )
        bot.presence.update(
            BotPresence("beta-id", "peer.example", "inst2", "beta", "~beta"),
        )

        await bounded(bot.commands.dispatch(OWNER, "STATUS"))
        assert fake_irc.privmsgs == [
            ("owner", "bot id=alpha-id nick=alpha_ peers=1 channels=1"),
            (
                "owner",
                (
                    "nats connection=up routes=0 jetstream=up leader=nats-1 "
                    "replicas=1/1 lag=0"
                ),
            ),
        ]

    async def test_status_reply_needs_live_session(self) -> None:
        """Send no NATS status once the admin renamed while it was read.

        Another user may hold the admin's old nick by the time NATS answers.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())
        status = coordinator.status

        async def status_after_nick() -> NATSStatus:
            bot.events.on_irc_message(IRCMessage("NICK", ("owner2",), OWNER))
            return await status()

        with patch.object(coordinator, "status", status_after_nick):
            await bounded(bot.commands.dispatch(OWNER, "STATUS"))

        await drain_session_writes(bot)
        # Only the line sent before the await reached the admin.
        assert fake_irc.privmsgs == [
            ("owner", "bot id=alpha-id nick=alpha peers=0 channels=0"),
        ]

    async def test_unknown_command(self) -> None:
        """Verify an unrecognized command sends an error to the user."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "XYZZY"))

        assert fake_irc.privmsgs == [("owner", "Unknown command")]

    async def test_bad_admin_input_gets_reply(self) -> None:
        """Answer malformed or inapplicable admin commands instead of crashing."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())
        replies = {
            "BAN #test": "BAN <channel> <mask>",
            "KICK #test": "KICK <channel> <nick> [reason]",
            "JOIN": "JOIN <channel> [key]",
            "DEOP #test ghost": "ghost is not opped on #test",
            "BAN #missing *!*@x": "Not opped on #missing",
            "DEOP #missing ghost": "Not opped on #missing",
            "OP #missing ghost": "Not opped on #missing",
            "UNBAN #missing *!*@x": "Not opped on #missing",
        }

        for text, reply in replies.items():
            with self.subTest(text=text):
                fake_irc.privmsgs.clear()

                await bounded(bot.commands.dispatch(OWNER, text))

                assert fake_irc.privmsgs == [("owner", reply)]

        assert fake_irc.modes == []
        assert coordinator.channel_puts == []

    async def test_extra_argument_gets_usage_reply(self) -> None:
        """Reject an argument past a command's last with its usage reply."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())
        replies = {
            "BAN #test *!*@x extra": "BAN <channel> <mask>",
            "DEOP #test alpha extra": "DEOP <channel> <nick>",
            "GETBANS #test extra": "GETBANS <channel>",
            "GETCHANS extra": "GETCHANS takes no arguments",
            "GETMODES #test extra": "GETMODES <channel>",
            "GETUSERS #test extra": "GETUSERS <channel>",
            "INVITE #test ghost extra": "INVITE <channel> <nick>",
            "JOIN #new key extra": "JOIN <channel> [key]",
            "OP #test alpha extra": "OP <channel> <nick>",
            "PART #test extra": "PART <channel>",
            "STATUS extra": "STATUS takes no arguments",
            "UNBAN #test *!*@x extra": "UNBAN <channel> <mask>",
        }

        for text, reply in replies.items():
            with self.subTest(text=text):
                fake_irc.privmsgs.clear()

                await bounded(bot.commands.dispatch(OWNER, text))

                assert fake_irc.privmsgs == [("owner", reply)]

        assert fake_irc.modes == []
        assert coordinator.channel_puts == []

    async def test_channel_update_rejects_oversized_mode_command(self) -> None:
        """Reject a channel update before storing an unusable mode command."""
        bot, _, coordinator = bot_with_coordinator()
        bot.config = replace(bot.config, channel_modes="+" + "n" * 499)

        with self.assertRaisesRegex(ValueError, "exceeds 512 bytes"):
            await bounded(
                bot.commands.channel_update(OWNER, "#test", None, present=True)
            )

        assert coordinator.channel_puts == []

    async def test_join_without_enforced_modes(self) -> None:
        """Join under the default config, which enforces no channel modes."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.config = replace(
            bot.config,
            channel_modes="",
            enforced_modes=(frozenset(), frozenset()),
        )
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.cmd_join(OWNER, ("#new",)))

        assert fake_irc.privmsgs == [("owner", "Joining #new")]
        assert coordinator.channel_puts[-1]["channel"] == "#new"

    async def test_join_preserves_live_key(self) -> None:
        """Verify a repeated keyless JOIN retains a key learned from IRC."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.key = "live-key"
        base = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")].revision
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.cmd_join(OWNER, ("#test",)))

        assert fake_irc.privmsgs == [("owner", "Joining #test")]
        payload = coordinator.channel_puts[-1]
        assert payload["key"] == "live-key"
        assert runtime.key == "live-key"
        # Written against the record it replaces, so a concurrent write wins cleanly.
        assert coordinator.channel_after == [base]

    async def test_join_stores_key(self) -> None:
        """Store a JOIN's key so every bot can join the keyed channel."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bounded(bot.commands.dispatch(OWNER, "JOIN #new hunter2"))

        assert fake_irc.privmsgs == [("owner", "Joining #new")]
        payload = coordinator.channel_puts[-1]
        assert payload["channel"] == "#new"
        assert payload["key"] == "hunter2"
