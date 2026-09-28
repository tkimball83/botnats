# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for command parsing, input validation, and rate limiting."""

import unittest
from collections import deque
from dataclasses import asdict
from unittest.mock import patch

from botnats.channel import JoinState
from botnats.commands import RateLimiter, parse_command
from botnats.irc.protocol import Prefix, casefold
from botnats.presence import BotPresence
from botnats.validators import (
    validate_channel,
    validate_join,
    validate_key,
    validate_target,
)
from tests.unit.helpers import (
    OWNER,
    FailingIRC,
    bot_with_coordinator,
    bot_with_irc,
)


class CommandTests(unittest.TestCase):
    """Tests for command parsing, channel validation, and key validation."""

    def test_parse_preserves_backslash(self) -> None:
        """Verify backslashes in arguments are preserved, not shell-escaped."""
        name, arguments = parse_command("deop #chan Evil\\dude")

        assert name == "DEOP"
        assert arguments == ("#chan", "Evil\\dude")

    def test_validate_channel(self) -> None:
        """Verify channel name validation accepts and rejects correctly."""
        assert validate_channel("#general") == "#general"
        for invalid in (
            "general",
            "#bad channel",
            "#bad\tchannel",
            "#bad,channel",
            "#bad\x07channel",
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "channel"),
            ):
                validate_channel(invalid)

    def test_validate_key(self) -> None:
        """Verify channel key validation accepts and rejects correctly."""
        assert validate_key("safe-key") == "safe-key"
        for invalid in (
            "",
            ":key",
            "two words",
            "one,two",
            "safe\r\nOPER root pass",
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "channel key"),
            ):
                validate_key(invalid)

    def test_validate_join_message_size_and_encoding(self) -> None:
        """Reject JOIN parameters that cannot fit in an IRC message."""
        invalid = (
            ("#" + "a" * 510, None),
            ("#test", "k" * 510),
            ("#" + chr(0xD800), None),
        )
        for channel, key in invalid:
            with self.subTest(channel=channel), self.assertRaises(ValueError):
                validate_join(channel, key)

    def test_validate_target(self) -> None:
        """Verify command target and ban-mask validation."""
        assert validate_target("*!*@evil.example") == "*!*@evil.example"
        for invalid in ("", ":nick", "*!*@ evil", "mask\twith\ttabs", "nul\x00"):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "target"),
            ):
                validate_target(invalid)


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


class AdminCommandTests(unittest.IsolatedAsyncioTestCase):
    """Tests for admin ban, op, deop, invite, and status commands."""

    async def test_admin_ban(self) -> None:
        """Verify BAN command sets a channel mode when bot is opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "BAN #test *!*@bad.host")

        assert fake_irc.modes == [("#test", "+b", ("*!*@bad.host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Banned *!*@bad.host on #test"),
        ]

    async def test_admin_ban_not_opped(self) -> None:
        """Verify BAN command reports when bot is not opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "BAN #test *!*@bad.host")

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "Not opped on #test")]

    async def test_admin_getbans(self) -> None:
        """Verify GETBANS command lists tracked channel bans."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "GETBANS #test")
        assert fake_irc.privmsgs == [("owner", "No bans tracked for #test")]

        fake_irc.privmsgs.clear()
        for _mask in ("*!*@bad.host", "*!*@evil.host"):
            runtime.add_ban(_mask)

        await bot.commands.dispatch(OWNER, "GETBANS #test")
        assert fake_irc.privmsgs == [
            ("owner", "#test +b *!*@bad.host"),
            ("owner", "#test +b *!*@evil.host"),
        ]

    async def test_admin_getmodes(self) -> None:
        """Verify GETMODES command reports tracked channel modes."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "GETMODES #test")
        assert fake_irc.privmsgs == [("owner", "No modes tracked for #test")]

        fake_irc.privmsgs.clear()
        runtime.modes = "+nst"
        await bot.commands.dispatch(OWNER, "GETMODES #test")
        assert fake_irc.privmsgs == [("owner", "#test +nst")]

        fake_irc.privmsgs.clear()
        runtime.key = "secret"
        await bot.commands.dispatch(OWNER, "GETMODES #test")
        assert fake_irc.privmsgs == [("owner", "#test +nst secret")]

    async def test_admin_getusers(self) -> None:
        """Verify GETUSERS command lists channel members with op prefixes."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "GETUSERS #test")
        assert fake_irc.privmsgs == [("owner", "No users tracked for #test")]

        fake_irc.privmsgs.clear()
        runtime.member("alpha").modes.add("o")
        runtime.member("beta")
        runtime.member("gamma").modes.add("o")
        await bot.commands.dispatch(OWNER, "GETUSERS #test")
        assert fake_irc.privmsgs == [
            ("owner", "#test @alpha beta @gamma"),
        ]

    async def test_admin_getusers_chunked(self) -> None:
        """Verify GETUSERS splits long nick lists across multiple messages."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        bot.authorizer.grant(OWNER.render())

        for i in range(80):
            runtime.member(f"longernickname{i:03d}")

        await bot.commands.dispatch(OWNER, "GETUSERS #test")
        assert len(fake_irc.privmsgs) > 1
        for _, text in fake_irc.privmsgs:
            assert text.startswith("#test ")

        all_nicks = []
        for _, text in fake_irc.privmsgs:
            all_nicks.extend(text.split()[1:])

        assert len(all_nicks) == 80

    async def test_admin_commands_with_disconnected_irc(self) -> None:
        """Verify admin commands degrade gracefully when IRC is disconnected."""
        bot, _, _ = bot_with_coordinator(irc=FailingIRC())
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "BAN #test *!*@bad.host")

        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        action = {"channel": "#test", "presence": asdict(peer)}
        await bot.channel_mgr.invite_peer(action)
        runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
        runtime.add_ban("*!~beta@beta.host")
        await bot.channel_mgr.unban_peer(action)

        assert "*!~beta@beta.host" in runtime.bans.values()

        runtime.pending_ops["beta"] = peer
        await bot.channel_mgr.flush_pending_ops(casefold("#test"))
        assert "o" not in runtime.member("beta").modes

    async def test_admin_deop(self) -> None:
        """Verify DEOP command removes operator mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.member("Target").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "DEOP #test Target")

        assert fake_irc.modes == [("#test", "-o", ("Target",))]

    async def test_admin_deop_removes_hidden_lower_modes(self) -> None:
        """Verify DEOP removes lower operator modes hidden by the highest one."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.caps.parse_prefix("(qao)~&@")
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").modes.add("q")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "DEOP #test Target")

        assert fake_irc.modes == [
            ("#test", "-q", ("Target",)),
            ("#test", "-a", ("Target",)),
            ("#test", "-o", ("Target",)),
        ]

    async def test_admin_deop_not_opped_target(self) -> None:
        """Verify DEOP reports when target is not opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "DEOP #test Target")

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "Target is not opped on #test")]

    async def test_admin_invite(self) -> None:
        """Verify INVITE command sends IRC INVITE directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "INVITE #test guest")

        assert fake_irc.sent == [("INVITE", ("guest", "#test"))]
        assert fake_irc.privmsgs == [("owner", "Invited guest to #test")]

    async def test_admin_op(self) -> None:
        """Verify OP command grants operator mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "OP #test Target")

        assert fake_irc.modes == [("#test", "+o", ("Target",))]

    async def test_admin_op_already_opped(self) -> None:
        """Verify OP reports when target is already opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.member("Target").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "OP #test Target")

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "Target is already opped on #test"),
        ]

    async def test_admin_op_unknown_target(self) -> None:
        """Verify OP reports when target is not found on channel."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "OP #test ghost")

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "ghost not found on #test")]

    async def test_admin_unban(self) -> None:
        """Verify UNBAN command removes a ban mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.add_ban("*!*@bad.host")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "UNBAN #test *!*@bad.host")

        assert fake_irc.modes == [("#test", "-b", ("*!*@bad.host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Unbanned *!*@bad.host on #test"),
        ]

    async def test_admin_unban_case_insensitive(self) -> None:
        """Verify UNBAN matches ban masks case-insensitively."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.add_ban("*!*@Bad.Host")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "UNBAN #test *!*@bad.host")

        assert fake_irc.modes == [("#test", "-b", ("*!*@Bad.Host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Unbanned *!*@Bad.Host on #test"),
        ]

    async def test_admin_unban_unknown_mask(self) -> None:
        """Verify UNBAN reports when mask is not in the ban list."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "UNBAN #test *!*@unknown.host")

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "No matching ban for *!*@unknown.host on #test"),
        ]

    async def test_cmd_status(self) -> None:
        """Verify STATUS command returns bot identity and channel count."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())
        bot.channel_mgr.channels[casefold("#test")].join = JoinState.JOINED
        bot.presence.update(
            BotPresence("Alpha", "host.example", "inst", "alpha", "~alpha"),
        )
        bot.presence.update(
            BotPresence("beta", "peer.example", "inst2", "beta", "~beta"),
        )

        await bot.commands.dispatch(OWNER, "STATUS")
        assert fake_irc.privmsgs == [
            ("owner", "bot id=alpha nick=alpha peers=1 channels=1"),
            (
                "owner",
                (
                    "nats connection=up routes=0 jetstream=up leader=nats-1 "
                    "replicas=1/1 lag=0"
                ),
            ),
        ]

    async def test_unknown_command(self) -> None:
        """Verify an unrecognized command sends an error to the user."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "XYZZY")

        assert fake_irc.privmsgs == [("owner", "Unknown command")]
