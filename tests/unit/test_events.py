# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC event handling and server message processing."""

import asyncio
import unittest
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

from botnats.channel import JOIN_RETRY_DELAY, JoinState
from botnats.config import mode_intent
from botnats.irc.protocol import IRCMessage, ISupportState, Prefix, casefold
from botnats.presence import BotPresence
from tests.unit.helpers import (
    FailingPartIRC,
    FailingWriteCoordinator,
    FakeCoordinator,
    FakeIRC,
    FakeKV,
    bot_with_channel,
    bot_with_coordinator,
    bot_with_irc,
    drain_session_writes,
    make_bot,
    settle,
)

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

    from botnats.nats.store import Session

CUSTOM_ISUPPORT = IRCMessage(
    "005",
    (
        "alpha",
        "CASEMAPPING=ascii",
        "CHANMODES=b,k,l,imn",
        "MONITOR",
        "PREFIX=(yov)@%+",
        "supported",
    ),
)
UNSET_MODE = IRCMessage("MODE", ("#test", "-n"), Prefix("someone", "user", "host"))


class ServerTests(unittest.IsolatedAsyncioTestCase):
    """Tests for IRC server message handling and mode enforcement."""

    async def test_ban_list_records_mask(self) -> None:
        """Verify 367 numeric adds a ban mask to the channel."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage(
                "367",
                ("alpha", "#test", "*!*@banned.host", "op", "1234567890"),
            ),
        )

        assert "*!*@banned.host" in runtime.bans.values()

    async def test_ban_matching_bot_requests_unban(self) -> None:
        """Track every new ban, and ask peers to lift only one matching this bot."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("beta").prefix = peer.to_prefix()
        runtime.member("beta").modes.add("o")

        async def ban(mask: str) -> None:
            bot.events.on_irc_message(
                IRCMessage("MODE", ("#test", "+b", mask), Prefix("op", "user", "host")),
            )
            await settle(bot)

        await ban("*!*@other.host")
        assert coordinator.help_requests == []

        await ban("*!*@alpha.host")
        assert set(runtime.bans.values()) == {"*!*@other.host", "*!*@alpha.host"}
        assert [kind for kind, _ in coordinator.help_requests] == ["unban"]

    async def test_unban_mode_forgets_tracked_ban(self) -> None:
        """Forget a tracked ban when MODE -b lifts it, ignoring case."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.add_ban("*!*@Bad.Host")

        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "-b", "*!*@BAD.HOST"), Prefix("op", "u", "h")),
        )

        assert runtime.bans == {}

    async def test_chghost_revokes_authorization(self) -> None:
        """Verify CHGHOST revokes the session and does not move it."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "old.host")
        new_user, new_host = "newuser", "new.host"
        bot.authorizer.grant(old_prefix.render())

        bot.events.on_irc_message(
            IRCMessage("CHGHOST", (new_user, new_host), old_prefix),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        new_prefix = Prefix("owner", new_user, new_host)
        assert not bot.authorizer.authorized(new_prefix.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0]["revoked"] is True

    async def test_chghost_without_identity_skips_revocation(self) -> None:
        """Log and skip revocation when no complete old identity exists."""
        bot, _ = bot_with_irc()

        with self.assertLogs("botnats.events", level="DEBUG") as logs:
            bot.events.on_irc_message(
                IRCMessage("CHGHOST", ("newuser", "new.host"), Prefix("owner")),
            )

        assert any("no complete identity" in line for line in logs.output)

    async def test_chghost_updates_member_prefix(self) -> None:
        """Update another user's member prefix, leaving this bot's identity."""
        bot, _ = bot_with_irc()
        identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")
        bot.identity.current = identity
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        old_prefix = Prefix("someone", "user", "old.host")
        runtime.member("someone").prefix = old_prefix

        bot.events.on_irc_message(
            IRCMessage("CHGHOST", ("newuser", "new.host"), old_prefix),
        )

        member = runtime.members.get(casefold("someone", "rfc1459"))
        assert member is not None
        assert member.prefix == Prefix("someone", "newuser", "new.host")
        assert bot.identity.current is identity

    async def test_chghost_updates_self_identity(self) -> None:
        """Verify CHGHOST on the bot itself refreshes its identity."""
        bot, _ = bot_with_irc()
        bot.identity.current = BotPresence(
            bot.config.bot_id, "old.host", "inst", "alpha", "~alpha"
        )

        bot.events.on_irc_message(
            IRCMessage(
                "CHGHOST",
                ("newuser", "new.host"),
                Prefix("alpha", "~alpha", "old.host"),
            ),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.user == "newuser"
        assert bot.identity.current.host == "new.host"

    async def test_rate_limited_commands_are_not_queued(self) -> None:
        """Drop a flood at the rate limit instead of queueing every message."""
        bot, _ = bot_with_irc()
        prefix = Prefix("flooder", "user", "host.example")

        async with bot.events.command_lock:
            for _ in range(100):
                bot.events.on_irc_message(
                    IRCMessage("PRIVMSG", ("alpha", "AUTH 000000"), prefix),
                )

            queued = len(bot.tasks)
            watched = bot.sessions.watched_identities[prefix.render()]
        async with asyncio.timeout(5):
            await bot.tasks.drain()

        assert queued == 8
        assert watched == (8, False)

    async def test_non_commands_are_not_queued(self) -> None:
        """Skip channel chatter, CTCP, and anonymous senders before queueing."""
        bot = make_bot(irc=FakeIRC())
        prefix = Prefix("owner", "user", "host.example")

        for message in (
            IRCMessage("PRIVMSG", ("#test", "STATUS"), prefix),
            IRCMessage("PRIVMSG", ("alpha", "\x01ACTION test\x01"), prefix),
            IRCMessage("PRIVMSG", ("alpha", "STATUS"), Prefix("owner")),
            IRCMessage("PRIVMSG", ("alpha", "STATUS")),
        ):
            bot.events.on_irc_message(message)

        assert not bot.tasks
        assert not bot.sessions.watched_identities

    async def test_end_of_names(self) -> None:
        """Query members, modes, and bans after NAMES; ask peers for op."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha")
        runtime.member("beta").prefix = peer.to_prefix()
        runtime.member("beta").modes.add("o")

        bot.events.on_irc_message(
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        )
        await settle(bot)

        assert fake_irc.sent == [
            ("WHO", ("#test",)),
            ("MODE", ("#test",)),
            ("MODE", ("#test", "+b")),
        ]
        assert [kind for kind, _ in coordinator.help_requests] == ["op"]

    async def test_end_of_names_queries_resent_after_refusal(self) -> None:
        """Resend NAMES on the next tick when the queries after it are refused.

        Its end reply then asks for members, modes, and bans again.
        """
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        end_of_names = IRCMessage("366", ("alpha", "#test", "End of /NAMES list"))

        # A full send queue refuses commands as a dropped connection does.
        fake_irc.connected = False
        bot.events.on_irc_message(end_of_names)
        fake_irc.connected = True
        bot.channel_mgr.join_desired()
        bot.events.on_irc_message(end_of_names)
        await settle(bot)

        assert fake_irc.sent == [
            ("NAMES", ("#test",)),
            ("WHO", ("#test",)),
            ("MODE", ("#test",)),
            ("MODE", ("#test", "+b")),
        ]
        assert not runtime.names_due

    async def test_names_and_who_record_only_operator_modes(self) -> None:
        """Track operator prefixes only; sub-op modes are never applied."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "+bob @carol @+dave")),
        )
        assert runtime.members["bob"].modes == set()
        assert runtime.members["carol"].modes == {"o"}
        # multi-prefix lists every prefix a member holds, highest first.
        assert set(runtime.members) == {"bob", "carol", "dave"}
        assert runtime.members["dave"].modes == {"o"}

        bot.events.on_irc_message(
            IRCMessage(
                "352",
                ("alpha", "#test", "user", "host", "srv", "bob", "H+", "0 realname"),
            ),
        )
        assert runtime.members["bob"].prefix == Prefix("bob", "user", "host")
        assert runtime.members["bob"].modes == set()

    async def test_names_replaces_stale_modes(self) -> None:
        """Verify a NAMES reply without op prefix clears a prior op mode."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("carol").modes.add("o")

        bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "carol")),
        )

        assert runtime.members["carol"].modes == set()

    async def test_quit_with_host_only_prefix_revokes_via_member(self) -> None:
        """Revoke the member's full identity on a QUIT lacking the user part."""
        bot, _, coordinator = bot_with_coordinator()
        owner = Prefix("owner", "user", "static.example")
        bot.authorizer.grant(owner.render())
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("owner").prefix = owner

        bot.events.on_irc_message(
            IRCMessage("QUIT", (), Prefix.parse("Owner@static.example")),
        )
        await drain_session_writes(bot)

        assert casefold("owner", "rfc1459") not in runtime.members
        assert not bot.authorizer.authorized(owner.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0]["prefix"] == owner.render()
        assert coordinator.session_puts[0]["revoked"] is True

    async def test_invite_ignores_joined_channel(self) -> None:
        """Verify an INVITE to an already-joined channel is ignored."""
        bot, fake_irc = bot_with_irc()
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#test"), Prefix("op", "u", "h")),
        )

        assert ("JOIN", ("#test",)) not in fake_irc.sent

    async def test_invite_ignores_unknown_channel(self) -> None:
        """Verify an INVITE to an unconfigured channel is ignored."""
        bot, fake_irc = bot_with_irc()

        bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#other"), Prefix("op", "u", "h")),
        )

        assert fake_irc.sent == []

    async def test_invite_joins_desired_channel(self) -> None:
        """Verify an INVITE to a desired unjoined channel triggers a join."""
        bot, fake_irc = bot_with_irc()

        bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#test"), Prefix("op", "u", "h")),
        )

        assert ("JOIN", ("#test",)) in fake_irc.sent

    async def test_isupport_parsing(self) -> None:
        """Verify ISUPPORT tokens update server capabilities and channel lookups."""
        bot, _ = bot_with_irc()
        mgr = bot.channel_mgr
        mgr.apply_record(mgr.new_record("#te[st", None, present=True))

        bot.events.handle_isupport(CUSTOM_ISUPPORT)
        runtime = mgr.channels[bot.caps.fold("#test")]
        runtime.join = JoinState.JOINED
        bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "@alpha %other")),
        )

        assert bot.caps.casemapping == "ascii"
        assert bot.caps.fold("[") != bot.caps.fold("{")
        # Keyed under rfc1459 as "#te{st" until the new casemapping rekeys it.
        assert mgr.runtime("#te[st") is not None
        assert bot.caps.chanmodes == ("b", "k", "l", "imn")
        assert bot.caps.op_mode == "y"
        assert mgr.is_self_opped(runtime)
        assert bot.caps.monitor

    async def test_isupport_removals_restore_defaults(self) -> None:
        """Restore default behavior when the server removes ISUPPORT values."""
        bot, _ = bot_with_irc()
        bot.events.handle_isupport(CUSTOM_ISUPPORT)

        bot.events.handle_isupport(
            IRCMessage(
                "005",
                (
                    "alpha",
                    "-CASEMAPPING",
                    "-CHANMODES",
                    "-MONITOR",
                    "-PREFIX",
                    "supported",
                ),
            ),
        )

        assert bot.caps == ISupportState()

    async def test_isupport_monitor_without_limit(self) -> None:
        """Use MONITOR whether or not the server advertises a target limit."""
        for token in ("MONITOR", "MONITOR=", "MONITOR=100"):
            with self.subTest(token=token):
                bot, fake_irc = bot_with_irc()
                fake_irc.current_nick = "fallback"

                bot.events.handle_isupport(
                    IRCMessage("005", ("alpha", token, "are supported")),
                )

                assert bot.caps.monitor
                assert ("MONITOR", ("+", "alpha")) in fake_irc.sent
                assert not bot.tasks

    async def test_refused_monitor_subscription_polls_ison(self) -> None:
        """Poll ISON instead when the send queue refuses MONITOR +."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        fake_irc.connected = False
        bot.caps.monitor = True

        bot.events.start_nick_watch()

        task = bot.events.nick_watch_task
        assert task is not None
        assert task.get_name() == "nick-ison-poll"
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_isupport_without_trailing(self) -> None:
        """Verify the final ISUPPORT token is kept when trailing text is omitted."""
        bot, _ = bot_with_irc()

        bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "CASEMAPPING=ascii", "MONITOR=100")),
        )

        assert bot.caps.casemapping == "ascii"
        assert bot.caps.monitor

    async def test_higher_prefix_counts_as_opped(self) -> None:
        """Verify PREFIX modes above operator retain operator privileges."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[bot.caps.fold("#test")]
        runtime.join = JoinState.JOINED

        bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "PREFIX=(qao)~&@", "supported")),
        )
        bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "~alpha")),
        )

        assert bot.channel_mgr.is_self_opped(runtime)

    async def test_higher_prefix_live_mode_updates(self) -> None:
        """Verify live MODE updates track privileges above operator."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[bot.caps.fold("#test")]
        runtime.member("alpha").modes.add("o")

        bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "PREFIX=(qao)~&@", "supported")),
        )
        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "+q", "Target"), Prefix("service")),
        )
        assert bot.caps.is_opped(runtime.members["target"].modes)

        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "-q", "Target"), Prefix("service")),
        )
        assert not bot.caps.is_opped(runtime.members["target"].modes)

    async def test_unhandled_join_error_logged_once(self) -> None:
        """Log an unhandled refusal of a pending JOIN once, until joined again."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINING
        refusal = IRCMessage("477", ("alpha", "#Test", "Registered nicks only"))

        with self.assertLogs("botnats.events", level="WARNING") as logs:
            bot.events.on_irc_message(refusal)

        assert logs.output == [
            "WARNING:botnats.events:cannot join #test: 477 Registered nicks only",
        ]

        with self.assertNoLogs("botnats.events", level="WARNING"):
            bot.events.on_irc_message(refusal)
            # An error about a channel the bot is in is not a join refusal.
            runtime.join = JoinState.JOINED
            bot.events.on_irc_message(
                IRCMessage("482", ("alpha", "#test", "not channel operator")),
            )

        runtime.reset()
        runtime.join = JoinState.JOINING
        with self.assertLogs("botnats.events", level="WARNING"):
            bot.events.on_irc_message(refusal)

        # The JOIN stays pending, to be resent after the reply timeout.
        assert runtime.join is JoinState.JOINING

    async def test_messages_naming_no_desired_channel_are_ignored(self) -> None:
        """Ignore a user MODE, and errors and replies naming no desired channel."""
        bot, fake_irc = bot_with_irc()

        for message in (
            IRCMessage("MODE", ("alpha", "+i"), Prefix("alpha", "~alpha", "host")),
            IRCMessage("433", ("*", "alpha", "Nickname is already in use")),
            IRCMessage("324", ("alpha", "#other", "+nt")),
            IRCMessage("352", ("alpha", "#other", "u", "h", "srv", "bob", "H", "0 r")),
            IRCMessage("367", ("alpha", "#other", "*!*@bad.host")),
            IRCMessage("475", ("alpha", "#other", "Cannot join channel (+k)")),
        ):
            bot.events.on_irc_message(message)

        assert fake_irc.sent == []
        assert not bot.tasks

    async def test_refusals_request_matching_help(self) -> None:
        """Ask for a raised limit, an invite, or an unban; retry a bad key alone."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]

        for numeric in ("471", "473", "474", "475"):
            # A pending JOIN already due for a resend.
            runtime.join = JoinState.JOINING
            runtime.join_retry_at = 0.0
            bot.events.on_irc_message(
                IRCMessage(numeric, ("alpha", "#test", "cannot join channel")),
            )
            await settle(bot)

            # Every refusal paces the JOIN: the next tick does not resend it.
            assert not runtime.join_due()

        assert [kind for kind, _ in coordinator.help_requests] == [
            "limit",
            "invite",
            "unban",
        ]

    async def test_refused_join_retried_after_delay(self) -> None:
        """Resend a refused JOIN once the retry delay passes, not every tick.

        An INVITE resends it at once.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        join = ("JOIN", ("#test",))

        bot.channel_mgr.join_desired()
        bot.events.on_irc_message(
            IRCMessage("474", ("alpha", "#test", "Cannot join channel (+b)")),
        )
        bot.channel_mgr.join_desired()
        assert fake_irc.sent == [join]

        runtime.join_retry_at -= JOIN_RETRY_DELAY
        bot.channel_mgr.join_desired()
        assert fake_irc.sent == [join, join]

        bot.events.on_irc_message(
            IRCMessage("473", ("alpha", "#test", "Cannot join channel (+i)")),
        )
        bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#test"), Prefix("op", "u", "h")),
        )
        assert fake_irc.sent == [join, join, join]
        await settle(bot)

    async def test_bad_key_refusal_takes_the_stored_key(self) -> None:
        """Join with a peer's recorded key once the server refuses this bot's.

        The peer's record, spelling the channel its own way, arrived while
        this bot had a key of its own pending, and the change that followed
        was hidden as "*".
        """
        bot, fake_irc, _ = bot_with_coordinator(FailingWriteCoordinator())
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        op = Prefix("op", "~op", "op.host")
        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+k", "A"), op))
        mgr.apply_record(
            mgr.new_record(
                "#Test", "B", present=True, after=mgr.channel_records[folded].revision
            ),
        )
        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+k", "*"), op))
        bot.events.on_irc_message(IRCMessage("KICK", ("#test", "alpha"), op))
        await settle(bot)

        mgr.safe_join(runtime)
        bot.events.on_irc_message(
            IRCMessage("475", ("alpha", "#test", "Cannot join channel (+k)")),
        )
        mgr.safe_join(runtime)

        assert fake_irc.sent == [("JOIN", ("#Test", "A")), ("JOIN", ("#Test", "B"))]

    async def test_mode_enforce_once_on_op_with_unset(self) -> None:
        """Verify one enforcement when a single MODE ops the bot and unsets."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test", "rfc1459")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+o-n", "alpha"),
                Prefix("someone", "user", "host"),
            ),
        )
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_deop_requests_op_unless_reopped(self) -> None:
        """Ask peers for op after a deop, but not after a deop-reop MODE line."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        # An opped peer is present, so a spurious op request would be sent.
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("beta").prefix = peer.to_prefix()
        runtime.member("beta").modes.add("o")

        async def mode(*params: str) -> None:
            bot.events.on_irc_message(
                IRCMessage("MODE", ("#test", *params), Prefix("someone", "u", "h")),
            )
            await settle(bot)

        await mode("-o+o", "alpha", "alpha")
        assert fake_irc.modes == []
        assert coordinator.help_requests == []

        await mode("-o", "alpha")
        assert fake_irc.modes == []
        assert [kind for kind, _ in coordinator.help_requests] == ["op"]

    async def test_peer_op_prompts_op_request(self) -> None:
        """Ask for op once a peer bot gains it while this bot lacks it."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha")
        runtime.member("beta").prefix = peer.to_prefix()

        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "+o", "beta"), Prefix("chanserv")),
        )
        await settle(bot)

        assert [kind for kind, _ in coordinator.help_requests] == ["op"]

    async def test_mode_enforce_on_unset(self) -> None:
        """Verify channel modes are re-enforced when unset by another user."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test", "rfc1459")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        fake_irc.current_nick = "Alpha"

        bot.events.on_irc_message(UNSET_MODE)
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_mode_enforcement_resent_after_refusal(self) -> None:
        """Enforce modes after the next tick's NAMES when enforcement is refused."""
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        # A full send queue refuses commands as a dropped connection does.
        fake_irc.connected = False
        bot.events.on_irc_message(UNSET_MODE)
        fake_irc.connected = True
        bot.channel_mgr.join_desired()
        bot.events.on_irc_message(
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        )

        assert fake_irc.sent == [
            ("NAMES", ("#test",)),
            ("WHO", ("#test",)),
            ("MODE", ("#test",)),
            ("MODE", ("#test", "+b")),
            ("MODE", ("#test", "+npst")),
        ]

    async def test_mode_enforce_unset_mode_added(self) -> None:
        """Verify enforcement triggers when a negated mode is set by another user."""
        bot, fake_irc = bot_with_irc()
        bot.config = replace(
            bot.config,
            channel_modes="+np-s",
            enforced_modes=mode_intent("+np-s"),
        )
        folded = casefold("#test", "rfc1459")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+s"),
                Prefix("someone", "user", "host"),
            ),
        )
        assert fake_irc.modes == [("#test", "+np-s", ())]

    async def test_mode_key_tracking(self) -> None:
        """Verify channel key is tracked on mode changes."""
        bot, _ = bot_with_irc()
        folded = casefold("#test", "rfc1459")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        assert runtime.key is None

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+k", "secret"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.key == "secret"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k", "*"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.key is None

    async def test_mode_key_recorded_under_configured_spelling(self) -> None:
        """Record a key seen under an equivalent spelling on the channel's record.

        Under rfc1459, MODE #a{ changes the configured #A[. The store keys
        records by exact name, so the write must name #A[ and compare against
        its revision, never start a second record for #a{.
        """
        coordinator = FakeCoordinator()
        kv = FakeKV()
        coordinator.channels.kv = cast("KeyValue", kv)
        bot, _, _ = bot_with_coordinator(coordinator)
        await bot.channel_mgr.write_record("#A[", None, present=True)
        configured = bot.channel_mgr.durable_revision("#A[")
        runtime = bot.channel_mgr.runtime("#a{")
        assert runtime is not None
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage("MODE", ("#a{", "+k", "newkey"), Prefix("op", "u", "h")),
        )
        await settle(bot)

        assert [(put["channel"], put["key"]) for put in coordinator.channel_puts] == [
            ("#A[", None),
            ("#A[", "newkey"),
        ]
        assert coordinator.channel_after == [None, configured]
        assert list(kv.entries) == [coordinator.channels.key("#A[")]
        assert bot.channel_mgr.channel_records[bot.caps.fold("#a{")].key == "newkey"

    async def test_mode_hidden_key_ignored(self) -> None:
        """Keep the stored key when MODE shows a hidden '*' key, opped or not."""
        bot, _, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "secret"

        for opped in (False, True):
            if opped:
                runtime.member("alpha").modes.add("o")

            bot.events.on_irc_message(
                IRCMessage(
                    "MODE",
                    ("#test", "+k", "*"),
                    Prefix("services", "service", "services.host"),
                ),
            )
            await settle(bot)

            assert runtime.key == "secret"
            assert coordinator.channel_puts == []

    async def test_mode_hidden_key_drops_pending_write(self) -> None:
        """Drop a key write still pending once MODE hides a key, but keep the key.

        Under rfc1459, MODE #room{ changes the configured #room[. A netsplit
        can resend an unchanged key as "*".
        """
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr = bot.channel_mgr
        mgr.apply_record(mgr.new_record("#room[", None, present=True))
        runtime = mgr.channels[casefold("#room[", "rfc1459")]
        runtime.join = JoinState.JOINED
        op = Prefix("op", "~op", "op.host")
        bot.events.on_irc_message(IRCMessage("MODE", ("#room[", "+k", "old"), op))
        await settle(bot)

        assert runtime.key_pending
        bot.events.on_irc_message(IRCMessage("MODE", ("#room{", "+k", "*"), op))
        coordinator.failing = False
        await mgr.retry_pending_keys()

        assert not runtime.key_pending
        assert runtime.key == "old"
        assert coordinator.channel_puts == []

    async def test_mode_key_unset_without_argument(self) -> None:
        """Clear the channel key when a server strips the -k argument."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "secret"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )

        assert runtime.key is None

        runtime.key = "secret"
        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k+o", "bob"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )

        assert runtime.key is None
        assert runtime.member("bob").modes == {"o"}

    async def test_nick_only_prefix_moves_bot_identity(self) -> None:
        """Advertise the new nick when a NICK prefix omits user@host."""
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            bot.config.bot_id, "host.example", "inst", "alpha", "~alpha"
        )
        fake_irc.current_nick = "newalpha"

        bot.events.on_irc_message(
            IRCMessage("NICK", ("newalpha",), Prefix.parse("alpha")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.nick == "newalpha"
        assert bot.identity.current.host == "host.example"

    async def test_nick_only_prefix_skips_members_awaiting_who(self) -> None:
        """Revoke from another channel's member when NAMES alone lists one.

        A member WHO has not described yet has no user or host to complete a
        nick-only QUIT, NICK, or CHGHOST prefix from.
        """
        owner = Prefix("owner", "user", "host.example")
        for message in (
            IRCMessage("QUIT", ("bye",), Prefix("Owner")),
            IRCMessage("NICK", ("newowner",), Prefix("Owner")),
            IRCMessage("CHGHOST", ("newuser", "new.host"), Prefix("Owner")),
        ):
            with self.subTest(command=message.command):
                bot, _, coordinator = bot_with_coordinator()
                bot.authorizer.grant(owner.render())
                mgr = bot.channel_mgr
                mgr.apply_record(mgr.new_record("#other", None, present=True))
                # Seen first, as listed by NAMES; WHO has not answered yet.
                mgr.channels[casefold("#test", "rfc1459")].member("owner")
                mgr.channels[casefold("#other", "rfc1459")].member(
                    "owner"
                ).prefix = owner

                with self.assertNoLogs("botnats", level="ERROR"):
                    bot.events.on_irc_message(message)
                    await drain_session_writes(bot)

                assert not bot.authorizer.authorized(owner.render())
                assert [
                    (put["prefix"], put["revoked"]) for put in coordinator.session_puts
                ] == [(owner.render(), True)]

    async def test_mode_key_unusable(self) -> None:
        """Ignore a key no JOIN could send, and record nothing for it."""
        bot, _, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "old-key"

        # A malformed key, and one that makes "JOIN #test <key>" over 512 bytes.
        for key in ("bad key", "k" * 500):
            with (
                self.subTest(key=key[:8]),
                self.assertLogs("botnats.events", level="WARNING"),
            ):
                bot.events.on_irc_message(
                    IRCMessage(
                        "MODE",
                        ("#test", "+k", key),
                        Prefix("chanserv", "service", "services.host"),
                    ),
                )
                assert not bot.tasks

        # An unusable +k is ignored: the existing key is retained and nothing
        # is republished cluster-wide.
        assert runtime.key == "old-key"
        assert coordinator.channel_puts == []

    async def test_channel_modes_from_324(self) -> None:
        """Verify RPL_CHANNELMODEIS populates the runtime mode string."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage("324", ("alpha", "#test", "+nstk", "secret"), None),
        )
        assert runtime.modes == "+nstk"

        # A channel without modes is shown as a bare "+".
        bot.events.on_irc_message(IRCMessage("324", ("alpha", "#test", "+"), None))
        assert runtime.modes == ""

    async def test_channel_key_reconciled_from_324(self) -> None:
        """Store a key RPL_CHANNELMODEIS shows or lacks; ignore a hidden one."""
        bot, _, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        async def channel_modes(*params: str) -> None:
            bot.events.on_irc_message(
                IRCMessage("324", ("alpha", "#test", *params), None),
            )
            await settle(bot)

        await channel_modes("+ntk", "*")
        assert runtime.key is None
        assert coordinator.channel_puts == []

        await channel_modes("+ntk", "real-key")
        assert runtime.key == "real-key"
        assert [p["key"] for p in coordinator.channel_puts] == ["real-key"]

        # A key shown as "*" or with no argument at all is hidden, not gone.
        for hidden in (("+ntk", "*"), ("+ntk",)):
            await channel_modes(*hidden)
            assert runtime.key == "real-key"

        await channel_modes("+ntk", "real-key")
        assert len(coordinator.channel_puts) == 1

        await channel_modes("+nt")
        assert runtime.key is None
        assert [p["key"] for p in coordinator.channel_puts] == ["real-key", None]

    async def test_channel_modes_repair_stale_key_record(self) -> None:
        """Record a key RPL_CHANNELMODEIS shows that only the record lacks.

        A key write lost while this bot was out of the channel leaves the key
        in memory alone, and other bots would join with the stale record.
        """
        bot, _, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "new-key"

        bot.events.on_irc_message(
            IRCMessage("324", ("alpha", "#test", "+ntk", "new-key"), None),
        )
        await settle(bot)

        assert [p["key"] for p in coordinator.channel_puts] == ["new-key"]
        record = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]
        assert record.key == "new-key"

    async def test_channel_modes_ignored_after_kick(self) -> None:
        """Keep the key when a mode query is answered after a KICK.

        The server shows the channel to a non-member without its key, so
        taking that reply would send the next JOIN without one.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        mgr = bot.channel_mgr
        await mgr.write_record("#test", "secret", present=True)
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage("KICK", ("#test", "alpha"), Prefix("op", "~op", "op.host")),
        )
        bot.events.on_irc_message(IRCMessage("324", ("alpha", "#test", "+nt")))
        await settle(bot)
        mgr.join_desired()

        assert fake_irc.sent == [("JOIN", ("#test", "secret"))]

    async def test_late_channel_replies_ignored_after_kick(self) -> None:
        """Ignore NAMES, WHO, and ban list replies that arrive after a KICK.

        Services can kick the bot right after it joins, before the server
        answers the queries the join sent: the replies would restore members
        and bans of a channel it has left, and a late end of NAMES would query
        it again and ask peers for op in it.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.runtime("#test")
        assert runtime is not None
        runtime.join = JoinState.JOINED

        for message in (
            IRCMessage("KICK", ("#test", "alpha"), Prefix("ChanServ", "s", "svc")),
            IRCMessage("353", ("alpha", "=", "#test", "@bob")),
            IRCMessage("352", ("alpha", "#test", "u", "h", "srv", "bob", "H@", "0 r")),
            IRCMessage("367", ("alpha", "#test", "*!*@bad.host")),
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        ):
            bot.events.on_irc_message(message)

        await settle(bot)

        assert runtime.members == {}
        assert runtime.bans == {}
        assert fake_irc.sent == []
        assert [kind for kind, _ in coordinator.help_requests] == ["unban"]

    async def test_op_gain_requeries_channel_modes(self) -> None:
        """Once opped, query modes for a hidden key and enforce them, once."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        services = Prefix("chanserv", "service", "services.host")

        for _ in range(2):
            bot.events.on_irc_message(
                IRCMessage("MODE", ("#test", "+o", "alpha"), services),
            )

        assert fake_irc.sent.count(("MODE", ("#test",))) == 1
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_op_gain_mode_query_resent_after_refusal(self) -> None:
        """Resend NAMES on the next tick when the MODE query on op is refused.

        Its end reply then queries the modes again.
        """
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        record = fake_irc.send

        def refuse_mode_query(
            command: str,
            *params: str,
            trailing: str | None = None,
        ) -> None:
            if (command, params) == ("MODE", ("#test",)):
                msg = "IRC outbound queue is full"
                raise ConnectionError(msg)

            record(command, *params, trailing=trailing)

        with patch.object(fake_irc, "send", refuse_mode_query):
            bot.events.on_irc_message(
                IRCMessage("MODE", ("#test", "+o", "alpha"), Prefix("chanserv")),
            )

        bot.channel_mgr.join_desired()

        assert fake_irc.sent == [
            ("MODE", ("#test", "+npst")),
            ("NAMES", ("#test",)),
        ]

    async def test_channel_limit_tracked(self) -> None:
        """Track +l from RPL_CHANNELMODEIS and MODE changes."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        services = Prefix("chanserv", "service", "services.host")

        bot.events.on_irc_message(
            IRCMessage("324", ("alpha", "#test", "+ntlk", "5", "secret"), None),
        )
        assert runtime.limit == 5

        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+l", "7"), services))
        assert runtime.limit == 7

        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "-l"), services))
        assert runtime.limit is None

        # RPL_CHANNELMODEIS is the full mode state: a limit it lacks is gone.
        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+l", "9"), services))
        bot.events.on_irc_message(
            IRCMessage("324", ("alpha", "#test", "+ntk", "secret"), None),
        )
        assert runtime.limit is None

    async def test_channel_modes_updated_on_change(self) -> None:
        """Verify MODE changes update the tracked channel mode string."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+nst"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+i"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == "+nsti"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-s"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == "+nti"

    async def test_channel_modes_tracks_type_b(self) -> None:
        """Verify type-B modes are removed from the mode string on unset."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+nstk"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k", "*"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == "+nst"

    async def test_channel_modes_removal_clears_string(self) -> None:
        """Verify removing the last mode produces an empty string, not '+'."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+n"

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-n"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == ""

    async def test_mode_no_enforce_when_not_opped(self) -> None:
        """Verify mode enforcement is skipped when bot is not opped."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test", "rfc1459")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(UNSET_MODE)
        assert fake_irc.modes == []

    async def test_modes_are_isolated_across_channels(self) -> None:
        """Verify modes, bans, keys, and members change on only one channel."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        mgr = bot.channel_mgr
        first = mgr.runtime("#test")
        assert first is not None
        first.join = JoinState.JOINED
        first.member("alpha").modes.add("o")
        first.member("Target").prefix = Prefix("Target", "user", "first.host")

        mgr.apply_record(mgr.new_record("#other", "second-key", present=True))
        second = mgr.runtime("#other")
        assert second is not None
        second.join = JoinState.JOINED
        second.add_ban("*!*@second.host")
        second.member("alpha").modes.add("o")
        second.member("Target").modes.add("v")

        bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+obk", "Target", "*!*@first.host", "first-key"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        await settle(bot)

        assert first.modes == "+k"
        assert first.member("Target").modes == {"o"}
        assert set(first.bans.values()) == {"*!*@first.host"}
        assert first.key == "first-key"
        assert second.member("Target").modes == {"v"}
        assert set(second.bans.values()) == {"*!*@second.host"}
        assert second.key == "second-key"
        assert len(coordinator.channel_puts) == 1
        payload = coordinator.channel_puts[0]
        assert payload["channel"] == "#test"
        assert payload["key"] == "first-key"
        assert payload["present"] is True
        assert fake_irc.modes == []

    async def test_modes_enforced_on_multiple_channels(self) -> None:
        """Verify mode enforcement is independently triggered for each channel."""
        bot, fake_irc = bot_with_irc()
        mgr = bot.channel_mgr
        mgr.apply_record(mgr.new_record("#other", None, present=True))
        for channel in ("#test", "#other"):
            runtime = mgr.runtime(channel)
            assert runtime is not None
            runtime.join = JoinState.JOINED
            runtime.member("alpha").modes.add("o")

        for channel in ("#test", "#other"):
            bot.events.on_irc_message(
                IRCMessage("366", ("alpha", channel, "End of /NAMES list")),
            )

        assert fake_irc.modes == [
            ("#test", "+b", ()),
            ("#test", "+npst", ()),
            ("#other", "+b", ()),
            ("#other", "+npst", ()),
        ]

    async def test_nick_change(self) -> None:
        """Verify nick change updates identity and channel member tracking."""
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            bot.config.bot_id, "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        fake_irc.current_nick = "NewNick"

        bot.events.on_irc_message(
            IRCMessage("NICK", ("NewNick",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.nick == "NewNick"
        assert casefold("alpha", "rfc1459") not in runtime.members
        member = runtime.members[casefold("NewNick", "rfc1459")]
        assert member.nick == "NewNick"
        assert member.prefix == Prefix("NewNick", "~alpha", "host.example")

    async def test_nick_change_requires_new_authentication(self) -> None:
        """Revoke the session on NICK; the new nick must authenticate again."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        new_prefix = Prefix("newowner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())

        bot.events.on_irc_message(
            IRCMessage("NICK", ("newowner",), old_prefix),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        assert not bot.authorizer.authorized(new_prefix.render())
        assert [put["revoked"] for put in coordinator.session_puts] == [True]

    async def test_other_kick_preserves_state(self) -> None:
        """Verify kick of another user preserves channel state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("victim").prefix = Prefix("victim", "user", "host")

        bot.events.on_irc_message(
            IRCMessage(
                "KICK",
                ("#test", "victim", "reason"),
                Prefix("someone", "user", "host"),
            ),
        )

        assert runtime.joined
        assert "*!*@old.ban" in runtime.bans.values()
        assert casefold("alpha", "rfc1459") in runtime.members
        assert casefold("victim", "rfc1459") not in runtime.members

    async def test_quit_does_not_wait_for_durable_write(self) -> None:
        """Revoke locally at once while the durable write runs in background."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())
        release = asyncio.Event()
        record_put = coordinator.put_session

        async def slow_put(session: dict[str, Any]) -> Session:
            await release.wait()
            return await record_put(session)

        with patch.object(coordinator, "put_session", slow_put):
            bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.sessions.pending
            release.set()
            await drain_session_writes(bot)

        assert not bot.sessions.pending
        assert [put["revoked"] for put in coordinator.session_puts] == [True]

    async def test_commands_run_in_background_in_order(self) -> None:
        """Keep IRC flowing during a slow command; still finish commands in order."""
        bot, _ = bot_with_irc()
        release = asyncio.Event()
        finished: list[str] = []

        async def dispatch(prefix: Prefix, text: str) -> None:
            del prefix
            if text == "SLOW":
                await release.wait()

            finished.append(text)

        owner = Prefix("owner", "user", "host.example")
        with patch.object(bot.commands, "dispatch", dispatch):
            for text in ("SLOW", "FAST"):
                bot.events.on_irc_message(
                    IRCMessage("PRIVMSG", ("alpha", text), owner),
                )

            await asyncio.sleep(0)
            assert finished == []
            release.set()
            await settle(bot)

        assert finished == ["SLOW", "FAST"]

    async def test_self_join_clears_state(self) -> None:
        """Reset channel state on a self-join and learn this bot's identity."""
        bot, _, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("stale").prefix = Prefix("stale", "user", "host")

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )
        await settle(bot)

        assert runtime.joined
        assert runtime.bans == {}
        assert casefold("stale", "rfc1459") not in runtime.members
        assert casefold("alpha", "rfc1459") in runtime.members
        assert bot.identity.current == BotPresence(
            bot.config.bot_id,
            "host.example",
            bot.identity.instance_id,
            "alpha",
            "~alpha",
        )

    async def test_self_join_orphaned(self) -> None:
        """Verify self-join to undesired channel triggers immediate part."""
        bot, fake_irc = bot_with_irc()
        bot.channel_mgr.channels.pop(casefold("#test", "rfc1459"))

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )
        # The server follows the JOIN echo with NAMES of the channel left.
        bot.events.on_irc_message(IRCMessage("353", ("alpha", "=", "#test", "@alpha")))
        bot.events.on_irc_message(
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        )

        assert fake_irc.sent == [("PART", ("#test",))]

    async def test_self_join_orphaned_queued(self) -> None:
        """Queue the PART of an orphan channel when it cannot be sent.

        The bot is in the channel, so if it is wanted again before the PART
        goes out, it is joined at once and relearns the channel with NAMES.
        """
        fake_irc = FailingPartIRC()
        bot = bot_with_channel(irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        mgr = bot.channel_mgr
        mgr.channels.pop(casefold("#test", "rfc1459"))

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert mgr.pending_parts == {"#test": "#test"}

        mgr.apply_record(mgr.new_record("#test", None, present=True))

        runtime = mgr.runtime("#test")
        assert runtime is not None
        assert runtime.joined
        assert mgr.pending_parts == {}
        assert fake_irc.sent == [("NAMES", ("#test",))]

    async def test_leaving_a_pending_part_channel_drops_the_part(self) -> None:
        """Forget a pending PART once this bot is kicked or parts anyway.

        Wanted again, the channel is then joined like any other, not treated
        as one this bot never left. Another user leaving changes nothing.
        """
        alpha = Prefix("alpha", "~alpha", "host.example")
        bob = Prefix("bob", "user", "bob.host")
        for other, own in (
            (
                IRCMessage("KICK", ("#test", "bob", "bye"), alpha),
                IRCMessage("KICK", ("#Test", "alpha", "bye"), bob),
            ),
            (
                IRCMessage("PART", ("#test",), bob),
                IRCMessage("PART", ("#Test",), alpha),
            ),
        ):
            with self.subTest(command=own.command):
                fake_irc = FailingPartIRC()
                bot = bot_with_channel(irc=fake_irc)
                bot.identity.current = BotPresence(
                    "alpha", "host.example", "inst", "alpha", "~alpha"
                )
                mgr = bot.channel_mgr
                mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
                mgr.apply_record(mgr.new_record("#test", None, present=False))

                bot.events.on_irc_message(other)
                assert mgr.pending_parts == {"#test": "#test"}

                bot.events.on_irc_message(own)
                assert mgr.pending_parts == {}

                mgr.apply_record(mgr.new_record("#test", None, present=True))

                runtime = mgr.runtime("#test")
                assert runtime is not None
                assert runtime.join is JoinState.JOINING
                assert fake_irc.sent == [("JOIN", ("#test",))]

    async def test_other_join_records_member_identity(self) -> None:
        """Record another user's full identity when they join, keeping state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        prefix = Prefix("Bob", "user", "bob.host")

        bot.events.on_irc_message(IRCMessage("JOIN", ("#test",), prefix))

        member = runtime.members.get(casefold("bob", "rfc1459"))
        assert member is not None
        assert member.prefix == prefix
        assert runtime.joined
        assert "*!*@old.ban" in runtime.bans.values()

    async def test_self_kick_clears_state(self) -> None:
        """Clear channel state on a self-kick and ask peers for an unban."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("other").prefix = Prefix("other", "user", "host")

        bot.events.on_irc_message(
            IRCMessage(
                "KICK",
                ("#test", "alpha", "reason"),
                Prefix("someone", "user", "host"),
            ),
        )
        await settle(bot)

        assert not runtime.joined
        assert runtime.bans == {}
        assert runtime.members == {}
        assert [kind for kind, _ in coordinator.help_requests] == ["unban"]

    async def test_self_part_clears_state(self) -> None:
        """Verify self-part clears channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("other").prefix = Prefix("other", "user", "host")

        bot.events.on_irc_message(
            IRCMessage("PART", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert not runtime.joined
        assert runtime.bans == {}
        assert runtime.members == {}

    async def test_userhost_identity(self) -> None:
        """Verify USERHOST reply sets bot identity."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)

        bot.events.on_irc_message(
            IRCMessage("302", ("alpha", "alpha=+~user@real.host")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.user == "~user"
        assert bot.identity.current.host == "real.host"

    async def test_userhost_identity_as_away_operator(self) -> None:
        """Read the identity past the operator (*) and away (-) markers."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)

        bot.events.on_irc_message(
            IRCMessage("302", ("alpha", "other=+x@y alpha*=-bot@cloaked.host")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.user == "bot"
        assert bot.identity.current.host == "cloaked.host"

    async def test_part_removes_other_member(self) -> None:
        """Drop another user who parts, leaving this bot's membership intact."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("bob")

        bot.events.on_irc_message(
            IRCMessage("PART", ("#test",), Prefix("Bob", "user", "host")),
        )

        assert casefold("bob", "rfc1459") not in runtime.members
        assert runtime.joined

    async def test_who_reply_about_self_sets_identity(self) -> None:
        """Learn this bot's own user and host from a WHO reply."""
        bot, _ = bot_with_irc()
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage(
                "352",
                (
                    "alpha",
                    "#test",
                    "~alpha",
                    "alpha.host",
                    "irc.server",
                    "alpha",
                    "H",
                    "0 realname",
                ),
            ),
        )
        async with asyncio.timeout(5):
            await bot.tasks.drain()

        assert bot.identity.current == BotPresence(
            bot.config.bot_id,
            "alpha.host",
            bot.identity.instance_id,
            "alpha",
            "~alpha",
        )

    async def test_who_reply_updates_member(self) -> None:
        """Verify 352 numeric updates member prefix and modes."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        bot.events.on_irc_message(
            IRCMessage(
                "352",
                (
                    "alpha",
                    "#test",
                    "user",
                    "host.example",
                    "irc.server",
                    "someone",
                    "H@",
                    "0 realname",
                ),
            ),
        )

        member = runtime.members.get(casefold("someone", "rfc1459"))
        assert member is not None
        assert member.prefix == Prefix("someone", "user", "host.example")
        assert "o" in member.modes

    async def test_set_identity_dedup(self) -> None:
        """Sweep pending joins when the identity changes, not when it repeats."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        prefix = Prefix("alpha", "~alpha", "real.host")
        join = ("JOIN", ("#test",))

        bot.events.set_identity(prefix)
        assert fake_irc.sent == [join]

        # The channel goes idle again, as after a kick. A burst of WHO and
        # USERHOST replies about this bot must not resend the JOIN; the next
        # tick retries it.
        runtime.reset()
        bot.events.set_identity(prefix)
        assert fake_irc.sent == [join]

        bot.events.set_identity(Prefix("alpha", "~alpha", "new.host"))
        assert bot.identity.current is not None
        assert bot.identity.current.host == "new.host"
        assert fake_irc.sent == [join, join]
        await settle(bot)

    async def test_set_identity_dedups_presence_publish(self) -> None:
        """Verify redundant identity updates do not re-publish presence."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        prefix = Prefix("alpha", "~alpha", "real.host")

        bot.events.set_identity(prefix)
        bot.events.set_identity(prefix)
        await settle(bot)

        assert len(coordinator.presence_puts) == 1

        bot.events.set_identity(Prefix("alpha", "~alpha", "new.host"))
        await settle(bot)

        assert bot.identity.current is not None
        assert bot.identity.current.host == "new.host"
        assert len(coordinator.presence_puts) == 2

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
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").modes.add("o")
        runtime.modes = "+nstl"
        runtime.limit = 3
        runtime.names_due = True
        runtime.cooldowns["op"] = 1.0
        bot.channel_mgr.pending_parts[bot.caps.fold("#gone")] = "#gone"
        bot.identity.current = BotPresence("alpha", "host", "one", "alpha", "user")
        bot.identity.registered = True
        generation = bot.identity.generation

        bot.events.on_irc_disconnect()

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
        assert runtime.bans == {}
        assert not runtime.members
        assert runtime.modes == ""
        assert runtime.limit is None
        assert not runtime.names_due
        assert runtime.cooldowns == {}
        assert bot.channel_mgr.pending_parts == {}
        assert bot.authorizer.authorized(identity)


class NickWatchTests(unittest.IsolatedAsyncioTestCase):
    """Tests for ISON and MONITOR nickname reclaim."""

    async def test_ison_reply_reclaims_nick(self) -> None:
        """Reclaim the desired nickname when ISON reports it offline."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        bot.events.on_irc_message(
            IRCMessage("303", ("alpha", "")),
        )

        assert ("NICK", ("alpha",)) in fake_irc.sent
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_ison_reply_skips_when_nick_online(self) -> None:
        """Do not reclaim when ISON reports the desired nick is still taken."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        bot.events.on_irc_message(
            IRCMessage("303", ("fallback", "ALPHA")),
        )

        assert ("NICK", ("alpha",)) not in fake_irc.sent

    async def test_monitor_offline_reclaims_nick(self) -> None:
        """Reclaim the desired nickname when MONITOR reports it offline."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        bot.events.on_irc_message(
            IRCMessage("731", ("fallback", "ALPHA!user@host")),
        )

        assert ("NICK", ("alpha",)) in fake_irc.sent
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_monitor_offline_ignores_unrelated_nick(self) -> None:
        """Ignore MONITOR offline for nicks other than the desired one."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        bot.events.on_irc_message(
            IRCMessage("731", ("fallback", "stranger!user@host")),
        )

        assert ("NICK", ("alpha",)) not in fake_irc.sent

    async def test_refused_monitor_reclaim_polls_ison(self) -> None:
        """Poll ISON, once, when the send queue refuses a NICK MONITOR prompted.

        MONITOR reports the nick offline only once, so nothing else retries it.
        """
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.caps.monitor = True
        bot.events.start_nick_watch()
        assert bot.events.nick_watch_task is None

        fake_irc.connected = False
        for _ in range(2):
            bot.events.on_irc_message(
                IRCMessage("731", ("fallback", "alpha!user@host")),
            )

        task = bot.events.nick_watch_task
        assert task is not None
        assert task.get_name() == "nick-ison-poll"
        assert bot.tasks == {task}
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_server_refused_monitor_reclaim_polls_ison(self) -> None:
        """Poll ISON when the server refuses a NICK that MONITOR prompted.

        A nick delay or services hold refuses it with 437 after MONITOR has
        reported the nick offline, and MONITOR does not report it again.
        """
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.caps.monitor = True
        bot.events.start_nick_watch()

        bot.events.on_irc_message(
            IRCMessage("731", ("fallback", "alpha!user@host")),
        )
        bot.events.on_irc_message(
            IRCMessage("437", ("fallback", "alpha", "Nick temporarily unavailable")),
        )

        assert fake_irc.sent == [("MONITOR", ("+", "alpha")), ("NICK", ("alpha",))]
        task = bot.events.nick_watch_task
        assert task is not None
        assert task.get_name() == "nick-ison-poll"
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_welcome_starts_ison_poll(self) -> None:
        """Start ISON polling when registered with a fallback nick."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        bot.events.on_irc_message(
            IRCMessage("001", ("fallback", "Welcome")),
        )

        assert bot.events.nick_watch_task is not None
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_welcome_skips_watch_when_nick_matches(self) -> None:
        """Register, skipping the nick watch, when given the desired nick."""
        bot, _ = bot_with_irc()

        bot.events.on_irc_message(
            IRCMessage("001", ("alpha", "Welcome")),
        )

        assert bot.identity.registered
        assert bot.events.nick_watch_task is None
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_isupport_monitor_switches_nick_watch(self) -> None:
        """Watch the nick with MONITOR while advertised, and with ISON after."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.events.start_nick_watch()
        poll = bot.events.nick_watch_task
        assert poll is not None

        bot.events.on_irc_message(
            IRCMessage("005", ("fallback", "MONITOR=100", "supported")),
        )
        async with asyncio.timeout(5):
            await asyncio.gather(poll, return_exceptions=True)

        assert poll.cancelled()
        assert bot.events.nick_watch_task is None
        assert ("MONITOR", ("+", "alpha")) in fake_irc.sent

        bot.events.on_irc_message(
            IRCMessage("005", ("fallback", "-MONITOR", "supported")),
        )

        assert not bot.caps.monitor
        assert bot.events.nick_watch_task is not None
        async with asyncio.timeout(5):
            await bot.tasks.drain()

    async def test_nick_reclaim_stops_ison_watch(self) -> None:
        """Stop the ISON poll when the bot reclaims its desired nickname."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.events.start_nick_watch()
        poll = bot.events.nick_watch_task
        assert poll is not None

        fake_irc.current_nick = "alpha"
        bot.events.on_irc_message(
            IRCMessage("NICK", ("alpha",), Prefix("fallback", "~alpha", "host")),
        )
        async with asyncio.timeout(5):
            await asyncio.gather(poll, return_exceptions=True)

        assert poll.cancelled()
        assert bot.events.nick_watch_task is None

    async def test_nick_change_away_starts_watch(self) -> None:
        """Start a nick watch when the bot's nick changes away from desired."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "forced"
        bot.identity.registered = True

        bot.events.on_irc_message(
            IRCMessage("NICK", ("forced",), Prefix("alpha", "~alpha", "host")),
        )

        assert bot.events.nick_watch_task is not None
        bot.events.stop_nick_watch()

    async def test_other_user_nick_change_does_not_start_watch(self) -> None:
        """Ignore another user's nick change for this bot's identity and watch."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        identity = BotPresence("alpha", "host", "inst", "fallback", "~alpha")
        bot.identity.current = identity
        bot.identity.registered = True

        bot.events.on_irc_message(
            IRCMessage(
                "NICK",
                ("newnick",),
                Prefix("stranger", "user", "host"),
            ),
        )

        assert bot.identity.current is identity
        assert bot.events.nick_watch_task is None

    async def test_nick_change_away_skips_watch_before_registration(self) -> None:
        """Do not start a nick watch before registration completes."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "forced"

        bot.events.on_irc_message(
            IRCMessage("NICK", ("forced",), Prefix("alpha", "~alpha", "host")),
        )

        assert bot.events.nick_watch_task is None

    async def test_nick_reclaim_sends_monitor_unsubscribe(self) -> None:
        """Send MONITOR - when reclaiming a nick on a MONITOR-capable server."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "alpha"
        bot.caps.monitor = True

        bot.events.on_irc_message(
            IRCMessage("NICK", ("alpha",), Prefix("fallback", "~alpha", "host")),
        )

        assert ("MONITOR", ("-", "alpha")) in fake_irc.sent

    async def test_disconnect_stops_watch(self) -> None:
        """Stop the nick watch when IRC disconnects."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.events.start_nick_watch()
        poll = bot.events.nick_watch_task
        assert poll is not None

        bot.events.on_irc_disconnect()
        async with asyncio.timeout(5):
            await asyncio.gather(poll, return_exceptions=True)

        assert poll.cancelled()
        assert bot.events.nick_watch_task is None

    async def test_ison_poll_loop_polls_until_cancelled(self) -> None:
        """Keep polling ISON, even once the nick is ours, until the watch stops.

        A loop that ended on its own would leave nick_watch_task holding a
        finished task, so poll_ison would never start another.
        """
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        record = fake_irc.send
        polled_twice = asyncio.Event()

        def send_then_reclaim(
            command: str,
            *params: str,
            trailing: str | None = None,
        ) -> None:
            record(command, *params, trailing=trailing)
            fake_irc.current_nick = "alpha"
            if len(fake_irc.sent) == 2:
                polled_twice.set()

        with (
            patch("botnats.events.ISON_POLL_INTERVAL", 0),
            patch.object(fake_irc, "send", send_then_reclaim),
        ):
            poll = asyncio.create_task(bot.events.ison_poll_loop())
            async with asyncio.timeout(1):
                await polled_twice.wait()

            poll.cancel()
            async with asyncio.timeout(1):
                await asyncio.gather(poll, return_exceptions=True)

        assert poll.cancelled()
        assert fake_irc.sent[:2] == [("ISON", ("alpha",)), ("ISON", ("alpha",))]
