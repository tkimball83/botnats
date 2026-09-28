# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC event handling and server message processing."""

import asyncio
import time
import unittest
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats.auth import totp
from botnats.bot import Bot
from botnats.channel import ChannelRuntime, JoinState
from botnats.irc.client import DEFAULT_NICK_LENGTH
from botnats.irc.protocol import IRCMessage, ISupportState, Prefix, casefold
from botnats.presence import BotPresence
from tests.unit.helpers import (
    FailingPartIRC,
    FailingPublishCoordinator,
    FakeCoordinator,
    FakeIRC,
    bot_with_channel,
    bot_with_coordinator,
    bot_with_irc,
    config,
    drain_session_writes,
)

CUSTOM_ISUPPORT = IRCMessage(
    "005",
    (
        "alpha",
        "CASEMAPPING=ascii",
        "CHANMODES=b,k,l,imn",
        "MODES=6",
        "NICKLEN=12",
        "PREFIX=(yov)@%+",
        "supported",
    ),
)
UNSET_MODE = IRCMessage("MODE", ("#test", "-n"), Prefix("someone", "user", "host"))


class ServerTests(unittest.IsolatedAsyncioTestCase):
    """Tests for IRC server message handling and mode enforcement."""

    async def test_revocation_escalates_over_same_expiry_winner(self) -> None:
        """Escalate when the store winner shares the revocation's expiry."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = "owner!user@host.example"
        expires_at = time.time() + 600
        stale = bot.authorizer.create(prefix, expires_at, "alpha", 1, revoked=True)
        winner = bot.authorizer.create(prefix, expires_at, "alpha", 2)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(return_value=asdict(winner)),
        ):
            synced = await bot.sessions.sync(prefix, asdict(stale))

        assert not synced
        pending = bot.sessions.pending[casefold(prefix, "ascii")]
        assert pending["revoked"] is True
        assert pending["version"] == winner.version + 1
        assert not bot.authorizer.authorized(prefix)

    async def test_ban_list_records_mask(self) -> None:
        """Verify 367 numeric adds a ban mask to the channel."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]

        await bot.events.on_irc_message(
            IRCMessage(
                "367",
                ("alpha", "#test", "*!*@banned.host", "op", "1234567890"),
            ),
        )

        assert "*!*@banned.host" in runtime.bans.values()

    async def test_banned_requests_unban(self) -> None:
        """Verify 474 numeric triggers an unban request."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )

        await bot.events.on_irc_message(
            IRCMessage("474", ("alpha", "#test", "Cannot join channel (+b)")),
        )
        await asyncio.sleep(0)

        suffixes = [suffix for suffix, _ in coordinator.help_requests]
        assert suffixes == ["unban"]

    async def test_chghost_revokes_authorization(self) -> None:
        """Verify CHGHOST revokes the session and does not move it."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "old.host")
        new_user, new_host = "newuser", "new.host"
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("CHGHOST", (new_user, new_host), old_prefix),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        new_prefix = Prefix("owner", new_user, new_host)
        assert not bot.authorizer.authorized(new_prefix.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0][1]["revoked"] is True

    async def test_chghost_nick_only_prefix_revokes_via_member(self) -> None:
        """Revoke from the stored member identity on a nick-only CHGHOST."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "old.host")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("CHGHOST", ("newuser", "new.host"), Prefix("owner")),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0][1]["revoked"] is True

    async def test_chghost_queues_revocation_when_nats_unavailable(self) -> None:
        """Queue revocation as a pending session when put_session fails."""
        bot, _, _ = bot_with_coordinator(FailingPublishCoordinator())
        old_prefix = Prefix("owner", "user", "old.host")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("CHGHOST", ("newuser", "new.host"), old_prefix),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        pending = bot.sessions.pending
        assert len(pending) == 1
        session = next(iter(pending.values()))
        assert session["revoked"] is True

    async def test_chghost_without_identity_skips_revocation(self) -> None:
        """Log and skip revocation when no complete old identity exists."""
        bot, _, coordinator = bot_with_coordinator()

        with self.assertLogs("botnats.irc.events", level="DEBUG") as logs:
            await bot.events.on_irc_message(
                IRCMessage("CHGHOST", ("newuser", "new.host"), Prefix("owner")),
            )

        assert coordinator.session_puts == []
        assert any("no complete identity" in line for line in logs.output)

    async def test_chghost_updates_member_prefix(self) -> None:
        """Verify CHGHOST updates the member prefix in channel state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        old_prefix = Prefix("someone", "user", "old.host")
        runtime.member("someone").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("CHGHOST", ("newuser", "new.host"), old_prefix),
        )

        member = runtime.members.get(casefold("someone"))
        assert member is not None
        assert member.prefix == Prefix("someone", "newuser", "new.host")

    async def test_chghost_updates_self_identity(self) -> None:
        """Verify CHGHOST on the bot itself refreshes its identity."""
        bot, _ = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "old.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "old.host")

        await bot.events.on_irc_message(
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
                await bot.events.on_irc_message(
                    IRCMessage("PRIVMSG", ("alpha", "AUTH 000000"), prefix),
                )

            queued = len(bot.tasks)
            watched = bot.sessions.watched_identities[prefix.render()]
        await bot.tasks.drain()

        assert queued == 8
        assert watched == (8, False)

    async def test_non_commands_are_not_queued(self) -> None:
        """Skip channel chatter, CTCP, and anonymous senders before queueing."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        for message in (
            IRCMessage("PRIVMSG", ("#test", "STATUS"), prefix),
            IRCMessage("PRIVMSG", ("alpha", "\x01ACTION test\x01"), prefix),
            IRCMessage("PRIVMSG", ("alpha", "STATUS"), Prefix("owner")),
            IRCMessage("PRIVMSG", ("alpha", "STATUS")),
        ):
            await bot.events.on_irc_message(message)

        assert not bot.tasks
        assert not bot.sessions.watched_identities
        assert fake_irc.privmsgs == []

    async def test_end_of_names(self) -> None:
        """Verify end-of-names triggers WHO and ban list requests."""
        bot, fake_irc = bot_with_irc()

        await bot.events.on_irc_message(
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        )

        assert ("WHO", ("#test",)) in fake_irc.sent
        assert ("MODE", ("#test", "+b")) in fake_irc.sent

    async def test_names_and_who_record_only_operator_modes(self) -> None:
        """Track operator prefixes only; sub-op modes are never applied."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]

        await bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "+bob @carol")),
        )
        assert runtime.member("bob").modes == set()
        assert runtime.member("carol").modes == {"o"}

        await bot.events.on_irc_message(
            IRCMessage(
                "352",
                ("alpha", "#test", "user", "host", "srv", "bob", "H+"),
            ),
        )
        assert runtime.member("bob").modes == set()

    async def test_names_replaces_stale_modes(self) -> None:
        """Verify a NAMES reply without op prefix clears a prior op mode."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("carol").modes.add("o")

        await bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "carol")),
        )

        assert runtime.member("carol").modes == set()

    async def test_quit_with_host_only_prefix_removes_member(self) -> None:
        """Remove a member whose QUIT prefix omits the user part."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("owner")

        await bot.events.on_irc_message(
            IRCMessage("QUIT", (), Prefix.parse("owner@static.example")),
        )

        assert casefold("owner") not in runtime.members

    async def test_invite_ignores_joined_channel(self) -> None:
        """Verify an INVITE to an already-joined channel is ignored."""
        bot, fake_irc = bot_with_irc()
        bot.channel_mgr.channels[casefold("#test")].join = JoinState.JOINED

        await bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#test"), Prefix("op", "u", "h")),
        )

        assert ("JOIN", ("#test",)) not in fake_irc.sent

    async def test_invite_ignores_unknown_channel(self) -> None:
        """Verify an INVITE to an unconfigured channel is ignored."""
        bot, fake_irc = bot_with_irc()

        await bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#other"), Prefix("op", "u", "h")),
        )

        assert fake_irc.sent == []

    async def test_invite_joins_desired_channel(self) -> None:
        """Verify an INVITE to a desired unjoined channel triggers a join."""
        bot, fake_irc = bot_with_irc()

        await bot.events.on_irc_message(
            IRCMessage("INVITE", ("alpha", "#test"), Prefix("op", "u", "h")),
        )

        assert ("JOIN", ("#test",)) in fake_irc.sent

    async def test_isupport_chanmodes_extra_groups(self) -> None:
        """Verify CHANMODES with more than four groups keeps the first four."""
        bot, _ = bot_with_irc()

        await bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "CHANMODES=beI,k,l,imnst,X", "supported")),
        )

        assert bot.caps.chanmodes == ("beI", "k", "l", "imnst")

    async def test_isupport_parsing(self) -> None:
        """Verify ISUPPORT tokens update server capabilities."""
        bot, fake_irc = bot_with_irc()

        await bot.events.handle_isupport(CUSTOM_ISUPPORT)
        runtime = bot.channel_mgr.channels[bot.caps.fold("#test")]
        await bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "@alpha %other")),
        )

        assert bot.caps.casemapping == "ascii"
        assert bot.caps.fold("[") != bot.caps.fold("{")
        assert bot.caps.mode_limit == 6
        assert bot.caps.op_mode == "y"
        assert bot.channel_mgr.is_self_opped(runtime)
        assert fake_irc.casemapping == "ascii"
        assert fake_irc.nickname_length == 12

    async def test_isupport_removals_restore_defaults(self) -> None:
        """Restore default behavior when the server removes ISUPPORT values."""
        bot, fake_irc = bot_with_irc()
        await bot.events.handle_isupport(CUSTOM_ISUPPORT)

        await bot.events.handle_isupport(
            IRCMessage(
                "005",
                (
                    "alpha",
                    "-CASEMAPPING",
                    "-CHANMODES",
                    "-MODES",
                    "-NICKLEN",
                    "-PREFIX",
                    "supported",
                ),
            ),
        )

        assert bot.caps == ISupportState()
        assert fake_irc.casemapping == ISupportState().casemapping
        assert fake_irc.nickname_length == DEFAULT_NICK_LENGTH

    async def test_isupport_monitor_without_limit(self) -> None:
        """Use MONITOR whether or not the server advertises a target limit."""
        for token in ("MONITOR", "MONITOR=", "MONITOR=100"):
            with self.subTest(token=token):
                bot, fake_irc = bot_with_irc()
                fake_irc.current_nick = "fallback"

                await bot.events.handle_isupport(
                    IRCMessage("005", ("alpha", token, "are supported")),
                )
                await asyncio.gather(*bot.tasks)

                assert bot.caps.monitor
                assert ("MONITOR", ("+", "alpha")) in fake_irc.sent
                await bot.tasks.drain()

    async def test_isupport_without_trailing(self) -> None:
        """Verify the final ISUPPORT token is kept when trailing text is omitted."""
        bot, fake_irc = bot_with_irc()

        await bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "CASEMAPPING=ascii", "NICKLEN=12")),
        )

        assert bot.caps.casemapping == "ascii"
        assert fake_irc.nickname_length == 12

    async def test_higher_prefix_counts_as_opped(self) -> None:
        """Verify PREFIX modes above operator retain operator privileges."""
        bot, _ = bot_with_irc()

        await bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "PREFIX=(qao)~&@", "supported")),
        )
        await bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "~alpha")),
        )

        runtime = bot.channel_mgr.channels[bot.caps.fold("#test")]
        assert bot.channel_mgr.is_self_opped(runtime)

    async def test_higher_prefix_live_mode_updates(self) -> None:
        """Verify live MODE updates track privileges above operator."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[bot.caps.fold("#test")]
        runtime.member("alpha").modes.add("o")

        await bot.events.handle_isupport(
            IRCMessage("005", ("alpha", "PREFIX=(qao)~&@", "supported")),
        )
        await bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "+q", "Target"), Prefix("service")),
        )
        assert bot.caps.is_opped(runtime.member("Target").modes)

        await bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "-q", "Target"), Prefix("service")),
        )
        assert not bot.caps.is_opped(runtime.member("Target").modes)

    async def test_join_denied_requests_invite(self) -> None:
        """Verify invite-only, bad-key, and channel-full replies request an invite."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )

        for numeric in ("471", "473", "475"):
            bot.channel_mgr.channels[casefold("#test")].cooldowns.clear()
            await bot.events.on_irc_message(
                IRCMessage(numeric, ("alpha", "#test", "cannot join channel")),
            )
            await asyncio.sleep(0)

        suffixes = [suffix for suffix, _ in coordinator.help_requests]
        assert suffixes == ["invite", "invite", "invite"]

    async def test_mode_enforce_once_on_op_with_unset(self) -> None:
        """Verify one enforcement when a single MODE ops the bot and unsets."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+o-n", "alpha"),
                Prefix("someone", "user", "host"),
            ),
        )
        await asyncio.sleep(0)
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_mode_net_noop_triggers_nothing(self) -> None:
        """Verify a deop-reop MODE line sends no enforcement or peer request."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-o+o", "alpha", "alpha"),
                Prefix("someone", "user", "host"),
            ),
        )
        await asyncio.sleep(0)
        assert fake_irc.modes == []
        assert coordinator.help_requests == []

    async def test_mode_enforce_on_unset(self) -> None:
        """Verify channel modes are re-enforced when unset by another user."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        await bot.events.on_irc_message(UNSET_MODE)
        await asyncio.sleep(0)
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_mode_enforce_unset_mode_added(self) -> None:
        """Verify enforcement triggers when a negated mode is set by another user."""
        bot, fake_irc = bot_with_irc()
        bot.channel_mgr.mode_intent = (frozenset("np"), frozenset("s"))
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+s"),
                Prefix("someone", "user", "host"),
            ),
        )
        await asyncio.sleep(0)
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_mode_key_tracking(self) -> None:
        """Verify channel key is tracked on mode changes."""
        bot, _ = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        assert runtime.key is None

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+k", "secret"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.key == "secret"

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k", "*"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.key is None

    async def test_mode_key_unset_without_argument(self) -> None:
        """Clear the channel key when a server strips the -k argument."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.key = "secret"

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-k"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )

        assert runtime.key is None

        runtime.key = "secret"
        await bot.events.on_irc_message(
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
        bot.identity.registered = True
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        fake_irc.current_nick = "newalpha"

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newalpha",), Prefix.parse("alpha")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.nick == "newalpha"
        assert bot.identity.current.host == "host.example"

    async def test_nick_only_prefix_revokes_session_via_member(self) -> None:
        """Revoke the stored member identity's session on a bare NICK."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newowner",), Prefix("owner")),
        )
        await drain_session_writes(bot)

        new_prefix = Prefix("newowner", "user", "host.example")
        assert not bot.authorizer.authorized(new_prefix.render())
        assert not bot.authorizer.authorized(old_prefix.render())
        assert [put[0] for put in coordinator.session_puts] == [old_prefix.render()]

    async def test_mode_key_unusable(self) -> None:
        """Verify unusable channel key is ignored and not republished."""
        coordinator = FakeCoordinator()
        bot, _ = bot_with_irc(coordinator=coordinator)
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.key = "old-key"

        with self.assertLogs("botnats.irc.events", level="WARNING"):
            await bot.events.on_irc_message(
                IRCMessage(
                    "MODE",
                    ("#test", "+k", "bad key"),
                    Prefix("chanserv", "service", "services.host"),
                ),
            )
            await asyncio.sleep(0)

        # An unusable +k is ignored: the existing key is retained and nothing
        # is republished cluster-wide.
        assert runtime.key == "old-key"
        assert coordinator.channel_puts == []

    async def test_channel_modes_from_324(self) -> None:
        """Verify RPL_CHANNELMODEIS populates the runtime mode string."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED

        await bot.events.on_irc_message(
            IRCMessage("324", ("alpha", "#test", "+nstk", "secret"), None),
        )
        assert runtime.modes == "+nstk"

    async def test_channel_modes_updated_on_change(self) -> None:
        """Verify MODE changes update the tracked channel mode string."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+nst"

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+i"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == "+nsti"

        await bot.events.on_irc_message(
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
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+nstk"

        await bot.events.on_irc_message(
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
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.modes = "+n"

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "-n"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        assert runtime.modes == ""

    async def test_channel_modes_reset_on_disconnect(self) -> None:
        """Verify channel modes are cleared on reset."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.modes = "+nst"

        runtime.reset()
        assert runtime.modes == ""

    async def test_mode_no_enforce_when_not_opped(self) -> None:
        """Verify mode enforcement is skipped when bot is not opped."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        await bot.events.on_irc_message(UNSET_MODE)
        await asyncio.sleep(0)
        assert fake_irc.modes == []

    async def test_modes_are_isolated_across_channels(self) -> None:
        """Verify modes, bans, keys, and members change on only one channel."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        first = bot.channel_mgr.runtime("#test")
        assert first is not None
        first.join = JoinState.JOINED
        first.member("alpha").modes.add("o")
        first.member("Target").prefix = Prefix("Target", "user", "first.host")

        second = ChannelRuntime(
            channel="#other",
            join=JoinState.JOINED,
            key="second-key",
        )
        second.add_ban("*!*@second.host")
        second.member("alpha").modes.add("o")
        second.member("Target").modes.add("v")
        bot.channel_mgr.channels[casefold("#other")] = second

        await bot.events.on_irc_message(
            IRCMessage(
                "MODE",
                ("#test", "+obk", "Target", "*!*@first.host", "first-key"),
                Prefix("chanserv", "service", "services.host"),
            ),
        )
        await asyncio.sleep(0)

        assert first.member("Target").modes == {"o"}
        assert set(first.bans.values()) == {"*!*@first.host"}
        assert first.key == "first-key"
        assert second.member("Target").modes == {"v"}
        assert set(second.bans.values()) == {"*!*@second.host"}
        assert second.key == "second-key"
        assert len(coordinator.channel_puts) == 1
        _, payload = coordinator.channel_puts[0]
        assert payload["channel"] == "#test"
        assert payload["key"] == "first-key"
        assert payload["present"] is True
        assert fake_irc.modes == []

    async def test_modes_enforced_on_multiple_channels(self) -> None:
        """Verify mode enforcement is independently triggered for each channel."""
        bot, fake_irc = bot_with_irc()
        first = bot.channel_mgr.runtime("#test")
        assert first is not None
        first.member("alpha").modes.add("o")
        second = ChannelRuntime(channel="#other", join=JoinState.JOINED)
        second.member("alpha").modes.add("o")
        bot.channel_mgr.channels[casefold("#other")] = second

        for channel in ("#test", "#other"):
            await bot.events.on_irc_message(
                IRCMessage("366", ("alpha", channel, "End of /NAMES list")),
            )

        await asyncio.sleep(0)

        assert fake_irc.modes == [
            ("#test", "+b", ()),
            ("#other", "+b", ()),
            ("#test", "+npst", ()),
            ("#other", "+npst", ()),
        ]

    async def test_nick_change(self) -> None:
        """Verify nick change updates identity and channel member tracking."""
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "host.example", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        fake_irc.current_nick = "NewNick"

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("NewNick",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.nick == "NewNick"
        assert casefold("NewNick") in runtime.members
        assert casefold("alpha") not in runtime.members

    async def test_nick_change_requires_new_authentication(self) -> None:
        """Revoke the session on NICK; the new nick must authenticate again."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        new_prefix = Prefix("newowner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newowner",), old_prefix),
        )
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(old_prefix.render())
        assert not bot.authorizer.authorized(new_prefix.render())
        assert [put[1]["revoked"] for put in coordinator.session_puts] == [True]

    async def test_other_kick_preserves_state(self) -> None:
        """Verify kick of another user preserves channel state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("victim").prefix = Prefix("victim", "user", "host")

        await bot.events.on_irc_message(
            IRCMessage(
                "KICK",
                ("#test", "victim", "reason"),
                Prefix("someone", "user", "host"),
            ),
        )

        assert runtime.joined
        assert "*!*@old.ban" in runtime.bans.values()
        assert casefold("alpha") in runtime.members
        assert casefold("victim") not in runtime.members

    async def test_quit_does_not_wait_for_durable_write(self) -> None:
        """Revoke locally at once while the durable write runs in background."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())
        release = asyncio.Event()

        async def slow_put(
            identity: str, session: dict[str, object]
        ) -> dict[str, object]:
            del identity
            await release.wait()
            return session

        with patch.object(coordinator, "put_session", AsyncMock(side_effect=slow_put)):
            async with asyncio.timeout(1):
                await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.sessions.pending
            release.set()
            await drain_session_writes(bot)

        assert not bot.sessions.pending

    async def test_revocation_queued_during_write_is_kept(self) -> None:
        """Keep a revocation queued while an older write for the identity runs."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        session = bot.authorizer.grant(prefix.render())
        writing = asyncio.Event()
        release = asyncio.Event()
        written: list[dict[str, object]] = []

        async def slow_put(
            identity: str, record: dict[str, object]
        ) -> dict[str, object]:
            del identity
            if not record["revoked"]:
                writing.set()
                await release.wait()

            written.append(record)
            return record

        with patch.object(coordinator, "put_session", AsyncMock(side_effect=slow_put)):
            grant = asyncio.create_task(
                bot.sessions.sync(prefix.render(), asdict(session)),
            )
            async with asyncio.timeout(1):
                await writing.wait()
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            release.set()
            await grant
            await drain_session_writes(bot)

        assert [record["revoked"] for record in written] == [False, True]
        assert not bot.sessions.pending

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
            async with asyncio.timeout(1):
                for text in ("SLOW", "FAST"):
                    await bot.events.on_irc_message(
                        IRCMessage("PRIVMSG", ("alpha", text), owner),
                    )

            await asyncio.sleep(0)
            assert finished == []
            release.set()
            await asyncio.gather(*bot.tasks)

        assert finished == ["SLOW", "FAST"]

    async def test_quit_invalidates_queued_auth(self) -> None:
        """Refuse an AUTH that was still queued behind another command at QUIT."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        owner = Prefix("owner", "user", "host.example")
        release = asyncio.Event()
        code = totp(bot.authorizer.secret, int(time.time() // 30))

        async def slow_status(prefix: Prefix, arguments: tuple[str, ...]) -> None:
            del prefix, arguments
            await release.wait()

        bot.authorizer.grant(owner.render())
        with patch.dict(bot.commands.handlers, {"STATUS": slow_status}):
            for text in ("STATUS", f"AUTH {code}"):
                await bot.events.on_irc_message(
                    IRCMessage("PRIVMSG", ("alpha", text), owner),
                )

            await asyncio.sleep(0)
            # The AUTH waits behind STATUS when the user quits.
            await bot.events.on_irc_message(IRCMessage("QUIT", (), owner))
            release.set()
            await asyncio.gather(*bot.tasks)

        assert not bot.authorizer.authorized(owner.render())
        assert ("owner", "Authorized") not in fake_irc.privmsgs
        assert not bot.sessions.watched_identities

    async def test_quit_revokes_authorization(self) -> None:
        """Verify QUIT destroys the session bound to that IRC connection."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(prefix.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0][1]["revoked"] is True

    async def test_revocation_retries_authoritative_active_winner(self) -> None:
        """Revoke a newer active session returned by the durable store."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        active = bot.authorizer.grant(prefix.render())
        winner = bot.authorizer.create(
            prefix.render(),
            active.expires_at + 1,
            "beta",
            active.version,
        )
        attempts: list[dict[str, object]] = []

        async def put_session(
            identity: str,
            session: dict[str, object],
        ) -> dict[str, object]:
            del identity
            attempts.append(session)
            return asdict(winner) if len(attempts) == 1 else session

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ):
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.sessions.pending
            await bot.sessions.retry()

        assert len(attempts) == 2
        assert attempts[-1]["revoked"] is True
        assert attempts[-1]["version"] == winner.version + 1
        assert not bot.sessions.pending

    async def test_revocation_retries_failed_publish(self) -> None:
        """Retry a session revocation after JetStream recovers."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=NatsError("unavailable")),
        ) as put:
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert bot.sessions.pending
            put.side_effect = None
            put.return_value = next(iter(bot.sessions.pending.values()))
            await bot.sessions.retry()

        assert not bot.sessions.pending
        assert put.await_count == 2

    async def test_duplicate_coordinator_queues_session_writes(self) -> None:
        """Queue session writes while the coordinator reports a duplicate ID."""
        bot, _, coordinator = bot_with_coordinator()
        coordinator.unique = False

        assert not await bot.sessions.sync("a!u@h", {"revoked": False})

        assert bot.sessions.pending
        assert not coordinator.session_puts

    async def test_pending_revocation_blocks_later_session_writes(self) -> None:
        """Never write a queued grant past an earlier still-pending revocation."""
        bot, _, coordinator = bot_with_coordinator()
        blocked = asdict(
            bot.authorizer.create(
                "old!user@host.example",
                time.time() + 100,
                bot.authorizer.issuer,
                1,
                revoked=True,
            ),
        )
        identity = "new!user@host.example"
        session = asdict(
            bot.authorizer.create(
                identity,
                time.time() + 100,
                bot.authorizer.issuer,
                1,
            ),
        )

        async def put_session(
            stored_identity: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            del stored_identity
            if payload is blocked:
                msg = "unavailable"
                raise NatsError(msg)

            return payload

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            assert not await bot.sessions.sync("old!user@host.example", blocked)
            assert not await bot.sessions.sync(identity, session)

        assert put.await_count == 2
        assert all(call.args[1] is blocked for call in put.await_args_list)
        assert casefold(identity, "ascii") in bot.sessions.pending

    async def test_expired_revocation_drains_from_pending_queue(self) -> None:
        """Drop a pending revocation once its durable record has expired."""
        bot, _, coordinator = bot_with_coordinator()
        revocation = asdict(
            bot.authorizer.create(
                "old!user@host.example",
                time.time() - 1,
                bot.authorizer.issuer,
                1,
                revoked=True,
            ),
        )
        identity = "new!user@host.example"
        session = asdict(
            bot.authorizer.create(
                identity,
                time.time() + 100,
                bot.authorizer.issuer,
                1,
            ),
        )

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=[NatsError("unavailable"), revocation, session]),
        ):
            assert not await bot.sessions.sync(
                "old!user@host.example",
                revocation,
            )
            assert bot.sessions.pending
            assert await bot.sessions.sync(identity, session)

        assert not bot.sessions.pending
        assert bot.authorizer.authorized(identity)

    async def test_new_session_replaces_pending_revocation(self) -> None:
        """Never retry an old revocation after a newer session write succeeds."""
        bot, _, coordinator = bot_with_coordinator()
        old_identity = "Owner!user@host.example"
        identity = old_identity.casefold()
        expires_at = time.time() + 100
        session = asdict(
            bot.authorizer.create(
                identity,
                expires_at,
                bot.authorizer.issuer,
                2,
            ),
        )
        revocation = asdict(
            bot.authorizer.create(
                old_identity,
                expires_at,
                bot.authorizer.issuer,
                1,
                revoked=True,
            ),
        )

        async def put_session(
            stored_identity: str,
            payload: dict[str, object],
        ) -> dict[str, object]:
            if payload.get("revoked") is True:
                msg = "unavailable"
                raise NatsError(msg)

            coordinator.session_puts.append((stored_identity, payload))
            return payload

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            assert not await bot.sessions.sync(old_identity, revocation)
            assert await bot.sessions.sync(identity, session)
            await bot.sessions.retry()

        assert put.await_count == 2
        assert coordinator.session_puts == [(identity, session)]
        assert not bot.sessions.pending

    async def test_session_write_applies_authoritative_winner(self) -> None:
        """Converge local authorization when a newer durable mutation wins."""
        bot, _, coordinator = bot_with_coordinator()
        identity = "owner!user@host.example"
        active = bot.authorizer.grant(identity)
        winner = bot.authorizer.create(
            identity,
            active.expires_at,
            active.issuer,
            active.version + 1,
            revoked=True,
        )
        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(return_value=asdict(winner)),
        ):
            assert await bot.sessions.sync(identity, asdict(active))

        assert not bot.authorizer.authorized(identity)

    async def test_self_join_clears_state(self) -> None:
        """Verify self-join resets channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("stale").prefix = Prefix("stale", "user", "host")

        await bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert runtime.joined
        assert runtime.bans == {}
        assert casefold("stale") not in runtime.members
        assert casefold("alpha") in runtime.members

    async def test_self_join_orphaned(self) -> None:
        """Verify self-join to undesired channel triggers immediate part."""
        bot, fake_irc = bot_with_irc()
        bot.channel_mgr.channels.pop(casefold("#test"))

        await bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert casefold("#test") not in bot.channel_mgr.channels
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_self_join_orphaned_queued(self) -> None:
        """Verify orphaned self-join queues part when send fails."""
        bot = bot_with_channel(irc=FailingPartIRC())
        bot.channel_mgr.channels.pop(casefold("#test"))

        await bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert "#test" in bot.channel_mgr.pending_parts

    async def test_self_kick_clears_state(self) -> None:
        """Verify self-kick clears channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("other").prefix = Prefix("other", "user", "host")

        await bot.events.on_irc_message(
            IRCMessage(
                "KICK",
                ("#test", "alpha", "reason"),
                Prefix("someone", "user", "host"),
            ),
        )

        assert not runtime.joined
        assert runtime.bans == {}
        assert runtime.members == {}

    async def test_self_part_clears_state(self) -> None:
        """Verify self-part clears channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.add_ban("*!*@old.ban")
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        runtime.member("other").prefix = Prefix("other", "user", "host")

        await bot.events.on_irc_message(
            IRCMessage("PART", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert not runtime.joined
        assert runtime.bans == {}
        assert runtime.members == {}

    async def test_userhost_identity(self) -> None:
        """Verify USERHOST reply sets bot identity."""
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)

        await bot.events.on_irc_message(
            IRCMessage("302", ("alpha", "alpha=+~user@real.host")),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.user == "~user"
        assert bot.identity.current.host == "real.host"

    async def test_who_reply_updates_member(self) -> None:
        """Verify 352 numeric updates member prefix and modes."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("someone")

        await bot.events.on_irc_message(
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

        member = runtime.members.get(casefold("someone"))
        assert member is not None
        assert member.prefix == Prefix("someone", "user", "host.example")
        assert "o" in member.modes

    async def test_whois_sets_identity(self) -> None:
        """Verify 311 numeric sets the bot's identity."""
        bot = Bot(config(), irc=FakeIRC())

        await bot.events.on_irc_message(
            IRCMessage(
                "311",
                ("alpha", "alpha", "~user", "real.host", "*", "realname"),
            ),
        )

        assert bot.identity.current is not None
        assert bot.identity.current.user == "~user"
        assert bot.identity.current.host == "real.host"


class NickWatchTests(unittest.IsolatedAsyncioTestCase):
    """Tests for ISON and MONITOR nickname reclaim."""

    async def test_ison_reply_reclaims_nick(self) -> None:
        """Reclaim the desired nickname when ISON reports it offline."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        await bot.events.on_irc_message(
            IRCMessage("303", ("alpha", "")),
        )

        assert ("NICK", ("alpha",)) in fake_irc.sent

    async def test_ison_reply_skips_when_nick_online(self) -> None:
        """Do not reclaim when ISON reports the desired nick is still taken."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        await bot.events.on_irc_message(
            IRCMessage("303", ("fallback", "alpha")),
        )

        assert ("NICK", ("alpha",)) not in fake_irc.sent

    async def test_monitor_offline_reclaims_nick(self) -> None:
        """Reclaim the desired nickname when MONITOR reports it offline."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.caps.monitor = True

        await bot.events.on_irc_message(
            IRCMessage("731", ("fallback", "alpha!user@host")),
        )

        assert ("NICK", ("alpha",)) in fake_irc.sent

    async def test_monitor_offline_ignores_unrelated_nick(self) -> None:
        """Ignore MONITOR offline for nicks other than the desired one."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.caps.monitor = True

        await bot.events.on_irc_message(
            IRCMessage("731", ("fallback", "stranger!user@host")),
        )

        assert ("NICK", ("alpha",)) not in fake_irc.sent

    async def test_welcome_starts_ison_poll(self) -> None:
        """Start ISON polling when registered with a fallback nick."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"

        await bot.events.on_irc_message(
            IRCMessage("001", ("fallback", "Welcome")),
        )

        assert bot.events.nick_watch_task is not None
        bot.events.stop_nick_watch()

    async def test_welcome_skips_watch_when_nick_matches(self) -> None:
        """Skip nick watch when registered with the desired nick."""
        bot, _ = bot_with_irc()

        await bot.events.on_irc_message(
            IRCMessage("001", ("alpha", "Welcome")),
        )

        assert bot.events.nick_watch_task is None

    async def test_isupport_monitor_upgrades_to_monitor(self) -> None:
        """Upgrade from ISON polling to MONITOR when ISUPPORT advertises it."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.identity.registered = True
        bot.events.start_nick_watch()
        assert bot.events.nick_watch_task is not None

        await bot.events.on_irc_message(
            IRCMessage("005", ("fallback", "MONITOR=100", "supported")),
        )
        await asyncio.sleep(0)

        assert bot.events.nick_watch_task is None
        assert ("MONITOR", ("+", "alpha")) in fake_irc.sent

    async def test_nick_reclaim_stops_ison_watch(self) -> None:
        """Stop the ISON poll when the bot reclaims its desired nickname."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.identity.registered = True
        bot.events.start_nick_watch()
        assert bot.events.nick_watch_task is not None

        fake_irc.current_nick = "alpha"
        await bot.events.on_irc_message(
            IRCMessage("NICK", ("alpha",), Prefix("fallback", "~alpha", "host")),
        )

        assert bot.events.nick_watch_task is None

    async def test_nick_change_away_starts_watch(self) -> None:
        """Start a nick watch when the bot's nick changes away from desired."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "forced"
        bot.identity.registered = True

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("forced",), Prefix("alpha", "~alpha", "host")),
        )

        assert bot.events.nick_watch_task is not None
        bot.events.stop_nick_watch()

    async def test_other_user_nick_change_does_not_start_watch(self) -> None:
        """Ignore nick changes from other users for watch lifecycle."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.identity.registered = True

        await bot.events.on_irc_message(
            IRCMessage(
                "NICK",
                ("newnick",),
                Prefix("stranger", "user", "host"),
            ),
        )

        assert bot.events.nick_watch_task is None

    async def test_nick_change_away_skips_watch_before_registration(self) -> None:
        """Do not start a nick watch before registration completes."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "forced"

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("forced",), Prefix("alpha", "~alpha", "host")),
        )

        assert bot.events.nick_watch_task is None

    async def test_nick_reclaim_sends_monitor_unsubscribe(self) -> None:
        """Send MONITOR - when reclaiming a nick on a MONITOR-capable server."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "alpha"
        bot.caps.monitor = True

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("alpha",), Prefix("fallback", "~alpha", "host")),
        )

        assert ("MONITOR", ("-", "alpha")) in fake_irc.sent

    async def test_disconnect_stops_watch(self) -> None:
        """Stop the nick watch when IRC disconnects."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        bot.identity.registered = True
        bot.events.start_nick_watch()
        assert bot.events.nick_watch_task is not None

        bot.on_irc_disconnect()

        assert bot.events.nick_watch_task is None

    async def test_ison_poll_loop_polls_until_nick_reclaimed(self) -> None:
        """Poll ISON for the desired nick, and stop once it is reclaimed."""
        bot, fake_irc = bot_with_irc()
        fake_irc.current_nick = "fallback"
        record = fake_irc.send

        async def send_then_reclaim(
            command: str,
            *params: str,
            trailing: str | None = None,
        ) -> None:
            await record(command, *params, trailing=trailing)
            fake_irc.current_nick = "alpha"

        with (
            patch("botnats.irc.events.ISON_POLL_INTERVAL", 0),
            patch.object(fake_irc, "send", send_then_reclaim),
        ):
            async with asyncio.timeout(1):
                await bot.events.ison_poll_loop()

        assert fake_irc.sent == [("ISON", ("alpha",))]
