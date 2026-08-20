# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC event handling and server message processing."""

import asyncio
import time
import unittest
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats.bot import Bot
from botnats.channel import ChannelRuntime
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


def fail_first_revocation(attempts: list[tuple[str, bool]]) -> AsyncMock:
    """Build a session writer that fails its first revocation."""
    failed = False

    async def put_session(
        identity: str,
        session: dict[str, object],
    ) -> dict[str, object]:
        nonlocal failed
        revoked = session.get("revoked") is True
        attempts.append((identity, revoked))
        if revoked and not failed:
            failed = True
            message = "unavailable"
            raise NatsError(message)
        return session

    return AsyncMock(side_effect=put_session)


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
            synced = await bot.events.sync_session(prefix, asdict(stale))

        assert not synced
        pending = bot.events.pending_sessions[casefold(prefix, "ascii")]
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
        bot.identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")

        await bot.events.on_irc_message(
            IRCMessage("474", ("alpha", "#test", "Cannot join channel (+b)")),
        )
        await asyncio.sleep(0)

        suffixes = [suffix for suffix, _ in coordinator.offer_requests]
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

        assert not bot.authorizer.authorized(old_prefix.render())
        assert len(coordinator.session_puts) == 1
        assert coordinator.session_puts[0][1]["revoked"] is True

    async def test_chghost_queues_revocation_when_nats_unavailable(self) -> None:
        """Queue revocation as a pending session when put_session fails."""
        bot, _, _ = bot_with_coordinator()
        bot.coordinator = FailingPublishCoordinator()
        old_prefix = Prefix("owner", "user", "old.host")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("CHGHOST", ("newuser", "new.host"), old_prefix),
        )

        assert not bot.authorizer.authorized(old_prefix.render())
        pending = bot.events.pending_sessions
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
        bot.identity = BotPresence("alpha", "old.host", "inst", "alpha", "~alpha")
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "old.host")

        await bot.events.on_irc_message(
            IRCMessage(
                "CHGHOST",
                ("newuser", "new.host"),
                Prefix("alpha", "~alpha", "old.host"),
            ),
        )

        assert bot.identity is not None
        assert bot.identity.user == "newuser"
        assert bot.identity.host == "new.host"

    async def test_ctcp_ignored(self) -> None:
        """Verify CTCP messages are silently ignored."""
        bot = Bot(config())
        fake_irc = FakeIRC()
        bot.irc = fake_irc
        prefix = Prefix("owner", "user", "host.example")

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "\x01ACTION test\x01"), prefix),
        )

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
        bot.channel_mgr.channels[casefold("#test")].joined = True

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
        runtime = bot.channel_mgr.channels[bot.fold("#test")]
        await bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "@alpha %other")),
        )

        assert bot.caps.casemapping == "ascii"
        assert bot.fold("[") != bot.fold("{")
        assert bot.caps.mode_limit == 6
        assert bot.caps.op_mode == "y"
        assert bot.is_self_opped(runtime)
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

        runtime = bot.channel_mgr.channels[bot.fold("#test")]
        assert bot.is_self_opped(runtime)

    async def test_higher_prefix_live_mode_updates(self) -> None:
        """Verify live MODE updates track privileges above operator."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[bot.fold("#test")]
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
        bot.identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")

        for numeric in ("471", "473", "475"):
            bot.channel_mgr.cooldowns.clear()
            await bot.events.on_irc_message(
                IRCMessage(numeric, ("alpha", "#test", "cannot join channel")),
            )
            await asyncio.sleep(0)

        suffixes = [suffix for suffix, _ in coordinator.offer_requests]
        assert suffixes == ["invite", "invite", "invite"]

    async def test_mode_enforce_once_on_op_with_unset(self) -> None:
        """Verify one enforcement when a single MODE ops the bot and unsets."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.joined = True

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
        bot.identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.joined = True
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
        assert coordinator.offer_requests == []

    async def test_mode_enforce_on_unset(self) -> None:
        """Verify channel modes are re-enforced when unset by another user."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.joined = True
        runtime.member("alpha").modes.add("o")

        await bot.events.on_irc_message(UNSET_MODE)
        await asyncio.sleep(0)
        assert fake_irc.modes == [("#test", "+npst", ())]

    async def test_mode_enforce_unset_mode_added(self) -> None:
        """Verify enforcement triggers when a negated mode is set by another user."""
        bot, fake_irc = bot_with_irc()
        bot.events.enforced_set = frozenset("np")
        bot.events.enforced_unset = frozenset("s")
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.joined = True
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
        runtime.joined = True

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
        runtime.joined = True
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
        bot.registered = True
        bot.identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")
        fake_irc.current_nick = "newalpha"

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newalpha",), Prefix.parse("alpha")),
        )

        assert bot.identity is not None
        assert bot.identity.nick == "newalpha"
        assert bot.identity.host == "host.example"

    async def test_nick_only_prefix_moves_session_via_member(self) -> None:
        """Move the session using the stored member identity on a bare NICK."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newowner",), Prefix("owner")),
        )

        new_prefix = Prefix("newowner", "user", "host.example")
        assert bot.authorizer.authorized(new_prefix.render())
        assert not bot.authorizer.authorized(old_prefix.render())
        assert len(coordinator.session_puts) == 2

    async def test_mode_key_unusable(self) -> None:
        """Verify unusable channel key is ignored and not republished."""
        bot, _ = bot_with_irc()
        coordinator = FakeCoordinator()
        bot.coordinator = coordinator
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.key = "old-key"

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

    async def test_mode_no_enforce_when_not_opped(self) -> None:
        """Verify mode enforcement is skipped when bot is not opped."""
        bot, fake_irc = bot_with_irc()
        folded = casefold("#test")
        runtime = bot.channel_mgr.channels[folded]
        runtime.joined = True

        await bot.events.on_irc_message(UNSET_MODE)
        await asyncio.sleep(0)
        assert fake_irc.modes == []

    async def test_modes_are_isolated_across_channels(self) -> None:
        """Verify modes, bans, keys, and members change on only one channel."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        first = bot.runtime("#test")
        assert first is not None
        first.joined = True
        first.member("alpha").modes.add("o")
        first.member("Target").prefix = Prefix("Target", "user", "first.host")

        second = ChannelRuntime(joined=True, key="second-key")
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
        first = bot.runtime("#test")
        assert first is not None
        first.member("alpha").modes.add("o")
        second = ChannelRuntime(joined=True)
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
        bot.identity = BotPresence("alpha", "host.example", "inst", "alpha", "~alpha")
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "host.example")
        fake_irc.current_nick = "NewNick"

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("NewNick",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert bot.identity is not None
        assert bot.identity.nick == "NewNick"
        assert casefold("NewNick") in runtime.members
        assert casefold("alpha") not in runtime.members

    async def test_nick_change_moves_authorization(self) -> None:
        """Verify an observed nick change moves the active authorization session."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        new_prefix = Prefix("newowner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())
        bot.channel_mgr.channels[casefold("#test")].member("owner").prefix = old_prefix

        await bot.events.on_irc_message(
            IRCMessage("NICK", ("newowner",), old_prefix),
        )

        assert not bot.authorizer.authorized(old_prefix.render())
        assert bot.authorizer.authorized(new_prefix.render())
        assert len(coordinator.session_puts) == 2
        assert coordinator.session_puts[0][1]["revoked"] is True

    async def test_nick_change_waits_for_durable_revocation(self) -> None:
        """Do not publish the moved session before revoking the old identity."""
        bot, _, coordinator = bot_with_coordinator()
        old_prefix = Prefix("owner", "user", "host.example")
        new_prefix = Prefix("newowner", "user", "host.example")
        bot.authorizer.grant(old_prefix.render())
        attempts: list[tuple[str, bool]] = []

        with patch.object(
            coordinator,
            "put_session",
            fail_first_revocation(attempts),
        ):
            await bot.events.on_irc_message(
                IRCMessage("NICK", (new_prefix.nick,), old_prefix),
            )
            assert attempts == [(old_prefix.render().casefold(), True)]
            assert len(bot.events.pending_sessions) == 2
            await bot.events.retry_pending_sessions()

        assert attempts == [
            (old_prefix.render().casefold(), True),
            (old_prefix.render().casefold(), True),
            (new_prefix.render().casefold(), False),
        ]
        assert not bot.events.pending_sessions

    async def test_repeated_nick_change_preserves_revocation_order(self) -> None:
        """Keep repeated moves behind the first durable revocation."""
        bot, _, coordinator = bot_with_coordinator()
        first = Prefix("owner", "user", "host.example")
        second = Prefix("owner2", "user", "host.example")
        third = Prefix("owner3", "user", "host.example")
        bot.authorizer.grant(first.render())
        attempts: list[tuple[str, bool]] = []

        with patch.object(
            coordinator,
            "put_session",
            fail_first_revocation(attempts),
        ):
            await bot.events.on_irc_message(
                IRCMessage("NICK", (second.nick,), first),
            )
            await bot.events.on_irc_message(
                IRCMessage("NICK", (third.nick,), second),
            )

        assert attempts == [
            (first.render().casefold(), True),
            (first.render().casefold(), True),
            (second.render().casefold(), True),
            (third.render().casefold(), False),
        ]
        assert not bot.events.pending_sessions

    async def test_other_kick_preserves_state(self) -> None:
        """Verify kick of another user preserves channel state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
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

    async def test_quit_revokes_authorization(self) -> None:
        """Verify QUIT destroys the session bound to that IRC connection."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))

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
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.events.pending_sessions
            await bot.events.retry_pending_sessions()

        assert len(attempts) == 2
        assert attempts[-1]["revoked"] is True
        assert attempts[-1]["version"] == winner.version + 1
        assert not bot.events.pending_sessions

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
            assert bot.events.pending_sessions
            put.side_effect = None
            put.return_value = next(iter(bot.events.pending_sessions.values()))
            await bot.events.retry_pending_sessions()

        assert not bot.events.pending_sessions
        assert put.await_count == 2

    async def test_duplicate_coordinator_queues_session_writes(self) -> None:
        """Queue session writes while the coordinator reports a duplicate ID."""
        bot, _, coordinator = bot_with_coordinator()
        coordinator.unique = False

        assert not await bot.events.sync_session("a!u@h", {"revoked": False})

        assert bot.events.pending_sessions
        assert not coordinator.session_puts

    async def test_requeued_identity_moves_to_queue_tail(self) -> None:
        """Keep the pending queue in causal order when an identity re-queues."""
        bot, _, coordinator = bot_with_coordinator()

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=NatsError("unavailable")),
        ):
            assert not await bot.events.sync_session("b!u@h", {"revoked": False})
            assert not await bot.events.sync_session("a!u@h", {"revoked": True})
            assert not await bot.events.sync_session("b!u@h", {"revoked": False})

        assert list(bot.events.pending_sessions) == ["a!u@h", "b!u@h"]

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
            assert not await bot.events.sync_session("old!user@host.example", blocked)
            assert not await bot.events.sync_session(identity, session)

        assert put.await_count == 2
        assert all(call.args[1] is blocked for call in put.await_args_list)
        assert casefold(identity, "ascii") in bot.events.pending_sessions

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
            assert not await bot.events.sync_session(
                "old!user@host.example",
                revocation,
            )
            assert bot.events.pending_sessions
            assert await bot.events.sync_session(identity, session)

        assert not bot.events.pending_sessions
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
            assert not await bot.events.sync_session(old_identity, revocation)
            assert await bot.events.sync_session(identity, session)
            await bot.events.retry_pending_sessions()

        assert put.await_count == 2
        assert coordinator.session_puts == [(identity, session)]
        assert not bot.events.pending_sessions

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
            assert await bot.events.sync_session(identity, asdict(active))
        assert not bot.authorizer.authorized(identity)

    async def test_self_join_clears_state(self) -> None:
        """Verify self-join resets channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
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
        bot = bot_with_channel()
        bot.irc = FailingPartIRC()
        bot.channel_mgr.channels.pop(casefold("#test"))

        await bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "host.example")),
        )

        assert "#test" in bot.channel_mgr.pending_parts

    async def test_self_kick_clears_state(self) -> None:
        """Verify self-kick clears channel runtime state."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
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
        runtime.joined = True
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
        bot = Bot(config())
        fake_irc = FakeIRC()
        bot.irc = fake_irc

        await bot.events.on_irc_message(
            IRCMessage("302", ("alpha", "alpha=+~user@real.host")),
        )

        assert bot.identity is not None
        assert bot.identity.user == "~user"
        assert bot.identity.host == "real.host"

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
        bot = Bot(config())
        bot.irc = FakeIRC()

        await bot.events.on_irc_message(
            IRCMessage(
                "311",
                ("alpha", "alpha", "~user", "real.host", "*", "realname"),
            ),
        )

        assert bot.identity is not None
        assert bot.identity.user == "~user"
        assert bot.identity.host == "real.host"
