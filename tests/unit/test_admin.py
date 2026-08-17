# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for administrative IRC commands and authorization."""

import time
import unittest
from unittest.mock import AsyncMock, patch

from botnats.admin import totp
from botnats.irc.protocol import IRCMessage, Prefix, casefold
from botnats.presence import BotPresence
from tests.unit.helpers import (
    FailingIRC,
    FailingPublishCoordinator,
    bot_with_coordinator,
    bot_with_irc,
)

OWNER = Prefix("owner", "user", "real.host")


class AdminTests(unittest.IsolatedAsyncioTestCase):
    """Tests for admin ban, op, deop, invite, and status commands."""

    async def test_admin_ban(self) -> None:
        """Verify BAN command sets a channel mode when bot is opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "BAN #test *!*@bad.host"), OWNER),
        )

        assert fake_irc.modes == [("#test", "+b", ("*!*@bad.host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Banned *!*@bad.host on #test"),
        ]

    async def test_admin_ban_not_opped(self) -> None:
        """Verify BAN command reports when bot is not opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "BAN #test *!*@bad.host"), OWNER),
        )

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "Not opped on #test")]

    async def test_admin_bans(self) -> None:
        """Verify BANS command lists tracked channel bans."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "BANS #test"), OWNER),
        )
        assert fake_irc.privmsgs == [("owner", "No bans tracked for #test")]

        fake_irc.privmsgs.clear()
        runtime.bans.update({"*!*@bad.host", "*!*@evil.host"})
        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "BANS #test"), OWNER),
        )
        assert fake_irc.privmsgs == [
            ("owner", "#test +b *!*@bad.host"),
            ("owner", "#test +b *!*@evil.host"),
        ]

    async def test_admin_commands_with_disconnected_irc(self) -> None:
        """Verify admin commands degrade gracefully when IRC is disconnected."""
        bot, _, _ = bot_with_coordinator()
        bot.irc = FailingIRC()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "BAN #test *!*@bad.host"), OWNER),
        )

        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        action = {"channel": "#test", "presence": peer.to_dict()}
        await bot.callbacks.on_invite_grant(action)
        runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
        runtime.bans.add("*!~beta@beta.host")
        await bot.callbacks.on_unban_grant(action)

        assert "*!~beta@beta.host" in runtime.bans

        bot.channel_mgr.pending_ops[casefold("#test")] = {"beta": peer}
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

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "DEOP #test Target"), OWNER),
        )

        assert fake_irc.modes == [("#test", "-o", ("Target",))]

    async def test_admin_deop_removes_hidden_lower_modes(self) -> None:
        """Verify DEOP removes lower operator modes hidden by the highest one."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.caps.parse_prefix("(qao)~&@")
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").modes.add("q")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "DEOP #test Target"), OWNER),
        )

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

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "DEOP #test Target"), OWNER),
        )

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "Target is not opped on #test")]

    async def test_admin_invite(self) -> None:
        """Verify INVITE command sends IRC INVITE directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "INVITE #test guest"), OWNER),
        )

        assert fake_irc.sent == [("INVITE", ("guest", "#test"))]
        assert fake_irc.privmsgs == [("owner", "Invited guest to #test")]

    async def test_admin_op(self) -> None:
        """Verify OP command grants operator mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "OP #test Target"), OWNER),
        )

        assert fake_irc.modes == [("#test", "+o", ("Target",))]

    async def test_admin_op_already_opped(self) -> None:
        """Verify OP reports when target is already opped."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Target").prefix = Prefix("Target", "user", "real.host")
        runtime.member("Target").modes.add("o")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "OP #test Target"), OWNER),
        )

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

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "OP #test ghost"), OWNER),
        )

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [("owner", "ghost not found on #test")]

    async def test_admin_unban(self) -> None:
        """Verify UNBAN command removes a ban mode directly."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.bans.add("*!*@bad.host")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "UNBAN #test *!*@bad.host"), OWNER),
        )

        assert fake_irc.modes == [("#test", "-b", ("*!*@bad.host",))]
        assert fake_irc.privmsgs == [
            ("owner", "Unbanned *!*@bad.host on #test"),
        ]

    async def test_admin_unban_case_insensitive(self) -> None:
        """Verify UNBAN matches ban masks case-insensitively."""
        bot, fake_irc, _ = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        runtime.bans.add("*!*@Bad.Host")
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "UNBAN #test *!*@bad.host"), OWNER),
        )

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

        await bot.events.handle_command(
            IRCMessage(
                "PRIVMSG",
                ("alpha", "UNBAN #test *!*@unknown.host"),
                OWNER,
            ),
        )

        assert fake_irc.modes == []
        assert fake_irc.privmsgs == [
            ("owner", "No matching ban for *!*@unknown.host on #test"),
        ]

    async def test_auth_auto_op(self) -> None:
        """Verify authenticated users receive automatic operator privileges."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == [("#test", "+o", ("owner",))]

    async def test_auth_auto_op_skips_already_opped(self) -> None:
        """Verify auto-op skips users who already have operator status."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER
        runtime.member("owner").modes.add("o")

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_mismatched_identity(self) -> None:
        """Do not op a nickname held by a different IRC identity."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = Prefix("owner", "other", "other.host")

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_when_not_opped(self) -> None:
        """Verify auto-op skips channels where bot is not opped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.member("owner").prefix = OWNER

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_claim_publish_failure_revokes(self) -> None:
        """Verify a publish failure after claim success revokes the session."""
        bot, fake_irc = bot_with_irc()
        bot.coordinator = FailingPublishCoordinator(claim_result=True)
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await bot.auth_flow.authenticate(prefix, (valid_code,))

        assert not bot.authorizer.authorized(prefix.render())
        pending = next(iter(bot.events.pending_sessions.values()))
        assert pending["prefix"] == prefix.render()
        assert pending["revoked"] is True
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_success_grants_session(self) -> None:
        """Verify a valid TOTP code grants an authorized session."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await bot.auth_flow.authenticate(prefix, (valid_code,))

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorized")]
        assert len(coordinator.session_puts) == 1

    async def test_auth_fails_closed_when_coordinator_unready(self) -> None:
        """Deny authentication when the coordinator cannot enforce mesh limits."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        coordinator.connected = False
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await bot.auth_flow.authenticate(prefix, (valid_code,))

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == []
        assert coordinator.session_puts == []

    async def test_auth_denies_when_durable_revocation_wins(self) -> None:
        """Do not report success when newer durable state revokes the session."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        async def put_session(
            identity: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            del identity
            incoming = bot.authorizer.parse(record, time.time())
            assert incoming is not None
            winner = bot.authorizer.create(
                incoming.prefix,
                incoming.expires_at,
                incoming.issuer,
                incoming.version + 1,
                revoked=True,
            )
            return winner.to_dict()

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ):
            await bot.auth_flow.authenticate(prefix, (valid_code,))

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_cmd_key(self) -> None:
        """Verify KEY command reports the channel key."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "KEY #test"), OWNER),
        )
        assert fake_irc.privmsgs == [("owner", "No key set for #test")]

        fake_irc.privmsgs.clear()
        bot.channel_mgr.channels[casefold("#test")].key = "secret"
        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "KEY #test"), OWNER),
        )
        assert fake_irc.privmsgs == [("owner", "Key for #test: secret")]

    async def test_cmd_key_unknown_channel(self) -> None:
        """Verify KEY command reports unknown channels."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "KEY #unknown"), OWNER),
        )
        assert fake_irc.privmsgs == [("owner", "No record for #unknown")]

    async def test_cmd_status(self) -> None:
        """Verify STATUS command returns bot identity and channel count."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.authorizer.grant(OWNER.render())
        bot.channel_mgr.channels[casefold("#test")].joined = True
        bot.presence.update(
            BotPresence("Alpha", "host.example", "inst", "alpha", "~alpha"),
        )
        bot.presence.update(
            BotPresence("beta", "peer.example", "inst2", "beta", "~beta"),
        )

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "STATUS"), OWNER),
        )
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

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "XYZZY"), OWNER),
        )

        assert fake_irc.privmsgs == [("owner", "Unknown command")]
