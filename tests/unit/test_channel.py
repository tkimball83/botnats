# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for channel management, join, part, and lifecycle."""

import asyncio
import json
import time
import unittest
from dataclasses import asdict, astuple, replace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import MagicMock, call, patch

from nats.errors import Error as NatsError

from botnats.channel import (
    JOIN_REPLY_TIMEOUT,
    JOIN_RETRY_DELAY,
    PEER_HELP_DELAY,
    ChannelRecord,
    ChannelRuntime,
    JoinState,
    revision_number,
)
from botnats.config import mode_intent
from botnats.irc.protocol import IRCMessage, ISupportState, Prefix, casefold
from botnats.presence import BotPresence
from botnats.validators import MAX_CHANNEL_REVISION, parse_channel_record
from tests.unit.helpers import (
    OWNER,
    FailingPartIRC,
    FailingWriteCoordinator,
    FakeCoordinator,
    FakeIRC,
    FakeKV,
    bot_with_channel,
    bot_with_coordinator,
    bot_with_irc,
    make_bot,
    settle,
)

if TYPE_CHECKING:
    from botnats.bot import Bot
    from botnats.validators import ChannelFields

# A banned peer asking into a full #test, and one already in it asking for op.
INVITEE = BotPresence("beta-id", "beta.host", "one", "beta", "~beta")
OP_REQUESTER = BotPresence("gamma-id", "gamma.host", "two", "gamma", "~gamma")
HELP_GIVEN = [
    ("INVITE", ("beta", "#test")),
    ("MODE", ("#test", "-b", "*!~beta@beta.host")),
    ("MODE", ("#test", "+l", "3")),
    ("MODE", ("#test", "+o", "gamma")),
]


async def see_key(bot: Bot, runtime: ChannelRuntime, key: str | None) -> None:
    """See a channel key change on IRC, as MODE shows it, and await its write."""
    bot.events.process_key(runtime, key)
    await settle(bot)


def part_and_want_again(bot: Bot) -> ChannelRuntime:
    """Leave a joined #test, and want it again before the server takes the PART.

    Return the channel's new runtime: not joined, while the server still
    sends this bot the channel's MODE changes until it takes the PART.
    """
    mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
    mgr.channels[folded].join = JoinState.JOINED
    mgr.apply_record(mgr.new_record("#test", None, present=False))
    mgr.apply_record(mgr.new_record("#test", None, present=True))
    return mgr.channels[folded]


async def request_help(bot: Bot) -> None:
    """Deliver INVITEE's invite, unban, and room requests, and OP_REQUESTER's op.

    Each arrives as the coordinator hands it over, by kind, and is answered
    with no random delay.
    """
    with patch("botnats.channel.PEER_HELP_DELAY", 0):
        for kind, peer in (
            ("invite", INVITEE),
            ("unban", INVITEE),
            ("limit", INVITEE),
            ("op", OP_REQUESTER),
        ):
            bot.callbacks.on_help(kind, "#test", peer)
            await settle(bot)


class ChannelManagerTests(unittest.IsolatedAsyncioTestCase):
    """Tests for channel join, part, and record application."""

    async def test_enforce_modes_logs_invalid_command(self) -> None:
        """Keep invalid mode configuration from crashing a background task."""
        bot, fake_irc = bot_with_irc()

        with (
            patch.object(
                fake_irc,
                "send",
                MagicMock(side_effect=ValueError("bad mode command")),
            ) as send,
            self.assertLogs("botnats.channel", level="WARNING") as logs,
        ):
            bot.channel_mgr.enforce_modes(
                bot.channel_mgr.channels[casefold("#test", "rfc1459")]
            )

        send.assert_called_once_with("MODE", "#test", "+npst")
        assert logs.output == [
            "WARNING:botnats.channel:cannot enforce modes on #test: bad mode command",
        ]

    async def test_enforce_modes_rejects_server_argument_mode(self) -> None:
        """Skip a configured mode reclassified by the active IRC server."""
        bot, fake_irc = bot_with_irc()
        bot.config = replace(
            bot.config,
            channel_modes="+x",
            enforced_modes=mode_intent("+x"),
        )
        bot.caps.chanmodes = ("beI", "kx", "l", "imnst")

        with self.assertLogs("botnats.channel", level="WARNING"):
            bot.channel_mgr.enforce_modes(
                bot.channel_mgr.channels[casefold("#test", "rfc1459")]
            )

        assert fake_irc.modes == []

    async def test_enforce_modes_checks_unset_modes_as_removed(self) -> None:
        """Unset a limit, which takes no argument to remove; skip one that does."""
        bot, fake_irc = bot_with_irc()
        bot.caps.chanmodes = ("beI", "kx", "l", "imnst")
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        bot.config = replace(
            bot.config,
            channel_modes="+n-l",
            enforced_modes=mode_intent("+n-l"),
        )

        with self.assertNoLogs("botnats.channel", level="WARNING"):
            bot.channel_mgr.enforce_modes(runtime)

        assert fake_irc.sent == [("MODE", ("#test", "+n-l"))]

        bot.config = replace(
            bot.config,
            channel_modes="+n-x",
            enforced_modes=mode_intent("+n-x"),
        )
        with self.assertLogs("botnats.channel", level="WARNING") as logs:
            bot.channel_mgr.enforce_modes(runtime)

        assert fake_irc.sent == [("MODE", ("#test", "+n-l"))]
        assert "configured mode requires an argument" in logs.output[0]

    async def test_enforce_modes_skips_quietly(self) -> None:
        """Send nothing without configured modes; skip a lost connection quietly."""
        bot, fake_irc = bot_with_irc()
        configured = bot.config
        bot.config = replace(
            configured,
            channel_modes="",
            enforced_modes=mode_intent(""),
        )

        with (
            patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send,
            self.assertNoLogs("botnats.channel", level="WARNING"),
        ):
            bot.channel_mgr.enforce_modes(
                bot.channel_mgr.channels[casefold("#test", "rfc1459")]
            )
            assert send.call_args_list == []

            bot.config = configured
            fake_irc.connected = False
            bot.channel_mgr.enforce_modes(
                bot.channel_mgr.channels[casefold("#test", "rfc1459")]
            )

        send.assert_called_once_with("MODE", "#test", "+npst")

    async def test_enforce_modes_refused_is_due_again(self) -> None:
        """Keep NAMES due when the send queue refuses enforcement.

        The next tick resends NAMES, whose end reply enforces again.
        """
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        # A full send queue refuses commands as a dropped connection does.
        fake_irc.connected = False

        bot.channel_mgr.enforce_modes(runtime)

        assert runtime.names_due

    async def test_new_record_orders_local_changes(self) -> None:
        """Order a bot's own changes without a shared process-wide counter."""
        bot = bot_with_channel()
        other = bot_with_channel()

        first = bot.channel_mgr.new_record("#x", None, present=True)
        second = bot.channel_mgr.new_record("#x", "key", present=True)

        # Equal counters would order by random suffix alone.
        assert revision_number(second.revision) > revision_number(first.revision)
        # The other bot has minted only its own record for #test.
        assert other.channel_mgr.last_revision == 1

    async def test_casemapping_change(self) -> None:
        """Verify casemapping change migrates channel and auth state."""
        bot = bot_with_channel(irc=FakeIRC())
        bot.authorizer.grant("Nick[!~user@host.example")
        bot.channel_mgr.apply_record(
            bot.channel_mgr.new_record("#Test[]", None, present=True),
        )
        assert casefold("#Test[]", "rfc1459") in bot.channel_mgr.channels

        bot.channel_mgr.set_casemapping("ascii")

        new_folded = casefold("#Test[]", "ascii")
        assert new_folded in bot.channel_mgr.channels
        assert casefold("#Test[]", "rfc1459") not in bot.channel_mgr.channels
        assert new_folded in bot.channel_mgr.channel_records
        assert bot.authorizer.authorized("nick[!~user@host.example")
        assert not bot.authorizer.authorized("nick{!~user@host.example")

        # A casemapping this bot cannot fold by keeps the current one.
        bot.channel_mgr.set_casemapping("rfc7613")

        assert bot.caps.casemapping == "ascii"

    async def test_casemapping_change_keeps_joined_runtime(self) -> None:
        """Keep a joined channel's live state; the server sends no second JOIN."""
        bot = bot_with_channel(irc=FakeIRC())
        runtime = bot.channel_mgr.runtime("#test")
        assert runtime is not None
        runtime.join = JoinState.JOINED
        runtime.member("Nick[").modes.add("o")
        runtime.add_ban("*!*@Bad[")

        bot.channel_mgr.set_casemapping("ascii")

        assert bot.channel_mgr.runtime("#test") is runtime
        assert runtime.joined
        assert set(runtime.members) == {"nick["}
        assert set(runtime.bans) == {"*!*@bad["}

    async def test_older_colliding_record_does_not_replace_newer(self) -> None:
        """Keep the newer record when an older one folds onto the same channel."""
        bot = make_bot()
        older = bot.channel_mgr.new_record("#room{", "older", present=True)
        newer = bot.channel_mgr.new_record("#room[", "newer", present=True)

        bot.channel_mgr.apply_record(newer)
        bot.channel_mgr.apply_record(older)

        assert bot.channel_mgr.channel_records[casefold("#room[", "rfc1459")] == newer
        runtime = bot.channel_mgr.runtime("#room[")
        assert runtime is not None
        assert runtime.channel == "#room["
        assert runtime.key == "newer"

    async def test_casemapping_change_preserves_colliding_records(self) -> None:
        """Keep records that collide temporarily under one server casemapping.

        The newer record arrives first, so only revision order, not arrival,
        keeps it when the records collide again.
        """
        bot = make_bot()
        first = bot.channel_mgr.new_record("#room[", "first", present=True)
        second = bot.channel_mgr.new_record("#room{", "second", present=True)

        bot.channel_mgr.apply_record(second)
        bot.channel_mgr.apply_record(first)
        assert len(bot.channel_mgr.channel_records) == 1

        bot.channel_mgr.set_casemapping("ascii")
        assert len(bot.channel_mgr.channel_records) == 2
        assert {record.key for record in bot.channel_mgr.channel_records.values()} == {
            "first",
            "second",
        }
        # The channel split off gets a fresh runtime, which joins with its key.
        assert {runtime.key for runtime in bot.channel_mgr.channels.values()} == {
            "first",
            "second",
        }

        bot.channel_mgr.set_casemapping("rfc1459")
        assert list(bot.channel_mgr.channel_records.values()) == [second]
        assert [runtime.key for runtime in bot.channel_mgr.channels.values()] == [
            "second",
        ]

        bot.channel_mgr.set_casemapping("ascii")
        assert len(bot.channel_mgr.channel_records) == 2

    async def test_casemapping_change_parts_tombstoned_channel(self) -> None:
        """Queue a PART when a joined channel now folds onto a tombstone."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        bot.channel_mgr.set_casemapping("ascii")
        joined = bot.channel_mgr.new_record("#room[", None, present=True)
        bot.channel_mgr.apply_record(joined)
        bot.channel_mgr.channels[casefold("#room[", "ascii")].join = JoinState.JOINED
        tombstone = bot.channel_mgr.new_record("#room{", None, present=False)
        bot.channel_mgr.apply_record(tombstone)

        bot.channel_mgr.set_casemapping("rfc1459")

        folded = casefold("#room{", "rfc1459")
        assert folded not in bot.channel_mgr.channels
        assert bot.channel_mgr.pending_parts == {folded: "#room["}

        bot.channel_mgr.retry_pending_parts()
        assert ("PART", ("#room[",)) in fake_irc.sent
        assert bot.channel_mgr.pending_parts == {}

    async def test_casemapping_change_drops_part_of_desired_channel(self) -> None:
        """Drop a pending PART that now folds onto a channel still desired.

        Under rfc1459 the server has merged #room{, left while the send queue
        was full, with #room[, joined after it: this bot stays.
        """
        fake_irc = FailingPartIRC()
        bot = make_bot(irc=fake_irc)
        mgr = bot.channel_mgr
        mgr.set_casemapping("ascii")
        mgr.apply_record(mgr.new_record("#room{", None, present=True))
        mgr.channels[casefold("#room{", "ascii")].join = JoinState.JOINED
        mgr.apply_record(mgr.new_record("#room{", None, present=False))
        assert mgr.pending_parts == {"#room{": "#room{"}
        mgr.apply_record(mgr.new_record("#room[", None, present=True))
        joined = mgr.channels[casefold("#room[", "ascii")]
        joined.join = JoinState.JOINED

        mgr.set_casemapping("rfc1459")

        assert mgr.runtime("#room{") is joined
        assert mgr.pending_parts == {}
        fake_irc.failing = False
        mgr.retry_pending_parts()
        assert fake_irc.sent == []

    async def test_multi_channel_join_part_isolation(self) -> None:
        """Verify keyed channels join and part without changing their peers."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        first = bot.channel_mgr.new_record("#first", "first-key", present=True)
        second = bot.channel_mgr.new_record("#second", "second-key", present=True)

        bot.channel_mgr.apply_record(first)
        bot.channel_mgr.apply_record(second)
        first_runtime = bot.channel_mgr.runtime("#first")
        second_runtime = bot.channel_mgr.runtime("#second")
        assert first_runtime is not None
        assert second_runtime is not None
        first_runtime.join = JoinState.JOINED
        second_runtime.join = JoinState.JOINED

        bot.channel_mgr.apply_record(
            bot.channel_mgr.new_record(
                "#first",
                None,
                present=False,
                after=first.revision,
            ),
        )

        assert ("JOIN", ("#first", "first-key")) in fake_irc.sent
        assert ("JOIN", ("#second", "second-key")) in fake_irc.sent
        assert ("PART", ("#first",)) in fake_irc.sent
        assert ("PART", ("#second",)) not in fake_irc.sent
        assert bot.channel_mgr.runtime("#first") is None
        second_runtime = bot.channel_mgr.runtime("#second")
        assert second_runtime is not None
        assert second_runtime.joined
        assert second_runtime.key == "second-key"

    async def test_part_waits_for_join_echo(self) -> None:
        """Leave a channel whose JOIN was in flight once its echo arrives."""
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.channel_mgr.join_desired()

        tombstone = bot.channel_mgr.new_record("#test", None, present=False)
        bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test", "rfc1459") not in bot.channel_mgr.channels
        assert fake_irc.sent == [("JOIN", ("#test",))]

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "alpha.host")),
        )
        assert fake_irc.sent == [("JOIN", ("#test",)), ("PART", ("#test",))]

    async def test_unconfirmed_channel_is_joined_again(self) -> None:
        """Join a channel wanted again whose JOIN the server never confirmed.

        Only a joined channel gets a PART, so a full send queue leaves no
        pending PART to mistake for membership.
        """
        for join in (JoinState.IDLE, JoinState.JOINING):
            with self.subTest(join=join):
                fake_irc = FailingPartIRC()
                bot = bot_with_channel(irc=fake_irc)
                bot.identity.current = BotPresence(
                    "alpha", "alpha.host", "inst", "alpha", "~alpha"
                )
                mgr = bot.channel_mgr
                mgr.channels[casefold("#test", "rfc1459")].join = join
                tombstone = mgr.new_record("#test", None, present=False)
                mgr.apply_record(tombstone)
                assert mgr.pending_parts == {}

                mgr.apply_record(
                    mgr.new_record(
                        "#test", None, present=True, after=tombstone.revision
                    ),
                )

                runtime = mgr.runtime("#test")
                assert runtime is not None
                assert runtime.join is JoinState.JOINING
                assert fake_irc.sent == [("JOIN", ("#test",))]

    async def test_part_cleared_on_re_desired(self) -> None:
        """Relearn a channel wanted again before its PART goes out.

        A PART that could not be sent leaves this bot in the channel, so the
        server would not answer a JOIN: the channel is joined at once, NAMES
        relearns its members, and the next tick sends no PART.
        """
        fake_irc = FailingPartIRC()
        bot = bot_with_channel(irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        mgr = bot.channel_mgr
        old = mgr.channels[casefold("#test", "rfc1459")]
        old.join = JoinState.JOINED
        old.member("alpha").modes.add("o")
        old.member("stale")
        old.add_ban("*!*@stale.host")
        old.set_limit("10")
        old.cooldowns["op"] = 1.0
        old.modes = "+ntl"

        tombstone = mgr.new_record("#Test", None, present=False)
        mgr.apply_record(tombstone)
        assert mgr.pending_parts == {"#test": "#Test"}

        mgr.apply_record(
            mgr.new_record("#test", None, present=True, after=tombstone.revision),
        )

        # Nothing seen while the channel was not wanted is trusted.
        runtime = mgr.runtime("#test")
        assert runtime is not None
        assert runtime is not old
        assert runtime.joined
        assert runtime.members == {}
        assert runtime.bans == {}
        assert runtime.limit is None
        assert runtime.cooldowns == {}
        assert runtime.modes == ""
        assert mgr.pending_parts == {}
        assert fake_irc.sent == [("NAMES", ("#test",))]

        fake_irc.failing = False
        await bot.maintenance_tick()
        assert fake_irc.sent == [("NAMES", ("#test",))]

        # The NAMES reply restores the membership the fresh runtime lacks.
        bot.events.on_irc_message(
            IRCMessage("353", ("alpha", "=", "#test", "@alpha bob")),
        )
        bot.events.on_irc_message(
            IRCMessage("366", ("alpha", "#test", "End of /NAMES list")),
        )

        assert set(runtime.members) == {"alpha", "bob"}
        assert mgr.is_self_opped(runtime)
        assert fake_irc.sent[1:] == [
            ("WHO", ("#test",)),
            ("MODE", ("#test",)),
            ("MODE", ("#test", "+b")),
            ("MODE", ("#test", "+npst")),
        ]

    async def test_rejoin_names_waits_for_send_queue(self) -> None:
        """Resend a rejoin's NAMES, once, after a full send queue drains.

        Without NAMES the channel would stay joined with no members or ops.
        """
        bot, fake_irc = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        mgr = bot.channel_mgr
        mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
        tombstone = mgr.new_record("#test", None, present=False)
        full = ConnectionError("IRC outbound queue is full")
        with patch.object(fake_irc, "send", side_effect=full):
            mgr.apply_record(tombstone)
            mgr.apply_record(
                mgr.new_record("#test", None, present=True, after=tombstone.revision),
            )

        runtime = mgr.runtime("#test")
        assert runtime is not None
        assert runtime.joined
        assert fake_irc.sent == []

        await bot.maintenance_tick()
        await bot.maintenance_tick()
        assert fake_irc.sent == [("NAMES", ("#test",))]

    async def test_rejoin_after_part_starts_fresh(self) -> None:
        """Verify a channel joined again after a PART keeps none of its old state."""
        bot, fake_irc = bot_with_irc()
        manager = bot.channel_mgr
        runtime = manager.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.cooldowns.update({"invite": 1, "op": 1, "unban": 1})
        runtime.member("alpha").modes.add("o")
        runtime.add_ban("*!*@bad.host")
        runtime.set_limit("10")
        parted = manager.new_record(
            "#test",
            None,
            present=False,
            after=manager.channel_records[casefold("#test", "rfc1459")].revision,
        )
        manager.apply_record(parted)
        assert fake_irc.sent == [("PART", ("#test",))]

        manager.apply_record(
            manager.new_record("#test", None, present=True, after=parted.revision),
        )

        rejoined = manager.runtime("#test")
        assert rejoined is not None
        assert rejoined is not runtime
        assert rejoined.join is JoinState.IDLE
        assert rejoined.cooldowns == {}
        assert rejoined.members == {}
        assert rejoined.bans == {}
        assert rejoined.limit is None

    async def test_part_queued_on_failure(self) -> None:
        """Keep a failed part queued, retrying it each maintenance tick until sent."""
        fake_irc = FailingPartIRC()
        bot = bot_with_channel(irc=fake_irc)
        bot.identity.registered = True
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED

        tombstone = bot.channel_mgr.new_record("#test", None, present=False)
        bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test", "rfc1459") not in bot.channel_mgr.channels
        assert "#test" in bot.channel_mgr.pending_parts

        await bot.maintenance_tick()
        assert "#test" in bot.channel_mgr.pending_parts

        fake_irc.failing = False
        await bot.maintenance_tick()

        assert "#test" not in bot.channel_mgr.pending_parts
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_part_tombstone_precedence(self) -> None:
        """Verify tombstone record takes precedence over stale join."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        join = bot.channel_mgr.new_record("#test", None, present=True)
        tombstone = bot.channel_mgr.new_record(
            "#test",
            None,
            present=False,
            after=join.revision,
        )

        bot.channel_mgr.apply_record(join)
        bot.channel_mgr.apply_record(tombstone)
        bot.channel_mgr.apply_record(join)

        assert casefold("#test", "rfc1459") not in bot.channel_mgr.channels
        assert (
            bot.channel_mgr.channel_records[casefold("#test", "rfc1459")] == tombstone
        )
        # The stale join does not displace the durable copy a write names.
        assert bot.channel_mgr.durable_revision("#test") == tombstone.revision
        # The stale join does not rejoin the parted channel; the JOIN still in
        # flight is left when its echo arrives.
        assert fake_irc.sent == [("JOIN", ("#test",))]

    async def test_record_key_is_versioned(self) -> None:
        """Verify a newer record that changes the key updates it authoritatively."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(irc=FakeIRC(), coordinator=coordinator)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.key = "livekey"
        current = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]

        bot.channel_mgr.apply_record(
            bot.channel_mgr.new_record(
                "#test",
                "durablekey",
                present=True,
                after=current.revision,
            ),
        )
        assert runtime.key == "durablekey"

        base = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")].revision
        await see_key(bot, runtime, "recordkey")

        assert runtime.key == "recordkey"
        record = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]
        assert record.key == "recordkey"
        assert coordinator.channel_puts == [asdict(record)]
        assert coordinator.channel_after == [base]

    async def test_record_key_skips_unchanged_value(self) -> None:
        """Avoid a new durable revision when the key is unchanged."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        current = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]
        record = bot.channel_mgr.new_record(
            "#test",
            "same-key",
            present=True,
            after=current.revision,
        )
        bot.channel_mgr.apply_record(record)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED

        bot.events.process_key(runtime, "same-key")
        assert runtime.key_pending
        await settle(bot)

        assert not runtime.key_pending
        assert coordinator.channel_puts == []
        assert bot.channel_mgr.channel_records[casefold("#test", "rfc1459")] == record

    async def test_record_key_retries_failed_publish(self) -> None:
        """Retry a failed key write once JetStream recovers; never apply it early."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test", "rfc1459")
        before = bot.channel_mgr.channel_records[folded]
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED

        await see_key(bot, runtime, "recordkey")

        assert runtime.key_pending
        # A failed write must not shadow newer remote records.
        assert bot.channel_mgr.channel_records[folded] == before
        assert bot.channel_mgr.writing == set()
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert not runtime.key_pending
        assert coordinator.channel_puts[0]["key"] == "recordkey"
        assert bot.channel_mgr.channel_records[folded].key == "recordkey"

    async def test_failed_key_write_does_not_override_a_later_part(self) -> None:
        """Drop a failed key write that a concurrent PART superseded."""
        coordinator = FailingWriteCoordinator()
        bot, fake_irc, _ = bot_with_coordinator(coordinator)
        folded = casefold("#test", "rfc1459")
        base = bot.channel_mgr.channel_records[folded]
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        await see_key(bot, runtime, "newkey")
        assert runtime.key_pending
        # Another bot parts the channel at the revision number this write used,
        # with a suffix that sorts lower than any this bot might have minted.
        number = revision_number(base.revision) + 1
        tombstone = replace(
            ChannelRecord.new("#test", None, present=False, after=base.revision),
            revision=f"{number:020d}-{'0' * 32}",
        )

        bot.channel_mgr.apply_record(tombstone)
        assert fake_irc.sent == [("PART", ("#test",))]
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert folded not in bot.channel_mgr.channels
        assert coordinator.channel_puts == []

    async def test_queued_key_write_does_not_override_a_later_part(self) -> None:
        """Drop a key write that waited its turn while another bot parted."""
        coordinator = FakeCoordinator()
        bot, _, _ = bot_with_coordinator(coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        tombstone = ChannelRecord.new(
            "#test",
            None,
            present=False,
            after=mgr.channel_records[folded].revision,
        )

        async with mgr.key_lock:
            # MODE +k k queues behind a key write still in flight...
            bot.events.process_key(runtime, "k")
            assert runtime.key_pending
            # ...while another bot's PART #test arrives.
            mgr.apply_record(tombstone)

        await settle(bot)

        assert coordinator.channel_puts == []
        assert folded not in mgr.channels
        assert mgr.channel_records[folded] == tombstone

    async def test_failed_key_write_does_not_override_a_newer_key(self) -> None:
        """Drop a failed key write once another bot has recorded a newer key."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test", "rfc1459")
        base = bot.channel_mgr.channel_records[folded]
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        await see_key(bot, runtime, "stale")
        assert runtime.key_pending
        # While this bot was cut off, another bot recorded a later MODE +k,
        # which IRC showed this bot only as "*".
        newer = replace(
            ChannelRecord.new("#test", "x", present=True, after=base.revision),
            revision=f"{revision_number(base.revision) + 2:020d}-{'0' * 32}",
        )

        runtime.hide_key()
        bot.channel_mgr.apply_record(newer)
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert coordinator.channel_puts == []
        assert not runtime.key_pending
        assert bot.channel_mgr.channel_records[folded].key == "x"
        assert runtime.key == "x"

    async def test_writes_name_the_record_under_their_own_key(self) -> None:
        """Base each write on its own durable key, not a merged local record.

        Under rfc1459, #room[ and #room{ are one IRC channel but two durable
        keys; basing a #room{ write on #room['s revision could never pass the
        store's check.
        """
        coordinator = FakeCoordinator()
        bot, _, _ = bot_with_coordinator(coordinator)
        mgr = bot.channel_mgr
        brace = mgr.new_record("#room{", None, present=True)
        bracket = mgr.new_record("#room[", None, present=True)
        mgr.apply_record(brace)
        mgr.apply_record(bracket)
        assert mgr.channel_records[casefold("#room{", "rfc1459")] == bracket

        runtime = mgr.runtime("#room{")
        assert runtime is not None
        runtime.join = JoinState.JOINED
        # A key write names the channel's newest record, #room[...
        await see_key(bot, runtime, "secret")
        # ...and a command the spelling it was given.
        await bot.commands.cmd_join(OWNER, ("#room{", "other"))

        assert coordinator.channel_after == [bracket.revision, brace.revision]

    async def test_unrelated_newer_record_keeps_observed_key(self) -> None:
        """Keep an observed key and its pending write past an unrelated record."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        keyed = mgr.new_record(
            "#test", "A", present=True, after=mgr.channel_records[folded].revision
        )
        mgr.apply_record(keyed)
        await see_key(bot, runtime, "B")
        # Another bot re-issues JOIN #test, carrying the stored key A over.
        mgr.apply_record(
            mgr.new_record("#test", "A", present=True, after=keyed.revision),
        )

        assert runtime.key == "B"
        coordinator.failing = False
        await mgr.retry_pending_keys()

        assert [put["key"] for put in coordinator.channel_puts] == ["B"]
        assert mgr.channel_records[folded].key == "B"

    async def test_late_key_write_keeps_newer_observed_key(self) -> None:
        """Keep the key seen on IRC when this bot's write of an older one lands.

        Otherwise a failed write of the newer key is retried with the older.
        """
        coordinator = FakeCoordinator()
        bot = bot_with_channel(irc=FakeIRC(), coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def put_channel(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            if record["key"] == "B":
                msg = "NATS disconnected"
                raise NatsError(msg)

            in_flight.set()
            await release.wait()
            return await record_put(record, after=after)

        op = Prefix("op", "~op", "op.host")
        with patch.object(coordinator, "put_channel", put_channel):
            async with asyncio.timeout(5):
                bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+k", "A"), op))
                await in_flight.wait()
                # The key moves on to B while the write of A is in flight.
                bot.events.on_irc_message(
                    IRCMessage("MODE", ("#test", "-k+k", "A", "B"), op),
                )
                release.set()
                await settle(bot)

        assert runtime.key == "B"
        await mgr.retry_pending_keys()

        assert mgr.channel_records[folded].key == "B"
        assert not runtime.key_pending

    async def test_key_is_pending_once_seen(self) -> None:
        """Keep a key seen on IRC past a record landing before its write starts."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED

        bot.events.process_key(runtime, "B")
        # Another bot's record of an older key lands first.
        mgr.apply_record(
            mgr.new_record(
                "#test", "A", present=True, after=mgr.channel_records[folded].revision
            ),
        )
        assert runtime.key == "B"
        await settle(bot)

        assert mgr.channel_records[folded].key == "B"

    async def test_observed_key_outlasts_an_equivalent_spelling(self) -> None:
        """Keep a key awaiting its write past records under an equivalent name.

        Under rfc1459, #room{ records rename the #room[ channel; the key this
        bot saw on IRC stays pending under #room[ all the same.
        """
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#room[", "rfc1459")
        bracket = mgr.new_record("#room[", None, present=True)
        mgr.apply_record(bracket)
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        await see_key(bot, runtime, "B")
        # Another bot records the old key twice, spelling the channel #room{.
        brace = mgr.new_record("#room{", None, present=True, after=bracket.revision)
        mgr.apply_record(brace)
        mgr.apply_record(
            mgr.new_record("#room{", None, present=True, after=brace.revision),
        )

        assert runtime.channel == "#room{"
        assert runtime.key == "B"
        coordinator.failing = False
        await mgr.retry_pending_keys()

        assert mgr.channel_records[folded].key == "B"
        assert not runtime.key_pending

    async def test_joined_bot_learns_a_hidden_key_from_peers(self) -> None:
        """Take a peer's recorded key when IRC showed this bot only "*".

        With no key of its own left to record, this bot knows nothing newer,
        and joins with that key again after a kick.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        op = Prefix("op", "~op", "op.host")

        bot.events.on_irc_message(IRCMessage("MODE", ("#test", "+k", "*"), op))
        mgr.apply_record(
            mgr.new_record(
                "#test", "x", present=True, after=mgr.channel_records[folded].revision
            ),
        )
        assert runtime.key == "x"

        bot.events.on_irc_message(IRCMessage("KICK", ("#test", "alpha"), op))
        await settle(bot)
        mgr.join_desired()

        assert fake_irc.sent == [("JOIN", ("#test", "x"))]

    async def test_key_write_that_loses_is_retried(self) -> None:
        """Rewrite the key seen on IRC after a concurrent record wins its write.

        The winner can carry the old key over, as when another bot re-issues
        JOIN with the key it has stored; the observed key must not be lost.
        """
        coordinator = FakeCoordinator()
        kv = cast("FakeKV", coordinator.channels.kv)
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        keyed = mgr.new_record(
            "#test", "A", present=True, after=mgr.channel_records[folded].revision
        )
        await coordinator.channels.put(asdict(keyed), after=None)
        mgr.apply_record(keyed)
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        record_put = coordinator.put_channel

        async def racing_put(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            # Another bot's JOIN #test, carrying its stored key A, lands first.
            competing = ChannelRecord.new(
                "#test", "A", present=True, after=keyed.revision
            )
            await coordinator.channels.put(asdict(competing), after=keyed.revision)
            return await record_put(record, after=after)

        with patch.object(coordinator, "put_channel", racing_put):
            await see_key(bot, runtime, "B")  # MODE #test +k B, seen on IRC

        assert mgr.channel_records[folded].key == "A"
        assert runtime.key_pending

        await mgr.retry_pending_keys()

        _, stored = kv.entries[coordinator.channels.key("#test")]
        assert json.loads(stored)["key"] == "B"
        assert mgr.channel_records[folded].key == "B"
        assert not runtime.key_pending

    async def test_key_seen_while_parting_is_not_recorded(self) -> None:
        """Record no key shown to the membership this bot's PART is leaving.

        Wanted again before the server takes the PART, the channel has a
        runtime that has not joined: the record knows best until its JOIN.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = part_and_want_again(bot)
        assert fake_irc.sent == [("PART", ("#test",)), ("JOIN", ("#test",))]

        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "+k", "seen"), Prefix("op", "~op", "op.host")),
        )
        assert runtime.key_pending
        await settle(bot)

        assert coordinator.channel_puts == []
        assert not runtime.key_pending

    async def test_late_write_keeps_a_key_seen_and_hidden(self) -> None:
        """Keep the key IRC showed while this bot's older write was in flight.

        IRC then hid the key, so nothing is pending when the older write
        lands; the stored key still serves a JOIN the server refuses.
        """
        coordinator = FakeCoordinator()
        bot, fake_irc, _ = bot_with_coordinator(coordinator)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def slow_put(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            in_flight.set()
            await release.wait()
            return await record_put(record, after=after)

        with patch.object(coordinator, "put_channel", slow_put):
            async with asyncio.timeout(5):
                bot.events.process_key(runtime, "A")
                await in_flight.wait()
                bot.events.process_key(runtime, "B")
                runtime.hide_key()
                release.set()
                await settle(bot)

        # The KV watch delivers the write again after its reply, as does a
        # watch replay after a reconnect.
        bot.callbacks.on_channel(astuple(mgr.channel_records[folded]))

        assert [put["key"] for put in coordinator.channel_puts] == ["A"]
        assert runtime.key == "B"

        runtime.reset()  # kicked
        mgr.safe_join(runtime)
        mgr.refuse_key(runtime)
        mgr.safe_join(runtime)

        assert fake_irc.sent == [("JOIN", ("#test", "B")), ("JOIN", ("#test", "A"))]

    async def test_late_write_watched_before_its_reply_keeps_the_key(self) -> None:
        """Keep the key IRC showed when the watch delivers this bot's write first.

        NATS does not order the KV watch against the store's reply, so the
        record is this bot's own write whichever reaches it first.
        """
        coordinator = FakeCoordinator()
        bot, fake_irc, _ = bot_with_coordinator(coordinator)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def watched_put(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            in_flight.set()
            await release.wait()
            stored = await record_put(record, after=after)
            bot.callbacks.on_channel(stored)
            return stored

        with patch.object(coordinator, "put_channel", watched_put):
            async with asyncio.timeout(5):
                bot.events.process_key(runtime, "A")
                await in_flight.wait()
                bot.events.process_key(runtime, "B")
                runtime.hide_key()
                release.set()
                await settle(bot)

        assert mgr.channel_records[folded].key == "A"
        runtime.reset()  # kicked
        mgr.safe_join(runtime)

        assert fake_irc.sent == [("JOIN", ("#test", "B"))]

    async def test_own_write_keys_a_channel_not_joined(self) -> None:
        """Join a channel with the key this bot's own write stored for it."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )

        await bot.channel_mgr.write_record("#new", "key", present=True)

        assert fake_irc.sent == [("JOIN", ("#new", "key"))]

    async def test_unjoined_channel_takes_the_recorded_key(self) -> None:
        """Take a record's key in a channel this bot has not joined.

        A key it saw before a kick is no longer pending, nor is one shown to
        the membership a PART still in flight is leaving.
        """
        bot, _, _ = bot_with_coordinator(FailingWriteCoordinator())
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        await see_key(bot, runtime, "seen")
        assert runtime.key_pending

        runtime.reset()  # kicked
        assert not runtime.key_pending
        peer = mgr.new_record(
            "#test", "x", present=True, after=mgr.channel_records[folded].revision
        )
        mgr.apply_record(peer)
        assert runtime.key == "x"

        runtime = part_and_want_again(bot)  # once it has joined again
        bot.events.on_irc_message(
            IRCMessage("MODE", ("#test", "+k", "late"), Prefix("op", "~op", "op.host")),
        )
        assert runtime.key_pending
        mgr.apply_record(mgr.new_record("#test", "y", present=True))
        assert runtime.key == "y"
        await settle(bot)

        assert not runtime.key_pending

    async def test_retry_skips_channels_changed_meanwhile(self) -> None:
        """Skip a key hidden, or a channel parted, while an earlier write ran.

        The keys still pending after them are written all the same.
        """
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr = bot.channel_mgr
        channels = ("#test", "#hidden", "#parted", "#kept")
        for channel in channels[1:]:
            mgr.apply_record(mgr.new_record(channel, None, present=True))

        runtimes = [mgr.channels[casefold(channel, "rfc1459")] for channel in channels]
        for runtime in runtimes:
            runtime.join = JoinState.JOINED
            await see_key(bot, runtime, "seen")
            assert runtime.key_pending

        coordinator.failing = False
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def slow_put(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            in_flight.set()
            await release.wait()
            return await record_put(record, after=after)

        with patch.object(coordinator, "put_channel", slow_put):
            async with asyncio.timeout(5):
                retry = asyncio.create_task(mgr.retry_pending_keys())
                await in_flight.wait()
                runtimes[1].hide_key()
                mgr.apply_record(
                    mgr.new_record(
                        "#parted",
                        None,
                        present=False,
                        after=mgr.channel_records["#parted"].revision,
                    ),
                )
                release.set()
                await retry

        assert [put["channel"] for put in coordinator.channel_puts] == [
            "#test",
            "#kept",
        ]
        assert "#parted" not in mgr.channels
        assert not mgr.channel_records["#parted"].present

    async def test_quick_key_changes_are_written_in_order(self) -> None:
        """Compare each key change against the record the previous one left."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        base = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")].revision
        await see_key(bot, runtime, "k")
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()

        async def slow_put(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            in_flight.set()
            await release.wait()
            return await record_put(record, after=after)

        with patch.object(coordinator, "put_channel", slow_put):
            async with asyncio.timeout(5):
                bot.events.process_key(runtime, None)
                await in_flight.wait()
                # MODE +k k arrives while the -k write is still in flight.
                bot.events.process_key(runtime, "k")
                release.set()
                await settle(bot)

        puts = coordinator.channel_puts
        assert [record["key"] for record in puts] == ["k", None, "k"]
        # Each write names the record the previous one stored as its base.
        assert coordinator.channel_after == [
            base,
            *(record["revision"] for record in puts[:2]),
        ]
        assert bot.channel_mgr.channel_records[casefold("#test", "rfc1459")].key == "k"

    async def test_record_key_defers_local_apply_to_durable_write(self) -> None:
        """Apply only the record the durable store returns on success."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test", "rfc1459")
        before = bot.channel_mgr.channel_records[folded]
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        seen: list[ChannelRecord] = []

        async def put_channel(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            del after
            seen.append(bot.channel_mgr.channel_records[folded])
            return parse_channel_record(record)

        with patch.object(coordinator, "put_channel", put_channel):
            await see_key(bot, runtime, "recordkey")

        # The locally minted record must not shadow remote authoritative
        # records while the durable write is still in flight.
        assert seen == [before]
        assert bot.channel_mgr.channel_records[folded].key == "recordkey"

    async def test_write_record_orders_after_current_record(self) -> None:
        """Mint a write after a peer's record whose revision outruns this bot's.

        A record numbered from this bot's own counter alone would sort before
        the peer's: the store would accept it, yet every bot, this one
        included, would ignore it as stale.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        mgr = bot.channel_mgr
        peer = ChannelRecord.new("#test", None, present=True, floor=1_000)
        await coordinator.channels.put(asdict(peer), after=None)
        mgr.apply_record(peer)
        mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
        assert mgr.last_revision < revision_number(peer.revision)

        assert await mgr.write_record("#Test", None, present=False)

        assert fake_irc.sent == [("PART", ("#Test",))]
        assert mgr.runtime("#test") is None
        record = mgr.channel_records[casefold("#test", "rfc1459")]
        assert not record.present
        assert record.revision > peer.revision

    async def test_write_record_reports_a_lost_write(self) -> None:
        """Apply the stored winner, never the attempt, and report losing to it."""
        bot, _, coordinator = bot_with_coordinator()
        mgr = bot.channel_mgr
        # Stored by a peer, but not yet watched here.
        winner = ChannelRecord.new("#new", None, present=False, floor=1_000)
        await coordinator.channels.put(asdict(winner), after=None)

        assert not await mgr.write_record("#new", None, present=True)

        assert [put["present"] for put in coordinator.channel_puts] == [True]
        assert mgr.runtime("#new") is None
        assert mgr.channel_records[casefold("#new", "rfc1459")] == winner

    async def test_write_applies_authoritative_winner(self) -> None:
        """Converge local channel state when a newer durable mutation wins."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        # Joined, with no key of its own pending: the winner's key applies.
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED
        winner: ChannelRecord | None = None

        async def put_channel(
            record: dict[str, Any],
            *,
            after: str | None,
        ) -> ChannelFields:
            del after
            nonlocal winner
            incoming = ChannelRecord(*parse_channel_record(record))
            winner = bot.channel_mgr.new_record(
                incoming.channel,
                "durablekey",
                present=True,
                after=incoming.revision,
            )
            return astuple(winner)

        with patch.object(coordinator, "put_channel", put_channel):
            await bot.channel_mgr.write_record("#test", "stale-key", present=True)

        assert winner is not None
        assert bot.channel_mgr.channel_records[casefold("#test", "rfc1459")] == winner
        assert (
            bot.channel_mgr.channels[casefold("#test", "rfc1459")].key == "durablekey"
        )

    async def test_quit_prefix_outranks_stored_member_prefix(self) -> None:
        """Return a complete QUIT prefix over the member prefix stored for it.

        A stored prefix can be stale, as after a host change this bot never
        saw: it completes only a prefix lacking a user or host.
        """
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("owner").prefix = Prefix("owner", "user", "stale.host")
        prefix = Prefix("owner", "user", "host.example")

        assert bot.channel_mgr.forget_member(prefix) == prefix

    async def test_nick_prefix_outranks_stored_member_prefix(self) -> None:
        """Return a complete NICK prefix over the member prefix stored for it."""
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("owner").prefix = Prefix("owner", "user", "stale.host")
        prefix = Prefix("owner", "user", "host.example")

        assert bot.channel_mgr.rename_member(prefix, "newowner") == prefix

    async def test_chghost_prefix_outranks_stored_member_prefix(self) -> None:
        """Return a complete CHGHOST prefix over the member prefix stored for it."""
        bot = bot_with_channel()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("owner").prefix = Prefix("owner", "user", "stale.host")
        prefix = Prefix("owner", "user", "host.example")
        new_prefix = Prefix("owner", "newuser", "new.host")

        assert bot.channel_mgr.change_member_host(prefix, new_prefix) == prefix

    async def test_disconnected_bot_does_not_help(self) -> None:
        """Swallow a lost connection in every help action; report no help given."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.add_ban("*!~beta@beta.host")
        runtime.limit = 1
        bot.presence.update(INVITEE)
        fake_irc.connected = False

        with (
            patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send,
            self.assertNoLogs("botnats.channel", level="INFO"),
        ):
            bot.channel_mgr.invite_peer("#test", INVITEE)
            bot.channel_mgr.make_room("#test", INVITEE)
            bot.channel_mgr.unban_peer("#test", INVITEE)
            # Invited peers are outside the channel; op goes to a member.
            runtime.member("beta").prefix = INVITEE.to_prefix()
            bot.channel_mgr.op_peer("#test", INVITEE)

        # Each action reached IRC, so each swallowed its own ConnectionError.
        assert send.call_args_list == [
            call("INVITE", "beta", "#test"),
            call("MODE", "#test", "+l", "2"),
            call("MODE", "#test", "-b", "*!~beta@beta.host"),
            call("MODE", "#test", "+o", "beta"),
        ]

    async def test_help_needs_active_peer_presence(self) -> None:
        """Help no peer whose presence expired or was never announced."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("gamma").prefix = OP_REQUESTER.to_prefix()
        runtime.add_ban("*!~beta@beta.host")
        runtime.limit = 2
        # beta's heartbeat has lapsed; gamma has not announced itself.
        bot.presence.update(INVITEE, now=time.monotonic() - bot.presence.ttl - 1)

        await request_help(bot)
        assert fake_irc.sent == []

        for peer in (INVITEE, OP_REQUESTER):
            bot.presence.update(peer)

        await request_help(bot)
        assert fake_irc.sent == HELP_GIVEN

    async def test_help_needs_self_opped(self) -> None:
        """Help peers only while this bot holds operator status itself."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha")
        runtime.member("gamma").prefix = OP_REQUESTER.to_prefix()
        runtime.add_ban("*!~beta@beta.host")
        runtime.limit = 2
        for peer in (INVITEE, OP_REQUESTER):
            bot.presence.update(peer)

        await request_help(bot)
        assert fake_irc.sent == []

        runtime.member("alpha").modes.add("o")
        await request_help(bot)
        assert fake_irc.sent == HELP_GIVEN

    async def test_op_help_waits_for_who(self) -> None:
        """Op no peer before WHO shows who holds its nick."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.presence.update(OP_REQUESTER)
        runtime.member("gamma")  # listed by NAMES; WHO has not answered yet

        bot.channel_mgr.op_peer("#test", OP_REQUESTER)
        assert fake_irc.modes == []

        runtime.member("gamma").prefix = OP_REQUESTER.to_prefix()
        bot.channel_mgr.op_peer("#test", OP_REQUESTER)
        assert fake_irc.modes == [("#test", "+o", ("gamma",))]

    async def test_help_request_rechecks_state_after_delay(self) -> None:
        """Wait under PEER_HELP_DELAY, then op a peer unless already helped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peers = (
            BotPresence("beta-id", "beta.host", "one", "beta", "~beta"),
            BotPresence("gamma-id", "gamma.host", "two", "gamma", "~gamma"),
        )
        for peer in peers:
            bot.presence.update(peer)
            runtime.member(peer.nick).prefix = peer.to_prefix()

        delays: list[float] = []
        both_waiting = asyncio.Event()
        release = asyncio.Event()
        real_sleep = asyncio.sleep

        async def gated_sleep(delay: float) -> None:
            # The patch reaches every caller of asyncio.sleep: hold only the
            # help delay, and let settle() yield as usual.
            task = asyncio.current_task()
            if task is None or task.get_name() != "peer-help":
                await real_sleep(delay)
                return

            delays.append(delay)
            if len(delays) == len(peers):
                both_waiting.set()

            await release.wait()

        with (
            patch("asyncio.sleep", gated_sleep),
            patch("secrets.randbelow", return_value=999) as randbelow,
        ):
            for peer in peers:
                bot.callbacks.on_help("op", "#test", peer)

            async with asyncio.timeout(5):
                await both_waiting.wait()
                assert fake_irc.modes == []
                # Another peer ops beta while both requests wait out their delay.
                runtime.member("beta").modes.add("o")
                release.set()
                await settle(bot)

        # The longest delay the draw allows stays under PEER_HELP_DELAY.
        assert randbelow.call_args_list == [call(1000)] * len(peers)
        assert delays == [0.999] * len(peers)
        assert all(0 <= delay < PEER_HELP_DELAY for delay in delays)
        assert fake_irc.modes == [("#test", "+o", ("gamma",))]

    async def test_unknown_help_kind_is_ignored(self) -> None:
        """Drop a help request of a kind this bot has no action for."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta-id", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        with (
            patch("botnats.channel.PEER_HELP_DELAY", 0),
            self.assertNoLogs("botnats", level="ERROR"),
        ):
            bot.callbacks.on_help("unknown", "#test", peer)
            await settle(bot)

        assert fake_irc.sent == []

    async def test_help_request_without_runtime_or_member_is_ignored(self) -> None:
        """Drop an op request for a channel not loaded, or a peer not in it."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta-id", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        with (
            patch("botnats.channel.PEER_HELP_DELAY", 0),
            self.assertNoLogs("botnats", level="ERROR"),
        ):
            # #gone was just parted, or is not loaded yet.
            bot.callbacks.on_help("op", "#gone", peer)
            # beta's JOIN #test has not reached this server yet.
            bot.callbacks.on_help("op", "#test", peer)
            await settle(bot)

        assert fake_irc.sent == []

    async def test_invite_peer(self) -> None:
        """Invite a known peer bot, unless it is in the channel already."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        invitee = replace(INVITEE, nick="Beta")
        bot.presence.update(invitee)
        # Another peer's invite got beta in while this request waited.
        runtime.member("beta")

        bot.channel_mgr.invite_peer("#test", invitee)
        assert fake_irc.sent == []

        runtime.remove("beta")
        bot.channel_mgr.invite_peer("#test", invitee)
        assert fake_irc.sent == [("INVITE", ("Beta", "#test"))]

    async def test_make_room_raises_limit_for_left_out_bots(self) -> None:
        """Raise a full channel's limit by the number of bots not in it."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("user")
        runtime.limit = 2
        peers = (
            BotPresence("beta-id", "beta.host", "one", "beta", "~beta"),
            BotPresence("gamma-id", "gamma.host", "two", "gamma", "~gamma"),
            BotPresence("delta-id", "delta.host", "three", "Delta", "~delta"),
        )
        for peer in peers:
            bot.presence.update(peer)

        runtime.member("delta")

        bot.channel_mgr.make_room("#test", peers[0])
        # Three members plus beta and gamma, left out; delta is already in.
        assert fake_irc.sent == [("MODE", ("#test", "+l", "5"))]

        runtime.limit = 5
        bot.channel_mgr.make_room("#test", peers[0])
        assert len(fake_irc.sent) == 1

    async def test_make_room_needs_a_limit(self) -> None:
        """Leave a channel without a tracked limit alone."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta-id", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)

        bot.channel_mgr.make_room("#test", peer)

        assert fake_irc.sent == []

    async def test_make_room_needs_a_bot_left_out(self) -> None:
        """Leave a limit below the member count alone while no bot is left out."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("user")
        runtime.limit = 1
        bot.presence.update(INVITEE)
        # Another peer's help got beta in while this request waited.
        runtime.member("beta")

        bot.channel_mgr.make_room("#test", INVITEE)
        assert fake_irc.sent == []

        runtime.remove("beta")
        bot.channel_mgr.make_room("#test", INVITEE)
        assert fake_irc.sent == [("MODE", ("#test", "+l", "3"))]

    async def test_op_peer_one_at_a_time(self) -> None:
        """Op each requesting peer with its own MODE line."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")

        peers = (
            BotPresence("beta-id", "beta.host", "one", "Beta", "~beta"),
            BotPresence("gamma-id", "gamma.host", "two", "Gamma", "~gamma"),
        )
        for peer in peers:
            bot.presence.update(peer)
            # IRC shows each member in another case than its presence.
            nick = peer.nick.lower()
            runtime.member(nick).prefix = Prefix(nick, peer.user, peer.host)
            bot.channel_mgr.op_peer("#test", peer)

        assert fake_irc.modes == [
            ("#test", "+o", ("Beta",)),
            ("#test", "+o", ("Gamma",)),
        ]

    async def test_op_requires_matching_host(self) -> None:
        """Verify op request is rejected when peer host does not match."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta-id", "real.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        runtime.member("beta").prefix = Prefix("beta", "~beta", "stolen.host")

        assert bot.channel_mgr.help_eligible("#test", peer) is None

    async def test_unban_matching_masks(self) -> None:
        """Verify an unban request removes only matching ban masks."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        for mask in ("*!~beta@bot.host", "*!other@*", "*!*@bot.host"):
            runtime.add_ban(mask)

        peer = BotPresence("beta-id", "bot.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        bot.channel_mgr.unban_peer("#test", peer)

        assert fake_irc.modes == [
            ("#test", "-b", ("*!*@bot.host",)),
            ("#test", "-b", ("*!~beta@bot.host",)),
        ]

    async def test_join_waits_for_identity(self) -> None:
        """Join nothing between 001 and the USERHOST reply naming this bot.

        A JOIN refused before then could ask no peer for help.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.on_registered()  # 001

        await bot.maintenance_tick()
        assert fake_irc.sent == []

        bot.events.on_irc_message(
            IRCMessage("302", ("alpha", "alpha=+~alpha@alpha.host")),
        )
        await settle(bot)

        assert fake_irc.sent == [("JOIN", ("#test",))]

    async def test_join_state_transitions(self) -> None:
        """Send JOIN when idle; resend one in flight or refused once it is due."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]

        bot.channel_mgr.join_desired()
        assert runtime.join is JoinState.JOINING
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 1

        bot.events.on_irc_message(
            IRCMessage("473", ("alpha", "#test", "Cannot join channel (+i)")),
        )
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 1
        runtime.join_retry_at -= JOIN_RETRY_DELAY
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "alpha.host")),
        )
        assert runtime.join is JoinState.JOINED

    async def test_queued_join_awaits_its_reply_from_its_send(self) -> None:
        """Await a JOIN's reply from when the send queue gets to it."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        fake_irc.queue_delay = 100.0

        bot.channel_mgr.join_desired()
        runtime.join_retry_at -= JOIN_REPLY_TIMEOUT
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 1

        runtime.join_retry_at -= fake_irc.queue_delay
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

    async def test_refused_join_send_stays_due(self) -> None:
        """Leave a JOIN the send queue refuses due for the next tick."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        fake_irc.connected = False

        bot.channel_mgr.join_desired()
        assert runtime.join is JoinState.IDLE

        fake_irc.connected = True
        bot.channel_mgr.join_desired()
        assert fake_irc.sent == [("JOIN", ("#test",))]

    async def test_unban_request_identity(self) -> None:
        """Send this bot's identity with a request; send none before it is known."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)

        await bot.channel_mgr.request_peer("unban", "#test")
        assert coordinator.help_requests == []

        bot.identity.current = BotPresence(
            "alpha", "bot.host", "one", "alpha", "~alpha"
        )
        await bot.channel_mgr.request_peer("unban", "#test")

        assert coordinator.help_requests == [
            ("unban", {"channel": "#test", "presence": asdict(bot.identity.current)}),
        ]

    async def test_peer_requests_cool_down_per_kind(self) -> None:
        """Publish one request of each kind per cooldown, however often asked."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        bot.identity.current = BotPresence(
            "alpha", "bot.host", "one", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        # Long enough that no stall between requests can outlast it; each
        # kind last asked a full cooldown ago, however long the clock has run.
        cooldown = 3600.0
        expired = asyncio.get_running_loop().time() - cooldown
        runtime.cooldowns.update(invite=expired, limit=expired)

        with patch("botnats.channel.PEER_REQUEST_COOLDOWN", cooldown):
            for kind in ("invite", "invite", "limit"):
                await bot.channel_mgr.request_peer(kind, "#test")

            assert [kind for kind, _ in coordinator.help_requests] == [
                "invite",
                "limit",
            ]

            # The invite request's cooldown runs out.
            runtime.cooldowns["invite"] -= cooldown
            await bot.channel_mgr.request_peer("invite", "#test")

        assert [kind for kind, _ in coordinator.help_requests] == [
            "invite",
            "limit",
            "invite",
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

    async def test_requests_op_before_who_replies(self) -> None:
        """Verify op request proceeds when opped members lack prefixes."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("beta").modes.add("o")

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 1

    async def test_requests_op_for_unopped_channels(self) -> None:
        """Request op only in joined channels where this bot lacks it.

        A peer bot is opped in every channel, so only this bot's own state
        decides: #test and #unopped need op, #opped needs none, and #waiting
        is not joined yet.
        """
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        peer = BotPresence("beta-id", "beta.host", "two", "beta", "~beta")
        bot.presence.update(peer)
        for channel in ("#opped", "#unopped", "#waiting"):
            record = bot.channel_mgr.new_record(channel, None, present=True)
            bot.channel_mgr.apply_record(record)

        for channel, state in (
            ("#test", JoinState.JOINED),
            ("#opped", JoinState.JOINED),
            ("#unopped", JoinState.JOINED),
            ("#waiting", JoinState.JOINING),
        ):
            runtime = bot.channel_mgr.channels[casefold(channel, "rfc1459")]
            runtime.join = state
            runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
            runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
            runtime.member("beta").modes.add("o")

        bot.channel_mgr.channels["#opped"].member("alpha").modes.add("o")

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert [payload["channel"] for _, payload in op_requests] == [
            "#test",
            "#unopped",
        ]

    async def test_skips_op_request_when_only_user_opped(self) -> None:
        """Request no op while only a non-peer user, and no peer bot, holds it."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.presence.update(BotPresence("beta-id", "beta.host", "two", "beta", "~beta"))
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("beta").prefix = Prefix("beta", "~beta", "beta.host")
        runtime.member("stranger").prefix = Prefix("stranger", "user", "other.host")
        runtime.member("stranger").modes.add("o")

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0


class ChannelStateTests(unittest.TestCase):
    """Tests for channel records and per-channel runtime state."""

    def test_channel_revision_ordering(self) -> None:
        """Verify channel record revision ordering and serialization."""
        update = ChannelRecord.new("#test", "key", present=True)
        tombstone = ChannelRecord.new(
            "#test",
            None,
            present=False,
            after=update.revision,
        )

        # Compare the counters: equal counters fall back to random suffix order.
        assert revision_number(tombstone.revision) > revision_number(update.revision)
        assert tombstone.revision > update.revision
        assert ChannelRecord(*parse_channel_record(asdict(tombstone))) == tombstone

    def test_new_record_rejects_counter_past_maximum(self) -> None:
        """Refuse to build a record past the last revision counter."""
        with self.assertRaisesRegex(ValueError, "counter is exhausted"):
            ChannelRecord.new(
                "#test",
                None,
                present=True,
                after=f"{MAX_CHANNEL_REVISION:020d}-{'0' * 32}",
            )

    def test_member_reuses_entry(self) -> None:
        """Verify repeated member lookups reuse the tracked object."""
        runtime = ChannelRuntime(ISupportState())

        member = runtime.member("User")

        assert runtime.member("user") is member
        assert member.nick == "user"

    def test_set_key_validation(self) -> None:
        """Reject a key that is malformed or too long to JOIN this channel with."""
        runtime = ChannelRuntime(ISupportState(), channel="#test")
        runtime.key = "old-key"
        # "JOIN #test <key>\r\n" is 13 bytes plus the key; IRC allows 512.
        longest = "k" * 499

        for unusable in ("bad key", f"{longest}k"):
            with self.subTest(key=unusable[:8]):
                assert not runtime.set_key(unusable)
                assert runtime.key == "old-key"

        assert runtime.set_key(longest)
        assert runtime.key == longest

        assert runtime.set_key(None)
        assert runtime.key is None
