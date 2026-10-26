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

from botnats.bot import Bot
from botnats.channel import (
    JOIN_REPLY_TIMEOUT,
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
    config,
    make_bot,
)

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

    from botnats.validators import ChannelFields

# A peer asking for an invite, and one already in #test asking for op.
INVITEE = BotPresence("beta", "beta.host", "one", "beta", "~beta")
OP_REQUESTER = BotPresence("gamma", "gamma.host", "two", "gamma", "~gamma")
HELP_GIVEN = [("INVITE", ("beta", "#test")), ("MODE", ("#test", "+o", "gamma"))]


async def settle(bot: Bot) -> None:
    """Wait for background tasks, including any the finished ones spawned."""
    while bot.tasks:
        await asyncio.gather(*bot.tasks)


def request_help(bot: Bot) -> None:
    """Deliver INVITEE's invite request and OP_REQUESTER's op request."""
    bot.channel_mgr.invite_peer("#test", INVITEE)
    bot.channel_mgr.op_peer("#test", OP_REQUESTER)


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

    async def test_new_record_orders_local_changes(self) -> None:
        """Order a bot's own changes without a shared process-wide counter."""
        bot = bot_with_channel()
        other = bot_with_channel()

        first = bot.channel_mgr.new_record("#x", None, present=True)
        second = bot.channel_mgr.new_record("#x", "key", present=True)

        assert second.revision > first.revision
        assert other.channel_mgr.last_revision < bot.channel_mgr.last_revision

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
        assert new_folded in bot.channel_mgr.channel_records
        assert bot.authorizer.authorized("nick[!~user@host.example")
        assert not bot.authorizer.authorized("nick{!~user@host.example")

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
        bot = Bot(config())
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
        """Keep records that collide temporarily under one server casemapping."""
        bot = Bot(config())
        first = bot.channel_mgr.new_record("#room[", "first", present=True)
        second = bot.channel_mgr.new_record("#room{", "second", present=True)

        bot.channel_mgr.apply_record(first)
        bot.channel_mgr.apply_record(second)
        assert len(bot.channel_mgr.channel_records) == 1

        bot.channel_mgr.set_casemapping("ascii")
        assert len(bot.channel_mgr.channel_records) == 2
        assert {record.key for record in bot.channel_mgr.channel_records.values()} == {
            "first",
            "second",
        }

        bot.channel_mgr.set_casemapping("rfc1459")
        assert len(bot.channel_mgr.channel_records) == 1

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

    async def test_join_part_nats_failure(self) -> None:
        """Verify join and part commands report NATS write failures."""
        bot, fake_irc, _ = bot_with_coordinator(FailingWriteCoordinator())
        bot.authorizer.grant(OWNER.render())

        await bot.commands.dispatch(OWNER, "JOIN #new")
        await bot.commands.dispatch(OWNER, "PART #test")

        assert casefold("#new", "rfc1459") not in bot.channel_mgr.channels
        assert casefold("#test", "rfc1459") in bot.channel_mgr.channels
        # Each reply is the write's own error, so each command attempted one.
        assert fake_irc.privmsgs == [
            ("owner", "NATS disconnected: channel #new"),
            ("owner", "NATS disconnected: channel #test"),
        ]

    async def test_multi_channel_join_part_isolation(self) -> None:
        """Verify keyed channels join and part without changing their peers."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
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
        """Verify failed part is queued and retried on next maintenance tick."""
        fake_irc = FailingPartIRC()
        bot = bot_with_channel(irc=fake_irc)
        bot.identity.registered = True
        bot.channel_mgr.channels[casefold("#test", "rfc1459")].join = JoinState.JOINED

        tombstone = bot.channel_mgr.new_record("#test", None, present=False)
        bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test", "rfc1459") not in bot.channel_mgr.channels
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
        bot.identity.registered = True
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
        await bot.channel_mgr.record_key("#test", "recordkey")

        assert runtime.key == "recordkey"
        record = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")]
        assert record.key == "recordkey"
        assert coordinator.channel_puts == [asdict(record)]
        assert coordinator.channel_expected == [base]

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

        await bot.channel_mgr.record_key("#test", "same-key")

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
        runtime.set_key("recordkey")  # MODE +k recordkey, seen on IRC

        await bot.channel_mgr.record_key("#test", "recordkey")

        assert bot.channel_mgr.pending_keys == {"#test": "#test"}
        # A failed write must not shadow newer remote records.
        assert bot.channel_mgr.channel_records[folded] == before
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert not bot.channel_mgr.pending_keys
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
        runtime.set_key("newkey")
        await bot.channel_mgr.record_key("#test", "newkey")
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
        assert not bot.channel_mgr.pending_keys

    async def test_queued_key_write_does_not_override_a_later_part(self) -> None:
        """Drop a key write that waited its turn while another bot parted."""
        coordinator = FakeCoordinator()
        bot, _, _ = bot_with_coordinator(coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        tombstone = ChannelRecord.new(
            "#test",
            None,
            present=False,
            after=mgr.channel_records[folded].revision,
        )

        async with asyncio.timeout(5):
            async with mgr.key_lock:
                # MODE +k k queues behind a key write still in flight...
                write = asyncio.create_task(mgr.record_key("#test", "k"))
                # One step runs the write up to the lock it waits on.
                await asyncio.sleep(0)
                # ...while another bot's PART #test arrives.
                mgr.apply_record(tombstone)

            await write

        assert coordinator.channel_puts == []
        assert folded not in mgr.channels
        assert mgr.channel_records[folded] == tombstone
        assert not mgr.pending_keys

    async def test_failed_key_write_does_not_override_a_newer_key(self) -> None:
        """Drop a failed key write once another bot has recorded a newer key."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test", "rfc1459")
        base = bot.channel_mgr.channel_records[folded]
        runtime = bot.channel_mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.set_key("stale")
        await bot.channel_mgr.record_key("#test", "stale")
        # While this bot was cut off, another bot recorded a later MODE +k.
        newer = replace(
            ChannelRecord.new("#test", "x", present=True, after=base.revision),
            revision=f"{revision_number(base.revision) + 2:020d}-{'0' * 32}",
        )

        bot.channel_mgr.apply_record(newer)
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert coordinator.channel_puts == []
        assert not bot.channel_mgr.pending_keys
        assert bot.channel_mgr.channel_records[folded].key == "x"

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

        # Each write names the spelling that is not the newest local record.
        await mgr.record_key("#room{", "secret")
        assert mgr.channel_records[casefold("#room[", "rfc1459")].channel == "#room{"
        await bot.commands.cmd_join(OWNER, ("#room[", "other"))

        assert coordinator.channel_expected == [brace.revision, bracket.revision]

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
        runtime.set_key("B")
        await mgr.record_key("#test", "B")
        # Another bot re-issues JOIN #test, carrying the stored key A over.
        mgr.apply_record(
            mgr.new_record("#test", "A", present=True, after=keyed.revision),
        )

        assert runtime.key == "B"
        coordinator.failing = False
        await mgr.retry_pending_keys()

        assert [put["key"] for put in coordinator.channel_puts] == ["B"]
        assert mgr.channel_records[folded].key == "B"

    async def test_key_write_that_loses_is_retried(self) -> None:
        """Rewrite the key seen on IRC after a concurrent record wins its write.

        The winner can carry the old key over, as when another bot re-issues
        JOIN with the key it has stored; the observed key must not be lost.
        """
        coordinator = FakeCoordinator()
        kv = FakeKV()
        coordinator.channels.kv = cast("KeyValue", kv)
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        keyed = mgr.new_record(
            "#test", "A", present=True, after=mgr.channel_records[folded].revision
        )
        await coordinator.channels.put(asdict(keyed), expected=None)
        mgr.apply_record(keyed)
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        runtime.set_key("B")  # MODE #test +k B, seen on IRC
        record_put = coordinator.put_channel

        async def racing_put(
            record: dict[str, Any],
            *,
            expected: str | None,
        ) -> ChannelFields:
            # Another bot's JOIN #test, carrying its stored key A, lands first.
            competing = ChannelRecord.new(
                "#test", "A", present=True, after=keyed.revision
            )
            await coordinator.channels.put(asdict(competing), expected=keyed.revision)
            return await record_put(record, expected=expected)

        with patch.object(coordinator, "put_channel", racing_put):
            await mgr.record_key("#test", "B")

        assert mgr.channel_records[folded].key == "A"
        assert mgr.pending_keys == {"#test": "#test"}

        await mgr.retry_pending_keys()

        _, stored = kv.entries[coordinator.channels.key("#test")]
        assert json.loads(stored)["key"] == "B"
        assert mgr.channel_records[folded].key == "B"
        assert not mgr.pending_keys

    async def test_retry_does_not_replay_a_superseded_key(self) -> None:
        """Retry with the key seen on IRC now, not the one seen at failure."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        mgr, folded = bot.channel_mgr, casefold("#test", "rfc1459")
        runtime = mgr.channels[folded]
        runtime.join = JoinState.JOINED
        stored = mgr.new_record(
            "#test", "A", present=True, after=mgr.channel_records[folded].revision
        )
        mgr.apply_record(stored)
        runtime.set_key("B")
        await mgr.record_key("#test", "B")
        # The key then moves on to C and back to A, recorded by other bots;
        # A is also what this bot now sees on IRC.
        changed = mgr.new_record("#test", "C", present=True, after=stored.revision)
        mgr.apply_record(changed)
        mgr.apply_record(
            mgr.new_record("#test", "A", present=True, after=changed.revision),
        )

        coordinator.failing = False
        await mgr.retry_pending_keys()

        assert runtime.key == "A"
        assert coordinator.channel_puts == []
        assert mgr.channel_records[folded].key == "A"

    async def test_retry_dropped_once_bot_leaves_channel(self) -> None:
        """Drop a failed key write once this bot can no longer see the key."""
        coordinator = FailingWriteCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.set_key("seen")
        await bot.channel_mgr.record_key("#test", "seen")
        runtime.reset()  # kicked, or the IRC connection dropped

        coordinator.failing = False
        await bot.channel_mgr.retry_pending_keys()

        assert coordinator.channel_puts == []
        assert not bot.channel_mgr.pending_keys

    async def test_quick_key_changes_are_written_in_order(self) -> None:
        """Compare each key change against the record the previous one left."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        base = bot.channel_mgr.channel_records[casefold("#test", "rfc1459")].revision
        await bot.channel_mgr.record_key("#test", "k")
        record_put = coordinator.put_channel
        in_flight = asyncio.Event()
        release = asyncio.Event()
        restoring = asyncio.Event()

        async def slow_put(
            record: dict[str, Any],
            *,
            expected: str | None,
        ) -> ChannelFields:
            in_flight.set()
            await release.wait()
            return await record_put(record, expected=expected)

        async def restore() -> None:
            # Runs on until record_key first waits, before the test resumes.
            restoring.set()
            await bot.channel_mgr.record_key("#test", "k")

        with patch.object(coordinator, "put_channel", slow_put):
            async with asyncio.timeout(5):
                removed = asyncio.create_task(
                    bot.channel_mgr.record_key("#test", None),
                )
                await in_flight.wait()
                # MODE +k k arrives while the -k write is still in flight.
                restored = asyncio.create_task(restore())
                await restoring.wait()
                release.set()
                await asyncio.gather(removed, restored)

        puts = coordinator.channel_puts
        assert [record["key"] for record in puts] == ["k", None, "k"]
        # Each write names the record the previous one stored as its base.
        assert coordinator.channel_expected == [
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
        seen: list[ChannelRecord] = []

        async def put_channel(
            record: dict[str, Any],
            *,
            expected: str | None,
        ) -> ChannelFields:
            del expected
            seen.append(bot.channel_mgr.channel_records[folded])
            return parse_channel_record(record)

        with patch.object(coordinator, "put_channel", put_channel):
            await bot.channel_mgr.record_key("#test", "recordkey")

        # The locally minted record must not shadow remote authoritative
        # records while the durable write is still in flight.
        assert seen == [before]
        assert bot.channel_mgr.channel_records[folded].key == "recordkey"

    async def test_record_key_applies_authoritative_winner(self) -> None:
        """Converge local channel state when a newer durable mutation wins."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        winner: ChannelRecord | None = None

        async def put_channel(
            record: dict[str, Any],
            *,
            expected: str | None,
        ) -> ChannelFields:
            del expected
            nonlocal winner
            incoming = ChannelRecord.from_dict(record)
            winner = bot.channel_mgr.new_record(
                incoming.channel,
                "durablekey",
                present=True,
                after=incoming.revision,
            )
            return astuple(winner)

        with patch.object(coordinator, "put_channel", put_channel):
            await bot.channel_mgr.record_key("#test", "stale-key")

        assert winner is not None
        assert bot.channel_mgr.channel_records[casefold("#test", "rfc1459")] == winner
        assert (
            bot.channel_mgr.channels[casefold("#test", "rfc1459")].key == "durablekey"
        )

    async def test_safe_join_unsendable_key(self) -> None:
        """Log an unsendable channel key and leave the JOIN not in flight."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.key = "bad key"

        with self.assertLogs("botnats.channel", level="WARNING") as logs:
            bot.channel_mgr.safe_join(runtime)

        assert fake_irc.sent == []
        assert len(logs.output) == 1
        assert "cannot join #test" in logs.output[0]
        # Only a JOIN that reached the send queue is in flight.
        assert runtime.join is JoinState.IDLE

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
        # beta's heartbeat has lapsed; gamma has not announced itself.
        bot.presence.update(INVITEE, now=time.monotonic() - bot.presence.ttl - 1)

        request_help(bot)
        assert fake_irc.sent == []

        for peer in (INVITEE, OP_REQUESTER):
            bot.presence.update(peer)

        request_help(bot)
        assert fake_irc.sent == HELP_GIVEN

    async def test_help_needs_self_opped(self) -> None:
        """Help peers only while this bot holds operator status itself."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha")
        runtime.member("gamma").prefix = OP_REQUESTER.to_prefix()
        for peer in (INVITEE, OP_REQUESTER):
            bot.presence.update(peer)

        request_help(bot)
        assert fake_irc.sent == []

        runtime.member("alpha").modes.add("o")
        request_help(bot)
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
        """Act on a peer's op request after the delay, unless already helped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peers = (
            BotPresence("beta", "beta.host", "one", "beta", "~beta"),
            BotPresence("gamma", "gamma.host", "two", "gamma", "~gamma"),
        )
        for peer in peers:
            bot.presence.update(peer)
            runtime.member(peer.nick).prefix = peer.to_prefix()

        delays: list[float] = []
        both_waiting = asyncio.Event()
        release = asyncio.Event()

        async def gated_sleep(delay: float) -> None:
            delays.append(delay)
            if len(delays) == len(peers):
                both_waiting.set()

            await release.wait()

        with patch("botnats.channel.asyncio.sleep", gated_sleep):
            for peer in peers:
                bot.callbacks.on_help("op", "#test", peer)

            async with asyncio.timeout(5):
                await both_waiting.wait()
                assert fake_irc.modes == []
                # Another peer ops beta while both requests wait out their delay.
                runtime.member("beta").modes.add("o")
                release.set()
                await settle(bot)

        assert fake_irc.modes == [("#test", "+o", ("gamma",))]

    async def test_unknown_help_kind_is_ignored(self) -> None:
        """Drop a help request of a kind this bot has no action for."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        with (
            patch("botnats.channel.PEER_HELP_DELAY", 0),
            self.assertNoLogs("botnats", level="ERROR"),
        ):
            bot.callbacks.on_help("unknown", "#test", peer)
            await settle(bot)

        assert fake_irc.sent == []

    async def test_invite_peer(self) -> None:
        """Invite a known peer bot, unless it is in the channel already."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        bot.presence.update(INVITEE)
        # Another peer's invite got beta in while this request waited.
        runtime.member("Beta")

        bot.channel_mgr.invite_peer("#test", INVITEE)
        assert fake_irc.sent == []

        runtime.remove("Beta")
        bot.channel_mgr.invite_peer("#test", INVITEE)
        assert fake_irc.sent == [("INVITE", ("beta", "#test"))]

    async def test_make_room_raises_limit_for_left_out_bots(self) -> None:
        """Raise a full channel's limit by the number of bots not in it."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("user")
        runtime.limit = 2
        peers = (
            BotPresence("beta", "beta.host", "one", "beta", "~beta"),
            BotPresence("gamma", "gamma.host", "two", "gamma", "~gamma"),
            BotPresence("delta", "delta.host", "three", "delta", "~delta"),
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
        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)

        bot.channel_mgr.make_room("#test", peer)

        assert fake_irc.sent == []

    async def test_op_peer_one_at_a_time(self) -> None:
        """Op each requesting peer with its own MODE line."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("alpha").modes.add("o")

        peers = (
            BotPresence("beta", "beta.host", "one", "beta", "~beta"),
            BotPresence("gamma", "gamma.host", "two", "gamma", "~gamma"),
        )
        for peer in peers:
            bot.presence.update(peer)
            runtime.member(peer.nick).prefix = Prefix(peer.nick, peer.user, peer.host)
            bot.channel_mgr.op_peer("#test", peer)

        assert fake_irc.modes == [
            ("#test", "+o", ("beta",)),
            ("#test", "+o", ("gamma",)),
        ]

    async def test_op_requires_matching_host(self) -> None:
        """Verify op request is rejected when peer host does not match."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "real.host", "one", "beta", "~beta")
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

        peer = BotPresence("beta", "bot.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        bot.channel_mgr.unban_peer("#test", peer)

        assert fake_irc.modes == [
            ("#test", "-b", ("*!*@bot.host",)),
            ("#test", "-b", ("*!~beta@bot.host",)),
        ]

    async def test_join_state_transitions(self) -> None:
        """Send JOIN only when idle: not while in flight, again after refusal."""
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
        assert runtime.join is JoinState.IDLE
        bot.channel_mgr.join_desired()
        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

        bot.events.on_irc_message(
            IRCMessage("JOIN", ("#test",), Prefix("alpha", "~alpha", "alpha.host")),
        )
        assert runtime.join is JoinState.JOINED

    async def test_join_without_reply_is_retried(self) -> None:
        """Resend a JOIN that got neither an echo nor a refusal in time."""
        bot, fake_irc, _ = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]

        bot.channel_mgr.join_desired()
        runtime.join_sent_at -= JOIN_REPLY_TIMEOUT
        bot.channel_mgr.join_desired()

        assert len([cmd for cmd in fake_irc.sent if cmd[0] == "JOIN"]) == 2

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
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("beta").modes.add("o")

        await bot.channel_mgr.request_ops()

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

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert [payload["channel"] for _, payload in op_requests] == ["#test"]

    async def test_skips_op_request_when_no_peer_opped(self) -> None:
        """Verify no op request is sent when no peer has op."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0

    async def test_skips_op_request_when_only_user_opped(self) -> None:
        """Verify opped non-peer users do not trigger op requests."""
        bot, _, coordinator = bot_with_coordinator()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").prefix = Prefix("alpha", "~alpha", "alpha.host")
        runtime.member("stranger").prefix = Prefix("stranger", "user", "other.host")
        runtime.member("stranger").modes.add("o")

        await bot.channel_mgr.request_ops()

        op_requests = [r for r in coordinator.help_requests if r[0] == "op"]
        assert len(op_requests) == 0


class ChannelStateTests(unittest.TestCase):
    """Tests for channel records and per-channel runtime state."""

    def test_channel_record_injection(self) -> None:
        """Verify read and new channel records reject injected channel names."""
        channel = "#safe\r\nOPER root pass"
        unsafe = {
            "channel": channel,
            "key": None,
            "present": True,
            "revision": "00000000000000000001-0123456789abcdef0123456789abcdef",
        }

        with self.assertRaisesRegex(ValueError, "unsupported characters"):
            ChannelRecord.from_dict(unsafe)

        with self.assertRaisesRegex(ValueError, "unsupported characters"):
            ChannelRecord.new(channel, None, present=True)

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
        assert ChannelRecord.from_dict(asdict(tombstone)) == tombstone

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

    def test_refuse_join_ends_only_a_pending_join(self) -> None:
        """Return a pending JOIN to idle; leave a joined or idle channel alone."""
        runtime = ChannelRuntime(ISupportState(), channel="#test")

        for state, after in (
            (JoinState.JOINING, JoinState.IDLE),
            (JoinState.JOINED, JoinState.JOINED),
            (JoinState.IDLE, JoinState.IDLE),
        ):
            with self.subTest(state=state):
                runtime.join = state
                runtime.refuse_join()
                assert runtime.join is after
