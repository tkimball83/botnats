# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for channel management, join, part, and lifecycle."""

import asyncio
import unittest
from dataclasses import replace
from unittest.mock import AsyncMock, patch

from botnats.bot import Bot
from botnats.channel import ChannelRecord, ChannelRuntime
from botnats.irc.protocol import IRCMessage, Prefix, casefold
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

EXPECTED_NATS_FAILURE_PRIVMSGS = 2
EXPECTED_SPLIT_RECORDS = 2


class ChannelManagerTests(unittest.IsolatedAsyncioTestCase):
    """Tests for channel join, part, and record application."""

    async def test_channel_update_rejects_oversized_mode_command(self) -> None:
        """Reject a channel update before storing an unusable mode command."""
        bot, _, coordinator = bot_with_coordinator()
        bot.config = replace(bot.config, channel_modes="+" + "n" * 499)

        with self.assertRaisesRegex(ValueError, "exceeds 512 bytes"):
            await bot.commands.channel_update(
                Prefix("owner", "user", "real.host"),
                "#test",
                None,
                present=True,
            )

        assert coordinator.channel_puts == []

    async def test_enforce_modes_logs_invalid_command(self) -> None:
        """Keep invalid mode configuration from crashing a background task."""
        bot, fake_irc = bot_with_irc()

        with (
            patch.object(
                fake_irc,
                "send",
                AsyncMock(side_effect=ValueError("bad mode command")),
            ),
            self.assertLogs("botnats.channel", level="WARNING"),
        ):
            await bot.channel_mgr.enforce_modes("#test")

    async def test_enforce_modes_rejects_server_argument_mode(self) -> None:
        """Skip a configured mode reclassified by the active IRC server."""
        bot, fake_irc = bot_with_irc()
        bot.config = replace(bot.config, channel_modes="+x")
        bot.caps.chanmodes = ("beI", "kx", "l", "imnst")

        with self.assertLogs("botnats.channel", level="WARNING"):
            await bot.channel_mgr.enforce_modes("#test")

        assert fake_irc.modes == []

    async def test_channel_revision_rejects_impossible_counter(self) -> None:
        """Prevent an impossible revision from blocking subsequent updates."""
        impossible = f"{'9' * 20}-{'0' * 32}"
        with self.assertRaisesRegex(ValueError, "invalid revision"):
            ChannelRecord.from_dict(
                {
                    "channel": "#test",
                    "key": None,
                    "present": True,
                    "revision": impossible,
                },
            )
        with self.assertRaisesRegex(ValueError, "invalid revision"):
            ChannelRecord.new("#test", None, present=True, after=impossible)

    async def test_casemapping_change(self) -> None:
        """Verify casemapping change migrates channel and auth state."""
        bot = bot_with_channel()
        bot.irc = FakeIRC()
        bot.authorizer.grant("Nick[!~user@host.example")
        old_folded = casefold("#Test[]")
        record = ChannelRecord.new(
            "#Test[]",
            None,
            present=True,
        )
        bot.channel_mgr.channel_records[old_folded] = record
        bot.channel_mgr.source_records[casefold(record.channel, "ascii")] = record
        bot.channel_mgr.desired_channels[old_folded] = "#Test[]"
        bot.channel_mgr.channels[old_folded] = ChannelRuntime(casemapping="rfc1459")

        bot.channel_mgr.set_casemapping("ascii")

        new_folded = casefold("#Test[]", "ascii")
        assert new_folded in bot.channel_mgr.channels
        assert new_folded in bot.channel_mgr.desired_channels
        assert new_folded in bot.channel_mgr.channel_records
        assert bot.authorizer.authorized("nick[!~user@host.example")
        assert not bot.authorizer.authorized("nick{!~user@host.example")

    async def test_casemapping_change_preserves_colliding_records(self) -> None:
        """Keep records that collide temporarily under one server casemapping."""
        bot = Bot(config())
        first = ChannelRecord.new("#room[", "first", present=True)
        second = ChannelRecord.new("#room{", "second", present=True)

        await bot.channel_mgr.apply_record(first)
        await bot.channel_mgr.apply_record(second)
        assert len(bot.channel_mgr.channel_records) == 1

        bot.channel_mgr.set_casemapping("ascii")
        assert len(bot.channel_mgr.channel_records) == EXPECTED_SPLIT_RECORDS
        assert {record.key for record in bot.channel_mgr.channel_records.values()} == {
            "first",
            "second",
        }

        bot.channel_mgr.set_casemapping("rfc1459")
        bot.channel_mgr.set_casemapping("ascii")
        assert len(bot.channel_mgr.channel_records) == EXPECTED_SPLIT_RECORDS

    async def test_casemapping_change_parts_tombstoned_channel(self) -> None:
        """Queue a PART when a rekeyed joined channel folds onto a tombstone."""
        bot = Bot(config())
        fake_irc = FakeIRC()
        bot.irc = fake_irc
        bot.channel_mgr.set_casemapping("ascii")
        joined = ChannelRecord.new("#room[", None, present=True)
        await bot.channel_mgr.apply_record(joined)
        bot.channel_mgr.channels[casefold("#room[", "ascii")].joined = True
        tombstone = ChannelRecord.new("#room{", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        bot.channel_mgr.set_casemapping("rfc1459")

        folded = casefold("#room{")
        assert folded not in bot.channel_mgr.channels
        assert bot.channel_mgr.pending_parts == {folded: "#room{"}

        await bot.channel_mgr.retry_pending_parts()
        assert ("PART", ("#room{",)) in fake_irc.sent
        assert bot.channel_mgr.pending_parts == {}

    async def test_flush_cancellation_does_not_respawn(self) -> None:
        """Verify a cancelled op-flush does not resurrect a background task."""
        bot, _ = bot_with_irc()
        bot.identity = BotPresence("alpha", "alpha.host", "inst", "alpha", "~alpha")
        folded = casefold("#test")
        bot.channel_mgr.channels[folded].joined = True
        peer = BotPresence("beta", "beta.host", "two", "beta", "~beta")

        bot.channel_mgr.queue_pending_op(folded, peer)
        await asyncio.sleep(0)
        tasks = [task for task in bot.tasks if task.get_name() == "op-batch"]
        assert len(tasks) == 1

        tasks[0].cancel()
        with self.assertRaises(asyncio.CancelledError):
            await tasks[0]
        await asyncio.sleep(0)

        live = [
            task
            for task in bot.tasks
            if task.get_name() == "op-batch" and not task.done()
        ]
        assert live == []
        assert folded not in bot.channel_mgr.pending_op_flushes

    async def test_join_part_nats_failure(self) -> None:
        """Verify join and part commands handle NATS publish failures."""
        bot = bot_with_channel()
        coordinator = FailingPublishCoordinator()
        fake_irc = FakeIRC()
        bot.coordinator = coordinator
        bot.irc = fake_irc
        prefix = Prefix("owner", "user", "real.host")
        bot.authorizer.grant(prefix.render())

        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "JOIN #new"), prefix),
        )
        await bot.events.handle_command(
            IRCMessage("PRIVMSG", ("alpha", "PART #test"), prefix),
        )

        assert casefold("#new") not in bot.channel_mgr.desired_channels
        assert casefold("#test") in bot.channel_mgr.desired_channels
        assert len(fake_irc.privmsgs) == EXPECTED_NATS_FAILURE_PRIVMSGS

    async def test_join_preserves_live_key(self) -> None:
        """Verify a repeated keyless JOIN retains a key learned from IRC."""
        bot, _, coordinator = bot_with_coordinator()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.key = "live-key"
        prefix = Prefix("owner", "user", "real.host")

        await bot.commands.cmd_join(prefix, ("#test",))

        _, payload = coordinator.channel_puts[-1]
        assert payload["key"] == "live-key"
        assert runtime.key == "live-key"

    async def test_multi_channel_join_part_isolation(self) -> None:
        """Verify keyed channels join and part without changing their peers."""
        bot = Bot(config())
        fake_irc = FakeIRC()
        bot.irc = fake_irc
        bot.identity = BotPresence("alpha", "alpha.host", "inst", "alpha", "~alpha")
        bot.registered = True
        first = ChannelRecord.new("#first", "first-key", present=True)
        second = ChannelRecord.new("#second", "second-key", present=True)

        await bot.channel_mgr.apply_record(first)
        await bot.channel_mgr.apply_record(second)
        first_runtime = bot.runtime("#first")
        second_runtime = bot.runtime("#second")
        assert first_runtime is not None
        assert second_runtime is not None
        first_runtime.joined = True
        second_runtime.joined = True

        await bot.channel_mgr.apply_record(
            ChannelRecord.new(
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
        assert bot.runtime("#first") is None
        second_runtime = bot.runtime("#second")
        assert second_runtime is not None
        assert second_runtime.joined
        assert second_runtime.key == "second-key"

    async def test_part_before_join_echoed(self) -> None:
        """Verify part is sent even when channel was never fully joined."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        assert not runtime.joined

        tombstone = ChannelRecord.new("#test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test") not in bot.channel_mgr.channels
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_part_cleared_on_re_desired(self) -> None:
        """Verify re-desiring a case-equivalent channel clears its pending part."""
        bot = bot_with_channel()
        bot.irc = FailingPartIRC()

        tombstone = ChannelRecord.new("#Test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)
        assert "#test" in bot.channel_mgr.pending_parts

        rejoin = ChannelRecord.new(
            "#test",
            None,
            present=True,
            after=tombstone.revision,
        )
        await bot.channel_mgr.apply_record(rejoin)

        assert "#test" not in bot.channel_mgr.pending_parts
        assert casefold("#test") in bot.channel_mgr.desired_channels

    async def test_part_clears_transient_state(self) -> None:
        """Verify parting clears cooldowns and queued operator grants."""
        bot, _ = bot_with_irc()
        folded = bot.fold("#test")
        manager = bot.channel_mgr
        manager.cooldowns[("invite", folded)] = 1
        manager.cooldowns[("op", folded)] = 1
        manager.cooldowns[("unban", folded)] = 1
        manager.pending_ops[folded] = {}
        current = bot.channel_mgr.channel_records[folded]

        await manager.apply_record(
            ChannelRecord.new(
                "#test",
                None,
                present=False,
                after=current.revision,
            ),
        )

        assert not any(k[1] == folded for k in manager.cooldowns)
        assert folded not in manager.pending_ops

    async def test_part_queued_on_failure(self) -> None:
        """Verify failed part is queued and retried on next maintenance tick."""
        bot = bot_with_channel()
        bot.irc = FailingPartIRC()
        bot.registered = True

        tombstone = ChannelRecord.new("#test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test") not in bot.channel_mgr.channels
        assert "#test" in bot.channel_mgr.pending_parts

        fake_irc = FakeIRC()
        bot.irc = fake_irc
        await bot.maintenance_tick()

        assert "#test" not in bot.channel_mgr.pending_parts
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_part_tombstone_precedence(self) -> None:
        """Verify tombstone record takes precedence over stale join."""
        bot = Bot(config())
        join = ChannelRecord.new("#test", None, present=True)
        tombstone = ChannelRecord.new(
            "#test",
            None,
            present=False,
            after=join.revision,
        )

        await bot.channel_mgr.apply_record(join)
        await bot.channel_mgr.apply_record(tombstone)
        await bot.channel_mgr.apply_record(join)

        assert casefold("#test") not in bot.channel_mgr.desired_channels
        assert bot.channel_mgr.channel_records[casefold("#test")] == tombstone

    async def test_record_key_is_versioned(self) -> None:
        """Verify newer channel records authoritatively update the key."""
        bot = bot_with_channel()
        bot.irc = FakeIRC()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.joined = True
        runtime.key = "livekey"
        current = bot.channel_mgr.channel_records[casefold("#test")]

        await bot.channel_mgr.apply_record(
            ChannelRecord.new(
                "#test",
                None,
                present=True,
                after=current.revision,
            ),
        )
        assert runtime.key is None

        coordinator = FakeCoordinator()
        bot.coordinator = coordinator
        await bot.channel_mgr.record_key("#test", "recordkey")

        assert runtime.key == "recordkey"
        record = bot.channel_mgr.channel_records[casefold("#test")]
        assert record.key == "recordkey"
        assert coordinator.channel_puts == [("#test", record.to_dict())]

    async def test_record_key_skips_unchanged_value(self) -> None:
        """Avoid a new durable revision when the key is unchanged."""
        bot = bot_with_channel()
        current = bot.channel_mgr.channel_records[casefold("#test")]
        record = ChannelRecord.new(
            "#test",
            "same-key",
            present=True,
            after=current.revision,
        )
        await bot.channel_mgr.apply_record(record)
        coordinator = FakeCoordinator()
        bot.coordinator = coordinator

        await bot.channel_mgr.record_key("#test", "same-key")

        assert coordinator.channel_puts == []
        assert bot.channel_mgr.channel_records[casefold("#test")] == record

    async def test_record_key_retries_failed_publish(self) -> None:
        """Retry a live channel-key record after JetStream recovers."""
        bot = bot_with_channel()
        bot.coordinator = FailingPublishCoordinator()

        await bot.channel_mgr.record_key("#test", "recordkey")

        assert casefold("#test") in bot.channel_mgr.pending_records
        coordinator = FakeCoordinator()
        bot.coordinator = coordinator
        await bot.channel_mgr.retry_pending_records()

        assert not bot.channel_mgr.pending_records
        assert coordinator.channel_puts[0][1]["key"] == "recordkey"

    async def test_record_retry_keeps_newer_pending_update(self) -> None:
        """Keep a newer pending record that arrives during an older retry."""
        bot = bot_with_channel()
        folded = casefold("#test")
        current = bot.channel_mgr.channel_records[folded]
        old = ChannelRecord.new(
            "#test",
            "old-key",
            present=True,
            after=current.revision,
        )
        await bot.channel_mgr.apply_record(old)
        bot.channel_mgr.pending_records[folded] = old
        started = asyncio.Event()
        release = asyncio.Event()

        async def put_channel(
            channel: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            del channel
            started.set()
            await release.wait()
            return record

        coordinator = FakeCoordinator()
        bot.coordinator = coordinator
        with patch.object(
            coordinator,
            "put_channel",
            AsyncMock(side_effect=put_channel),
        ):
            retry = asyncio.create_task(bot.channel_mgr.retry_pending_records())
            await started.wait()
            newer = ChannelRecord.new(
                "#test",
                "new-key",
                present=True,
                after=old.revision,
            )
            await bot.channel_mgr.apply_record(newer)
            bot.channel_mgr.pending_records[folded] = newer
            release.set()
            await retry

        assert bot.channel_mgr.pending_records[folded] == newer

    async def test_record_key_applies_authoritative_winner(self) -> None:
        """Converge local channel state when a newer durable mutation wins."""
        bot = bot_with_channel()
        coordinator = FakeCoordinator()
        bot.coordinator = coordinator
        winner: ChannelRecord | None = None

        async def put_channel(
            channel: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            nonlocal winner
            incoming = ChannelRecord.from_dict(record)
            winner = ChannelRecord.new(
                channel,
                "durablekey",
                present=True,
                after=incoming.revision,
            )
            return winner.to_dict()

        with patch.object(
            coordinator,
            "put_channel",
            AsyncMock(side_effect=put_channel),
        ):
            await bot.channel_mgr.record_key("#test", "stale-key")

        assert winner is not None
        assert bot.channel_mgr.channel_records[casefold("#test")] == winner
        assert bot.channel_mgr.channels[casefold("#test")].key == "durablekey"

    async def test_safe_join_unsendable_key(self) -> None:
        """Verify safe join handles unsendable channel keys gracefully."""
        bot = bot_with_channel()

        class RejectingIRC(FakeIRC):
            """IRC stub that rejects join with invalid key characters."""

            async def join(self, channel: str, key: str | None = None) -> None:
                """Raise ValueError to simulate unsendable parameters."""
                del channel, key
                msg = "IRC parameter contains unsupported characters"
                raise ValueError(msg)

        bot.irc = RejectingIRC()

        with self.assertLogs("botnats.channel", level="WARNING"):
            await bot.channel_mgr.safe_join("#test", "bad key")
