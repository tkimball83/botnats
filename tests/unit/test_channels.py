# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for channel management, join, part, and lifecycle."""

import asyncio
import unittest
from dataclasses import asdict, replace
from unittest.mock import AsyncMock, patch

from botnats.bot import Bot
from botnats.channel import ChannelRecord, ChannelRuntime, JoinState
from botnats.config import mode_intent
from botnats.irc.protocol import Prefix, casefold
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


async def settle(bot: Bot) -> None:
    """Wait for background tasks, including any the finished ones spawned."""
    while bot.tasks:
        await asyncio.gather(*bot.tasks)


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
        bot.channel_mgr.mode_intent = mode_intent(bot.config.channel_modes)
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
        old_folded = casefold("#Test[]")
        record = bot.channel_mgr.new_record(
            "#Test[]",
            None,
            present=True,
        )
        bot.channel_mgr.channel_records[old_folded] = record
        bot.channel_mgr.source_records[casefold(record.channel, "ascii")] = record
        bot.channel_mgr.channels[old_folded] = ChannelRuntime(
            casemapping="rfc1459",
            channel="#Test[]",
        )

        bot.channel_mgr.set_casemapping("ascii")

        new_folded = casefold("#Test[]", "ascii")
        assert new_folded in bot.channel_mgr.channels
        assert new_folded in bot.channel_mgr.channel_records
        assert bot.authorizer.authorized("nick[!~user@host.example")
        assert not bot.authorizer.authorized("nick{!~user@host.example")

    async def test_casemapping_change_preserves_colliding_records(self) -> None:
        """Keep records that collide temporarily under one server casemapping."""
        bot = Bot(config())
        first = bot.channel_mgr.new_record("#room[", "first", present=True)
        second = bot.channel_mgr.new_record("#room{", "second", present=True)

        await bot.channel_mgr.apply_record(first)
        await bot.channel_mgr.apply_record(second)
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
        bot = Bot(config(), irc=fake_irc)
        bot.channel_mgr.set_casemapping("ascii")
        joined = bot.channel_mgr.new_record("#room[", None, present=True)
        await bot.channel_mgr.apply_record(joined)
        bot.channel_mgr.channels[casefold("#room[", "ascii")].join = JoinState.JOINED
        tombstone = bot.channel_mgr.new_record("#room{", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        bot.channel_mgr.set_casemapping("rfc1459")

        folded = casefold("#room{")
        assert folded not in bot.channel_mgr.channels
        assert bot.channel_mgr.pending_parts == {folded: "#room["}

        await bot.channel_mgr.retry_pending_parts()
        assert ("PART", ("#room[",)) in fake_irc.sent
        assert bot.channel_mgr.pending_parts == {}

    async def test_flush_cancellation_does_not_respawn(self) -> None:
        """Verify a cancelled op-flush does not resurrect a background task."""
        bot, _ = bot_with_irc()
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        folded = casefold("#test")
        bot.channel_mgr.channels[folded].join = JoinState.JOINED
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
        assert not bot.channel_mgr.channels[folded].op_flush_scheduled

    async def test_join_part_nats_failure(self) -> None:
        """Verify join and part commands handle NATS publish failures."""
        coordinator = FailingPublishCoordinator()
        fake_irc = FakeIRC()
        bot = bot_with_channel(irc=fake_irc, coordinator=coordinator)
        prefix = Prefix("owner", "user", "real.host")
        bot.authorizer.grant(prefix.render())

        await bot.commands.dispatch(prefix, "JOIN #new")
        await bot.commands.dispatch(prefix, "PART #test")

        assert casefold("#new") not in bot.channel_mgr.channels
        assert casefold("#test") in bot.channel_mgr.channels
        assert len(fake_irc.privmsgs) == 2

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
        fake_irc = FakeIRC()
        bot = Bot(config(), irc=fake_irc)
        bot.identity.current = BotPresence(
            "alpha", "alpha.host", "inst", "alpha", "~alpha"
        )
        bot.identity.registered = True
        first = bot.channel_mgr.new_record("#first", "first-key", present=True)
        second = bot.channel_mgr.new_record("#second", "second-key", present=True)

        await bot.channel_mgr.apply_record(first)
        await bot.channel_mgr.apply_record(second)
        first_runtime = bot.channel_mgr.runtime("#first")
        second_runtime = bot.channel_mgr.runtime("#second")
        assert first_runtime is not None
        assert second_runtime is not None
        first_runtime.join = JoinState.JOINED
        second_runtime.join = JoinState.JOINED

        await bot.channel_mgr.apply_record(
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

    async def test_part_before_join_echoed(self) -> None:
        """Verify part is sent even when channel was never fully joined."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        assert not runtime.joined

        tombstone = bot.channel_mgr.new_record("#test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test") not in bot.channel_mgr.channels
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_part_cleared_on_re_desired(self) -> None:
        """Verify re-desiring a case-equivalent channel clears its pending part."""
        bot = bot_with_channel(irc=FailingPartIRC())

        tombstone = bot.channel_mgr.new_record("#Test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)
        assert "#test" in bot.channel_mgr.pending_parts

        rejoin = bot.channel_mgr.new_record(
            "#test",
            None,
            present=True,
            after=tombstone.revision,
        )
        await bot.channel_mgr.apply_record(rejoin)

        assert "#test" not in bot.channel_mgr.pending_parts
        assert casefold("#test") in bot.channel_mgr.channels

    async def test_part_clears_transient_state(self) -> None:
        """Verify parting clears cooldowns and queued operator grants."""
        bot, _ = bot_with_irc()
        folded = bot.caps.fold("#test")
        manager = bot.channel_mgr
        runtime = manager.channels[folded]
        runtime.cooldowns.update({"invite": 1, "op": 1, "unban": 1})
        runtime.pending_ops["beta"] = BotPresence("beta", "h", "i", "beta", "u")
        current = bot.channel_mgr.channel_records[folded]

        await manager.apply_record(
            bot.channel_mgr.new_record(
                "#test",
                None,
                present=False,
                after=current.revision,
            ),
        )

        # The channel's owner, with its cooldowns and queued grants, is gone.
        assert folded not in manager.channels

    async def test_part_queued_on_failure(self) -> None:
        """Verify failed part is queued and retried on next maintenance tick."""
        fake_irc = FailingPartIRC()
        bot = bot_with_channel(irc=fake_irc)
        bot.identity.registered = True

        tombstone = bot.channel_mgr.new_record("#test", None, present=False)
        await bot.channel_mgr.apply_record(tombstone)

        assert casefold("#test") not in bot.channel_mgr.channels
        assert "#test" in bot.channel_mgr.pending_parts

        fake_irc.failing = False
        await bot.maintenance_tick()

        assert "#test" not in bot.channel_mgr.pending_parts
        assert ("PART", ("#test",)) in fake_irc.sent

    async def test_part_tombstone_precedence(self) -> None:
        """Verify tombstone record takes precedence over stale join."""
        bot = Bot(config())
        join = bot.channel_mgr.new_record("#test", None, present=True)
        tombstone = bot.channel_mgr.new_record(
            "#test",
            None,
            present=False,
            after=join.revision,
        )

        await bot.channel_mgr.apply_record(join)
        await bot.channel_mgr.apply_record(tombstone)
        await bot.channel_mgr.apply_record(join)

        assert casefold("#test") not in bot.channel_mgr.channels
        assert bot.channel_mgr.channel_records[casefold("#test")] == tombstone

    async def test_record_key_is_versioned(self) -> None:
        """Verify newer channel records authoritatively update the key."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(irc=FakeIRC(), coordinator=coordinator)
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.key = "livekey"
        current = bot.channel_mgr.channel_records[casefold("#test")]

        await bot.channel_mgr.apply_record(
            bot.channel_mgr.new_record(
                "#test",
                None,
                present=True,
                after=current.revision,
            ),
        )
        assert runtime.key is None

        await bot.channel_mgr.record_key("#test", "recordkey")

        assert runtime.key == "recordkey"
        record = bot.channel_mgr.channel_records[casefold("#test")]
        assert record.key == "recordkey"
        assert coordinator.channel_puts == [("#test", asdict(record))]

    async def test_record_key_skips_unchanged_value(self) -> None:
        """Avoid a new durable revision when the key is unchanged."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        current = bot.channel_mgr.channel_records[casefold("#test")]
        record = bot.channel_mgr.new_record(
            "#test",
            "same-key",
            present=True,
            after=current.revision,
        )
        await bot.channel_mgr.apply_record(record)

        await bot.channel_mgr.record_key("#test", "same-key")

        assert coordinator.channel_puts == []
        assert bot.channel_mgr.channel_records[casefold("#test")] == record

    async def test_record_key_retries_failed_publish(self) -> None:
        """Retry a live channel-key record after JetStream recovers."""
        coordinator = FailingPublishCoordinator()
        bot = bot_with_channel(coordinator=coordinator)

        await bot.channel_mgr.record_key("#test", "recordkey")

        assert casefold("#test") in bot.channel_mgr.pending_records
        coordinator.failing = False
        await bot.channel_mgr.retry_pending_records()

        assert not bot.channel_mgr.pending_records
        assert coordinator.channel_puts[0][1]["key"] == "recordkey"

    async def test_record_retry_keeps_newer_pending_update(self) -> None:
        """Keep a newer pending record that arrives during an older retry."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test")
        current = bot.channel_mgr.channel_records[folded]
        old = bot.channel_mgr.new_record(
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

        with patch.object(
            coordinator,
            "put_channel",
            AsyncMock(side_effect=put_channel),
        ):
            retry = asyncio.create_task(bot.channel_mgr.retry_pending_records())
            await started.wait()
            newer = bot.channel_mgr.new_record(
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

    async def test_record_key_defers_local_apply_to_durable_write(self) -> None:
        """Apply only the record the durable store returns on success."""
        coordinator = FakeCoordinator()
        bot = bot_with_channel(coordinator=coordinator)
        folded = casefold("#test")
        before = bot.channel_mgr.channel_records[folded]
        seen: list[ChannelRecord] = []

        async def put_channel(
            channel: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            del channel
            seen.append(bot.channel_mgr.channel_records[folded])
            return record

        with patch.object(
            coordinator,
            "put_channel",
            AsyncMock(side_effect=put_channel),
        ):
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
            channel: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            nonlocal winner
            incoming = ChannelRecord.from_dict(record)
            winner = bot.channel_mgr.new_record(
                channel,
                "durablekey",
                present=True,
                after=incoming.revision,
            )
            return asdict(winner)

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

        with self.assertLogs("botnats.channel", level="WARNING"):
            runtime = bot.channel_mgr.channels[casefold("#test")]
            runtime.key = "bad key"
            await bot.channel_mgr.safe_join(runtime)

    async def test_disconnected_bot_does_not_help(self) -> None:
        """Verify a bot with a closing IRC socket does not act on a peer request."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "peer.host", "one", "beta", "user")
        runtime.member("beta").prefix = peer.to_prefix()
        bot.presence.update(peer)
        fake_irc.connected = False

        assert (
            bot.channel_mgr.help_eligible(
                {"channel": "#test", "presence": asdict(peer)}
            )
            is None
        )

    async def test_help_request_rechecks_state_after_delay(self) -> None:
        """Act on a peer's op request after the delay, unless already helped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        runtime.member("beta").prefix = peer.to_prefix()
        payload = {"channel": "#test", "presence": asdict(peer)}

        with patch("botnats.channel.PEER_HELP_DELAY", 0):
            bot.callbacks.on_op(payload)
            await settle(bot)
            assert fake_irc.modes == [("#test", "+o", ("beta",))]

            # Another peer opped beta first: this bot sends nothing more.
            runtime.member("beta").modes.add("o")
            bot.callbacks.on_op(payload)
            await settle(bot)

        assert fake_irc.modes == [("#test", "+o", ("beta",))]

    async def test_invite_peer(self) -> None:
        """Verify an invite request sends an INVITE command for a known peer."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "beta.host", "one", "beta", "~beta")
        bot.presence.update(peer)

        await bot.channel_mgr.invite_peer(
            {"channel": "#test", "presence": asdict(peer)},
        )

        assert fake_irc.sent == [("INVITE", ("beta", "#test"))]

    async def test_op_batching(self) -> None:
        """Verify multiple op requests batch into a single MODE command."""
        bot, fake_irc = bot_with_irc()
        bot.caps.mode_limit = 4
        runtime = bot.channel_mgr.channels[casefold("#test")]
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
            await bot.channel_mgr.op_peer(
                {"channel": "#test", "presence": asdict(peer)}
            )

        async with asyncio.timeout(5):
            await asyncio.gather(*bot.tasks)
        assert fake_irc.modes == [("#test", "+oo", ("beta", "gamma"))]

    async def test_op_requires_matching_host(self) -> None:
        """Verify op request is rejected when peer host does not match."""
        bot, _ = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        peer = BotPresence("beta", "real.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        runtime.member("beta").prefix = Prefix("beta", "~beta", "stolen.host")

        assert (
            bot.channel_mgr.help_eligible(
                {"channel": "#test", "presence": asdict(peer)}
            )
            is None
        )

    async def test_unban_matching_masks(self) -> None:
        """Verify an unban request removes only matching ban masks."""
        bot, fake_irc = bot_with_irc()
        bot.caps.mode_limit = 4
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.member("alpha").modes.add("o")
        for _mask in ("*!~beta@bot.host", "*!other@*"):
            runtime.add_ban(_mask)

        peer = BotPresence("beta", "bot.host", "one", "beta", "~beta")
        bot.presence.update(peer)
        payload = {"channel": "#test", "presence": asdict(peer)}

        await bot.channel_mgr.unban_peer(payload)

        assert fake_irc.modes == [("#test", "-b", ("*!~beta@bot.host",))]
