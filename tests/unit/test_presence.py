# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for bot presence records, registry expiry, and identity discovery."""

import asyncio
import unittest
from dataclasses import asdict
from typing import TYPE_CHECKING
from unittest.mock import patch

from botnats.irc.protocol import IRCMessage
from botnats.presence import BotPresence, PresenceRegistry
from tests.unit.helpers import FakeIRC, make_bot

if TYPE_CHECKING:
    from botnats.bot import Bot


class PresenceTests(unittest.TestCase):
    """Tests for presence parsing, expiry, and update semantics."""

    def test_from_dict_rejects_invalid_input(self) -> None:
        """Verify from_dict rejects non-dict, missing, and empty fields."""
        base = {
            "bot_id": "b",
            "host": "h",
            "instance_id": "i",
            "nick": "n",
            "user": "u",
        }
        with self.assertRaises(TypeError):
            BotPresence.from_dict("not a dict")

        with self.assertRaises(ValueError):
            BotPresence.from_dict({**base, "bot_id": ""})

        with self.assertRaises(ValueError):
            BotPresence.from_dict({**base, "nick": 42})

        with self.assertRaises(ValueError):
            BotPresence.from_dict({"bot_id": "b"})

    def test_from_dict_round_trip(self) -> None:
        """Verify from_dict restores a presence serialized by asdict."""
        original = BotPresence("alpha", "host", "instance", "Alpha", "user")
        restored = BotPresence.from_dict(asdict(original))
        assert original == restored

    def test_presence_expiry(self) -> None:
        """Verify presence entries expire after TTL."""
        registry = PresenceRegistry(ttl=10)
        presence = BotPresence("vhagar", "host", "instance", "vhagar", "user")
        registry.update(presence, now=5)

        assert registry.active(now=14.9) == (presence,)
        assert registry.active(now=15) == ()

    def test_presence_membership(self) -> None:
        """Verify exact presence membership uses the current bot entry."""
        registry = PresenceRegistry(ttl=10)
        # A mixed-case bot ID: entries are keyed by its casefold.
        old = BotPresence("Vhagar", "old.host", "instance", "vhagar", "user")
        current = BotPresence("Vhagar", "new.host", "instance", "Vhagar", "user")
        registry.update(current, now=5)

        assert registry.has(current, now=14.9)
        assert not registry.has(old, now=14.9)
        assert not registry.has(current, now=15.1)

    def test_presence_update_overwrites(self) -> None:
        """Verify presence update overwrites the previous entry and deadline."""
        registry = PresenceRegistry(ttl=10)
        old = BotPresence("vhagar", "old.host", "instance", "vhagar", "user")
        registry.update(old, now=5)
        new = BotPresence("vhagar", "new.host", "instance", "Vhagar", "user")
        registry.update(new, now=12)

        # Past the old entry's deadline (15), within the new one's (22).
        active = registry.active(now=15.5)
        assert len(active) == 1
        assert active[0].host == "new.host"
        assert registry.active(now=22.1) == ()

    def test_presence_prune_removes_expired(self) -> None:
        """Drop only entries whose heartbeat deadline has passed."""
        registry = PresenceRegistry(ttl=10)
        stale = BotPresence("old", "host", "one", "old", "user")
        live = BotPresence("new", "host", "two", "new", "user")
        registry.update(stale, now=0)
        registry.update(live, now=5)

        registry.prune(now=12)

        assert list(registry.entries) == ["new"]

    def test_presence_remove(self) -> None:
        """Remove a presence immediately on a watch deletion."""
        registry = PresenceRegistry(ttl=10)
        presence = BotPresence("Vhagar", "host", "instance", "Vhagar", "user")
        registry.update(presence, now=5)

        registry.remove("VHAGAR")

        assert registry.active(now=6) == ()

    def test_presence_peers_exclude_own_id(self) -> None:
        """Exclude this bot from its peers whatever the case of either bot ID."""
        # The TTL outlasts the test, since peers() reads the monotonic clock.
        registry = PresenceRegistry(ttl=3600)
        own = BotPresence("Alpha", "host", "one", "alpha", "user")
        peer = BotPresence("Beta", "host", "two", "beta", "user")
        registry.update(own)
        registry.update(peer)

        assert registry.peers("aLPHA") == (peer,)


class SelfIdentityTests(unittest.IsolatedAsyncioTestCase):
    """Tests for discovering this bot's own IRC identity."""

    async def test_identity_discovery_accepts_final_response(self) -> None:
        """Allow the final identity query time to receive its response."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        # USERHOST asks about the nick in use, here a fallback.
        fake_irc.current_nick = "alpha_"

        async def receive_identity(delay: float) -> None:
            del delay
            bot.identity.current = BotPresence("alpha", "host", "one", "alpha", "user")

        with (
            patch("botnats.presence.IDENTITY_RETRY_ATTEMPTS", 1),
            patch("botnats.presence.asyncio.sleep", receive_identity),
        ):
            await bot.identity.discover(bot.identity.generation)

        assert fake_irc.sent == [("USERHOST", ("alpha_",))]
        assert fake_irc.reconnects == 0

    async def test_identity_discovery_stops_after_reset(self) -> None:
        """Stop a discovery whose connection reset while it waited for a reply."""
        # With two attempts the check before the second USERHOST sees the
        # reset; with one, only the check before reconnecting does.
        for attempts in (1, 2):
            fake_irc = FakeIRC()
            bot = make_bot(irc=fake_irc)
            fake_irc.current_nick = "alpha_"
            generation = bot.identity.generation

            async def reset_identity(delay: float, bot: Bot = bot) -> None:
                del delay
                bot.identity.reset()

            with (
                self.subTest(attempts=attempts),
                patch("botnats.presence.IDENTITY_RETRY_ATTEMPTS", attempts),
                patch("botnats.presence.asyncio.sleep", reset_identity),
            ):
                async with asyncio.timeout(1):
                    await bot.identity.discover(generation)

                assert bot.identity.generation == generation + 1
                assert fake_irc.sent == [("USERHOST", ("alpha_",))]
                assert fake_irc.reconnects == 0

    async def test_identity_discovery_reconnects(self) -> None:
        """Verify bot reconnects when identity discovery exhausts retries."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        with (
            patch("botnats.presence.IDENTITY_RETRY_ATTEMPTS", 1),
            patch("botnats.presence.IDENTITY_RETRY_DELAY", 0),
            self.assertLogs("botnats.presence", level="WARNING"),
        ):
            bot.events.handle_welcome(IRCMessage("001", ("alpha", "welcome")))
            tasks = tuple(bot.tasks)
            async with asyncio.timeout(1):
                await asyncio.gather(*tasks)

        assert fake_irc.sent == [("USERHOST", ("alpha",))]
        assert fake_irc.reconnects == 1
