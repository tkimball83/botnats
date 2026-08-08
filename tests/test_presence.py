# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for bot presence matching and registry expiry."""

import unittest

from botnats.irc import Prefix
from botnats.presence import BotPresence, PresenceRegistry


class PresenceTests(unittest.TestCase):
    """Tests for presence matching, expiry, and update semantics."""

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
        """Verify from_dict and to_dict produce equivalent presences."""
        original = BotPresence("alpha", "host", "instance", "Alpha", "user")
        restored = BotPresence.from_dict(original.to_dict())
        assert original == restored

    def test_presence_expiry(self) -> None:
        """Verify presence entries expire after TTL."""
        registry = PresenceRegistry(ttl=10)
        presence = BotPresence("vhagar", "host", "instance", "vhagar", "user")
        registry.update(presence, now=5)

        assert registry.active(now=14.9) == (presence,)
        assert registry.active(now=15) == ()

    def test_presence_matching(self) -> None:
        """Verify presence matches prefix by nick, user, and host."""
        presence = BotPresence("vhagar", "host.example", "instance", "Vhagar", "~bot")

        assert presence.matches(Prefix("vhagar", "~bot", "HOST.EXAMPLE"))
        assert not presence.matches(Prefix("vhagar", "someone", "host.example"))

    def test_presence_membership(self) -> None:
        """Verify exact presence membership uses the current bot entry."""
        registry = PresenceRegistry(ttl=10)
        old = BotPresence("vhagar", "old.host", "instance", "vhagar", "user")
        current = BotPresence("vhagar", "new.host", "instance", "Vhagar", "user")
        registry.update(current, now=5)

        assert registry.has(current, now=14.9)
        assert not registry.has(old, now=14.9)
        assert not registry.has(current, now=15.1)

    def test_presence_update_overwrites(self) -> None:
        """Verify presence update overwrites previous entry."""
        registry = PresenceRegistry(ttl=10)
        old = BotPresence("vhagar", "old.host", "instance", "vhagar", "user")
        registry.update(old, now=5)
        new = BotPresence("vhagar", "new.host", "instance", "Vhagar", "user")
        registry.update(new, now=12)

        active = registry.active(now=14.9)
        assert len(active) == 1
        assert active[0].host == "new.host"
        assert registry.active(now=22.1) == ()

    def test_presence_remove(self) -> None:
        """Remove an expired presence immediately from a watch deletion."""
        registry = PresenceRegistry(ttl=10)
        presence = BotPresence("Vhagar", "host", "instance", "Vhagar", "user")
        registry.update(presence, now=5)

        registry.remove("vhagar")

        assert registry.active(now=6) == ()
