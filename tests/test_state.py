# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for channel record ordering and runtime state."""

import unittest

from botnats.channel import ChannelRecord, ChannelRuntime
from botnats.irc import Prefix

PRE_MERGE_MEMBER_COUNT = 2


class StateTests(unittest.TestCase):
    """Tests for channel record ordering and runtime state management."""

    def setUp(self) -> None:
        """Reset process-global revision counter between tests."""
        ChannelRecord.last_revision = 0

    def test_channel_record_injection(self) -> None:
        """Verify channel record rejects injection in channel names."""
        unsafe = {
            "channel": "#safe\r\nOPER root pass",
            "key": None,
            "present": True,
            "revision": "00000000000000000001-0123456789abcdef0123456789abcdef",
        }

        with self.assertRaisesRegex(ValueError, "unsupported characters"):
            ChannelRecord.from_dict(unsafe)

    def test_channel_revision_ordering(self) -> None:
        """Verify channel record revision ordering and serialization."""
        update = ChannelRecord.new("#test", "key", present=True)
        tombstone = ChannelRecord.new(
            "#test",
            None,
            present=False,
            after=update.revision,
        )

        assert tombstone.revision > update.revision
        assert ChannelRecord.from_dict(tombstone.to_dict()) == tombstone

    def test_channel_revision_validation(self) -> None:
        """Verify malformed revisions cannot permanently outrank valid updates."""
        for revision in ("", "1", "z", "0" * 20 + "-not-hex"):
            with (
                self.subTest(revision=revision),
                self.assertRaisesRegex(ValueError, "invalid revision"),
            ):
                ChannelRecord.from_dict(
                    {
                        "channel": "#safe",
                        "key": None,
                        "present": True,
                        "revision": revision,
                    },
                )

    def test_member_reuses_entry(self) -> None:
        """Verify repeated member lookups reuse the tracked object."""
        runtime = ChannelRuntime()

        member = runtime.member("User")

        assert runtime.member("user") is member
        assert member.nick == "user"

    def test_set_casemapping_member_collision(self) -> None:
        """Verify casemapping change merges colliding member entries."""
        runtime = ChannelRuntime(casemapping="ascii")

        runtime.member("user[").prefix = Prefix("user[", "u", "host")
        runtime.member("user{").prefix = Prefix("user{", "u", "host")
        assert len(runtime.members) == PRE_MERGE_MEMBER_COUNT

        runtime.set_casemapping("rfc1459")
        assert len(runtime.members) == 1

    def test_set_key_validation(self) -> None:
        """Verify runtime set_key rejects invalid keys."""
        runtime = ChannelRuntime()
        runtime.key = "old-key"

        assert not runtime.set_key("bad key")
        assert runtime.key == "old-key"

        assert runtime.set_key("new-key")
        assert runtime.key == "new-key"

        assert runtime.set_key(None)
        assert runtime.key is None
