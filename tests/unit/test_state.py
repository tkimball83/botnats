# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for channel record ordering and runtime state."""

import unittest
from dataclasses import asdict

from botnats.channel import ChannelRecord, ChannelRuntime, revision_number
from botnats.irc.protocol import ISupportState
from botnats.validators import MAX_CHANNEL_REVISION, validate_channel_revision


class StateTests(unittest.TestCase):
    """Tests for channel record ordering and runtime state management."""

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

    def test_channel_revision_requires_ascii_digits(self) -> None:
        """Reject revision counters written with non-ASCII decimal digits."""
        arabic_indic = "\u0660" * 19 + "\u0661"
        assert int(arabic_indic) == 1
        with self.assertRaisesRegex(ValueError, "invalid revision"):
            validate_channel_revision(f"{arabic_indic}-{'0' * 32}")

        validate_channel_revision(f"{'0' * 19}1-{'0' * 32}")

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

    def test_channel_revision_validation(self) -> None:
        """Verify malformed revisions cannot permanently outrank valid updates."""
        suffix = "0" * 32
        for revision in (
            None,
            "",
            "1",
            "z",
            "0" * 20 + "-not-hex",
            f"{MAX_CHANNEL_REVISION + 1:020d}-{suffix}",
        ):
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

        validate_channel_revision(f"{MAX_CHANNEL_REVISION:020d}-{suffix}")

    def test_new_record_rejects_counter_past_maximum(self) -> None:
        """Refuse to build on an invalid revision or past the last counter."""
        suffix = "0" * 32
        with self.assertRaisesRegex(ValueError, "invalid revision"):
            ChannelRecord.new(
                "#test",
                None,
                present=True,
                after=f"{MAX_CHANNEL_REVISION + 1:020d}-{suffix}",
            )

        with self.assertRaisesRegex(ValueError, "counter is exhausted"):
            ChannelRecord.new(
                "#test",
                None,
                present=True,
                after=f"{MAX_CHANNEL_REVISION:020d}-{suffix}",
            )

    def test_member_reuses_entry(self) -> None:
        """Verify repeated member lookups reuse the tracked object."""
        runtime = ChannelRuntime(ISupportState())

        member = runtime.member("User")

        assert runtime.member("user") is member
        assert member.nick == "user"

    def test_set_key_validation(self) -> None:
        """Verify runtime set_key rejects invalid keys."""
        runtime = ChannelRuntime(ISupportState())
        runtime.key = "old-key"

        assert not runtime.set_key("bad key")
        assert runtime.key == "old-key"

        assert runtime.set_key("new-key")
        assert runtime.key == "new-key"

        assert runtime.set_key(None)
        assert runtime.key is None
