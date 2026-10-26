# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC channel, key, JOIN, server URL, and channel revision validation."""

import re
import unittest

from botnats.validators import (
    MAX_CHANNEL_REVISION,
    parse_channel_record,
    validate_channel,
    validate_channel_revision,
    validate_join,
    validate_key,
    validate_server_url,
)


class ValidatorTests(unittest.TestCase):
    """Tests for validating IRC parameters before they are sent or stored."""

    def test_validate_channel(self) -> None:
        """Verify channel name validation accepts and rejects correctly."""
        for valid in ("#general", "&local", "+modeless", "!ABCDEsafe"):
            assert validate_channel(valid) == valid

        for invalid, message in (
            ("#", "channel name is empty"),
            ("", "channel must start with #, &, +, or !"),
            ("x", "channel must start with #, &, +, or !"),
            ("general", "channel must start with #, &, +, or !"),
            ("#bad channel", "channel contains unsupported characters"),
            ("#bad\tchannel", "channel contains unsupported characters"),
            ("#bad,channel", "channel contains unsupported characters"),
            ("#bad\x07channel", "channel contains unsupported characters"),
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, f"^{re.escape(message)}$"),
            ):
                validate_channel(invalid)

    def test_validate_key(self) -> None:
        """Verify channel key validation accepts and rejects correctly."""
        assert validate_key("safe-key") == "safe-key"
        for invalid in (
            "",
            ":key",
            "two words",
            "one,two",
            "safe\r\nOPER root pass",
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "channel key"),
            ):
                validate_key(invalid)

    def test_validate_join_message_size_and_encoding(self) -> None:
        """Reject malformed JOIN parameters and those no IRC message fits."""
        # The comma passes format_message, so only the channel or key check
        # rejects it.
        invalid = (
            ("#bad,channel", None),
            ("#test", "one,two"),
            ("#" + "a" * 510, None),
            ("#test", "k" * 510),
            ("#" + chr(0xD800), None),
        )
        for channel, key in invalid:
            with self.subTest(channel=channel, key=key), self.assertRaises(ValueError):
                validate_join(channel, key)

    def test_validate_server_url(self) -> None:
        """Reject unsupported URL schemes, components, and ports."""
        schemes = frozenset({"nats"})
        assert validate_server_url("nats://host:4222", schemes, "NATS") == (
            "nats",
            "host",
            4222,
        )
        assert validate_server_url("nats://host", schemes, "NATS") == (
            "nats",
            "host",
            None,
        )
        for invalid in (
            "http://host:4222",
            "nats://host:4222?name=x",
            "nats://host:4222#x",
            "nats://host:",
            "nats://host:bad",
            "nats://host:0",
            "nats://host:70000",
            "nats://host/stream",
            "nats://user@host:4222",
            "nats://user:secret@host:4222",
            "nats://ho\x1bst:4222",
            "nats://ho\x7fst:4222",
            "nats://" + chr(0xD800) + ":4222",
        ):
            # The exact message never echoes the URL or a credential in it.
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "^invalid NATS server URL$"),
            ):
                validate_server_url(invalid, schemes, "NATS")

    def test_channel_revision_requires_ascii_digits(self) -> None:
        """Reject revision counters written with non-ASCII decimal digits."""
        arabic_indic = "\u0660" * 19 + "\u0661"
        assert int(arabic_indic) == 1
        with self.assertRaisesRegex(ValueError, "invalid revision"):
            validate_channel_revision(f"{arabic_indic}-{'0' * 32}")

        valid = f"{'0' * 19}1-{'0' * 32}"
        assert validate_channel_revision(valid) == valid

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
                parse_channel_record(
                    {
                        "channel": "#safe",
                        "key": None,
                        "present": True,
                        "revision": revision,
                    },
                )

        # The same record with the highest valid revision parses.
        newest = f"{MAX_CHANNEL_REVISION:020d}-{suffix}"
        assert parse_channel_record(
            {"channel": "#safe", "key": None, "present": True, "revision": newest},
        ) == ("#safe", None, True, newest)
