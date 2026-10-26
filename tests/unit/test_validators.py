# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC channel, key, JOIN, and target validation."""

import unittest

from botnats.validators import (
    validate_channel,
    validate_join,
    validate_key,
    validate_target,
)


class ValidatorTests(unittest.TestCase):
    """Tests for validating IRC parameters before they are sent or stored."""

    def test_validate_channel(self) -> None:
        """Verify channel name validation accepts and rejects correctly."""
        for valid in ("#general", "&local", "+modeless", "!ABCDEsafe"):
            assert validate_channel(valid) == valid

        for invalid in (
            "#",
            "general",
            "#bad channel",
            "#bad\tchannel",
            "#bad,channel",
            "#bad\x07channel",
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "channel"),
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

    def test_validate_target(self) -> None:
        """Verify command target and ban-mask validation."""
        assert validate_target("*!*@evil.example") == "*!*@evil.example"
        for invalid in ("", ":nick", "*!*@ evil", "mask\twith\ttabs", "nul\x00"):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "target"),
            ):
                validate_target(invalid)
