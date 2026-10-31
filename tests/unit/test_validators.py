# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC channel, key, JOIN, server URL, and channel record validation."""

import re
import unittest

from botnats.validators import (
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
        # A safe channel takes its full name, the server's channel ID first.
        for valid in ("#general", "&local", "+modeless", "!ABCDEsafe", "!0Z9A8s"):
            assert validate_channel(valid) == valid

        bad_start = "channel must start with #, &, +, or ! and a 5-character channel ID"
        for invalid, message in (
            ("#", "channel name is empty"),
            ("", bad_start),
            ("x", bad_start),
            ("general", bad_start),
            # Short names, a creation request, and an ID with no short name.
            ("!safe", bad_start),
            ("!ABCDsafe", bad_start),
            ("!!safe", bad_start),
            ("!", bad_start),
            ("!ABCDE", bad_start),
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
            "nats://:4222",
            "nats://host:",
            "nats://host:bad",
            "nats://host:0",
            "nats://host:70000",
            "nats://host/stream",
            "nats://user@host:4222",
            "nats://user:secret@host:4222",
            "nats://:secret@host:4222",
            "nats://ho st:4222",
            # IDNA maps an ideographic space to an ASCII one.
            "nats://ho\u3000st:4222",
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

    def test_parse_channel_record_rejects_malformed_fields(self) -> None:
        """Reject a channel record whose channel, key, or presence is malformed."""
        record: dict[str, object] = {
            "channel": "#safe",
            "key": None,
            "present": True,
            "revision": f"{'0' * 19}1-{'0' * 32}",
        }
        assert parse_channel_record(record) == (
            "#safe",
            None,
            True,
            record["revision"],
        )

        # A missing key would read as no key, and 1 as True.
        keyless = {k: v for k, v in record.items() if k != "key"}
        for value, error, message in (
            ({**record, "channel": ["#safe"]}, TypeError, "invalid channel"),
            (keyless, ValueError, "invalid key"),
            ({**record, "key": 5}, ValueError, "invalid key"),
            ({**record, "channel": "#safe QUIT"}, ValueError, "channel contains"),
            ({**record, "key": "bad key"}, ValueError, "channel key contains"),
            ({**record, "present": 1}, TypeError, "invalid presence flag"),
        ):
            with self.subTest(value=value), self.assertRaisesRegex(error, message):
                parse_channel_record(value)

    def test_channel_revision_validation(self) -> None:
        """Verify malformed revisions cannot permanently outrank valid updates."""
        suffix = "0" * 32
        for revision in (
            None,
            "",
            "1",
            "z",
            "0" * 20 + "-not-hex",
            # The counter after the 20-digit maximum.
            f"{10**20}-{suffix}",
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
