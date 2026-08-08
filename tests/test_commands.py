# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for command parsing, input validation, and rate limiting."""

import unittest

from botnats.admin import RateLimiter, parse_command
from botnats.validators import (
    validate_channel,
    validate_join,
    validate_key,
    validate_target,
)


class CommandTests(unittest.TestCase):
    """Tests for command parsing, channel validation, and key validation."""

    def test_parse_preserves_backslash(self) -> None:
        """Verify backslashes in arguments are preserved, not shell-escaped."""
        name, arguments = parse_command("deop #chan Evil\\dude")

        assert name == "DEOP"
        assert arguments == ("#chan", "Evil\\dude")

    def test_validate_channel(self) -> None:
        """Verify channel name validation accepts and rejects correctly."""
        assert validate_channel("#general") == "#general"
        for invalid in (
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
        """Reject JOIN parameters that cannot fit in an IRC message."""
        invalid = (
            ("#" + "a" * 510, None),
            ("#test", "k" * 510),
            ("#" + chr(0xD800), None),
        )
        for channel, key in invalid:
            with self.subTest(channel=channel), self.assertRaises(ValueError):
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


class RateLimitTests(unittest.IsolatedAsyncioTestCase):
    """Tests for rate limiter windowing and bucket eviction."""

    async def test_bucket_eviction(self) -> None:
        """Verify the least recently used bucket is evicted at capacity."""
        limiter = RateLimiter(max_buckets=2)
        limiter.check("a", limit=10, window=60)
        limiter.check("b", limit=10, window=60)
        limiter.check("a", limit=10, window=60)
        limiter.check("c", limit=10, window=60)
        assert "a" in limiter.buckets
        assert "b" not in limiter.buckets
        assert "c" in limiter.buckets

    async def test_independent_keys(self) -> None:
        """Verify rate limits are tracked independently per key."""
        limiter = RateLimiter()
        assert limiter.check("alice", limit=1, window=60)
        assert limiter.check("bob", limit=1, window=60)
        assert not limiter.check("alice", limit=1, window=60)

    async def test_window_expiry(self) -> None:
        """Verify rate limit resets after window expires."""
        limiter = RateLimiter()
        assert limiter.check("user", limit=1, window=0.0)
        assert limiter.check("user", limit=1, window=0.0)

    async def test_within_limit(self) -> None:
        """Verify requests within limit are allowed and excess is denied."""
        limiter = RateLimiter()
        for _ in range(3):
            assert limiter.check("user", limit=3, window=60)
        assert not limiter.check("user", limit=3, window=60)
