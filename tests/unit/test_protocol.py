# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC protocol parsing, formatting, casemapping, and ISUPPORT state."""

import sys
import unittest
from typing import TYPE_CHECKING

from botnats.irc.protocol import (
    DEFAULT_CHANMODES,
    DEFAULT_MEMBERSHIP_MODES,
    MAX_IRC_MESSAGE_BYTES,
    IRCMessage,
    ISupportState,
    Prefix,
    casefold,
    format_message,
    iter_mode_changes,
    mask_matches,
    parse_message,
)

if TYPE_CHECKING:
    from types import FrameType

    from _typeshed import TraceFunction

# The linear matcher runs a few hundred lines on the adversarial mask.
MASK_MATCH_LINE_BUDGET = 10_000


class IRCProtocolTests(unittest.TestCase):
    """Tests for prefix matching, message parsing, modes, and ISUPPORT state."""

    def test_ban_mask_matching(self) -> None:
        """Verify ban mask matching against IRC prefixes."""
        prefix = Prefix("Bot[One]", "~user", "2001:db8::1")

        assert mask_matches("bot[one]!*@2001:db8::*", prefix, "rfc1459")
        assert mask_matches("*!~user@*", prefix, "rfc1459")
        assert not mask_matches("*!other@*", prefix, "rfc1459")

    def test_ban_mask_many_wildcards(self) -> None:
        """Fail a mask of many wildcards within a line budget, without backtracking.

        A recursive backtracking matcher runs millions of lines failing this
        nick, so it trips the budget long before it would finish.
        """
        prefix = Prefix("a" * 28, "user", "host")
        lines = 0

        def count_lines(frame: FrameType, event: str, arg: object) -> TraceFunction:
            nonlocal lines
            del frame, arg
            if event == "line":
                lines += 1
                if lines > MASK_MATCH_LINE_BUDGET:
                    msg = "mask matching ran past its line budget"
                    raise AssertionError(msg)

            return count_lines

        sys.settrace(count_lines)
        try:
            matched = mask_matches("*a" * 13 + "b!*@*", prefix, "rfc1459")
        finally:
            sys.settrace(None)

        assert not matched
        assert mask_matches("*a" * 13 + "!*@*", prefix, "rfc1459")

    def test_ban_mask_host_folding_uses_ascii(self) -> None:
        """Verify mask_matches folds user/host with ascii, not server casemapping."""
        prefix = Prefix("nick", "user[1]", "host[2]")

        assert mask_matches("nick!user[1]@host[2]", prefix, "rfc1459")
        assert not mask_matches("nick!user{1}@host{2}", prefix, "rfc1459")
        assert mask_matches("NICK!*@*", prefix, "rfc1459")
        assert not mask_matches("nick!user{1}@*", prefix, "rfc1459")

    def test_ban_mask_wildcards(self) -> None:
        """Verify single- and multi-character wildcards and non-matches."""
        prefix = Prefix("alice", "~alice", "host.example")

        assert mask_matches("a????!*@*", prefix, "rfc1459")
        assert mask_matches("*!*@host.example", prefix, "rfc1459")
        assert mask_matches("*", prefix, "rfc1459")
        assert not mask_matches("a???!*@*", prefix, "rfc1459")
        assert not mask_matches("bob!*@*", prefix, "rfc1459")
        # A literal "*" in an ident must not consume the mask's wildcard.
        assert mask_matches("*!*b@*", Prefix("alice", "*ab", "h"), "rfc1459")
        assert mask_matches("*!a*b@*", Prefix("alice", "a*xb", "h"), "rfc1459")

    def test_casefold(self) -> None:
        """Verify casefold applies correct mapping for each mode."""
        assert casefold("Nick[\\]^", "rfc1459") == "nick{|}~"
        assert casefold("Nick[\\]^", "strict-rfc1459") == "nick{|}^"
        assert casefold("Nick[\\]^", "ascii") == "nick[\\]^"

    def test_format_injection(self) -> None:
        """Verify format_message rejects parameter injection attempts."""
        unsafe = (
            ("JOIN", ("#safe\r\nOPER root password",), None),
            ("JOIN", ("#safe", "key with space"), None),
            ("NOTICE", ("owner",), "safe\nQUIT"),
            # A leading colon would turn a middle parameter into the trailing one.
            ("INVITE", (":owner", "#safe"), None),
            # An empty middle parameter would vanish, moving the trailing one up.
            ("KICK", ("#safe", ""), "reason"),
        )

        for command, params, trailing in unsafe:
            with (
                self.subTest(
                    params=params,
                    trailing=trailing,
                ),
                self.assertRaisesRegex(ValueError, "unsupported characters"),
            ):
                format_message(command, params, trailing)

    def test_mode_parser(self) -> None:
        """Verify mode string parsing yields correct add/remove tuples."""
        changes = list(
            iter_mode_changes(
                "+koo-v",
                ("key", "one", "two", "voice"),
                DEFAULT_CHANMODES,
                DEFAULT_MEMBERSHIP_MODES,
            ),
        )

        assert changes == [
            (True, "k", "key"),
            (True, "o", "one"),
            (True, "o", "two"),
            (False, "v", "voice"),
        ]

    def test_mode_parser_bare_unset_key_keeps_pairing(self) -> None:
        """Verify a stripped -k argument does not steal later arguments."""
        defaults = (DEFAULT_CHANMODES, DEFAULT_MEMBERSHIP_MODES)
        assert list(iter_mode_changes("-k+o", ("alpha",), *defaults)) == [
            (False, "k", None),
            (True, "o", "alpha"),
        ]
        # A conforming batch with the key present pairs exactly as before.
        assert list(iter_mode_changes("-k+o", ("key", "alpha"), *defaults)) == [
            (False, "k", "key"),
            (True, "o", "alpha"),
        ]

    def test_mode_parser_custom_modes(self) -> None:
        """Verify mode parser pairs arguments by the server's mode groups."""
        # Unlike the defaults, x takes an argument (type B), e takes none
        # (type D), and y is a membership mode.
        changes = list(
            iter_mode_changes(
                "+yxe-k",
                ("target", "xarg", "key"),
                ("b", "kx", "l", "eimn"),
                "oyv",
            ),
        )

        assert changes == [
            (True, "y", "target"),
            (True, "x", "xarg"),
            (True, "e", None),
            (False, "k", "key"),
        ]

    def test_parse_rejects_control_chars_in_params(self) -> None:
        """Verify inbound controls are rejected throughout the message."""
        for line in (
            "PING :tok\x00en\r\n",
            "PRIVMSG bot :a\rb\r\n",
            ":nick!user@ho\x00st PING :token\r\n",
            "@account=ba\x00d PING :token\r\n",
            "PI\x00NG :token\r\n",
        ):
            with self.assertRaisesRegex(ValueError, "control characters"):
                parse_message(line)

    def test_parse_accepts_decode_inflated_message(self) -> None:
        """Accept a wire-legal line whose replacement chars inflate re-encoding."""
        raw = b"PRIVMSG #chan :" + b"\xe9" * 400 + b"\r\n"
        assert len(raw) <= MAX_IRC_MESSAGE_BYTES

        message = parse_message(raw.decode(errors="replace"))

        assert message.command == "PRIVMSG"
        assert message.params[0] == "#chan"

    def test_parse_splits_params_on_space_only(self) -> None:
        """Verify a tab inside a param does not fragment it."""
        message = parse_message("PRIVMSG #a\tb :hi\r\n")

        assert message.params == ("#a\tb", "hi")

    def test_parse_tagged_message(self) -> None:
        """Verify message tags are stripped before parsing."""
        message = parse_message(
            "@account=test;label=a\\sb :Nick!user@host PRIVMSG bot :hello world\r\n",
        )

        assert message.command == "PRIVMSG"
        assert message.params == ("bot", "hello world")
        assert message.prefix == Prefix("Nick", "user", "host")
        # Repeated separators after the tags still leave a prefix first.
        assert parse_message("@id=1  :srv PING :tok\r\n") == IRCMessage(
            "PING",
            ("tok",),
            Prefix("srv"),
        )

    def test_prefix_parse_host_without_user(self) -> None:
        """Parse the RFC 2812 nick@host prefix form without a user part."""
        prefix = Prefix.parse("owner@static.example")

        assert prefix.nick == "owner"
        assert prefix.user is None
        assert prefix.host == "static.example"
        assert not prefix.complete

    def test_prefix_match(self) -> None:
        """Verify prefix matching is case-insensitive on nick and host."""
        prefix = Prefix("Owner", "user", "Host.Example")

        assert prefix.matches(Prefix("owner", "user", "host.example"), "rfc1459")
        assert not prefix.matches(Prefix("owner", "other", "host.example"), "rfc1459")
        assert not prefix.matches(Prefix("owner", "user", "other.example"), "rfc1459")
        assert not prefix.matches(Prefix("owner", "user", "straße.example"), "rfc1459")
        assert not Prefix("owner", "user", "straße.example").matches(
            Prefix("owner", "user", "strasse.example"),
            "rfc1459",
        )

    def test_isupport_chanmodes_extra_groups(self) -> None:
        """Verify CHANMODES with more than four groups keeps the first four."""
        caps = ISupportState()

        caps.apply("CHANMODES", "beIq,kf,lj,imnstC,X")

        assert caps.chanmodes == ("beIq", "kf", "lj", "imnstC")

    def test_isupport_empty_prefix_clears_membership_modes(self) -> None:
        """Track no membership prefixes when PREFIX advertises none."""
        for value in ("", "()"):
            with self.subTest(value=value):
                caps = ISupportState()

                caps.apply("PREFIX", value)

                assert caps.member_prefixes == {}
                assert caps.membership_modes == ""

    def test_isupport_malformed_prefix_ignored(self) -> None:
        """Keep the advertised membership prefixes when PREFIX is malformed."""
        for value in ("(ov", "(ov)@", "(ov)@+%"):
            with self.subTest(value=value):
                caps = ISupportState()
                caps.apply("PREFIX", "(yov)@%+")

                caps.apply("PREFIX", value)

                assert caps.member_prefixes == {"@": "y", "%": "o", "+": "v"}
                assert caps.membership_modes == "yov"
                assert caps.op_mode == "y"

    def test_identity_fold(self) -> None:
        """Fold only protocol-defined identity equivalents."""
        caps = ISupportState()

        # The nick folds under the server casemapping, user@host as ASCII.
        assert caps.fold_identity("Nick[!User[@HOST") == "nick{!user[@host"
        assert caps.fold_identity(
            "Nick!^user@host.example",
        ) != caps.fold_identity(
            "Nick!~user@host.example",
        )
        assert caps.fold_identity(
            "Nick!user@straße.example",
        ) != caps.fold_identity(
            "Nick!user@strasse.example",
        )

    def test_prefix_without_op_mode_fails_closed(self) -> None:
        """Never count a sub-operator PREFIX rank as channel operator."""
        caps = ISupportState()

        caps.parse_prefix("(v)+")
        assert caps.op_mode == "o"
        assert not caps.is_opped({"v"})

        caps.parse_prefix("(qv)~+")
        assert caps.op_mode == "q"
        assert caps.is_opped({"q"})
        assert not caps.is_opped({"v"})
