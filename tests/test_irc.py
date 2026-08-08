# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC protocol parsing, formatting, and client behavior."""

import asyncio
import ssl
import time
import unittest
from unittest.mock import AsyncMock, create_autospec, patch

from botnats.irc import (
    IRCClient,
    IRCClientConfig,
    Prefix,
    casefold,
    iter_mode_changes,
    mask_matches,
)
from botnats.irc.client import DESIRED_CAPS, IRCServer, next_nickname
from botnats.irc.protocol import format_message, parse_message

COLLISION_NICK_LENGTH = 9
MASK_MATCH_BUDGET_SECONDS = 0.5


async def ignore_message(message: object) -> None:
    """Ignore an IRC message in transport-only tests."""
    del message


def irc_client(
    *,
    idle_timeout: float = 120,
    pong_timeout: float = 30,
    port: int = 6667,
    tls: bool = False,
    verify_tls: bool = True,
) -> IRCClient:
    """Build an IRC client for transport-only tests."""
    return IRCClient(
        config=IRCClientConfig(
            connect_timeout=1,
            idle_timeout=idle_timeout,
            nickname="alpha",
            pong_timeout=pong_timeout,
            servers=(IRCServer("127.0.0.1", port, tls=tls),),
            verify_tls=verify_tls,
        ),
        on_disconnect=lambda: None,
        on_message=ignore_message,
    )


def mock_writer() -> asyncio.StreamWriter:
    """Create a mock StreamWriter that reports as connected."""
    writer = create_autospec(asyncio.StreamWriter, instance=True)
    writer.is_closing.return_value = False
    return writer


class IRCProtocolTests(unittest.TestCase):
    """Tests for prefix matching, message parsing, and mode iteration."""

    def test_ban_mask_matching(self) -> None:
        """Verify ban mask matching against IRC prefixes."""
        prefix = Prefix("Bot[One]", "~user", "2001:db8::1")

        assert mask_matches("bot[one]!*@2001:db8::*", prefix)
        assert mask_matches("*!~user@*", prefix)
        assert not mask_matches("*!other@*", prefix)

    def test_ban_mask_no_backtracking(self) -> None:
        """Verify an adversarial mask matches without catastrophic backtracking."""
        prefix = Prefix("a" * 60, "user", "host")
        evil = "*a" * 40 + "!*@*"

        start = time.perf_counter()
        mask_matches(evil, prefix)
        assert time.perf_counter() - start < MASK_MATCH_BUDGET_SECONDS

    def test_ban_mask_wildcards(self) -> None:
        """Verify single- and multi-character wildcards and non-matches."""
        prefix = Prefix("alice", "~alice", "host.example")

        assert mask_matches("a????!*@*", prefix)
        assert mask_matches("*!*@host.example", prefix)
        assert mask_matches("*", prefix)
        assert not mask_matches("a???!*@*", prefix)
        assert not mask_matches("bob!*@*", prefix)

    def test_casefold(self) -> None:
        """Verify casefold applies correct mapping for each mode."""
        assert casefold("Nick[\\]^") == "nick{|}~"
        assert casefold("Nick[\\]^", "strict-rfc1459") == "nick{|}^"
        assert casefold("Nick[\\]^", "ascii") == "nick[\\]^"

    def test_config_validation(self) -> None:
        """Verify IRCClientConfig rejects invalid timing and empty servers."""
        srv = (IRCServer("host", 6667, tls=False),)
        args = (30.0, "bot", srv)
        IRCClientConfig(*args, verify_tls=True)
        with self.assertRaisesRegex(ValueError, "positive"):
            IRCClientConfig(0, "bot", srv, verify_tls=True)
        with self.assertRaisesRegex(ValueError, "positive"):
            IRCClientConfig(*args, verify_tls=True, idle_timeout=0)
        with self.assertRaisesRegex(ValueError, "positive"):
            IRCClientConfig(*args, verify_tls=True, pong_timeout=0)
        with self.assertRaisesRegex(ValueError, "empty"):
            IRCClientConfig(30, "bot", (), verify_tls=True)
        oversized = "n" * 300
        with self.assertRaisesRegex(ValueError, "512 bytes"):
            IRCClientConfig(
                30,
                oversized,
                srv,
                verify_tls=True,
            )

    def test_tls_verification_can_be_disabled(self) -> None:
        """Configure an IRCS context that accepts an unverified certificate."""
        client = irc_client(tls=True, verify_tls=False)

        assert client.tls_context is not None
        assert not client.tls_context.check_hostname
        assert client.tls_context.verify_mode == ssl.CERT_NONE

    def test_format_injection(self) -> None:
        """Verify format_message rejects parameter injection attempts."""
        unsafe = (
            ("JOIN", ("#safe\r\nOPER root password",), None),
            ("JOIN", ("#safe", "key with space"), None),
            ("NOTICE", ("owner",), "safe\nQUIT"),
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
            ),
        )

        assert changes == [
            (True, "k", "key"),
            (True, "o", "one"),
            (True, "o", "two"),
            (False, "v", "voice"),
        ]

    def test_mode_parser_custom_modes(self) -> None:
        """Verify mode parser handles custom channel modes and prefixes."""
        changes = list(
            iter_mode_changes(
                "+y-k",
                ("target", "key"),
                ("b", "k", "l", "imn"),
                "oyv",
            ),
        )

        assert changes == [(True, "y", "target"), (False, "k", "key")]

    def test_nickname_collision(self) -> None:
        """Verify collision nicknames have correct length and are alphabetic."""
        candidates = [next_nickname(COLLISION_NICK_LENGTH) for _ in range(20)]

        assert all(len(candidate) == COLLISION_NICK_LENGTH for candidate in candidates)
        assert all(candidate.isalpha() for candidate in candidates)

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

    def test_parse_rejects_oversized_message(self) -> None:
        """Reject inbound IRC messages larger than the protocol limit."""
        with self.assertRaisesRegex(ValueError, "exceeds 512 bytes"):
            parse_message("PING :" + "x" * 505 + "\r\n")

    def test_parse_splits_params_on_space_only(self) -> None:
        """Verify a tab inside a param does not fragment it."""
        message = parse_message("PRIVMSG #a\tb :hi\r\n")

        assert message.params == ("#a\tb", "hi")

    def test_parse_tagged_message(self) -> None:
        """Verify tagged IRC message parsing extracts all fields."""
        message = parse_message(
            "@account=test;label=a\\sb :Nick!user@host PRIVMSG bot :hello world\r\n",
        )

        assert message.command == "PRIVMSG"
        assert message.params == ("bot", "hello world")
        assert message.prefix == Prefix("Nick", "user", "host")
        assert message.tags == {"account": "test", "label": "a b"}

    def test_prefix_match(self) -> None:
        """Verify prefix matching is case-insensitive on nick and host."""
        prefix = Prefix("Owner", "user", "Host.Example")

        assert prefix.matches(Prefix("owner", "user", "host.example"))
        assert not prefix.matches(Prefix("owner", "other", "host.example"))
        assert not prefix.matches(Prefix("owner", "user", "other.example"))
        assert not prefix.matches(Prefix("owner", "user", "straße.example"))
        assert not Prefix("owner", "user", "straße.example").matches(
            Prefix("owner", "user", "strasse.example"),
        )


class IRCClientTests(unittest.IsolatedAsyncioTestCase):
    """Tests for IRC client queue limits and idle ping behavior."""

    def cap_client(self, *, negotiating: bool = True) -> IRCClient:
        """Return a connected client with automatic sender cleanup."""
        client = irc_client()
        client.cap_negotiating = negotiating
        client.outbound = asyncio.Queue(maxsize=64)
        client.sender_task = asyncio.create_task(asyncio.sleep(60))
        client.writer = mock_writer()
        self.addAsyncCleanup(client.stop_sender)
        return client

    async def test_registration_nick_rejections_retry(self) -> None:
        """Verify registration retries every nickname rejection numeric."""
        client = irc_client()
        retry = AsyncMock()
        numerics = ("432", "433", "436", "437")

        with patch.object(IRCClient, "nick_collision", retry):
            for numeric in numerics:
                message = parse_message(
                    f":server {numeric} * alpha :nickname rejected\r\n",
                )
                await client.dispatch_line(message, mock_writer(), None)

        assert retry.await_count == len(numerics)

    async def test_cap_ls_multiline(self) -> None:
        """Verify multiline CAP LS accumulates before requesting."""
        client = self.cap_client()
        first = parse_message(":server CAP * LS * :multi-prefix sasl\r\n")
        await client.handle_cap(first)
        assert client.cap_negotiating
        assert client.outbound is not None
        assert client.outbound.empty()

        second = parse_message(":server CAP * LS :chghost\r\n")
        await client.handle_cap(second)
        assert "chghost" in client.cap_available
        sent = client.outbound.get_nowait()
        assert sent == b"CAP REQ :chghost multi-prefix\r\n"

    async def test_cap_ls_no_desired(self) -> None:
        """Verify CAP END is sent when no desired capabilities are available."""
        client = self.cap_client()
        message = parse_message(":server CAP * LS :sasl\r\n")
        await client.handle_cap(message)

        assert not client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP END\r\n"

    async def test_cap_ls_requests_desired(self) -> None:
        """Verify desired capabilities are requested when advertised."""
        client = self.cap_client()
        message = parse_message(":server CAP * LS :chghost multi-prefix\r\n")
        await client.handle_cap(message)

        assert client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP REQ :chghost multi-prefix\r\n"

    async def test_cap_ls_strips_values(self) -> None:
        """Verify capability values are stripped when parsing LS."""
        client = self.cap_client()
        message = parse_message(
            ":server CAP * LS :chghost sasl=PLAIN,EXTERNAL\r\n",
        )
        await client.handle_cap(message)

        assert client.cap_available == {"chghost", "sasl"}
        assert "chghost" in DESIRED_CAPS

    async def test_cap_nak_ends_negotiation(self) -> None:
        """Verify CAP NAK still sends CAP END."""
        client = self.cap_client()
        message = parse_message(":server CAP * NAK :chghost\r\n")
        await client.handle_cap(message)

        assert not client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP END\r\n"

    async def test_cap_new_and_del_after_registration(self) -> None:
        """Verify post-registration capability availability stays current."""
        client = self.cap_client(negotiating=False)
        client.cap_available = {"chghost"}
        await client.handle_cap(
            parse_message(":server CAP alpha NEW :multi-prefix sasl\r\n"),
        )
        assert client.cap_available == {"chghost", "multi-prefix", "sasl"}
        assert client.outbound is not None
        assert client.outbound.get_nowait() == b"CAP REQ :multi-prefix\r\n"

        await client.handle_cap(
            parse_message(":server CAP alpha ACK :multi-prefix\r\n"),
        )
        await client.handle_cap(
            parse_message(":server CAP alpha DEL :chghost\r\n"),
        )
        assert client.cap_available == {"multi-prefix", "sasl"}
        assert client.outbound.empty()

    async def test_close_releases_writer(self) -> None:
        """Verify repeated shutdown closes and releases the active writer."""
        client = irc_client()
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        client.writer = writer

        await client.close()
        await client.close()

        assert client.writer is None
        writer.close.assert_called_once_with()
        writer.wait_closed.assert_awaited_once_with()

    async def test_idle_ping_pong(self) -> None:
        """Verify idle timeout sends PING and raises on missing PONG."""
        ping_seen = asyncio.Event()

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            await reader.readline()
            await reader.readline()
            await reader.readline()
            ping = await reader.readline()
            if ping.startswith(b"PING :"):
                ping_seen.set()
            await asyncio.sleep(0.1)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        client = irc_client(idle_timeout=0.02, pong_timeout=0.02, port=port)
        try:
            with self.assertRaisesRegex(ConnectionError, "did not answer"):
                await client.run_connection(client.config.servers[0])
            assert ping_seen.is_set()
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_oversized_server_line_disconnects(self) -> None:
        """Disconnect when a server sends a line over the IRC limit."""

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            for _ in range(3):
                await reader.readline()
            writer.write(b"PING :" + b"x" * 505 + b"\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(port=port)
        try:
            with self.assertRaisesRegex(ConnectionError, "oversized line"):
                await client.run_connection(client.config.servers[0])
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_outbound_queue_bounded(self) -> None:
        """Verify outbound queue raises ConnectionError when full."""
        client = irc_client()
        client.outbound = asyncio.Queue(maxsize=1)
        client.outbound.put_nowait(b"PING :queued\r\n")
        client.sender_task = asyncio.create_task(asyncio.sleep(60))
        client.writer = mock_writer()
        try:
            with self.assertRaisesRegex(ConnectionError, "queue is full"):
                await client.send("NOTICE", "owner", trailing="hello")
        finally:
            client.sender_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await client.sender_task
            client.sender_task = None
            client.outbound = None
            client.writer = None
