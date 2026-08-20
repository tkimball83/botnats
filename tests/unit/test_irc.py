# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for IRC protocol parsing, formatting, and client behavior."""

import asyncio
import ssl
import time
import unittest
from unittest.mock import AsyncMock, create_autospec, patch

from botnats.irc.client import (
    DESIRED_CAPS,
    NICK_COLLISION_LIMIT,
    SEND_BURST,
    SEND_RATE,
    IRCClient,
    IRCClientConfig,
    IRCServer,
    next_nickname,
    pong_reply,
)
from botnats.irc.protocol import (
    MAX_IRC_MESSAGE_BYTES,
    IRCMessage,
    Prefix,
    casefold,
    format_message,
    iter_mode_changes,
    mask_matches,
    parse_message,
)

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

    def test_pong_reply_echoes_raw_token(self) -> None:
        """Verify PONG echoes raw PING token bytes and always fits the wire."""
        assert pong_reply(b"PING :token\r\n") == b"PONG :token\r\n"
        assert pong_reply(b"PING token\r\n") == b"PONG token\r\n"
        assert pong_reply(b":server PING :token\r\n") == b"PONG :token\r\n"
        assert pong_reply(b"PING server1 :token\r\n") == b"PONG server1 :token\r\n"
        assert pong_reply(b"PING srv1 srv2\r\n") == b"PONG srv1 srv2\r\n"
        assert pong_reply(b"PING  token\r\n") == b"PONG token\r\n"
        assert pong_reply(b"PING a\tb\r\n") == b"PONG a\tb\r\n"
        # Tags plus a prefix: the prefix's space-colon must not be the marker.
        assert (
            pong_reply(b"@time=2026-01-01T00:00:00Z :srv PING :token\r\n")
            == b"PONG :token\r\n"
        )
        assert pong_reply(b"@id=1 PING token\r\n") == b"PONG token\r\n"
        # Repeated separator spaces are filtered by parse_message and must
        # not corrupt the byte-level echo either.
        assert pong_reply(b":srv  PING :token\r\n") == b"PONG :token\r\n"
        assert pong_reply(b"@id=1  PING  :token\r\n") == b"PONG :token\r\n"

        inflating = b"PING :" + b"\xe9" * 400 + b"\r\n"
        reply = pong_reply(inflating)
        assert reply == b"PONG :" + b"\xe9" * 400 + b"\r\n"
        assert len(reply) <= len(inflating) <= MAX_IRC_MESSAGE_BYTES

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

    def test_ban_mask_host_folding_uses_ascii(self) -> None:
        """Verify mask_matches folds user/host with ascii, not server casemapping."""
        prefix = Prefix("nick", "user[1]", "host[2]")

        assert mask_matches("nick!user[1]@host[2]", prefix)
        assert not mask_matches("nick!user{1}@host{2}", prefix)
        assert mask_matches("NICK!*@*", prefix, "rfc1459")
        assert not mask_matches("nick!user{1}@*", prefix, "rfc1459")

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
        with self.assertRaisesRegex(ValueError, "unsupported casemapping"):
            casefold("Nick", "utf8")

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

    def test_mode_parser_bare_unset_key_keeps_pairing(self) -> None:
        """Verify a stripped -k argument does not steal later arguments."""
        assert list(iter_mode_changes("-k+o", ("alpha",))) == [
            (False, "k", None),
            (True, "o", "alpha"),
        ]
        # A conforming batch with the key present pairs exactly as before.
        assert list(iter_mode_changes("-k+o", ("key", "alpha"))) == [
            (False, "k", "key"),
            (True, "o", "alpha"),
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
        candidates = [next_nickname(9) for _ in range(20)]

        assert all(len(candidate) == 9 for candidate in candidates)
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

    def failover_client(self) -> IRCClient:
        """Build a client with two failover servers for run_forever tests."""
        return IRCClient(
            config=IRCClientConfig(
                connect_timeout=1,
                nickname="alpha",
                servers=(
                    IRCServer("127.0.0.1", 6667, tls=False),
                    IRCServer("127.0.0.1", 6668, tls=False),
                ),
                verify_tls=False,
            ),
            on_disconnect=lambda: None,
            on_message=ignore_message,
        )

    async def test_run_forever_rotates_servers_with_backoff(self) -> None:
        """Rotate failover servers on failure with growing bounded backoff."""
        client = self.failover_client()
        delays: list[float] = []
        ports: list[int] = []

        async def failing_connection(server: IRCServer) -> None:
            ports.append(server.port)
            if len(ports) >= 4:
                client.stopping = True
            msg = "connection refused"
            raise OSError(msg)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        with (
            patch.object(client, "run_connection", failing_connection),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            self.assertLogs("botnats.irc.client", level="WARNING"),
        ):
            await client.run_forever()

        assert ports == [6667, 6668, 6667, 6668]
        assert len(delays) == len(ports) - 1
        for attempt, delay in enumerate(delays, start=1):
            base = 1.5**attempt
            assert base <= delay < base + 1.0

    async def test_run_forever_resets_backoff_after_stable_session(self) -> None:
        """Reset backoff and keep the server after a stable registered session."""
        client = self.failover_client()
        delays: list[float] = []
        ports: list[int] = []

        async def connection(server: IRCServer) -> None:
            ports.append(server.port)
            client.registered_with_server = len(ports) == 2
            if len(ports) >= 3:
                client.stopping = True
            msg = "connection lost"
            raise OSError(msg)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        with (
            patch.object(client, "run_connection", connection),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            patch("botnats.irc.client.STABLE_SESSION_SECONDS", 0.0),
            self.assertLogs("botnats.irc.client", level="WARNING"),
        ):
            await client.run_forever()

        # Failure rotates away; the stable session keeps its server and
        # resets the backoff to the base delay.
        assert ports == [6667, 6668, 6668]
        assert delays[0] >= 1.5
        assert 1.0 <= delays[1] < 1.0 + 1.0

    async def test_send_loop_rate_limits_after_burst(self) -> None:
        """Delay sends once the token-bucket burst allowance is spent."""
        client = irc_client()
        writer = mock_writer()
        client.writer = writer
        outbound: asyncio.Queue[bytes] = asyncio.Queue()
        for index in range(6):
            outbound.put_nowait(b"PRIVMSG nick :%d\r\n" % index)
        sleeps: list[float] = []
        real_sleep = asyncio.sleep

        async def record_sleep(delay: float) -> None:
            sleeps.append(delay)

        with (
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            patch.object(client, "send_immediate", AsyncMock()) as send,
        ):
            task = asyncio.create_task(client.send_loop(writer, outbound))
            while send.await_count < 6:
                await real_sleep(0)
            task.cancel()

        # The burst allowance goes out untouched; the rest wait ~1s each.
        assert len(sleeps) == 6 - int(SEND_BURST)
        assert all(delay > 1.0 / (2 * SEND_RATE) for delay in sleeps)

    async def test_registration_nick_rejections_retry(self) -> None:
        """Verify registration retries every nickname rejection numeric."""
        client = irc_client()
        retry = AsyncMock()
        numerics = ("432", "433", "436", "437")

        with patch.object(IRCClient, "nick_collision", retry):
            for numeric in numerics:
                raw = f":server {numeric} * alpha :nickname rejected\r\n".encode()
                await client.dispatch_line(
                    parse_message(raw.decode()), raw, mock_writer(), None
                )

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

    async def test_dispatch_answers_inflated_ping(self) -> None:
        """Verify dispatch_line answers a decode-inflated PING from raw bytes."""
        client = self.cap_client()
        raw = b"PING :" + b"\xe9" * 400 + b"\r\n"
        message = parse_message(raw.decode(errors="replace"))

        with patch.object(client, "send_immediate", AsyncMock()) as send:
            result = await client.dispatch_line(message, raw, mock_writer(), "tok")

        assert result == "tok"
        send.assert_awaited_once()
        assert send.await_args is not None
        assert send.await_args.args[0] == b"PONG :" + b"\xe9" * 400 + b"\r\n"

    async def test_bare_ping_gets_pong(self) -> None:
        """Answer a PING with no token instead of ignoring it."""
        client = self.cap_client()
        raw = b"PING\r\n"

        with patch.object(client, "send_immediate", AsyncMock()) as send:
            await client.dispatch_line(
                parse_message(raw.decode()),
                raw,
                mock_writer(),
                None,
            )

        send.assert_awaited_once()
        assert send.await_args is not None
        assert send.await_args.args[0] == b"PONG\r\n"

    async def test_cap_new_ack_mid_ls_does_not_end_negotiation(self) -> None:
        """Verify a NEW-triggered ACK before LS completes keeps negotiating."""
        client = self.cap_client()
        assert client.outbound is not None

        await client.handle_cap(parse_message(":server CAP * NEW :chghost\r\n"))
        assert client.outbound.get_nowait() == b"CAP REQ :chghost\r\n"

        await client.handle_cap(parse_message(":server CAP * ACK :chghost\r\n"))
        assert client.cap_negotiating
        assert client.outbound.empty()

        await client.handle_cap(parse_message(":server CAP * LS :multi-prefix\r\n"))
        assert client.outbound.get_nowait() == b"CAP REQ :multi-prefix\r\n"

        await client.handle_cap(parse_message(":server CAP * ACK :multi-prefix\r\n"))
        assert not client.cap_negotiating
        assert client.outbound.get_nowait() == b"CAP END\r\n"

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
        client.cap_ls_done = True
        message = parse_message(":server CAP * NAK :chghost\r\n")
        await client.handle_cap(message)

        assert not client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP END\r\n"

    async def test_cap_new_and_del_after_registration(self) -> None:
        """Verify NEW requests desired capabilities and DEL is ignored."""
        client = self.cap_client(negotiating=False)
        await client.handle_cap(
            parse_message(":server CAP alpha NEW :multi-prefix sasl\r\n"),
        )
        assert client.outbound is not None
        assert client.outbound.get_nowait() == b"CAP REQ :multi-prefix\r\n"

        await client.handle_cap(
            parse_message(":server CAP alpha ACK :multi-prefix\r\n"),
        )
        await client.handle_cap(
            parse_message(":server CAP alpha DEL :chghost\r\n"),
        )
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
            await asyncio.sleep(0.5)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        client = irc_client(idle_timeout=0.05, pong_timeout=0.05, port=port)
        try:
            with self.assertRaisesRegex(ConnectionError, "did not answer"):
                await client.run_connection(client.config.servers[0])
            assert ping_seen.is_set()
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_oversized_server_line_is_skipped(self) -> None:
        """Skip a complete oversized line without dropping the session."""
        dispatched: list[str] = []

        async def record_message(message: IRCMessage) -> None:
            dispatched.append(message.command)

        boundary = b":server 002 alpha :" + b"x" * 491 + b"\r\n"
        assert len(boundary) == MAX_IRC_MESSAGE_BYTES

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            for _ in range(3):
                await reader.readline()
            writer.write(b":server 005 " + b"x" * 505 + b" :are supported\r\n")
            writer.write(boundary)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(port=port)
        client.on_message = record_message
        try:
            with (
                self.assertLogs("botnats.irc.client", level="DEBUG") as logs,
                self.assertRaisesRegex(ConnectionError, "closed the connection"),
            ):
                await client.run_connection(client.config.servers[0])
            # The oversized line is dropped with a trace; the 512-byte
            # boundary line and the session itself survive it.
            assert dispatched == ["002"]
            assert any("oversized" in line for line in logs.output)
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_partial_line_at_eof_is_not_dispatched(self) -> None:
        """Drop a line truncated by a dying peer instead of parsing it."""
        dispatched: list[object] = []

        async def record_message(message: object) -> None:
            dispatched.append(message)

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            for _ in range(3):
                await reader.readline()
            writer.write(b":x!u@h MODE #chan -o bo")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(port=port)
        client.on_message = record_message
        try:
            with self.assertRaisesRegex(ConnectionError, "closed the connection"):
                await client.run_connection(client.config.servers[0])
            assert dispatched == []
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_readline_limit_overflow_disconnects(self) -> None:
        """Disconnect when a line overflows the stream reader's buffer."""

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            for _ in range(3):
                await reader.readline()
            writer.write(b"x" * 70_000 + b"\r\n")
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

    async def test_registration_timeout_disconnects(self) -> None:
        """Disconnect when the server never completes registration."""

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            for _ in range(3):
                await reader.readline()
            await asyncio.sleep(1.0)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(port=port)
        try:
            with (
                patch("botnats.irc.client.REGISTRATION_TIMEOUT", 0.05),
                self.assertRaisesRegex(ConnectionError, "complete registration"),
            ):
                await client.run_connection(client.config.servers[0])
        finally:
            await client.close()
            server.close()
            await server.wait_closed()

    async def test_nick_collision_limit_disconnects(self) -> None:
        """Raise once nickname collisions exhaust the retry limit."""
        client = self.cap_client()
        client.nickname_attempts = NICK_COLLISION_LIMIT

        with self.assertRaisesRegex(ConnectionError, "collision limit"):
            await client.nick_collision()

    async def test_send_immediate_write_timeout_disconnects(self) -> None:
        """Close the socket and raise when a write never drains."""
        client = irc_client()
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        writer.is_closing.return_value = False

        async def slow_drain() -> None:
            await asyncio.sleep(60)

        writer.drain = slow_drain
        client.writer = writer

        with (
            patch("botnats.irc.client.WRITE_TIMEOUT", 0.01),
            self.assertRaisesRegex(ConnectionError, "write timed out"),
        ):
            await client.send_immediate(b"PING :token\r\n", writer)
        writer.close.assert_called_once_with()

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
