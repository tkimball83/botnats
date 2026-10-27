# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the IRC client's connection, dispatch, and sending."""

import asyncio
import socket
import ssl
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from botnats.irc.client import (
    FALLBACK_NICK_LENGTH,
    NICK_COLLISION_LIMIT,
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
    ISupportState,
    format_message,
    parse_message,
)
from tests.unit.helpers import hang


def fill_send_buffer(writer: asyncio.StreamWriter) -> None:
    """Write until the socket buffers are full and bytes wait unsent."""
    while not writer.transport.get_write_buffer_size():
        writer.write(b"x" * 65536)


def ignore_message(message: object) -> None:
    """Ignore an IRC message in transport-only tests."""
    del message


def irc_client(
    *,
    ports: tuple[int, ...] = (6667,),
    tls: bool = False,
    verify_tls: bool = True,
) -> IRCClient:
    """Build an IRC client for transport-only tests, one server per port."""
    return IRCClient(
        caps=ISupportState(),
        config=IRCClientConfig(
            connect_timeout=1,
            nickname="alpha",
            servers=tuple(IRCServer("127.0.0.1", port, tls=tls) for port in ports),
            verify_tls=verify_tls,
        ),
        on_disconnect=lambda: None,
        on_message=ignore_message,
    )


def mock_writer() -> MagicMock:
    """Create a mock StreamWriter that reports as connected."""
    writer = create_autospec(asyncio.StreamWriter, instance=True)
    writer.is_closing.return_value = False
    return writer


class IRCServerTests(unittest.TestCase):
    """Tests for IRC server URL parsing."""

    def test_parse_maps_scheme_to_tls_and_default_port(self) -> None:
        """Map each IRC scheme to its TLS setting and default port."""
        assert IRCServer.parse("irc://irc.example.test") == IRCServer(
            "irc.example.test", 6667, tls=False
        )
        assert IRCServer.parse("ircs://irc.example.test") == IRCServer(
            "irc.example.test", 6697, tls=True
        )
        assert IRCServer.parse("irc://irc.example.test:6697") == IRCServer(
            "irc.example.test", 6697, tls=False
        )
        with self.assertRaisesRegex(ValueError, "^invalid IRC server URL$"):
            IRCServer.parse("nats://irc.example.test:6667")


class IRCClientTests(unittest.IsolatedAsyncioTestCase):
    """Tests for IRC client connection, dispatch, negotiation, and sending."""

    def cap_client(self, *, negotiating: bool = True) -> IRCClient:
        """Return a connected client with automatic sender cleanup."""
        client = irc_client()
        client.cap_negotiating = negotiating
        client.outbound = asyncio.Queue(maxsize=64)
        client.sender_task = asyncio.create_task(hang())
        client.writer = mock_writer()
        self.addAsyncCleanup(client.stop_sender)
        return client

    async def unread_connection(
        self,
        client: IRCClient,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect a client to a peer that never reads what is sent to it."""
        local, peer = socket.socketpair()
        self.addCleanup(peer.close)
        reader, writer = await asyncio.open_connection(sock=local)
        client.writer = writer
        return reader, writer

    def test_pong_reply_echoes_raw_token(self) -> None:
        """Verify PONG echoes raw PING token bytes and always fits the wire."""
        # A bare PING still gets an answer.
        assert pong_reply(b"PING\r\n") == b"PONG\r\n"
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
        # Leading and repeated separator spaces are filtered by parse_message
        # and must not corrupt the byte-level echo either.
        assert pong_reply(b":srv  PING :token\r\n") == b"PONG :token\r\n"
        assert pong_reply(b"@id=1  PING  :token\r\n") == b"PONG :token\r\n"
        assert pong_reply(b" PING :token\r\n") == b"PONG :token\r\n"

        inflating = b"PING :" + b"\xe9" * 400 + b"\r\n"
        assert len(inflating) <= MAX_IRC_MESSAGE_BYTES
        assert pong_reply(inflating) == b"PONG :" + b"\xe9" * 400 + b"\r\n"

    def test_tls_context_verifies_as_configured(self) -> None:
        """Verify IRCS certificates and hostnames unless configured not to."""
        for verify, mode in ((True, ssl.CERT_REQUIRED), (False, ssl.CERT_NONE)):
            with self.subTest(verify=verify):
                client = irc_client(tls=True, verify_tls=verify)

                assert client.tls_context is not None
                assert client.tls_context.check_hostname is verify
                assert client.tls_context.verify_mode == mode

    def test_nickname_collision(self) -> None:
        """Verify collision nicknames have correct length and are alphabetic."""
        candidates = [next_nickname(9) for _ in range(20)]

        assert all(len(candidate) == 9 for candidate in candidates)
        assert all(candidate.isalpha() for candidate in candidates)

    async def test_run_forever_rotates_servers_with_backoff(self) -> None:
        """Rotate failover servers on failure with growing, capped backoff."""
        client = irc_client(ports=(6667, 6668))
        delays: list[float] = []
        ports: list[int] = []
        real_sleep = asyncio.sleep

        async def failing_connection(server: IRCServer) -> None:
            ports.append(server.port)
            if len(ports) >= 11:
                # Stop the loop the way SIGTERM does, by cancellation.
                raise asyncio.CancelledError

            msg = "connection refused"
            raise OSError(msg)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)
            await real_sleep(0)

        with (
            patch.object(client, "run_connection", failing_connection),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6668] * 5 + [6667]
        # The backoff grows to its cap of 8 steps and then stays there.
        assert len(delays) == 10
        for attempt, delay in enumerate(delays, start=1):
            base = 1.5 ** min(attempt, 8)
            assert base <= delay < base + 1.0

    async def test_run_forever_keeps_backoff_after_short_session(self) -> None:
        """Rotate and keep backing off after a registered but brief session."""
        client = irc_client(ports=(6667, 6668))
        delays: list[float] = []
        ports: list[int] = []
        real_sleep = asyncio.sleep

        async def connection(server: IRCServer) -> None:
            ports.append(server.port)
            # Registration alone is not stability: this session is far
            # shorter than STABLE_SESSION_SECONDS.
            client.registered_with_server = len(ports) == 2
            if len(ports) >= 3:
                raise asyncio.CancelledError

            msg = "connection lost"
            raise OSError(msg)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)
            await real_sleep(0)

        with (
            patch.object(client, "run_connection", connection),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6668, 6667]
        assert 1.5 <= delays[0] < 1.5 + 1.0
        assert 1.5**2 <= delays[1] < 1.5**2 + 1.0

    async def test_run_forever_resets_backoff_after_stable_session(self) -> None:
        """Reset backoff and keep the server after a stable registered session."""
        client = irc_client(ports=(6667, 6668))
        delays: list[float] = []
        ports: list[int] = []
        real_sleep = asyncio.sleep

        async def connection(server: IRCServer) -> None:
            ports.append(server.port)
            client.registered_with_server = len(ports) == 2
            if len(ports) >= 3:
                raise asyncio.CancelledError

            msg = "connection lost"
            raise OSError(msg)

        async def record_sleep(delay: float) -> None:
            delays.append(delay)
            await real_sleep(0)

        with (
            patch.object(client, "run_connection", connection),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            patch("botnats.irc.client.STABLE_SESSION_SECONDS", 0.0),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
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
        messages = [b"%d" % index for index in range(6)]
        for message in messages:
            outbound.put_nowait(message)

        # Only the sender reads this clock, which moves by the time it sleeps.
        clock = 0.0
        timeline: list[bytes | float] = []
        all_sent = asyncio.Event()

        async def record_sleep(delay: float) -> None:
            nonlocal clock
            clock += delay
            timeline.append(delay)

        async def record_send(encoded: bytes, target: asyncio.StreamWriter) -> None:
            del target
            timeline.append(encoded)
            if outbound.empty():
                all_sent.set()

        with (
            patch(
                "botnats.irc.client.asyncio.get_running_loop",
                return_value=SimpleNamespace(time=lambda: clock),
            ),
            patch("botnats.irc.client.SEND_BURST", 4.5),
            patch("botnats.irc.client.asyncio.sleep", record_sleep),
            patch.object(client, "send_immediate", record_send),
        ):
            task = asyncio.create_task(client.send_loop(writer, outbound))
            async with asyncio.timeout(5):
                await all_sent.wait()

            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        # Four whole tokens go out at once, and the half token left over
        # shortens only the first wait. Each later send waits a whole token:
        # neither that half token nor the time slept may be counted twice.
        assert timeline == [
            *messages[:4],
            0.5 / SEND_RATE,
            messages[4],
            1.0 / SEND_RATE,
            messages[5],
        ]

    async def test_registration_nick_rejections_retry(self) -> None:
        """Verify registration retries every nickname rejection numeric."""
        client = irc_client()
        retry = MagicMock()
        numerics = ("432", "433", "436", "437")

        with patch.object(IRCClient, "nick_collision", retry):
            for numeric in numerics:
                raw = f":server {numeric} * alpha :nickname rejected\r\n".encode()
                await client.dispatch_line(
                    parse_message(raw.decode()), raw, mock_writer(), None
                )

        assert retry.call_count == len(numerics)

    async def test_nick_rejection_after_registration_is_dispatched(self) -> None:
        """Pass a post-registration nick rejection on instead of renaming."""
        client = irc_client()
        client.registered_with_server = True
        dispatched: list[str] = []

        def record_message(message: IRCMessage) -> None:
            dispatched.append(message.command)

        client.on_message = record_message
        retry = MagicMock()
        numerics = ["432", "433", "436", "437"]

        with patch.object(IRCClient, "nick_collision", retry):
            for numeric in numerics:
                raw = f":server {numeric} alpha beta :nickname rejected\r\n".encode()
                await client.dispatch_line(
                    parse_message(raw.decode()), raw, mock_writer(), None
                )

        retry.assert_not_called()
        assert dispatched == numerics

    async def test_handler_failure_is_logged_and_dispatch_continues(self) -> None:
        """Log a failing message handler and keep dispatching later lines."""
        client = irc_client()
        dispatched: list[str] = []

        def fragile_handler(message: IRCMessage) -> None:
            if message.command == "PRIVMSG":
                msg = "handler bug"
                raise RuntimeError(msg)

            dispatched.append(message.command)

        client.on_message = fragile_handler
        lines = (b":nick!u@h PRIVMSG alpha :boom\r\n", b":server 002 alpha :hi\r\n")

        with self.assertLogs("botnats.irc.client", level="ERROR") as logs:
            for raw in lines:
                result = await client.dispatch_line(
                    parse_message(raw.decode()), raw, mock_writer(), "token"
                )
                assert result == "token"

        assert dispatched == ["002"]
        assert len(logs.output) == 1
        assert "IRC message handler failed for PRIVMSG" in logs.output[0]

    async def test_cap_line_reaches_capability_negotiation(self) -> None:
        """Route a CAP line to negotiation rather than the message handler."""
        client = self.cap_client()
        handler = MagicMock()
        client.on_message = handler
        raw = b":server CAP * LS :chghost\r\n"

        await client.dispatch_line(
            parse_message(raw.decode()), raw, mock_writer(), None
        )

        handler.assert_not_called()
        assert client.cap_available == {"chghost"}
        assert client.outbound is not None
        assert client.outbound.get_nowait() == b"CAP REQ :chghost\r\n"

    async def test_reconnect_drops_socket_with_unsent_bytes(self) -> None:
        """Force a reconnection at once, though a peer never reads what is unsent.

        A close would wait to flush those bytes first, so the read loop would
        never see EOF.
        """
        client = irc_client()
        client.reconnect()  # Without a socket there is nothing to drop.
        async with asyncio.timeout(5):
            reader, writer = await self.unread_connection(client)
            fill_send_buffer(writer)

            client.reconnect()

            assert await reader.read() == b""
            await client.close()

    async def test_welcome_and_own_nick_change_track_current_nick(self) -> None:
        """Follow the server-assigned nick and this client's own NICK changes."""
        client = self.cap_client()

        async def dispatch(raw: bytes) -> None:
            await client.dispatch_line(
                parse_message(raw.decode()),
                raw,
                mock_writer(),
                None,
            )

        await dispatch(b":server 001 Alpha[ :Welcome\r\n")
        assert client.registered_with_server
        assert not client.cap_negotiating
        assert client.current_nick == "Alpha["

        # rfc1459 folds [ and { together, so this NICK is this client's own.
        await dispatch(b":alpha{!user@host NICK :beta\r\n")
        assert client.current_nick == "beta"
        assert client.is_self("BETA")

        await dispatch(b":other!user@host NICK :gamma\r\n")
        assert client.current_nick == "beta"

    async def test_nick_collision_fits_rfc1459_nick_length(self) -> None:
        """Pick a fallback nick no longer than RFC 1459 allows.

        A collision happens during registration, before ISUPPORT advertises
        the server's own limit.
        """
        client = self.cap_client()
        client.config = replace(client.config, nickname="alphabetsoup")

        client.nick_collision()

        assert len(client.current_nick) == FALLBACK_NICK_LENGTH
        assert client.outbound is not None
        assert (
            client.outbound.get_nowait() == f"NICK {client.current_nick}\r\n".encode()
        )

    async def test_matching_pong_clears_ping_token(self) -> None:
        """Clear the outstanding PING only for a PONG carrying its token."""
        client = irc_client()

        async def dispatch(raw: bytes) -> str | None:
            return await client.dispatch_line(
                parse_message(raw.decode()),
                raw,
                mock_writer(),
                "token",
            )

        assert await dispatch(b":server PONG server :other\r\n") == "token"
        assert await dispatch(b":server PONG server :token\r\n") is None

    async def test_short_lines_keep_ping_token_and_nick(self) -> None:
        """Pass over lines without the parameters or source a handler reads.

        run_forever does not catch the IndexError or AttributeError that
        reading them would raise, so the process would exit.
        """
        client = irc_client()
        for raw in (
            b":server PONG\r\n",
            b":server CAP *\r\n",
            b":server 001\r\n",
            b"NICK beta\r\n",
            b":alpha!u@h NICK\r\n",
        ):
            with self.subTest(raw=raw):
                result = await client.dispatch_line(
                    parse_message(raw.decode()), raw, mock_writer(), "token"
                )

                assert result == "token"
                assert client.current_nick == "alpha"

    async def test_cap_ls_multiline(self) -> None:
        """Verify multiline CAP LS accumulates before requesting."""
        client = self.cap_client()
        first = parse_message(":server CAP * LS * :multi-prefix sasl\r\n")
        client.handle_cap(first)
        assert client.cap_negotiating
        assert client.outbound is not None
        assert client.outbound.empty()

        second = parse_message(":server CAP * LS :chghost\r\n")
        client.handle_cap(second)
        assert "chghost" in client.cap_available
        sent = client.outbound.get_nowait()
        assert sent == b"CAP REQ :chghost multi-prefix\r\n"

    async def test_dispatch_answers_ping_from_raw_bytes(self) -> None:
        """Verify dispatch_line answers inflated and bare PINGs from raw bytes."""
        client = irc_client()
        token = b"\xe9" * 400
        cases = (
            (b"PING :" + token + b"\r\n", b"PONG :" + token + b"\r\n"),
            # A PING without parameters must not fall through unanswered.
            (b"PING\r\n", b"PONG\r\n"),
        )

        for raw, reply in cases:
            message = parse_message(raw.decode(errors="replace"))
            with (
                self.subTest(params=len(message.params)),
                patch.object(client, "send_immediate", AsyncMock()) as send,
            ):
                result = await client.dispatch_line(message, raw, mock_writer(), "tok")

                assert result == "tok"
                send.assert_awaited_once()
                assert send.await_args is not None
                assert send.await_args.args[0] == reply

    async def test_cap_new_ack_mid_ls_does_not_end_negotiation(self) -> None:
        """Verify a NEW-triggered ACK before LS completes keeps negotiating."""
        client = self.cap_client()
        assert client.outbound is not None

        client.handle_cap(parse_message(":server CAP * NEW :chghost\r\n"))
        assert client.outbound.get_nowait() == b"CAP REQ :chghost\r\n"

        client.handle_cap(parse_message(":server CAP * ACK :chghost\r\n"))
        assert client.cap_negotiating
        assert client.outbound.empty()

        client.handle_cap(parse_message(":server CAP * LS :multi-prefix\r\n"))
        assert client.outbound.get_nowait() == b"CAP REQ :multi-prefix\r\n"

        client.handle_cap(parse_message(":server CAP * ACK :multi-prefix\r\n"))
        assert not client.cap_negotiating
        assert client.outbound.get_nowait() == b"CAP END\r\n"

    async def test_cap_ls_no_desired(self) -> None:
        """Verify CAP END is sent when no desired capabilities are available."""
        client = self.cap_client()
        message = parse_message(":server CAP * LS :sasl\r\n")
        client.handle_cap(message)

        assert not client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP END\r\n"

    async def test_cap_ls_requests_desired(self) -> None:
        """Verify desired capabilities are requested when advertised."""
        client = self.cap_client()
        message = parse_message(":server CAP * LS :chghost multi-prefix\r\n")
        client.handle_cap(message)

        assert client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP REQ :chghost multi-prefix\r\n"

    async def test_cap_ls_strips_values(self) -> None:
        """Verify capability values are stripped when parsing LS."""
        client = self.cap_client()
        message = parse_message(
            ":server CAP * LS :chghost=1 sasl=PLAIN,EXTERNAL\r\n",
        )
        client.handle_cap(message)

        assert client.cap_available == {"chghost", "sasl"}
        # The valued capability is still recognized and requested by name.
        assert client.outbound is not None
        assert client.outbound.get_nowait() == b"CAP REQ :chghost\r\n"

    async def test_cap_nak_ends_negotiation(self) -> None:
        """Verify CAP NAK still sends CAP END."""
        client = self.cap_client()
        client.cap_ls_done = True
        message = parse_message(":server CAP * NAK :chghost\r\n")
        client.handle_cap(message)

        assert not client.cap_negotiating
        assert client.outbound is not None
        sent = client.outbound.get_nowait()
        assert sent == b"CAP END\r\n"

    async def test_cap_new_and_del_after_registration(self) -> None:
        """Verify NEW requests desired capabilities and DEL is ignored."""
        client = self.cap_client(negotiating=False)
        client.handle_cap(
            parse_message(":server CAP alpha NEW :multi-prefix sasl\r\n"),
        )
        assert client.outbound is not None
        assert client.outbound.get_nowait() == b"CAP REQ :multi-prefix\r\n"

        client.handle_cap(
            parse_message(":server CAP alpha ACK :multi-prefix\r\n"),
        )
        client.handle_cap(
            parse_message(":server CAP alpha DEL :chghost\r\n"),
        )
        assert client.outbound.empty()

    async def test_cap_new_with_full_queue_keeps_session(self) -> None:
        """Drop a CAP NEW request that finds the send queue full, not the session."""
        client = self.cap_client(negotiating=False)
        client.outbound = asyncio.Queue(maxsize=1)
        client.outbound.put_nowait(b"JOIN #queued\r\n")
        raw = b":server CAP alpha NEW :chghost\r\n"

        result = await client.dispatch_line(
            parse_message(raw.decode()), raw, mock_writer(), "token"
        )

        assert result == "token"
        assert client.outbound.get_nowait() == b"JOIN #queued\r\n"
        assert client.outbound.empty()

    async def test_close_drops_socket_with_unsent_bytes(self) -> None:
        """Shut down at once and release the writer, though bytes stay unsent.

        A close would wait to flush them to a peer that never reads.
        """
        client = irc_client()
        async with asyncio.timeout(5):
            _, writer = await self.unread_connection(client)
            fill_send_buffer(writer)

            await client.close()
            await client.close()

        assert client.writer is None
        assert writer.is_closing()

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
            # Never answer the PING; hold the connection until the client leaves.
            await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        client = irc_client(ports=(port,))
        try:
            async with asyncio.timeout(5):
                with (
                    patch("botnats.irc.client.IDLE_TIMEOUT", 0),
                    patch("botnats.irc.client.PONG_TIMEOUT", 0),
                    self.assertRaisesRegex(ConnectionError, "did not answer"),
                ):
                    await client.run_connection(client.config.servers[0])

                await ping_seen.wait()
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

    async def test_oversized_server_line_is_skipped(self) -> None:
        """Skip a complete oversized line without dropping the session."""
        dispatched: list[str] = []

        def record_message(message: IRCMessage) -> None:
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
        client = irc_client(ports=(port,))
        client.on_message = record_message
        try:
            with (
                self.assertLogs("botnats.irc.client", level="DEBUG") as logs,
                self.assertRaisesRegex(ConnectionError, "connection closed"),
            ):
                async with asyncio.timeout(5):
                    await client.run_connection(client.config.servers[0])
            # The oversized line is dropped with a trace; the 512-byte
            # boundary line and the session itself survive it.
            assert dispatched == ["002"]
            assert any("oversized" in line for line in logs.output)
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

    async def test_partial_line_at_eof_is_not_dispatched(self) -> None:
        """Drop a line truncated by a dying peer instead of parsing it."""
        dispatched: list[object] = []

        def record_message(message: object) -> None:
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
        client = irc_client(ports=(port,))
        client.on_message = record_message
        try:
            with self.assertRaisesRegex(ConnectionError, "connection closed"):
                async with asyncio.timeout(5):
                    await client.run_connection(client.config.servers[0])

            assert dispatched == []
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

    async def test_malformed_server_line_is_skipped(self) -> None:
        """Skip a line that does not parse and keep reading the session."""
        client = irc_client()
        dispatched: list[str] = []

        def record_message(message: IRCMessage) -> None:
            dispatched.append(message.command)

        client.on_message = record_message
        reader = asyncio.StreamReader()
        reader.feed_data(b":server\r\n:server 002 alpha :hi\r\n")
        reader.feed_eof()
        connection = (reader, mock_writer())

        with (
            patch.object(client, "establish", AsyncMock(return_value=connection)),
            self.assertRaisesRegex(ConnectionError, "connection closed"),
        ):
            async with asyncio.timeout(5):
                await client.run_connection(client.config.servers[0])

        assert dispatched == ["002"]

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
        client = irc_client(ports=(port,))
        try:
            with self.assertRaisesRegex(ConnectionError, "oversized line"):
                async with asyncio.timeout(5):
                    await client.run_connection(client.config.servers[0])
        finally:
            async with asyncio.timeout(5):
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
            # Hold the connection open until the client gives up and leaves.
            await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(ports=(port,))
        try:
            with (
                patch("botnats.irc.client.REGISTRATION_TIMEOUT", 0),
                self.assertRaisesRegex(ConnectionError, "complete registration"),
            ):
                async with asyncio.timeout(5):
                    await client.run_connection(client.config.servers[0])
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

    async def test_reconnect_restarts_registration(self) -> None:
        """Negotiate and register afresh on the session after a registered one.

        The first session advertises a desired capability, spends the whole
        nickname collision budget, and registers under the fallback nick;
        none of it may carry into the next session.
        """
        collision = b":server 433 * alpha :Nickname is already in use\r\n"
        greetings = (
            b":server CAP * LS :multi-prefix\r\n"
            + collision * NICK_COLLISION_LIMIT
            + b":server CAP * ACK :multi-prefix\r\n:server 001 bravo :Welcome\r\n",
            # An ACK of a NEW capability ahead of this session's LS reply
            # must not end negotiation as though that LS were done.
            b":server CAP * NEW :chghost\r\n"
            b":server CAP * ACK :chghost\r\n"
            b":server CAP * LS :sasl chghost\r\n"
            b":server CAP * ACK :chghost\r\n"
            + collision
            + b":server 001 bravo :Welcome\r\n",
        )
        sessions: list[list[bytes]] = []

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            received: list[bytes] = []
            writer.write(greetings[len(sessions)])
            sessions.append(received)
            # Read through the client's post-welcome JOIN, or until it leaves.
            while line := await reader.readline():
                received.append(line)
                if line == b"JOIN #sync\r\n":
                    break

            writer.close()
            await writer.wait_closed()

        def join_on_welcome(message: IRCMessage) -> None:
            if message.command == "001":
                client.send("JOIN", "#sync")

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(ports=(port,))
        client.on_message = join_on_welcome
        try:
            # Lift the send rate limit so neither session waits on it.
            with (
                patch("botnats.irc.client.SEND_BURST", 64.0),
                patch("botnats.irc.client.next_nickname", return_value="bravo"),
            ):
                async with asyncio.timeout(5):
                    for _ in greetings:
                        with self.assertRaisesRegex(
                            ConnectionError,
                            "connection closed",
                        ):
                            await client.run_connection(client.config.servers[0])

                        await client.close()
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

        assert sessions[1] == [
            b"CAP LS 302\r\n",
            b"NICK alpha\r\n",
            b"USER alpha 0 * :alpha\r\n",
            b"CAP REQ :chghost\r\n",
            b"CAP REQ :chghost\r\n",
            b"CAP END\r\n",
            b"NICK bravo\r\n",
            b"JOIN #sync\r\n",
        ]

    async def test_nick_collision_limit_disconnects(self) -> None:
        """Retry up to the collision limit, then raise on the next collision."""
        client = self.cap_client()
        client.nickname_attempts = NICK_COLLISION_LIMIT - 1

        client.nick_collision()
        assert client.nickname_attempts == NICK_COLLISION_LIMIT
        assert client.outbound is not None
        assert (
            client.outbound.get_nowait() == f"NICK {client.current_nick}\r\n".encode()
        )

        with self.assertRaisesRegex(ConnectionError, "collision limit"):
            client.nick_collision()

        assert client.outbound.empty()

    async def test_send_immediate_write_timeout_disconnects(self) -> None:
        """Drop the socket and raise when writes to a peer that never reads stall.

        A close would wait to flush the bytes that did not drain, so the read
        loop would never see EOF.
        """
        client = irc_client()
        line = format_message("PRIVMSG", ("#chan",), "x" * 480)
        async with asyncio.timeout(5):
            reader, writer = await self.unread_connection(client)
            with (
                patch("botnats.irc.client.WRITE_TIMEOUT", 0),
                self.assertRaisesRegex(ConnectionError, "write timed out"),
            ):
                for _ in range(10_000):
                    await client.send_immediate(line, writer)

            assert await reader.read() == b""
            await client.close()

    async def test_send_immediate_skips_waiting_on_another_drain(self) -> None:
        """Write a PONG at once while the sender still waits for its write to drain."""
        client = irc_client()
        writer = mock_writer()
        client.writer = writer
        draining = asyncio.Event()
        drained = asyncio.Event()

        async def stalled_drain() -> None:
            draining.set()
            await drained.wait()

        writer.drain.side_effect = stalled_drain
        async with asyncio.timeout(5):
            sender = asyncio.create_task(
                client.send_immediate(b"PRIVMSG #chan :x\r\n", writer),
            )
            await draining.wait()
            draining.clear()
            pong = asyncio.create_task(
                client.send_immediate(b"PONG :token\r\n", writer),
            )
            await draining.wait()

            writer.write.assert_called_with(b"PONG :token\r\n")
            drained.set()
            await asyncio.gather(sender, pong)

    async def test_outbound_queue_bounded(self) -> None:
        """Verify outbound queue raises ConnectionError when full."""
        client = self.cap_client()
        client.outbound = asyncio.Queue(maxsize=1)
        client.outbound.put_nowait(b"PING :queued\r\n")

        with self.assertRaisesRegex(ConnectionError, "queue is full"):
            client.send("NOTICE", "owner", trailing="hello")

    async def test_send_refuses_closing_socket(self) -> None:
        """Refuse a command once the socket is closing, though the sender lives."""
        client = self.cap_client()
        writer = mock_writer()
        writer.is_closing.return_value = True
        client.writer = writer

        with self.assertRaisesRegex(ConnectionError, "not connected"):
            client.send("NOTICE", "owner", trailing="hello")

        assert client.outbound is not None
        assert client.outbound.empty()

    async def test_send_queue_holds_join_burst(self) -> None:
        """Queue the join burst for a few hundred channels without overflow.

        Each channel takes a JOIN, then WHO, MODE, and ban list queries.
        """

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        client = irc_client(ports=(port,))
        try:
            await client.establish(client.config.servers[0])
            for index in range(250):
                channel = f"#channel{index}"
                client.send("JOIN", channel)
                client.send("WHO", channel)
                client.send("MODE", channel)
                client.send("MODE", channel, "+b")
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

    async def test_disconnect_callback_failure_is_contained(self) -> None:
        """Log a failing disconnect callback and keep reconnecting."""
        client = irc_client()
        ports: list[int] = []
        real_sleep = asyncio.sleep

        def failing_callback() -> None:
            msg = "callback bug"
            raise RuntimeError(msg)

        async def failing_connection(server: IRCServer) -> None:
            ports.append(server.port)
            if len(ports) >= 2:
                raise asyncio.CancelledError

            msg = "connection refused"
            raise OSError(msg)

        async def skip_sleep(delay: float) -> None:
            del delay
            await real_sleep(0)

        client.on_disconnect = failing_callback
        with (
            patch.object(client, "run_connection", failing_connection),
            patch("botnats.irc.client.asyncio.sleep", skip_sleep),
            self.assertLogs("botnats.irc.client", level="WARNING") as logs,
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6667]
        failures = [line for line in logs.output if "callback failed" in line]
        assert len(failures) == 2

    async def test_send_loop_aborts_writer_after_failed_write(self) -> None:
        """Drop the socket and stop sending once a queued write fails."""
        client = irc_client()
        writer = mock_writer()
        writer.drain.side_effect = ConnectionResetError("peer reset")
        client.writer = writer
        outbound: asyncio.Queue[bytes] = asyncio.Queue()
        outbound.put_nowait(b"PING :one\r\n")
        outbound.put_nowait(b"PING :two\r\n")

        async with asyncio.timeout(5):
            await client.send_loop(writer, outbound)

        writer.write.assert_called_once_with(b"PING :one\r\n")
        # A close() after an abort would drop a TLS transport's protocol.
        writer.transport.abort.assert_called_once_with()
        writer.close.assert_not_called()

    async def test_stop_sender_propagates_caller_cancellation(self) -> None:
        """Re-raise cancellation aimed at the caller, not only the sender's own."""
        client = irc_client()
        sender_stopping = asyncio.Event()

        async def slow_sender() -> None:
            try:
                await hang()
            finally:
                # Still winding down when the caller is cancelled in turn.
                sender_stopping.set()
                await hang()

        client.sender_task = asyncio.create_task(slow_sender())
        stopper = asyncio.create_task(client.stop_sender())
        async with asyncio.timeout(5):
            await sender_stopping.wait()
            stopper.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await stopper

        assert client.sender_task is None

    async def test_stop_sender_absorbs_sender_cancellation(self) -> None:
        """Absorb the sender's own cancellation when the caller is not cancelled."""
        client = irc_client()
        client.sender_task = asyncio.create_task(hang())
        client.outbound = asyncio.Queue()

        async with asyncio.timeout(5):
            await client.stop_sender()

        assert client.sender_task is None
        assert client.outbound is None
