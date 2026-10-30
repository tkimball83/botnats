# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the IRC client's connection, dispatch, and sending."""

import asyncio
import errno
import socket
import ssl
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from botnats.irc.client import (
    NICK_COLLISION_LIMIT,
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
from tests.unit.helpers import bounded, hang

REAL_SLEEP = asyncio.sleep


class FakeClock:
    """A loop clock that moves only by the time the sender waits.

    Its timeline records each line written and each wait, in order.
    """

    def __init__(self, client: IRCClient) -> None:
        self.client = client
        self.drained = asyncio.Event()
        # Long past the zero a fresh client is charged up to, so an idle
        # spell must bank no more than the whole credit.
        self.now = 100.0
        # A test clears it to hold the sender in a wait.
        self.resume = asyncio.Event()
        self.resume.set()
        self.sleeping = asyncio.Event()
        self.timeline: list[bytes | float] = []

    async def sleep(self, delay: float) -> None:
        """Pass the time waited, then hold the sender while it is paused."""
        self.now += delay
        self.timeline.append(delay)
        # Yield as a real sleep does, so a sender that stops advancing the
        # clock spins into the test's bound instead of hanging the loop.
        await REAL_SLEEP(0)
        self.sleeping.set()
        await self.resume.wait()

    def time(self) -> float:
        """Return the fake loop time."""
        return self.now

    def write(self, encoded: bytes) -> None:
        """Record a written line, noting when it leaves the queue empty."""
        self.timeline.append(encoded)
        if self.client.outbound is not None and self.client.outbound.empty():
            self.drained.set()


async def dispatch(
    client: IRCClient,
    raw: bytes,
    ping_token: str | None = None,
) -> str | None:
    """Parse and dispatch one server line as run_connection does, bounded."""
    message = parse_message(raw.decode(errors="replace"))
    async with asyncio.timeout(5):
        return await client.dispatch_line(message, raw, mock_writer(), ping_token)


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


def queue_notice(client: IRCClient, text: str) -> bytes:
    """Queue a NOTICE and return the line it puts on the wire."""
    client.send("NOTICE", "owner", trailing=text)
    return format_message("NOTICE", ("owner",), text)


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

        async def stop_sender() -> None:
            async with asyncio.timeout(5):
                await client.stop_sender()

        self.addAsyncCleanup(stop_sender)
        return client

    def paced_client(self) -> tuple[IRCClient, FakeClock]:
        """Return a connected client whose sender runs on a fake clock."""
        client = irc_client()
        clock = FakeClock(client)
        writer = mock_writer()
        writer.write.side_effect = clock.write
        client.outbound = asyncio.Queue()
        client.writer = writer
        self.enterContext(
            patch(
                "asyncio.get_running_loop",
                return_value=SimpleNamespace(time=clock.time),
            ),
        )
        self.enterContext(patch("asyncio.sleep", clock.sleep))
        client.sender_task = asyncio.create_task(
            client.send_loop(writer, client.outbound),
        )

        async def stop_sender() -> None:
            clock.resume.set()
            async with asyncio.timeout(5):
                await client.stop_sender()

        self.addAsyncCleanup(stop_sender)
        return client, clock

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
        assert pong_reply(b"@id=1  :srv PING :token\r\n") == b"PONG :token\r\n"
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

    async def test_establish_uses_tls_only_for_ircs_servers(self) -> None:
        """Connect over TLS to an ircs:// server and in plain text to irc://."""
        servers = (
            IRCServer.parse("ircs://irc.example.test"),
            IRCServer.parse("irc://irc.example.test"),
        )
        client = IRCClient(
            caps=ISupportState(),
            config=IRCClientConfig(
                connect_timeout=1,
                nickname="alpha",
                servers=servers,
                verify_tls=True,
            ),
            on_disconnect=lambda: None,
            on_message=ignore_message,
        )
        connect = AsyncMock(return_value=(asyncio.StreamReader(), mock_writer()))

        with patch("asyncio.open_connection", connect):
            async with asyncio.timeout(5):
                for server in servers:
                    await client.establish(server)
                    await client.close()

        assert client.tls_context is not None
        contexts = [call.kwargs["ssl"] for call in connect.await_args_list]
        assert contexts == [client.tls_context, None]

    async def test_establish_registers_a_fixed_username(self) -> None:
        """Register any valid nick under a username every server accepts.

        Without identd the server takes the username from USER, and hybrid,
        solanum, and charybdis refuse one that does not start alphanumeric.
        """
        client = irc_client()
        client.config = replace(client.config, nickname="_bot")
        connect = AsyncMock(return_value=(asyncio.StreamReader(), mock_writer()))
        with patch("asyncio.open_connection", connect):
            async with asyncio.timeout(5):
                await client.establish(client.config.servers[0])

        assert client.outbound is not None
        lines = [client.outbound.get_nowait() for _ in range(3)]
        async with asyncio.timeout(5):
            await client.close()

        assert lines == [
            b"CAP LS 302\r\n",
            b"NICK _bot\r\n",
            b"USER botnats 0 * :_bot\r\n",
        ]

    async def test_establish_gives_up_after_connect_timeout(self) -> None:
        """Abandon a connection attempt that outlasts the connect timeout."""
        client = irc_client()
        client.config = replace(client.config, connect_timeout=0)

        async def unanswered(*arguments: object, **options: object) -> None:
            del arguments, options
            await hang()

        with patch("asyncio.open_connection", unanswered):
            # The bound sits outside assertRaises: an unenforced connect
            # timeout ends in the bound's cancellation, not a TimeoutError.
            async with asyncio.timeout(5):
                with self.assertRaises(TimeoutError):
                    await client.establish(client.config.servers[0])

    async def test_establish_races_past_an_unanswered_address(self) -> None:
        """Reach a later resolved address while an earlier one never answers.

        A first address that drops packets, as broken IPv6 or a dead
        round-robin member does, must not hold the connect until it times out.
        """

        async def server_handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            # Hold the connection until the client leaves.
            await reader.read()
            writer.close()
            await writer.wait_closed()

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
        port = server.sockets[0].getsockname()[1]
        unanswered = ("192.0.2.1", port)
        live = ("127.0.0.1", port)
        attempts: list[tuple[str, int]] = []
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect

        async def resolve(
            *arguments: object, **options: object
        ) -> list[tuple[object, ...]]:
            del arguments, options
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)
                for address in (unanswered, live)
            ]

        async def connect(sock: socket.socket, address: tuple[str, int]) -> None:
            attempts.append(address)
            if address == unanswered:
                await hang()

            await real_connect(sock, address)

        client = irc_client()
        try:
            with (
                patch.object(loop, "getaddrinfo", resolve),
                patch.object(loop, "sock_connect", connect),
                # Race the next address at once instead of after a real wait.
                patch("botnats.irc.client.HAPPY_EYEBALLS_DELAY", 0),
            ):
                _, writer = await bounded(
                    client.establish(IRCServer("irc.example.test", port, tls=False)),
                )

            assert attempts == [unanswered, live]
            assert writer.get_extra_info("peername") == live
        finally:
            async with asyncio.timeout(5):
                await client.close()
                server.close()
                await server.wait_closed()

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
            patch("asyncio.sleep", record_sleep),
            # The largest jitter, so its scale is pinned too.
            patch("secrets.randbelow", return_value=999),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6668] * 5 + [6667]
        # The backoff grows to its cap of 8 steps and then stays there.
        assert delays == [1.5 ** min(attempt, 8) + 0.999 for attempt in range(1, 11)]

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
            patch("asyncio.sleep", record_sleep),
            patch("secrets.randbelow", return_value=0),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6668, 6667]
        assert delays == [1.5, 1.5**2]

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
            patch("asyncio.sleep", record_sleep),
            patch("botnats.irc.client.STABLE_SESSION_SECONDS", 0.0),
            patch("secrets.randbelow", return_value=0),
            self.assertLogs("botnats.irc.client", level="WARNING"),
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        # Failure rotates away; the stable session keeps its server and
        # resets the backoff to the base delay.
        assert ports == [6667, 6668, 6668]
        assert delays == [1.5, 1.0]

    async def test_send_loop_spends_flood_credit_then_waits(self) -> None:
        """Send a burst that fits the flood credit at once, then wait each cost."""
        client, clock = self.paced_client()
        # Each short line costs two seconds of the ten-second credit.
        lines = [queue_notice(client, str(index)) for index in range(7)]
        assert client.queue_delay == 14.0

        async with asyncio.timeout(5):
            await clock.drained.wait()

        assert clock.timeline == [*lines[:5], 2.0, lines[5], 2.0, lines[6]]
        assert client.queue_delay == 0.0
        # A written line leaves no zero count behind.
        assert not client.queued_lines

    async def test_send_loop_charges_long_lines_more(self) -> None:
        """Charge a long line the larger of ircu's and UnrealIRCd's costs."""
        client, clock = self.paced_client()
        burst = [queue_notice(client, str(index)) for index in range(5)]
        # UnrealIRCd's 1 + len / 90 is the larger cost of the 460-byte line,
        # ircu's 2 + len / 120 that of the 150-byte one.
        longer = queue_notice(client, "x" * 444)
        shorter = queue_notice(client, "x" * 134)
        assert (len(longer), len(shorter)) == (460, 150)

        async with asyncio.timeout(5):
            await clock.drained.wait()

        assert clock.timeline == [*burst, 6.0, longer, 3.0, shorter]

    async def test_ping_and_pong_spend_flood_credit(self) -> None:
        """Write a PING or PONG at once, and make the queued lines wait its cost."""
        client, clock = self.paced_client()
        writer = client.writer
        assert writer is not None
        ping = format_message("PING", (), "token")
        pong = pong_reply(b"PING :token\r\n")
        burst = [queue_notice(client, str(index)) for index in range(5)]
        async with asyncio.timeout(5):
            await clock.drained.wait()
            # The credit is spent, yet the PING goes out without waiting.
            await client.send_immediate(ping, writer)
            clock.resume.clear()
            later = queue_notice(client, "later")
            await clock.sleeping.wait()
            # A PONG sent while that line waits on the PING lengthens its wait.
            await client.send_immediate(pong, writer)
            clock.drained.clear()
            clock.resume.set()
            await clock.drained.wait()

        assert clock.timeline == [*burst, ping, 4.0, pong, 2.0, later]

    async def test_send_unless_waiting_skips_a_waiting_copy(self) -> None:
        """Skip a copy of a line not yet written when asked, and only then."""
        client, clock = self.paced_client()
        burst = [queue_notice(client, str(index)) for index in range(5)]
        op = format_message("MODE", ("#chan", "+o", "beta"), None)
        async with asyncio.timeout(5):
            await clock.drained.wait()
            clock.drained.clear()
            clock.resume.clear()
            assert client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            await clock.sleeping.wait()
            # The first copy waits on the credit: a help copy is skipped, and
            # any other caller's copy still queues.
            assert not client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            assert client.queue_delay == 2
            assert client.send("MODE", "#chan", "+o", "beta")
            assert client.queue_delay == 2 + 2
            # Wake the sender, which writes the first copy and then waits to
            # write the second: a help copy is still skipped.
            clock.sleeping.clear()
            clock.resume.set()
            clock.resume.clear()
            await clock.sleeping.wait()
            assert not client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            clock.resume.set()
            await clock.drained.wait()
            clock.drained.clear()
            # Once every copy is written, the line queues again.
            assert client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            await clock.drained.wait()

        assert clock.timeline == [*burst, 2.0, op, 2.0, op, 2.0, op]

    async def test_stop_sender_forgets_waiting_lines(self) -> None:
        """Queue a help line on the next connection, though its copy never went out."""
        client, clock = self.paced_client()
        burst = [queue_notice(client, str(index)) for index in range(5)]
        op = format_message("MODE", ("#chan", "+o", "beta"), None)
        writer = mock_writer()
        writer.write.side_effect = clock.write
        connect = AsyncMock(return_value=(asyncio.StreamReader(), writer))
        async with asyncio.timeout(5):
            await clock.drained.wait()
            clock.resume.clear()
            assert client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            assert not client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            await clock.sleeping.wait()
            await client.close()
            clock.drained.clear()
            clock.resume.set()
            with patch("asyncio.open_connection", connect):
                await client.establish(client.config.servers[0])

            assert client.send("MODE", "#chan", "+o", "beta", unless_waiting=True)
            await clock.drained.wait()

        assert clock.timeline == [
            *burst,
            2.0,
            b"CAP LS 302\r\n",
            b"NICK alpha\r\n",
            b"USER botnats 0 * :alpha\r\n",
            op,
        ]

    async def test_queue_delay_counts_queued_cost(self) -> None:
        """Report the flood credit the queued lines spend, long lines costing more."""
        client = self.cap_client(negotiating=False)
        assert client.queue_delay == 0.0

        # The short JOIN costs two seconds, the 460-byte PRIVMSG six.
        client.send("JOIN", "#one")
        client.send("PRIVMSG", "#chan", trailing="x" * 443)
        assert client.queue_delay == 2 + 6

    async def test_establish_starts_with_whole_flood_credit(self) -> None:
        """Send registration at once, though the last connection spent its credit."""
        client, clock = self.paced_client()
        burst = [queue_notice(client, str(index)) for index in range(5)]
        writer = mock_writer()
        writer.write.side_effect = clock.write
        connect = AsyncMock(return_value=(asyncio.StreamReader(), writer))
        async with asyncio.timeout(5):
            await clock.drained.wait()
            await client.close()
            clock.drained.clear()
            with patch("asyncio.open_connection", connect):
                await client.establish(client.config.servers[0])

            await clock.drained.wait()

        assert clock.timeline == [
            *burst,
            b"CAP LS 302\r\n",
            b"NICK alpha\r\n",
            b"USER botnats 0 * :alpha\r\n",
        ]

    async def test_registration_nick_rejections_retry(self) -> None:
        """Verify registration retries every nickname rejection numeric."""
        client = irc_client()
        retry = MagicMock()
        numerics = ("432", "433", "436", "437")

        with patch.object(IRCClient, "nick_collision", retry):
            for numeric in numerics:
                raw = f":server {numeric} * alpha :nickname rejected\r\n".encode()
                await dispatch(client, raw)

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
                await dispatch(client, raw)

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
                assert await dispatch(client, raw, "token") == "token"

        assert dispatched == ["002"]
        assert len(logs.output) == 1
        assert "IRC message handler failed for PRIVMSG" in logs.output[0]

    async def test_cap_line_reaches_capability_negotiation(self) -> None:
        """Route a CAP line to negotiation rather than the message handler."""
        client = self.cap_client()
        handler = MagicMock()
        client.on_message = handler
        await dispatch(client, b":server CAP * LS :chghost\r\n")

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
        """Follow the server-assigned nick and own NICK changes before handlers run."""
        client = self.cap_client()
        # Handlers read the nick, so they must see each change already made.
        seen: list[str] = []

        def record_nick(message: IRCMessage) -> None:
            del message
            seen.append(client.current_nick)

        client.on_message = record_nick

        await dispatch(client, b":server 001 Alpha[ :Welcome\r\n")
        assert client.registered_with_server
        assert not client.cap_negotiating
        assert client.current_nick == "Alpha["

        # rfc1459 folds [ and { together, so this NICK is this client's own.
        await dispatch(client, b":alpha{!user@host NICK :beta\r\n")
        assert client.current_nick == "beta"
        assert client.is_self("BETA")

        await dispatch(client, b":other!user@host NICK :gamma\r\n")
        assert client.current_nick == "beta"
        assert seen == ["Alpha[", "beta", "beta"]

    async def test_nick_collision_keeps_configured_length(self) -> None:
        """Pick a fallback nick as long as the configured one.

        A collision happens during registration, before ISUPPORT advertises
        the server's own limit; configuration keeps the nick within RFC 1459's.
        """
        client = self.cap_client()

        client.nick_collision()

        assert len(client.current_nick) == len("alpha")
        assert client.outbound is not None
        assert (
            client.outbound.get_nowait() == f"NICK {client.current_nick}\r\n".encode()
        )

    async def test_matching_pong_clears_ping_token(self) -> None:
        """Clear the outstanding PING only for a PONG carrying its token."""
        client = irc_client()

        other = b":server PONG server :other\r\n"
        matching = b":server PONG server :token\r\n"
        assert await dispatch(client, other, "token") == "token"
        assert await dispatch(client, matching, "token") is None

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
                assert await dispatch(client, raw, "token") == "token"
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
            with (
                self.subTest(reply=reply[:6]),
                patch.object(client, "send_immediate", AsyncMock()) as send,
            ):
                assert await dispatch(client, raw, "tok") == "tok"
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
        # IRCv3 allows an empty LS list.
        for line in (":server CAP * LS :sasl\r\n", ":server CAP * LS :\r\n"):
            with self.subTest(line=line):
                client = self.cap_client()
                client.handle_cap(parse_message(line))

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

    async def test_cap_ls_after_registration_is_ignored(self) -> None:
        """Ignore a late CAP LS instead of restarting negotiation traffic.

        A REQ or END it queued could find the send queue full and end the
        registered session.
        """
        client = self.cap_client(negotiating=False)
        client.cap_available = {"multi-prefix"}
        client.cap_ls_done = True

        client.handle_cap(
            parse_message(":server CAP alpha LS :chghost multi-prefix\r\n"),
        )

        assert client.cap_available == {"multi-prefix"}
        assert client.cap_ls_done
        assert not client.cap_negotiating
        assert client.outbound is not None
        assert client.outbound.empty()

    async def test_cap_new_and_del_after_registration(self) -> None:
        """Verify NEW requests desired capabilities and DEL is ignored."""
        client = self.cap_client(negotiating=False)
        # The LS phase finished before registration, so only the ended
        # negotiation keeps this ACK from sending another CAP END.
        client.cap_ls_done = True
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

        assert await dispatch(client, raw, "token") == "token"
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

    async def test_close_survives_reset_socket(self) -> None:
        """Return normally when a reset socket re-raises its error on close.

        run_forever closes after every session, so the error would end it.
        """
        client = irc_client()
        writer = mock_writer()
        writer.wait_closed.side_effect = ConnectionResetError("peer reset")
        client.writer = writer

        async with asyncio.timeout(5):
            await client.close()

        assert client.writer is None
        writer.transport.abort.assert_called_once_with()

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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
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

    async def test_registered_session_outlives_registration_timeout(self) -> None:
        """Idle past the registration deadline with a PING once registered."""
        client = irc_client()
        dispatched: list[str] = []

        def record_message(message: IRCMessage) -> None:
            dispatched.append(message.command)

        client.on_message = record_message
        writer = mock_writer()
        client.writer = writer
        reader = asyncio.StreamReader()
        reader.feed_data(b":server 001 alpha :Welcome\r\n")
        loop = asyncio.get_running_loop()

        def answer_ping(encoded: bytes) -> None:
            # Answer a loop turn later, so the client must wait for the PONG.
            if encoded.startswith(b"PING :"):
                token = encoded.removeprefix(b"PING :").removesuffix(b"\r\n")
                loop.call_soon(
                    reader.feed_data,
                    b":server PONG server :" + token + b"\r\n:server 002 alpha :hi\r\n",
                )
                loop.call_soon(reader.feed_eof)

        writer.write.side_effect = answer_ping
        connection = (reader, writer)

        with (
            patch.object(client, "establish", AsyncMock(return_value=connection)),
            patch("botnats.irc.client.REGISTRATION_TIMEOUT", 0),
            patch("botnats.irc.client.IDLE_TIMEOUT", 0),
            self.assertRaisesRegex(ConnectionError, "connection closed"),
        ):
            async with asyncio.timeout(5):
                await client.run_connection(client.config.servers[0])

        assert dispatched == ["001", "002"]

    async def test_answered_ping_lets_the_next_idle_spell_ping(self) -> None:
        """Clear an answered PING, so a quiet session PINGs again and stays up."""
        client = irc_client()
        dispatched: list[str] = []

        def record_message(message: IRCMessage) -> None:
            dispatched.append(message.command)

        client.on_message = record_message
        writer = mock_writer()
        reader = asyncio.StreamReader()
        reader.feed_data(b":server 001 alpha :Welcome\r\n")
        pings: list[bytes] = []

        def answer_ping(encoded: bytes) -> None:
            # Answer before the client reads again, as the PONG wait is zero:
            # a PING its PONG did not clear then fails at once.
            if encoded.startswith(b"PING :"):
                pings.append(encoded)
                token = encoded.removeprefix(b"PING :").removesuffix(b"\r\n")
                reader.feed_data(b":server PONG server :" + token + b"\r\n")
                if len(pings) == 2:
                    reader.feed_data(b":server 002 alpha :hi\r\n")
                    reader.feed_eof()

        writer.write.side_effect = answer_ping
        connection = (reader, writer)

        with (
            patch.object(client, "establish", AsyncMock(return_value=connection)),
            patch("botnats.irc.client.IDLE_TIMEOUT", 0),
            patch("botnats.irc.client.PONG_TIMEOUT", 0),
            self.assertRaisesRegex(ConnectionError, "connection closed"),
        ):
            async with asyncio.timeout(5):
                await client.run_connection(client.config.servers[0])

        assert len(pings) == 2
        assert dispatched == ["001", "002"]

    async def test_socket_timeout_ends_session_without_ping(self) -> None:
        """End the session with a socket's ETIMEDOUT, not a PING as if idle."""
        client = irc_client()
        writer = mock_writer()
        reader = asyncio.StreamReader()
        reader.feed_data(b":server 001 alpha :Welcome\r\n")
        error = TimeoutError(errno.ETIMEDOUT, "Connection timed out")

        def lose_connection(message: IRCMessage) -> None:
            # Once registered, the kernel gives up on the peer, and
            # connection_lost stores its error on the reader.
            if message.command == "001":
                reader.set_exception(error)

        client.on_message = lose_connection
        connection = (reader, writer)

        with (
            patch.object(client, "establish", AsyncMock(return_value=connection)),
            self.assertRaises(TimeoutError) as raised,
        ):
            async with asyncio.timeout(5):
                await client.run_connection(client.config.servers[0])

        assert raised.exception is error
        writer.write.assert_not_called()

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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
        port = server.sockets[0].getsockname()[1]
        client = irc_client(ports=(port,))
        client.on_message = join_on_welcome
        try:
            # Lift the flood credit so neither session waits on it.
            with (
                patch("botnats.irc.client.SEND_CREDIT", 1000.0),
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
            b"USER botnats 0 * :alpha\r\n",
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

    async def test_send_immediate_propagates_socket_timeout(self) -> None:
        """Raise a socket's ETIMEDOUT from drain as itself, not as a write timeout."""
        client = irc_client()
        writer = mock_writer()
        error = TimeoutError(errno.ETIMEDOUT, "Connection timed out")
        writer.drain.side_effect = error

        with self.assertRaises(TimeoutError) as raised:
            async with asyncio.timeout(5):
                await client.send_immediate(b"PING :token\r\n", writer)

        assert raised.exception is error

    async def test_send_immediate_refuses_closing_socket(self) -> None:
        """Refuse a line once the socket is closing, and write nothing.

        A closing TLS transport drops writes without raising until its
        connection_lost arrives.
        """
        client = irc_client()
        writer = mock_writer()
        writer.is_closing.return_value = True

        with self.assertRaisesRegex(ConnectionError, "not connected"):
            async with asyncio.timeout(5):
                await client.send_immediate(b"PING :token\r\n", writer)

        writer.write.assert_not_called()

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

        # A refused line is not waiting, so unless_waiting help still sends it.
        assert not client.queued_lines
        assert client.queue_delay == 0.0

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

    async def test_send_refuses_while_close_stops_sender(self) -> None:
        """Refuse a command while close waits for the sender, the socket still open.

        The command would find no queue, and its caller handles only
        ConnectionError.
        """
        client = irc_client()
        client.outbound = asyncio.Queue()
        client.writer = mock_writer()
        sender_stopping = asyncio.Event()
        released = asyncio.Event()
        self.addCleanup(released.set)

        async def slow_sender() -> None:
            try:
                await hang()
            finally:
                sender_stopping.set()
                await released.wait()

        client.sender_task = asyncio.create_task(slow_sender())
        closer = asyncio.create_task(client.close())
        async with asyncio.timeout(5):
            await sender_stopping.wait()
            assert client.connected
            with self.assertRaisesRegex(ConnectionError, "not connected"):
                client.send("NOTICE", "owner", trailing="hello")

            released.set()
            await closer

        assert client.writer is None

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

        server = await bounded(asyncio.start_server(server_handler, "127.0.0.1", 0))
        port = server.sockets[0].getsockname()[1]
        client = irc_client(ports=(port,))
        try:
            async with asyncio.timeout(5):
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
        """Log a failing disconnect callback and still close and reconnect."""
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
            patch.object(client, "close", AsyncMock()) as close,
            patch("asyncio.sleep", skip_sleep),
            self.assertLogs("botnats.irc.client", level="WARNING") as logs,
            self.assertRaises(asyncio.CancelledError),
        ):
            async with asyncio.timeout(5):
                await client.run_forever()

        assert ports == [6667, 6667]
        assert close.await_count == 2
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
        released = asyncio.Event()
        self.addCleanup(released.set)

        async def slow_sender() -> None:
            try:
                await hang()
            finally:
                # Still winding down when the caller is cancelled in turn.
                sender_stopping.set()
                await released.wait()

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
        client.writer = mock_writer()
        client.send("JOIN", "#one")
        assert client.queue_delay == 2.0

        async with asyncio.timeout(5):
            await client.stop_sender()

        assert client.sender_task is None
        assert client.outbound is None
        # The discarded lines no longer delay anything.
        assert client.queue_delay == 0.0
