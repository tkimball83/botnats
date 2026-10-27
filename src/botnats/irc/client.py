# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC client with reconnection and rate-limited sending."""

import asyncio
import logging
import secrets
import ssl
from contextlib import suppress
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING

from botnats import error_label, log_task_failure
from botnats.irc.protocol import (
    MAX_IRC_MESSAGE_BYTES,
    IRCMessage,
    ISupportState,
    format_message,
    parse_message,
)
from botnats.validators import validate_server_url

if TYPE_CHECKING:
    from collections.abc import Callable

LOGGER = logging.getLogger(__name__)

DESIRED_CAPS = frozenset({"chghost", "multi-prefix"})
# RFC 1459's NICKLEN: a collision happens during registration, before the
# server advertises its own limit.
FALLBACK_NICK_LENGTH = 9
# A quiet connection gets a PING after IDLE_TIMEOUT and must answer it
# within PONG_TIMEOUT.
IDLE_TIMEOUT = 120.0
IRC_SCHEMES = frozenset({"irc", "ircs"})
NICK_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
NICK_COLLISION_LIMIT = 20
# Room for a full join burst: a JOIN and the WHO, MODE, and ban list queries
# that follow it, for a few hundred channels.
OUTBOUND_LIMIT = 1024
PONG_TIMEOUT = 30.0
REGISTRATION_TIMEOUT = 60.0
SEND_BURST = 4.0
SEND_RATE = 1.0
STABLE_SESSION_SECONDS = 60.0
WRITE_TIMEOUT = 30.0


@dataclass(frozen=True, slots=True)
class IRCServer:
    """One IRC connection target."""

    host: str
    port: int
    tls: bool

    @classmethod
    def parse(cls, value: str) -> IRCServer:
        """Construct an IRC server from a URL string."""
        scheme, hostname, port = validate_server_url(value, IRC_SCHEMES, "IRC")
        return cls(
            host=hostname,
            port=port or (6697 if scheme == "ircs" else 6667),
            tls=scheme == "ircs",
        )


@dataclass(frozen=True, slots=True)
class IRCClientConfig:
    """Connection settings for an IRC client."""

    connect_timeout: float
    nickname: str
    servers: tuple[IRCServer, ...]
    verify_tls: bool


class IRCClient:
    """Reconnectable IRC socket with a rate-limited send queue."""

    def __init__(
        self,
        *,
        caps: ISupportState,
        config: IRCClientConfig,
        on_disconnect: Callable[[], None],
        on_message: Callable[[IRCMessage], None],
    ) -> None:
        self.cap_available: set[str] = set()
        self.cap_negotiating = False
        self.cap_ls_done = False
        self.caps = caps
        self.config = config
        self.current_nick = config.nickname
        self.nickname_attempts = 0
        self.on_disconnect = on_disconnect
        self.on_message = on_message
        self.outbound: asyncio.Queue[bytes] | None = None
        self.sender_task: asyncio.Task[None] | None = None
        self.registered_with_server = False
        needs_tls = any(s.tls for s in config.servers)
        self.tls_context = ssl.create_default_context() if needs_tls else None
        if self.tls_context is not None and not config.verify_tls:
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE

        self.writer: asyncio.StreamWriter | None = None

    async def close(self) -> None:
        """Shut down the sender and drop the socket."""
        try:
            await self.stop_sender()
        finally:
            writer = self.writer
            self.writer = None
            if writer is not None:
                # Abort, not close: a close waits to flush unsent bytes, which
                # a peer that stopped reading never takes.
                writer.transport.abort()
                with suppress(OSError):
                    await writer.wait_closed()

    @property
    def connected(self) -> bool:
        """Return whether the underlying socket is open."""
        return self.writer is not None and not self.writer.is_closing()

    async def dispatch_line(
        self,
        message: IRCMessage,
        raw: bytes,
        writer: asyncio.StreamWriter,
        ping_token: str | None,
    ) -> str | None:
        """Handle one parsed message and return the updated PING token."""
        if message.command == "PING":
            # Echo the server's raw token bytes: lossy decoding can inflate
            # them past 512, and a re-encoded token would not byte-match.
            await self.send_immediate(pong_reply(raw), writer)
            return ping_token

        if (
            message.command == "PONG"
            and ping_token is not None
            and message.params
            and message.params[-1] == ping_token
        ):
            return None

        if (
            message.command in {"432", "433", "436", "437"}
            and not self.registered_with_server
        ):
            self.nick_collision()
            return ping_token

        if message.command == "CAP":
            self.handle_cap(message)
            return ping_token

        self.track_registration(message)
        try:
            self.on_message(message)
        except Exception:
            LOGGER.exception("IRC message handler failed for %s", message.command)

        return ping_token

    async def establish(
        self,
        server: IRCServer,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a connection to the given server and begin registration."""
        context = self.tls_context if server.tls else None
        connect = asyncio.open_connection(
            server.host,
            server.port,
            ssl=context,
            server_hostname=server.host if context else None,
        )
        async with asyncio.timeout(self.config.connect_timeout):
            reader, writer = await connect
        self.writer = writer
        outbound: asyncio.Queue[bytes] = asyncio.Queue(maxsize=OUTBOUND_LIMIT)
        self.outbound = outbound
        self.sender_task = asyncio.create_task(
            self.send_loop(writer, outbound),
            name="irc-sender",
        )
        self.sender_task.add_done_callback(
            partial(log_task_failure, logger=LOGGER, label="IRC sender"),
        )
        self.cap_available = set()
        self.cap_negotiating = True
        self.cap_ls_done = False
        self.current_nick = self.config.nickname
        self.nickname_attempts = 0
        LOGGER.info("connected to IRC server %s:%s", server.host, server.port)
        self.send("CAP", "LS", "302")
        self.send("NICK", self.current_nick)
        self.send(
            "USER",
            self.config.nickname,
            "0",
            "*",
            trailing=self.config.nickname,
        )
        return reader, writer

    def handle_cap(self, message: IRCMessage) -> None:
        """Process CAP subcommands during capability negotiation."""
        if len(message.params) < 3:
            return

        subcommand = message.params[1].upper()
        caps = {cap.partition("=")[0] for cap in message.params[-1].split()}
        if subcommand == "LS":
            if not self.cap_negotiating:
                return

            self.cap_available.update(caps)
            if len(message.params) >= 4 and message.params[2] == "*":
                return

            self.cap_ls_done = True
            wanted = DESIRED_CAPS & self.cap_available
            if wanted:
                self.send("CAP", "REQ", trailing=" ".join(sorted(wanted)))
            else:
                self.send("CAP", "END")
                self.cap_negotiating = False
        elif subcommand == "NEW":
            wanted = DESIRED_CAPS & caps
            if wanted:
                # A full send queue is temporary; it must not end the session.
                with suppress(ConnectionError):
                    self.send("CAP", "REQ", trailing=" ".join(sorted(wanted)))
        elif subcommand in {"ACK", "NAK"} and self.cap_negotiating and self.cap_ls_done:
            # End only once the LS phase has issued its REQ; a NEW-triggered
            # ACK arriving mid-LS must not cut the initial exchange short.
            self.send("CAP", "END")
            self.cap_negotiating = False

    def is_self(self, nickname: str) -> bool:
        """Return whether a nickname identifies this client."""
        return self.caps.fold(nickname) == self.caps.fold(self.current_nick)

    def nick_collision(self) -> None:
        """Pick a random fallback nickname after registration rejects one."""
        self.nickname_attempts += 1
        if self.nickname_attempts > NICK_COLLISION_LIMIT:
            msg = "IRC nickname collision limit exceeded"
            raise ConnectionError(msg)

        self.current_nick = next_nickname(
            min(len(self.config.nickname), FALLBACK_NICK_LENGTH),
        )
        self.send("NICK", self.current_nick)

    def reconnect(self) -> None:
        """Force a reconnection by dropping the current socket."""
        if self.writer is not None:
            self.writer.transport.abort()

    async def run_connection(self, server: IRCServer) -> None:
        """Read and dispatch messages from a single server session."""
        self.registered_with_server = False
        reader, writer = await self.establish(server)
        loop = asyncio.get_running_loop()
        ping_token: str | None = None
        pong_deadline = 0.0
        registration_deadline = loop.time() + REGISTRATION_TIMEOUT
        while True:
            now = loop.time()
            if ping_token is None:
                timeout = IDLE_TIMEOUT
            else:
                timeout = max(0.0, pong_deadline - now)

            if not self.registered_with_server:
                timeout = min(timeout, max(0.0, registration_deadline - now))

            try:
                async with asyncio.timeout(timeout):
                    raw = await reader.readline()
            except TimeoutError as error:
                if (
                    not self.registered_with_server
                    and loop.time() >= registration_deadline
                ):
                    msg = "IRC server did not complete registration"
                    raise ConnectionError(msg) from error

                if ping_token is not None:
                    msg = "IRC server did not answer client PING"
                    raise ConnectionError(msg) from error

                ping_token = secrets.token_hex(16)
                pong_deadline = loop.time() + PONG_TIMEOUT
                await self.send_immediate(
                    format_message("PING", (), ping_token),
                    writer,
                )
                continue
            except ValueError as error:
                msg = "IRC server sent an oversized line"
                raise ConnectionError(msg) from error

            if not check_line(raw):
                continue

            try:
                message = parse_message(raw.decode(errors="replace"))
            except ValueError:
                continue

            ping_token = await self.dispatch_line(message, raw, writer, ping_token)

    async def run_forever(self) -> None:
        """Maintain a persistent connection with automatic reconnection."""
        index = 0
        backoff = 0
        loop = asyncio.get_running_loop()
        while True:
            server = self.config.servers[index % len(self.config.servers)]
            session_start = loop.time()
            try:
                await self.run_connection(server)
            except (OSError, ValueError) as error:
                LOGGER.warning(
                    "IRC connection to %s:%s ended: %s",
                    server.host,
                    server.port,
                    error_label(error),
                )
            finally:
                try:
                    self.on_disconnect()
                except Exception:
                    LOGGER.exception("IRC disconnect callback failed")

                await self.close()

            duration = loop.time() - session_start
            if self.registered_with_server and duration >= STABLE_SESSION_SECONDS:
                backoff = 0
            else:
                index += 1
                backoff = min(backoff + 1, 8)

            delay = 1.5**backoff + secrets.randbelow(1000) / 1000
            await asyncio.sleep(delay)

    def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Enqueue an IRC command for rate-limited delivery."""
        encoded = format_message(command, params, trailing)
        outbound = self.outbound
        if (
            not self.connected
            or outbound is None
            or self.sender_task is None
            or self.sender_task.done()
        ):
            msg = "IRC is not connected"
            raise ConnectionError(msg)

        try:
            outbound.put_nowait(encoded)
        except asyncio.QueueFull as error:
            msg = "IRC outbound queue is full"
            raise ConnectionError(msg) from error

    async def send_immediate(
        self,
        encoded: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Write a pre-encoded message to the socket without queuing."""
        if self.writer is not writer or writer.is_closing():
            msg = "IRC is not connected"
            raise ConnectionError(msg)

        writer.write(encoded)
        try:
            async with asyncio.timeout(WRITE_TIMEOUT):
                await writer.drain()
        except TimeoutError as error:
            # Abort: a close would wait on the very bytes that did not drain.
            writer.transport.abort()
            msg = "IRC write timed out"
            raise ConnectionError(msg) from error

    async def send_loop(
        self,
        writer: asyncio.StreamWriter,
        outbound: asyncio.Queue[bytes],
    ) -> None:
        """Drain the outbound queue at the configured send rate."""
        loop = asyncio.get_running_loop()
        tokens = SEND_BURST
        updated = loop.time()
        try:
            while True:
                encoded = await outbound.get()
                now = loop.time()
                tokens = min(SEND_BURST, tokens + (now - updated) * SEND_RATE)
                updated = now
                if tokens < 1.0:
                    await asyncio.sleep((1.0 - tokens) / SEND_RATE)
                    updated = loop.time()
                    tokens = 0.0
                else:
                    tokens -= 1.0

                await self.send_immediate(encoded, writer)
        except OSError, RuntimeError:
            # Abort: a close() after an abort drops a TLS transport's protocol,
            # and the reader's next resume_reading() would then crash.
            writer.transport.abort()

    async def stop_sender(self) -> None:
        """Cancel the sender task and discard pending messages."""
        task = self.sender_task
        self.sender_task = None
        self.outbound = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None and current.cancelling() > 0:
                    raise

    def track_registration(self, message: IRCMessage) -> None:
        """Update the current nickname from server replies."""
        if message.command == "001":
            self.cap_negotiating = False
            self.registered_with_server = True
            if message.params:
                self.current_nick = message.params[0]
        elif (
            message.command == "NICK"
            and message.prefix is not None
            and message.params
            and self.is_self(message.prefix.nick)
        ):
            self.current_nick = message.params[-1]


def check_line(raw: bytes) -> bool:
    """Return whether a complete line is parseable; raise on truncation.

    readline yields an unterminated fragment at EOF; a partial line cut off
    by a dying peer must not be parsed as a complete message. A complete but
    oversized line (tags or a sloppy server pushing past 512 bytes) is merely
    skipped: disconnecting would turn one bad line into reconnect churn.
    """
    if not raw.endswith(b"\n"):
        msg = "IRC connection closed"
        raise ConnectionError(msg)

    if len(raw) > MAX_IRC_MESSAGE_BYTES:
        LOGGER.debug("ignoring oversized %d-byte IRC line", len(raw))
        return False

    return True


def pong_reply(line: bytes) -> bytes:
    """Build a PONG that echoes a PING's raw token bytes.

    Tags and prefix, with any repeated separators after them, are dropped
    first, mirroring parse_message, so a leading prefix's space-colon is not
    mistaken for the trailing-parameter marker.
    The token is kept verbatim, so the reply never exceeds the wire length of
    the PING that parse_message already accepted.
    """
    rest = line.rstrip(b"\r\n")
    if rest.startswith(b"@"):
        _, _, rest = rest.partition(b" ")
        rest = rest.lstrip(b" ")

    if rest.startswith(b":"):
        _, _, rest = rest.partition(b" ")
        rest = rest.lstrip(b" ")

    head, trailing_sep, trailing = rest.partition(b" :")
    tokens = [token for token in head.split(b" ") if token][1:]
    reply = b" ".join([b"PONG", *tokens])
    if trailing_sep:
        return reply + b" :" + trailing + b"\r\n"

    return reply + b"\r\n"


def next_nickname(length: int) -> str:
    """Generate a random alphabetic nickname of the given length."""
    return "".join(secrets.choice(NICK_ALPHABET) for _ in range(length))
