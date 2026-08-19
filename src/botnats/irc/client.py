# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC client with reconnection and rate-limited sending."""

import asyncio
import logging
import secrets
import ssl
import uuid
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from botnats import error_label
from botnats.irc.protocol import (
    CASEMAPPINGS,
    DEFAULT_CASEMAPPING,
    MAX_IRC_MESSAGE_BYTES,
    IRCMessage,
    casefold,
    format_message,
    parse_message,
)
from botnats.validators import validate_server_url

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

LOGGER = logging.getLogger(__name__)

DEFAULT_NICK_LENGTH = 9
DESIRED_CAPS = frozenset({"chghost", "multi-prefix"})
IRC_SCHEMES = frozenset({"irc", "ircs"})
MIN_CAP_MULTILINE_PARAMS = 4
MIN_CAP_PARAMS = 3
NICK_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
NICK_COLLISION_LIMIT = 20
OUTBOUND_LIMIT = 64
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
    """Connection and rate-limit settings for an IRC client."""

    connect_timeout: float
    nickname: str
    servers: tuple[IRCServer, ...]
    verify_tls: bool
    idle_timeout: float = 120.0
    pong_timeout: float = 30.0

    def __post_init__(self) -> None:
        """Validate timing and server parameters."""
        if (
            self.connect_timeout <= 0
            or self.idle_timeout <= 0
            or self.pong_timeout <= 0
        ):
            msg = "IRC timeouts must be positive"
            raise ValueError(msg)
        if not self.servers:
            msg = "IRC servers must not be empty"
            raise ValueError(msg)
        format_message("NICK", (self.nickname,), None)
        format_message(
            "USER",
            (self.nickname, "0", "*"),
            self.nickname,
        )


class IRCClient:
    """Reconnectable IRC socket with serialized writes."""

    def __init__(
        self,
        *,
        config: IRCClientConfig,
        on_disconnect: Callable[[], None],
        on_message: Callable[[IRCMessage], Awaitable[None]],
    ) -> None:
        """Configure the client with connection and rate-limit settings."""
        self.cap_available: set[str] = set()
        self.cap_negotiating = False
        self.cap_ls_done = False
        self.casemapping = DEFAULT_CASEMAPPING
        self.config = config
        self.current_nick = config.nickname
        self.desired_nick = config.nickname
        self.nickname_attempts = 0
        self.nickname_length = DEFAULT_NICK_LENGTH
        self.on_disconnect = on_disconnect
        self.on_message = on_message
        self.outbound: asyncio.Queue[bytes] | None = None
        self.sender_task: asyncio.Task[None] | None = None
        self.registered_with_server = False
        self.stopping = False
        needs_tls = any(s.tls for s in config.servers)
        self.tls_context = ssl.create_default_context() if needs_tls else None
        if self.tls_context is not None and not config.verify_tls:
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE
        self.writer: asyncio.StreamWriter | None = None
        self.write_lock = asyncio.Lock()

    async def close(self) -> None:
        """Shut down the sender and close the socket."""
        self.stopping = True
        try:
            await self.stop_sender()
        finally:
            writer = self.writer
            self.writer = None
            if writer is not None:
                writer.close()
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
        if message.command == "PING" and message.params:
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
            await self.nick_collision()
            return ping_token
        if message.command == "CAP":
            await self.handle_cap(message)
            return ping_token
        self.track_registration(message)
        try:
            await self.on_message(message)
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
        self.sender_task.add_done_callback(self.sender_done)
        self.cap_available = set()
        self.cap_negotiating = True
        self.cap_ls_done = False
        self.current_nick = self.desired_nick
        self.nickname_attempts = 0
        self.registered_with_server = False
        LOGGER.info("connected to IRC server %s:%s", server.host, server.port)
        await self.send("CAP", "LS", "302")
        await self.send("NICK", self.current_nick)
        await self.send(
            "USER",
            self.config.nickname,
            "0",
            "*",
            trailing=self.config.nickname,
        )
        return reader, writer

    async def handle_cap(self, message: IRCMessage) -> None:
        """Process CAP subcommands during capability negotiation."""
        if len(message.params) < MIN_CAP_PARAMS:
            return
        subcommand = message.params[1].upper()
        caps = {cap.partition("=")[0] for cap in message.params[-1].split()}
        if subcommand == "LS":
            if not self.cap_negotiating:
                return
            self.cap_available.update(caps)
            if (
                len(message.params) >= MIN_CAP_MULTILINE_PARAMS
                and message.params[2] == "*"
            ):
                return
            self.cap_ls_done = True
            wanted = DESIRED_CAPS & self.cap_available
            if wanted:
                await self.send("CAP", "REQ", trailing=" ".join(sorted(wanted)))
            else:
                await self.send("CAP", "END")
                self.cap_negotiating = False
        elif subcommand == "NEW":
            wanted = DESIRED_CAPS & caps
            if wanted:
                await self.send("CAP", "REQ", trailing=" ".join(sorted(wanted)))
        elif subcommand in {"ACK", "NAK"} and self.cap_negotiating and self.cap_ls_done:
            # End only once the LS phase has issued its REQ; a NEW-triggered
            # ACK arriving mid-LS must not cut the initial exchange short.
            await self.send("CAP", "END")
            self.cap_negotiating = False

    async def nick_collision(self) -> None:
        """Pick a random fallback nickname after registration rejects one."""
        self.nickname_attempts += 1
        if self.nickname_attempts > NICK_COLLISION_LIMIT:
            msg = "IRC nickname collision limit exceeded"
            raise ConnectionError(msg)
        self.current_nick = next_nickname(
            min(len(self.desired_nick), self.nickname_length),
        )
        await self.send("NICK", self.current_nick)

    async def reconnect(self) -> None:
        """Force a reconnection by closing the current socket."""
        if self.writer is not None:
            self.writer.close()

    def reset_caps(self) -> None:
        """Reset capabilities learned from the previous server connection."""
        self.nickname_length = DEFAULT_NICK_LENGTH

    async def run_connection(self, server: IRCServer) -> None:
        """Read and dispatch messages from a single server session."""
        self.registered_with_server = False
        reader, writer = await self.establish(server)
        loop = asyncio.get_running_loop()
        ping_token: str | None = None
        pong_deadline = 0.0
        registration_deadline = loop.time() + REGISTRATION_TIMEOUT
        while not self.stopping:
            now = loop.time()
            if ping_token is None:
                timeout = self.config.idle_timeout
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
                ping_token = uuid.uuid4().hex
                pong_deadline = loop.time() + self.config.pong_timeout
                await self.send_immediate(
                    format_message("PING", (), ping_token),
                    writer,
                )
                continue
            except ValueError as error:
                msg = "IRC server sent an oversized line"
                raise ConnectionError(msg) from error
            if not raw or len(raw) > MAX_IRC_MESSAGE_BYTES:
                msg = (
                    "IRC server closed the connection"
                    if not raw
                    else "IRC server sent an oversized line"
                )
                raise ConnectionError(msg)
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
        while not self.stopping:
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
                try:
                    await self.stop_sender()
                finally:
                    if self.writer is not None:
                        self.writer.close()
                        with suppress(OSError):
                            await self.writer.wait_closed()
                        self.writer = None
            if self.stopping:
                break
            duration = loop.time() - session_start
            if self.registered_with_server and duration >= STABLE_SESSION_SECONDS:
                backoff = 0
            else:
                index += 1
                backoff = min(backoff + 1, 8)
            delay = min(30.0, 1.5**backoff) + secrets.randbelow(1000) / 1000
            await asyncio.sleep(delay)

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Enqueue an IRC command for rate-limited delivery."""
        encoded = format_message(command, params, trailing)
        outbound = self.outbound
        if (
            self.writer is None
            or self.writer.is_closing()
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
        async with self.write_lock:
            if self.writer is not writer or writer.is_closing():
                msg = "IRC is not connected"
                raise ConnectionError(msg)
            writer.write(encoded)
            try:
                async with asyncio.timeout(WRITE_TIMEOUT):
                    await writer.drain()
            except TimeoutError as error:
                writer.close()
                msg = "IRC write timed out"
                raise ConnectionError(msg) from error

    async def send_loop(
        self,
        writer: asyncio.StreamWriter,
        outbound: asyncio.Queue[bytes],
    ) -> None:
        """Drain the outbound queue at the configured send rate."""
        loop = asyncio.get_running_loop()
        burst = SEND_BURST
        rate = SEND_RATE
        tokens = burst
        updated = loop.time()
        try:
            while True:
                encoded = await outbound.get()
                now = loop.time()
                tokens = min(burst, tokens + (now - updated) * rate)
                updated = now
                if tokens < 1.0:
                    await asyncio.sleep((1.0 - tokens) / rate)
                    updated = loop.time()
                    tokens = 0.0
                else:
                    tokens -= 1.0
                await self.send_immediate(encoded, writer)
        except OSError, RuntimeError:
            writer.close()

    def sender_done(self, task: asyncio.Task[None]) -> None:
        """Log unexpected sender task failures."""
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error("IRC sender failed", exc_info=error)

    def set_casemapping(self, casemapping: str) -> None:
        """Apply the server-advertised case-folding rule."""
        if casemapping in CASEMAPPINGS:
            self.casemapping = casemapping

    def set_nickname_length(self, length: int) -> None:
        """Record the server-advertised maximum nickname length."""
        if length > 0:
            self.nickname_length = length

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
            self.nickname_attempts = 0
            if message.params:
                self.current_nick = message.params[0]
        elif (
            message.command == "NICK"
            and message.prefix is not None
            and message.params
            and casefold(message.prefix.nick, self.casemapping)
            == casefold(self.current_nick, self.casemapping)
        ):
            self.current_nick = message.params[-1]


def pong_reply(line: bytes) -> bytes:
    """Build a PONG that echoes a PING's raw token bytes.

    Tags and prefix are dropped first, mirroring parse_message, so a leading
    prefix's space-colon is not mistaken for the trailing-parameter marker.
    The token is kept verbatim, so the reply never exceeds the wire length of
    the PING that parse_message already accepted.
    """
    rest = line.rstrip(b"\r\n")
    if rest.startswith(b"@"):
        _, _, rest = rest.partition(b" ")
    if rest.startswith(b":"):
        _, _, rest = rest.partition(b" ")
    _, trailing_sep, trailing = rest.partition(b" :")
    if trailing_sep:
        return b"PONG :" + trailing + b"\r\n"
    tokens = [token for token in rest.split(b" ")[1:] if token]
    return b"PONG " + b" ".join(tokens) + b"\r\n"


def next_nickname(length: int) -> str:
    """Generate a random alphabetic nickname of the given length."""
    return "".join(secrets.choice(NICK_ALPHABET) for _ in range(max(1, length)))
