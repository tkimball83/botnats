# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fakes and factories for bot-level tests."""

import asyncio
import base64
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

from nats.errors import Error as NatsError
from nats.js.errors import KeyNotFoundError, KeyWrongLastSequenceError

from botnats.bot import Bot
from botnats.config import BotConfig
from botnats.irc.client import IRCServer
from botnats.irc.protocol import (
    IRCMessage,
    ISupportState,
    Prefix,
    format_message,
)
from botnats.nats.status import NATSStatus
from botnats.nats.store import (
    AttemptStore,
    ChannelStore,
    ClaimStore,
    Session,
    SessionStore,
    parse_session_record,
    session_signature,
)

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

    from botnats.irc.protocol import IRCProtocol
    from botnats.nats.coordinator import CoordinatorProtocol

AUTH_KEY = b"12345678901234567890"
COORDINATION_KEY_TEXT = "coordination-secret-used-only-for-tests"
COORDINATION_KEY = COORDINATION_KEY_TEXT.encode()
NATS_CREDENTIAL = "nats-token"
OWNER = Prefix("owner", "user", "real.host")

# Every value differs from its default, so a field the loader drops or
# misroutes cannot pass as its default.
CONFIG = b"""{
  "authorization": {
    "session_ttl_seconds": 600
  },
  "bot": {
    "health_port": 9080,
    "id": "botnats-1",
    "network": "libera",
    "nickname": "botnick"
  },
  "coordination": {
    "maintenance_interval_seconds": 2,
    "presence_ttl_seconds": 10
  },
  "irc": {
    "channel_modes": "+nt-s",
    "connect_timeout_seconds": 45,
    "servers": ["ircs://irc.example.test:6697", "irc://irc2.example.test:6668"],
    "verify_tls": false
  },
  "nats": {
    "jetstream_replicas": 3,
    "monitor_port": 9222,
    "servers": ["nats://nats.internal:4222", "tls://nats2.internal:4223"]
  }
}
"""
SECRETS = {
    "BOTNATS_COORDINATION_SECRET": COORDINATION_KEY_TEXT,
    "BOTNATS_NATS_TOKEN": NATS_CREDENTIAL,
    "BOTNATS_TOTP_SECRET": base64.b32encode(AUTH_KEY).decode(),
}


async def drain_session_writes(bot: Bot) -> None:
    """Wait for durable session writes that IRC handlers run in background."""
    await asyncio.gather(
        *(task for task in tuple(bot.tasks) if task.get_name() == "session-sync"),
    )


async def send_command(bot: Bot, prefix: Prefix, text: str) -> None:
    """Queue a private-message command as IRC delivers it and wait for it."""
    await bot.events.on_irc_message(IRCMessage("PRIVMSG", ("alpha", text), prefix))
    await asyncio.gather(
        *(task for task in tuple(bot.tasks) if task.get_name() == "admin-command"),
    )


def session_record(
    expires_at: float,
    version: int = 0,
    *,
    revoked: bool = False,
) -> dict[str, object]:
    """Build a signed durable session record for owner!user@host."""
    record: dict[str, object] = {
        "expires_at": expires_at,
        "issuer": "alpha",
        "prefix": "owner!user@host",
        "revoked": revoked,
        "version": version,
    }
    record["signature"] = session_signature(COORDINATION_KEY, "efnet", record)
    return record


def session_value(expires_at: float) -> Session:
    """Build a validated session for owner!user@host."""
    session = parse_session_record(
        COORDINATION_KEY,
        "efnet",
        session_record(expires_at),
    )
    assert session is not None
    return session


def bot_with_channel(
    *,
    irc: IRCProtocol | None = None,
    coordinator: CoordinatorProtocol | None = None,
) -> Bot:
    """Create a bot with a single test channel registered."""
    bot = make_bot(irc=irc, coordinator=coordinator)
    record = bot.channel_mgr.new_record("#test", None, present=True)
    bot.channel_mgr.apply_record(record)
    return bot


def make_bot(
    *,
    irc: IRCProtocol | None = None,
    coordinator: CoordinatorProtocol | None = None,
) -> Bot:
    """Create a bot whose fake IRC client folds names with the bot's own caps."""
    bot = Bot(config(), irc=irc, coordinator=coordinator)
    if isinstance(irc, FakeIRC):
        irc.caps = bot.caps

    return bot


def bot_with_coordinator(
    coordinator: FakeCoordinator | None = None,
    *,
    irc: FakeIRC | None = None,
) -> tuple[Bot, FakeIRC, FakeCoordinator]:
    """Create a bot wired to a fake IRC client and fake coordinator."""
    coordinator = coordinator or FakeCoordinator()
    fake_irc = irc or FakeIRC()
    return (
        bot_with_channel(irc=fake_irc, coordinator=coordinator),
        fake_irc,
        coordinator,
    )


def bot_with_irc(
    *,
    coordinator: CoordinatorProtocol | None = None,
) -> tuple[Bot, FakeIRC]:
    """Create a bot wired to a fake IRC client."""
    fake_irc = FakeIRC()
    return bot_with_channel(irc=fake_irc, coordinator=coordinator), fake_irc


def config() -> BotConfig:
    """Build a default test configuration."""
    return BotConfig(
        auth_session_ttl=3600,
        bot_id="alpha",
        channel_modes="+npst",
        coordination_secret=COORDINATION_KEY_TEXT,
        enforced_modes=(frozenset("npst"), frozenset()),
        health_port=8080,
        irc_connect_timeout=30,
        irc_servers=(IRCServer("irc.example.test", 6697, tls=True),),
        irc_verify_tls=True,
        jetstream_replicas=1,
        maintenance_interval=3,
        nats_monitor_port=8222,
        nats_servers=("nats://nats.internal:4222",),
        nats_token=NATS_CREDENTIAL,
        network="efnet",
        nickname="alpha",
        presence_ttl=15,
        totp_secret=AUTH_KEY,
    )


class FakeIRC:
    """In-memory IRC client stub that records sent commands.

    It delivers every command at once, so unlike IRCClient its outbound queue
    never fills. It does not parse server lines either: tests set current_nick
    where IRCClient would track it from 001 and NICK.
    """

    def __init__(self) -> None:
        """Initialize empty recording buffers."""
        # Replaced with the bot's own capabilities when wired to a bot.
        self.caps = ISupportState()
        self.connected = True
        self.current_nick = "alpha"
        self.modes: list[tuple[str, str, tuple[str, ...]]] = []
        self.privmsgs: list[tuple[str, str]] = []
        self.reconnects = 0
        self.sent: list[tuple[str, tuple[str, ...]]] = []

    async def close(self) -> None:
        """Close the connection, as IRCClient.close does."""
        self.connected = False

    def is_self(self, nickname: str) -> bool:
        """Return whether a nickname identifies this client."""
        return self.caps.fold(nickname) == self.caps.fold(self.current_nick)

    def reconnect(self) -> None:
        """Drop the connection, as IRCClient.reconnect does, and count it."""
        self.connected = False
        self.reconnects += 1

    async def run_forever(self) -> None:
        """No-op run loop."""
        return

    def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Validate and record a raw command, failing when disconnected."""
        format_message(command, params, trailing)
        if not self.connected:
            msg = "IRC is not connected"
            raise ConnectionError(msg)

        if command == "MODE" and params[1:]:
            self.modes.append((params[0], params[1], params[2:]))

        if command == "PRIVMSG" and params and trailing is not None:
            self.privmsgs.append((params[0], trailing))
        else:
            self.sent.append((command, params))


class FailingIRC(FakeIRC):
    """IRC stub that raises ConnectionError on send."""

    def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Raise ConnectionError to simulate a disconnect."""
        del command, params, trailing
        msg = "IRC disconnected"
        raise ConnectionError(msg)


class FailingPartIRC(FakeIRC):
    """IRC stub that raises ConnectionError on PART until it recovers."""

    def __init__(self) -> None:
        """Start failing PART commands."""
        super().__init__()
        self.failing = True

    def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Raise ConnectionError for PART commands while failing."""
        if self.failing and command == "PART":
            msg = "IRC outbound queue is full"
            raise ConnectionError(msg)

        super().send(command, *params, trailing=trailing)


class FakeKV:
    """In-memory JetStream KV bucket with the revision checks the stores use."""

    def __init__(self) -> None:
        """Start with an empty bucket."""
        self.entries: dict[str, tuple[int, bytes]] = {}
        self.sequence = 0

    async def create(self, key: str, value: bytes) -> int:
        """Store a new key, or fail as JetStream does when it already exists."""
        if key in self.entries:
            raise KeyWrongLastSequenceError

        return self.store(key, value)

    async def get(self, key: str) -> SimpleNamespace:
        """Return the stored entry, or fail as JetStream does when it is absent."""
        if key not in self.entries:
            raise KeyNotFoundError

        revision, value = self.entries[key]
        return SimpleNamespace(key=key, revision=revision, value=value)

    def store(self, key: str, value: bytes) -> int:
        """Write a value under the next stream sequence and return it."""
        self.sequence += 1
        self.entries[key] = (self.sequence, value)
        return self.sequence

    async def update(self, key: str, value: bytes, last: int) -> int:
        """Replace a key only while its revision is still last."""
        if key not in self.entries or self.entries[key][0] != last:
            raise KeyWrongLastSequenceError

        return self.store(key, value)


class FakeCoordinator:
    """In-memory coordinator over the real stores, recording writes and requests.

    Channel, session, attempt, and claim writes go through the production
    stores on in-memory buckets, so they sign, validate, order, and dedupe
    exactly as they would against JetStream.
    """

    def __init__(self) -> None:
        """Open every store on an empty in-memory bucket."""
        self.attempts = AttemptStore("efnet", 1, COORDINATION_KEY)
        self.channels = ChannelStore("efnet", 1, COORDINATION_KEY)
        self.claims = ClaimStore("efnet", 1, COORDINATION_KEY)
        self.sessions = SessionStore(
            "efnet",
            1,
            COORDINATION_KEY,
            config().auth_session_ttl,
        )
        for store in (self.attempts, self.channels, self.claims, self.sessions):
            store.kv = cast("KeyValue", FakeKV())

        self.bot_id = "alpha"
        self.channel_expected: list[str | None] = []
        self.channel_puts: list[dict[str, Any]] = []
        self.claim_requests: list[int] = []
        self.connected = True
        self.duplicate = False
        self.help_requests: list[tuple[str, dict[str, object]]] = []
        self.presence_puts: list[dict[str, Any]] = []
        self.session_puts: list[dict[str, Any]] = []

    def require_writable(self) -> None:
        """Mirror the real write gate: this process must own its bot ID."""
        if self.duplicate or not self.connected:
            msg = f"duplicate bot ID: {self.bot_id}"
            raise RuntimeError(msg)

    async def close(self) -> None:
        """No-op close."""
        return

    async def put_channel(
        self,
        record: dict[str, Any],
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Record a channel write and store it as ChannelStore would."""
        self.require_writable()
        self.channel_puts.append(record)
        self.channel_expected.append(expected)
        return await self.channels.put(record, expected=expected)

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Record a presence write."""
        if presence.get("bot_id") != self.bot_id:
            msg = "presence does not match coordinator bot ID"
            raise ValueError(msg)

        self.require_writable()
        self.presence_puts.append(presence)

    async def put_session(self, session: dict[str, Any]) -> dict[str, Any]:
        """Record a session write and store it as SessionStore would."""
        self.require_writable()
        self.session_puts.append(session)
        return await self.sessions.put(session)

    @property
    def ready(self) -> bool:
        """Mirror real readiness: connected and owning this bot ID."""
        return self.connected and not self.duplicate

    async def request_auth(self, identity: str) -> bool:
        """Reserve an attempt slot through the real AttemptStore."""
        return self.ready and await self.attempts.allow(identity)

    async def request_claim(self, counter: int) -> bool:
        """Claim a TOTP counter once through the real ClaimStore."""
        if not self.ready:
            return False

        self.claim_requests.append(counter)
        return await self.claims.claim(counter)

    async def request_help(self, kind: str, payload: dict[str, object]) -> None:
        """Record a help request, dropping it when not ready."""
        if self.ready:
            self.help_requests.append((kind, payload))

    async def start(self) -> None:
        """No-op start."""
        return

    async def status(self) -> NATSStatus:
        """Return a healthy fake NATS cluster status."""
        return NATSStatus(
            connection=self.connected,
            jetstream="up" if self.connected else "unknown",
            lag=0 if self.connected else None,
            leader="nats-1" if self.connected else None,
            offline=(),
            replicas_current=1 if self.connected else None,
            replicas_total=1,
            routes=0 if self.connected else None,
        )


class FailingWriteCoordinator(FakeCoordinator):
    """Coordinator stub whose channel and session writes fail until it recovers."""

    def __init__(self) -> None:
        """Start failing channel and session writes."""
        super().__init__()
        self.failing = True

    async def put_channel(
        self,
        record: dict[str, Any],
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Raise NatsError while failing, to simulate a NATS disconnect."""
        if self.failing:
            msg = f"NATS disconnected: channel {record['channel']}"
            raise NatsError(msg)

        return await super().put_channel(record, expected=expected)

    async def put_session(self, session: dict[str, Any]) -> dict[str, Any]:
        """Raise NatsError while failing, to simulate a NATS disconnect."""
        if self.failing:
            msg = f"NATS disconnected: session {session['prefix']}"
            raise NatsError(msg)

        return await super().put_session(session)
