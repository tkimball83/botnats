# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fakes and factories for bot-level tests."""

import time
from typing import Any

from nats.errors import Error as NatsError

from botnats.bot import Bot
from botnats.channel import ChannelRecord, ChannelRuntime
from botnats.config import BotConfig
from botnats.irc.client import IRCServer
from botnats.irc.protocol import casefold, format_message
from botnats.nats.status import NATSStatus
from botnats.nats.store import ATTEMPT_LIMIT, ATTEMPT_WINDOW

AUTH_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
COORDINATION_KEY = b"coordination-secret-used-only-for-tests"
COORDINATION_KEY_TEXT = "coordination-secret-used-only-for-tests"
NATS_CREDENTIAL = "nats-token"


def bot_with_channel() -> Bot:
    """Create a bot with a single test channel registered."""
    bot = Bot(config())
    folded = casefold("#test")
    record = ChannelRecord.new(
        "#test",
        None,
        present=True,
    )
    bot.channel_mgr.channel_records[folded] = record
    bot.channel_mgr.source_records[casefold(record.channel, "ascii")] = record
    bot.channel_mgr.desired_channels[folded] = "#test"
    bot.channel_mgr.channels[folded] = ChannelRuntime()
    return bot


def bot_with_coordinator() -> tuple[Bot, FakeIRC, FakeCoordinator]:
    """Create a bot wired to a fake IRC client and fake coordinator."""
    bot, fake_irc = bot_with_irc()
    coordinator = FakeCoordinator()
    bot.coordinator = coordinator
    return bot, fake_irc, coordinator


def bot_with_irc() -> tuple[Bot, FakeIRC]:
    """Create a bot wired to a fake IRC client."""
    bot = bot_with_channel()
    fake_irc = FakeIRC()
    bot.irc = fake_irc
    return bot, fake_irc


def config() -> BotConfig:
    """Build a default test configuration."""
    return BotConfig(
        auth_session_ttl=3600,
        bot_id="alpha",
        channel_modes="+npst",
        coordination_secret=COORDINATION_KEY_TEXT,
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
        totp_secret=AUTH_SEED,
    )


class FakeIRC:
    """In-memory IRC client stub that records sent commands."""

    def __init__(self) -> None:
        """Initialize empty recording buffers."""
        self.casemapping = "rfc1459"
        self.connected = True
        self.current_nick = "alpha"
        self.desired_nick = "alpha"
        self.modes: list[tuple[str, str, tuple[str, ...]]] = []
        self.nickname_length = 9
        self.privmsgs: list[tuple[str, str]] = []
        self.reconnects = 0
        self.sent: list[tuple[str, tuple[str, ...]]] = []

    async def close(self) -> None:
        """No-op close."""
        return

    async def reconnect(self) -> None:
        """Increment the reconnect counter."""
        self.reconnects += 1

    def reset_caps(self) -> None:
        """Reset server-advertised capabilities."""
        self.nickname_length = 9

    async def run_forever(self) -> None:
        """No-op run loop."""
        return

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Validate and record a raw command, failing when disconnected."""
        if not self.connected:
            msg = "IRC is not connected"
            raise ConnectionError(msg)
        format_message(command, params, trailing)
        if command == "MODE" and params[1:]:
            self.modes.append((params[0], params[1], params[2:]))
        if command == "PRIVMSG" and params and trailing is not None:
            self.privmsgs.append((params[0], trailing))
        else:
            self.sent.append((command, params))

    def set_casemapping(self, casemapping: str) -> None:
        """Update the casemapping setting."""
        self.casemapping = casemapping

    def set_nickname_length(self, length: int) -> None:
        """Update the nickname length limit."""
        self.nickname_length = length


class FailingIRC(FakeIRC):
    """IRC stub that raises ConnectionError on send."""

    async def send(
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
    """IRC stub that raises ConnectionError on part."""

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Raise ConnectionError for PART commands."""
        if command == "PART":
            msg = "IRC outbound queue is full"
            raise ConnectionError(msg)
        await super().send(command, *params, trailing=trailing)


class FakeCoordinator:
    """In-memory coordinator stub that records KV puts and offers."""

    def __init__(self, *, claim_result: bool = False) -> None:
        """Initialize empty recording buffers."""
        self.auth_slots: dict[str, list[float]] = {}
        self.bot_id = "alpha"
        self.channel_puts: list[tuple[str, dict[str, Any]]] = []
        self.claim_requests: list[int] = []
        self.claim_result = claim_result
        self.connected = True
        self.offer_requests: list[tuple[str, dict[str, object]]] = []
        self.owns_presence = True
        self.presence_puts: list[dict[str, Any]] = []
        self.session_puts: list[tuple[str, dict[str, Any]]] = []
        self.synced = True
        self.unique = True

    def require_unique(self) -> None:
        """Mirror the real duplicate-ID write gate."""
        if not self.unique or not self.owns_presence:
            msg = f"duplicate bot ID: {self.bot_id}"
            raise RuntimeError(msg)

    async def close(self) -> None:
        """No-op close."""
        return

    async def put_channel(
        self,
        channel: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a channel KV put."""
        self.require_unique()
        self.channel_puts.append((channel, record))
        return record

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Record a presence KV put."""
        if presence.get("bot_id") != self.bot_id:
            msg = "presence does not match coordinator bot ID"
            raise ValueError(msg)
        self.require_unique()
        self.presence_puts.append(presence)

    async def put_session(
        self,
        identity: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a session KV put."""
        self.require_unique()
        self.session_puts.append((identity, session))
        return session

    @property
    def ready(self) -> bool:
        """Mirror real readiness: connection, replay, presence, uniqueness."""
        return self.connected and self.unique and self.synced and self.owns_presence

    async def request_auth(self, identity: str) -> bool:
        """Claim one attempt slot per identity, matching real slot-based store."""
        if not self.ready:
            return False
        now = time.monotonic()
        cutoff = now - ATTEMPT_WINDOW
        slots = self.auth_slots.setdefault(identity, [])
        for idx, ts in enumerate(slots):
            if ts <= cutoff:
                slots[idx] = now
                return True
        if len(slots) < ATTEMPT_LIMIT:
            slots.append(now)
            return True
        return False

    async def request_claim(self, counter: int) -> bool:
        """Allow or deny claims, failing closed when not ready."""
        if not self.ready:
            return False
        self.claim_requests.append(counter)
        return self.claim_result

    async def request_offer(self, base_suffix: str, payload: dict[str, object]) -> bool:
        """Record an offer request, refusing when not ready or misowned."""
        if not self.ready:
            return False
        presence = payload.get("presence")
        if not isinstance(presence, dict) or presence.get("bot_id") != self.bot_id:
            return False
        self.offer_requests.append((base_suffix, payload))
        return True

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


class FailingPublishCoordinator(FakeCoordinator):
    """Coordinator stub that raises NatsError on all KV writes."""

    async def put_channel(
        self,
        channel: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """Raise NatsError to simulate a NATS disconnect."""
        msg = f"NATS disconnected: channel {channel} with {len(record)} fields"
        raise NatsError(msg)

    async def put_session(
        self,
        identity: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Raise NatsError to simulate a NATS disconnect."""
        msg = f"NATS disconnected: session {identity} with {len(session)} fields"
        raise NatsError(msg)
