# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Shared fakes and factories for bot-level tests."""

import asyncio
import time
from typing import TYPE_CHECKING, Any

from nats.errors import Error as NatsError

from botnats.bot import Bot
from botnats.channel import ChannelRuntime
from botnats.config import BotConfig
from botnats.irc.client import IRCServer
from botnats.irc.protocol import IRCMessage, Prefix, casefold, format_message
from botnats.nats.status import NATSStatus
from botnats.nats.store import ATTEMPT_LIMIT, ATTEMPT_WINDOW, session_signature

if TYPE_CHECKING:
    from botnats.irc.protocol import IRCProtocol
    from botnats.nats.coordinator import CoordinatorProtocol

AUTH_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
COORDINATION_KEY = b"coordination-secret-used-only-for-tests"
COORDINATION_KEY_TEXT = "coordination-secret-used-only-for-tests"
NATS_CREDENTIAL = "nats-token"
OWNER = Prefix("owner", "user", "real.host")


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


def bot_with_channel(
    *,
    irc: IRCProtocol | None = None,
    coordinator: CoordinatorProtocol | None = None,
) -> Bot:
    """Create a bot with a single test channel registered."""
    bot = Bot(config(), irc=irc, coordinator=coordinator)
    folded = casefold("#test")
    record = bot.channel_mgr.new_record(
        "#test",
        None,
        present=True,
    )
    bot.channel_mgr.channel_records[folded] = record
    bot.channel_mgr.source_records[casefold(record.channel, "ascii")] = record
    bot.channel_mgr.channels[folded] = ChannelRuntime(channel="#test")
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
    irc: FakeIRC | None = None,
    *,
    coordinator: CoordinatorProtocol | None = None,
) -> tuple[Bot, FakeIRC]:
    """Create a bot wired to a fake IRC client."""
    fake_irc = irc or FakeIRC()
    return bot_with_channel(irc=fake_irc, coordinator=coordinator), fake_irc


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

    def is_self(self, nickname: str) -> bool:
        """Return whether a nickname identifies this client."""
        return casefold(nickname, self.casemapping) == casefold(
            self.current_nick,
            self.casemapping,
        )

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
    """IRC stub that raises ConnectionError on PART until it recovers."""

    def __init__(self) -> None:
        """Start failing PART commands."""
        super().__init__()
        self.failing = True

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Raise ConnectionError for PART commands while failing."""
        if self.failing and command == "PART":
            msg = "IRC outbound queue is full"
            raise ConnectionError(msg)

        await super().send(command, *params, trailing=trailing)


class FakeCoordinator:
    """In-memory coordinator stub that records KV puts and help requests."""

    def __init__(self, *, claim_result: bool = False) -> None:
        """Initialize empty recording buffers."""
        self.auth_slots: dict[str, list[float]] = {}
        self.bot_id = "alpha"
        self.channel_expected: list[str | None] = []
        self.channel_puts: list[tuple[str, dict[str, Any]]] = []
        self.claim_requests: list[int] = []
        self.claim_result = claim_result
        self.connected = True
        self.help_requests: list[tuple[str, dict[str, object]]] = []
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
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Record a channel KV put and the revision it was written after."""
        self.require_unique()
        self.channel_puts.append((channel, record))
        self.channel_expected.append(expected)
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

    async def request_help(self, kind: str, payload: dict[str, object]) -> None:
        """Record a help request, dropping it when not ready or misowned."""
        presence = payload.get("presence")
        if (
            self.ready
            and isinstance(presence, dict)
            and presence.get("bot_id") == self.bot_id
        ):
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


class FailingPublishCoordinator(FakeCoordinator):
    """Coordinator stub whose KV writes raise NatsError until it recovers."""

    def __init__(self, *, claim_result: bool = False) -> None:
        """Start failing every KV write."""
        super().__init__(claim_result=claim_result)
        self.failing = True

    async def put_channel(
        self,
        channel: str,
        record: dict[str, Any],
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Raise NatsError while failing, to simulate a NATS disconnect."""
        if self.failing:
            msg = f"NATS disconnected: channel {channel} with {len(record)} fields"
            raise NatsError(msg)

        return await super().put_channel(channel, record, expected=expected)

    async def put_session(
        self,
        identity: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Raise NatsError while failing, to simulate a NATS disconnect."""
        if self.failing:
            msg = f"NATS disconnected: session {identity} with {len(session)} fields"
            raise NatsError(msg)

        return await super().put_session(identity, session)
