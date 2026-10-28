# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Bot identity and NATS presence heartbeat tracking."""

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field, fields
from typing import TYPE_CHECKING

from botnats.irc.protocol import Prefix
from botnats.nats.store import PUBLISH_ERRORS

if TYPE_CHECKING:
    from botnats.irc.protocol import IRCSender
    from botnats.nats.coordinator import PresenceWriter

IDENTITY_RETRY_ATTEMPTS = 5
IDENTITY_RETRY_DELAY = 5.0
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class BotPresence:
    """Immutable snapshot of a bot's IRC identity and instance metadata."""

    bot_id: str
    host: str
    instance_id: str
    nick: str
    user: str

    @classmethod
    def from_dict(cls, value: object) -> BotPresence:
        """Construct a presence from a dictionary, validating required fields."""
        if not isinstance(value, dict):
            msg = "presence must be an object"
            raise TypeError(msg)

        values: list[str] = []
        for f in fields(cls):
            item = value.get(f.name)
            if not isinstance(item, str) or not item:
                msg = "presence contains an invalid identity"
                raise ValueError(msg)

            values.append(item)

        return cls(*values)

    def to_prefix(self) -> Prefix:
        """Convert to an IRC prefix for mask matching."""
        return Prefix(self.nick, self.user, self.host)


@dataclass(slots=True)
class PresenceRegistry:
    """Live NATS heartbeats indexed by stable bot ID."""

    ttl: float
    entries: dict[str, tuple[BotPresence, float]] = field(default_factory=dict)

    def active(self, *, now: float | None = None) -> tuple[BotPresence, ...]:
        """Return all presences whose heartbeats have not expired."""
        current = time.monotonic() if now is None else now
        return tuple(
            presence
            for presence, deadline in self.entries.values()
            if deadline > current
        )

    def has(self, presence: BotPresence, *, now: float | None = None) -> bool:
        """Return whether the exact presence is active."""
        current = time.monotonic() if now is None else now
        entry = self.entries.get(presence.bot_id.casefold())
        return entry is not None and entry[1] > current and entry[0] == presence

    def peers(self, bot_id: str) -> tuple[BotPresence, ...]:
        """Return the active presences of every bot other than bot_id."""
        own = bot_id.casefold()
        return tuple(peer for peer in self.active() if peer.bot_id.casefold() != own)

    def prune(self, *, now: float | None = None) -> None:
        """Remove entries whose heartbeat deadline has passed."""
        current = time.monotonic() if now is None else now
        for key in [k for k, v in self.entries.items() if v[1] <= current]:
            del self.entries[key]

    def remove(self, bot_id: str) -> None:
        """Remove a bot presence by stable ID."""
        self.entries.pop(bot_id.casefold(), None)

    def update(
        self,
        presence: BotPresence,
        *,
        now: float | None = None,
    ) -> None:
        """Record or refresh a heartbeat for the given bot presence."""
        current = time.monotonic() if now is None else now
        self.entries[presence.bot_id.casefold()] = (presence, current + self.ttl)


class SelfIdentity:
    """Own this bot's resolved IRC identity and its registration state."""

    def __init__(
        self,
        *,
        bot_id: str,
        coordinator: PresenceWriter,
        instance_id: str,
        irc: IRCSender,
    ) -> None:
        self.bot_id = bot_id
        self.coordinator = coordinator
        self.current: BotPresence | None = None
        # Bumped on every disconnect, so a discovery started for an older
        # connection stops instead of acting on this one.
        self.generation = 0
        self.instance_id = instance_id
        self.irc = irc
        self.registered = False

    async def announce(self) -> None:
        """Write this bot's presence; the next heartbeat retries a failure."""
        if self.current is not None:
            with suppress(*PUBLISH_ERRORS):
                await self.coordinator.put_presence(asdict(self.current))

    async def discover(self, generation: int) -> None:
        """Query the IRC server to resolve the bot's host and user prefix."""
        for _ in range(IDENTITY_RETRY_ATTEMPTS):
            if generation != self.generation or self.current is not None:
                return

            try:
                # WHO, not USERHOST: about oneself, USERHOST shows the real
                # host on most servers, not the visible one peers see and
                # match bans against.
                self.irc.send("WHO", self.irc.current_nick)
            except ConnectionError:
                return

            await asyncio.sleep(IDENTITY_RETRY_DELAY)

        if generation == self.generation and self.current is None:
            LOGGER.warning("IRC identity discovery failed; reconnecting")
            self.irc.reconnect()

    def on_registered(self) -> None:
        """Start a new registration; disconnecting already forgot any old identity."""
        self.registered = True
        LOGGER.info("registered on IRC as %s", self.irc.current_nick)

    def reset(self) -> None:
        """Forget the identity of a connection that ended or restarted."""
        self.current = None
        self.generation += 1
        self.registered = False

    def set(self, prefix: Prefix) -> bool:
        """Record a resolved identity; return whether it changed."""
        if not prefix.complete:
            return False

        identity = BotPresence(
            bot_id=self.bot_id,
            host=prefix.host or "",
            instance_id=self.instance_id,
            nick=self.irc.current_nick,
            user=prefix.user or "",
        )
        if identity == self.current:
            return False

        self.current = identity
        return True
