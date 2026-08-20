# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Bot identity and NATS presence heartbeat tracking."""

import time
from dataclasses import dataclass, field, fields

from botnats.irc.protocol import DEFAULT_CASEMAPPING, Prefix


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

    def matches(self, prefix: Prefix, casemapping: str = DEFAULT_CASEMAPPING) -> bool:
        """Check whether this presence corresponds to the given IRC prefix."""
        return self.to_prefix().matches(prefix, casemapping)

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
        self.prune(now=now)
        return tuple(entry[0] for entry in self.entries.values())

    def has(self, presence: BotPresence, *, now: float | None = None) -> bool:
        """Return whether the exact presence is active."""
        self.prune(now=now)
        entry = self.entries.get(presence.bot_id.casefold())
        return entry is not None and entry[0] == presence

    def prune(self, *, now: float | None = None) -> None:
        """Remove entries whose heartbeat deadline has passed."""
        current = time.monotonic() if now is None else now
        self.entries = {k: v for k, v in self.entries.items() if v[1] > current}

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
