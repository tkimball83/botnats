# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""This process's compare-and-set claim on its bot ID's presence key."""

import asyncio
import logging
from contextlib import suppress
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from botnats.nats.store import PUBLISH_ERRORS

if TYPE_CHECKING:
    from botnats.nats.store import PresenceStore

LOGGER = logging.getLogger(__name__)


class PresenceState(Enum):
    """This process's hold on its bot ID's presence key."""

    UNCLAIMED = auto()
    OWNED = auto()
    DUPLICATE = auto()


class PresenceClaim:
    """Own this process's claim on its bot ID's presence key.

    All ownership state lives here and changes only through the transitions
    below. Transitions that need no KV round trip (observing a watched record,
    a disconnect reset) apply at once, so the watch and nats-py's reconnect
    never wait behind a write. Every ownership change bumps a generation, and
    a KV write records its result only if no change happened while it was in
    flight. The lock only keeps two presence writes from running at once.
    """

    def __init__(self, store: PresenceStore, bot_id: str, instance_id: str) -> None:
        self.bot_id = bot_id
        self.generation = 0
        self.instance_id = instance_id
        self.key = bot_id.casefold()
        self.last: dict[str, Any] = {
            "bot_id": bot_id,
            "host": "",
            "instance_id": instance_id,
            "nick": "",
            "user": "",
        }
        self.lock = asyncio.Lock()
        self.revision: int | None = None
        self.state = PresenceState.UNCLAIMED
        self.store = store

    @property
    def duplicate(self) -> bool:
        """Return whether a live peer holds this bot ID."""
        return self.state is PresenceState.DUPLICATE

    @property
    def owned(self) -> bool:
        """Return whether this process owns its presence key."""
        return self.state is PresenceState.OWNED

    def require(self) -> None:
        """Require ownership before any write that speaks for this bot ID."""
        if not self.owned:
            msg = f"duplicate bot ID: {self.bot_id}"
            raise RuntimeError(msg)

    def reset(self) -> None:
        """Drop ownership when Core NATS disconnects; a duplicate stays one."""
        # Always invalidate writes in flight: their connection is gone.
        self.generation += 1
        if self.owned:
            self.state = PresenceState.UNCLAIMED

        self.revision = None

    def transition(self, state: PresenceState, revision: int | None) -> None:
        """Move to a state; a real change invalidates writes in flight."""
        if state is not self.state:
            self.generation += 1

        self.state = state
        self.revision = revision

    async def put(self, presence: dict[str, Any]) -> None:
        """Write or refresh presence, reclaiming the key when not owned."""
        if presence.get("bot_id") != self.bot_id:
            msg = "presence does not match coordinator bot ID"
            raise ValueError(msg)

        async with self.lock:
            self.last = presence
            generation = self.generation
            if self.owned and self.revision is not None:
                revision = await self.store.update(self.bot_id, presence, self.revision)
                if generation != self.generation:
                    return

                if revision is not None:
                    self.revision = revision
                    return

                self.transition(PresenceState.UNCLAIMED, None)

            await self.claim()
        self.require()

    async def reclaim(self) -> None:
        """Reclaim the key after a watch replay, while unowned."""
        async with self.lock:
            if not self.owned:
                await self.claim()

    async def expired(self) -> None:
        """Handle this bot's key being deleted, then try to reclaim it."""
        async with self.lock:
            if self.owned:
                self.transition(PresenceState.UNCLAIMED, None)

            await self.claim()

    def observe(self, instance_id: str, revision: int) -> bool:
        """Apply a validly signed record on this bot's key; report a duplicate.

        Needs no KV round trip, so it never waits behind a presence write.
        """
        if instance_id != self.instance_id:
            self.yield_key()
            return True

        self.adopt(max(self.revision or 0, revision))
        return False

    async def release(self) -> None:
        """Delete the owned key on shutdown so a replacement can claim it."""
        async with self.lock:
            revision = self.revision
            if self.owned and revision is not None:
                with suppress(*PUBLISH_ERRORS):
                    await self.store.delete(self.bot_id, revision)

            self.reset()

    async def claim(self) -> None:
        """Create the key, or reclaim it from a stale or forged occupant.

        A validly signed record from another instance is a duplicate to yield
        to; a transient store error propagates to the caller's retry path
        instead of being misread as one. A result that arrives after a reset
        is stale and discarded.
        """
        generation = self.generation
        revision = await self.store.create(self.bot_id, self.last)
        if revision is None:
            revision = await self.store.reclaim(
                self.bot_id,
                self.last,
                self.instance_id,
            )

        if generation != self.generation:
            return

        if revision is None:
            self.yield_key()
        else:
            self.adopt(revision)

    def adopt(self, revision: int) -> None:
        """Take ownership at a revision."""
        if self.duplicate:
            LOGGER.info("duplicate bot ID conflict resolved: %s", self.bot_id)

        self.transition(PresenceState.OWNED, revision)

    def yield_key(self) -> None:
        """Yield this bot ID to a live peer."""
        if not self.duplicate:
            LOGGER.error("duplicate bot ID detected: %s", self.bot_id)

        self.transition(PresenceState.DUPLICATE, None)
