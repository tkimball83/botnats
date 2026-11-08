# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""This process's compare-and-set claim on its bot ID's presence key."""

import asyncio
import logging
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from botnats.nats.store import PUBLISH_ERRORS, StoreUnavailableError

if TYPE_CHECKING:
    from botnats.nats.store import PresenceStore

LOGGER = logging.getLogger(__name__)


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
        # Whether a live peer holds this bot ID.
        self.duplicate = False
        self.generation = 0
        self.instance_id = instance_id
        self.key = store.key(bot_id)
        self.lock = asyncio.Lock()
        # A reclaim may run after IRC drops, so it claims the key without an
        # IRC identity, which peers do not record; only put() writes one.
        self.placeholder: dict[str, Any] = {
            "bot_id": bot_id,
            "host": "",
            "instance_id": instance_id,
            "nick": "",
            "user": "",
        }
        # The owned revision; None while this process does not own the key.
        self.revision: int | None = None
        self.store = store

    @property
    def owned(self) -> bool:
        """Return whether this process owns its presence key."""
        return self.revision is not None

    def require(self) -> None:
        """Require ownership before any write that speaks for this bot ID."""
        if not self.owned:
            msg = f"bot ID {self.bot_id} does not own its presence key"
            raise StoreUnavailableError(msg)

    def reset(self) -> None:
        """Drop ownership when Core NATS disconnects; a duplicate stays one."""
        # Always invalidate writes in flight: their connection is gone.
        self.generation += 1
        self.revision = None

    def transition(self, revision: int | None, *, duplicate: bool) -> None:
        """Move to a state; a real change invalidates writes in flight."""
        if (revision is not None) != self.owned or duplicate != self.duplicate:
            self.generation += 1

        self.duplicate = duplicate
        self.revision = revision

    async def put(self, presence: dict[str, Any]) -> None:
        """Write or refresh presence, reclaiming the key when not owned."""
        async with self.lock:
            generation = self.generation
            if self.revision is not None:
                revision = await self.store.update(self.bot_id, presence, self.revision)
                if generation != self.generation:
                    return

                if revision is not None:
                    self.revision = revision
                    return

                self.transition(None, duplicate=False)

            await self.claim(presence)

    async def reclaim(self) -> None:
        """Reclaim the key after a watch replay, while unowned."""
        async with self.lock:
            if not self.owned:
                await self.claim(self.placeholder)

    async def deleted(self, revision: int) -> None:
        """Handle this bot's key being deleted, then try to reclaim it.

        A delete older than the owned revision is ignored: this claim's own
        write already replaced the record it removed.
        """
        async with self.lock:
            if self.revision is not None and revision < self.revision:
                return

            if self.owned:
                self.transition(None, duplicate=False)

            await self.claim(self.placeholder)

    def observe(self, instance_id: str, revision: int) -> None:
        """Apply a validly signed record on this bot's key.

        Needs no KV round trip, so it never waits behind a presence write. A
        record older than the owned revision is ignored, like a stale delete:
        this claim's own write already replaced it.
        """
        if self.revision is not None and revision < self.revision:
            return

        if instance_id != self.instance_id:
            self.yield_key()
            return

        self.adopt(revision)

    async def release(self) -> None:
        """Delete the owned key on shutdown so a replacement can claim it."""
        async with self.lock:
            revision = self.revision
            if revision is not None:
                with suppress(*PUBLISH_ERRORS):
                    await self.store.delete(self.bot_id, revision, self.instance_id)

            self.reset()

    async def claim(self, presence: dict[str, Any]) -> None:
        """Create the key, or reclaim it from a stale or forged occupant.

        A validly signed record from another instance is a duplicate to yield
        to; a transient store error propagates to the caller's retry path
        instead of being misread as one. A result that arrives after a reset
        is stale and discarded.
        """
        generation = self.generation
        revision = await self.store.create(self.bot_id, presence)
        if revision is None:
            revision = await self.store.reclaim(
                self.bot_id,
                presence,
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

        self.transition(revision, duplicate=False)

    def yield_key(self) -> None:
        """Yield this bot ID to a live peer."""
        if not self.duplicate:
            LOGGER.error("duplicate bot ID detected: %s", self.bot_id)

        self.transition(None, duplicate=True)
