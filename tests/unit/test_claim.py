# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the presence claim's ownership transitions."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from botnats.nats.claim import PresenceClaim, PresenceState
from botnats.nats.store import PresenceStore
from tests.unit.helpers import COORDINATION_KEY

INSTANCE_ID = "instance"
PRESENCE = {"bot_id": "alpha", "instance_id": INSTANCE_ID}


def build_claim() -> PresenceClaim:
    """Build an unclaimed presence claim over an unopened store."""
    store = PresenceStore("efnet", 1, 15.0, COORDINATION_KEY)
    return PresenceClaim(store, "alpha", INSTANCE_ID)


class PresenceClaimTests(unittest.IsolatedAsyncioTestCase):
    """Tests for claiming, refreshing, and yielding a presence key."""

    def test_require_needs_ownership(self) -> None:
        """Refuse writes until this process owns its presence key."""
        claim = build_claim()

        with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
            claim.require()

        claim.state = PresenceState.OWNED
        claim.require()

    async def test_heartbeat_reclaims_after_duplicate(self) -> None:
        """Retry atomic presence reclaim when TTL expiry emits no watch event."""
        claim = build_claim()
        claim.state = PresenceState.DUPLICATE

        with (
            patch.object(
                claim.store,
                "create",
                AsyncMock(side_effect=(None, 1)),
            ) as create,
            patch.object(claim.store, "update", AsyncMock(return_value=2)) as update,
            patch.object(claim.store, "reclaim", AsyncMock(return_value=None)),
        ):
            with self.assertRaisesRegex(RuntimeError, "duplicate bot ID"):
                await claim.put(PRESENCE)

            await claim.put(PRESENCE)

        assert not claim.duplicate
        assert create.await_count == 2
        update.assert_not_awaited()

    async def test_reclaim_claims_occupied_key(self) -> None:
        """Claim an occupied key via a single reclaim on the heartbeat path."""
        claim = build_claim()
        reclaimed_revision = 7

        with (
            patch.object(claim.store, "create", AsyncMock(return_value=None)),
            patch.object(
                claim.store,
                "reclaim",
                AsyncMock(return_value=reclaimed_revision),
            ) as reclaim,
        ):
            await claim.put(PRESENCE)

        assert claim.owned
        assert claim.revision == reclaimed_revision
        reclaim.assert_awaited_once_with("alpha", PRESENCE, INSTANCE_ID)

    async def test_transient_reclaim_error_is_not_a_duplicate(self) -> None:
        """Propagate a transient reclaim failure without marking a duplicate."""
        claim = build_claim()

        with (
            patch.object(claim.store, "create", AsyncMock(return_value=None)),
            patch.object(
                claim.store,
                "reclaim",
                AsyncMock(side_effect=OSError("blip")),
            ),
            self.assertRaises(OSError),
        ):
            await claim.put(PRESENCE)

        assert not claim.duplicate
        assert not claim.owned

    async def test_observe_does_not_wait_for_presence_write(self) -> None:
        """Apply a duplicate at once during a slow write, which then records nothing."""
        claim = build_claim()
        claim.adopt(1)
        writing = asyncio.Event()
        release = asyncio.Event()

        async def slow_update(*arguments: object) -> int:
            del arguments
            writing.set()
            await release.wait()
            return 2

        with patch.object(claim.store, "update", slow_update):
            write = asyncio.create_task(claim.put(PRESENCE))
            async with asyncio.timeout(1):
                await writing.wait()
            with self.assertLogs("botnats.nats.claim", level="ERROR"):
                # The write holds the lock; observing must not wait for it.
                assert claim.observe("other-instance", 3)

            release.set()
            await write

        assert claim.duplicate
        assert claim.revision is None

    async def test_reclaim_after_reset_is_discarded(self) -> None:
        """Record nothing from a reclaim that finishes after a disconnect."""
        claim = build_claim()

        async def create_then_reset(*arguments: object) -> int:
            del arguments
            claim.reset()
            return 1

        with patch.object(claim.store, "create", create_then_reset):
            await claim.reclaim()

        assert not claim.owned

    async def test_stale_owner_cannot_overwrite_new_owner(self) -> None:
        """Fail closed when a heartbeat loses its owned KV revision."""
        claim = build_claim()
        claim.adopt(1)

        with (
            patch.object(claim.store, "update", AsyncMock(return_value=None)),
            patch.object(claim.store, "create", AsyncMock(return_value=None)),
            patch.object(claim.store, "reclaim", AsyncMock(return_value=None)),
            self.assertLogs("botnats.nats.claim", level="ERROR"),
            self.assertRaisesRegex(RuntimeError, "duplicate bot ID"),
        ):
            await claim.put(PRESENCE)

        assert not claim.owned
        assert claim.duplicate

    async def test_expired_owner_reclaims_id(self) -> None:
        """Reclaim an expired owned key without reporting a duplicate."""
        claim = build_claim()
        claim.adopt(1)
        reclaimed_revision = 2

        with (
            patch.object(claim.store, "update", AsyncMock(return_value=None)),
            patch.object(
                claim.store,
                "create",
                AsyncMock(return_value=reclaimed_revision),
            ),
        ):
            await claim.put(PRESENCE)

        assert claim.owned
        assert not claim.duplicate
        assert claim.revision == reclaimed_revision
