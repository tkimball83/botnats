# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the presence claim's ownership transitions."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats.nats.claim import PresenceClaim, PresenceState
from botnats.nats.store import PresenceStore, StoreUnavailableError
from tests.unit.helpers import COORDINATION_KEY

INSTANCE_ID = "instance"
NOT_OWNED = "bot ID alpha does not own its presence key"
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

        with self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED):
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
            patch.object(claim.store, "reclaim", AsyncMock(return_value=None)),
        ):
            with self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED):
                await claim.put(PRESENCE)

            await claim.put(PRESENCE)

        assert not claim.duplicate
        assert create.await_count == 2

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
            async with asyncio.timeout(1):
                await write

        assert claim.duplicate
        assert claim.revision is None

    async def test_reclaim_owns_created_key(self) -> None:
        """Own the key at the revision a reclaim after a replay creates."""
        claim = build_claim()
        created_revision = 3

        with patch.object(
            claim.store, "create", AsyncMock(return_value=created_revision)
        ):
            await claim.reclaim()

        assert claim.owned
        assert claim.revision == created_revision

    async def test_reclaim_after_reset_is_discarded(self) -> None:
        """Record nothing from a reclaim that finishes after a disconnect."""
        claim = build_claim()

        async def create_then_reset(*arguments: object) -> int:
            del arguments
            claim.reset()
            return 1

        create = AsyncMock(side_effect=create_then_reset)
        with patch.object(claim.store, "create", create):
            await claim.reclaim()

        create.assert_awaited_once()
        assert not claim.owned
        assert claim.revision is None

    async def test_stale_owner_cannot_overwrite_new_owner(self) -> None:
        """Fail closed when a heartbeat loses its owned KV revision."""
        claim = build_claim()
        claim.adopt(1)

        with (
            patch.object(claim.store, "update", AsyncMock(return_value=None)),
            patch.object(claim.store, "create", AsyncMock(return_value=None)),
            patch.object(claim.store, "reclaim", AsyncMock(return_value=None)),
            self.assertLogs("botnats.nats.claim", level="ERROR"),
            self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED),
        ):
            await claim.put(PRESENCE)

        assert claim.duplicate

    async def test_heartbeat_refreshes_owned_revision(self) -> None:
        """Refresh an owned key in place under its last revision."""
        claim = build_claim()
        claim.adopt(1)
        refreshed_revision = 2

        with (
            patch.object(
                claim.store,
                "update",
                AsyncMock(return_value=refreshed_revision),
            ) as update,
            patch.object(claim.store, "create", AsyncMock(return_value=None)) as create,
        ):
            await claim.put(PRESENCE)

        update.assert_awaited_once_with("alpha", PRESENCE, 1)
        create.assert_not_awaited()
        assert claim.owned
        assert claim.revision == refreshed_revision

    async def test_deleted_key_drops_ownership_before_reclaim(self) -> None:
        """Stop owning a deleted key even when reclaiming it fails."""
        claim = build_claim()
        claim.adopt(1)

        with (
            patch.object(
                claim.store, "create", AsyncMock(side_effect=NatsError("down"))
            ),
            self.assertRaises(NatsError),
        ):
            await claim.expired()

        assert not claim.owned
        assert claim.revision is None

    async def test_lost_revision_drops_ownership_before_reclaim(self) -> None:
        """Stop owning a key whose revision was lost even when reclaiming it fails."""
        claim = build_claim()
        claim.adopt(1)

        with (
            patch.object(claim.store, "update", AsyncMock(return_value=None)),
            patch.object(
                claim.store, "create", AsyncMock(side_effect=NatsError("down"))
            ),
            self.assertRaises(NatsError),
        ):
            await claim.put(PRESENCE)

        assert not claim.owned
        assert claim.revision is None

    def test_observe_own_record_adopts_newest_revision(self) -> None:
        """Adopt this instance's own watched record, never moving backwards."""
        claim = build_claim()

        assert not claim.observe(INSTANCE_ID, 6)
        assert claim.owned
        assert claim.revision == 6

        assert not claim.observe(INSTANCE_ID, 5)
        assert claim.revision == 6

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
        assert claim.revision == reclaimed_revision

    async def test_release_deletes_owned_revision_of_this_instance(self) -> None:
        """Delete the owned revision of this instance's record, then stop owning it."""
        claim = build_claim()
        claim.adopt(3)
        delete = AsyncMock(return_value=None)

        with patch.object(claim.store, "delete", delete):
            await claim.release()

        delete.assert_awaited_once_with("alpha", 3, INSTANCE_ID)
        assert not claim.owned
        assert claim.revision is None
