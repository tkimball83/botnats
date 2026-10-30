# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the presence claim's ownership transitions."""

import asyncio
import json
import unittest
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats.nats.claim import PresenceClaim, PresenceState
from botnats.nats.store import PresenceStore, StoreUnavailableError
from botnats.presence import BotPresence
from tests.unit.helpers import COORDINATION_KEY, FakeKV, bounded

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from nats.js.kv import KeyValue

INSTANCE_ID = "instance"
NOT_OWNED = "bot ID alpha does not own its presence key"
PRESENCE = {"bot_id": "alpha", "instance_id": INSTANCE_ID}
# A complete record, which the store can sign.
IDENTITY = {
    "bot_id": "alpha",
    "host": "host",
    "instance_id": INSTANCE_ID,
    "nick": "alpha",
    "user": "user",
}


def build_claim() -> PresenceClaim:
    """Build an unclaimed presence claim over an unopened store."""
    store = PresenceStore("efnet", 1, 15.0, COORDINATION_KEY)
    return PresenceClaim(store, "alpha", INSTANCE_ID)


def open_claim() -> tuple[PresenceClaim, FakeKV]:
    """Build an unclaimed presence claim over an empty in-memory bucket."""
    claim = build_claim()
    kv = FakeKV()
    claim.store.kv = cast("KeyValue", kv)
    return claim, kv


async def overlap(claim: PresenceClaim, *writes: Awaitable[None]) -> list[bool]:
    """Run presence writes at once; return the claim's ownership at each turn."""
    owned: list[bool] = []
    async with asyncio.timeout(5):
        running = asyncio.gather(*writes)
        while not running.done():
            owned.append(claim.owned)
            await asyncio.sleep(0)

        await running

    return owned


class PresenceClaimTests(unittest.IsolatedAsyncioTestCase):
    """Tests for claiming, refreshing, and yielding a presence key."""

    def test_require_needs_ownership(self) -> None:
        """Refuse writes until this process owns its presence key."""
        claim = build_claim()

        with self.assertRaisesRegex(StoreUnavailableError, NOT_OWNED):
            claim.require()

        claim.adopt(1)
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
            await bounded(claim.put(PRESENCE))
            assert claim.duplicate

            await bounded(claim.put(PRESENCE))

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
            await bounded(claim.put(PRESENCE))

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
            # By message: the bound's TimeoutError is an OSError too.
            self.assertRaisesRegex(OSError, "blip"),
        ):
            await bounded(claim.put(PRESENCE))

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
                claim.observe("other-instance", 3)

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
            await bounded(claim.reclaim())

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
            await bounded(claim.reclaim())

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
        ):
            await bounded(claim.put(PRESENCE))

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
            await bounded(claim.put(PRESENCE))

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
            await bounded(claim.deleted())

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
            await bounded(claim.put(PRESENCE))

        assert not claim.owned
        assert claim.revision is None

    def test_observe_own_record_adopts_newest_revision(self) -> None:
        """Adopt this instance's own watched record, never moving backwards."""
        claim = build_claim()

        claim.observe(INSTANCE_ID, 6)
        assert claim.owned
        assert claim.revision == 6

        claim.observe(INSTANCE_ID, 5)
        assert claim.owned
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
            self.assertNoLogs("botnats.nats.claim", level="ERROR"),
        ):
            await bounded(claim.put(PRESENCE))

        assert claim.owned
        assert claim.revision == reclaimed_revision

    async def test_release_deletes_owned_revision_of_this_instance(self) -> None:
        """Delete the owned revision of this instance's record, then stop owning it."""
        claim = build_claim()
        claim.adopt(3)
        delete = AsyncMock(return_value=None)

        with patch.object(claim.store, "delete", delete):
            await bounded(claim.release())

        delete.assert_awaited_once_with("alpha", 3, INSTANCE_ID)
        assert not claim.owned
        assert claim.revision is None

    async def test_release_survives_failed_delete(self) -> None:
        """Stop owning the key on shutdown even when deleting it fails."""
        claim = build_claim()
        claim.adopt(3)
        delete = AsyncMock(side_effect=NatsError("timeout"))

        with patch.object(claim.store, "delete", delete):
            await bounded(claim.release())

        delete.assert_awaited_once_with("alpha", 3, INSTANCE_ID)
        assert not claim.owned
        assert claim.revision is None

    async def test_duplicate_release_leaves_live_owner_key(self) -> None:
        """Leave the key to its live owner when a duplicate process shuts down.

        Without an owned revision, nats-py would delete it unconditionally.
        """
        claim = build_claim()
        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            claim.observe("other-instance", 1)

        delete = AsyncMock(return_value=None)

        with patch.object(claim.store, "delete", delete):
            await bounded(claim.release())

        delete.assert_not_awaited()

    def test_reset_keeps_duplicate(self) -> None:
        """Report a duplicate once across reconnects, and its resolution later."""
        claim = build_claim()
        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            claim.observe("other-instance", 1)

        claim.reset()
        # The watch replay after the reconnect shows the duplicate again.
        with self.assertNoLogs("botnats.nats.claim", level="ERROR"):
            claim.observe("other-instance", 1)

        with self.assertLogs("botnats.nats.claim", level="INFO") as logs:
            claim.observe(INSTANCE_ID, 2)

        assert [log.getMessage() for log in logs.records] == [
            "duplicate bot ID conflict resolved: alpha",
        ]

    async def test_deleted_key_keeps_duplicate_until_resolved(self) -> None:
        """Report a duplicate resolved when its occupant deletes the key."""
        claim = build_claim()
        with self.assertLogs("botnats.nats.claim", level="ERROR"):
            claim.observe("other-instance", 1)

        with (
            patch.object(claim.store, "create", AsyncMock(return_value=2)),
            self.assertLogs("botnats.nats.claim", level="INFO") as logs,
        ):
            await bounded(claim.deleted())

        assert [log.getMessage() for log in logs.records] == [
            "duplicate bot ID conflict resolved: alpha",
        ]
        assert claim.owned
        assert claim.revision == 2

    async def test_own_record_observed_during_write_keeps_its_revision(self) -> None:
        """Record a heartbeat's revision when the watch shows the last one meanwhile.

        Observing this instance's own record while owned changes no ownership,
        so the write in flight still counts.
        """
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
            async with asyncio.timeout(5):
                await writing.wait()
                claim.observe(INSTANCE_ID, 1)
                release.set()
                await write

        assert claim.owned
        assert claim.revision == 2

    async def test_overlapping_writes_keep_ownership(self) -> None:
        """Keep the key while an identity change overlaps a heartbeat.

        Both writes would update from the same revision: the loser would drop
        the key until a reclaim, taking readiness with it.
        """
        claim, kv = open_claim()
        await bounded(claim.put(IDENTITY))
        renamed = {**IDENTITY, "nick": "renamed"}

        owned = await overlap(claim, claim.put(IDENTITY), claim.put(renamed))

        assert owned
        assert all(owned)
        assert claim.revision == kv.entries["alpha"][0]

    async def test_reclaim_overlapping_heartbeat_owns_stored_revision(self) -> None:
        """Own the stored revision when a reclaim and a heartbeat claim at once.

        The losing claim would overwrite the winner's record after ownership
        changed and discard its revision, so the next heartbeat would lose the
        key.
        """
        for transition in (PresenceClaim.reclaim, PresenceClaim.deleted):
            with self.subTest(transition=transition.__name__):
                claim, kv = open_claim()

                await overlap(claim, transition(claim), claim.put(IDENTITY))

                assert claim.owned
                assert claim.revision == kv.entries["alpha"][0]

    async def test_reclaim_writes_no_irc_identity(self) -> None:
        """Reclaim without the IRC identity a heartbeat wrote, which peers skip.

        IRC may have dropped since that heartbeat: writing the identity again
        would have peers record, for a full TTL, a bot that is not on IRC.
        """
        for transition in (PresenceClaim.reclaim, PresenceClaim.deleted):
            with self.subTest(transition=transition.__name__):
                claim, kv = open_claim()
                await bounded(claim.put(IDENTITY))
                # The key expired or was deleted, and NATS dropped meanwhile.
                del kv.entries["alpha"]
                claim.reset()

                await bounded(transition(claim))

                assert claim.owned
                record = json.loads(kv.entries["alpha"][1])
                assert claim.store.valid("alpha", record)
                with self.assertRaisesRegex(ValueError, "invalid identity"):
                    BotPresence.from_dict(record)
