# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Live NATS tests for coordinator state exchange, conflicts, and help requests."""

import asyncio
import os
import time
import unittest
import uuid
from dataclasses import asdict
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from botnats.channel import ChannelRecord
from botnats.nats.coordinator import Coordinator, NATSConfig
from botnats.nats.envelope import Envelope
from botnats.nats.store import ATTEMPT_LIMIT
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    coordination_key,
    delete_buckets,
    nats_urls,
)
from tests.integration.test_mesh import poll_until
from tests.integration.test_restart import session_record

if TYPE_CHECKING:
    from botnats.bot import NATSCallbackHandler
    from botnats.presence import BotPresence

# The presence payload beta's help requests carry.
BETA_PRESENCE = {
    "bot_id": "beta",
    "host": "host",
    "instance_id": "instance",
    "nick": "beta",
    "user": "user",
}
EVENT_TIMEOUT = 5.0
HELP_KINDS = ("invite", "limit", "op", "unban")
SESSION_TTL = 300.0
START_TIMEOUT = 30.0


def ignore(*arguments: object, **keywords: object) -> None:
    """Accept and ignore a coordinator callback."""
    del arguments, keywords


def build_coordinator(
    bot_id: str,
    network: str,
    events: dict[str, asyncio.Event],
) -> Coordinator:
    """Build a coordinator whose help requests set the event for their kind."""

    def on_help(kind: str, channel: str, presence: BotPresence) -> None:
        del channel, presence
        if kind in events:
            events[kind].set()

    callbacks = SimpleNamespace(
        on_channel=ignore,
        on_help=on_help,
        on_presence=ignore,
        on_presence_delete=ignore,
        on_session_delete=ignore,
        on_session_update=ignore,
        on_sessions_replayed=ignore,
    )
    return Coordinator(
        callbacks=cast("NATSCallbackHandler", callbacks),
        config=NATSConfig(
            instance_id=uuid.uuid4().hex,
            monitor_port=8222,
            network=network,
            presence_ttl=15.0,
            replicas=JETSTREAM_REPLICAS,
            servers=tuple(nats_urls()),
            session_ttl=SESSION_TTL,
            token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
        ),
        envelope=Envelope(bot_id, coordination_key()),
    )


async def wait_until_ready(*coordinators: Coordinator) -> None:
    """Wait until every coordinator has replayed its watches and owns its ID."""

    async def ready() -> bool:
        return all(coordinator.ready for coordinator in coordinators)

    await poll_until(ready, wait_seconds=START_TIMEOUT, interval=0.05)


class CoordinatorIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Tests for live NATS state exchange, conflicts, and help requests."""

    async def asyncSetUp(self) -> None:
        """Start two coordinators on a fresh network and clean them up after."""
        self.events = {kind: asyncio.Event() for kind in HELP_KINDS}
        self.network = f"test{uuid.uuid4().hex}"
        self.alpha = build_coordinator("alpha", self.network, self.events)
        self.beta = build_coordinator("beta", self.network, {})
        # Cleanups run last-registered first: buckets go before connections.
        self.addAsyncCleanup(self.alpha.close)
        self.addAsyncCleanup(self.beta.close)
        self.addAsyncCleanup(self.delete_buckets)
        async with asyncio.timeout(START_TIMEOUT):
            await self.alpha.start()
            await self.beta.start()

        await wait_until_ready(self.alpha, self.beta)

    async def delete_buckets(self) -> None:
        """Delete this test's buckets so they don't load later phases."""
        nc = self.alpha.nc
        if nc is not None:
            await delete_buckets(nc, *(store.bucket for store in self.alpha.stores))

    async def test_auth_claim_dedup(self) -> None:
        """Verify a TOTP counter can be claimed once across the whole mesh."""
        assert await self.alpha.request_claim(123)
        assert not await self.beta.request_claim(123)

    async def test_auth_claim_replica_count(self) -> None:
        """Verify the claim bucket uses the configured replica count."""
        assert self.alpha.claims.kv is not None
        status = await self.alpha.claims.kv.status()

        assert status.stream_info.config.num_replicas == JETSTREAM_REPLICAS

    async def test_auth_rate_limit(self) -> None:
        """Verify authentication attempts are limited across the mesh."""
        coordinators = (self.alpha, self.beta)
        attempts = [
            await coordinators[attempt % 2].request_auth("rate.example")
            for attempt in range(ATTEMPT_LIMIT + 1)
        ]

        assert attempts == [True] * ATTEMPT_LIMIT + [False]

    async def test_help_requests_reach_peer(self) -> None:
        """Deliver every kind of broadcast help request from one bot to its peer."""
        for kind in HELP_KINDS:
            with self.subTest(kind=kind):
                await self.beta.request_help(
                    kind,
                    {"channel": "#shared", "presence": BETA_PRESENCE},
                )
                async with asyncio.timeout(EVENT_TIMEOUT):
                    await self.events[kind].wait()

    async def test_channel_write_conflict_has_one_winner(self) -> None:
        """Hand a writer that raced on a stale base the record that won instead."""
        first = asdict(ChannelRecord.new("#shared", "first", present=True))
        second = asdict(ChannelRecord.new("#shared", "second", present=True))

        stored_first = await self.alpha.put_channel(first, after=None)
        stored_second = await self.beta.put_channel(second, after=None)

        _, stored_key, _, _ = stored_first
        assert stored_key == "first"
        assert stored_second == stored_first

    async def test_session_write_keeps_highest_order(self) -> None:
        """Keep the newest session or revocation when bots write concurrently."""
        expires_at = time.time() + 120
        active = session_record(self.network, expires_at)
        stale = session_record(self.network, expires_at - 60)
        revocation = session_record(
            self.network,
            expires_at,
            revoked=True,
            version=1,
        )

        assert asdict(await self.alpha.put_session(active)) == active
        assert asdict(await self.beta.put_session(stale)) == active
        assert asdict(await self.beta.put_session(revocation)) == revocation

    async def test_duplicate_bot_id_stays_unready(self) -> None:
        """Keep a second process with a live bot's ID unready; the owner stays ready."""
        duplicate = build_coordinator("alpha", self.network, {})
        self.addAsyncCleanup(duplicate.close)
        async with asyncio.timeout(START_TIMEOUT):
            await duplicate.start()

        async def yielded() -> bool:
            return duplicate.claim.duplicate

        await poll_until(yielded, wait_seconds=START_TIMEOUT, interval=0.05)

        assert not duplicate.ready
        assert self.alpha.ready
