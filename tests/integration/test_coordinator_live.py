# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Live NATS tests for coordinator state exchange and help requests."""

import asyncio
import time
import unittest
import uuid
from contextlib import suppress
from functools import partial
from typing import TYPE_CHECKING
from unittest.mock import patch

from botnats.nats.store import ATTEMPT_LIMIT
from tests.unit.test_coordinator import (
    BETA_PRESENCE,
    JETSTREAM_REPLICAS,
    Fixtures,
    build_coordinator,
)

if TYPE_CHECKING:
    from botnats.nats.coordinator import Coordinator

GRANT_TIMEOUT = 5


class CoordinatorIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Tests for live NATS state exchange and help requests."""

    async def asyncSetUp(self) -> None:
        """Connect two coordinators wired to shared test fixtures."""
        self.fixtures = Fixtures(
            events={
                "op": asyncio.Event(),
                "unban": asyncio.Event(),
            },
        )
        network = f"test{uuid.uuid4().hex}"
        self.alpha = build_coordinator("alpha", self.fixtures, network)
        self.beta = build_coordinator("beta", self.fixtures, network)
        ready = asyncio.Event()

        def mark_synced(coordinator: Coordinator, name: str) -> None:
            coordinator.synced_watches.add(name)
            if self.alpha.ready and self.beta.ready:
                ready.set()

        with (
            patch.object(
                self.alpha,
                "mark_watch_synced",
                partial(mark_synced, self.alpha),
            ),
            patch.object(
                self.beta,
                "mark_watch_synced",
                partial(mark_synced, self.beta),
            ),
        ):
            await self.alpha.start()
            await self.beta.start()
            async with asyncio.timeout(GRANT_TIMEOUT):
                await ready.wait()

        assert self.alpha.ready
        assert self.beta.ready

    async def asyncTearDown(self) -> None:
        """Close both coordinators."""
        await self.beta.close()
        await self.alpha.close()

    async def test_auth_claim_dedup(self) -> None:
        """Verify a TOTP counter can be claimed once across the whole mesh."""
        counter = 123
        assert self.alpha.claims.kv is not None
        with suppress(Exception):
            await self.alpha.claims.kv.delete(self.alpha.claims.key(counter))

        assert await self.alpha.request_claim(counter)
        assert not await self.beta.request_claim(counter)

    async def test_auth_claim_replica_count(self) -> None:
        """Verify the claim bucket uses the configured replica count."""
        assert self.alpha.claims.kv is not None
        status = await self.alpha.claims.kv.status()

        assert status.stream_info.config.num_replicas == JETSTREAM_REPLICAS

    async def test_auth_rate_limit(self) -> None:
        """Verify authentication attempts are limited across the mesh."""
        identity = f"rate-{time.time_ns()}.example"
        attempts = [
            await coordinator.request_auth(identity)
            for coordinator in (self.alpha, self.beta, self.alpha, self.beta)
        ]

        assert attempts == [True] * ATTEMPT_LIMIT + [False]

    async def test_auth_rate_limit_boundary(self) -> None:
        """Verify the mesh limit does not reset at a fixed-window boundary."""
        identity = f"boundary-{time.time_ns()}.example"
        for coordinator in (self.alpha, self.beta, self.alpha):
            assert await coordinator.attempts.allow(identity, now=59.9)

        assert not await self.beta.attempts.allow(identity, now=60)

    async def test_op_request_reaches_peer(self) -> None:
        """Deliver a broadcast op request from one bot to its peer."""
        await self.beta.request_help(
            "op",
            {"channel": "#shared", "presence": BETA_PRESENCE},
        )

        async with asyncio.timeout(GRANT_TIMEOUT):
            await self.fixtures.events["op"].wait()

    async def test_unban_request_reaches_peer(self) -> None:
        """Deliver a broadcast unban request from one bot to its peer."""
        await self.beta.request_help(
            "unban",
            {"channel": "#shared", "presence": BETA_PRESENCE},
        )

        async with asyncio.timeout(GRANT_TIMEOUT):
            await self.fixtures.events["unban"].wait()
