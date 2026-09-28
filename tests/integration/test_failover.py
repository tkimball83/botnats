# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify TOTP claims remain available during one NATS-node failure."""

import asyncio
import os
from typing import TYPE_CHECKING

import nats
from nats.errors import Error as NatsError

from botnats.nats.store import ClaimStore
from tests.unit.helpers import COORDINATION_KEY as SECRET

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

COUNTER = 987_654_320
LEADER_TIMEOUT = 30.0


async def ignore_error(error: Exception) -> None:
    """Suppress expected connection errors while a NATS node is down."""
    del error


async def open_claims() -> tuple[nats.NATS, ClaimStore, KeyValue]:
    """Connect through any surviving node and open the claim bucket."""
    nc = await nats.connect(
        servers=os.environ["BOTNATS_TEST_NATS_URLS"].split(","),
        connect_timeout=2,
        error_cb=ignore_error,
        max_reconnect_attempts=5,
        token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
    )
    claims = ClaimStore("integration", 3, SECRET)
    try:
        async with asyncio.timeout(LEADER_TIMEOUT):
            while True:
                try:
                    return nc, claims, await claims.open(nc.jetstream())
                except NatsError:
                    await asyncio.sleep(0.2)
    except BaseException:
        await nc.drain()
        raise


async def stream_leader() -> str:
    """Return the NATS node that leads the claim stream."""
    nc, _, kv = await open_claims()
    try:
        cluster = (await kv.status()).stream_info.cluster
        if cluster is None or not cluster.leader:
            msg = "claim stream has no leader"
            raise RuntimeError(msg)

        return cluster.leader
    finally:
        await nc.drain()


async def claim_after_failover(previous: str) -> None:
    """Claim a counter once a replacement leader is elected."""
    nc, claims, kv = await open_claims()
    try:
        await wait_leader(kv, previous)
        assert await claims.claim(COUNTER)
    finally:
        await nc.drain()


async def wait_leader(kv: KeyValue, previous: str) -> None:
    """Wait for JetStream to elect a replacement stream leader."""
    async with asyncio.timeout(LEADER_TIMEOUT):
        while True:
            try:
                cluster = (await kv.status()).stream_info.cluster
            except NatsError:
                pass
            else:
                if cluster is not None and cluster.leader != previous:
                    return

            await asyncio.sleep(0.2)
