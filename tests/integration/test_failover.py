# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify TOTP claims remain available during one NATS-node failure."""

import asyncio
import os
import sys
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
    """Suppress expected connection errors from the killed test node."""
    del error


async def run(phase: str) -> None:
    """Report the stream leader or claim a counter through the surviving quorum."""
    nc = await nats.connect(
        servers=os.environ["BOTNATS_TEST_NATS_URLS"].split(","),
        connect_timeout=2,
        error_cb=ignore_error,
        max_reconnect_attempts=5,
        token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
    )
    try:
        claims = ClaimStore("integration", 3, SECRET)
        async with asyncio.timeout(LEADER_TIMEOUT):
            while True:
                try:
                    kv = await claims.open(nc.jetstream())
                except NatsError:
                    await asyncio.sleep(0.2)
                else:
                    break
        if phase == "leader":
            cluster = (await kv.status()).stream_info.cluster
            if cluster is None or not cluster.leader:
                msg = "claim stream has no leader"
                raise RuntimeError(msg)
            sys.stdout.write(f"{cluster.leader}\n")
        elif phase == "claim":
            await wait_leader(kv, sys.argv[2])
            assert await claims.claim(COUNTER)
        else:
            msg = f"unknown failover-test phase: {phase}"
            raise ValueError(msg)
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


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
