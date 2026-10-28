# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify TOTP claims survive and remain available during one NATS-node failure."""

import asyncio
import os
from contextlib import suppress
from typing import TYPE_CHECKING

import nats
from nats.errors import Error as NatsError

from botnats.nats.store import ClaimStore

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nats.js.kv import KeyValue

CONNECT_TIMEOUT = 30.0
COUNTER = 987_654_320
FRESH_COUNTER = 987_654_319
# The bots' jetstream_replicas in config/*.json; their buckets set it.
JETSTREAM_REPLICAS = 3
LEADER_TIMEOUT = 30.0
RETRY_INTERVAL = 0.2


def coordination_key() -> bytes:
    """Return the coordination secret run.py gives the bots."""
    return os.environ["BOTNATS_TEST_COORDINATION_SECRET"].encode()


def nats_urls() -> list[str]:
    """Return the published address of every NATS node, as run.py last saw it."""
    return os.environ["BOTNATS_TEST_NATS_URLS"].split(",")


async def ignore_error(error: Exception) -> None:
    """Suppress expected connection errors while a NATS node is down."""
    del error


async def keep_trying[T](
    attempt: Callable[[], Awaitable[T | None]],
    wait_seconds: float,
    failure: str,
) -> T:
    """Repeat an attempt through NATS errors until it returns a result.

    A timeout fails with the last NATS error as its cause, so a permanent
    problem such as a bad token is not reported as a bare timeout.
    """
    last_error: Exception | None = None
    try:
        async with asyncio.timeout(wait_seconds):
            while True:
                try:
                    result = await attempt()
                except (NatsError, OSError) as error:
                    last_error = error
                else:
                    if result is not None:
                        return result

                await asyncio.sleep(RETRY_INTERVAL)
    except TimeoutError as error:
        raise AssertionError(failure) from last_error or error


async def connect() -> nats.NATS:
    """Connect to any NATS node, retrying while Docker exposes a restarted one."""
    return await keep_trying(
        lambda: nats.connect(
            servers=nats_urls(),
            connect_timeout=2,
            error_cb=ignore_error,
            max_reconnect_attempts=5,
            token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
        ),
        CONNECT_TIMEOUT,
        "no NATS node accepted a connection",
    )


async def delete_buckets(nc: nats.NATS, *buckets: str) -> None:
    """Delete a test's own buckets so they don't load later phases."""
    js = nc.jetstream()
    for bucket in buckets:
        with suppress(NatsError):
            await js.delete_key_value(bucket)


async def open_claims() -> tuple[nats.NATS, ClaimStore, KeyValue]:
    """Connect through any surviving node and open the claim bucket."""
    nc = await connect()
    claims = ClaimStore("integration", JETSTREAM_REPLICAS, coordination_key())
    try:
        kv = await keep_trying(
            lambda: claims.open(nc.jetstream()),
            LEADER_TIMEOUT,
            "the claim bucket did not open",
        )
    except BaseException:
        await nc.drain()
        raise

    return nc, claims, kv


async def claim_before_failover() -> str:
    """Claim COUNTER and return the NATS node that leads the claim stream."""
    nc, claims, kv = await open_claims()
    try:
        assert await claims.claim(COUNTER)
        cluster = (await kv.status()).stream_info.cluster
        if cluster is None or not cluster.leader:
            msg = "claim stream has no leader"
            raise RuntimeError(msg)

        return cluster.leader
    finally:
        await nc.drain()


async def check_after_failover(previous: str) -> None:
    """Once a new leader is elected, expect COUNTER refused and a fresh one claimed."""
    nc, claims, kv = await open_claims()
    try:
        await wait_leader(kv, previous)
        # The fresh claim shows the store accepts writes, so the refusal
        # that follows is replay dedup rather than a failed publish.
        assert await claims.claim(FRESH_COUNTER)
        assert not await claims.claim(COUNTER)
    finally:
        await nc.drain()


async def wait_leader(kv: KeyValue, previous: str) -> None:
    """Wait for JetStream to elect a replacement stream leader."""

    async def new_leader() -> str | None:
        cluster = (await kv.status()).stream_info.cluster
        # No leader at all means the election is still running.
        if cluster is None or cluster.leader in {None, "", previous}:
            return None

        return cluster.leader

    await keep_trying(new_leader, LEADER_TIMEOUT, f"no leader replaced {previous}")
