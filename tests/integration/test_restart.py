# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a TOTP claim survives a complete NATS cluster restart."""

import asyncio
import os
import sys

import nats
from nats.errors import Error as NatsError

from botnats.nats.store import ClaimStore

CONNECT_TIMEOUT = 30.0
COUNTER = 987_654_321
SECRET = b"coordination-secret-used-only-for-tests"


async def connect() -> nats.NATS:
    """Connect after Docker exposes the restarted server's host port."""
    async with asyncio.timeout(CONNECT_TIMEOUT):
        while True:
            try:
                return await nats.connect(
                    os.environ["BOTNATS_TEST_NATS_URL"],
                    connect_timeout=2,
                    error_cb=ignore_error,
                    max_reconnect_attempts=5,
                    token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
                )
            except NatsError, OSError:
                await asyncio.sleep(0.2)


async def ignore_error(error: Exception) -> None:
    """Suppress expected connection errors during host-port recovery."""
    del error


async def run(phase: str) -> None:
    """Create or verify the restart-test claim."""
    nc = await connect()
    try:
        claims = ClaimStore("efnet", 3, SECRET)
        if phase == "mark":
            await claims.open(nc.jetstream())
            assert await claims.claim(COUNTER)
        elif phase == "check":
            async with asyncio.timeout(CONNECT_TIMEOUT):
                while True:
                    try:
                        kv = await claims.open(nc.jetstream())
                        entry = await kv.get(claims.key(COUNTER))
                    except NatsError:
                        await asyncio.sleep(0.5)
                        continue
                    assert entry.value == b"1"
                    break
        else:
            msg = f"unknown restart-test phase: {phase}"
            raise ValueError(msg)
    finally:
        await nc.drain()


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
