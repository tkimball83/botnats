# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify durable state survives a complete NATS cluster restart."""

import asyncio
import json
import os
import sys

import nats
from nats.errors import Error as NatsError

from botnats.channel import ChannelRecord
from botnats.nats.store import ChannelStore, ClaimStore

CHANNEL = "#botnats-restart"
CHANNEL_KEY = "restart-key"
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
        channels = ChannelStore("efnet", 3, SECRET)
        if phase == "mark":
            await claims.open(nc.jetstream())
            assert await claims.claim(COUNTER)
            await channels.open(nc.jetstream())
            record = ChannelRecord.new(CHANNEL, CHANNEL_KEY, present=True).to_dict()
            stored = await channels.put(CHANNEL, record)
            assert stored["key"] == CHANNEL_KEY
        elif phase == "check":
            # A missing key here can be transient while JetStream replays after
            # the restart, so keep retrying; only a genuine loss (or an elapsed
            # claim TTL) exhausts the timeout, which we surface as a clear error
            # instead of an opaque TimeoutError.
            try:
                async with asyncio.timeout(CONNECT_TIMEOUT):
                    while True:
                        try:
                            kv = await claims.open(nc.jetstream())
                            entry = await kv.get(claims.key(COUNTER))
                            channel_kv = await channels.open(nc.jetstream())
                            channel_entry = await channel_kv.get(channels.key(CHANNEL))
                        except NatsError:
                            await asyncio.sleep(0.5)
                            continue
                        assert entry.value == b"1"
                        assert channel_entry.value is not None
                        channel_record = json.loads(channel_entry.value)
                        assert channel_record["key"] == CHANNEL_KEY
                        assert channel_record["present"] is True
                        break
            except TimeoutError:
                msg = "durable state missing after NATS restart"
                raise AssertionError(msg) from None
        else:
            msg = f"unknown restart-test phase: {phase}"
            raise ValueError(msg)
    finally:
        await nc.drain()


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
