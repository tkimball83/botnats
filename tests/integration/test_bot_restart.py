# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a restarted bot rebuilds its channels, keys, and ops from the mesh."""

import json

from botnats.nats.store import ChannelStore
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    coordination_key,
)
from tests.integration.test_failover import connect as connect_nats
from tests.integration.test_mesh import (
    BOTS,
    CHANNELS,
    connect,
    join_as_operator,
    modes,
    poll_until,
    wait_for_bots,
    wait_for_names,
    wait_for_operators,
)

ROTATED_KEY = "rotated-key"


async def change_key() -> None:
    """Change the keyed channel's key while a bot is down.

    The running bots must record the new key in JetStream, where the missing
    bot finds it once it is back; this reads the durable channel record, not
    a bot's in-memory state.
    """
    channel, old_key = CHANNELS[1]
    channels = ChannelStore("integration", JETSTREAM_REPLICAS, coordination_key())
    nc = await connect_nats()
    try:
        kv = await channels.open(nc.jetstream())
        session = await connect()
        try:
            await join_as_operator(session)
            await session.send("MODE", channel, "-k", old_key)
            await session.send("MODE", channel, "+k", ROTATED_KEY)

            async def recorded() -> bool:
                entry = await kv.get(channels.key(channel))
                assert entry.value is not None
                return json.loads(entry.value)["key"] == ROTATED_KEY

            await poll_until(recorded)
        finally:
            await session.close()
    finally:
        await nc.drain()


async def run(key: str = CHANNELS[1][1]) -> None:
    """Check the bots hold both present channels with ops, and not the parted one."""
    first, _ = CHANNELS[0]
    second, _ = CHANNELS[1]
    third, _ = CHANNELS[2]
    session = await connect()
    try:
        await wait_for_bots(session)
        # Joining with the key proves the channel still has it; a restarted
        # bot back inside that keyed channel proves it knew the key too.
        await session.send("JOIN", second, key)
        await wait_for_names(session, second, present=BOTS | {"owner"})
        mode_string = await modes(session, second)
        assert "k" in mode_string, mode_string
        await wait_for_operators(session, second, present=BOTS)
        await session.send("JOIN", third)
        await wait_for_names(session, third, present=BOTS | {"owner"})
        await wait_for_operators(session, third, present=BOTS)
        # Checked once every bot is back, so a late rejoin is caught too. The
        # bots are invisible (+i), so only a member of the channel sees them.
        await session.send("JOIN", first)
        await wait_for_names(session, first, absent=BOTS)
    finally:
        await session.close()
