# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a restarted bot rebuilds ephemeral state from its peers."""

import asyncio
import os

from tests.integration.test_mesh import (
    BOTS,
    CHANNELS,
    COMMAND_TIMEOUT,
    connect,
    wait_for_bots,
    wait_for_names,
    wait_for_operators,
)


async def run() -> None:
    """Check desired channels and keys after a bot restart."""
    restarted_bot = frozenset({os.environ["BOTNATS_TEST_RESTARTED_BOT"]})
    session = await connect(os.environ["BOTNATS_TEST_IRC_ADDRESS"])
    try:
        await wait_for_bots(session)
        first, _ = CHANNELS[0]
        second, second_key = CHANNELS[1]

        await wait_for_names(session, first, absent=restarted_bot)
        await session.send("JOIN", second, second_key)
        await wait_for_names(session, second, present=BOTS)
        await wait_for_operators(session, second, present=BOTS)
    finally:
        await asyncio.wait_for(session.close(), timeout=COMMAND_TIMEOUT)


if __name__ == "__main__":
    asyncio.run(run())
