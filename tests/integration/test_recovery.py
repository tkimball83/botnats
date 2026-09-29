# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify recovery from a ban, a kick, and a full channel, and a session restart."""

import asyncio
import base64
import os
import time
from typing import TYPE_CHECKING

from botnats.auth import totp
from tests.integration.test_mesh import (
    CHANNELS,
    COMMAND_TIMEOUT,
    STARTUP_TIMEOUT,
    IRCSession,
    connect,
    names,
    private_message,
    wait_for_bots,
    wait_for_names,
    wait_for_operators,
    wait_for_reply,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

RESTART_TIMEOUT = 90.0
STATUS_POLL_WAIT = 3.0


async def wait_for_authorized_status(session: IRCSession, bot: str) -> str:
    """Poll STATUS until the bot answers; unauthorized senders get no reply."""
    async with asyncio.timeout(RESTART_TIMEOUT):
        while True:
            await session.send("PRIVMSG", bot, trailing="STATUS")
            try:
                reply = await session.read_until(
                    private_message(bot),
                    wait_seconds=STATUS_POLL_WAIT,
                )
            except AssertionError:
                continue

            return reply.params[-1]


async def rejoin_after_ban(session: IRCSession) -> None:
    """Ban and kick a bot; the mesh must get it back in and lift the ban."""
    channel, key = CHANNELS[1]
    await session.send("JOIN", channel, key)
    await wait_for_reply(
        session, "alpha", f"OP {channel} owner", f"Opped owner on {channel}"
    )
    await wait_for_operators(session, channel, present=frozenset({"owner"}))

    await session.send("MODE", channel, "+b", "gamma!*@*")
    await session.send("KICK", channel, "gamma", trailing="recovery test")
    await session.read_until(
        lambda message: (
            message.command == "KICK"
            and len(message.params) >= 2
            and message.params[1].casefold() == "gamma"
        ),
        wait_seconds=COMMAND_TIMEOUT,
    )

    # The mesh must get gamma back in and the ban lifted, whichever recovery
    # path wins (unban request on kick, peers lifting a peer's ban, or a
    # refused JOIN retried after the unban). The unit tests pin down the
    # refusal transition itself; its timing cannot be forced from outside.
    await wait_for_names(session, channel, present=frozenset({"gamma"}))
    await wait_for_reply(
        session,
        "beta",
        f"GETBANS {channel}",
        f"No bans tracked for {channel}",
    )


async def rejoin_full_channel(session: IRCSession) -> None:
    """Kick a bot from a channel limited to those left; peers must make room."""
    channel, _ = CHANNELS[1]
    members = await names(session, channel)
    await session.send("MODE", channel, "+l", str(len(members) - 1))
    await session.send("KICK", channel, "gamma", trailing="limit test")

    # gamma's JOIN is refused as full until a peer raises the limit for it.
    await wait_for_names(session, channel, present=frozenset({"gamma"}))
    await session.send("MODE", channel, "-l")


async def session_survives_restart(
    session: IRCSession,
    restart: Callable[[str], Awaitable[None]],
) -> None:
    """Restart a bot; its admin session must replay from JetStream, not reset."""
    await restart("alpha")
    reply = await wait_for_authorized_status(session, "alpha")
    assert reply.startswith("bot id=alpha"), reply


async def run(restart: Callable[[str], Awaitable[None]]) -> None:
    """Authenticate once, then exercise every recovery path on one connection."""
    secret = base64.b32decode(os.environ["BOTNATS_TEST_TOTP_SECRET"])
    session = await connect(os.environ["BOTNATS_TEST_IRC_ADDRESS"])
    try:
        await wait_for_bots(session)
        # The next window's code: the mesh test already claimed this window's.
        code = totp(secret, int(time.time() // 30) + 1)
        await session.send("PRIVMSG", "alpha", trailing=f"AUTH {code}")
        await session.read_until(
            private_message("alpha", "Authorized"),
            wait_seconds=COMMAND_TIMEOUT,
        )

        await rejoin_after_ban(session)
        await rejoin_full_channel(session)
        # Keep this connection open across the restart: closing it would QUIT
        # and revoke the very session under test.
        await session_survives_restart(session, restart)
    finally:
        await asyncio.wait_for(session.close(), timeout=STARTUP_TIMEOUT)
