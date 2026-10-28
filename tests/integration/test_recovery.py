# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify recovery from a ban, a kick, a full or invite-only channel, and a restart."""

import asyncio
from typing import TYPE_CHECKING

from tests.integration.test_mesh import (
    CHANNELS,
    COMMAND_TIMEOUT,
    IRCSession,
    authenticate,
    connect,
    fresh_code,
    join_as_operator,
    names,
    private_message,
    wait_for_bots,
    wait_for_modes,
    wait_for_names,
    wait_for_reply,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

# The restarted bot's STATUS reply queues behind its registration, WHO, and
# rejoin (JOIN, WHO, MODE, MODE +b, then MODE and enforced modes once
# opped): 12 lines, sent within 16 seconds of connecting under flood pacing.
RESTART_TIMEOUT = 90.0
# A reply later than one poll is read by the next; this only paces resends.
STATUS_POLL_WAIT = 3.0


async def wait_for_authorized_status(session: IRCSession) -> str:
    """Poll alpha's STATUS until it answers; unauthorized senders get no reply.

    Only a silent poll is retried: a closed connection fails at once.
    """
    async with asyncio.timeout(RESTART_TIMEOUT):
        while True:
            await session.send("PRIVMSG", "alpha", trailing="STATUS")
            try:
                reply = await session.read_until(
                    private_message("alpha"),
                    wait_seconds=STATUS_POLL_WAIT,
                )
            except TimeoutError:
                continue

            return reply.params[-1]


async def rejoin_after_ban(session: IRCSession) -> None:
    """Ban and kick a bot; the mesh must get it back in and lift the ban."""
    channel, _ = CHANNELS[1]
    await join_as_operator(session)

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


async def rejoin_invite_only(session: IRCSession) -> None:
    """Kick a bot from an invite-only channel; a peer must invite it back."""
    channel, _ = CHANNELS[1]
    await session.send("MODE", channel, "+i")
    await wait_for_modes(session, channel, present="i")
    await session.send("KICK", channel, "gamma", trailing="invite test")

    # gamma's JOIN is refused as invite-only until a peer invites it.
    await wait_for_names(session, channel, present=frozenset({"gamma"}))
    await session.send("MODE", channel, "-i")


async def session_survives_restart(
    session: IRCSession,
    restart: Callable[[str], Awaitable[None]],
) -> None:
    """Restart a bot; its admin session must replay from JetStream, not reset."""
    await restart("alpha")
    reply = await wait_for_authorized_status(session)
    assert reply.startswith("bot id=alpha"), reply


async def run(restart: Callable[[str], Awaitable[None]]) -> None:
    """Authenticate once, then exercise every recovery path on one connection."""
    session = await connect()
    try:
        await wait_for_bots(session)
        await authenticate(session, "alpha", fresh_code())

        await rejoin_after_ban(session)
        await rejoin_full_channel(session)
        await rejoin_invite_only(session)
        # Keep this connection open across the restart: closing it would QUIT
        # and revoke the very session under test.
        await session_survives_restart(session, restart)
    finally:
        await session.close()
