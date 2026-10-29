# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""End-to-end tests for a three-bot mesh on real NATS and IRC servers."""

import asyncio
import base64
import os
import time
from typing import TYPE_CHECKING

from botnats.auth import totp
from botnats.irc.protocol import IRCMessage, format_message, parse_message
from tests.integration.test_failover import JETSTREAM_REPLICAS

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

BOTS = frozenset({"alpha", "beta", "gamma"})
CHANNELS = (
    ("#botnats-first", "first-key"),
    ("#botnats-second", "second-key"),
    # Never keyed: it keeps only the enforced modes.
    ("#botnats-third", None),
)
# Waits on the IRC server itself, which the bots' send pacing never delays.
COMMAND_TIMEOUT = 15.0
# Convergence polls. The slowest, a kicked bot's JOIN sent behind its queued
# lines and refused twice before a peer's help lands, then retried 10 and 20
# seconds after those refusals, takes about 37.5 seconds. This doubles it.
# Nick reclaims follow Ergo's MONITOR notices, not the bots' 60-second ISON
# poll.
CONVERGENCE_TIMEOUT = 75.0
POLL_INTERVAL = 0.25
# The bots pace IRC output by flood cost: five short lines at once, then one
# every two seconds. The slowest replies, to run()'s later JOINs, queue behind
# the previous channel's WHO, MODE, MODE +b, enforced modes and +o for each
# peer, then that JOIN: eight lines, or 16 seconds. This doubles it.
REPLY_TIMEOUT = 32.0
TEST_BAN = "*!*@blocked.example"
# TOTP counters this run has spent: each counter authenticates only once.
USED_COUNTERS: set[int] = set()


class IRCSession:
    """Small raw IRC client used to observe the complete wire behavior."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Store the connected stream pair and a diagnostic transcript."""
        self.reader = reader
        self.transcript: list[str] = []
        self.writer = writer

    async def close(self) -> None:
        """Close the IRC connection without waiting on a stuck peer."""
        self.writer.close()
        async with asyncio.timeout(COMMAND_TIMEOUT):
            await self.writer.wait_closed()

    async def read_until(
        self,
        predicate: Callable[[IRCMessage], bool],
        *,
        wait_seconds: float,
    ) -> IRCMessage:
        """Read until a matching message arrives.

        Raises TimeoutError when none arrives in time, and ConnectionError when
        the server closes the connection, so a polling caller can retry the
        first and stop on the second.
        """
        try:
            async with asyncio.timeout(wait_seconds):
                while True:
                    raw = await self.reader.readline()
                    if not raw:
                        msg = "IRC server closed the integration-test connection"
                        raise ConnectionError(msg)

                    line = raw.decode(errors="replace").rstrip("\r\n")
                    self.transcript.append(line)
                    message = parse_message(line)
                    if message.command == "PING" and message.params:
                        await self.send("PONG", trailing=message.params[-1])

                    if predicate(message):
                        return message
        except TimeoutError:
            pass

        recent = "\n".join(self.transcript[-20:])
        msg = f"timed out waiting for IRC response; recent traffic:\n{recent}"
        raise TimeoutError(msg)

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Write one IRC protocol message."""
        self.writer.write(format_message(command, params, trailing))
        await self.writer.drain()


async def authenticate(
    session: IRCSession,
    bot: str,
    code: str,
    expected: str = "Authorized",
) -> None:
    """Send AUTH with a code and wait for the bot's exact reply."""
    await session.send("PRIVMSG", bot, trailing=f"AUTH {code}")
    await session.read_until(
        private_message(bot, expected),
        wait_seconds=REPLY_TIMEOUT,
    )


async def command(session: IRCSession, bot: str, text: str) -> str:
    """Send one bot command and return its next private response."""
    await session.send("PRIVMSG", bot, trailing=text)
    response = await session.read_until(
        private_message(bot),
        wait_seconds=REPLY_TIMEOUT,
    )
    return response.params[-1]


async def connect() -> IRCSession:
    """Connect and register the integration-test IRC user."""
    address = os.environ["BOTNATS_TEST_IRC_ADDRESS"]
    host, separator, raw_port = address.rpartition(":")
    if not separator:
        msg = f"invalid IRC address: {address!r}"
        raise ValueError(msg)

    reader, writer = await asyncio.open_connection(host, int(raw_port))
    session = IRCSession(reader, writer)
    try:
        await session.send("NICK", "owner")
        await session.send("USER", "owner", "0", "*", trailing="BotNATS test owner")
        # The owner session a previous step just closed can hold the nick for
        # a moment; ask again until the server releases it.
        async with asyncio.timeout(COMMAND_TIMEOUT):
            while (
                await session.read_until(
                    lambda message: message.command in {"001", "433"},
                    wait_seconds=COMMAND_TIMEOUT,
                )
            ).command == "433":
                await asyncio.sleep(POLL_INTERVAL)
                await session.send("NICK", "owner")
    except BaseException:
        await session.close()
        raise

    return session


def fresh_code() -> str:
    """Return a currently valid TOTP code whose counter this run has not spent."""
    secret = base64.b32decode(os.environ["BOTNATS_TEST_TOTP_SECRET"])
    current = int(time.time() // 30)
    # The bots accept one counter either side of the current one.
    counter = next(
        counter for counter in (current, current + 1) if counter not in USED_COUNTERS
    )
    USED_COUNTERS.add(counter)
    return totp(secret, counter)


async def join_as_operator(session: IRCSession) -> None:
    """Join the second channel and wait until alpha has opped the owner there."""
    channel, key = CHANNELS[1]
    await session.send("JOIN", channel, key)
    await wait_for_reply(
        session, "alpha", f"OP {channel} owner", f"Opped owner on {channel}"
    )
    await wait_for_operators(session, channel, present=frozenset({"owner"}))


async def modes(session: IRCSession, channel: str) -> str:
    """Query and return the simple channel mode string."""
    await session.send("MODE", channel)
    response = await session.read_until(
        lambda message: (
            message.command == "324"
            and len(message.params) >= 3
            and message.params[1].casefold() == channel.casefold()
        ),
        wait_seconds=COMMAND_TIMEOUT,
    )
    return response.params[2]


async def names(session: IRCSession, channel: str) -> set[str]:
    """Return the current nicknames visible in one channel."""
    return {
        name.lstrip("~&@%+").casefold()
        for name in await names_entries(session, channel)
    }


async def names_entries(session: IRCSession, channel: str) -> list[str]:
    """Return raw NAMES entries for one channel."""
    await session.send("NAMES", channel)
    result: list[str] = []
    while True:
        response = await session.read_until(
            names_reply(channel),
            wait_seconds=COMMAND_TIMEOUT,
        )
        if response.command == "366":
            return result

        result.extend(response.params[-1].split())


def names_reply(channel: str) -> Callable[[IRCMessage], bool]:
    """Return a predicate for NAMES replies belonging to one channel."""

    def matches(message: IRCMessage) -> bool:
        if message.command == "353" and len(message.params) >= 2:
            return message.params[-2].casefold() == channel.casefold()

        return (
            message.command == "366"
            and len(message.params) >= 2
            and message.params[1].casefold() == channel.casefold()
        )

    return matches


async def operators(session: IRCSession, channel: str) -> set[str]:
    """Return channel members carrying an operator-level prefix."""
    return {
        name[1:].casefold()
        for name in await names_entries(session, channel)
        if name.startswith(("~", "&", "@"))
    }


def private_message(
    source: str,
    text: str | None = None,
) -> Callable[[IRCMessage], bool]:
    """Return a predicate for a private reply with optional exact text."""

    def matches(message: IRCMessage) -> bool:
        return (
            message.command == "PRIVMSG"
            and message.prefix is not None
            and message.prefix.nick.casefold() == source.casefold()
            and len(message.params) >= 2
            and message.params[0].casefold() == "owner"
            and (text is None or message.params[-1] == text)
        )

    return matches


async def poll_until(
    check: Callable[[], Awaitable[bool]],
    *,
    wait_seconds: float = CONVERGENCE_TIMEOUT,
    interval: float = POLL_INTERVAL,
) -> None:
    """Re-run an async check until it passes or the wait expires."""
    async with asyncio.timeout(wait_seconds):
        while True:
            if await check():
                return

            await asyncio.sleep(interval)


async def run() -> None:
    """Exercise auth deduplication, session propagation, and channel convergence."""
    session = await connect()
    try:
        await wait_for_bots(session)

        # One code authenticates once across the whole mesh.
        code = fresh_code()
        await authenticate(session, "alpha", code)
        await authenticate(session, "gamma", code, "Authorization failed")

        for channel, key in CHANNELS:
            supplied = f" {key}-supplied" if key else ""
            assert await command(session, "alpha", f"JOIN {channel}{supplied}") == (
                f"Joining {channel}"
            )
            await wait_for_channel(session, channel)

        await wait_for_status(session)

        for channel, key in CHANNELS:
            if key is not None:
                # Key the channel with other than the key the admin supplied:
                # later rejoins need the key the bots saw on IRC and stored.
                await wait_for_reply(
                    session, "alpha", f"OP {channel} owner", f"Opped owner on {channel}"
                )
                await wait_for_operators(session, channel, present=frozenset({"owner"}))
                await session.send("MODE", channel, "+k", key)
                _, tracked, *arguments = (
                    await command(session, "gamma", f"GETMODES {channel}")
                ).split()
                assert "k" in tracked
                assert arguments[-1] == key

            channel_modes = await modes(session, channel)
            assert ("k" in channel_modes) == (key is not None)
            assert "m" in channel_modes
            assert "n" in channel_modes
            assert "t" in channel_modes

        first, _ = CHANNELS[0]
        second, second_key = CHANNELS[1]
        third, _ = CHANNELS[2]

        # Multiple channels with different modes: set an extra mode on the
        # first channel, then remove an enforced one. The bots must restore
        # the enforced +m without touching +i, and the second channel must
        # keep its own modes.
        await session.send("MODE", first, "+i")
        await wait_for_modes(session, first, present="i")
        await session.send("MODE", first, "-m")
        await wait_for_modes(session, first, present="m")
        assert "i" in await modes(session, first)
        assert "i" not in await modes(session, second)

        assert await command(session, "alpha", f"BAN {first} {TEST_BAN}") == (
            f"Banned {TEST_BAN} on {first}"
        )
        await wait_for_reply(
            session,
            "beta",
            f"GETBANS {first}",
            f"{first} +b {TEST_BAN}",
        )
        assert await command(session, "beta", f"GETBANS {second}") == (
            f"No bans tracked for {second}"
        )

        assert await command(session, "alpha", f"PART {first}") == f"Parting {first}"
        await wait_for_names(session, first, absent=BOTS)
        await wait_for_names(session, second, present=BOTS)
        await wait_for_names(session, third, present=BOTS)
        reply = await command(session, "gamma", f"GETMODES {second}")
        assert second_key in reply
        assert "channels=2" in await command(session, "beta", "STATUS")
    finally:
        await session.close()


async def wait_for_bots(session: IRCSession) -> None:
    """Wait until all three bot nicknames are registered on IRC."""

    async def online() -> bool:
        await session.send("ISON", *sorted(BOTS))
        response = await session.read_until(
            lambda message: message.command == "303",
            wait_seconds=COMMAND_TIMEOUT,
        )
        return set(response.params[-1].casefold().split()) == BOTS

    await poll_until(online)


async def wait_for_channel(session: IRCSession, channel: str) -> None:
    """Join one channel, not yet keyed, and wait until all bots converge into it."""
    await session.send("JOIN", channel)
    await wait_for_names(session, channel, present=BOTS)


async def wait_for_names(
    session: IRCSession,
    channel: str,
    *,
    absent: frozenset[str] = frozenset(),
    present: frozenset[str] = frozenset(),
) -> None:
    """Wait until required nicks are present and forbidden nicks are absent."""

    async def converged() -> bool:
        current = await names(session, channel)
        return current >= present and current.isdisjoint(absent)

    await poll_until(converged)


async def wait_for_modes(
    session: IRCSession,
    channel: str,
    *,
    present: str,
) -> None:
    """Wait until a channel's mode string contains the required flag."""

    async def has_mode() -> bool:
        return present in await modes(session, channel)

    await poll_until(has_mode)


async def wait_for_operators(
    session: IRCSession,
    channel: str,
    *,
    present: frozenset[str],
) -> None:
    """Wait until the required members hold operator status in one channel."""

    async def opped() -> bool:
        return await operators(session, channel) >= present

    await poll_until(opped)


async def wait_for_status(session: IRCSession) -> None:
    """Poll beta's STATUS until it reports the expected mesh state."""

    async def healthy() -> bool:
        await session.send("PRIVMSG", "beta", trailing="STATUS")
        local_status = await session.read_until(
            private_message("beta"),
            wait_seconds=REPLY_TIMEOUT,
        )
        nats_status = await session.read_until(
            private_message("beta"),
            wait_seconds=REPLY_TIMEOUT,
        )
        local_text = local_status.params[-1]
        if "peers=2" not in local_text or "channels=3" not in local_text:
            return False

        nats_fields = dict(
            field.split("=", 1) for field in nats_status.params[-1].split()[1:]
        )
        # STATUS shows "?" for a route count it could not read; keep polling.
        routes = nats_fields.get("routes", "")
        return (
            nats_fields.get("connection") == "up"
            and routes.isdigit()
            and int(routes) >= 2
            and nats_fields.get("jetstream") == "up"
            and nats_fields.get("replicas")
            == f"{JETSTREAM_REPLICAS}/{JETSTREAM_REPLICAS}"
        )

    await poll_until(healthy, interval=2.0)


async def wait_for_reply(
    session: IRCSession,
    bot: str,
    command_text: str,
    expected: str,
) -> None:
    """Poll a bot command until replicated state produces the expected reply."""

    async def replied() -> bool:
        return await command(session, bot, command_text) == expected

    await poll_until(replied, interval=2.0)
