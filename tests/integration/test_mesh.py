# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""End-to-end tests for a three-bot mesh on real NATS and IRC servers."""

import asyncio
import base64
import os
import time
from typing import TYPE_CHECKING

from botnats.admin import totp
from botnats.irc.protocol import IRCMessage, format_message, parse_message

if TYPE_CHECKING:
    from collections.abc import Callable

BOTS = frozenset({"alpha", "beta", "gamma"})
CHANNELS = (
    ("#botnats-first", "first-key"),
    ("#botnats-second", "second-key"),
)
COMMAND_TIMEOUT = 15.0
STARTUP_TIMEOUT = 45.0
TEST_BAN = "*!*@blocked.example"


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
        """Close the IRC connection."""
        self.writer.close()
        await self.writer.wait_closed()

    async def read_until(
        self,
        predicate: Callable[[IRCMessage], bool],
        *,
        wait_seconds: float,
    ) -> IRCMessage:
        """Read through IRC traffic until a matching message arrives."""
        try:
            async with asyncio.timeout(wait_seconds):
                while True:
                    raw = await self.reader.readline()
                    if not raw:
                        msg = "IRC server closed the integration-test connection"
                        raise AssertionError(msg)
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
        raise AssertionError(msg)

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Write one IRC protocol message."""
        self.writer.write(format_message(command, params, trailing))
        await self.writer.drain()


async def command(session: IRCSession, bot: str, text: str) -> str:
    """Send one bot command and return its next private response."""
    await session.send("PRIVMSG", bot, trailing=text)
    response = await session.read_until(
        private_message(bot),
        wait_seconds=COMMAND_TIMEOUT,
    )
    return response.params[-1]


async def connect(address: str) -> IRCSession:
    """Connect and register the integration-test IRC user."""
    host, separator, raw_port = address.rpartition(":")
    if not separator:
        msg = f"invalid IRC address: {address!r}"
        raise ValueError(msg)
    reader, writer = await asyncio.open_connection(host, int(raw_port))
    session = IRCSession(reader, writer)
    await session.send("NICK", "owner")
    await session.send("USER", "owner", "0", "*", trailing="BotNATS test owner")
    await session.read_until(
        lambda message: message.command == "001",
        wait_seconds=COMMAND_TIMEOUT,
    )
    return session


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


async def run() -> None:
    """Exercise auth deduplication, session propagation, and channel convergence."""
    address = os.environ["BOTNATS_TEST_IRC_ADDRESS"]
    encoded_secret = os.environ["BOTNATS_TEST_TOTP_SECRET"]
    secret = base64.b32decode(encoded_secret)
    session = await connect(address)
    try:
        await wait_for_bots(session)

        code = totp(secret, int(time.time() // 30))
        await session.send("PRIVMSG", "alpha", trailing=f"AUTH {code}")
        await session.read_until(
            private_message("alpha", "Authorized"),
            wait_seconds=COMMAND_TIMEOUT,
        )

        await session.send("PRIVMSG", "gamma", trailing=f"AUTH {code}")
        await session.read_until(
            private_message("gamma", "Authorization failed"),
            wait_seconds=COMMAND_TIMEOUT,
        )

        for channel, key in CHANNELS:
            assert await command(session, "alpha", f"JOIN {channel} {key}") == (
                f"Joining {channel}"
            )
            await wait_for_channel(session, channel, key)

        await wait_for_status(session, "beta")

        for channel, key in CHANNELS:
            await wait_for_reply(
                session, "gamma", f"KEY {channel}", f"Key for {channel}: {key}"
            )
            channel_modes = await modes(session, channel)
            assert "m" in channel_modes
            assert "n" in channel_modes
            assert "t" in channel_modes

        first, _ = CHANNELS[0]
        second, second_key = CHANNELS[1]

        # Multiple channels with different modes: op the owner on the first
        # channel and set an extra mode there. The mesh must keep the modes
        # isolated per channel and not re-apply the enforced set over +i.
        assert await command(session, "alpha", f"OP {first} owner") == (
            f"Opped owner on {first}"
        )
        await wait_for_operators(session, first, present=frozenset({"owner"}))
        await session.send("MODE", first, "+i")
        await wait_for_modes(session, first, present="i")
        assert "i" not in await modes(session, second)

        await wait_for_operators(session, first, present=frozenset({"alpha"}))
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
        assert await command(session, "gamma", f"KEY {second}") == (
            f"Key for {second}: {second_key}"
        )
        assert "channels=1" in await command(session, "beta", "STATUS")
    finally:
        await session.close()


async def wait_for_bots(session: IRCSession) -> None:
    """Wait until all three bot nicknames are registered on IRC."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            await session.send("ISON", *sorted(BOTS))
            response = await session.read_until(
                lambda message: message.command == "303",
                wait_seconds=COMMAND_TIMEOUT,
            )
            online = set(response.params[-1].casefold().split())
            if online == BOTS:
                return
            await asyncio.sleep(0.25)


async def wait_for_channel(session: IRCSession, channel: str, key: str) -> None:
    """Join one channel and wait until all bots have converged into it."""
    await session.send("JOIN", channel, key)
    await wait_for_names(session, channel, present=BOTS)


async def wait_for_names(
    session: IRCSession,
    channel: str,
    *,
    absent: frozenset[str] = frozenset(),
    present: frozenset[str] = frozenset(),
) -> None:
    """Wait until required nicks are present and forbidden nicks are absent."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            current = await names(session, channel)
            if current >= present and current.isdisjoint(absent):
                return
            await asyncio.sleep(0.25)


async def wait_for_modes(
    session: IRCSession,
    channel: str,
    *,
    present: str,
) -> None:
    """Wait until a channel's mode string contains the required flag."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            if present in await modes(session, channel):
                return
            await asyncio.sleep(0.25)


async def wait_for_operators(
    session: IRCSession,
    channel: str,
    *,
    present: frozenset[str],
) -> None:
    """Wait until the required members hold operator status in one channel."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            if await operators(session, channel) >= present:
                return
            await asyncio.sleep(0.25)


async def wait_for_status(session: IRCSession, bot: str) -> None:
    """Poll STATUS until the bot reports the expected mesh state."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            await session.send("PRIVMSG", bot, trailing="STATUS")
            local_status = await session.read_until(
                private_message(bot),
                wait_seconds=COMMAND_TIMEOUT,
            )
            nats_status = await session.read_until(
                private_message(bot),
                wait_seconds=COMMAND_TIMEOUT,
            )
            local_text = local_status.params[-1]
            if "peers=2" not in local_text or "channels=2" not in local_text:
                await asyncio.sleep(2.0)
                continue
            nats_fields = dict(
                field.split("=", 1) for field in nats_status.params[-1].split()[1:]
            )
            if (
                nats_fields.get("connection") == "up"
                and int(nats_fields.get("routes", "0")) >= 2
                and nats_fields.get("jetstream") == "up"
                and nats_fields.get("replicas") == "3/3"
            ):
                return
            await asyncio.sleep(2.0)


async def wait_for_reply(
    session: IRCSession,
    bot: str,
    command_text: str,
    expected: str,
) -> None:
    """Poll a bot command until replicated state produces the expected reply."""
    async with asyncio.timeout(STARTUP_TIMEOUT):
        while True:
            if await command(session, bot, command_text) == expected:
                return
            await asyncio.sleep(2.0)


if __name__ == "__main__":
    asyncio.run(run())
