# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Admin commands received as IRC private messages, and their rate limit."""

import asyncio
import logging
from collections import OrderedDict, deque
from dataclasses import asdict
from typing import TYPE_CHECKING

from botnats import error_label
from botnats.auth import limit_identity
from botnats.channel import ChannelRecord
from botnats.irc.protocol import MAX_IRC_MESSAGE_BYTES, format_message
from botnats.nats.store import PUBLISH_ERRORS
from botnats.validators import validate_channel, validate_key, validate_target

if TYPE_CHECKING:
    from botnats.bot import Bot
    from botnats.channel import ChannelRuntime
    from botnats.irc.protocol import Prefix

LOGGER = logging.getLogger(__name__)
MAX_RATE_BUCKETS = 8192


class CommandHandler:
    """Processes authenticated admin commands from IRC private messages."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot
        self.command_limiter = RateLimiter()
        self.handlers = {
            "BAN": self.cmd_ban,
            "GETBANS": self.cmd_getbans,
            "GETCHANS": self.cmd_getchans,
            "GETMODES": self.cmd_getmodes,
            "GETUSERS": self.cmd_getusers,
            "DEOP": self.cmd_deop,
            "INVITE": self.cmd_invite,
            "JOIN": self.cmd_join,
            "KICK": self.cmd_kick,
            "OP": self.cmd_op,
            "PART": self.cmd_part,
            "STATUS": self.cmd_status,
            "UNBAN": self.cmd_unban,
        }

    def allow(self, prefix: Prefix) -> bool:
        """Record one command from a sender and return whether it is within limits."""
        return self.command_limiter.check(limit_identity(prefix))

    async def reply(self, nickname: str, message: str) -> None:
        """Send a private message, dropping unsendable or undeliverable lines."""
        try:
            await self.bot.irc.send("PRIVMSG", nickname, trailing=message)
        except ConnectionError:
            pass
        except ValueError as error:
            LOGGER.warning("dropped PRIVMSG to %s: %s", nickname, error_label(error))

    async def reply_list(self, nickname: str, head: str, items: list[str]) -> None:
        """Reply with items after head, packed into as few lines as fit."""
        overhead = len(format_message("PRIVMSG", (nickname,), ""))
        limit = MAX_IRC_MESSAGE_BYTES - overhead
        current = head
        for item in items:
            candidate = f"{current} {item}"
            if len(candidate.encode()) > limit:
                await self.reply(nickname, current)
                current = f"{head} {item}"
            else:
                current = candidate

        await self.reply(nickname, current)

    async def channel_update(
        self,
        prefix: Prefix,
        channel: str,
        key: str | None,
        *,
        present: bool,
    ) -> None:
        """Publish a channel record update and apply it locally."""
        if present and self.bot.config.channel_modes:
            # Validation only: reject the join before the durable write when
            # the enforced MODE line cannot fit this channel name in 512 bytes.
            format_message(
                "MODE",
                (channel, self.bot.config.channel_modes),
                None,
            )

        current = self.bot.channel_mgr.channel_records.get(self.bot.caps.fold(channel))
        if present and key is None:
            runtime = self.bot.channel_mgr.runtime(channel)
            if runtime is not None:
                key = runtime.key

        record = self.bot.channel_mgr.new_record(
            channel,
            key,
            present=present,
            after=current.revision if current else None,
        )
        stored = await self.bot.coordinator.put_channel(
            channel,
            asdict(record),
            expected=self.bot.channel_mgr.durable_revision(channel),
        )
        authoritative = ChannelRecord.from_dict(stored)
        await self.bot.channel_mgr.apply_record(authoritative)
        if authoritative != record:
            await self.reply(prefix.nick, f"Update superseded for {channel}")
            return

        action = "Joining" if present else "Parting"
        await self.reply(prefix.nick, f"{action} {channel}")

    async def cmd_ban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Set a ban mask on a channel."""
        if len(arguments) != 2:
            msg = "BAN <channel> <mask>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        mask = validate_target(arguments[1])
        self.opped_channel(channel)
        await self.bot.irc.send("MODE", channel, "+b", mask)
        await self.reply(prefix.nick, f"Banned {mask} on {channel}")

    async def cmd_getbans(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List all tracked ban masks for a channel."""
        if len(arguments) != 1:
            msg = "GETBANS <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            await self.reply(prefix.nick, f"No record for {channel}")
        elif runtime.bans:
            for mask in sorted(runtime.bans.values()):
                await self.reply(prefix.nick, f"{channel} +b {mask}")
        else:
            await self.reply(prefix.nick, f"No bans tracked for {channel}")

    async def cmd_getmodes(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Display the tracked channel modes."""
        if len(arguments) != 1:
            msg = "GETMODES <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            await self.reply(prefix.nick, f"No record for {channel}")
        elif runtime.modes:
            limit = str(runtime.limit) if runtime.limit is not None else None
            values = {"k": runtime.key, "l": limit}
            # Mode arguments follow their letters' order, as in a MODE line.
            parts = [channel, runtime.modes]
            parts.extend(value for mode in runtime.modes if (value := values.get(mode)))
            await self.reply(prefix.nick, " ".join(parts))
        else:
            await self.reply(
                prefix.nick,
                f"No modes tracked for {channel}",
            )

    async def cmd_getusers(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List tracked members of a channel."""
        if len(arguments) != 1:
            msg = "GETUSERS <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            await self.reply(prefix.nick, f"No record for {channel}")
        elif runtime.members:
            nicks = sorted(
                (
                    f"@{m.nick}" if self.bot.caps.is_opped(m.modes) else m.nick
                    for m in runtime.members.values()
                ),
                key=lambda n: n.lstrip("@").casefold(),
            )
            await self.reply_list(prefix.nick, channel, nicks)
        else:
            await self.reply(
                prefix.nick,
                f"No users tracked for {channel}",
            )

    async def cmd_getchans(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List tracked channels: @ where this bot is opped, - where it is not in."""
        if arguments:
            msg = "GETCHANS takes no arguments"
            raise ValueError(msg)

        channel_mgr = self.bot.channel_mgr
        if not channel_mgr.channels:
            await self.reply(prefix.nick, "No channels tracked")
            return

        channels: list[str] = []
        for runtime in sorted(
            channel_mgr.channels.values(),
            key=lambda r: r.channel.casefold(),
        ):
            if not runtime.joined:
                channels.append(f"-{runtime.channel}")
            elif channel_mgr.is_self_opped(runtime):
                channels.append(f"@{runtime.channel}")
            else:
                channels.append(runtime.channel)

        await self.reply_list(prefix.nick, "Channels", channels)

    async def cmd_deop(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove operator status from a user on a channel."""
        if len(arguments) != 2:
            msg = "DEOP <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None or not self.bot.caps.is_opped(member.modes):
            await self.reply(
                prefix.nick,
                f"{target} is not opped on {channel}",
            )
            return

        operator_modes = self.bot.caps.operator_modes
        highest = next(
            index for index, mode in enumerate(operator_modes) if mode in member.modes
        )
        for mode in operator_modes[highest:]:
            await self.bot.irc.send("MODE", channel, f"-{mode}", member.nick)

        await self.reply(
            prefix.nick,
            f"Deopped {member.nick} on {channel}",
        )

    async def cmd_invite(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Invite a user to a channel."""
        if len(arguments) != 2:
            msg = "INVITE <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        self.opped_channel(channel)
        await self.bot.irc.send("INVITE", target, channel)
        await self.reply(prefix.nick, f"Invited {target} to {channel}")

    async def cmd_join(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Add a channel to the desired set and begin joining it."""
        if not 1 <= len(arguments) <= 2:
            msg = "JOIN <channel> [key]"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        key = validate_key(arguments[1]) if len(arguments) == 2 else None
        await self.channel_update(prefix, channel, key, present=True)

    async def cmd_kick(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Kick a user from a channel, with an optional reason."""
        if len(arguments) < 2:
            msg = "KICK <channel> <nick> [reason]"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None:
            await self.reply(prefix.nick, f"{target} not found on {channel}")
            return

        reason = " ".join(arguments[2:]) or None
        await self.bot.irc.send("KICK", channel, member.nick, trailing=reason)
        await self.reply(prefix.nick, f"Kicked {member.nick} from {channel}")

    async def cmd_op(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Grant operator status to a user on a channel."""
        if len(arguments) != 2:
            msg = "OP <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None or member.prefix is None or not member.prefix.complete:
            await self.reply(
                prefix.nick,
                f"{target} not found on {channel}",
            )
            return

        if self.bot.caps.is_opped(member.modes):
            await self.reply(
                prefix.nick,
                f"{member.nick} is already opped on {channel}",
            )
            return

        await self.bot.irc.send(
            "MODE",
            channel,
            f"+{self.bot.caps.op_mode}",
            member.nick,
        )
        await self.reply(
            prefix.nick,
            f"Opped {member.nick} on {channel}",
        )

    async def cmd_part(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove a channel from the desired set and leave it."""
        if len(arguments) != 1:
            msg = "PART <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        await self.channel_update(prefix, channel, None, present=False)

    async def cmd_status(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Report the bot's current connection and channel status."""
        if arguments:
            msg = "STATUS takes no arguments"
            raise ValueError(msg)

        joined = sum(
            runtime.joined for runtime in self.bot.channel_mgr.channels.values()
        )
        own_id = self.bot.config.bot_id.casefold()
        peers = sum(
            peer.bot_id.casefold() != own_id for peer in self.bot.presence.active()
        )
        await self.reply(
            prefix.nick,
            f"bot id={self.bot.config.bot_id} nick={self.bot.irc.current_nick} "
            f"peers={peers} channels={joined}",
        )
        status = await self.bot.coordinator.status()
        await self.reply(prefix.nick, status.render())

    async def cmd_unban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove a ban mask from a channel."""
        if len(arguments) != 2:
            msg = "UNBAN <channel> <mask>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        mask = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        stored = runtime.bans.get(self.bot.caps.fold(mask))
        if stored is None:
            await self.reply(
                prefix.nick,
                f"No matching ban for {mask} on {channel}",
            )
            return

        await self.bot.irc.send("MODE", channel, "-b", stored)
        await self.reply(prefix.nick, f"Unbanned {stored} on {channel}")

    async def dispatch(self, prefix: Prefix, text: str) -> None:
        """Route an incoming private message to the appropriate command handler."""
        try:
            name, arguments = parse_command(text)
        except ValueError as error:
            # Unauthenticated senders get silence, not a parse-error reply
            # that would confirm a bot is listening.
            rendered = prefix.render()
            if self.bot.authorizer.authorized(rendered):
                await self.reply(
                    prefix.nick,
                    str(error) or "Command failed",
                )

            return

        if name == "AUTH":
            await self.bot.auth_flow.authenticate(prefix, arguments)
            return

        rendered = prefix.render()
        if not self.bot.authorizer.authorized(rendered):
            return

        handler = self.handlers.get(name)
        if handler is None:
            await self.reply(prefix.nick, "Unknown command")
            return

        try:
            await handler(prefix, arguments)
        except (*PUBLISH_ERRORS, ValueError) as error:
            await self.reply(prefix.nick, str(error) or "Command failed")

    def opped_channel(self, channel: str) -> ChannelRuntime:
        """Return a tracked channel where this bot has operator status."""
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None or not self.bot.channel_mgr.is_self_opped(runtime):
            msg = f"Not opped on {channel}"
            raise ValueError(msg)

        return runtime


class RateLimiter:
    """Sliding-window rate limiter keyed by identity string."""

    def __init__(self, *, limit: int = 8, window: float = 10.0) -> None:
        self.buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self.limit = limit
        self.window = window

    def check(self, key: str) -> bool:
        """Record an event and return whether the key is within its rate limit."""
        now = asyncio.get_running_loop().time()
        cutoff = now - self.window
        bucket = self.buckets.get(key)
        if bucket is None:
            if len(self.buckets) >= MAX_RATE_BUCKETS and not self.evict_stale(cutoff):
                # Fail closed: evicting a fresh bucket would let identity
                # churn reset an actively limited key's budget.
                return False

            bucket = deque()
            self.buckets[key] = bucket
        else:
            self.buckets.move_to_end(key)

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.limit:
            return False

        bucket.append(now)
        return True

    def evict_stale(self, cutoff: float) -> bool:
        """Evict the least-recently-used bucket only if it has fully expired."""
        key, bucket = next(iter(self.buckets.items()))
        if bucket and bucket[-1] > cutoff:
            return False

        del self.buckets[key]
        return True


def parse_command(value: str) -> tuple[str, tuple[str, ...]]:
    """Split raw text into a command name and arguments."""
    words = value.split()
    if not words:
        msg = "empty command"
        raise ValueError(msg)

    return words[0].upper(), tuple(words[1:])
