# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Admin commands received as IRC private messages, and their rate limit."""

import asyncio
import logging
from collections import OrderedDict, deque
from functools import partial
from typing import TYPE_CHECKING

from botnats import error_label
from botnats.auth import limit_identity
from botnats.irc.protocol import MAX_IRC_MESSAGE_BYTES, format_message
from botnats.nats.store import PUBLISH_ERRORS
from botnats.validators import validate_channel, validate_key

if TYPE_CHECKING:
    from botnats.bot import Bot
    from botnats.channel import ChannelMember, ChannelRuntime
    from botnats.irc.protocol import Prefix

LOGGER = logging.getLogger(__name__)
MAX_RATE_BUCKETS = 8192
# Room for the ":nick!user@host " source a server puts in front of each line
# it relays, which counts toward the recipient's 512-byte limit.
RELAY_SOURCE_BYTES = 128


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

    def holds(self, prefix: Prefix) -> bool:
        """Return whether a command's sender still holds its session and nick.

        Replies go by nick. An IRC disconnect revokes nothing, but this bot
        sees no QUIT or NICK while away, so it no longer vouches for a sender
        whose command it received before.
        """
        rendered = prefix.render()
        if not self.bot.authorizer.authorized(rendered):
            return False

        return self.bot.sessions.watched_valid(rendered)

    def reply(self, prefix: Prefix, message: str, *, checked: bool = True) -> None:
        """Send a private message, dropping unsendable or undeliverable lines.

        A checked line goes out only if the sender's session still holds when
        its turn in the send queue comes: flood pacing can hold it for
        minutes, while the session ends and its nick passes to another user.
        """
        check = partial(self.bot.authorizer.authorized, prefix.render())
        try:
            self.bot.irc.send(
                "PRIVMSG",
                prefix.nick,
                trailing=message,
                check=check if checked else None,
            )
        except ConnectionError:
            pass
        except ValueError as error:
            LOGGER.warning("dropped PRIVMSG to %s: %s", prefix.nick, error_label(error))

    def reply_list(self, prefix: Prefix, head: str, items: list[str]) -> None:
        """Reply with items after head, packed into as few lines as fit."""
        overhead = len(format_message("PRIVMSG", (prefix.nick,), ""))
        limit = MAX_IRC_MESSAGE_BYTES - RELAY_SOURCE_BYTES - overhead
        current = head
        for item in items:
            # An item too long for any line would be cut off in relay.
            if len(f"{head} {item}".encode()) > limit:
                LOGGER.warning(
                    "dropped a list item too long to send to %s", prefix.nick
                )
                continue

            candidate = f"{current} {item}"
            if len(candidate.encode()) > limit:
                self.reply(prefix, current)
                current = f"{head} {item}"
            else:
                current = candidate

        # A header alone is never sent.
        if current != head:
            self.reply(prefix, current)

    async def channel_update(
        self,
        prefix: Prefix,
        channel: str,
        key: str | None,
        *,
        present: bool,
    ) -> None:
        """Publish a channel record update and apply it locally."""
        channellen = self.bot.caps.channellen
        # Past the limit a server refuses the JOIN, or truncates the name to
        # another channel. Servers count the bytes this bot sends as UTF-8.
        if present and channellen is not None and len(channel.encode()) > channellen:
            msg = f"channel name exceeds the server limit of {channellen} bytes"
            raise ValueError(msg)

        if present and self.bot.config.channel_modes:
            # Validation only: reject the join before the durable write when
            # the enforced MODE line cannot fit this channel name in 512 bytes.
            format_message(
                "MODE",
                (channel, self.bot.config.channel_modes),
                None,
            )

        # Take turns with this bot's key writes: one still in flight would
        # beat this write's compare-and-set. The key is read at the turn, or
        # the write could put back a key one of them replaced.
        async with self.bot.channel_mgr.write_lock:
            if present and key is None:
                runtime = self.bot.channel_mgr.runtime(channel)
                if runtime is not None:
                    key = runtime.key

            won = await self.bot.channel_mgr.write_record(channel, key, present=present)

        # The session may have ended during the write, and its nick passed to
        # another user: reply only while it still holds.
        if not self.holds(prefix):
            return

        if not won:
            self.reply(prefix, f"Update superseded for {channel}")
            return

        action = "Joining" if present else "Parting"
        self.reply(prefix, f"{action} {channel}")

    async def cmd_ban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Set a ban mask on a channel."""
        if len(arguments) != 2:
            msg = "BAN <channel> <mask>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        mask = arguments[1]
        self.opped_channel(channel)
        self.bot.irc.send("MODE", channel, "+b", mask)
        self.reply(prefix, f"Banned {mask} on {channel}")

    async def cmd_getbans(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List all tracked ban masks for a channel."""
        if len(arguments) != 1:
            msg = "GETBANS <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            self.reply(prefix, f"No record for {channel}")
        elif runtime.bans:
            # Packed like the other lists: one line per ban could fill the
            # outbound queue and crowd out the bot's own commands.
            self.reply_list(prefix, f"{channel} +b", sorted(runtime.bans.values()))
        else:
            self.reply(prefix, f"No bans tracked for {channel}")

    async def cmd_getmodes(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Display the tracked channel modes."""
        if len(arguments) != 1:
            msg = "GETMODES <channel>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            self.reply(prefix, f"No record for {channel}")
        elif runtime.modes:
            # "*" holds the place of an unknown value, such as a key IRC hid
            # or the argument of a mode this bot does not track.
            limit = str(runtime.limit) if runtime.limit is not None else "*"
            values = {"k": runtime.key or "*", "l": limit}
            # Mode arguments follow their letters' order, as in a MODE line:
            # one for each letter CHANMODES gives an argument when set.
            chanmodes = self.bot.caps.chanmodes
            parts = [channel, runtime.modes]
            parts.extend(
                values.get(mode, "*")
                for mode in runtime.modes
                if mode in chanmodes[1] + chanmodes[2]
            )
            self.reply(prefix, " ".join(parts))
        else:
            self.reply(
                prefix,
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
            self.reply(prefix, f"No record for {channel}")
        elif runtime.members:
            nicks = sorted(
                (
                    f"@{m.nick}" if self.bot.caps.is_opped(m.modes) else m.nick
                    for m in runtime.members.values()
                ),
                key=lambda n: n.lstrip("@").casefold(),
            )
            self.reply_list(prefix, channel, nicks)
        else:
            self.reply(
                prefix,
                f"No users tracked for {channel}",
            )

    async def cmd_getchans(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List tracked channels: @ where this bot is opped, - where it is not in."""
        if arguments:
            msg = "GETCHANS takes no arguments"
            raise ValueError(msg)

        channel_mgr = self.bot.channel_mgr
        if not channel_mgr.channels:
            self.reply(prefix, "No channels tracked")
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

        self.reply_list(prefix, "Channels", channels)

    async def cmd_deop(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove operator status from a user on a channel."""
        if len(arguments) != 2:
            msg = "DEOP <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = arguments[1]
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None or not self.bot.caps.is_opped(member.modes):
            self.reply(
                prefix,
                f"{target} is not opped on {channel}",
            )
            return

        operator_modes = self.bot.caps.operator_modes
        highest = next(
            index for index, mode in enumerate(operator_modes) if mode in member.modes
        )
        check = partial(self.target_holds, channel, member.nick, member)
        for mode in operator_modes[highest:]:
            self.bot.irc.send("MODE", channel, f"-{mode}", member.nick, check=check)

        self.reply(
            prefix,
            f"Deopped {member.nick} on {channel}",
        )

    async def cmd_invite(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Invite a user to a channel."""
        if len(arguments) != 2:
            msg = "INVITE <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = arguments[1]
        self.opped_channel(channel)
        self.bot.irc.send("INVITE", target, channel)
        self.reply(prefix, f"Invited {target} to {channel}")

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
        target = arguments[1]
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None:
            self.reply(prefix, f"{target} not found on {channel}")
            return

        reason = " ".join(arguments[2:]) or None
        self.bot.irc.send(
            "KICK",
            channel,
            member.nick,
            trailing=reason,
            check=partial(self.target_holds, channel, member.nick, member),
        )
        self.reply(prefix, f"Kicked {member.nick} from {channel}")

    async def cmd_op(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Grant operator status to a user on a channel."""
        if len(arguments) != 2:
            msg = "OP <channel> <nick>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        target = arguments[1]
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.caps.fold(target))
        if member is None:
            self.reply(
                prefix,
                f"{target} not found on {channel}",
            )
            return

        if self.bot.caps.is_opped(member.modes):
            self.reply(
                prefix,
                f"{member.nick} is already opped on {channel}",
            )
            return

        self.bot.irc.send(
            "MODE",
            channel,
            f"+{self.bot.caps.op_mode}",
            member.nick,
            check=partial(self.target_holds, channel, member.nick, member),
        )
        self.reply(
            prefix,
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
        peers = len(self.bot.presence.peers(self.bot.config.bot_id))
        self.reply(
            prefix,
            f"bot id={self.bot.config.bot_id} nick={self.bot.irc.current_nick} "
            f"peers={peers} channels={joined}",
        )
        status = await self.bot.coordinator.status()
        # The session may have ended while NATS answered.
        if self.holds(prefix):
            self.reply(prefix, status.render())

    async def cmd_unban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove a ban mask from a channel."""
        if len(arguments) != 2:
            msg = "UNBAN <channel> <mask>"
            raise ValueError(msg)

        channel = validate_channel(arguments[0])
        mask = arguments[1]
        runtime = self.opped_channel(channel)
        stored = runtime.bans.get(self.bot.caps.fold(mask))
        if stored is None:
            self.reply(
                prefix,
                f"No matching ban for {mask} on {channel}",
            )
            return

        self.bot.irc.send("MODE", channel, "-b", stored)
        self.reply(prefix, f"Unbanned {stored} on {channel}")

    async def dispatch(self, prefix: Prefix, text: str) -> None:
        """Route an incoming private message to the appropriate command handler."""
        try:
            name, arguments = parse_command(text)
        except ValueError as error:
            # Unauthenticated senders get silence, not a parse-error reply
            # that would confirm a bot is listening.
            if self.holds(prefix):
                self.reply(prefix, str(error))

            return

        if name == "AUTH":
            await self.bot.auth_flow.authenticate(prefix, arguments)
            return

        if not self.holds(prefix):
            return

        handler = self.handlers.get(name)
        if handler is None:
            self.reply(prefix, "Unknown command")
            return

        try:
            await handler(prefix, arguments)
        except (*PUBLISH_ERRORS, ValueError) as error:
            # A handler may fail after an await that outlived the session.
            if self.holds(prefix):
                self.reply(prefix, str(error) or "Command failed")

    def opped_channel(self, channel: str) -> ChannelRuntime:
        """Return a tracked channel where this bot has operator status."""
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None or not self.bot.channel_mgr.is_self_opped(runtime):
            msg = f"Not opped on {channel}"
            raise ValueError(msg)

        return runtime

    def target_holds(self, channel: str, nick: str, member: ChannelMember) -> bool:
        """Return whether a member still holds, in a channel, the nick a line names.

        An OP, DEOP, or KICK line goes out only if this holds when its turn in
        the send queue comes: flood pacing can hold it for minutes, while the
        target leaves or renames and another user takes the nick. A member
        lasts while its user stays, so a newcomer's is another. The nick is
        passed on its own, since a rename changes the member's.
        """
        runtime = self.bot.channel_mgr.runtime(channel)
        return (
            runtime is not None
            and runtime.members.get(self.bot.caps.fold(nick)) is member
        )


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
        if bucket[-1] > cutoff:
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
