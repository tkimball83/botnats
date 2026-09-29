# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC event routing, coordination triggers, and capability tracking."""

import asyncio
import logging
from contextlib import suppress
from typing import TYPE_CHECKING

from botnats.channel import JoinState
from botnats.irc.client import DEFAULT_NICK_LENGTH
from botnats.irc.protocol import (
    DEFAULT_CASEMAPPING,
    DEFAULT_CHANMODES,
    DEFAULT_MEMBER_PREFIXES,
    DEFAULT_MEMBERSHIP_MODES,
    IRCMessage,
    Prefix,
    iter_mode_changes,
    mask_matches,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from botnats.bot import Bot
    from botnats.channel import ChannelRuntime

ISON_POLL_INTERVAL = 5.0
LOGGER = logging.getLogger(__name__)


class IRCEventHandler:
    """Routes incoming IRC messages and reacts to coordination-relevant events."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot
        self.command_lock = asyncio.Lock()
        self.nick_watch_task: asyncio.Task[None] | None = None
        self.handlers: dict[str, Callable[[IRCMessage], Awaitable[None]]] = {
            "001": self.handle_welcome,
            "005": self.handle_isupport,
            "302": self.handle_userhost,
            "303": self.handle_ison_reply,
            "324": self.handle_channel_modes,
            "352": self.handle_who,
            "353": self.handle_names,
            "366": self.handle_end_of_names,
            "367": self.handle_ban_list,
            "471": self.handle_channel_full,
            "473": self.handle_invite_only,
            "474": self.handle_banned,
            "475": self.handle_join_refused,
            "731": self.handle_monitor_offline,
            "CHGHOST": self.handle_chghost,
            "INVITE": self.handle_invite,
            "JOIN": self.handle_join,
            "KICK": self.handle_kick,
            "MODE": self.handle_mode,
            "NICK": self.handle_nick,
            "PART": self.handle_part,
            "PRIVMSG": self.queue_command,
            "QUIT": self.handle_quit,
        }

    def apply_mode_changes(
        self,
        runtime: ChannelRuntime,
        channel: str,
        modes: str,
        arguments: tuple[str, ...],
    ) -> tuple[bool, bool]:
        """Apply individual mode changes and return enforcement flags."""
        lost_enforced = False
        saw_new_op = False
        channel_modes = (
            self.bot.caps.chanmodes[1]
            + self.bot.caps.chanmodes[2]
            + self.bot.caps.chanmodes[3]
        )
        enforced_set, enforced_unset = self.bot.channel_mgr.mode_intent
        for adding, mode, argument in iter_mode_changes(
            modes,
            arguments,
            self.bot.caps.chanmodes,
            self.bot.caps.membership_modes,
        ):
            if (not adding and mode in enforced_set) or (
                adding and mode in enforced_unset
            ):
                lost_enforced = True

            if mode in channel_modes:
                self.update_channel_modes(runtime, mode, adding=adding)

            if mode in "kl":
                self.process_setting(runtime, channel, mode, argument, adding=adding)
                continue

            if argument is None:
                continue

            if mode == "b":
                self.process_ban(runtime, channel, argument, adding=adding)
            elif mode in self.bot.caps.operator_modes:
                self.process_op(runtime, mode, argument, adding=adding)
                if adding:
                    saw_new_op = True

        return lost_enforced, saw_new_op

    def process_setting(
        self,
        runtime: ChannelRuntime,
        channel: str,
        mode: str,
        argument: str | None,
        *,
        adding: bool,
    ) -> None:
        """Track the channel key or member limit from one mode change."""
        if mode == "l":
            runtime.set_limit(argument if adding else None)
        elif argument is not None:
            self.process_key(runtime, channel, argument, adding=adding)
        elif not adding and runtime.key is not None:
            self.process_key(runtime, channel, "", adding=False)

    async def handle_ban_list(self, message: IRCMessage) -> None:
        """Record a ban mask from the channel ban list reply."""
        if len(message.params) < 3:
            return

        channel = message.params[1]
        mask = message.params[2]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is not None:
            runtime.add_ban(mask)

    async def handle_channel_modes(self, message: IRCMessage) -> None:
        """Take the modes, limit, and key from an RPL_CHANNELMODEIS reply.

        The reply is the channel's full state, so a key it lacks is gone and
        a key it shows replaces the stored one; a hidden key changes nothing.
        """
        if len(message.params) < 3:
            return

        channel = message.params[1]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return

        runtime.modes = message.params[2]
        runtime.set_limit(None)
        key: str | None = None
        for adding, mode, argument in iter_mode_changes(
            message.params[2],
            message.params[3:],
            self.bot.caps.chanmodes,
            self.bot.caps.membership_modes,
        ):
            if adding and mode == "l":
                runtime.set_limit(argument)
            elif adding and mode == "k":
                # ircu shows other members "*" in place of the key.
                key = argument or "*"

        if key not in ("*", runtime.key):
            self.process_key(runtime, channel, key or "", adding=key is not None)

    def log_join_error(self, message: IRCMessage) -> None:
        """Log, once, an unhandled error naming a channel this bot is joining.

        Refusals such as 477 (registered nicks only) vary by server; the JOIN
        stays pending and is resent after JOIN_REPLY_TIMEOUT.
        """
        if len(message.params) < 3:
            return

        runtime = self.bot.channel_mgr.runtime(message.params[1])
        if (
            runtime is None
            or runtime.join is not JoinState.JOINING
            or runtime.join_error == message.command
        ):
            return

        runtime.join_error = message.command
        LOGGER.warning(
            "cannot join %s: %s %s",
            runtime.channel,
            message.command,
            message.params[-1],
        )

    def join_refused(self, channel: str) -> None:
        """Return a refused JOIN to idle so the next tick tries again."""
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is not None:
            runtime.refuse_join()

    async def handle_banned(self, message: IRCMessage) -> None:
        """Request an unban when the bot is banned from a channel."""
        if len(message.params) >= 2:
            self.join_refused(message.params[1])
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("unban", message.params[1]),
                "banned-unban-request",
            )

    async def handle_chghost(self, message: IRCMessage) -> None:
        """Revoke authorization and update member state after a host change."""
        if message.prefix is None or len(message.params) < 2:
            return

        nick = message.prefix.nick
        new_user = message.params[0]
        new_host = message.params[1]
        new_prefix = Prefix(nick, new_user, new_host)
        folded = self.bot.caps.fold(nick)
        old_prefix = self.bot.channel_mgr.change_member_host(message.prefix, new_prefix)
        if old_prefix.complete:
            self.bot.sessions.revoke(old_prefix)
        else:
            LOGGER.debug(
                "CHGHOST for %s carried no complete identity; nothing to revoke",
                nick,
            )

        identity = self.bot.identity.current
        if identity is not None and folded == self.bot.caps.fold(identity.nick):
            await self.set_identity(new_prefix)

    async def set_identity(self, prefix: Prefix) -> None:
        """Record this bot's identity; announce it and join once it changes.

        The presence write runs in background: the IRC read loop must not wait
        on JetStream.
        """
        if self.bot.identity.set(prefix):
            self.bot.tasks.spawn(self.bot.identity.announce(), "presence-announce")
            await self.bot.channel_mgr.join_desired()

    async def queue_command(self, message: IRCMessage) -> None:
        """Run a private-message command in background, in arrival order.

        AUTH and the durable JOIN/PART commands wait on JetStream; the IRC
        read loop must not. The FIFO lock keeps an admin's commands in order.
        """
        prefix = message.prefix
        # Channel chatter, CTCP, anonymous senders, and senders over their
        # rate limit are not commands: skip them before queueing anything, so
        # a flood cannot grow the queue.
        if (
            prefix is None
            or not prefix.complete
            or len(message.params) < 2
            or not self.bot.irc.is_self(message.params[0])
            or message.params[-1].startswith("\x01")
            or not self.bot.commands.allow(prefix)
        ):
            return
        # Watched from arrival, in read-loop order: a QUIT that follows this
        # message invalidates an AUTH still waiting behind earlier commands.
        self.bot.sessions.watch_identity(prefix.render())
        self.bot.tasks.spawn(
            self.run_command(prefix, message.params[-1]), "admin-command"
        )

    async def run_command(self, prefix: Prefix, text: str) -> None:
        """Handle one queued command after every command queued before it."""
        try:
            async with self.command_lock:
                await self.bot.commands.dispatch(prefix, text)
        finally:
            self.bot.sessions.unwatch_identity(prefix.render())

    async def handle_end_of_names(self, message: IRCMessage) -> None:
        """Finalize channel join by requesting WHO data and enforcing modes."""
        if len(message.params) < 2:
            return

        channel = message.params[1]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return

        with suppress(ConnectionError):
            await self.bot.irc.send("WHO", channel)

        with suppress(ConnectionError):
            await self.bot.irc.send("MODE", channel)

        with suppress(ConnectionError):
            await self.bot.irc.send("MODE", channel, "+b")

        if self.bot.channel_mgr.is_self_opped(runtime):
            self.bot.tasks.spawn(
                self.bot.channel_mgr.enforce_modes(channel),
                "names-enforce-modes",
            )
        else:
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("op", channel),
                "names-op-request",
            )

    async def handle_invite(self, message: IRCMessage) -> None:
        """Join a configured channel when invited."""
        if len(message.params) < 2:
            return

        target, channel = message.params[0], message.params[1]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is not None and not runtime.joined and self.bot.irc.is_self(target):
            await self.bot.channel_mgr.safe_join(runtime)

    async def handle_ison_reply(self, message: IRCMessage) -> None:
        """Reclaim the desired nickname when ISON reports it offline."""
        if not message.params:
            return

        nicks = message.params[-1].split()
        desired = self.bot.irc.desired_nick
        folded = self.bot.caps.fold(desired)
        for nick in nicks:
            if self.bot.caps.fold(nick) == folded:
                return

        await self.try_nick_reclaim()

    async def handle_monitor_offline(self, message: IRCMessage) -> None:
        """Reclaim the desired nickname when MONITOR reports it offline."""
        if not message.params:
            return

        targets = message.params[-1].split(",")
        desired = self.bot.irc.desired_nick
        folded = self.bot.caps.fold(desired)
        for target in targets:
            nick = target.partition("!")[0]
            if self.bot.caps.fold(nick) == folded:
                await self.try_nick_reclaim()
                return

    async def try_nick_reclaim(self) -> None:
        """Send a NICK command to reclaim the desired nickname."""
        desired = self.bot.irc.desired_nick
        if self.bot.caps.fold(self.bot.irc.current_nick) == self.bot.caps.fold(desired):
            return

        with suppress(ConnectionError):
            await self.bot.irc.send("NICK", desired)

    def start_nick_watch(self) -> None:
        """Begin watching for the desired nickname to become available."""
        self.stop_nick_watch()
        if self.bot.caps.fold(self.bot.irc.current_nick) == self.bot.caps.fold(
            self.bot.irc.desired_nick,
        ):
            return

        if self.bot.caps.monitor:
            self.bot.tasks.spawn(self.monitor_nick(), "nick-monitor")
        else:
            self.nick_watch_task = self.bot.tasks.spawn(
                self.ison_poll_loop(),
                "nick-ison-poll",
            )

    def stop_nick_watch(self) -> None:
        """Cancel any running nickname watch."""
        task = self.nick_watch_task
        self.nick_watch_task = None
        if task is not None:
            task.cancel()

    async def stop_nick_watch_async(self) -> None:
        """Cancel the nickname watch and unsubscribe from MONITOR."""
        self.stop_nick_watch()
        if self.bot.caps.monitor:
            with suppress(ConnectionError):
                await self.bot.irc.send(
                    "MONITOR",
                    "-",
                    self.bot.irc.desired_nick,
                )

    async def monitor_nick(self) -> None:
        """Subscribe to MONITOR notifications for the desired nickname."""
        await self.bot.irc.send(
            "MONITOR",
            "+",
            self.bot.irc.desired_nick,
        )

    async def ison_poll_loop(self) -> None:
        """Poll ISON at a fixed interval until the desired nickname is free."""
        while True:
            await asyncio.sleep(ISON_POLL_INTERVAL)
            if self.bot.caps.fold(self.bot.irc.current_nick) == self.bot.caps.fold(
                self.bot.irc.desired_nick,
            ):
                return

            with suppress(ConnectionError):
                await self.bot.irc.send("ISON", self.bot.irc.desired_nick)

    def forget_isupport(self, name: str) -> None:
        """Restore default behavior for a removed ISUPPORT parameter."""
        match name.upper():
            case "CASEMAPPING":
                self.bot.channel_mgr.set_casemapping(DEFAULT_CASEMAPPING)
            case "CHANMODES":
                self.bot.caps.chanmodes = DEFAULT_CHANMODES
            case "MONITOR":
                self.bot.caps.monitor = False
            case "NICKLEN":
                self.bot.irc.set_nickname_length(DEFAULT_NICK_LENGTH)
            case "PREFIX":
                self.bot.caps.member_prefixes = dict(DEFAULT_MEMBER_PREFIXES)
                self.bot.caps.membership_modes = DEFAULT_MEMBERSHIP_MODES
                self.bot.caps.op_mode = "o"

    def apply_isupport(self, name: str, value: str) -> None:
        """Apply a single ISUPPORT name=value token."""
        match name.upper():
            case "CASEMAPPING":
                self.bot.channel_mgr.set_casemapping(value.lower())
            case "CHANMODES":
                self.bot.caps.parse_chanmodes(value)
            case "MONITOR":
                # The value is only a target limit, and this bot monitors one.
                self.bot.caps.monitor = True
                self.start_nick_watch()
            case "NICKLEN":
                with suppress(ValueError):
                    self.bot.irc.set_nickname_length(int(value))

            case "PREFIX":
                self.bot.caps.parse_prefix(value)

    async def handle_isupport(self, message: IRCMessage) -> None:
        """Parse RPL_ISUPPORT tokens into server capability state."""
        tokens = message.params[1:]
        if tokens and " " in tokens[-1]:
            tokens = tokens[:-1]

        for token in tokens:
            # "TOKEN" and "TOKEN=" are equivalent: an empty value.
            name, _, value = token.partition("=")
            if name.startswith("-"):
                self.forget_isupport(name[1:])
            else:
                self.apply_isupport(name, value)

    async def handle_join(self, message: IRCMessage) -> None:
        """Process a JOIN event, initializing channel state for self-joins."""
        if message.prefix is None or not message.params:
            return

        channel = message.params[0]
        runtime = self.bot.channel_mgr.runtime(channel)
        is_self = self.bot.irc.is_self(message.prefix.nick)
        if runtime is None:
            if is_self:
                try:
                    await self.bot.irc.send("PART", channel)
                except ConnectionError:
                    mgr = self.bot.channel_mgr
                    mgr.pending_parts[self.bot.caps.fold(channel)] = channel

            return

        if is_self:
            runtime.reset()
            runtime.join = JoinState.JOINED
            runtime.member(message.prefix.nick).prefix = message.prefix
            if message.prefix.complete:
                await self.set_identity(message.prefix)

            LOGGER.info("joined %s", channel)
        else:
            runtime.member(message.prefix.nick).prefix = message.prefix

    async def handle_invite_only(self, message: IRCMessage) -> None:
        """Request a peer invite when an invite-only channel refuses a JOIN."""
        if len(message.params) >= 2:
            self.join_refused(message.params[1])
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("invite", message.params[1]),
                "invite-request",
            )

    async def handle_channel_full(self, message: IRCMessage) -> None:
        """Ask peers to raise the limit of a channel too full to join."""
        if len(message.params) >= 2:
            self.join_refused(message.params[1])
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("limit", message.params[1]),
                "limit-request",
            )

    async def handle_join_refused(self, message: IRCMessage) -> None:
        """Retry a JOIN refused for a bad key.

        An invite does not get past +k, so none is requested; the next attempt
        uses the stored key, which peers in the channel keep current.
        """
        if len(message.params) >= 2:
            self.join_refused(message.params[1])

    async def handle_kick(self, message: IRCMessage) -> None:
        """Handle a KICK by removing the target or requesting an unban for self."""
        if len(message.params) < 2:
            return

        channel = message.params[0]
        target = message.params[1]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return

        if self.bot.irc.is_self(target):
            runtime.reset()
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("unban", channel),
                "kick-unban-request",
            )
        else:
            runtime.remove(target)

    async def handle_mode(self, message: IRCMessage) -> None:
        """Apply channel MODE changes and trigger enforcement or op requests."""
        if len(message.params) < 2:
            return

        channel = message.params[0]
        modes = message.params[1]
        arguments = message.params[2:]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return

        was_opped = self.bot.channel_mgr.is_self_opped(runtime)
        lost_enforced, saw_new_op = self.apply_mode_changes(
            runtime,
            channel,
            modes,
            arguments,
        )
        opped = self.bot.channel_mgr.is_self_opped(runtime)
        if opped and not was_opped:
            # Operators see the key that ircu hides from other members.
            with suppress(ConnectionError):
                await self.bot.irc.send("MODE", channel)

        if opped and (lost_enforced or not was_opped):
            self.bot.tasks.spawn(
                self.bot.channel_mgr.enforce_modes(channel),
                "enforce-modes",
            )
        elif not opped and (saw_new_op or was_opped):
            self.bot.tasks.spawn(
                self.bot.channel_mgr.request_peer("op", channel),
                "op-request",
            )

    async def handle_names(self, message: IRCMessage) -> None:
        """Parse NAMES reply entries and update member mode prefixes."""
        if len(message.params) < 4:
            return

        channel = message.params[-2]
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return
        # A prefix symbol not yet advertised via ISUPPORT stays attached to
        # the nick and creates a phantom member; the WHO that follows
        # end-of-names replaces it with the correctly keyed record.
        for decorated_nick in message.params[-1].split():
            modes: set[str] = set()
            nick = decorated_nick
            while nick and nick[0] in self.bot.caps.member_prefixes:
                mode = self.bot.caps.member_prefixes[nick[0]]
                if mode in self.bot.caps.operator_modes:
                    modes.add(mode)

                nick = nick[1:]

            if nick:
                runtime.member(nick).modes = modes

    async def handle_nick(self, message: IRCMessage) -> None:
        """Update member records and bot identity when a nick changes."""
        if message.prefix is None or not message.params:
            return

        old_nick = message.prefix.nick
        new_nick = message.params[-1]
        old_folded = self.bot.caps.fold(old_nick)
        old_prefix = self.bot.channel_mgr.rename_member(message.prefix, new_nick)
        new_prefix = Prefix(new_nick, old_prefix.user, old_prefix.host)
        # A new nick is a new identity: it must authenticate again.
        if old_prefix.complete:
            self.bot.sessions.revoke(old_prefix)

        identity = self.bot.identity.current
        if identity is not None and old_folded == self.bot.caps.fold(identity.nick):
            await self.set_identity(
                Prefix(
                    new_nick,
                    new_prefix.user or identity.user or None,
                    new_prefix.host or identity.host or None,
                ),
            )

        if self.bot.irc.is_self(new_nick):
            if self.bot.caps.fold(new_nick) == self.bot.caps.fold(
                self.bot.irc.desired_nick
            ):
                await self.stop_nick_watch_async()
            elif self.bot.identity.registered:
                self.start_nick_watch()

    async def handle_part(self, message: IRCMessage) -> None:
        """Remove a member on PART or reset channel state for self-parts."""
        if message.prefix is None or not message.params:
            return

        runtime = self.bot.channel_mgr.runtime(message.params[0])
        if runtime is None:
            return

        if self.bot.irc.is_self(message.prefix.nick):
            runtime.reset()
        else:
            runtime.remove(message.prefix.nick)

    async def handle_quit(self, message: IRCMessage) -> None:
        """Remove a user and revoke its session on QUIT."""
        if message.prefix is None:
            return

        self.bot.channel_mgr.forget_member(message.prefix.nick)
        if message.prefix.complete:
            self.bot.sessions.revoke(message.prefix)

    async def handle_userhost(self, message: IRCMessage) -> None:
        """Extract the bot's user and host from a USERHOST reply."""
        if not message.params:
            return

        for entry in message.params[-1].split():
            nickname, separator, userhost = entry.partition("=")
            if not separator:
                continue

            userhost = userhost.lstrip("+-")
            user, at, host = userhost.partition("@")
            if at and self.bot.irc.is_self(nickname.rstrip("*")):
                await self.set_identity(
                    Prefix(self.bot.irc.current_nick, user, host),
                )
                return

    async def handle_welcome(self, message: IRCMessage) -> None:
        """Notify the bot that IRC registration is complete."""
        LOGGER.debug("received welcome: %s", " ".join(message.params))
        self.bot.identity.on_registered()
        self.bot.tasks.spawn(
            self.bot.identity.discover(self.bot.identity.generation),
            "identity-discovery",
        )
        self.bot.channel_mgr.reset()
        self.start_nick_watch()

    async def handle_who(self, message: IRCMessage) -> None:
        """Update member identity and modes from a WHO reply entry."""
        if len(message.params) < 8:
            return

        channel, user, host, nick, flags = (
            message.params[1],
            message.params[2],
            message.params[3],
            message.params[5],
            message.params[6],
        )
        runtime = self.bot.channel_mgr.runtime(channel)
        if runtime is None:
            return

        member = runtime.member(nick)
        member.prefix = Prefix(nick, user, host)
        member.modes = {
            mode
            for prefix, mode in self.bot.caps.member_prefixes.items()
            if prefix in flags and mode in self.bot.caps.operator_modes
        }
        if self.bot.irc.is_self(nick):
            await self.set_identity(member.prefix)

    async def on_irc_message(self, message: IRCMessage) -> None:
        """Route an IRC message to its registered handler."""
        if handler := self.handlers.get(message.command):
            await handler(message)
        elif message.command.isdigit() and message.command[0] in "45":
            self.log_join_error(message)

    def process_ban(
        self,
        runtime: ChannelRuntime,
        channel: str,
        mask: str,
        *,
        adding: bool,
    ) -> None:
        """Add or remove a ban mask and request unban when the bot is affected."""
        if adding:
            runtime.add_ban(mask)
            identity = self.bot.identity.current
            if identity is not None and mask_matches(
                mask,
                identity.to_prefix(),
                self.bot.caps.casemapping,
            ):
                self.bot.tasks.spawn(
                    self.bot.channel_mgr.request_peer("unban", channel),
                    "ban-unban-request",
                )
        else:
            runtime.remove_ban(mask)

    def process_key(
        self,
        runtime: ChannelRuntime,
        channel: str,
        argument: str,
        *,
        adding: bool,
    ) -> None:
        """Store or clear the channel key and publish it via NATS."""
        if not runtime.set_key(argument if adding else None):
            LOGGER.warning("ignoring unusable channel key on %s", channel)
            return

        self.bot.tasks.spawn(
            self.bot.channel_mgr.record_key(channel, runtime.key),
            "record-channel-key",
        )

    def process_op(
        self,
        runtime: ChannelRuntime,
        mode: str,
        nick: str,
        *,
        adding: bool,
    ) -> None:
        """Grant or revoke a member's operator status."""
        member = runtime.member(nick)
        if adding:
            member.modes.add(mode)
        else:
            member.modes.discard(mode)

    @staticmethod
    def update_channel_modes(
        runtime: ChannelRuntime,
        mode: str,
        *,
        adding: bool,
    ) -> None:
        """Add or remove a mode letter from the channel mode string."""
        current = runtime.modes.lstrip("+")
        if adding:
            if mode not in current:
                runtime.modes = f"+{current}{mode}"
        elif mode in current:
            remaining = current.replace(mode, "")
            runtime.modes = f"+{remaining}" if remaining else ""
