# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC event routing, coordination triggers, and capability tracking."""

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import asdict
from typing import TYPE_CHECKING

from botnats.irc.client import DEFAULT_NICK_LENGTH
from botnats.irc.protocol import (
    DEFAULT_CASEMAPPING,
    DEFAULT_CHANMODES,
    DEFAULT_MEMBER_PREFIXES,
    DEFAULT_MEMBERSHIP_MODES,
    IRCMessage,
    Prefix,
    casefold,
    iter_mode_changes,
    mask_matches,
)
from botnats.nats.coordinator import PUBLISH_ERRORS

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
        self.caps = bot.caps
        self.enforced_set, self.enforced_unset = bot.channel_mgr.mode_intent
        self.pending_sessions: dict[str, dict[str, object]] = {}
        # ponytail: global ordering; use dependency-aware queues if contention appears.
        self.session_lock = asyncio.Lock()
        self.nick_watch_task: asyncio.Task[None] | None = None
        self.handlers: dict[str, Callable[[IRCMessage], Awaitable[None]]] = {
            "001": self.handle_welcome,
            "005": self.handle_isupport,
            "302": self.handle_userhost,
            "303": self.handle_ison_reply,
            "311": self.handle_whois_user,
            "324": self.handle_channel_modes,
            "352": self.handle_who,
            "353": self.handle_names,
            "366": self.handle_end_of_names,
            "367": self.handle_ban_list,
            "471": self.handle_join_denied,
            "473": self.handle_join_denied,
            "474": self.handle_banned,
            "475": self.handle_join_denied,
            "731": self.handle_monitor_offline,
            "CHGHOST": self.handle_chghost,
            "INVITE": self.handle_invite,
            "JOIN": self.handle_join,
            "KICK": self.handle_kick,
            "MODE": self.handle_mode,
            "NICK": self.handle_nick,
            "PART": self.handle_part,
            "PRIVMSG": self.handle_command,
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
            self.caps.chanmodes[1] + self.caps.chanmodes[2] + self.caps.chanmodes[3]
        )
        for adding, mode, argument in iter_mode_changes(
            modes,
            arguments,
            self.caps.chanmodes,
            self.caps.membership_modes,
        ):
            if (not adding and mode in self.enforced_set) or (
                adding and mode in self.enforced_unset
            ):
                lost_enforced = True
            if mode in channel_modes:
                self.update_channel_modes(runtime, mode, adding=adding)
            if argument is None:
                if mode == "k" and not adding and runtime.key is not None:
                    self.process_key(runtime, channel, "", adding=False)
                continue
            if mode == "b":
                self.process_ban(runtime, channel, argument, adding=adding)
            elif mode == "k":
                self.process_key(runtime, channel, argument, adding=adding)
            elif mode in self.caps.operator_modes:
                self.process_op(runtime, mode, argument, adding=adding)
                if adding:
                    saw_new_op = True
        return lost_enforced, saw_new_op

    async def handle_ban_list(self, message: IRCMessage) -> None:
        """Record a ban mask from the channel ban list reply."""
        if len(message.params) < 3:
            return
        channel = message.params[1]
        mask = message.params[2]
        runtime = self.bot.runtime(channel)
        if runtime is not None:
            runtime.add_ban(mask)

    async def handle_channel_modes(self, message: IRCMessage) -> None:
        """Store the channel mode string from an RPL_CHANNELMODEIS reply."""
        if len(message.params) < 3:
            return
        channel = message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is not None:
            runtime.modes = message.params[2]

    async def handle_banned(self, message: IRCMessage) -> None:
        """Request an unban when the bot is banned from a channel."""
        if len(message.params) >= 2:
            self.bot.spawn(
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
        folded = self.bot.fold(nick)
        # Capture the old full identity before overwriting member state: a
        # nick-only CHGHOST prefix would otherwise destroy the only copy and
        # silently skip the required revocation.
        old_prefix = message.prefix
        for runtime in self.bot.channel_mgr.channels.values():
            member = runtime.members.get(folded)
            if member is not None:
                if (
                    not old_prefix.complete
                    and member.prefix is not None
                    and member.prefix.complete
                ):
                    old_prefix = member.prefix
                member.prefix = new_prefix
        if old_prefix.complete:
            await self.revoke_session(old_prefix)
        else:
            LOGGER.debug(
                "CHGHOST for %s carried no complete identity; nothing to revoke",
                nick,
            )
        if self.bot.identity is not None and folded == self.bot.fold(
            self.bot.identity.nick,
        ):
            await self.bot.set_identity(new_prefix)

    async def handle_command(self, message: IRCMessage) -> None:
        """Dispatch a private message as a bot command."""
        if (
            message.prefix is None
            or not message.prefix.complete
            or len(message.params) < 2
        ):
            return
        target, text = message.params[0], message.params[-1]
        if not self.bot.is_self(target):
            return
        if text.startswith("\x01"):
            return
        await self.bot.commands.dispatch(message.prefix, text)

    async def handle_end_of_names(self, message: IRCMessage) -> None:
        """Finalize channel join by requesting WHO data and enforcing modes."""
        if len(message.params) < 2:
            return
        channel = message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        with suppress(ConnectionError):
            await self.bot.irc.send("WHO", channel)
        with suppress(ConnectionError):
            await self.bot.irc.send("MODE", channel)
        with suppress(ConnectionError):
            await self.bot.irc.send("MODE", channel, "+b")
        if self.bot.is_self_opped(runtime):
            self.bot.spawn(
                self.bot.channel_mgr.enforce_modes(channel),
                "names-enforce-modes",
            )
        else:
            self.bot.spawn(
                self.bot.channel_mgr.request_peer("op", channel),
                "names-op-request",
            )

    async def handle_invite(self, message: IRCMessage) -> None:
        """Join a configured channel when invited."""
        if len(message.params) < 2:
            return
        target, channel = message.params[0], message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is not None and not runtime.joined and self.bot.is_self(target):
            await self.bot.channel_mgr.safe_join(channel, runtime.key)

    async def handle_ison_reply(self, message: IRCMessage) -> None:
        """Reclaim the desired nickname when ISON reports it offline."""
        if not message.params:
            return
        nicks = message.params[-1].split()
        desired = self.bot.irc.desired_nick
        folded = self.bot.fold(desired)
        for nick in nicks:
            if self.bot.fold(nick) == folded:
                return
        await self.try_nick_reclaim()

    async def handle_monitor_offline(self, message: IRCMessage) -> None:
        """Reclaim the desired nickname when MONITOR reports it offline."""
        if not message.params:
            return
        targets = message.params[-1].split(",")
        desired = self.bot.irc.desired_nick
        folded = self.bot.fold(desired)
        for target in targets:
            nick = target.partition("!")[0]
            if self.bot.fold(nick) == folded:
                await self.try_nick_reclaim()
                return

    async def try_nick_reclaim(self) -> None:
        """Send a NICK command to reclaim the desired nickname."""
        desired = self.bot.irc.desired_nick
        if self.bot.fold(self.bot.irc.current_nick) == self.bot.fold(desired):
            return
        with suppress(ConnectionError):
            await self.bot.irc.send("NICK", desired)

    def start_nick_watch(self) -> None:
        """Begin watching for the desired nickname to become available."""
        self.stop_nick_watch()
        if self.bot.fold(self.bot.irc.current_nick) == self.bot.fold(
            self.bot.irc.desired_nick,
        ):
            return
        if self.caps.monitor_limit is not None:
            self.bot.spawn(self.monitor_nick(), "nick-monitor")
        else:
            self.nick_watch_task = asyncio.create_task(
                self.ison_poll_loop(),
                name="nick-ison-poll",
            )
            self.nick_watch_task.add_done_callback(self.bot.task_done)
            self.bot.tasks.add(self.nick_watch_task)

    def stop_nick_watch(self) -> None:
        """Cancel any running nickname watch."""
        task = self.nick_watch_task
        self.nick_watch_task = None
        if task is not None:
            task.cancel()

    async def stop_nick_watch_async(self) -> None:
        """Cancel the nickname watch and unsubscribe from MONITOR."""
        self.stop_nick_watch()
        if self.caps.monitor_limit is not None:
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
            if self.bot.fold(self.bot.irc.current_nick) == self.bot.fold(
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
                self.caps.chanmodes = DEFAULT_CHANMODES
            case "MODES":
                self.caps.mode_limit = 1
            case "MONITOR":
                self.caps.monitor_limit = None
            case "NICKLEN":
                self.bot.irc.set_nickname_length(DEFAULT_NICK_LENGTH)
            case "PREFIX":
                self.caps.member_prefixes = dict(DEFAULT_MEMBER_PREFIXES)
                self.caps.membership_modes = DEFAULT_MEMBERSHIP_MODES
                self.caps.op_mode = "o"

    def apply_isupport(self, name: str, value: str) -> None:
        """Apply a single ISUPPORT name=value token."""
        match name.upper():
            case "CASEMAPPING":
                self.bot.channel_mgr.set_casemapping(value.lower())
            case "CHANMODES":
                self.caps.parse_chanmodes(value)
            case "MODES":
                self.caps.parse_modes(value)
            case "MONITOR":
                with suppress(ValueError):
                    self.caps.monitor_limit = max(1, int(value))
                if self.caps.monitor_limit is not None:
                    self.start_nick_watch()
            case "NICKLEN":
                with suppress(ValueError):
                    self.bot.irc.set_nickname_length(int(value))
            case "PREFIX":
                self.caps.parse_prefix(value)

    async def handle_isupport(self, message: IRCMessage) -> None:
        """Parse RPL_ISUPPORT tokens into server capability state."""
        tokens = message.params[1:]
        if tokens and " " in tokens[-1]:
            tokens = tokens[:-1]
        for token in tokens:
            name, separator, value = token.partition("=")
            if not separator:
                if name.startswith("-"):
                    self.forget_isupport(name[1:])
                continue
            self.apply_isupport(name, value)

    async def handle_join(self, message: IRCMessage) -> None:
        """Process a JOIN event, initializing channel state for self-joins."""
        if message.prefix is None or not message.params:
            return
        channel = message.params[0]
        runtime = self.bot.runtime(channel)
        is_self = self.bot.is_self(message.prefix.nick)
        if runtime is None:
            if is_self:
                try:
                    await self.bot.irc.send("PART", channel)
                except ConnectionError:
                    mgr = self.bot.channel_mgr
                    mgr.pending_parts[self.bot.fold(channel)] = channel
            return
        if is_self:
            runtime.reset()
            runtime.joined = True
            runtime.member(message.prefix.nick).prefix = message.prefix
            if message.prefix.complete:
                await self.bot.set_identity(message.prefix)
            LOGGER.info("joined %s", channel)
        else:
            runtime.member(message.prefix.nick).prefix = message.prefix

    async def handle_join_denied(self, message: IRCMessage) -> None:
        """Request a peer invite when a channel refuses a direct join."""
        if len(message.params) >= 2:
            self.bot.spawn(
                self.bot.channel_mgr.request_peer("invite", message.params[1]),
                "invite-request",
            )

    async def handle_kick(self, message: IRCMessage) -> None:
        """Handle a KICK by removing the target or requesting an unban for self."""
        if len(message.params) < 2:
            return
        channel = message.params[0]
        target = message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        if self.bot.is_self(target):
            runtime.reset()
            self.bot.spawn(
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
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        was_opped = self.bot.is_self_opped(runtime)
        lost_enforced, saw_new_op = self.apply_mode_changes(
            runtime,
            channel,
            modes,
            arguments,
        )
        opped = self.bot.is_self_opped(runtime)
        if opped and (lost_enforced or not was_opped):
            self.bot.spawn(
                self.bot.channel_mgr.enforce_modes(channel),
                "enforce-modes",
            )
        elif not opped and (saw_new_op or was_opped):
            self.bot.spawn(
                self.bot.channel_mgr.request_peer("op", channel),
                "op-request",
            )

    async def handle_names(self, message: IRCMessage) -> None:
        """Parse NAMES reply entries and update member mode prefixes."""
        if len(message.params) < 4:
            return
        channel = message.params[-2]
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        # A prefix symbol not yet advertised via ISUPPORT stays attached to
        # the nick and creates a phantom member; the WHO that follows
        # end-of-names replaces it with the correctly keyed record.
        for decorated_nick in message.params[-1].split():
            modes: set[str] = set()
            nick = decorated_nick
            while nick and nick[0] in self.caps.member_prefixes:
                mode = self.caps.member_prefixes[nick[0]]
                if mode in self.caps.operator_modes:
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
        old_folded = self.bot.fold(old_nick)
        old_prefix = self.update_nick_members(message.prefix, new_nick)
        new_prefix = Prefix(new_nick, old_prefix.user, old_prefix.host)
        if old_prefix.complete:
            await self.move_nick_session(old_prefix, new_prefix)
        identity = self.bot.identity
        if identity is not None and old_folded == self.bot.fold(identity.nick):
            await self.bot.set_identity(
                Prefix(
                    new_nick,
                    new_prefix.user or identity.user or None,
                    new_prefix.host or identity.host or None,
                ),
            )
        if self.bot.is_self(new_nick):
            if self.bot.fold(new_nick) == self.bot.fold(self.bot.irc.desired_nick):
                await self.stop_nick_watch_async()
            elif self.bot.registered:
                self.start_nick_watch()

    def update_nick_members(self, prefix: Prefix, new_nick: str) -> Prefix:
        """Rekey channel members for a nick change and return the best old prefix."""
        old_folded = self.bot.fold(prefix.nick)
        new_folded = self.bot.fold(new_nick)
        old_prefix = prefix
        for runtime in self.bot.channel_mgr.channels.values():
            member = runtime.members.pop(old_folded, None)
            if member is not None:
                member.nick = new_nick
                member_prefix = member.prefix
                if member_prefix is not None:
                    if not old_prefix.complete and member_prefix.complete:
                        old_prefix = member_prefix
                    member.prefix = Prefix(
                        new_nick,
                        member_prefix.user,
                        member_prefix.host,
                    )
                runtime.members[new_folded] = member
        return old_prefix

    async def move_nick_session(self, old_prefix: Prefix, new_prefix: Prefix) -> None:
        """Move an authenticated session from the old to the new identity."""
        old_identity = old_prefix.render()
        new_identity = new_prefix.render()
        moved = self.bot.authorizer.move(old_identity, new_identity)
        if moved is None:
            return
        previous, session = moved
        if await self.sync_session(old_identity, asdict(previous)):
            await self.sync_session(new_identity, asdict(session))
        else:
            async with self.session_lock:
                key = casefold(new_identity, "ascii")
                self.pending_sessions.pop(key, None)
                self.pending_sessions[key] = asdict(session)

    async def handle_part(self, message: IRCMessage) -> None:
        """Remove a member on PART or reset channel state for self-parts."""
        if message.prefix is None or not message.params:
            return
        runtime = self.bot.runtime(message.params[0])
        if runtime is None:
            return
        if self.bot.is_self(message.prefix.nick):
            runtime.reset()
        else:
            runtime.remove(message.prefix.nick)

    async def handle_quit(self, message: IRCMessage) -> None:
        """Remove a user and revoke its session on QUIT."""
        if message.prefix is None:
            return
        for runtime in self.bot.channel_mgr.channels.values():
            runtime.remove(message.prefix.nick)
        if message.prefix.complete:
            await self.revoke_session(message.prefix)

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
            if at and self.bot.is_self(nickname.rstrip("*")):
                await self.bot.set_identity(
                    Prefix(self.bot.irc.current_nick, user, host),
                )
                return

    async def handle_welcome(self, message: IRCMessage) -> None:
        """Notify the bot that IRC registration is complete."""
        LOGGER.debug("received welcome: %s", " ".join(message.params))
        self.bot.on_registered()
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
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        member = runtime.member(nick)
        member.prefix = Prefix(nick, user, host)
        member.modes = {
            mode
            for prefix, mode in self.caps.member_prefixes.items()
            if prefix in flags and mode in self.caps.operator_modes
        }
        if self.bot.is_self(nick):
            await self.bot.set_identity(member.prefix)

    async def handle_whois_user(self, message: IRCMessage) -> None:
        """Set the bot's identity from a WHOIS user reply."""
        if len(message.params) >= 4 and self.bot.is_self(message.params[1]):
            await self.bot.set_identity(
                Prefix(message.params[1], message.params[2], message.params[3]),
            )

    async def on_irc_message(self, message: IRCMessage) -> None:
        """Route an IRC message to its registered handler."""
        if handler := self.handlers.get(message.command):
            await handler(message)

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
            if self.bot.identity is not None and mask_matches(
                mask,
                self.bot.identity.to_prefix(),
                self.bot.caps.casemapping,
            ):
                self.bot.spawn(
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
        self.bot.spawn(
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

    async def revoke_session(self, prefix: Prefix) -> None:
        """Revoke authorization and propagate the signed revocation to peers."""
        identity = prefix.render()
        revoked = self.bot.authorizer.revoke(identity)
        if revoked is not None:
            await self.sync_session(identity, asdict(revoked))

    async def retry_pending_sessions(self) -> None:
        """Retry session writes that failed while JetStream was unavailable."""
        async with self.session_lock:
            await self._drain_sessions()

    async def sync_session(
        self,
        identity: str,
        session: dict[str, object],
    ) -> bool:
        """Apply or queue one session update; report this update's outcome."""
        identity = casefold(identity, "ascii")
        async with self.session_lock:
            # Pop before inserting so a re-queued identity moves to the tail;
            # dict assignment alone would keep its stale causal position.
            self.pending_sessions.pop(identity, None)
            self.pending_sessions[identity] = session
            await self._drain_sessions()
            return identity not in self.pending_sessions

    async def _drain_sessions(self) -> None:
        """Apply queued session mutations in insertion order.

        Stop at the first failure: insertion order carries causality (a nick
        move queues revoke-old before grant-new), so later entries must not
        leapfrog an earlier one that is still pending.
        """
        for identity, session in tuple(self.pending_sessions.items()):
            if not await self._apply_session(identity, session):
                return

    async def _apply_session(
        self,
        identity: str,
        session: dict[str, object],
    ) -> bool:
        """Apply the current queued session mutation while holding the lock."""
        try:
            stored = await self.bot.coordinator.put_session(identity, session)
        except PUBLISH_ERRORS:
            return False
        self.bot.authorizer.import_session(stored)
        if session.get("revoked") is True:
            winner = self.bot.authorizer.parse(stored, time.time())
            if winner is not None and not winner.revoked:
                replacement = asdict(
                    self.bot.authorizer.create(
                        winner.prefix,
                        winner.expires_at,
                        winner.issuer,
                        winner.version + 1,
                        revoked=True,
                    ),
                )
                self.bot.authorizer.import_session(replacement)
                self.pending_sessions[identity] = replacement
                return False
        self.pending_sessions.pop(identity, None)
        return True
