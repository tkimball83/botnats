# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC event routing, coordination triggers, and capability tracking."""

import asyncio
import logging
import time
from contextlib import suppress
from typing import TYPE_CHECKING

from botnats.config import mode_intent
from botnats.irc.client import DEFAULT_NICK_LENGTH
from botnats.irc.protocol import (
    IRCMessage,
    ISupportState,
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
LOGGER = logging.getLogger(__name__)

MIN_BAN_LIST_PARAMS = 3
MIN_CHANNEL_PARAMS = 2
MIN_CHGHOST_PARAMS = 2
MIN_KICK_PARAMS = 2
MIN_MODE_PARAMS = 2
MIN_NAMES_PARAMS = 4
MIN_WHOIS_PARAMS = 4
MIN_WHO_REPLY_PARAMS = 8


class IRCEventHandler:
    """Routes incoming IRC messages and reacts to coordination-relevant events."""

    def __init__(self, bot: Bot) -> None:
        """Initialize the handler with bot context and server capabilities."""
        self.bot = bot
        self.caps = bot.caps
        self.enforced_set, self.enforced_unset = mode_intent(
            bot.config.channel_modes,
        )
        self.pending_sessions: dict[str, dict[str, object]] = {}
        # ponytail: global ordering; use dependency-aware queues if contention appears.
        self.session_lock = asyncio.Lock()
        self.handlers: dict[str, Callable[[IRCMessage], Awaitable[None]]] = {
            "001": self.handle_welcome,
            "005": self.handle_isupport,
            "302": self.handle_userhost,
            "311": self.handle_whois_user,
            "352": self.handle_who,
            "353": self.handle_names,
            "366": self.handle_end_of_names,
            "367": self.handle_ban_list,
            "471": self.handle_join_denied,
            "473": self.handle_join_denied,
            "474": self.handle_banned,
            "475": self.handle_join_denied,
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
            if argument is None:
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
        if len(message.params) < MIN_BAN_LIST_PARAMS:
            return
        channel = message.params[1]
        mask = message.params[2]
        runtime = self.bot.runtime(channel)
        if runtime is not None:
            runtime.bans.add(mask)

    async def handle_banned(self, message: IRCMessage) -> None:
        """Request an unban when the bot is banned from a channel."""
        if len(message.params) >= MIN_CHANNEL_PARAMS:
            self.bot.spawn(
                self.bot.channel_mgr.request_peer("unban", message.params[1]),
                "banned-unban-request",
            )

    async def handle_chghost(self, message: IRCMessage) -> None:
        """Revoke authorization and update member state after a host change."""
        if message.prefix is None or len(message.params) < MIN_CHGHOST_PARAMS:
            return
        nick = message.prefix.nick
        new_user = message.params[0]
        new_host = message.params[1]
        new_prefix = Prefix(nick, new_user, new_host)
        folded = self.bot.fold(nick)
        for runtime in self.bot.channel_mgr.channels.values():
            member = runtime.members.get(folded)
            if member is not None:
                member.prefix = new_prefix
        if message.prefix.complete:
            await self.revoke_session(message.prefix)
        if self.bot.identity is not None and folded == self.bot.fold(
            self.bot.identity.nick,
        ):
            await self.bot.set_identity(new_prefix)

    async def handle_command(self, message: IRCMessage) -> None:
        """Dispatch a private message as a bot command."""
        if (
            message.prefix is None
            or not message.prefix.complete
            or len(message.params) < MIN_CHANNEL_PARAMS
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
        if len(message.params) < MIN_CHANNEL_PARAMS:
            return
        channel = message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        with suppress(ConnectionError):
            await self.bot.irc.send("WHO", channel)
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
        if len(message.params) < MIN_CHANNEL_PARAMS:
            return
        target, channel = message.params[0], message.params[1]
        runtime = self.bot.runtime(channel)
        if runtime is not None and not runtime.joined and self.bot.is_self(target):
            await self.bot.channel_mgr.safe_join(channel, runtime.key)

    def forget_isupport(self, name: str) -> None:
        """Restore default behavior for a removed ISUPPORT parameter."""
        defaults = ISupportState()
        match name.upper():
            case "CASEMAPPING":
                self.bot.channel_mgr.set_casemapping(defaults.casemapping)
            case "CHANMODES":
                self.caps.chanmodes = defaults.chanmodes
            case "MODES":
                self.caps.mode_limit = defaults.mode_limit
            case "NICKLEN":
                self.bot.irc.set_nickname_length(DEFAULT_NICK_LENGTH)
            case "PREFIX":
                self.caps.member_prefixes = defaults.member_prefixes
                self.caps.membership_modes = defaults.membership_modes
                self.caps.op_mode = defaults.op_mode

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
            match name.upper():
                case "CASEMAPPING":
                    self.bot.channel_mgr.set_casemapping(value.lower())
                case "CHANMODES":
                    self.caps.parse_chanmodes(value)
                case "MODES":
                    self.caps.parse_modes(value)
                case "NICKLEN":
                    with suppress(ValueError):
                        self.bot.irc.set_nickname_length(int(value))
                case "PREFIX":
                    self.caps.parse_prefix(value)

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
                    self.bot.channel_mgr.pending_parts[self.bot.fold(channel)] = channel
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
        if len(message.params) >= MIN_CHANNEL_PARAMS:
            self.bot.spawn(
                self.bot.channel_mgr.request_peer("invite", message.params[1]),
                "invite-request",
            )

    async def handle_kick(self, message: IRCMessage) -> None:
        """Handle a KICK by removing the target or requesting an unban for self."""
        if len(message.params) < MIN_KICK_PARAMS:
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
        if len(message.params) < MIN_MODE_PARAMS:
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
        if len(message.params) < MIN_NAMES_PARAMS:
            return
        channel = message.params[-2]
        runtime = self.bot.runtime(channel)
        if runtime is None:
            return
        for decorated_nick in message.params[-1].split():
            modes: set[str] = set()
            nick = decorated_nick
            while nick and nick[0] in self.caps.member_prefixes:
                modes.add(self.caps.member_prefixes[nick[0]])
                nick = nick[1:]
            if nick:
                runtime.member(nick).modes.update(modes)

    async def handle_nick(self, message: IRCMessage) -> None:
        """Update member records and bot identity when a nick changes."""
        if message.prefix is None or not message.params:
            return
        old_nick = message.prefix.nick
        new_nick = message.params[-1]
        old_folded = self.bot.fold(old_nick)
        new_folded = self.bot.fold(new_nick)
        new_prefix = Prefix(new_nick, message.prefix.user, message.prefix.host)
        for runtime in self.bot.channel_mgr.channels.values():
            member = runtime.members.pop(old_folded, None)
            if member is not None:
                member.nick = new_nick
                prefix = member.prefix
                if prefix is not None:
                    member.prefix = Prefix(new_nick, prefix.user, prefix.host)
                runtime.members[new_folded] = member
        if message.prefix.complete:
            old_identity = message.prefix.render()
            new_identity = new_prefix.render()
            moved = self.bot.authorizer.move(
                old_identity,
                new_identity,
            )
            if moved is not None:
                previous, session = moved
                if await self.sync_session(old_identity, previous.to_dict()):
                    await self.sync_session(new_identity, session.to_dict())
                else:
                    async with self.session_lock:
                        self.pending_sessions[casefold(new_identity, "ascii")] = (
                            session.to_dict()
                        )
        if self.bot.identity is not None and old_folded == self.bot.fold(
            self.bot.identity.nick,
        ):
            await self.bot.set_identity(new_prefix)

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
        await self.bot.on_registered()

    async def handle_who(self, message: IRCMessage) -> None:
        """Update member identity and modes from a WHO reply entry."""
        if len(message.params) < MIN_WHO_REPLY_PARAMS:
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
            if prefix in flags
        }
        if self.bot.is_self(nick):
            await self.bot.set_identity(member.prefix)

    async def handle_whois_user(self, message: IRCMessage) -> None:
        """Set the bot's identity from a WHOIS user reply."""
        if len(message.params) < MIN_WHOIS_PARAMS:
            return
        nick = message.params[1]
        user = message.params[2]
        host = message.params[3]
        if self.bot.is_self(nick):
            await self.bot.set_identity(Prefix(nick, user, host))

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
            runtime.bans.add(mask)
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

    async def revoke_session(self, prefix: Prefix) -> None:
        """Revoke authorization and propagate the deletion to peers."""
        revoked = self.bot.authorizer.revoke(prefix.render())
        if revoked is not None:
            await self.sync_session(
                prefix.render(),
                revoked.to_dict(),
            )

    async def retry_pending_sessions(self) -> None:
        """Retry session writes that failed while JetStream was unavailable."""
        async with self.session_lock:
            await self._drain_sessions()

    async def sync_session(
        self,
        identity: str,
        session: dict[str, object],
    ) -> bool:
        """Apply or queue one session update."""
        identity = casefold(identity, "ascii")
        async with self.session_lock:
            self.pending_sessions[identity] = session
            return await self._drain_sessions()

    async def _drain_sessions(self) -> bool:
        """Apply queued session mutations in insertion order."""
        for identity, session in tuple(self.pending_sessions.items()):
            if self.pending_sessions.get(identity, self) is not session:
                continue
            if not await self._apply_session(identity, session):
                return False
        return True

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
            if winner is None:
                return False
            if not winner.revoked:
                replacement = self.bot.authorizer.create(
                    winner.prefix,
                    winner.expires_at,
                    winner.issuer,
                    winner.version + 1,
                    revoked=True,
                ).to_dict()
                self.bot.authorizer.import_session(replacement)
                if self.pending_sessions.get(identity) is session:
                    self.pending_sessions[identity] = replacement
                return False
        if self.pending_sessions.get(identity) is session:
            self.pending_sessions.pop(identity, None)
        return True
