# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC behavior coordinated through Core NATS and JetStream."""

import asyncio
import logging
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from botnats.admin import AuthFlow, CommandHandler, TotpAuthorizer
from botnats.channel import ChannelManager, ChannelRecord, ChannelRuntime
from botnats.health_check import HealthCheck
from botnats.irc import (
    DEFAULT_CASEMAPPING,
    IRCClient,
    IRCClientConfig,
    IRCProtocol,
    Prefix,
    casefold,
    format_message,
    mask_matches,
)
from botnats.irc.events import IRCEventHandler
from botnats.irc.protocol import ISupportState
from botnats.nats import (
    PUBLISH_ERRORS,
    Coordinator,
    CoordinatorProtocol,
    Envelope,
    NATSConfig,
)
from botnats.presence import BotPresence, PresenceRegistry

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from botnats.config import BotConfig

LOGGER = logging.getLogger(__name__)


class Bot:
    """One stateless bot process."""

    def __init__(self, config: BotConfig) -> None:
        """Initialize the bot with validated configuration."""
        coordination_key = config.coordination_secret.encode()
        self.config = config
        self.caps = ISupportState()
        self.authorizer = TotpAuthorizer(
            config.totp_secret,
            coordination_secret=coordination_key,
            identity_fold=self.fold_identity,
            scope=(config.bot_id, config.network),
            session_ttl=config.auth_session_ttl,
        )
        self.callbacks = NATSCallbackHandler(self)
        self.channel_mgr = ChannelManager(self)
        self.commands = CommandHandler(self)
        self.identity: BotPresence | None = None
        self.identity_generation = 0
        self.identity_retry_attempts = 5
        self.identity_retry_delay = 5.0
        self.instance_id = uuid.uuid4().hex
        self.health_check = HealthCheck(ready=self.ready)
        self.events = IRCEventHandler(self)
        self.irc: IRCProtocol = IRCClient(
            config=IRCClientConfig(
                connect_timeout=config.irc_connect_timeout,
                nickname=config.nickname,
                servers=config.irc_servers,
                verify_tls=config.irc_verify_tls,
            ),
            on_disconnect=self.on_irc_disconnect,
            on_message=self.events.on_irc_message,
        )
        self.presence = PresenceRegistry(config.presence_ttl)
        self.registered = False
        self.tasks: set[asyncio.Task[None]] = set()

        self.coordinator: CoordinatorProtocol = Coordinator(
            callbacks=self.callbacks,
            config=NATSConfig(
                instance_id=self.instance_id,
                monitor_port=config.nats_monitor_port,
                network=config.network,
                presence_ttl=config.presence_ttl,
                replicas=config.jetstream_replicas,
                servers=config.nats_servers,
                session_ttl=config.auth_session_ttl,
                token=config.nats_token,
            ),
            envelope=Envelope(config.bot_id, coordination_key),
        )
        self.auth_flow = AuthFlow(self)

    def any_peer_opped(self, runtime: ChannelRuntime) -> bool:
        """Return whether any known peer bot holds operator status."""
        self_folded = self.fold(self.irc.current_nick)
        peers = self.presence.active()
        for folded, member in runtime.members.items():
            if folded == self_folded or not self.caps.is_opped(member.modes):
                continue
            if member.prefix is None:
                return True
            if any(
                peer.matches(member.prefix, self.caps.casemapping) for peer in peers
            ):
                return True
        return False

    async def batch_mode(
        self,
        channel: str,
        prefix: str,
        char: str,
        targets: list[str],
        label: str,
    ) -> None:
        """Apply mode changes in batches respecting server and IRC limits."""
        index = 0
        while index < len(targets):
            end = min(index + self.caps.mode_limit, len(targets))
            while end > index:
                batch = targets[index:end]
                try:
                    format_message(
                        "MODE",
                        (channel, prefix + (char * len(batch)), *batch),
                        None,
                    )
                except ValueError:
                    end -= 1
                else:
                    break
            if end == index:
                LOGGER.warning(
                    "cannot apply %s on %s: IRC MODE exceeds 512 bytes", label, channel
                )
                return
            try:
                await self.irc.send(
                    "MODE",
                    channel,
                    prefix + (char * len(batch)),
                    *batch,
                )
            except ConnectionError:
                return
            LOGGER.info("%s %s on %s", label, ",".join(batch), channel)
            index = end

    async def close(self) -> None:
        """Cancel background tasks and shut down all connections."""
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.health_check.close()
        await self.irc.close()
        await self.coordinator.close()

    async def discover_identity(self, generation: int) -> None:
        """Query the IRC server to resolve the bot's host and user prefix."""
        for _ in range(self.identity_retry_attempts):
            if generation != self.identity_generation or self.identity is not None:
                return
            try:
                await self.irc.send("WHOIS", self.irc.current_nick)
                await self.irc.send("USERHOST", self.irc.current_nick)
            except ConnectionError:
                return
            await asyncio.sleep(self.identity_retry_delay)
        if generation == self.identity_generation and self.identity is None:
            LOGGER.warning("IRC identity discovery failed; reconnecting")
            await self.irc.reconnect()

    def fold(self, value: str) -> str:
        """Normalize a string using the server's casemapping rules."""
        return casefold(value, self.caps.casemapping)

    def fold_identity(self, prefix: str) -> str:
        """Normalize a nick!user@host identity for case-insensitive comparison."""
        nick, bang, rest = prefix.partition("!")
        if not bang:
            return casefold(nick, self.caps.casemapping)
        return casefold(nick, self.caps.casemapping) + "!" + casefold(rest, "ascii")

    def is_self(self, nickname: str) -> bool:
        """Return whether a nickname identifies this IRC client."""
        return self.fold(nickname) == self.fold(self.irc.current_nick)

    def is_self_opped(self, runtime: ChannelRuntime) -> bool:
        """Check whether this bot holds operator status in the channel."""
        member = runtime.members.get(self.fold(self.irc.current_nick))
        return member is not None and self.caps.is_opped(member.modes)

    async def maintenance_loop(self) -> None:
        """Run the maintenance tick on a recurring interval."""
        while True:
            await asyncio.sleep(self.config.maintenance_interval)
            try:
                await self.maintenance_tick()
            except Exception:
                LOGGER.exception("maintenance tick failed")

    async def maintenance_tick(self) -> None:
        """Execute one round of presence, nick, and channel upkeep."""
        self.authorizer.prune()
        self.presence.prune()
        if self.registered:
            if self.fold(self.irc.current_nick) != self.fold(self.irc.desired_nick):
                with suppress(ConnectionError):
                    await self.irc.send("NICK", self.irc.desired_nick)
            await self.channel_mgr.retry_pending_parts()
            if self.identity is not None:
                with suppress(*PUBLISH_ERRORS):
                    await self.coordinator.put_presence(self.identity.to_dict())
                await self.channel_mgr.join_desired()
        if self.coordinator.ready:
            await self.events.retry_pending_sessions()
            await self.channel_mgr.retry_pending_records()
        if not self.registered:
            return
        for folded, channel in tuple(self.channel_mgr.desired_channels.items()):
            runtime = self.channel_mgr.channels.get(folded)
            if (
                runtime is not None
                and runtime.joined
                and not self.is_self_opped(runtime)
            ):
                with suppress(*PUBLISH_ERRORS):
                    await self.channel_mgr.request_peer("op", channel)

    def on_irc_disconnect(self) -> None:
        """Clear connection-scoped state when the IRC connection drops."""
        self.channel_mgr.set_casemapping(DEFAULT_CASEMAPPING)
        self.caps.reset()
        self.irc.reset_caps()
        self.channel_mgr.reset()
        self.identity = None
        self.identity_generation += 1
        self.registered = False

    async def on_registered(self) -> None:
        """Handle successful IRC registration and begin identity discovery."""
        self.registered = True
        self.identity = None
        self.identity_generation += 1
        self.channel_mgr.reset()
        LOGGER.info("registered on IRC as %s", self.irc.current_nick)
        self.spawn(
            self.discover_identity(self.identity_generation),
            "identity-discovery",
        )

    def ready(self) -> bool:
        """Return whether IRC and all coordination dependencies are ready."""
        return self.registered and self.irc.connected and self.coordinator.ready

    async def run(self) -> None:
        """Start all services and run the IRC connection loop until stopped."""
        await self.health_check.start()
        try:
            await self.coordinator.start()
            self.spawn(self.maintenance_loop(), "maintenance")
            await self.irc.run_forever()
        finally:
            await self.close()

    def runtime(self, channel: str) -> ChannelRuntime | None:
        """Return live state for a channel using IRC case folding."""
        return self.channel_mgr.channels.get(self.fold(channel))

    async def safe_privmsg(self, nickname: str, message: str) -> None:
        """Send a private message, silently ignoring connection failures."""
        with suppress(ConnectionError):
            await self.irc.send("PRIVMSG", nickname, trailing=message)

    async def set_identity(self, prefix: Prefix) -> None:
        """Store the bot's resolved identity and announce presence to peers."""
        if not prefix.complete:
            return
        identity = BotPresence(
            bot_id=self.config.bot_id,
            host=prefix.host or "",
            instance_id=self.instance_id,
            nick=self.irc.current_nick,
            user=prefix.user or "",
        )
        self.presence.update(identity)
        if identity == self.identity:
            return
        self.identity = identity
        with suppress(*PUBLISH_ERRORS):
            await self.coordinator.put_presence(identity.to_dict())
        await self.channel_mgr.join_desired()

    def spawn(self, coroutine: Coroutine[Any, Any, None], name: str) -> None:
        """Schedule a coroutine as a tracked background task."""
        task = asyncio.create_task(coroutine, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.task_done)

    def task_done(self, task: asyncio.Task[None]) -> None:
        """Handle completion of a background task and log any failures."""
        self.tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error(
                "background task %s failed: %s",
                task.get_name(),
                error,
                exc_info=(type(error), error, error.__traceback__),
            )


class NATSCallbackHandler:
    """Processes NATS coordination messages and KV watch updates."""

    def __init__(self, bot: Bot) -> None:
        """Initialize the handler with a reference to the bot instance."""
        self.bot = bot

    def eligible(
        self,
        payload: dict[str, Any],
        *,
        require_member: bool = True,
    ) -> tuple[str, BotPresence, ChannelRuntime] | None:
        """Return a validated peer action this bot can fulfill."""
        try:
            channel = payload["channel"]
            presence = BotPresence.from_dict(payload["presence"])
            if not isinstance(channel, str):
                return None
        except KeyError, TypeError, ValueError:
            return None
        runtime = self.bot.runtime(channel)
        if (
            runtime is None
            or not self.bot.presence.has(presence)
            or not self.bot.irc.connected
            or not self.bot.is_self_opped(runtime)
        ):
            return None
        if require_member:
            member = runtime.members.get(self.bot.fold(presence.nick))
            if (
                member is None
                or self.bot.caps.is_opped(member.modes)
                or member.prefix is None
                or not presence.matches(member.prefix, self.bot.caps.casemapping)
            ):
                return None
        return channel, presence, runtime

    async def on_channel(self, payload: dict[str, Any]) -> None:
        """Apply a channel configuration record from a KV watch update."""
        try:
            record = ChannelRecord.from_dict(payload)
        except TypeError, ValueError:
            return
        await self.bot.channel_mgr.apply_record(record)

    async def on_invite_grant(self, payload: dict[str, Any]) -> None:
        """Send an IRC INVITE to a peer bot that requested one."""
        parsed = self.eligible(payload, require_member=False)
        if parsed is None:
            return
        channel, presence, _ = parsed
        try:
            await self.bot.irc.send("INVITE", presence.nick, channel)
        except ConnectionError:
            return
        LOGGER.info("invited bot %s to %s", presence.bot_id, channel)

    def on_invite_request(self, payload: dict[str, Any]) -> bool:
        """Return whether this bot can fulfill an invite request."""
        return self.eligible(payload, require_member=False) is not None

    async def on_op_grant(self, payload: dict[str, Any]) -> None:
        """Queue an operator mode grant for a peer bot."""
        parsed = self.eligible(payload)
        if parsed is None:
            return
        channel, presence, _ = parsed
        self.bot.channel_mgr.queue_pending_op(self.bot.fold(channel), presence)

    def on_op_request(self, payload: dict[str, Any]) -> bool:
        """Return whether this bot can grant operator status to the requester."""
        return self.eligible(payload) is not None

    def on_presence(self, presence: BotPresence) -> None:
        """Register or refresh a peer bot's presence record from KV watch."""
        self.bot.presence.update(presence)

    def on_presence_delete(self, bot_id: str) -> None:
        """Remove an expired peer presence from the local registry."""
        self.bot.presence.remove(bot_id)

    def on_session_delete(self, prefix: str) -> None:
        """Remove a revoked session from local cache via KV watch."""
        key = self.bot.authorizer.identity_fold(prefix)
        session = self.bot.authorizer.sessions.get(key)
        if session is not None and casefold(session.prefix, "ascii") == casefold(
            prefix,
            "ascii",
        ):
            self.bot.authorizer.sessions.pop(key, None)

    def on_session_update(self, payload: dict[str, Any]) -> None:
        """Import a session from a KV watch update into local cache."""
        self.bot.authorizer.import_session(payload)

    async def on_unban_grant(self, payload: dict[str, Any]) -> None:
        """Remove channel bans matching a peer bot's hostmask."""
        parsed = self.eligible(payload, require_member=False)
        if parsed is None:
            return
        channel, presence, runtime = parsed
        prefix = presence.to_prefix()
        masks = sorted(
            mask
            for mask in runtime.bans
            if mask_matches(mask, prefix, self.bot.caps.casemapping)
        )
        await self.bot.batch_mode(channel, "-", "b", masks, "removed bot ban(s)")

    def on_unban_request(self, payload: dict[str, Any]) -> bool:
        """Return whether this bot can remove bans affecting the requester."""
        parsed = self.eligible(payload, require_member=False)
        if parsed is None:
            return False
        _, presence, runtime = parsed
        prefix = presence.to_prefix()
        return any(
            mask_matches(mask, prefix, self.bot.caps.casemapping)
            for mask in runtime.bans
        )
