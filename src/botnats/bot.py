# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC behavior coordinated through Core NATS and JetStream."""

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING, Any

from botnats import Tasks
from botnats.auth import AuthFlow, SessionSync, TotpAuthorizer
from botnats.channel import ChannelManager, ChannelRecord
from botnats.commands import CommandHandler
from botnats.health_check import HealthCheck
from botnats.irc.client import IRCClient, IRCClientConfig
from botnats.irc.events import IRCEventHandler
from botnats.irc.protocol import (
    DEFAULT_CASEMAPPING,
    IRCProtocol,
    ISupportState,
)
from botnats.nats.coordinator import Coordinator, CoordinatorProtocol, NATSConfig
from botnats.nats.envelope import Envelope
from botnats.presence import BotPresence, PresenceRegistry, SelfIdentity

if TYPE_CHECKING:
    from botnats.config import BotConfig

LOGGER = logging.getLogger(__name__)


class Bot:
    """One stateless bot process."""

    def __init__(
        self,
        config: BotConfig,
        *,
        irc: IRCProtocol | None = None,
        coordinator: CoordinatorProtocol | None = None,
    ) -> None:
        """Build and wire every component; tests may supply the IRC and NATS ends."""
        coordination_key = config.coordination_secret.encode()
        self.config = config
        self.caps = ISupportState()
        self.authorizer = TotpAuthorizer(
            config.totp_secret,
            coordination_secret=coordination_key,
            identity_fold=self.caps.fold_identity,
            scope=(config.bot_id, config.network),
            session_ttl=config.auth_session_ttl,
        )
        self.instance_id = uuid.uuid4().hex
        self.presence = PresenceRegistry(config.presence_ttl)
        self.tasks = Tasks()
        self.callbacks = NATSCallbackHandler(self)
        self._coordinator: CoordinatorProtocol = coordinator or Coordinator(
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
        self.sessions = SessionSync(self.authorizer, self.coordinator, self.tasks)
        self.channel_mgr = ChannelManager(self)
        self.commands = CommandHandler(self)
        self.auth_flow = AuthFlow(self)
        self.health_check = HealthCheck(ready=self.ready, port=config.health_port)
        self.events = IRCEventHandler(self)
        self._irc: IRCProtocol = irc or IRCClient(
            config=IRCClientConfig(
                connect_timeout=config.irc_connect_timeout,
                nickname=config.nickname,
                servers=config.irc_servers,
                verify_tls=config.irc_verify_tls,
            ),
            on_disconnect=self.on_irc_disconnect,
            on_message=self.events.on_irc_message,
        )
        self.identity = SelfIdentity(
            bot_id=config.bot_id,
            coordinator=self.coordinator,
            instance_id=self.instance_id,
            irc=self.irc,
            registry=self.presence,
        )

    @property
    def coordinator(self) -> CoordinatorProtocol:
        """Return the NATS coordinator; fixed at construction for every owner."""
        return self._coordinator

    @property
    def irc(self) -> IRCProtocol:
        """Return the IRC client; fixed at construction for every owner."""
        return self._irc

    async def close(self) -> None:
        """Cancel background tasks and shut down all connections."""
        # Cancel tracked tasks first: a task holding the presence claim's lock
        # would otherwise stall coordinator.close(), which also takes it.
        # Then stop the coordinator's callbacks and drain once more to reap any
        # task a subscription spawned before delivery stopped. The finally keeps
        # teardown atomic so a coordinator.close() error cannot leak the IRC
        # socket or the health port.
        await self.tasks.drain()
        try:
            await self.coordinator.close()
        finally:
            await self.tasks.drain()
            await self.health_check.close()
            await self.irc.close()

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
        if self.identity.registered:
            await self.channel_mgr.retry_pending_parts()
            if self.identity.current is not None:
                await self.identity.announce()
                await self.channel_mgr.join_desired()

        if self.coordinator.ready:
            await self.sessions.retry()
            await self.channel_mgr.retry_pending_records()

        if not self.identity.registered:
            return

        for runtime in tuple(self.channel_mgr.channels.values()):
            if runtime.joined and not self.channel_mgr.is_self_opped(runtime):
                await self.channel_mgr.request_peer("op", runtime.channel)

    def on_irc_disconnect(self) -> None:
        """Clear connection-scoped state when the IRC connection drops."""
        self.events.stop_nick_watch()
        self.channel_mgr.set_casemapping(DEFAULT_CASEMAPPING)
        self.caps.reset()
        self.irc.reset_caps()
        self.channel_mgr.reset()
        self.identity.reset()

    def ready(self) -> bool:
        """Return whether IRC and all coordination dependencies are ready."""
        return (
            self.identity.registered and self.irc.connected and self.coordinator.ready
        )

    async def run(self) -> None:
        """Start all services and run the IRC connection loop until stopped.

        Coordinator startup retries in the background for as long as NATS or
        JetStream is unavailable; the fail-closed boundary is authentication,
        not process liveness, so IRC must not wait on it.
        """
        await self.health_check.start()
        try:
            self.tasks.spawn(self.coordinator.start(), "coordinator-start")
            self.tasks.spawn(self.maintenance_loop(), "maintenance")
            await self.irc.run_forever()
        finally:
            await self.close()


class NATSCallbackHandler:
    """Processes NATS coordination messages and KV watch updates."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    async def on_channel(self, payload: dict[str, Any]) -> None:
        """Apply a channel configuration record from a KV watch update."""
        try:
            record = ChannelRecord.from_dict(payload)
        except TypeError, ValueError:
            return

        await self.bot.channel_mgr.apply_record(record)

    def on_presence(self, presence: BotPresence) -> None:
        """Register or refresh a peer bot's presence record from KV watch."""
        self.bot.presence.update(presence)

    def on_presence_delete(self, bot_id: str) -> None:
        """Remove an expired peer presence from the local registry."""
        self.bot.presence.remove(bot_id)

    def on_session_delete(self, key: str) -> None:
        """Drop the session a deleted KV key held."""
        self.bot.sessions.forget(key)

    def on_session_update(
        self,
        key: str,
        record: dict[str, Any],
        *,
        replaying: bool,
    ) -> None:
        """Apply a validated session record from the KV watch."""
        self.bot.sessions.observe(key, record, replaying=replaying)

    def on_sessions_replayed(self, keys: set[str]) -> None:
        """Drop sessions a completed watch replay no longer contains."""
        self.bot.sessions.replayed(keys)

    def on_invite(self, payload: dict[str, Any]) -> None:
        """Schedule a peer's invite request."""
        channels = self.bot.channel_mgr
        self.bot.tasks.spawn(
            channels.help_after_delay(channels.invite_peer, payload),
            "peer-invite",
        )

    def on_op(self, payload: dict[str, Any]) -> None:
        """Schedule a peer's op request."""
        channels = self.bot.channel_mgr
        self.bot.tasks.spawn(
            channels.help_after_delay(channels.op_peer, payload),
            "peer-op",
        )

    def on_unban(self, payload: dict[str, Any]) -> None:
        """Schedule a peer's unban request."""
        channels = self.bot.channel_mgr
        self.bot.tasks.spawn(
            channels.help_after_delay(channels.unban_peer, payload),
            "peer-unban",
        )
