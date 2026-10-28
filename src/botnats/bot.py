# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC behavior coordinated through Core NATS and JetStream."""

import asyncio
import logging
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING

from botnats import Tasks
from botnats.auth import AuthFlow, SessionSync, TotpAuthorizer
from botnats.channel import ChannelManager, ChannelRecord
from botnats.commands import CommandHandler
from botnats.events import IRCEventHandler
from botnats.health_check import HealthCheck
from botnats.irc.client import IRCClient, IRCClientConfig
from botnats.irc.protocol import IRCProtocol, ISupportState
from botnats.nats.coordinator import Coordinator, CoordinatorProtocol, NATSConfig
from botnats.nats.envelope import Envelope
from botnats.presence import BotPresence, PresenceRegistry, SelfIdentity

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from botnats.config import BotConfig
    from botnats.nats.store import Session
    from botnats.validators import ChannelFields

LOGGER = logging.getLogger(__name__)
# The most shutdown waits to write revocations still queued.
SHUTDOWN_SYNC_TIMEOUT = 5.0


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
        self.config = config
        self.caps = ISupportState()
        self.authorizer = TotpAuthorizer(
            config.totp_secret,
            coordination_secret=config.coordination_secret,
            identity_fold=self.caps.fold_identity,
            scope=(config.bot_id, config.network),
            session_ttl=config.auth_session_ttl,
        )
        instance_id = uuid.uuid4().hex
        self.presence = PresenceRegistry(config.presence_ttl)
        self.tasks = Tasks()
        self.callbacks = NATSCallbackHandler(self)
        self.coordinator: CoordinatorProtocol = coordinator or Coordinator(
            callbacks=self.callbacks,
            config=NATSConfig(
                instance_id=instance_id,
                monitor_port=config.nats_monitor_port,
                network=config.network,
                presence_ttl=config.presence_ttl,
                replicas=config.jetstream_replicas,
                servers=config.nats_servers,
                session_ttl=config.auth_session_ttl,
                token=config.nats_token,
            ),
            envelope=Envelope(config.bot_id, config.coordination_secret),
        )
        self.sessions = SessionSync(self.authorizer, self.coordinator, self.tasks)
        self.channel_mgr = ChannelManager(self)
        self.commands = CommandHandler(self)
        self.auth_flow = AuthFlow(self)
        self.health_check = HealthCheck(ready=self.ready, port=config.health_port)
        self.events = IRCEventHandler(self)
        self.irc: IRCProtocol = irc or IRCClient(
            caps=self.caps,
            config=IRCClientConfig(
                connect_timeout=config.irc_connect_timeout,
                nickname=config.nickname,
                servers=config.irc_servers,
                verify_tls=config.irc_verify_tls,
            ),
            on_disconnect=self.events.on_irc_disconnect,
            on_message=self.events.on_irc_message,
        )
        self.identity = SelfIdentity(
            bot_id=config.bot_id,
            coordinator=self.coordinator,
            instance_id=instance_id,
            irc=self.irc,
        )

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
            # A revocation still queued would stay valid until it expires for
            # peers that never saw its QUIT or NICK; flush it within one bound.
            with suppress(TimeoutError):
                async with asyncio.timeout(SHUTDOWN_SYNC_TIMEOUT):
                    await self.sessions.flush()

            await self.coordinator.close()
        finally:
            await self.tasks.drain()
            await self.health_check.close()
            await self.irc.close()

    async def maintenance_loop(
        self,
        tick: Callable[[], Awaitable[None]],
        label: str,
    ) -> None:
        """Run a tick on the maintenance interval, surviving its failures."""
        while True:
            await asyncio.sleep(self.config.maintenance_interval)
            try:
                await tick()
            except Exception:
                LOGGER.exception("%s failed", label)

    async def maintenance_tick(self) -> None:
        """Execute one round of session, channel, and op upkeep.

        The presence heartbeat runs in its own loop: a slow durable retry
        here must not delay it past the presence TTL.
        """
        self.authorizer.prune()
        self.presence.prune()
        self.channel_mgr.retry_pending_parts()
        self.channel_mgr.join_desired()
        await self.channel_mgr.request_ops()
        if self.coordinator.ready:
            await self.sessions.retry()
            await self.channel_mgr.retry_pending_keys()

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
            self.tasks.spawn(
                self.maintenance_loop(self.identity.announce, "presence heartbeat"),
                "presence-heartbeat",
            )
            self.tasks.spawn(
                self.maintenance_loop(self.maintenance_tick, "maintenance tick"),
                "maintenance",
            )
            await self.irc.run_forever()
        finally:
            await self.close()


class NATSCallbackHandler:
    """Processes NATS coordination messages and KV watch updates."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    def on_channel(self, fields: ChannelFields) -> None:
        """Apply a validated channel configuration record from the KV watch."""
        self.bot.channel_mgr.apply_record(ChannelRecord(*fields))

    def on_presence(self, presence: BotPresence) -> None:
        """Register or refresh a peer bot's presence record from KV watch."""
        self.bot.presence.update(presence)

    def on_presence_delete(self, bot_id: str) -> None:
        """Remove a deleted peer presence from the local registry."""
        self.bot.presence.remove(bot_id)

    def on_session_delete(self, key: str) -> None:
        """Drop the session a deleted KV key held."""
        self.bot.sessions.forget(key)

    def on_session_update(
        self,
        key: str,
        session: Session,
        *,
        replaying: bool,
    ) -> None:
        """Apply a validated session record from the KV watch."""
        self.bot.sessions.observe(key, session, replaying=replaying)

    def on_sessions_replayed(self, keys: set[str]) -> None:
        """Drop sessions a completed watch replay no longer contains."""
        self.bot.sessions.replayed(keys)

    def on_help(self, kind: str, channel: str, presence: BotPresence) -> None:
        """Schedule a peer's help request."""
        self.bot.tasks.spawn(
            self.bot.channel_mgr.help_after_delay(kind, channel, presence),
            "peer-help",
        )
