# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Core NATS messaging and JetStream-backed state coordination."""

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol

import nats
from nats.errors import Error as NatsError

from botnats import error_label
from botnats.config import IDENTIFIER_RE
from botnats.nats.status import NATSStatus, collect
from botnats.nats.store import (
    SESSION_EXPIRY_GRACE,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    PresenceStore,
    SessionStore,
    is_delete,
)
from botnats.presence import BotPresence

if TYPE_CHECKING:
    from nats.aio.msg import Msg

    from botnats.bot import NATSCallbackHandler
    from botnats.nats.envelope import Envelope

LOGGER = logging.getLogger(__name__)

CONNECT_ERRORS = (NatsError, OSError)
DECODE_ERRORS = (RecursionError, TypeError, ValueError)
DECODE_WARNING_INTERVAL = 5.0
OFFER_TIMEOUT = 0.35
PUBLISH_ERRORS = (*CONNECT_ERRORS, RuntimeError)
RECONNECT_WAIT = 1
REQUEST_ERRORS = (*CONNECT_ERRORS, *DECODE_ERRORS)
WATCH_NAMES = frozenset({"watch-channels", "watch-presence", "watch-sessions"})


@dataclass(frozen=True, slots=True)
class NATSConfig:
    """Validated settings for one NATS coordinator."""

    instance_id: str
    monitor_port: int
    network: str
    presence_ttl: float
    replicas: int
    servers: tuple[str, ...]
    session_ttl: float
    token: str = field(repr=False)


class CoordinatorProtocol(Protocol):
    """Structural interface for coordinator implementations."""

    async def close(self) -> None:
        """Close the NATS connection."""
        ...

    async def put_channel(
        self,
        channel: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """Store a channel record and return the authoritative record."""
        ...

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        ...

    async def put_session(
        self,
        identity: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Store an auth session and return the authoritative record."""
        ...

    @property
    def ready(self) -> bool:
        """Return whether Core NATS and JetStream stores are ready."""
        ...

    async def request_auth(self, identity: str) -> bool:
        """Atomically reserve one mesh-wide authentication attempt."""
        ...

    async def request_claim(self, counter: int) -> bool:
        """Atomically claim a TOTP counter."""
        ...

    async def request_offer(
        self,
        base_suffix: str,
        payload: dict[str, Any],
    ) -> bool:
        """Send an offer request and grant the winning responder."""
        ...

    async def start(self) -> None:
        """Connect to NATS and begin processing messages."""
        ...

    async def status(self) -> NATSStatus:
        """Return Core NATS and JetStream cluster status."""
        ...


JsonCallback = Callable[[dict[str, Any]], Awaitable[None]]
OfferCallback = Callable[[dict[str, Any]], bool]


def sender_owns_presence(sender: str, payload: dict[str, Any]) -> bool:
    """Return whether an action payload's presence belongs to its sender."""
    presence = payload.get("presence")
    return isinstance(presence, dict) and presence.get("bot_id") == sender


def _decode_record(value: bytes | None) -> dict[str, Any] | None:
    try:
        data = json.loads(value) if value is not None else None
    except DECODE_ERRORS:
        return None
    return data if isinstance(data, dict) else None


class Coordinator:
    """Reconnectable Core NATS client with JetStream KV state coordination."""

    def __init__(
        self,
        *,
        callbacks: NATSCallbackHandler,
        config: NATSConfig,
        envelope: Envelope,
    ) -> None:
        """Initialize the coordinator with NATS connection parameters."""
        coordination_key = envelope.coordination_key
        self.attempts = AttemptStore(
            config.network,
            config.replicas,
            coordination_key,
        )
        self.callbacks = callbacks
        self.bot_id = envelope.bot_id
        self.channels_store = ChannelStore(
            config.network,
            config.replicas,
            coordination_key,
        )
        self.claims = ClaimStore(
            config.network,
            config.replicas,
            coordination_key,
        )
        self.envelope = envelope
        self.instance_id = config.instance_id
        self.monitor_port = config.monitor_port
        self.nats_servers = config.servers
        self.nats_token = config.token
        self.nc: nats.NATS | None = None
        self.ns = f"botnats.v1.{config.network}"
        self.last_decode_warning = float("-inf")
        self.presence_store = PresenceStore(
            config.network,
            config.replicas,
            config.presence_ttl,
        )
        self.sessions = SessionStore(
            config.network,
            config.replicas,
            coordination_key,
            config.session_ttl,
        )
        self.stores = (
            self.attempts,
            self.channels_store,
            self.claims,
            self.presence_store,
            self.sessions,
        )
        self.last_presence: dict[str, Any] = {
            "bot_id": envelope.bot_id,
            "instance_id": config.instance_id,
        }
        self.owns_presence = False
        self.presence_lock = asyncio.Lock()
        self.presence_revision: int | None = None
        self.session_identities: dict[str, tuple[str, float]] = {}
        self.store_generation = 0
        self.suppressed_warnings = 0
        self.synced_watches: set[str] = set()
        self.unique = True
        self.watch_tasks: list[asyncio.Task[None]] = []

    async def cancel_watches(self) -> None:
        """Cancel all running KV watch tasks and await their completion."""
        tasks = self.watch_tasks
        self.watch_tasks = []
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def close(self) -> None:
        """Close the NATS connection and cancel watches."""
        nc = self.nc
        self.nc = None
        await self.cancel_watches()
        for store in self.stores:
            store.reset()
        if nc is not None and not nc.is_closed:
            await nc.close()

    @property
    def connected(self) -> bool:
        """Return whether the NATS connection is active."""
        return self.nc is not None and self.nc.is_connected

    def decode(
        self,
        message: Msg,
        kind: str = "NATS message",
    ) -> tuple[str, dict[str, Any]] | None:
        """Decode a signed message, logging malformed input consistently."""
        try:
            return self.envelope.decode(message.subject, message.data)
        except DECODE_ERRORS as error:
            self.warn_decode(kind, message.subject, error)
            return None

    def decode_action(
        self,
        message: Msg,
        kind: str = "NATS message",
    ) -> dict[str, Any] | None:
        """Decode an action whose signed sender owns its presence identity."""
        decoded = self.decode(message, kind)
        if decoded is None:
            return None
        sender, payload = decoded
        if not sender_owns_presence(sender, payload):
            self.warn_decode(
                kind,
                message.subject,
                ValueError("sender does not match presence"),
            )
            return None
        return payload

    async def dispatch(self, callback: JsonCallback, message: Msg) -> None:
        """Decode a NATS message and invoke the callback with its payload."""
        if (payload := self.decode_action(message)) is not None:
            await callback(payload)

    async def grant(self, callback: JsonCallback, message: Msg) -> None:
        """Dispatch a targeted grant unless this bot ID conflicts with a peer."""
        if self.ready:
            await self.dispatch(callback, message)

    async def init_stores(self) -> None:
        """Retry JetStream store initialization while Core NATS is connected."""
        nc = self.nc
        if nc is None:
            return
        self.store_generation += 1
        generation = self.store_generation
        js = nc.jetstream()
        while self.nc is nc and nc.is_connected and self.store_generation == generation:
            try:
                for store in self.stores:
                    await store.open(js)
            except PUBLISH_ERRORS as error:
                LOGGER.warning(
                    "JetStream reinitialization failed; retrying: %s",
                    error_label(error),
                )
                await asyncio.sleep(RECONNECT_WAIT)
            else:
                return

    def mark_duplicate(self) -> None:
        """Record a conflicting live instance using this bot ID."""
        if self.unique:
            LOGGER.error("duplicate bot ID detected: %s", self.bot_id)
        self.unique = False

    async def offer(self, callback: OfferCallback, message: Msg) -> None:
        """Evaluate an offer request and respond if eligible."""
        if not self.ready or not message.reply:
            return
        payload = self.decode_action(message, "offer")
        if payload is None:
            return
        if callback(payload):
            await message.respond(self.envelope.encode(message.reply, {}))

    async def on_disconnected(self) -> None:
        """Invalidate JetStream handles when Core NATS disconnects."""
        await self.cancel_watches()
        async with self.presence_lock:
            self.owns_presence = False
            self.presence_revision = None
        for store in self.stores:
            store.reset()

    async def on_error(self, error: Exception) -> None:
        """Log a NATS transport error."""
        LOGGER.warning("NATS error: %s", error_label(error))

    async def on_reconnected(self) -> None:
        """Resynchronize state after a NATS reconnection."""
        LOGGER.info("reconnected to Core NATS")
        await self.init_stores()
        await self.start_watches()

    async def publish(self, suffix: str, payload: dict[str, Any]) -> None:
        """Broadcast a signed message on the given subject suffix."""
        self.require_unique()
        if self.nc is None:
            msg = "NATS is unavailable"
            raise RuntimeError(msg)
        subject = f"{self.ns}.{suffix}"
        await self.nc.publish(subject, self.envelope.encode(subject, payload))

    async def put_channel(
        self,
        channel: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """Store a channel record and return the authoritative record."""
        self.require_unique()
        return await self.channels_store.put(channel, record)

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        if presence.get("bot_id") != self.bot_id:
            msg = "presence does not match coordinator bot ID"
            raise ValueError(msg)
        self.last_presence = presence
        async with self.presence_lock:
            if not self.owns_presence:
                await self.reclaim_presence()
                self.require_unique()
                return
            self.require_unique()
            revision = self.presence_revision
            if revision is not None:
                revision = await self.presence_store.update(
                    self.bot_id,
                    presence,
                    revision,
                )
            if revision is None:
                self.owns_presence = False
                self.presence_revision = None
                self.mark_duplicate()
                self.require_unique()
            self.presence_revision = revision

    async def put_session(
        self,
        identity: str,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Store an auth session and return the authoritative record."""
        self.require_unique()
        return await self.sessions.put(identity, session)

    @property
    def ready(self) -> bool:
        """Return whether Core NATS and JetStream stores are ready."""
        return (
            self.connected
            and all(store.ready for store in self.stores)
            and self.synced_watches == WATCH_NAMES
            and self.owns_presence
            and self.unique
        )

    async def reclaim_presence(self) -> None:
        """Atomically reclaim the presence key while holding presence_lock."""
        was_unique = self.unique
        revision = await self.presence_store.create(
            self.bot_id,
            self.last_presence,
        )
        if revision is not None:
            if not was_unique:
                LOGGER.info("duplicate bot ID conflict resolved: %s", self.bot_id)
            self.owns_presence = True
            self.presence_revision = revision
            self.unique = True
        else:
            self.owns_presence = False
            self.presence_revision = None
            self.mark_duplicate()

    async def request_auth(self, identity: str) -> bool:
        """Atomically reserve one mesh-wide authentication attempt."""
        return self.ready and await self.attempts.allow(identity)

    async def request_claim(self, counter: int) -> bool:
        """Atomically claim a TOTP counter via JetStream; deny on any failure."""
        return self.ready and await self.claims.claim(counter)

    async def request_offer(
        self,
        base_suffix: str,
        payload: dict[str, Any],
    ) -> bool:
        """Send an offer request and grant the winning responder."""
        if (
            not self.ready
            or self.nc is None
            or not sender_owns_presence(self.bot_id, payload)
        ):
            return False
        try:
            subject = f"{self.ns}.{base_suffix}.request"
            response = await self.nc.request(
                subject,
                self.envelope.encode(subject, payload),
                timeout=OFFER_TIMEOUT,
            )
            offer = self.decode(response, "offer response")
            if offer is None:
                return False
            bot_id, response_payload = offer
            if not IDENTIFIER_RE.fullmatch(bot_id) or response_payload:
                return False
            await self.publish(f"{base_suffix}.grant.{bot_id}", payload)
        except REQUEST_ERRORS:
            return False
        else:
            return True

    def require_unique(self) -> None:
        """Require this process to own its unique bot presence."""
        if not self.unique or not self.owns_presence:
            msg = f"duplicate bot ID: {self.bot_id}"
            raise RuntimeError(msg)

    async def run_watch(
        self,
        name: str,
        watch_fn: Callable[[], Awaitable[None]],
    ) -> None:
        """Run a watch coroutine, retrying on errors with backoff."""
        while self.connected:
            self.synced_watches.discard(name)
            try:
                await watch_fn()
            except asyncio.CancelledError:
                raise
            except CONNECT_ERRORS as error:
                if not self.connected:
                    return
                LOGGER.warning("watch %s failed: %s", name, error_label(error))
            except Exception:
                if not self.connected:
                    return
                LOGGER.exception("watch %s crashed", name)
            finally:
                self.synced_watches.discard(name)
            await asyncio.sleep(RECONNECT_WAIT)

    async def start(self) -> None:
        """Connect to NATS, subscribe to subjects, and start KV watches."""
        while self.nc is None:
            try:
                nc = await nats.connect(
                    servers=list(self.nats_servers),
                    token=self.nats_token,
                    name=f"botnats-{self.bot_id}",
                    allow_reconnect=True,
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=RECONNECT_WAIT,
                    disconnected_cb=self.on_disconnected,
                    error_cb=self.on_error,
                    reconnected_cb=self.on_reconnected,
                )
                self.nc = nc
                await self.init_stores()
                await self.subscribe()
            except CONNECT_ERRORS as error:
                LOGGER.warning(
                    "NATS connection failed; retrying: %s",
                    error_label(error),
                )
                if self.nc is not None:
                    with suppress(*PUBLISH_ERRORS):
                        await self.nc.close()
                    self.nc = None
                await asyncio.sleep(RECONNECT_WAIT)
        await self.start_watches()
        LOGGER.info("connected to Core NATS")

    async def start_watches(self) -> None:
        """Launch KV watch background tasks for all state buckets."""
        self.synced_watches.clear()
        await self.cancel_watches()
        watches = (
            ("watch-channels", self.watch_channels),
            ("watch-presence", self.watch_presence),
            ("watch-sessions", self.watch_sessions),
        )
        for name, watch_fn in watches:
            task = asyncio.create_task(self.run_watch(name, watch_fn), name=name)
            self.watch_tasks.append(task)

    def mark_watch_synced(self, name: str) -> None:
        """Record one completed watch replay."""
        self.synced_watches.add(name)

    async def status(self) -> NATSStatus:
        """Return Core NATS and JetStream cluster status."""
        return await collect(
            self.nc,
            self.claims.kv,
            self.claims.replicas,
            self.monitor_port,
        )

    async def subscribe(self) -> None:
        """Subscribe to offer coordination subjects on the active connection."""
        nc = self.nc
        if nc is None:
            return
        grants = (
            ("invite.grant", self.callbacks.on_invite_grant),
            ("op.grant", self.callbacks.on_op_grant),
            ("unban.grant", self.callbacks.on_unban_grant),
        )
        offers = (
            ("invite.request", self.callbacks.on_invite_request),
            ("op.request", self.callbacks.on_op_request),
            ("unban.request", self.callbacks.on_unban_request),
        )
        for suffix, grant_callback in grants:
            await nc.subscribe(
                f"{self.ns}.{suffix}.{self.bot_id}",
                cb=partial(self.grant, grant_callback),
            )
        for suffix, offer_callback in offers:
            await nc.subscribe(
                f"{self.ns}.{suffix}",
                cb=partial(self.offer, offer_callback),
            )

    def warn_decode(self, kind: str, subject: str, error: Exception) -> None:
        """Rate-limit warnings for malformed NATS messages."""
        now = time.monotonic()
        if now - self.last_decode_warning < DECODE_WARNING_INTERVAL:
            self.suppressed_warnings += 1
            return
        suffix = (
            f"; suppressed {self.suppressed_warnings} similar warning(s)"
            if self.suppressed_warnings
            else ""
        )
        LOGGER.warning(
            "ignored malformed %s on %s: %s%s",
            kind,
            subject,
            error_label(error),
            suffix,
        )
        self.last_decode_warning = now
        self.suppressed_warnings = 0

    async def watch_channels(self) -> None:
        """Watch the channels KV bucket and apply record updates."""
        kv = await self.channels_store.open()
        watcher = await kv.watchall()
        try:
            async for entry in watcher:
                if entry is None:
                    self.mark_watch_synced("watch-channels")
                    continue
                if is_delete(entry.operation):
                    continue
                data = _decode_record(entry.value)
                if (
                    data is not None
                    and self.channels_store.order(entry.key, data) is not None
                ):
                    await self.callbacks.on_channel(data)
        finally:
            await watcher.stop()

    async def watch_presence(self) -> None:
        """Watch the presence KV bucket and detect duplicate bot IDs."""
        kv = await self.presence_store.open()
        watcher = await kv.watchall()
        try:
            saw_conflict = False
            async for entry in watcher:
                if entry is None:
                    async with self.presence_lock:
                        if not saw_conflict and not self.owns_presence:
                            await self.reclaim_presence()
                    self.mark_watch_synced("watch-presence")
                    continue
                if is_delete(entry.operation):
                    self.callbacks.on_presence_delete(entry.key)
                    if entry.key == self.bot_id.casefold():
                        async with self.presence_lock:
                            self.owns_presence = False
                            self.presence_revision = None
                            await self.reclaim_presence()
                    continue
                data = _decode_record(entry.value)
                if data is not None and await self.observe_presence(
                    entry.key,
                    data,
                    entry.revision,
                ):
                    saw_conflict = True
        finally:
            await watcher.stop()

    async def observe_presence(
        self,
        key: str,
        data: dict[str, Any],
        revision: int,
    ) -> bool:
        """Apply one presence update and report a duplicate identity."""
        try:
            presence = BotPresence.from_dict(data)
        except TypeError, ValueError:
            return False
        if (
            not IDENTIFIER_RE.fullmatch(presence.bot_id)
            or presence.bot_id.casefold() != key
        ):
            return False
        self.callbacks.on_presence(presence)
        async with self.presence_lock:
            if presence.bot_id.casefold() != self.bot_id.casefold():
                return False
            if presence.instance_id != self.instance_id:
                self.owns_presence = False
                self.presence_revision = None
                self.mark_duplicate()
                return True
            if not self.unique:
                LOGGER.info("duplicate bot ID conflict resolved: %s", self.bot_id)
            self.owns_presence = True
            self.presence_revision = max(self.presence_revision or 0, revision)
            self.unique = True
            return False

    def observe_session(
        self,
        key: str,
        data: dict[str, Any],
        replayed: set[str] | None,
    ) -> None:
        """Apply one session update and retain its unexpired KV-key mapping."""
        prefix = data.get("prefix")
        if not isinstance(prefix, str):
            return
        order = self.sessions.order(prefix, data)
        if order is None or self.sessions.key(prefix) != key:
            return
        now = time.time()
        if replayed is None:
            self.prune_session_identities(now)
        if order[0] > now + self.sessions.ttl + SESSION_EXPIRY_GRACE:
            return
        if replayed is not None:
            replayed.add(key)
        expiry = order[0]
        if expiry > now:
            self.session_identities[key] = (prefix, expiry)
        elif mapped := self.session_identities.pop(key, None):
            self.callbacks.on_session_delete(mapped[0])
        self.callbacks.on_session_update(data)

    async def watch_sessions(self) -> None:
        """Watch the sessions KV bucket and update local auth state."""
        replayed: set[str] | None = set()
        kv = await self.sessions.open()
        watcher = await kv.watchall()
        try:
            async for entry in watcher:
                if entry is None:
                    if replayed is not None:
                        self.prune_session_identities()
                        for key in self.session_identities.keys() - replayed:
                            self.callbacks.on_session_delete(
                                self.session_identities.pop(key)[0],
                            )
                        replayed = None
                    self.mark_watch_synced("watch-sessions")
                    continue
                if is_delete(entry.operation):
                    mapped = self.session_identities.pop(entry.key, None)
                    if mapped is not None:
                        self.callbacks.on_session_delete(mapped[0])
                    continue
                data = _decode_record(entry.value)
                if data is not None:
                    self.observe_session(entry.key, data, replayed)
        finally:
            await watcher.stop()

    def prune_session_identities(self, now: float | None = None) -> None:
        """Discard expired KV-key mappings that receive no TTL delete event."""
        current = time.time() if now is None else now
        self.session_identities = {
            key: mapped
            for key, mapped in self.session_identities.items()
            if mapped[1] > current
        }
