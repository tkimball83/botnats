# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Core NATS messaging and JetStream-backed state coordination."""

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from contextvars import ContextVar
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
    StoreUnavailableError,
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
TRANSIENT_WARNING_INTERVAL = 60.0
PUBLISH_ERRORS = (*CONNECT_ERRORS, RuntimeError)
RECONNECT_WAIT = 1
REQUEST_ERRORS = (*CONNECT_ERRORS, *DECODE_ERRORS, RuntimeError)
WATCH_NAMES = frozenset({"watch-channels", "watch-presence", "watch-sessions"})

# Task-local generation of the running watch, None outside watch tasks.
WATCH_GENERATION: ContextVar[int | None] = ContextVar(
    "WATCH_GENERATION",
    default=None,
)


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
        self.transient_warnings: dict[str, tuple[float, int]] = {}
        self.presence_store = PresenceStore(
            config.network,
            config.replicas,
            config.presence_ttl,
            coordination_key,
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
            "host": "",
            "instance_id": config.instance_id,
            "nick": "",
            "user": "",
        }
        self.owns_presence = False
        self.presence_lock = asyncio.Lock()
        self.presence_revision: int | None = None
        self.resync_task: asyncio.Task[None] | None = None
        self.session_identities: dict[str, tuple[str, float]] = {}
        self.store_generation = 0
        self.synced_watches: set[str] = set()
        self.unique = True
        self.watch_generation = 0
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
        await self.cancel_resync()
        await self.cancel_watches()
        async with self.presence_lock:
            revision = self.presence_revision
            if self.owns_presence and revision is not None:
                with suppress(*PUBLISH_ERRORS):
                    await self.presence_store.delete(self.bot_id, revision)
            self.owns_presence = False
            self.presence_revision = None
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
        if self.unique and self.owns_presence:
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
                self.warn_transient(
                    "JetStream reinitialization failed; retrying",
                    error,
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
        # The reply subject is an unsigned NATS header; accepting only inbox
        # replies keeps a replayed request from minting a signed envelope
        # bound to an arbitrary coordination subject.
        if not self.ready or not message.reply.startswith("_INBOX."):
            return
        payload = self.decode_action(message, "offer")
        if payload is None:
            return
        if callback(payload):
            try:
                await message.respond(self.envelope.encode(message.reply, {}))
            except PUBLISH_ERRORS as error:
                self.warn_transient("offer response failed", error)

    async def on_disconnected(self) -> None:
        """Invalidate JetStream handles when Core NATS disconnects."""
        await self.cancel_resync()
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
        """Resynchronize state after a NATS reconnection.

        Runs as a background task: init_stores retries for as long as
        JetStream stays down, and blocking here would park the nats-py
        callback runner for the whole outage.
        """
        LOGGER.info("reconnected to Core NATS")
        await self.cancel_resync()
        self.resync_task = asyncio.create_task(self.resync(), name="nats-resync")
        self.resync_task.add_done_callback(self.resync_done)

    def resync_done(self, task: asyncio.Task[None]) -> None:
        """Surface a failed resynchronization instead of losing it to GC."""
        if self.resync_task is task:
            self.resync_task = None
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error(
                "NATS resynchronization failed: %s",
                error,
                exc_info=(type(error), error, error.__traceback__),
            )

    async def resync(self) -> None:
        """Reopen JetStream stores and restart watches after a reconnect."""
        await self.init_stores()
        await self.start_watches()

    async def cancel_resync(self) -> None:
        """Cancel an in-flight reconnect resynchronization task."""
        task = self.resync_task
        self.resync_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

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
        async with self.presence_lock:
            self.last_presence = presence
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
                await self.reclaim_presence()
                self.require_unique()
                return
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
        if revision is None:
            # The key is occupied: adopt this instance's own still-live record
            # after a reconnect, or overwrite an unsigned or forged clobber; a
            # validly signed foreign record leaves revision None (a duplicate).
            # A transient store error propagates to the caller's retry path
            # instead of being misread as a duplicate bot ID.
            revision = await self.presence_store.reclaim(
                self.bot_id,
                self.last_presence,
                self.instance_id,
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

    async def try_reclaim_presence(self) -> None:
        """Reclaim presence from a watch, containing transient store errors.

        A lost-race or transient failure concerns only this key; letting it
        propagate would restart the whole watch and drop readiness for a full
        replay. The next presence heartbeat retries the reclaim.
        """
        try:
            await self.reclaim_presence()
        except PUBLISH_ERRORS as error:
            self.warn_transient("presence reclaim failed; awaiting heartbeat", error)

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

    def discard_watch_synced(self, name: str, generation: int) -> None:
        """Invalidate one watch's replay marker unless it was superseded."""
        if generation == self.watch_generation:
            self.synced_watches.discard(name)

    async def run_watch(
        self,
        name: str,
        watch_fn: Callable[[], Awaitable[None]],
        generation: int,
    ) -> None:
        """Run a watch coroutine, retrying on errors with backoff.

        The generation check ejects a superseded task that survived
        cancellation because a CancelledError was replaced by a transport
        error raised from the watch body's cleanup.
        """
        WATCH_GENERATION.set(generation)
        while self.connected and generation == self.watch_generation:
            self.discard_watch_synced(name, generation)
            try:
                await watch_fn()
            except asyncio.CancelledError:
                raise
            except (*CONNECT_ERRORS, StoreUnavailableError) as error:
                if not self.connected:
                    return
                self.warn_transient(f"watch {name} failed", error)
            except Exception:
                if not self.connected:
                    return
                suffix = self.should_warn(f"watch {name} crashed")
                if suffix is not None:
                    LOGGER.exception("watch %s crashed%s", name, suffix)
            finally:
                self.discard_watch_synced(name, generation)
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
        self.watch_generation += 1
        generation = self.watch_generation
        self.synced_watches.clear()
        await self.cancel_watches()
        if self.watch_generation != generation:
            return
        watches = (
            ("watch-channels", self.watch_channels),
            ("watch-presence", self.watch_presence),
            ("watch-sessions", self.watch_sessions),
        )
        for name, watch_fn in watches:
            task = asyncio.create_task(
                self.run_watch(name, watch_fn, generation),
                name=name,
            )
            self.watch_tasks.append(task)

    def mark_watch_synced(self, name: str) -> None:
        """Record one completed watch replay unless the watch is superseded."""
        generation = WATCH_GENERATION.get()
        if generation is None or generation == self.watch_generation:
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

    def should_warn(
        self,
        context: str,
        interval: float = TRANSIENT_WARNING_INTERVAL,
    ) -> str | None:
        """Claim one rate-limited log slot for a context.

        Returns the suppression suffix to append when the context may log
        now, or None while it is throttled. Crash tracebacks share this
        throttle: a deterministic bug retried every second must not flood
        the log with one traceback per attempt.
        """
        now = time.monotonic()
        last, suppressed = self.transient_warnings.get(context, (float("-inf"), 0))
        if now - last < interval:
            self.transient_warnings[context] = (last, suppressed + 1)
            return None
        self.transient_warnings[context] = (now, 0)
        return f"; suppressed {suppressed} similar warning(s)" if suppressed else ""

    def warn_transient(self, context: str, error: Exception) -> None:
        """Rate-limit warnings per context for repeating transient failures."""
        suffix = self.should_warn(context)
        if suffix is not None:
            LOGGER.warning("%s: %s%s", context, error_label(error), suffix)

    def warn_decode(self, kind: str, subject: str, error: Exception) -> None:
        """Rate-limit warnings for malformed NATS messages."""
        suffix = self.should_warn("decode", DECODE_WARNING_INTERVAL)
        if suffix is not None:
            LOGGER.warning(
                "ignored malformed %s on %s: %s%s",
                kind,
                subject,
                error_label(error),
                suffix,
            )

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
                            await self.try_reclaim_presence()
                    self.mark_watch_synced("watch-presence")
                    continue
                if is_delete(entry.operation):
                    self.callbacks.on_presence_delete(entry.key)
                    if entry.key == self.bot_id.casefold():
                        async with self.presence_lock:
                            self.owns_presence = False
                            self.presence_revision = None
                            await self.try_reclaim_presence()
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
            or not self.presence_store.valid(data)
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
            self.callbacks.on_session_update(data)
        elif mapped := self.session_identities.pop(key, None):
            self.callbacks.on_session_delete(mapped[0])

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
