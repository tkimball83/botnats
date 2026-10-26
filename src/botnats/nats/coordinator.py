# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Core NATS messaging and JetStream-backed state coordination."""

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import nats

from botnats import error_label, log_task_failure
from botnats.nats.claim import PresenceClaim
from botnats.nats.status import NATSStatus, collect
from botnats.nats.store import (
    CONNECT_ERRORS,
    DECODE_ERRORS,
    PUBLISH_ERRORS,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    PresenceStore,
    SessionStore,
    StoreUnavailableError,
    decode_record,
    is_delete,
)
from botnats.presence import BotPresence

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nats.aio.msg import Msg

    from botnats.bot import NATSCallbackHandler
    from botnats.nats.envelope import Envelope

LOGGER = logging.getLogger(__name__)

DECODE_WARNING_INTERVAL = 5.0
TRANSIENT_WARNING_INTERVAL = 60.0
RECONNECT_WAIT = 1
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
        record: dict[str, Any],
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Store a channel record written after expected; return the winner."""
        ...

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        ...

    async def put_session(self, session: dict[str, Any]) -> dict[str, Any]:
        """Store an auth session and return the authoritative record."""
        ...

    @property
    def ready(self) -> bool:
        """Return whether this bot may act on and write coordination state."""
        ...

    async def request_auth(self, identity: str) -> bool:
        """Atomically reserve one mesh-wide authentication attempt."""
        ...

    async def request_claim(self, counter: int) -> bool:
        """Atomically claim a TOTP counter."""
        ...

    async def request_help(self, kind: str, payload: dict[str, Any]) -> None:
        """Broadcast an invite, limit, op, or unban request to every peer."""
        ...

    async def start(self) -> None:
        """Connect to NATS and begin processing messages."""
        ...

    async def status(self) -> NATSStatus:
        """Return Core NATS and JetStream cluster status."""
        ...


def sender_owns_presence(sender: str, payload: dict[str, Any]) -> bool:
    """Return whether an action payload's presence belongs to its sender."""
    presence = payload.get("presence")
    return isinstance(presence, dict) and presence.get("bot_id") == sender


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
        self.config = config
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
        self.claim = PresenceClaim(
            self.presence_store,
            envelope.bot_id,
            config.instance_id,
        )
        self.resync_task: asyncio.Task[None] | None = None
        self.store_generation = 0
        self.synced_watches: set[str] = set()
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
        await self.claim.release()
        for store in self.stores:
            store.reset()

        if nc is not None and not nc.is_closed:
            await nc.close()

    @property
    def connected(self) -> bool:
        """Return whether the NATS connection is active."""
        return self.nc is not None and self.nc.is_connected

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

    async def on_disconnected(self) -> None:
        """Invalidate JetStream handles when Core NATS disconnects."""
        await self.cancel_resync()
        await self.cancel_watches()
        self.claim.reset()
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

        log_task_failure(task, LOGGER, "NATS resynchronization")

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

    async def put_channel(
        self,
        record: dict[str, Any],
        *,
        expected: str | None,
    ) -> dict[str, Any]:
        """Store a channel record written after expected; return the winner."""
        self.claim.require()
        return await self.channels_store.put(record, expected=expected)

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        await self.claim.put(presence)

    async def put_session(self, session: dict[str, Any]) -> dict[str, Any]:
        """Store an auth session and return the authoritative record."""
        self.claim.require()
        return await self.sessions.put(session)

    @property
    def ready(self) -> bool:
        """Return whether this bot may act on and write coordination state.

        Core NATS is connected, every store is open, every watch has replayed
        in full, and this process owns its bot ID's presence key.
        """
        return (
            self.connected
            and all(store.ready for store in self.stores)
            and self.synced_watches == WATCH_NAMES
            and self.claim.owned
        )

    async def try_reclaim(self, transition: Callable[[], Awaitable[None]]) -> None:
        """Run a presence reclaim from a watch, containing transient errors.

        A lost race or transient failure concerns only this key; letting it
        propagate would restart the whole watch and drop readiness for a full
        replay. The next presence heartbeat retries the reclaim.
        """
        try:
            await transition()
        except PUBLISH_ERRORS as error:
            self.warn_transient("presence reclaim failed; awaiting heartbeat", error)

    async def request_auth(self, identity: str) -> bool:
        """Atomically reserve one mesh-wide authentication attempt."""
        return self.ready and await self.attempts.allow(identity)

    async def request_claim(self, counter: int) -> bool:
        """Atomically claim a TOTP counter via JetStream; deny on any failure."""
        return self.ready and await self.claims.claim(counter)

    async def request_help(self, kind: str, payload: dict[str, Any]) -> None:
        """Broadcast an invite, limit, op, or unban request to every peer.

        Each eligible peer acts on its own after a short random delay,
        rechecking IRC state first, so no peer waits on another. Two peers
        answering one request send a duplicate MODE or INVITE, which IRC
        servers treat as a no-op. A lost request is asked again next tick.
        """
        nc = self.nc
        if nc is None or not self.ready:
            return

        subject = f"{self.ns}.{kind}"
        with suppress(*PUBLISH_ERRORS):
            await nc.publish(subject, self.envelope.encode(subject, payload))

    def decode_help(self, message: Msg) -> dict[str, Any] | None:
        """Decode a request whose signed sender owns its presence identity."""
        try:
            sender, payload = self.envelope.decode(message.subject, message.data)
        except DECODE_ERRORS as error:
            self.warn_decode(message.subject, error)
            return None

        if not sender_owns_presence(sender, payload):
            self.warn_decode(
                message.subject,
                ValueError("sender does not match presence"),
            )
            return None

        return payload

    async def deliver_help(self, message: Msg) -> None:
        """Hand a peer's request and its kind to the bot; skip unready or our own."""
        if not self.ready:
            return

        payload = self.decode_help(message)
        if (
            payload is not None
            and payload["presence"]["bot_id"] != self.envelope.bot_id
        ):
            self.callbacks.on_help(message.subject.rpartition(".")[2], payload)

    async def subscribe_help(self) -> None:
        """Subscribe to help requests on the active connection."""
        nc = self.nc
        if nc is None:
            return

        # Help requests are the only subjects in the namespace; the last token
        # names the kind.
        await nc.subscribe(f"{self.ns}.*", cb=self.deliver_help)

    def warn_decode(self, subject: str, error: Exception) -> None:
        """Rate-limit warnings for malformed help requests."""
        suffix = self.should_warn("decode", DECODE_WARNING_INTERVAL)
        if suffix is not None:
            LOGGER.warning(
                "ignored malformed help request on %s: %s%s",
                subject,
                error_label(error),
                suffix,
            )

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
        """Run a watch coroutine, retrying on errors after a fixed wait.

        The generation check ejects a superseded task that survived
        cancellation because a CancelledError was replaced by a transport
        error raised from the watch body's cleanup.
        """
        while self.connected and generation == self.watch_generation:
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
                    servers=list(self.config.servers),
                    token=self.config.token,
                    name=f"botnats-{self.envelope.bot_id}",
                    allow_reconnect=True,
                    max_reconnect_attempts=-1,
                    reconnect_time_wait=RECONNECT_WAIT,
                    disconnected_cb=self.on_disconnected,
                    error_cb=self.on_error,
                    reconnected_cb=self.on_reconnected,
                )
                self.nc = nc
                await self.init_stores()
                await self.subscribe_help()
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
        """Record one completed watch replay."""
        self.synced_watches.add(name)

    async def status(self) -> NATSStatus:
        """Return Core NATS and JetStream cluster status."""
        return await collect(
            self.nc,
            self.claims.kv,
            self.claims.replicas,
            self.config.monitor_port,
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

                data = decode_record(entry.value)
                fields = (
                    self.channels_store.parse(entry.key, data)
                    if data is not None
                    else None
                )
                if fields is not None:
                    self.callbacks.on_channel(fields)
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
                    if not saw_conflict:
                        await self.try_reclaim(self.claim.reclaim)

                    self.mark_watch_synced("watch-presence")
                    continue

                if is_delete(entry.operation):
                    self.callbacks.on_presence_delete(entry.key)
                    if entry.key == self.claim.key:
                        await self.try_reclaim(self.claim.expired)

                    continue

                data = decode_record(entry.value)
                if data is not None and self.observe_presence(
                    entry.key,
                    data,
                    entry.revision,
                ):
                    saw_conflict = True
        finally:
            await watcher.stop()

    def observe_presence(
        self,
        key: str,
        data: dict[str, Any],
        revision: int,
    ) -> bool:
        """Apply one presence update and report a duplicate identity."""
        if not self.presence_store.valid(key, data):
            return False

        duplicate = key == self.claim.key and self.claim.observe(
            data["instance_id"],
            revision,
        )
        try:
            presence = BotPresence.from_dict(data)
        except TypeError, ValueError:
            # A starting process claims its key before it knows its IRC
            # identity: a duplicate to detect, not yet a peer to record.
            return duplicate

        self.callbacks.on_presence(presence)
        return duplicate

    async def watch_sessions(self) -> None:
        """Watch the sessions KV bucket and report validated records by key."""
        replayed: set[str] | None = set()
        kv = await self.sessions.open()
        watcher = await kv.watchall()
        try:
            async for entry in watcher:
                if entry is None:
                    if replayed is not None:
                        self.callbacks.on_sessions_replayed(replayed)
                        replayed = None

                    self.mark_watch_synced("watch-sessions")
                    continue

                if is_delete(entry.operation):
                    self.callbacks.on_session_delete(entry.key)
                    continue

                data = decode_record(entry.value)
                session = (
                    self.sessions.parse(entry.key, data) if data is not None else None
                )
                if session is None:
                    continue

                if replayed is not None:
                    replayed.add(entry.key)

                self.callbacks.on_session_update(
                    entry.key,
                    session,
                    replaying=replayed is not None,
                )
        finally:
            await watcher.stop()
