# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Core NATS messaging and JetStream-backed state coordination."""

import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol

import nats

from botnats import Tasks, error_label, log_task_failure
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
    decode_record,
    is_delete,
)
from botnats.presence import BotPresence

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from nats.aio.msg import Msg
    from nats.js.kv import KeyValue

    from botnats.bot import NATSCallbackHandler
    from botnats.nats.envelope import Envelope
    from botnats.nats.store import Session
    from botnats.validators import ChannelFields

    # Each KV watch, by name; it calls its argument once its replay is complete.
    type Watch = Callable[[Callable[[], None]], Awaitable[None]]

LOGGER = logging.getLogger(__name__)

DECODE_WARNING_INTERVAL = 5.0
MAX_OUTSTANDING_PINGS = 2
TRANSIENT_WARNING_INTERVAL = 60.0
RECONNECT_WAIT = 1


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


class PresenceWriter(Protocol):
    """Writes this bot's presence heartbeat."""

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        ...


class SessionWriter(Protocol):
    """Writes durable session mutations."""

    async def put_session(self, session: dict[str, Any]) -> Session:
        """Store an auth session and return the authoritative session."""
        ...


class CoordinatorProtocol(PresenceWriter, SessionWriter, Protocol):
    """Structural interface for coordinator implementations."""

    async def close(self) -> None:
        """Close the NATS connection."""
        ...

    async def put_channel(
        self,
        record: dict[str, Any],
        *,
        after: str | None,
    ) -> ChannelFields:
        """Store a channel record written after a revision; return the winner."""
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
        # Startup and a restart after nats-py closed the client never overlap.
        self.start_lock = asyncio.Lock()
        self.store_generation = 0
        self.synced_watches: set[str] = set()
        self.watch_generation = 0
        self.watch_tasks: list[asyncio.Task[None]] = []
        self.watcher_stops = Tasks()

    async def cancel_watches(self) -> None:
        """Cancel all running KV watch tasks and await their completion."""
        tasks = self.watch_tasks
        self.watch_tasks = []
        for task in tasks:
            task.cancel()

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

        if nc is not None:
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
        while nc.is_connected and self.store_generation == generation:
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

    async def on_closed(self) -> None:
        """Start over when nats-py closes the client for good.

        A server error, such as one for a rotated token, closes the client
        without reconnecting. close() drops the client first, so a client
        still held here was not closed on purpose. nats-py runs the
        disconnect callback just before this one, so no resync is left.
        """
        if self.nc is None:
            return

        self.nc = None
        self.resync_task = asyncio.create_task(self.start(), name="nats-restart")
        self.resync_task.add_done_callback(self.resync_done)

    async def on_error(self, error: Exception) -> None:
        """Log a NATS error, tracing one the help callback raised.

        nats-py reports transport errors, which repeat during an outage, and
        exceptions from subscription callbacks, which are bugs. Each keeps its
        own throttle, so an outage cannot hide a bug.
        """
        if isinstance(error, CONNECT_ERRORS):
            self.warn_transient("NATS error", error)
            return

        suffix = self.should_warn("NATS callback crashed")
        if suffix is not None:
            LOGGER.error("NATS callback crashed%s", suffix, exc_info=error)

    async def on_reconnected(self) -> None:
        """Resynchronize state after a NATS reconnection.

        Runs as a background task: init_stores retries for as long as
        JetStream stays down, and blocking here would park the nats-py
        callback runner for the whole outage. The disconnect callback that
        began this reconnect left no resync behind.
        """
        LOGGER.info("reconnected to Core NATS")
        self.resync_task = asyncio.create_task(self.resync(), name="nats-resync")
        self.resync_task.add_done_callback(self.resync_done)

    def resync_done(self, task: asyncio.Task[None]) -> None:
        """Surface a failed resynchronization or restart instead of losing it."""
        if self.resync_task is task:
            self.resync_task = None

        log_task_failure(task, LOGGER, "NATS resynchronization")

    async def resync(self) -> None:
        """Reopen JetStream stores and restart watches after a reconnect."""
        await self.init_stores()
        await self.start_watches()

    async def cancel_resync(self) -> None:
        """Cancel an in-flight resynchronization or restart task."""
        task = self.resync_task
        if task is None:
            return

        self.resync_task = None
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def put_channel(
        self,
        record: dict[str, Any],
        *,
        after: str | None,
    ) -> ChannelFields:
        """Store a channel record written after a revision; return the winner."""
        self.claim.require()
        return await self.channels_store.put(record, after=after)

    async def put_presence(self, presence: dict[str, Any]) -> None:
        """Store or refresh bot presence in JetStream KV."""
        await self.claim.put(presence)

    async def put_session(self, session: dict[str, Any]) -> Session:
        """Store an auth session and return the authoritative session."""
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
            and self.synced_watches == self.watches().keys()
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

    def decode_help(self, message: Msg) -> tuple[str, BotPresence] | None:
        """Decode a request's channel and the presence of the bot that signed it."""
        try:
            sender, payload = self.envelope.decode(message.subject, message.data)
            channel = payload["channel"]
            presence = BotPresence.from_dict(payload["presence"])
            if not isinstance(channel, str):
                msg = "help request names no channel"
                raise TypeError(msg)

            if presence.bot_id != sender:
                msg = "sender does not match presence"
                raise ValueError(msg)
        except (*DECODE_ERRORS, KeyError) as error:
            self.warn_decode(message.subject, error)
            return None

        return channel, presence

    async def deliver_help(self, message: Msg) -> None:
        """Hand a peer's request and its kind to the bot; skip unready or our own."""
        if not self.ready:
            return

        request = self.decode_help(message)
        if request is not None and request[1].bot_id != self.envelope.bot_id:
            channel, presence = request
            kind = message.subject.rpartition(".")[2]
            self.callbacks.on_help(kind, channel, presence)

    async def subscribe_help(self, nc: nats.NATS) -> None:
        """Subscribe a new client to help requests."""
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

    async def run_watch(self, name: str, watch_fn: Watch, generation: int) -> None:
        """Run a watch coroutine, retrying on errors after a fixed wait.

        The generation check ejects a superseded task that survived
        cancellation because a CancelledError was replaced by a transport
        error raised from the watch body's cleanup.
        """
        while self.connected and generation == self.watch_generation:
            try:
                await watch_fn(partial(self.synced_watches.add, name))
            except PUBLISH_ERRORS as error:
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
        async with self.start_lock:
            # A restart queued behind a start that has since connected.
            if self.nc is not None:
                return

            # nats-py drops a silent server on the ping after
            # MAX_OUTSTANDING_PINGS unanswered ones. Spacing those pings across
            # the presence TTL fails over by about when peers expire this bot;
            # nats-py takes whole seconds.
            ping_interval = max(
                1,
                int(self.config.presence_ttl / (MAX_OUTSTANDING_PINGS + 1)),
            )
            # nats-py retries the connection itself. A client it closes for
            # good while the stores open is dropped by on_closed; connect again.
            while self.nc is None:
                nc = await nats.connect(
                    servers=list(self.config.servers),
                    token=self.config.token,
                    name=f"botnats-{self.envelope.bot_id}",
                    allow_reconnect=True,
                    max_outstanding_pings=MAX_OUTSTANDING_PINGS,
                    max_reconnect_attempts=-1,
                    ping_interval=ping_interval,
                    reconnect_time_wait=RECONNECT_WAIT,
                    closed_cb=self.on_closed,
                    disconnected_cb=self.on_disconnected,
                    error_cb=self.on_error,
                    reconnected_cb=self.on_reconnected,
                )
                self.nc = nc
                # Before JetStream: a drop while it is down cancels a restart,
                # and nats-py replays only subscriptions it holds.
                await self.subscribe_help(nc)
                await self.init_stores()

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

        for name, watch_fn in self.watches().items():
            task = asyncio.create_task(
                self.run_watch(name, watch_fn, generation),
                name=name,
            )
            self.watch_tasks.append(task)

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

    def watches(self) -> dict[str, Watch]:
        """Return every KV watch by name; readiness needs each one's replay."""
        return {
            "watch-channels": self.watch_channels,
            "watch-presence": self.watch_presence,
            "watch-sessions": self.watch_sessions,
        }

    async def open_watcher(self, kv: KeyValue) -> KeyValue.KeyWatcher:
        """Watch every key of a bucket, stopping the watcher if cancelled first.

        nats-py subscribes before its setup round trip and keeps the
        subscription when cancelled there, replaying it on every reconnect. The
        setup runs as its own task instead, which cancelling the watch leaves
        running: a cancelled watch leaves at once, and a background task stops
        the watcher once it is set up. Unlike asyncio.shield, waiting this way
        logs nothing when a setup that outlived its watch fails.
        """
        setup = asyncio.create_task(kv.watchall())
        try:
            await asyncio.wait({setup})
        except asyncio.CancelledError:
            self.watcher_stops.spawn(stop_watcher(setup), "stop-watcher")
            raise

        return setup.result()

    async def watch_channels(self, synced: Callable[[], None]) -> None:
        """Watch the channels KV bucket and apply record updates."""
        kv = await self.channels_store.open()
        watcher = await self.open_watcher(kv)
        try:
            async for entry in watcher:
                if entry is None:
                    synced()
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

    async def watch_presence(self, synced: Callable[[], None]) -> None:
        """Watch the presence KV bucket and detect duplicate bot IDs."""
        kv = await self.presence_store.open()
        watcher = await self.open_watcher(kv)
        try:
            async for entry in watcher:
                if entry is None:
                    # Yields to a duplicate the replay showed if it still
                    # holds the key, and resolves it if it has expired since.
                    await self.try_reclaim(self.claim.reclaim)
                    synced()
                    continue

                if is_delete(entry.operation):
                    self.callbacks.on_presence_delete(entry.key)
                    if entry.key == self.claim.key:
                        await self.try_reclaim(self.claim.deleted)

                    continue

                data = decode_record(entry.value)
                if data is not None:
                    self.observe_presence(entry.key, data, entry.revision)
        finally:
            await watcher.stop()

    def observe_presence(
        self,
        key: str,
        data: dict[str, Any],
        revision: int,
    ) -> None:
        """Apply one presence update, including one on this bot's own key."""
        if not self.presence_store.valid(key, data):
            return

        if key == self.claim.key:
            self.claim.observe(data["instance_id"], revision)

        try:
            presence = BotPresence.from_dict(data)
        except ValueError:
            # A starting process claims its key before it knows its IRC
            # identity: a duplicate to detect, not yet a peer to record.
            return

        self.callbacks.on_presence(presence)

    async def watch_sessions(self, synced: Callable[[], None]) -> None:
        """Watch the sessions KV bucket and report validated records by key."""
        replayed: set[str] | None = set()
        kv = await self.sessions.open()
        watcher = await self.open_watcher(kv)
        try:
            async for entry in watcher:
                if entry is None:
                    if replayed is not None:
                        self.callbacks.on_sessions_replayed(replayed)
                        replayed = None

                    synced()
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


async def stop_watcher(setup: asyncio.Task[KeyValue.KeyWatcher]) -> None:
    """Stop a watcher once its setup completes; a failed setup leaves none."""
    with suppress(*PUBLISH_ERRORS):
        watcher = await setup
        await watcher.stop()
