# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""NATS monitoring and JetStream replica status."""

import asyncio
import json
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from nats.errors import Error as NatsError

if TYPE_CHECKING:
    from nats.aio.client import Client
    from nats.js.api import StreamInfo
    from nats.js.kv import KeyValue

MAX_RESPONSE_BYTES = 1_048_576
STATUS_TIMEOUT = 1.0


@dataclass(frozen=True, slots=True)
class NATSStatus:
    """Snapshot of Core NATS connectivity and JetStream replica health."""

    connection: bool
    jetstream: str
    lag: int | None
    leader: str | None
    offline: tuple[str, ...]
    replicas_current: int | None
    replicas_total: int
    routes: int | None

    def render(self) -> str:
        """Render a compact IRC status line."""
        fields = [
            f"nats connection={'up' if self.connection else 'down'}",
            f"routes={self.routes if self.routes is not None else '?'}",
            f"jetstream={self.jetstream}",
            f"leader={self.leader or '?'}",
            (
                "replicas="
                f"{self.replicas_current if self.replicas_current is not None else '?'}"
                f"/{self.replicas_total}"
            ),
            f"lag={self.lag if self.lag is not None else '?'}",
        ]
        if self.offline:
            fields.append(f"offline={','.join(self.offline)}")
        return " ".join(fields)


async def collect(
    nc: Client | None,
    kv: KeyValue | None,
    replicas: int,
    monitor_port: int,
) -> NATSStatus:
    """Collect a bounded status snapshot from the active NATS connection."""
    if nc is None or not nc.is_connected:
        return unknown(replicas, connected=False)

    url = nc.connected_url
    host = url.hostname if url is not None else None
    routes, info = await asyncio.gather(
        route_count(host, monitor_port),
        stream_info(kv),
    )
    if info is None:
        return unknown(replicas, connected=True, routes=routes)

    total = info.config.num_replicas or replicas
    if info.cluster is None:
        return NATSStatus(
            connection=True,
            jetstream="up" if total == 1 else "degraded",
            lag=0,
            leader=None,
            offline=(),
            replicas_current=1,
            replicas_total=total,
            routes=routes,
        )

    cluster = info.cluster
    peers = cluster.replicas or ()
    leader = cluster.leader
    current = int(bool(leader)) + sum(
        peer.current is True and peer.offline is not True for peer in peers
    )
    offline = tuple(sorted(peer.name for peer in peers if peer.offline and peer.name))
    lag = max((peer.lag or 0 for peer in peers), default=0)
    state = "up" if leader and current == total and not offline else "degraded"
    return NATSStatus(
        connection=True,
        jetstream=state,
        lag=lag,
        leader=leader,
        offline=offline,
        replicas_current=current,
        replicas_total=total,
        routes=routes,
    )


async def read_response(reader: asyncio.StreamReader) -> bytes:
    """Read a monitoring response without exceeding its size limit."""
    response = bytearray()
    while len(response) <= MAX_RESPONSE_BYTES:
        chunk = await reader.read(min(65_536, MAX_RESPONSE_BYTES + 1 - len(response)))
        if not chunk:
            break
        response.extend(chunk)
    return bytes(response)


async def route_count(host: str | None, port: int) -> int | None:
    """Return the connected server's route count from its monitoring endpoint.

    Uses non-blocking socket I/O so the timeout genuinely cancels a slow read
    and the connection is closed; a bare HTTP/1.0 request with an explicit 200
    status check refuses redirects without following them.
    """
    if host is None:
        return None
    location = f"[{host}]" if ":" in host else host
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(STATUS_TIMEOUT):
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(
                (
                    f"GET /routez?subs=0 HTTP/1.0\r\n"
                    f"Host: {location}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode(),
            )
            await writer.drain()
            response = await read_response(reader)
        if len(response) > MAX_RESPONSE_BYTES:
            return None
        header, separator, body = response.partition(b"\r\n\r\n")
        if not separator or not header.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
            return None
        payload = json.loads(body)
        if not isinstance(payload, dict):
            return None
        value = payload.get("num_routes")
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )
    except OSError, RecursionError, ValueError:
        return None
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()


async def stream_info(kv: KeyValue | None) -> StreamInfo | None:
    """Return the claim bucket stream information within a short timeout."""
    if kv is None:
        return None
    try:
        async with asyncio.timeout(STATUS_TIMEOUT):
            return (await kv.status()).stream_info
    except NatsError, OSError, RuntimeError:
        return None


def unknown(
    replicas: int,
    *,
    connected: bool,
    routes: int | None = None,
) -> NATSStatus:
    """Build a status snapshot whose cluster details are unavailable."""
    return NATSStatus(
        connection=connected,
        jetstream="unknown",
        lag=None,
        leader=None,
        offline=(),
        replicas_current=None,
        replicas_total=replicas,
        routes=routes,
    )
