# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for NATS route and JetStream replica status."""

import asyncio
import io
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

from nats.errors import Error as NatsError
from nats.js.api import ClusterInfo, PeerInfo

from botnats.nats.status import (
    MAX_RESPONSE_BYTES,
    collect,
    route_count,
    stream_info,
)


class NATSStatusTests(unittest.IsolatedAsyncioTestCase):
    """Tests for bounded cluster monitoring and status rendering."""

    async def test_collect_degraded_cluster(self) -> None:
        """Report offline and lagging JetStream replicas."""
        nc = MagicMock(is_connected=True, connected_url=urlparse("nats://nats-1:4222"))
        kv = AsyncMock()
        kv.status.return_value = SimpleNamespace(
            stream_info=SimpleNamespace(
                cluster=ClusterInfo(
                    leader="nats-1",
                    replicas=[
                        PeerInfo(current=True, name="nats-2"),
                        # A stale current flag does not count an offline peer.
                        PeerInfo(
                            current=True,
                            lag=4,
                            name="nats-3",
                            offline=True,
                        ),
                    ],
                ),
                config=SimpleNamespace(num_replicas=3),
            ),
        )

        with patch(
            "botnats.nats.status.route_count",
            AsyncMock(return_value=1),
        ):
            status = await collect(nc, kv, 3, 8222)

        assert status.jetstream == "degraded"
        assert status.lag == 4
        assert status.offline == ("nats-3",)
        assert status.render() == (
            "nats connection=up routes=1 jetstream=degraded leader=nats-1 "
            "replicas=2/3 lag=4 offline=nats-3"
        )

    async def test_collect_healthy_cluster(self) -> None:
        """Report a fully current cluster with a leader as up."""
        nc = MagicMock(is_connected=True, connected_url=urlparse("nats://nats-1:4222"))
        kv = AsyncMock()
        kv.status.return_value = SimpleNamespace(
            stream_info=SimpleNamespace(
                cluster=ClusterInfo(
                    leader="nats-1",
                    # NATS omits a zero lag, so a current peer carries none.
                    replicas=[
                        PeerInfo(current=True, name="nats-2"),
                        PeerInfo(current=True, name="nats-3"),
                    ],
                ),
                config=SimpleNamespace(num_replicas=3),
            ),
        )

        with patch(
            "botnats.nats.status.route_count",
            AsyncMock(return_value=2),
        ):
            status = await collect(nc, kv, 3, 8222)

        assert status.render() == (
            "nats connection=up routes=2 jetstream=up leader=nats-1 replicas=3/3 lag=0"
        )

    async def test_collect_stream_without_cluster(self) -> None:
        """Report a cluster-less stream as up only when it wants one replica."""
        nc = MagicMock(is_connected=True, connected_url=urlparse("nats://nats-1:4222"))
        for replicas, state in ((1, "up"), (3, "degraded")):
            with self.subTest(replicas=replicas):
                kv = AsyncMock()
                kv.status.return_value = SimpleNamespace(
                    stream_info=SimpleNamespace(
                        cluster=None,
                        config=SimpleNamespace(num_replicas=replicas),
                    ),
                )

                with patch(
                    "botnats.nats.status.route_count",
                    AsyncMock(return_value=0),
                ):
                    status = await collect(nc, kv, replicas, 8222)

                assert status.render() == (
                    f"nats connection=up routes=0 jetstream={state} leader=? "
                    f"replicas=1/{replicas} lag=0"
                )

    async def test_collect_unknown_when_disconnected(self) -> None:
        """Return unknown details without monitoring a disconnected client."""
        status = await collect(None, None, 3, 8222)

        assert status.render() == (
            "nats connection=down routes=? jetstream=unknown leader=? "
            "replicas=?/3 lag=?"
        )

    async def test_collect_unknown_when_monitoring_is_unavailable(self) -> None:
        """Keep connection status when cluster monitoring is unavailable."""
        nc = MagicMock(is_connected=True, connected_url=None)

        status = await collect(nc, None, 3, 8222)

        assert status.render() == (
            "nats connection=up routes=? jetstream=unknown leader=? replicas=?/3 lag=?"
        )

    async def test_collect_keeps_routes_without_stream_info(self) -> None:
        """Report the route count even when stream information is unavailable."""
        nc = MagicMock(is_connected=True, connected_url=urlparse("nats://nats-1:4222"))
        kv = AsyncMock()
        kv.status.side_effect = NatsError("timeout")

        with patch(
            "botnats.nats.status.route_count",
            AsyncMock(return_value=2),
        ):
            status = await collect(nc, kv, 3, 8222)

        assert status.render() == (
            "nats connection=up routes=2 jetstream=unknown leader=? replicas=?/3 lag=?"
        )

    async def test_route_count(self) -> None:
        """Parse the route count and connect to the given host and port."""
        for host, location in (("nats-1", "nats-1"), ("::1", "[::1]")):
            with self.subTest(host=host):
                reader = AsyncMock()
                reader.read.side_effect = [
                    b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n",
                    b'{"num_routes":2}',
                    b"",
                ]
                writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())
                connect = AsyncMock(return_value=(reader, writer))

                with patch("botnats.nats.status.asyncio.open_connection", connect):
                    routes = await route_count(host, 8222)

                assert routes == 2
                assert connect.await_args is not None
                assert connect.await_args.args == (host, 8222)
                request = writer.write.call_args.args[0]
                assert f"\r\nHost: {location}\r\n".encode() in request
                writer.close.assert_called_once_with()

    async def test_route_count_unknown_when_unreachable(self) -> None:
        """Report no route count when the monitoring port refuses connections."""
        with patch(
            "botnats.nats.status.asyncio.open_connection",
            AsyncMock(side_effect=ConnectionRefusedError("refused")),
        ):
            routes = await route_count("nats-1", 8222)

        assert routes is None

    async def test_route_count_unknown_when_unanswered(self) -> None:
        """Give up on a monitoring port that accepts but never answers."""
        writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())

        with (
            patch(
                "botnats.nats.status.asyncio.open_connection",
                AsyncMock(return_value=(asyncio.StreamReader(), writer)),
            ),
            patch("botnats.nats.status.STATUS_TIMEOUT", 0),
        ):
            async with asyncio.timeout(5):
                routes = await route_count("nats-1", 8222)

        assert routes is None
        writer.close.assert_called_once_with()

    async def test_route_count_refuses_redirects(self) -> None:
        """Reject a redirect response instead of following it."""
        reader = AsyncMock()
        reader.read.side_effect = [
            b"HTTP/1.0 302 Found\r\nLocation: http://evil.example/\r\n\r\n",
            b'{"num_routes":2}',
            b"",
        ]
        writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())

        with patch(
            "botnats.nats.status.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        ):
            routes = await route_count("nats-1", 8222)

        assert routes is None

    async def test_route_count_rejects_oversized_response(self) -> None:
        """Refuse a monitoring response that exceeds the size limit."""
        # Valid up to the limit: only the size check can reject it.
        response = io.BytesIO(
            b'HTTP/1.0 200 OK\r\n\r\n{"num_routes": 3}' + b" " * MAX_RESPONSE_BYTES,
        )
        reader = AsyncMock()
        reader.read.side_effect = response.read
        writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())

        with patch(
            "botnats.nats.status.asyncio.open_connection",
            AsyncMock(return_value=(reader, writer)),
        ):
            routes = await route_count("nats-1", 8222)

        assert routes is None

    async def test_stream_info_surfaces_programming_errors(self) -> None:
        """Never render a code defect as a transient unknown status."""
        kv = AsyncMock()
        kv.status.side_effect = TypeError("bug")

        with self.assertRaises(TypeError):
            await stream_info(kv)

    async def test_route_count_rejects_deeply_nested_json(self) -> None:
        """Treat a monitoring payload too deep to parse as an unknown count."""
        reader = AsyncMock()
        reader.read.side_effect = [b"HTTP/1.0 200 OK\r\n\r\n", b"[[]]", b""]
        writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())

        # The parser overflows only past the native stack, a depth that varies
        # by platform, so raise its RecursionError directly.
        with (
            patch(
                "botnats.nats.status.asyncio.open_connection",
                AsyncMock(return_value=(reader, writer)),
            ),
            patch(
                "botnats.nats.status.json.loads",
                side_effect=RecursionError("maximum recursion depth exceeded"),
            ) as loads,
        ):
            routes = await route_count("nats-1", 8222)

        assert routes is None
        loads.assert_called_once_with(b"[[]]")

    async def test_route_count_rejects_invalid_payloads(self) -> None:
        """Reject malformed monitoring payloads and impossible route counts."""
        for body in (
            b"[]",
            b'{"num_routes":-1}',
            b'{"num_routes":true}',
            b'{"num_routes":' + b"9" * 5_000 + b"}",
        ):
            with self.subTest(body=body):
                reader = AsyncMock()
                reader.read.side_effect = [b"HTTP/1.0 200 OK\r\n\r\n", body, b""]
                writer = MagicMock(drain=AsyncMock(), wait_closed=AsyncMock())

                with patch(
                    "botnats.nats.status.asyncio.open_connection",
                    AsyncMock(return_value=(reader, writer)),
                ):
                    routes = await route_count("nats-1", 8222)

                assert routes is None
