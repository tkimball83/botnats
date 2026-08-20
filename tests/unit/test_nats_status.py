# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for NATS route and JetStream replica status."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

from nats.js.api import ClusterInfo, PeerInfo

from botnats.nats.status import NATSStatus, collect, route_count, stream_info


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
                        PeerInfo(current=True, lag=0, name="nats-2"),
                        PeerInfo(
                            current=False,
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
                    replicas=[
                        PeerInfo(current=True, lag=0, name="nats-2"),
                        PeerInfo(current=True, lag=0, name="nats-3"),
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

    async def test_collect_single_node(self) -> None:
        """Report a replication-free single-node stream as up."""
        nc = MagicMock(is_connected=True, connected_url=urlparse("nats://nats-1:4222"))
        kv = AsyncMock()
        kv.status.return_value = SimpleNamespace(
            stream_info=SimpleNamespace(
                cluster=None,
                config=SimpleNamespace(num_replicas=1),
            ),
        )

        with patch(
            "botnats.nats.status.route_count",
            AsyncMock(return_value=0),
        ):
            status = await collect(nc, kv, 1, 8222)

        assert status.render() == (
            "nats connection=up routes=0 jetstream=up leader=? replicas=1/1 lag=0"
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

    def test_render_healthy(self) -> None:
        """Render a compact healthy status line."""
        status = NATSStatus(
            connection=True,
            jetstream="up",
            lag=0,
            leader="nats-1",
            offline=(),
            replicas_current=3,
            replicas_total=3,
            routes=2,
        )

        assert status.render() == (
            "nats connection=up routes=2 jetstream=up leader=nats-1 replicas=3/3 lag=0"
        )

    async def test_route_count(self) -> None:
        """Parse the route count and connect to the given host and port."""
        for host in ("nats-1", "::1"):
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
        reader = AsyncMock()
        reader.read.side_effect = lambda n: b"x" * n
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

    async def test_route_count_rejects_invalid_payloads(self) -> None:
        """Reject malformed monitoring payloads and impossible route counts."""
        for body in (
            b"[]",
            b'{"num_routes":-1}',
            b'{"num_routes":true}',
            b"[" * 2_000 + b"]" * 2_000,
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
