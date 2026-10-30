# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for HTTP health check endpoint."""

import asyncio
import ipaddress
import socket
import unittest
from unittest.mock import create_autospec, patch

from botnats.health_check import HealthCheck
from tests.unit.helpers import bounded


class HealthCheckTests(unittest.IsolatedAsyncioTestCase):
    """Tests for health check callable and HTTP responses."""

    async def request(self, health_check: HealthCheck, path: str) -> bytes:
        """Request one health path and return its response."""
        await bounded(health_check.start())
        try:
            assert health_check.server is not None
            port = next(
                sock.getsockname()[1]
                for sock in health_check.server.sockets
                if sock.family == socket.AF_INET
            )
            async with asyncio.timeout(5):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(f"GET {path} HTTP/1.0\r\n\r\n".encode())
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()

            return response
        finally:
            # wait_closed also waits on a handler that never closes its
            # connection, so the shutdown needs its own bound.
            async with asyncio.timeout(5):
                await health_check.close()

    async def test_close_is_idempotent(self) -> None:
        """Verify repeated shutdown stops and releases the listening server."""
        health_check = HealthCheck(ready=lambda: True, port=0)
        await bounded(health_check.start())
        server = health_check.server
        assert server is not None
        self.addAsyncCleanup(bounded, server.wait_closed())
        self.addCleanup(server.close)
        assert server.is_serving()

        async with asyncio.timeout(5):
            await health_check.close()
            await health_check.close()

        assert health_check.server is None
        assert not server.is_serving()

    async def test_listens_on_every_interface(self) -> None:
        """Listen on every interface, so probes from other hosts reach it."""
        health_check = HealthCheck(ready=lambda: True, port=0)
        await bounded(health_check.start())
        self.addAsyncCleanup(bounded, health_check.close())
        assert health_check.server is not None

        hosts = [sock.getsockname()[0] for sock in health_check.server.sockets]

        assert hosts
        assert all(ipaddress.ip_address(host).is_unspecified for host in hosts)

    async def test_request_timeout_closes_connection(self) -> None:
        """Close a connection that sends no request line within the timeout."""
        health_check = HealthCheck(ready=lambda: True, port=0)
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        real_timeout = asyncio.timeout
        delays: list[float | None] = []

        def short_timeout(delay: float | None) -> asyncio.Timeout:
            delays.append(delay)
            return real_timeout(0)

        async with real_timeout(5):
            with patch("asyncio.timeout", short_timeout):
                await health_check.handle(asyncio.StreamReader(), writer)

        assert delays == [5.0]
        writer.write.assert_not_called()
        writer.close.assert_called_once_with()

    async def test_overlong_request_line_closes_connection(self) -> None:
        """Close a connection whose request line overflows the reader limit."""
        health_check = HealthCheck(ready=lambda: True, port=0)
        writer = create_autospec(asyncio.StreamWriter, instance=True)
        reader = asyncio.StreamReader(limit=64)
        reader.feed_data(b"GET /" + b"x" * 128 + b" HTTP/1.0\r\n\r\n")
        reader.feed_eof()

        async with asyncio.timeout(5):
            await health_check.handle(reader, writer)

        writer.write.assert_not_called()
        writer.close.assert_called_once_with()

    async def test_liveness_ignores_dependencies(self) -> None:
        """Verify dependency loss does not fail the liveness endpoint."""
        response = await self.request(HealthCheck(ready=lambda: False, port=0), "/")

        assert response.startswith(b"HTTP/1.1 200")
        assert response.endswith(b"ok")

    async def test_readiness(self) -> None:
        """Verify readiness reflects the dependency callback."""
        ready = await self.request(HealthCheck(ready=lambda: True, port=0), "/ready")
        down = await self.request(HealthCheck(ready=lambda: False, port=0), "/ready")
        queried = await self.request(
            HealthCheck(ready=lambda: False, port=0),
            "/ready?probe=1",
        )

        assert ready.startswith(b"HTTP/1.1 200")
        assert down.startswith(b"HTTP/1.1 503")
        assert down.endswith(b"unhealthy")
        assert queried.startswith(b"HTTP/1.1 503")

    async def test_unknown_path_is_not_healthy(self) -> None:
        """Verify an incorrect probe path does not report liveness."""
        response = await self.request(
            HealthCheck(ready=lambda: True, port=0),
            "/health",
        )

        assert response.startswith(b"HTTP/1.1 404")
        assert response.endswith(b"not found")
