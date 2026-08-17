# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for HTTP health check endpoint."""

import asyncio
import socket
import unittest

from botnats.health_check import HealthCheck


class HealthCheckTests(unittest.IsolatedAsyncioTestCase):
    """Tests for health check callable and HTTP responses."""

    async def request(self, health_check: HealthCheck, path: str) -> bytes:
        """Request one health path and return its response."""
        await health_check.start()
        try:
            assert health_check.server is not None
            port = next(
                sock.getsockname()[1]
                for sock in health_check.server.sockets
                if sock.family == socket.AF_INET
            )
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"GET {path} HTTP/1.0\r\n\r\n".encode())
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            return response
        finally:
            await health_check.close()

    async def test_close_is_idempotent(self) -> None:
        """Verify repeated shutdown releases the listening server."""
        health_check = HealthCheck(ready=lambda: True, port=0)
        await health_check.start()

        await health_check.close()
        await health_check.close()

        assert health_check.server is None

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
