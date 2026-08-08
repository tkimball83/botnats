# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Minimal HTTP liveness and readiness endpoint."""

import asyncio
import logging
from contextlib import suppress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

LOGGER = logging.getLogger(__name__)

RESPONSE_NOT_FOUND = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 9\r\n"
    b"Connection: close\r\n\r\n"
    b"not found"
)

RESPONSE_OK = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n\r\n"
    b"ok"
)

RESPONSE_UNHEALTHY = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 9\r\n"
    b"Connection: close\r\n\r\n"
    b"unhealthy"
)


class HealthCheck:
    """HTTP liveness and readiness server."""

    def __init__(
        self,
        ready: Callable[[], bool],
        port: int = 8080,
    ) -> None:
        """Initialize the server with a readiness callback."""
        self.port = port
        self.ready = ready
        self.server: asyncio.Server | None = None

    async def close(self) -> None:
        """Stop the health check server."""
        server = self.server
        self.server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Respond to a single HTTP request with the current health status."""
        try:
            async with asyncio.timeout(5.0):
                request = await reader.readline()
            target = request.split(maxsplit=2)[1:2]
            path = target[0].partition(b"?")[0] if target else b""
            if path == b"/":
                response = RESPONSE_OK
            elif path == b"/ready":
                response = RESPONSE_OK if self.ready() else RESPONSE_UNHEALTHY
            else:
                response = RESPONSE_NOT_FOUND
            writer.write(response)
            await writer.drain()
        except OSError, ValueError:
            return
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    async def start(self) -> None:
        """Start listening for health check requests."""
        self.server = await asyncio.start_server(
            self.handle,
            host="",
            port=self.port,
        )
        LOGGER.info("health endpoint listening on port %d", self.port)
