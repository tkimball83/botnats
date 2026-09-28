# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Ephemeral IRC bot coordination over NATS."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Coroutine

LOGGER = logging.getLogger(__name__)


def error_label(error: BaseException) -> str:
    """Return a description of the error, falling back to the type name."""
    return str(error) or type(error).__name__


def log_task_failure(
    task: asyncio.Task[None],
    logger: logging.Logger,
    label: str,
) -> None:
    """Log an unhandled exception from a done callback, ignoring cancellation."""
    if task.cancelled():
        return

    error = task.exception()
    if error is not None:
        logger.error("%s failed: %s", label, error_label(error), exc_info=error)


class Tasks(set[asyncio.Task[None]]):
    """Own background tasks: start them, log their failures, and cancel them."""

    def spawn(
        self,
        coroutine: Coroutine[Any, Any, None],
        name: str,
    ) -> asyncio.Task[None]:
        """Start a tracked background task and return it."""
        task = asyncio.create_task(coroutine, name=name)
        self.add(task)
        task.add_done_callback(self.done)
        return task

    def done(self, task: asyncio.Task[None]) -> None:
        """Stop tracking a finished task and log its failure, if any."""
        self.discard(task)
        log_task_failure(task, LOGGER, f"background task {task.get_name()}")

    async def drain(self) -> None:
        """Cancel and await every tracked task, including any they spawn."""
        while self:
            tasks = tuple(self)
            for task in tasks:
                task.cancel()

            await asyncio.gather(*tasks, return_exceptions=True)
