# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Ephemeral IRC bot coordination over NATS."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio
    import logging


def error_label(error: Exception) -> str:
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
        logger.error(
            "%s failed: %s",
            label,
            error,
            exc_info=(type(error), error, error.__traceback__),
        )
