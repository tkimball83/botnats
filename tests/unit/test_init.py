# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for package-level helpers and background task ownership."""

import asyncio
import logging
import unittest

from botnats import Tasks, error_label, log_task_failure


async def block() -> None:
    """Wait until cancelled."""
    await asyncio.Event().wait()


async def fail() -> None:
    """Raise as a failing background task would."""
    msg = "boom"
    raise RuntimeError(msg)


async def succeed() -> None:
    """Finish cleanly."""


class ErrorLabelTests(unittest.TestCase):
    """Tests for the error_label helper."""

    def test_error_with_message(self) -> None:
        """Verify error_label returns the message when present."""
        assert error_label(ValueError("boom")) == "boom"

    def test_error_without_message(self) -> None:
        """Verify error_label falls back to the type name."""
        assert error_label(RuntimeError()) == "RuntimeError"


class LogTaskFailureTests(unittest.IsolatedAsyncioTestCase):
    """Tests for logging a finished task's failure."""

    async def test_logs_failure(self) -> None:
        """Log a failed task's error under its label, with the traceback."""
        logger = logging.getLogger("botnats.test")
        task = asyncio.create_task(fail())
        async with asyncio.timeout(5):
            await asyncio.wait([task])

        with self.assertLogs(logger, level="ERROR") as logs:
            log_task_failure(task, logger, "probe")

        assert [record.getMessage() for record in logs.records] == [
            "probe failed: boom"
        ]
        assert logs.records[0].exc_info is not None
        assert logs.records[0].exc_info[1] is task.exception()

    async def test_ignores_cancellation_and_success(self) -> None:
        """Log nothing for a task that was cancelled or finished cleanly."""
        logger = logging.getLogger("botnats.test")
        cancelled = asyncio.create_task(block())
        cancelled.cancel()
        succeeded = asyncio.create_task(succeed())
        async with asyncio.timeout(5):
            await asyncio.wait([cancelled, succeeded])

        with self.assertNoLogs(logger):
            log_task_failure(cancelled, logger, "probe")
            log_task_failure(succeeded, logger, "probe")


class TasksTests(unittest.IsolatedAsyncioTestCase):
    """Tests for spawning, tracking, and draining background tasks."""

    async def test_done_untracks_and_logs_failure(self) -> None:
        """Stop tracking a failed task and log its error by task name."""
        tasks = Tasks()
        with self.assertLogs("botnats", level="ERROR") as logs:
            task = tasks.spawn(fail(), "failing")
            async with asyncio.timeout(5):
                await asyncio.wait([task])

        assert [record.getMessage() for record in logs.records] == [
            "background task failing failed: boom"
        ]
        assert not tasks

    async def test_drain_reaps_tasks_spawned_while_draining(self) -> None:
        """Cancel and await a task that a cancelled task spawns on its way out."""
        tasks = Tasks()
        started = asyncio.Event()

        async def parent() -> None:
            started.set()
            try:
                await block()
            finally:
                tasks.spawn(block(), "child")

        tasks.spawn(parent(), "parent")
        async with asyncio.timeout(5):
            await started.wait()
            await tasks.drain()

        assert not tasks
