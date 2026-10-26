# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the process entry point."""

import asyncio
import io
import json
import logging
import os
import signal
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

from botnats.__main__ import main, run
from botnats.config import BotConfig
from tests.unit.helpers import CONFIG, SECRETS, config


class MainTests(unittest.TestCase):
    """Tests for startup, and startup errors reported as usage errors."""

    def run_main(self, config_path: Path, log_level: str = "INFO") -> str:
        """Run main() until it exits with a usage error; return the error."""
        stderr = io.StringIO()
        with (
            patch.object(sys, "argv", ["botnats", "--config", str(config_path)]),
            patch.dict(os.environ, {**SECRETS, "BOTNATS_LOG_LEVEL": log_level}),
            patch("botnats.__main__.logging.basicConfig"),
            patch("botnats.__main__.asyncio.run") as run_loop,
            patch("botnats.__main__.run") as run_bot,
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            main()

        assert raised.exception.code == 2
        run_loop.assert_not_called()
        run_bot.assert_not_called()
        # The program name argparse prints depends on how the tests run.
        _, separator, error = stderr.getvalue().splitlines()[-1].partition(": error: ")
        assert separator
        return error

    def test_invalid_configuration_is_a_usage_error(self) -> None:
        """Report an unreadable or invalid configuration instead of raising."""
        bad_nickname = json.loads(CONFIG)
        bad_nickname["bot"]["nickname"] = "1bad"
        for label, content, message in (
            ("missing file", None, "No such file or directory"),
            ("invalid JSON", "{", "Expecting property name"),
            ("not an object", "[]", "configuration must be an object"),
            (
                "invalid value",
                json.dumps(bad_nickname),
                "bot.nickname is not a valid IRC nickname",
            ),
        ):
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "bot.json")
                if content is not None:
                    path.write_text(content)

                error = self.run_main(path)

                assert error.startswith("invalid configuration: ")
                assert message in error

    def test_invalid_log_level_is_a_usage_error(self) -> None:
        """Reject an unknown BOTNATS_LOG_LEVEL before loading configuration."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_bytes(CONFIG)

            error = self.run_main(path, log_level="loud")

        assert error == "BOTNATS_LOG_LEVEL is not a valid log level: LOUD"

    def test_valid_configuration_runs_the_bot(self) -> None:
        """Run the bot for the loaded configuration on a new event loop."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_bytes(CONFIG)
            with (
                patch.object(sys, "argv", ["botnats", "--config", str(path)]),
                patch.dict(os.environ, {**SECRETS, "BOTNATS_LOG_LEVEL": "debug"}),
                patch("botnats.__main__.logging.basicConfig") as basic_config,
                patch("botnats.__main__.asyncio.run") as run_loop,
                patch("botnats.__main__.run", new_callable=MagicMock) as run_bot,
            ):
                main()
                loaded = BotConfig.load(path)

        run_bot.assert_called_once_with(loaded)
        run_loop.assert_called_once_with(run_bot.return_value)
        assert basic_config.call_args.kwargs["level"] == logging.DEBUG


class RunTests(unittest.IsolatedAsyncioTestCase):
    """Tests for running one configured bot until termination."""

    async def test_sigterm_cancels_the_running_bot(self) -> None:
        """Cancel the task running the bot on SIGTERM, so the bot shuts down."""
        started = asyncio.Event()

        async def serve() -> None:
            started.set()
            await asyncio.Event().wait()

        loop = asyncio.get_running_loop()
        with (
            patch("botnats.__main__.Bot") as bot_class,
            patch.object(loop, "add_signal_handler") as add_signal_handler,
        ):
            bot_class.return_value.run = serve
            task = asyncio.create_task(run(config()))
            async with asyncio.timeout(1):
                await started.wait()

            bot_class.assert_called_once_with(config())
            add_signal_handler.assert_called_once()
            signum, handler = add_signal_handler.call_args.args
            assert signum == signal.SIGTERM
            handler()
            with self.assertRaises(asyncio.CancelledError):
                async with asyncio.timeout(1):
                    await task

        assert task.cancelled()
