# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Process entry point."""

import argparse
import asyncio
import logging
import os
import signal
from contextlib import suppress

from botnats.bot import Bot
from botnats.config import BotConfig


def main() -> None:
    """Parse configuration and launch the bot event loop."""
    parser = argparse.ArgumentParser(description="Run the ephemeral BotNATS IRC bot")
    parser.add_argument(
        "--config",
        default=os.environ.get("BOTNATS_CONFIG", "/etc/botnats/bot.json"),
    )
    arguments = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=os.environ.get("BOTNATS_LOG_LEVEL", "INFO").upper(),
    )
    config = BotConfig.load(arguments.config)

    with suppress(KeyboardInterrupt, asyncio.CancelledError):
        asyncio.run(run(config))


async def run(config: BotConfig) -> None:
    """Run one configured bot until completion or termination."""
    bot = Bot(config)
    task = asyncio.current_task()
    if task is not None:
        with suppress(NotImplementedError):
            asyncio.get_running_loop().add_signal_handler(
                signal.SIGTERM,
                task.cancel,
            )
    await bot.run()


if __name__ == "__main__":
    main()
