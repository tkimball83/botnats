# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Run the Docker integration scenario: start the mesh, then each phase in order."""

import asyncio
import os
import signal
import sys
import unittest
from asyncio.subprocess import DEVNULL, PIPE
from functools import partial

from tests.integration import (
    test_bot_restart,
    test_failover,
    test_mesh,
    test_recovery,
    test_restart,
    test_ttl_change,
)

BOTS = tuple(sorted(test_mesh.BOTS))
COMPOSE = (
    "docker",
    "compose",
    "--file",
    "tests/integration/compose.yml",
    "--project-name",
    "botnats-test",
)
NATS_NODES = ("nats-1", "nats-2", "nats-3")
# One phase taking longer than this has hung, not just slowed down.
PHASE_TIMEOUT = 600.0
READY_ATTEMPTS = 60
STABLE_READY_CHECKS = 3
# The only copy of the test secrets: compose.yml reads them from here.
TEST_ENVIRONMENT = {
    "BOTNATS_TEST_COORDINATION_SECRET": "coordination-secret-used-only-for-tests",
    "BOTNATS_TEST_NATS_TOKEN": "integration-token",
    "BOTNATS_TEST_TOTP_SECRET": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
}
UP = ("up", "--detach", "--no-build", "--wait", "--wait-timeout", "120")


async def compose(*arguments: str, check: bool = True) -> None:
    """Run one docker compose command, streaming its output."""
    process = await asyncio.create_subprocess_exec(*COMPOSE, *arguments)
    if await process.wait() != 0 and check:
        msg = f"docker compose {' '.join(arguments)} failed"
        raise AssertionError(msg)


async def compose_output(*arguments: str) -> str | None:
    """Run one docker compose command; return its output, or None on failure."""
    process = await asyncio.create_subprocess_exec(
        *COMPOSE,
        *arguments,
        stdout=PIPE,
        stderr=DEVNULL,
    )
    stdout, _ = await process.communicate()
    return stdout.decode().strip() if process.returncode == 0 else None


async def published_address(service: str, port: str) -> str:
    """Return the host address Docker published for a service port."""
    address = await compose_output("port", service, port)
    if not address:
        msg = f"{service} does not publish port {port}"
        raise AssertionError(msg)

    return address


async def publish_nats_addresses() -> None:
    """Export NATS addresses; container restarts remap the published ports."""
    urls = [f"nats://{await published_address(node, '4222')}" for node in NATS_NODES]
    os.environ["BOTNATS_TEST_NATS_URLS"] = ",".join(urls)


async def wait_ready(service: str) -> None:
    """Wait until a bot reports ready on several consecutive checks."""
    stable = 0
    for _ in range(READY_ATTEMPTS):
        ready = await compose_output(
            "exec",
            "-T",
            service,
            "wget",
            "-qO-",
            "http://127.0.0.1:8080/ready",
        )
        stable = stable + 1 if ready == "ok" else 0
        if stable == STABLE_READY_CHECKS:
            return

        await asyncio.sleep(1)

    msg = f"{service} did not become ready"
    raise AssertionError(msg)


async def wait_all_ready() -> None:
    """Wait for every bot to report ready."""
    for bot in BOTS:
        await wait_ready(bot)


async def live_coordinator() -> None:
    """Run the live-NATS coordinator tests against the running cluster."""
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "tests.integration.test_coordinator_live",
    )
    # IsolatedAsyncioTestCase starts its own event loop, so it runs off this one.
    result = await asyncio.to_thread(unittest.TextTestRunner(verbosity=2).run, suite)
    # A test skipped for want of the mesh's environment proved nothing.
    if result.skipped or not result.wasSuccessful():
        msg = "live coordinator tests failed"
        raise AssertionError(msg)


async def node_failover() -> None:
    """Kill the claim-stream leader; claims must survive on the remaining quorum."""
    leader = await test_failover.stream_leader()
    if leader not in NATS_NODES:
        msg = f"unexpected JetStream leader: {leader}"
        raise AssertionError(msg)

    await compose("kill", leader)
    await wait_all_ready()
    await test_failover.claim_after_failover(leader)
    await compose(*UP, leader)
    await publish_nats_addresses()


async def cluster_restart() -> None:
    """Restart every NATS node; durable state must survive."""
    await test_restart.mark()
    await compose("kill", *NATS_NODES)
    await compose(*UP)
    await publish_nats_addresses()
    # Check durable state before waiting on bot readiness so the TTL'd claim
    # is read well inside its TTL; the bots' own recovery is verified after.
    await test_restart.check()
    await wait_all_ready()


async def recovery() -> None:
    """Recover from a ban, a kick, and limits, and keep a session across a restart."""
    await test_recovery.run(partial(compose, "restart"))
    await wait_ready("alpha")


async def serial_replacement() -> None:
    """Replace each bot in turn without losing channels, keys, or ops.

    The last bot is killed, not stopped, so its replacement must outlast the
    presence the dead process left behind; and a key change made while it is
    down must reach it through JetStream.
    """
    *restarted, killed = BOTS
    for bot in restarted:
        await compose("restart", bot)
        await wait_ready(bot)
        await test_bot_restart.run()

    new_key = "rotated-key"
    await compose("kill", killed)
    await test_bot_restart.change_key(new_key)
    await compose(*UP, killed)
    await wait_ready(killed)
    await test_bot_restart.run(new_key)


# The mesh runs before the NATS phases so they put the bots' own durable
# channels and keys at risk; serial replacement then proves the bots rebuild
# that state from JetStream.
PHASES = (
    ("live coordinator", live_coordinator),
    ("three-bot mesh", test_mesh.run),
    ("NATS node failover", node_failover),
    ("full NATS restart", cluster_restart),
    ("session TTL change", test_ttl_change.ttl_change),
    ("ban, kick, limit, invite, and restart recovery", recovery),
    ("serial bot replacement", serial_replacement),
)


async def main() -> None:
    """Start the mesh, run every phase, and always tear the mesh down."""
    # SIGTERM (a cancelled CI job, say) would otherwise kill the process before
    # the teardown below runs; cancelling this task runs it instead.
    task = asyncio.current_task()
    if task is not None:
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)

    os.environ.update(TEST_ENVIRONMENT)
    await compose("down", "--volumes", "--remove-orphans")
    try:
        await compose("build", "alpha")
        await compose(*UP)
        os.environ["BOTNATS_TEST_IRC_ADDRESS"] = await published_address("irc", "6667")
        await publish_nats_addresses()
        for name, phase in PHASES:
            sys.stdout.write(f"\n== {name}\n")
            sys.stdout.flush()
            try:
                async with asyncio.timeout(PHASE_TIMEOUT):
                    await phase()
            except BaseException:
                sys.stdout.write(f"\n== FAILED: {name}\n")
                raise
    except BaseException:
        await compose("logs", "--no-color", check=False)
        raise
    finally:
        await compose("down", "--volumes", "--remove-orphans", check=False)


if __name__ == "__main__":
    asyncio.run(main())
