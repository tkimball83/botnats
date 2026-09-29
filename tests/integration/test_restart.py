# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify durable state survives a complete NATS cluster restart."""

import asyncio
import json
import os
import time
import uuid
from dataclasses import asdict

import nats
from nats.errors import Error as NatsError
from nats.js.errors import BadRequestError

from botnats.channel import ChannelRecord
from botnats.nats.store import ChannelStore, ClaimStore, SessionStore, session_signature
from tests.integration.test_failover import ignore_error
from tests.unit.helpers import COORDINATION_KEY as SECRET

CHANNEL = "#botnats-restart"
CHANNEL_KEY = "restart-key"
CONNECT_TIMEOUT = 30.0
COUNTER = 987_654_321
SESSION_IDENTITY = "restart!user@host.example"
SESSION_TTL = 3600.0


def session_record(network: str, ttl: float = SESSION_TTL) -> dict[str, object]:
    """Build a session record signed for one network's store."""
    record: dict[str, object] = {
        "expires_at": time.time() + ttl / 2,
        "issuer": "restart-test",
        "prefix": SESSION_IDENTITY,
        "revoked": False,
        "version": 1,
    }
    record["signature"] = session_signature(SECRET, network, record)
    return record


async def connect() -> nats.NATS:
    """Connect after Docker exposes the restarted server's host port."""
    async with asyncio.timeout(CONNECT_TIMEOUT):
        while True:
            try:
                return await nats.connect(
                    os.environ["BOTNATS_TEST_NATS_URL"],
                    connect_timeout=2,
                    error_cb=ignore_error,
                    max_reconnect_attempts=5,
                    token=os.environ["BOTNATS_TEST_NATS_TOKEN"],
                )
            except NatsError, OSError:
                await asyncio.sleep(0.2)


async def mark() -> None:
    """Write a claim, channel, and session that must survive the restart."""
    nc = await connect()
    try:
        claims = ClaimStore("restart-test", 3, SECRET)
        channels = ChannelStore("restart-test", 3, SECRET)
        sessions = SessionStore("restart-test", 3, SECRET, SESSION_TTL)
        await claims.open(nc.jetstream())
        assert await claims.claim(COUNTER)
        await channels.open(nc.jetstream())
        record = asdict(ChannelRecord.new(CHANNEL, CHANNEL_KEY, present=True))
        stored = await channels.put(CHANNEL, record, expected=None)
        assert stored["key"] == CHANNEL_KEY
        await sessions.open(nc.jetstream())
        session = await sessions.put(SESSION_IDENTITY, session_record("restart-test"))
        assert session["prefix"] == SESSION_IDENTITY
    finally:
        await nc.drain()


async def check() -> None:
    """Verify the marked claim, channel, and session after the restart."""
    nc = await connect()
    try:
        claims = ClaimStore("restart-test", 3, SECRET)
        channels = ChannelStore("restart-test", 3, SECRET)
        sessions = SessionStore("restart-test", 3, SECRET, SESSION_TTL)
        # A missing key here can be transient while JetStream replays after
        # the restart, so keep retrying; only a genuine loss (or an elapsed
        # claim TTL) exhausts the timeout, which we surface as a clear error
        # instead of an opaque TimeoutError.
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                while True:
                    try:
                        kv = await claims.open(nc.jetstream())
                        entry = await kv.get(claims.key(COUNTER))
                        channel_kv = await channels.open(nc.jetstream())
                        channel_entry = await channel_kv.get(channels.key(CHANNEL))
                        session_kv = await sessions.open(nc.jetstream())
                        session_entry = await session_kv.get(
                            sessions.key(SESSION_IDENTITY),
                        )
                    except NatsError:
                        await asyncio.sleep(0.5)
                        continue

                    assert entry.value == b"1"
                    assert channel_entry.value is not None
                    channel_record = json.loads(channel_entry.value)
                    assert channel_record["key"] == CHANNEL_KEY
                    assert channel_record["present"] is True
                    assert session_entry.value is not None
                    stored_session = json.loads(session_entry.value)
                    assert stored_session["prefix"] == SESSION_IDENTITY
                    assert stored_session["issuer"] == "restart-test"
                    break
        except TimeoutError:
            msg = "durable state missing after NATS restart"
            raise AssertionError(msg) from None
    finally:
        await nc.drain()


async def ttl_change() -> None:
    """Reopen session buckets under new TTLs without losing their sessions."""
    # Below two minutes the TTL also sets the bucket's duplicate window.
    for old, new in ((SESSION_TTL, SESSION_TTL * 2), (15.0, 30.0)):
        await reopen_with_ttl(old, new)


async def reopen_with_ttl(old: float, new: float) -> None:
    """Change one bucket's TTL; a replica mismatch must still fail."""
    network = f"ttl{uuid.uuid4().hex}"
    nc = await connect()
    try:
        before = SessionStore(network, 3, SECRET, old)
        await before.open(nc.jetstream())
        await before.put(SESSION_IDENTITY, session_record(network, old))

        after = SessionStore(network, 3, SECRET, new)
        kv = await after.open(nc.jetstream())

        info = await nc.jetstream().stream_info(f"KV_{after.bucket}")
        assert info.config.max_age == new
        entry = await kv.get(after.key(SESSION_IDENTITY))
        assert entry.value is not None
        assert json.loads(entry.value)["prefix"] == SESSION_IDENTITY

        # A different replica count is not applied; it fails as before.
        fewer = SessionStore(network, 1, SECRET, new)
        try:
            await fewer.open(nc.jetstream())
        except BadRequestError:
            pass
        else:
            msg = "a replica mismatch opened the bucket"
            raise AssertionError(msg)
    finally:
        await nc.drain()
