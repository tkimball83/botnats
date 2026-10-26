# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify durable state survives a complete NATS cluster restart."""

import asyncio
import json
import time
from dataclasses import asdict

from nats.errors import Error as NatsError

from botnats.channel import ChannelRecord
from botnats.nats.store import ChannelStore, ClaimStore, SessionStore, session_signature
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    connect,
    coordination_key,
)

CHANNEL = "#botnats-restart"
CHANNEL_KEY = "restart-key"
COUNTER = 987_654_321
# JetStream may still be replaying streams just after the cluster restarts.
REPLAY_TIMEOUT = 30.0
SESSION_IDENTITY = "restart!user@host.example"
SESSION_TTL = 3600.0


def session_record(
    network: str,
    expires_at: float,
    *,
    revoked: bool = False,
    version: int = 0,
) -> dict[str, object]:
    """Build a session record for SESSION_IDENTITY signed for one network."""
    record: dict[str, object] = {
        "expires_at": expires_at,
        "issuer": "integration",
        "prefix": SESSION_IDENTITY,
        "revoked": revoked,
        "version": version,
    }
    record["signature"] = session_signature(coordination_key(), network, record)
    return record


def stores() -> tuple[ClaimStore, ChannelStore, SessionStore]:
    """Return the claim, channel, and session stores of the restart network."""
    secret = coordination_key()
    return (
        ClaimStore("restart-test", JETSTREAM_REPLICAS, secret),
        ChannelStore("restart-test", JETSTREAM_REPLICAS, secret),
        SessionStore("restart-test", JETSTREAM_REPLICAS, secret, SESSION_TTL),
    )


async def mark() -> None:
    """Write a claim, channel, and session that must survive the restart."""
    nc = await connect()
    try:
        claims, channels, sessions = stores()
        await claims.open(nc.jetstream())
        assert await claims.claim(COUNTER)
        await channels.open(nc.jetstream())
        record = asdict(ChannelRecord.new(CHANNEL, CHANNEL_KEY, present=True))
        stored = await channels.put(record, expected=None)
        assert stored["key"] == CHANNEL_KEY
        await sessions.open(nc.jetstream())
        expires_at = time.time() + SESSION_TTL / 2
        session = await sessions.put(session_record("restart-test", expires_at))
        assert session["prefix"] == SESSION_IDENTITY
    finally:
        await nc.drain()


async def check() -> None:
    """Verify the marked claim, channel, and session after the restart."""
    nc = await connect()
    try:
        claims, channels, sessions = stores()
        # A missing key here can be transient while JetStream replays after
        # the restart, so keep retrying; only a genuine loss (or an elapsed
        # claim TTL) exhausts the timeout, which we surface as a clear error
        # instead of an opaque TimeoutError.
        try:
            async with asyncio.timeout(REPLAY_TIMEOUT):
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
                    assert stored_session["issuer"] == "integration"
                    break
        except TimeoutError:
            msg = "durable state missing after NATS restart"
            raise AssertionError(msg) from None
    finally:
        await nc.drain()
