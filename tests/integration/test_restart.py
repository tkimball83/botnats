# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify durable state survives a complete NATS cluster restart."""

import json
import time
from dataclasses import asdict
from typing import TYPE_CHECKING

from botnats.channel import ChannelRecord
from botnats.nats.store import ChannelStore, ClaimStore, SessionStore, session_signature
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    connect,
    coordination_key,
    delete_buckets,
    keep_trying,
)

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

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
        _, stored_key, _, _ = await channels.put(record, expected=None)
        assert stored_key == CHANNEL_KEY
        await sessions.open(nc.jetstream())
        expires_at = time.time() + SESSION_TTL / 2
        session = await sessions.put(session_record("restart-test", expires_at))
        assert session.prefix == SESSION_IDENTITY
    finally:
        await nc.drain()


async def check() -> None:
    """Verify the marked claim, channel, and session after the restart."""
    nc = await connect()
    try:
        claims, channels, sessions = stores()

        async def read() -> tuple[KeyValue.Entry, ...]:
            # A missing key can be transient while JetStream replays after the
            # restart; only a genuine loss (or an elapsed claim TTL) times out.
            claim_kv = await claims.open(nc.jetstream())
            channel_kv = await channels.open(nc.jetstream())
            session_kv = await sessions.open(nc.jetstream())
            return (
                await claim_kv.get(claims.key(COUNTER)),
                await channel_kv.get(channels.key(CHANNEL)),
                await session_kv.get(sessions.key(SESSION_IDENTITY)),
            )

        entry, channel_entry, session_entry = await keep_trying(
            read,
            REPLAY_TIMEOUT,
            "durable state missing after NATS restart",
        )
        assert entry.value == b"1"
        assert channel_entry.value is not None
        channel_record = json.loads(channel_entry.value)
        assert channel_record["key"] == CHANNEL_KEY
        assert channel_record["present"] is True
        assert session_entry.value is not None
        stored_session = json.loads(session_entry.value)
        assert stored_session["prefix"] == SESSION_IDENTITY
        assert stored_session["issuer"] == "integration"
        await delete_buckets(nc, claims.bucket, channels.bucket, sessions.bucket)
    finally:
        await nc.drain()
