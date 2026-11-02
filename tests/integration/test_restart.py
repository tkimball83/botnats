# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify durable state survives a complete NATS cluster restart."""

import json
import time
from dataclasses import asdict
from typing import TYPE_CHECKING

from botnats.channel import ChannelRecord
from botnats.nats.store import (
    SESSION_TTL,
    AttemptStore,
    ChannelStore,
    ClaimStore,
    Session,
    SessionStore,
)
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    connect,
    coordination_key,
    delete_buckets,
    keep_trying,
)

if TYPE_CHECKING:
    from nats.js.kv import KeyValue

    from botnats.validators import ChannelFields

CHANNEL = "#botnats-restart"
CHANNEL_KEY = "restart-key"
COUNTER = 987_654_321
SESSION_IDENTITY = "restart!user@host.example"
ATTEMPT_HOST = "host.example"


def session_value(
    expires_at: float,
    *,
    revoked: bool = False,
    version: int = 0,
) -> Session:
    """Build a session for SESSION_IDENTITY."""
    return Session(expires_at, "integration", SESSION_IDENTITY, revoked, version)


def stores() -> tuple[ClaimStore, ChannelStore, SessionStore, AttemptStore]:
    """Return the claim, channel, session, and attempt stores of the network."""
    secret = coordination_key()
    return (
        ClaimStore("restart-test", JETSTREAM_REPLICAS, secret),
        ChannelStore("restart-test", JETSTREAM_REPLICAS, secret),
        SessionStore("restart-test", JETSTREAM_REPLICAS, secret),
        AttemptStore("restart-test", JETSTREAM_REPLICAS, secret),
    )


async def mark() -> None:
    """Write a claim, channel, session, and attempt that must survive."""
    nc = await connect()
    try:
        claims, channels, sessions, attempts = stores()
        record = asdict(ChannelRecord.new(CHANNEL, CHANNEL_KEY, present=True))
        expires_at = time.time() + SESSION_TTL / 2

        async def write() -> tuple[ChannelFields, Session] | None:
            # The failover phase's restarted node passes its healthcheck
            # before rejoining the meta group, so retry. Both puts return the
            # record already stored; claim() refuses a COUNTER stored by an
            # attempt whose ack was lost, as it refuses a failed publish, so
            # read the key to tell them apart.
            claim_kv = await claims.open(nc.jetstream())
            if (
                not await claims.claim(COUNTER)
                and (await claim_kv.get(claims.key(COUNTER))).value != b"1"
            ):
                return None

            await channels.open(nc.jetstream())
            channel = await channels.put(record, after=None)
            await sessions.open(nc.jetstream())
            session = await sessions.put(session_value(expires_at))
            # A retry after a lost ack takes a later slot; any attempt fills
            # slot 0 first, so slot 0 alone shows the attempt was recorded.
            attempt_kv = await attempts.open(nc.jetstream())
            if not await attempts.allow(ATTEMPT_HOST):
                await attempt_kv.get(attempts.key(ATTEMPT_HOST, 0))

            return channel, session

        (_, stored_key, _, _), session = await keep_trying(
            write,
            "durable state not written before NATS restart",
        )
        assert stored_key == CHANNEL_KEY
        assert session.prefix == SESSION_IDENTITY
    finally:
        await nc.drain()


async def check() -> None:
    """Verify the marked claim, channel, session, and attempt after restart."""
    nc = await connect()
    try:
        claims, channels, sessions, attempts = stores()

        async def read() -> tuple[KeyValue.Entry, ...]:
            # A missing key can be transient while JetStream replays after the
            # restart; only a genuine loss (or an elapsed claim TTL) times out.
            claim_kv = await claims.open(nc.jetstream())
            channel_kv = await channels.open(nc.jetstream())
            session_kv = await sessions.open(nc.jetstream())
            attempt_kv = await attempts.open(nc.jetstream())
            return (
                await claim_kv.get(claims.key(COUNTER)),
                await channel_kv.get(channels.key(CHANNEL)),
                await session_kv.get(sessions.key(SESSION_IDENTITY)),
                await attempt_kv.get(attempts.key(ATTEMPT_HOST, 0)),
            )

        entry, channel_entry, session_entry, attempt_entry = await keep_trying(
            read,
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
        assert attempt_entry.value is not None
        await delete_buckets(
            nc,
            claims.bucket,
            channels.bucket,
            sessions.bucket,
            attempts.bucket,
        )
    finally:
        await nc.drain()
