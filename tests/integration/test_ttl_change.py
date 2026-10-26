# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a changed session TTL is applied to existing buckets."""

import json
import time
import uuid

from nats.js.errors import BadRequestError

from botnats.nats.store import SessionStore
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    connect,
    coordination_key,
    delete_buckets,
)
from tests.integration.test_restart import SESSION_IDENTITY, SESSION_TTL, session_record


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
        before = SessionStore(network, JETSTREAM_REPLICAS, coordination_key(), old)
        await before.open(nc.jetstream())
        await before.put(session_record(network, time.time() + old / 2))

        after = SessionStore(network, JETSTREAM_REPLICAS, coordination_key(), new)
        kv = await after.open(nc.jetstream())

        info = await nc.jetstream().stream_info(f"KV_{after.bucket}")
        assert info.config.max_age == new
        entry = await kv.get(after.key(SESSION_IDENTITY))
        assert entry.value is not None
        assert json.loads(entry.value)["prefix"] == SESSION_IDENTITY

        # A different replica count is not applied; it fails as before.
        fewer = SessionStore(
            network,
            JETSTREAM_REPLICAS - 1,
            coordination_key(),
            new,
        )
        try:
            await fewer.open(nc.jetstream())
        except BadRequestError:
            pass
        else:
            msg = "a replica mismatch opened the bucket"
            raise AssertionError(msg)

        await delete_buckets(nc, after.bucket)
    finally:
        await nc.drain()
