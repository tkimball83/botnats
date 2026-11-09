# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Verify a changed presence TTL is applied to existing buckets."""

import json
import uuid

from nats.js.errors import BadRequestError

from botnats.nats.store import PresenceStore
from tests.integration.test_failover import (
    JETSTREAM_REPLICAS,
    connect,
    coordination_key,
    delete_buckets,
)

BOT_ID = "ttl"
PRESENCE = {
    "bot_id": BOT_ID,
    "host": "host",
    "instance_id": "instance",
    "nick": BOT_ID,
    "user": "user",
}


async def ttl_change() -> None:
    """Reopen presence buckets under new TTLs without losing their records."""
    # Below two minutes the TTL also sets the bucket's duplicate window.
    for old, new in ((300.0, 600.0), (15.0, 30.0)):
        await reopen_with_ttl(old, new)


async def reopen_with_ttl(old: float, new: float) -> None:
    """Change one bucket's TTL; a replica mismatch must still fail."""
    network = f"ttl{uuid.uuid4().hex}"
    nc = await connect()
    try:
        before = PresenceStore(network, JETSTREAM_REPLICAS, old, coordination_key())
        await before.open(nc.jetstream())
        assert await before.create(BOT_ID, PRESENCE) is not None

        after = PresenceStore(network, JETSTREAM_REPLICAS, new, coordination_key())
        kv = await after.open(nc.jetstream())

        info = await nc.jetstream().stream_info(f"KV_{after.bucket}")
        assert info.config.max_age == new
        entry = await kv.get(after.key(BOT_ID))
        assert entry.value is not None
        assert json.loads(entry.value)["bot_id"] == BOT_ID

        # A different replica count is not applied; it fails as before.
        fewer = PresenceStore(
            network,
            JETSTREAM_REPLICAS - 1,
            new,
            coordination_key(),
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
