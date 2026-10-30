# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""HMAC-signed NATS message envelope."""

import hmac
import json
import re
import secrets
import time
from collections import OrderedDict
from typing import Any

MAX_ENVELOPE_BYTES = 262_144
NONCE_RE = re.compile(r"[0-9a-f]{32}")
NONCE_TTL = 90  # must exceed 2 * TIMESTAMP_DRIFT_WINDOW to close the replay window
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")
SUBJECT_FIELD = "_botnats_subject"
TIMESTAMP_DRIFT_WINDOW = 30


class Envelope:
    """Encodes and decodes nonce-protected, HMAC-signed JSON envelopes."""

    def __init__(self, bot_id: str, coordination_key: bytes) -> None:
        self.bot_id = bot_id
        self.coordination_key = coordination_key
        # Per-process by design: a restarted bot accepts replays inside the
        # drift window; payload-level presence checks bound the impact.
        self.seen_nonces: OrderedDict[str, float] = OrderedDict()

    @staticmethod
    def body(
        nonce: str,
        payload: dict[str, Any],
        sender: str,
        timestamp: int,
    ) -> bytes:
        """Build the canonical JSON byte string used for HMAC signing."""
        return json.dumps(
            {
                "nonce": nonce,
                "payload": payload,
                "sender": sender,
                "timestamp": timestamp,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def decode(
        self,
        subject: str,
        value: bytes,
    ) -> tuple[str, dict[str, Any]]:
        """Verify and extract the sender and payload from a signed envelope."""
        if len(value) > MAX_ENVELOPE_BYTES:
            msg = "NATS envelope exceeds the size limit"
            raise ValueError(msg)

        envelope = json.loads(value)
        if not isinstance(envelope, dict):
            msg = "NATS envelope is not an object"
            raise TypeError(msg)

        nonce = envelope.get("nonce")
        payload = envelope.get("payload")
        sender = envelope.get("sender")
        signature = envelope.get("signature")
        timestamp = envelope.get("timestamp")
        if (
            not isinstance(nonce, str)
            or NONCE_RE.fullmatch(nonce) is None
            or not isinstance(payload, dict)
            or not isinstance(sender, str)
            or not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
            or not isinstance(timestamp, int)
        ):
            msg = "NATS envelope is malformed"
            raise ValueError(msg)

        now = time.time()
        if (
            not now - TIMESTAMP_DRIFT_WINDOW
            <= timestamp
            <= now + TIMESTAMP_DRIFT_WINDOW
        ):
            msg = "NATS envelope timestamp is outside the allowed window"
            raise ValueError(msg)

        self.prune_nonces(now)
        if nonce in self.seen_nonces:
            msg = "NATS envelope was replayed"
            raise ValueError(msg)

        expected = self.mac(self.body(nonce, payload, sender, timestamp))
        if not hmac.compare_digest(expected, signature):
            msg = "NATS envelope signature is invalid"
            raise ValueError(msg)

        if payload.get(SUBJECT_FIELD) != subject:
            msg = "NATS envelope is not bound to its subject"
            raise ValueError(msg)

        del payload[SUBJECT_FIELD]
        self.seen_nonces[nonce] = now + NONCE_TTL
        return sender, payload

    def encode(self, subject: str, payload: dict[str, Any]) -> bytes:
        """Wrap a payload in a signed, nonce-protected envelope."""
        signed_payload = {**payload, SUBJECT_FIELD: subject}
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        body = self.body(
            nonce,
            signed_payload,
            self.bot_id,
            timestamp,
        )
        return json.dumps(
            {
                "nonce": nonce,
                "payload": signed_payload,
                "sender": self.bot_id,
                "signature": self.mac(body),
                "timestamp": timestamp,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def mac(self, value: bytes) -> str:
        """Return the hexadecimal HMAC for canonical envelope bytes."""
        return hmac.digest(self.coordination_key, value, "sha256").hex()

    def prune_nonces(self, now: float) -> None:
        """Remove expired nonces from the replay-detection cache."""
        # Entries are inserted in expiry order, so expired nonces sit at the
        # front. OrderedDict's linked list keeps front peek-and-delete O(1);
        # plain-dict iteration would rescan tombstoned slots on every call.
        # Clock regressions only delay pruning, never drop live nonces.
        while self.seen_nonces:
            nonce, expiry = next(iter(self.seen_nonces.items()))
            if expiry > now:
                break

            del self.seen_nonces[nonce]
