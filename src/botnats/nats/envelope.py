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
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
NONCE_TTL = 90  # must exceed 2 * TIMESTAMP_DRIFT_WINDOW to close the replay window
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
SUBJECT_FIELD = "_botnats_subject"
TIMESTAMP_DRIFT_WINDOW = 30


class Envelope:
    """Encodes and decodes nonce-protected, HMAC-signed JSON envelopes."""

    def __init__(self, bot_id: str, coordination_key: bytes) -> None:
        """Initialize the envelope with a bot identity and signing key."""
        self.bot_id = bot_id
        self.coordination_key = coordination_key
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
        try:
            envelope = json.loads(value)
        except RecursionError as error:
            msg = "NATS envelope is too deeply nested"
            raise ValueError(msg) from error
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
            or not sender
            or not isinstance(signature, str)
            or SIGNATURE_RE.fullmatch(signature) is None
            or not isinstance(timestamp, int)
            or isinstance(timestamp, bool)
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
        bound_subject = payload.get(SUBJECT_FIELD)
        if bound_subject is None:
            msg = "NATS envelope is not bound to a subject"
            raise ValueError(msg)
        if not isinstance(bound_subject, str) or not hmac.compare_digest(
            bound_subject,
            subject,
        ):
            msg = "NATS envelope subject is invalid"
            raise ValueError(msg)
        payload.pop(SUBJECT_FIELD, None)
        self.seen_nonces[nonce] = now + NONCE_TTL
        return sender, payload

    def encode(self, subject: str, payload: dict[str, Any]) -> bytes:
        """Wrap a payload in a signed, nonce-protected envelope."""
        if SUBJECT_FIELD in payload:
            msg = f"payload field {SUBJECT_FIELD!r} is reserved"
            raise ValueError(msg)
        signed_payload = {**payload, SUBJECT_FIELD: subject}
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        body = self.body(
            nonce,
            signed_payload,
            self.bot_id,
            timestamp,
        )
        encoded = json.dumps(
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
        if len(encoded) > MAX_ENVELOPE_BYTES:
            msg = "NATS envelope exceeds the size limit"
            raise ValueError(msg)
        return encoded

    def mac(self, value: bytes) -> str:
        """Return the hexadecimal HMAC for canonical envelope bytes."""
        return hmac.digest(self.coordination_key, value, "sha256").hex()

    def prune_nonces(self, now: float | None = None) -> None:
        """Remove expired nonces from the replay-detection cache."""
        # Entries are inserted in expiry order, so expired nonces sit at the
        # front. OrderedDict's linked list keeps front peek-and-delete O(1);
        # plain-dict iteration would rescan tombstoned slots on every call.
        # Clock regressions only delay pruning, never drop live nonces.
        current = time.time() if now is None else now
        while self.seen_nonces:
            nonce, expiry = next(iter(self.seen_nonces.items()))
            if expiry > current:
                break
            del self.seen_nonces[nonce]
