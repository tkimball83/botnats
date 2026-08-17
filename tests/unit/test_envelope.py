# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the signed NATS message envelope."""

import json
import time
import unittest

from botnats.nats.envelope import Envelope
from tests.unit.helpers import COORDINATION_KEY

JSON_NESTING_DEPTH = 100_000
OVERSIZED_TIMESTAMP = 10**400
SUBJECT = "botnats.v1.efnet.channel"


class EnvelopeTests(unittest.TestCase):
    """Tests for envelope decoding safety."""

    def test_decode_rejects_deeply_nested_json(self) -> None:
        """Verify deeply nested JSON is rejected as a value error, not a crash."""
        envelope = Envelope("alpha", COORDINATION_KEY)

        with self.assertRaises(ValueError):
            envelope.decode(SUBJECT, b"[" * JSON_NESTING_DEPTH)

    def test_decode_rejects_large_payload(self) -> None:
        """Verify oversized envelopes are rejected before JSON parsing."""
        envelope = Envelope("alpha", COORDINATION_KEY)

        with self.assertRaisesRegex(ValueError, "size limit"):
            envelope.decode(SUBJECT, b" " * 262_145)

    def test_decode_rejects_non_hex_nonce(self) -> None:
        """Verify a correctly sized non-hex nonce is malformed."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["nonce"] = "z" * 32

        with self.assertRaisesRegex(ValueError, "malformed"):
            envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_oversized_timestamp(self) -> None:
        """Reject an integer timestamp too large for float arithmetic."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["timestamp"] = OVERSIZED_TIMESTAMP

        with self.assertRaisesRegex(ValueError, "allowed window"):
            envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_unbound_payload(self) -> None:
        """Reject signed envelopes that are not bound to their subject."""
        sender = Envelope("alpha", COORDINATION_KEY)
        nonce = "a" * 32
        payload: dict[str, object] = {}
        timestamp = int(time.time())
        encoded = json.dumps(
            {
                "nonce": nonce,
                "payload": payload,
                "sender": sender.bot_id,
                "signature": sender.mac(
                    sender.body(nonce, payload, sender.bot_id, timestamp),
                ),
                "timestamp": timestamp,
            },
        ).encode()

        with self.assertRaisesRegex(ValueError, "not bound"):
            Envelope("beta", COORDINATION_KEY).decode(SUBJECT, encoded)

    def test_encode_rejects_large_payload(self) -> None:
        """Verify encoding a payload that exceeds the size limit raises."""
        envelope = Envelope("alpha", COORDINATION_KEY)

        with self.assertRaisesRegex(ValueError, "size limit"):
            envelope.encode(SUBJECT, {"big": "x" * 262_144})

    def test_encode_rejects_reserved_field(self) -> None:
        """Verify encoding rejects payloads containing the reserved subject field."""
        envelope = Envelope("alpha", COORDINATION_KEY)

        with self.assertRaisesRegex(ValueError, "reserved"):
            envelope.encode(SUBJECT, {"_botnats_subject": "spoofed"})
