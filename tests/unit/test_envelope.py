# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the signed NATS message envelope."""

import json
import time
import unittest

from botnats.nats.envelope import Envelope
from tests.unit.helpers import COORDINATION_KEY

OVERSIZED_TIMESTAMP = 10**400
SUBJECT = "botnats.v1.efnet.channel"


class EnvelopeTests(unittest.TestCase):
    """Tests for envelope signing, replay protection, and decoding safety."""

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

    def test_decode_rejects_stale_timestamp(self) -> None:
        """Reject an envelope with a plausible but expired timestamp."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["timestamp"] = int(time.time()) - 60

        with self.assertRaisesRegex(ValueError, "allowed window"):
            envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_future_timestamp(self) -> None:
        """Reject an envelope with a timestamp too far in the future."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["timestamp"] = int(time.time()) + 60

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

    def test_envelope_security(self) -> None:
        """Verify envelope signing, replay rejection, and tamper detection."""
        key = COORDINATION_KEY
        sender = Envelope("alpha", key)
        receiver = Envelope("beta", key)

        encoded = sender.encode(SUBJECT, {"channel": "#test"})
        assert receiver.decode(SUBJECT, encoded) == (
            "alpha",
            {"channel": "#test"},
        )
        with self.assertRaisesRegex(ValueError, "replayed"):
            receiver.decode(SUBJECT, encoded)

        forged = json.dumps({"payload": {"channel": "#owned"}}).encode()
        with self.assertRaisesRegex(ValueError, "malformed"):
            receiver.decode(SUBJECT, forged)

        with self.assertRaisesRegex(TypeError, "not an object"):
            receiver.decode(SUBJECT, b"[]")

        tampered = json.loads(encoded)
        tampered["nonce"] = "f" * 32
        tampered["payload"] = {"channel": "#owned"}
        with self.assertRaisesRegex(ValueError, "signature"):
            receiver.decode(SUBJECT, json.dumps(tampered).encode())

    def test_decode_prunes_expired_nonces(self) -> None:
        """Prune expired nonces on decode, which keeps the replay cache bounded."""
        receiver = Envelope("beta", COORDINATION_KEY)
        receiver.seen_nonces["a" * 32] = 1.0
        receiver.seen_nonces["b" * 32] = 2.0
        receiver.seen_nonces["c" * 32] = time.time() + 60
        encoded = Envelope("alpha", COORDINATION_KEY).encode(SUBJECT, {})

        receiver.decode(SUBJECT, encoded)

        assert list(receiver.seen_nonces) == ["c" * 32, json.loads(encoded)["nonce"]]

    def test_subject_substitution(self) -> None:
        """Verify a signed message cannot be moved to another NATS subject."""
        key = COORDINATION_KEY
        sender = Envelope("alpha", key)
        receiver = Envelope("beta", key)
        encoded = sender.encode(SUBJECT, {"channel": "#test"})

        with self.assertRaisesRegex(ValueError, "not bound"):
            receiver.decode("botnats.v1.efnet.auth.session", encoded)
