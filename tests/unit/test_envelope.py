# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for the signed NATS message envelope."""

import json
import time
import unittest
from unittest.mock import patch

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

    def test_decode_rejects_non_hex_signature(self) -> None:
        """Reject a non-hex signature as malformed before comparing it."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        # compare_digest returns False for the first and raises TypeError for
        # the non-ASCII second.
        for signature in ("z" * 64, "é" * 64):
            encoded = json.loads(envelope.encode(SUBJECT, {}))
            encoded["signature"] = signature

            with (
                self.subTest(signature=signature),
                self.assertRaisesRegex(ValueError, "malformed"),
            ):
                envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_float_timestamp(self) -> None:
        """Reject a correctly signed timestamp that is not an integer."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["timestamp"] = float(encoded["timestamp"])
        encoded["signature"] = envelope.mac(
            envelope.body(
                encoded["nonce"],
                encoded["payload"],
                encoded["sender"],
                encoded["timestamp"],
            ),
        )

        with self.assertRaisesRegex(ValueError, "malformed"):
            envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_oversized_timestamp(self) -> None:
        """Reject an integer timestamp too large for float arithmetic."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        encoded = json.loads(envelope.encode(SUBJECT, {}))
        encoded["timestamp"] = OVERSIZED_TIMESTAMP

        with self.assertRaisesRegex(ValueError, "allowed window"):
            envelope.decode(SUBJECT, json.dumps(encoded).encode())

    def test_decode_rejects_boolean_timestamp(self) -> None:
        """Reject a boolean timestamp, an int the drift window refuses."""
        envelope = Envelope("alpha", COORDINATION_KEY)
        for timestamp in (True, False):
            encoded = json.loads(envelope.encode(SUBJECT, {}))
            encoded["timestamp"] = timestamp

            with (
                self.subTest(timestamp=timestamp),
                self.assertRaisesRegex(ValueError, "allowed window"),
            ):
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
        """Verify envelope signing, replay rejection, and malformed envelopes."""
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

    def test_signature_covers_every_field(self) -> None:
        """Reject an envelope with any one signed field changed and not re-signed.

        A client holding the NATS token but not the coordination secret could
        otherwise replay a captured envelope under a fresh nonce or timestamp.
        """
        sender = Envelope("alpha", COORDINATION_KEY)
        receiver = Envelope("beta", COORDINATION_KEY)
        for field in ("nonce", "payload", "sender", "timestamp"):
            # Never decoded, so its nonce is not yet a replay.
            tampered = json.loads(sender.encode(SUBJECT, {"channel": "#test"}))
            tampered[field] = {
                "nonce": "f" * 32,
                "payload": {**tampered["payload"], "channel": "#owned"},
                "sender": "gamma",
                # Still inside the drift window.
                "timestamp": tampered["timestamp"] - 1,
            }[field]

            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "signature"),
            ):
                receiver.decode(SUBJECT, json.dumps(tampered).encode())

        # Only authentic envelopes may grow the replay cache.
        assert not receiver.seen_nonces

    def test_decode_prunes_expired_nonces(self) -> None:
        """Prune expired nonces on decode, which keeps the replay cache bounded."""
        receiver = Envelope("beta", COORDINATION_KEY)
        receiver.seen_nonces["a" * 32] = 1.0
        receiver.seen_nonces["b" * 32] = 2.0
        receiver.seen_nonces["c" * 32] = time.time() + 60
        encoded = Envelope("alpha", COORDINATION_KEY).encode(SUBJECT, {})

        receiver.decode(SUBJECT, encoded)

        assert list(receiver.seen_nonces) == ["c" * 32, json.loads(encoded)["nonce"]]

    def test_nonce_outlives_drift_window(self) -> None:
        """Reject a replay for as long as the 30-second drift window accepts it."""
        sender = Envelope("alpha", COORDINATION_KEY)
        receiver = Envelope("beta", COORDINATION_KEY)
        signed_at = 1_000_000.0

        with patch("botnats.nats.envelope.time") as clock:
            clock.time.return_value = signed_at
            encoded = sender.encode(SUBJECT, {})
            # First seen at the window's future edge and replayed at its past
            # edge, so the nonce must outlive both halves of the window.
            clock.time.return_value = signed_at - 30
            assert receiver.decode(SUBJECT, encoded) == ("alpha", {})
            clock.time.return_value = signed_at + 30
            with self.assertRaisesRegex(ValueError, "replayed"):
                receiver.decode(SUBJECT, encoded)

            clock.time.return_value = signed_at + 31
            with self.assertRaisesRegex(ValueError, "allowed window"):
                receiver.decode(SUBJECT, encoded)

    def test_subject_substitution(self) -> None:
        """Verify a signed message cannot be moved to another NATS subject."""
        key = COORDINATION_KEY
        sender = Envelope("alpha", key)
        receiver = Envelope("beta", key)
        encoded = sender.encode(SUBJECT, {"channel": "#test"})

        with self.assertRaisesRegex(ValueError, "not bound"):
            receiver.decode("botnats.v1.efnet.auth.session", encoded)

        assert json.loads(encoded)["nonce"] not in receiver.seen_nonces
