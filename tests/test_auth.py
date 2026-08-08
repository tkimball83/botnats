# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for TOTP authorization and session management."""

import unittest

from botnats.admin import TotpAuthorizer
from tests.helpers import AUTH_SEED, COORDINATION_KEY


def authorizer(issuer: str = "alpha", network: str = "efnet") -> TotpAuthorizer:
    """Create a TotpAuthorizer with test credentials."""
    return TotpAuthorizer(
        AUTH_SEED,
        coordination_secret=COORDINATION_KEY,
        scope=(issuer, network),
        session_ttl=30,
    )


class TotpAuthorizerTests(unittest.TestCase):
    """Tests for TOTP code matching, session binding, and import."""

    def test_clock_drift_and_invalid_codes(self) -> None:
        """Verify clock drift tolerance and rejection of invalid codes."""
        auth = authorizer()

        assert auth.match("287082", now=60) == 1
        assert auth.match("not-a-code", now=59) is None
        assert auth.match("000000", now=59) is None
        assert auth.match("²" * 6, now=59) is None

    def test_rekey_collision_keeps_latest(self) -> None:
        """Verify rekey keeps the latest session when two prefixes collide."""
        auth = authorizer()
        auth.grant("Owner[!user@host", now=10)
        auth.grant("Owner{!user@host", now=15)

        auth.identity_fold = lambda p: p.casefold().translate(
            str.maketrans("[]\\^", "{}|~"),
        )
        auth.rekey(now=20)

        assert len(auth.sessions) == 1
        session = next(iter(auth.sessions.values()))
        assert session.prefix == "Owner{!user@host"

    def test_rekey_revocation_wins(self) -> None:
        """Verify rekey drops a session when a revocation collides."""
        auth = authorizer()
        auth.grant("Owner[!user@host", now=10)
        auth.revoke("Owner[!user@host")
        auth.grant("Owner{!user@host", now=10)

        auth.identity_fold = lambda p: p.casefold().translate(
            str.maketrans("[]\\^", "{}|~"),
        )
        auth.rekey(now=15)

        assert not auth.sessions

    def test_revocation_blocks_stale_import(self) -> None:
        """Verify a revoked session cannot be restored by a stale import."""
        auth = authorizer("alpha")
        prefix = "owner!user@example.test"
        auth.grant(prefix, now=10)
        session = auth.sessions[auth.identity_fold(prefix)]

        auth.revoke(prefix)
        auth.import_session(session.to_dict(), now=20)

        assert not auth.authorized(prefix, now=21)

    def test_durable_revocation_blocks_stale_session(self) -> None:
        """Keep a KV revocation authoritative over its original session."""
        source = authorizer("alpha")
        target = authorizer("beta")
        prefix = "owner!user@example.test"
        session = source.grant(prefix, now=10)
        revoked = source.revoke(prefix)
        assert revoked is not None
        revocation = revoked.to_dict()

        target.import_session(revocation, now=20)
        target.import_session(session.to_dict(), now=20)

        assert not target.authorized(prefix, now=21)

    def test_revocation_flag_is_authenticated(self) -> None:
        """Reject a revocation whose signed state marker is removed or changed."""
        source = authorizer("alpha")
        prefix = "owner!user@example.test"
        source.grant(prefix, now=10)
        revoked = source.revoke(prefix)
        assert revoked is not None

        missing = revoked.to_dict()
        missing.pop("revoked")
        changed = {**revoked.to_dict(), "revoked": False}
        for payload in (missing, changed):
            target = authorizer("beta")
            target.import_session(payload, now=20)
            assert not target.authorized(prefix, now=21)

    def test_session_binding_and_expiry(self) -> None:
        """Verify sessions bind to a prefix and expire after TTL."""
        auth = authorizer()
        prefix = "owner!user@example.test"

        auth.grant(prefix, now=11)
        assert not auth.authorized("other!user@example.test", now=12)
        assert auth.authorized(prefix, now=40.9)
        assert not auth.authorized(prefix, now=41)
        assert not auth.sessions

    def test_session_identity_uses_ascii_folding(self) -> None:
        """Keep Unicode identities distinct while folding IRC ASCII case."""
        auth = authorizer()
        prefix = "Owner!user@straße.example"
        auth.grant(prefix, now=10)

        assert auth.authorized("owner!USER@straße.example", now=20)
        assert not auth.authorized("owner!user@strasse.example", now=20)

    def test_session_import(self) -> None:
        """Verify a session imports into another authorizer instance."""
        first = authorizer("alpha")
        second = authorizer("beta")
        prefix = "owner!user@example.test"

        first.grant(prefix, now=10)
        session = next(iter(first.sessions.values()))
        second.import_session(session.to_dict(), now=20)

        assert second.authorized(prefix, now=39.9)
        assert not second.authorized(prefix, now=40)

    def test_session_lookup_prunes_expired(self) -> None:
        """Verify session lookup removes an expired local entry."""
        auth = authorizer()
        prefix = "owner!user@example.test"

        auth.grant(prefix, now=11)

        assert auth.get(prefix, now=41) is None
        assert not auth.sessions

    def test_session_moves_on_nick(self) -> None:
        """Verify an active session follows an observed nickname change."""
        auth = authorizer()
        old_prefix = "owner!user@old.example.test"
        new_prefix = "owner2!user@new.example.test"
        auth.grant(old_prefix, now=11)

        assert auth.move(old_prefix, new_prefix, now=12)
        assert not auth.authorized(old_prefix, now=13)
        assert auth.authorized(new_prefix, now=13)
        assert not auth.move("missing!user@host", new_prefix, now=13)

    def test_session_moves_across_fold_collision(self) -> None:
        """Keep repeated moves ordered when nicknames fold together."""

        def fold(value: str) -> str:
            return value.casefold().translate(str.maketrans("[]", "{}"))

        def folded_authorizer(issuer: str) -> TotpAuthorizer:
            return TotpAuthorizer(
                AUTH_SEED,
                coordination_secret=COORDINATION_KEY,
                identity_fold=fold,
                scope=(issuer, "efnet"),
                session_ttl=30,
            )

        source = folded_authorizer("alpha")
        target = folded_authorizer("beta")
        first = "Owner[!user@host"
        second = "Owner{!user@host"
        source.grant(first, now=10)

        first_revoked, moved = source.move(first, second, now=11) or (None, None)
        assert first_revoked is not None
        assert moved is not None
        target.import_session(first_revoked.to_dict(), now=12)
        target.import_session(moved.to_dict(), now=12)
        second_revoked, moved_back = source.move(second, first, now=13) or (
            None,
            None,
        )
        assert second_revoked is not None
        assert moved_back is not None
        target.import_session(second_revoked.to_dict(), now=14)
        target.import_session(moved_back.to_dict(), now=14)

        assert source.authorized(first, now=15)
        assert target.authorized(first, now=15)

    def test_session_network_binding(self) -> None:
        """Verify a session signed for one network is invalid on another."""
        first = authorizer("alpha", "efnet")
        second = authorizer("beta", "undernet")
        prefix = "owner!user@example.test"

        first.grant(prefix, now=10)
        session = next(iter(first.sessions.values()))
        second.import_session(session.to_dict(), now=20)

        assert not second.authorized(prefix, now=21)

    def test_session_signature_validation(self) -> None:
        """Verify forged and unsigned sessions are rejected."""
        receiver = authorizer("beta")
        unsigned = {
            "expires_at": 40.0,
            "prefix": "attacker!user@example.test",
        }
        forged = {
            **unsigned,
            "issuer": "alpha",
            "signature": "0" * 64,
        }
        non_ascii = {
            **forged,
            "signature": "é" * 64,
        }
        non_finite = receiver.create(
            "attacker!user@example.test",
            float("nan"),
            "alpha",
        ).to_dict()

        for bad in (unsigned, forged, non_ascii, non_finite):
            receiver.import_session(bad, now=20)

        assert not receiver.authorized("attacker!user@example.test", now=21)

    def test_totp_matching_windows(self) -> None:
        """Verify TOTP matching across the accepted counter window."""
        auth = authorizer()

        assert auth.match("287082", now=59) == 1
        assert auth.match("287082", now=89) == 1
        assert auth.match("287082", now=120) is None
