# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for TOTP authorization and session management."""

import asyncio
import time
import unittest
from dataclasses import asdict
from types import SimpleNamespace
from typing import Any, NamedTuple, cast
from unittest.mock import AsyncMock, patch

from botnats import Tasks
from botnats.auth import SessionSync, TotpAuthorizer, totp
from botnats.channel import JoinState
from botnats.irc.protocol import IRCMessage, Prefix, casefold
from tests.unit.helpers import (
    AUTH_SEED,
    COORDINATION_KEY,
    OWNER,
    FailingPublishCoordinator,
    FakeCoordinator,
    bot_with_coordinator,
    bot_with_irc,
    send_command,
    session_record,
)


def authorizer(issuer: str = "alpha", network: str = "efnet") -> TotpAuthorizer:
    """Create a TotpAuthorizer with test credentials."""
    return TotpAuthorizer(
        AUTH_SEED,
        coordination_secret=COORDINATION_KEY,
        identity_fold=lambda value: casefold(value, "ascii"),
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

        assert len(auth.records) == 1
        session = next(iter(auth.records.values()))
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

        assert [record.revoked for record in auth.records.values()] == [True]
        assert not auth.authorized("Owner[!user@host", now=15)
        assert not auth.authorized("Owner{!user@host", now=15)

    def test_revocation_blocks_stale_import(self) -> None:
        """Verify a revoked session cannot be restored by a stale import."""
        auth = authorizer("alpha")
        prefix = "owner!user@example.test"
        auth.grant(prefix, now=10)
        session = auth.records[auth.identity_fold(prefix)]

        auth.revoke(prefix)
        auth.import_session(asdict(session), now=20)

        assert not auth.authorized(prefix, now=21)

    def test_durable_revocation_blocks_stale_session(self) -> None:
        """Keep a KV revocation authoritative over its original session."""
        source = authorizer("alpha")
        target = authorizer("beta")
        prefix = "owner!user@example.test"
        session = source.grant(prefix, now=10)
        revoked = source.revoke(prefix)
        assert revoked is not None
        revocation = asdict(revoked)

        target.import_session(revocation, now=20)
        target.import_session(asdict(session), now=20)

        assert not target.authorized(prefix, now=21)

    def test_revocation_flag_is_authenticated(self) -> None:
        """Reject a revocation whose signed state marker is removed or changed."""
        source = authorizer("alpha")
        prefix = "owner!user@example.test"
        source.grant(prefix, now=10)
        revoked = source.revoke(prefix)
        assert revoked is not None

        missing = asdict(revoked)
        missing.pop("revoked")
        changed = {**asdict(revoked), "revoked": False}
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
        assert not auth.records

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
        session = next(iter(first.records.values()))
        second.import_session(asdict(session), now=20)

        assert second.authorized(prefix, now=39.9)
        assert not second.authorized(prefix, now=40)

    def test_session_lookup_prunes_expired(self) -> None:
        """Verify session lookup removes an expired local entry."""
        auth = authorizer()
        prefix = "owner!user@example.test"

        auth.grant(prefix, now=11)

        assert auth.get(prefix, now=41) is None
        assert not auth.records

    def test_session_network_binding(self) -> None:
        """Verify a session signed for one network is invalid on another."""
        first = authorizer("alpha", "efnet")
        second = authorizer("beta", "undernet")
        prefix = "owner!user@example.test"

        first.grant(prefix, now=10)
        session = next(iter(first.records.values()))
        second.import_session(asdict(session), now=20)

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
        non_finite = asdict(
            receiver.create(
                "attacker!user@example.test",
                float("nan"),
                "alpha",
            ),
        )

        for bad in (unsigned, forged, non_ascii, non_finite):
            receiver.import_session(bad, now=20)

        assert not receiver.authorized("attacker!user@example.test", now=21)

    def test_totp_matching_windows(self) -> None:
        """Verify TOTP matching across the accepted counter window."""
        auth = authorizer()

        assert auth.match("287082", now=59) == 1
        assert auth.match("287082", now=89) == 1
        assert auth.match("287082", now=120) is None


class AuthFlowTests(unittest.IsolatedAsyncioTestCase):
    """Tests for AUTH, session grants, and auto-op after authentication."""

    async def test_auth_auto_op(self) -> None:
        """Verify authenticated users receive automatic operator privileges."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == [("#test", "+o", ("owner",))]

    async def test_auth_auto_op_skips_already_opped(self) -> None:
        """Verify auto-op skips users who already have operator status."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER
        runtime.member("owner").modes.add("o")

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_mismatched_identity(self) -> None:
        """Do not op a nickname held by a different IRC identity."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = Prefix("owner", "other", "other.host")

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_when_not_opped(self) -> None:
        """Verify auto-op skips channels where bot is not opped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test")]
        runtime.join = JoinState.JOINED
        runtime.member("owner").prefix = OWNER

        await bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_claim_publish_failure_revokes(self) -> None:
        """Verify a publish failure after claim success revokes the session."""
        bot, fake_irc = bot_with_irc(
            coordinator=FailingPublishCoordinator(claim_result=True),
        )
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        pending = next(iter(bot.sessions.pending.values()))
        assert pending["prefix"] == prefix.render()
        assert pending["revoked"] is True
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_refuses_identity_invalidated_mid_auth(self) -> None:
        """Grant nothing when the user quits while AUTH waits on JetStream."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        claiming = asyncio.Event()
        release = asyncio.Event()

        async def slow_claim(counter: int) -> bool:
            del counter
            claiming.set()
            await release.wait()
            return True

        valid_code = totp(bot.authorizer.secret, int(time.time() // 30))
        with patch.object(coordinator, "request_claim", slow_claim):
            auth = asyncio.create_task(
                send_command(bot, prefix, f"AUTH {valid_code}"),
            )
            async with asyncio.timeout(1):
                await claiming.wait()
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            release.set()
            await auth

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts == []

    async def test_auth_success_grants_session(self) -> None:
        """Verify a valid TOTP code grants an authorized session."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorized")]
        assert len(coordinator.session_puts) == 1

    async def test_auth_fails_closed_when_coordinator_unready(self) -> None:
        """Deny authentication when the coordinator cannot enforce mesh limits."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        coordinator.connected = False
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == []
        assert coordinator.session_puts == []

    async def test_auth_denies_when_durable_revocation_wins(self) -> None:
        """Do not report success when newer durable state revokes the session."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        async def put_session(
            identity: str,
            record: dict[str, object],
        ) -> dict[str, object]:
            del identity
            incoming = bot.authorizer.parse(record, time.time())
            assert incoming is not None
            winner = bot.authorizer.create(
                incoming.prefix,
                incoming.expires_at,
                incoming.issuer,
                incoming.version + 1,
                revoked=True,
            )
            return asdict(winner)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ):
            await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_queues_session_when_uniqueness_lost(self) -> None:
        """Queue the session when require_unique fails mid-authentication."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.claim_result = True
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=RuntimeError("duplicate bot ID")),
        ):
            await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        pending = bot.sessions.pending
        assert len(pending) == 1
        session = next(iter(pending.values()))
        assert session["revoked"] is True
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]


class SessionFixtures(NamedTuple):
    """A SessionSync wired to an authorizer that only records calls."""

    sessions: SessionSync
    session_deletes: list[str]
    session_imports: list[dict[str, Any]]


def session_fixtures() -> SessionFixtures:
    """Build a SessionSync whose authorizer records imports and drops."""
    deletes: list[str] = []
    imports: list[dict[str, Any]] = []
    authorizer = SimpleNamespace(
        drop_session=deletes.append, import_session=imports.append
    )
    sessions = SessionSync(
        cast("TotpAuthorizer", authorizer), FakeCoordinator(), Tasks()
    )
    return SessionFixtures(sessions, deletes, imports)


class SessionSyncWatchTests(unittest.TestCase):
    """Tests for the watched session records SessionSync owns."""

    def test_identity_watch_survives_casemapping_change(self) -> None:
        """Release a watch taken before the casemapping changed."""
        bot, _ = bot_with_irc()
        identity = "nick[!user@host"
        bot.channel_mgr.set_casemapping("ascii")
        bot.sessions.watch_identity(identity)

        bot.channel_mgr.set_casemapping("rfc1459")
        bot.sessions.unwatch_identity(identity)

        assert not bot.sessions.watched_identities

    def test_session_identity_cache_prunes_during_updates(self) -> None:
        """Prune expired key mappings during normal watch traffic."""
        fixtures = session_fixtures()
        now = time.time()
        fixtures.sessions.watched["expired"] = ("expired!user@host", now - 1)
        expiry = now + 60
        key = "opaque"

        fixtures.sessions.observe(key, session_record(expiry), replaying=False)

        assert fixtures.sessions.watched == {key: ("owner!user@host", expiry)}

    def test_session_identity_cache_does_not_prune_during_replay(self) -> None:
        """Avoid rescanning the growing cache for every replayed session."""
        fixtures = session_fixtures()
        record = session_record(time.time() + 60)

        with patch.object(
            fixtures.sessions,
            "prune",
            wraps=fixtures.sessions.prune,
        ) as prune:
            fixtures.sessions.observe("opaque", record, replaying=True)

        prune.assert_not_called()
