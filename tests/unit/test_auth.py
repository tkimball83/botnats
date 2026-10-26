# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for TOTP authorization and session management."""

import asyncio
import time
import unittest
from dataclasses import asdict
from typing import Any
from unittest.mock import AsyncMock, patch

from nats.errors import Error as NatsError

from botnats import Tasks
from botnats.auth import TOTP_PERIOD, SessionSync, TotpAuthorizer, totp
from botnats.channel import JoinState
from botnats.irc.protocol import IRCMessage, Prefix, casefold
from botnats.nats.store import (
    ATTEMPT_LIMIT,
    SESSION_EXPIRY_GRACE,
    Session,
    SessionStore,
)
from tests.unit.helpers import (
    AUTH_KEY,
    COORDINATION_KEY,
    OWNER,
    FailingWriteCoordinator,
    FakeCoordinator,
    FakeIRC,
    bot_with_coordinator,
    bot_with_irc,
    drain_session_writes,
    make_bot,
    send_command,
    session_value,
)


def authorizer(issuer: str = "alpha", network: str = "efnet") -> TotpAuthorizer:
    """Create a TotpAuthorizer with test credentials."""
    return TotpAuthorizer(
        AUTH_KEY,
        coordination_secret=COORDINATION_KEY,
        identity_fold=lambda value: casefold(value, "ascii"),
        scope=(issuer, network),
        session_ttl=30,
    )


class TotpAuthorizerTests(unittest.TestCase):
    """Tests for TOTP code matching, session binding, and import."""

    def test_rfc_vector_and_invalid_codes(self) -> None:
        """Match the RFC 4226 test vector and reject malformed or wrong codes."""
        auth = authorizer()

        assert totp(AUTH_KEY, 1) == "287082"
        assert auth.match("not-a-code", now=59) is None
        assert auth.match("000000", now=59) is None
        assert auth.match("²" * 6, now=59) is None

    def test_rekey_collision_keeps_highest_ranked(self) -> None:
        """Keep the later-expiring session when two prefixes collide on rekey.

        The higher-ranked session is granted first, so keeping whichever
        record came last would keep the wrong one.
        """
        auth = authorizer()
        auth.grant("Owner{!user@host", now=15)
        auth.grant("Owner[!user@host", now=10)

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

    def test_dropped_key_keeps_revocation(self) -> None:
        """Keep a revocation when its durable key is deleted.

        drop_session forgets only a live session: forgetting the revocation
        would let the stale grant it revoked import again.
        """
        auth = authorizer("alpha")
        prefix = "owner!user@example.test"
        session = auth.grant(prefix, now=10)
        auth.revoke(prefix)

        auth.drop_session(prefix)
        auth.import_session(asdict(session), now=20)

        assert [record.revoked for record in auth.records.values()] == [True]
        assert not auth.authorized(prefix, now=21)
        # The stale grant is still importable where no revocation is held.
        fresh = authorizer("beta")
        fresh.import_session(asdict(session), now=20)
        assert fresh.authorized(prefix, now=21)

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
        """Bind a session to its prefix, expire it after TTL, and prune it."""
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

    def test_future_dated_session_is_rejected(self) -> None:
        """Reject a signed session expiring beyond one TTL plus grace from now."""
        receiver = authorizer()
        prefix = "owner!user@example.test"
        now = 1_000.0
        horizon = now + receiver.session_ttl + SESSION_EXPIRY_GRACE
        future = receiver.create(prefix, horizon + 1, "alpha")

        assert receiver.import_session(asdict(future), now=now) is None
        assert not receiver.authorized(prefix, now=now)

        edge = receiver.create(prefix, horizon, "alpha")
        assert receiver.import_session(asdict(edge), now=now) == edge
        assert receiver.authorized(prefix, now=now)

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
        """Reject complete records whose only defect is the signature or expiry."""
        source = authorizer("alpha")
        prefix = "attacker!user@example.test"
        valid = asdict(source.create(prefix, 40.0, "alpha"))
        payloads = {
            "forged": {**valid, "signature": "0" * 64},
            "non-ASCII": {**valid, "signature": "é" * 64},
            "non-finite": asdict(source.create(prefix, float("nan"), "alpha")),
            "unsigned": {k: v for k, v in valid.items() if k != "signature"},
        }

        for name, payload in payloads.items():
            with self.subTest(name):
                receiver = authorizer("beta")
                assert receiver.import_session(payload, now=20) is None
                assert not receiver.authorized(prefix, now=21)

        receiver = authorizer("beta")
        assert receiver.import_session(valid, now=20) is not None
        assert receiver.authorized(prefix, now=21)

    def test_totp_matching_windows(self) -> None:
        """Accept codes one period either side of now, and none further out."""
        auth = authorizer()
        now = 1_000_000.0
        current = int(now // TOTP_PERIOD)

        for offset in (-1, 0, 1):
            with self.subTest(offset=offset):
                counter = current + offset
                assert auth.match(totp(AUTH_KEY, counter), now=now) == counter

        for offset in (-2, 2):
            with self.subTest(offset=offset):
                assert auth.match(totp(AUTH_KEY, current + offset), now=now) is None


class AuthFlowTests(unittest.IsolatedAsyncioTestCase):
    """Tests for AUTH, session grants, and auto-op after authentication."""

    async def test_auth_auto_op(self) -> None:
        """Verify authenticated users receive automatic operator privileges."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == [("#test", "+o", ("owner",))]

    async def test_auth_auto_op_skips_already_opped(self) -> None:
        """Verify auto-op skips users who already have operator status."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER
        runtime.member("owner").modes.add("o")

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_mismatched_identity(self) -> None:
        """Do not op a nickname held by a different IRC identity."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = Prefix("owner", "other", "other.host")

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_when_not_opped(self) -> None:
        """Verify auto-op skips channels where bot is not opped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.join = JoinState.JOINED
        runtime.member("owner").prefix = OWNER

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_claim_publish_failure_revokes(self) -> None:
        """Verify a publish failure after claim success revokes the session."""
        bot, fake_irc = bot_with_irc(
            coordinator=FailingWriteCoordinator(),
        )
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        pending = next(iter(bot.sessions.pending.values()))
        assert pending.prefix == prefix.render()
        assert pending.revoked
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_grant_does_not_replace_queued_revocation(self) -> None:
        """Persist a QUIT's revocation queued while AUTH waits for the lock."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // 30))
        syncing = asyncio.Event()
        sync = bot.sessions.sync

        async def signal_sync(identity: str, session: Session) -> bool:
            syncing.set()
            return await sync(identity, session)

        with patch.object(bot.sessions, "sync", signal_sync):
            async with bot.sessions.lock:
                auth = asyncio.create_task(
                    send_command(bot, prefix, f"AUTH {valid_code}"),
                )
                async with asyncio.timeout(1):
                    await syncing.wait()
                # AUTH has granted locally and now waits for the lock.
                await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))

            await auth

        await drain_session_writes(bot)

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts
        assert all(put["revoked"] is True for put in coordinator.session_puts)
        assert bot.sessions.pending == {}

    async def test_auth_refuses_after_irc_disconnect_mid_auth(self) -> None:
        """Grant nothing when IRC disconnects while AUTH waits on JetStream."""
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
            bot.on_irc_disconnect()
            release.set()
            await auth

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts == []

    async def test_auth_revokes_after_irc_disconnect_mid_write(self) -> None:
        """Revoke a grant when IRC disconnects while it is being written."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        put_session = coordinator.put_session

        async def disconnect_during_put(record: dict[str, Any]) -> dict[str, Any]:
            bot.on_irc_disconnect()
            return await put_session(record)

        valid_code = totp(bot.authorizer.secret, int(time.time() // 30))
        with patch.object(coordinator, "put_session", disconnect_during_put):
            await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts[-1]["revoked"] is True

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
        """Grant a session for a valid TOTP code, then op the user where opped."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = prefix
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorized")]
        assert fake_irc.modes == [("#test", "+o", ("owner",))]
        assert len(coordinator.session_puts) == 1

    async def test_auth_refuses_replayed_code(self) -> None:
        """Authorize only the first identity to use a TOTP code."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        owner = Prefix("owner", "user", "host.example")
        intruder = Prefix("intruder", "user", "other.example")
        counter = int(time.time() // TOTP_PERIOD)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, owner, f"AUTH {valid_code}")
        await send_command(bot, intruder, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(owner.render())
        assert not bot.authorizer.authorized(intruder.render())
        assert fake_irc.privmsgs == [
            ("owner", "Authorized"),
            ("intruder", "Authorization failed"),
        ]
        assert coordinator.claim_requests == [counter, counter]
        assert len(coordinator.session_puts) == 1

    async def test_auth_fails_closed_when_coordinator_unready(self) -> None:
        """Stay silent and grant nothing when request_auth returns False.

        A malformed AUTH is silent too: its usage reply would tell a guesser
        that the bot is listening.

        This covers only AuthFlow's side: the fake coordinator denies attempts
        while disconnected. The real coordinator's readiness gate is tested in
        test_coordinator.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        coordinator.connected = False
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        for text in (f"AUTH {valid_code}", "AUTH", f"AUTH {valid_code} extra"):
            await send_command(bot, prefix, text)

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == []
        assert coordinator.session_puts == []

    async def test_auth_denies_when_durable_revocation_wins(self) -> None:
        """Do not report success when newer durable state revokes the session."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        async def put_session(record: dict[str, object]) -> dict[str, object]:
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

    async def test_auth_queues_revocation_when_bot_id_is_duplicate(self) -> None:
        """Queue a revocation when the session write fails on a duplicate bot ID."""
        bot, fake_irc, coordinator = bot_with_coordinator()
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
        assert session.revoked
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_attempt_limit(self) -> None:
        """Answer only the AUTH attempts the limit allows, however nicks cycle.

        The limit keys on the host, so a new nick on the same host gets no
        fresh attempts.
        """
        fake_irc = FakeIRC()
        coordinator = FakeCoordinator()
        bot = make_bot(irc=fake_irc, coordinator=coordinator)
        nicks = [f"nick{index}" for index in range(ATTEMPT_LIMIT + 2)]

        # Fewer attempts than the 8-per-10 s command limit, so only the
        # coordinator's AttemptStore can silence the surplus.
        with patch.object(bot.authorizer, "match", return_value=None):
            for nick in nicks:
                prefix = Prefix(nick, "user", "host.example")
                await send_command(bot, prefix, "AUTH 000000")

        assert fake_irc.privmsgs == [
            (nick, "Authorization failed") for nick in nicks[:ATTEMPT_LIMIT]
        ]
        assert coordinator.claim_requests == [-1] * ATTEMPT_LIMIT

    async def test_malformed_auth_counts_as_attempt(self) -> None:
        """Answer a malformed AUTH with its usage, and count it as an attempt.

        Once malformed attempts spend the limit, AUTH is silent, malformed or
        not, and even a valid code is refused.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))
        # A valid code with an extra argument is still malformed.
        malformed = ["AUTH", f"AUTH {valid_code} extra"]
        malformed += ["AUTH"] * (ATTEMPT_LIMIT - len(malformed))

        for text in (*malformed, f"AUTH {valid_code}", "AUTH"):
            await send_command(bot, prefix, text)

        assert fake_irc.privmsgs == [("owner", "AUTH <totp-code>")] * ATTEMPT_LIMIT
        assert not bot.authorizer.authorized(prefix.render())
        assert coordinator.claim_requests == []
        assert coordinator.session_puts == []

    async def test_wrong_auth_code_still_claims(self) -> None:
        """Deny an unmatched code, but still perform the claim round trip.

        The code goes through the IRC command queue, which watches the
        identity, so only the unmatched code can deny it: the first claim of
        the placeholder counter succeeds.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")

        with patch.object(bot.authorizer, "match", return_value=None):
            await send_command(bot, prefix, "AUTH 000000")

        assert coordinator.claim_requests == [-1]
        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts == []


class SessionSyncWriteTests(unittest.IsolatedAsyncioTestCase):
    """Tests for ordering and retrying durable session writes."""

    async def test_revocation_escalates_over_same_expiry_winner(self) -> None:
        """Escalate when the store winner shares the revocation's expiry."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = "owner!user@host.example"
        expires_at = time.time() + 600
        stale = bot.authorizer.create(prefix, expires_at, "alpha", 1, revoked=True)
        winner = bot.authorizer.create(prefix, expires_at, "alpha", 2)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(return_value=asdict(winner)),
        ):
            synced = await bot.sessions.sync(prefix, stale)

        assert not synced
        pending = bot.sessions.pending[casefold(prefix, "ascii")]
        assert pending.revoked
        assert pending.version == winner.version + 1
        assert not bot.authorizer.authorized(prefix)

    async def test_duplicate_coordinator_queues_session_writes(self) -> None:
        """Queue session writes while the coordinator reports a duplicate ID."""
        bot, _, coordinator = bot_with_coordinator()
        coordinator.duplicate = True
        session = bot.authorizer.grant("a!u@h")

        assert not await bot.sessions.sync("a!u@h", session)
        assert bot.sessions.pending

        coordinator.duplicate = False
        await bot.sessions.retry()

        assert coordinator.session_puts == [asdict(session)]
        assert not bot.sessions.pending

    async def test_pending_revocation_blocks_later_session_writes(self) -> None:
        """Never write a queued grant past an earlier still-pending revocation."""
        bot, _, coordinator = bot_with_coordinator()
        blocked = bot.authorizer.create(
            "old!user@host.example",
            time.time() + 100,
            bot.authorizer.issuer,
            1,
            revoked=True,
        )
        identity = "new!user@host.example"
        session = bot.authorizer.create(
            identity,
            time.time() + 100,
            bot.authorizer.issuer,
            1,
        )

        async def put_session(payload: dict[str, object]) -> dict[str, object]:
            if payload == asdict(blocked):
                msg = "unavailable"
                raise NatsError(msg)

            return payload

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            assert not await bot.sessions.sync("old!user@host.example", blocked)
            assert not await bot.sessions.sync(identity, session)

        assert put.await_count == 2
        assert all(call.args[0] == asdict(blocked) for call in put.await_args_list)
        assert casefold(identity, "ascii") in bot.sessions.pending

    async def test_expired_revocation_drains_from_pending_queue(self) -> None:
        """Drain a pending revocation whose stored record has already expired.

        The expired record imports as no winner: the queue must still drop it
        and write the next identity, without caching the expired record.
        """
        bot, _, coordinator = bot_with_coordinator()
        revocation = bot.authorizer.create(
            "old!user@host.example",
            time.time() - 1,
            bot.authorizer.issuer,
            1,
            revoked=True,
        )
        identity = "new!user@host.example"
        session = bot.authorizer.create(
            identity,
            time.time() + 100,
            bot.authorizer.issuer,
            1,
        )

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(
                side_effect=[
                    NatsError("unavailable"),
                    asdict(revocation),
                    asdict(session),
                ],
            ),
        ):
            assert not await bot.sessions.sync(
                "old!user@host.example",
                revocation,
            )
            assert bot.sessions.pending
            assert await bot.sessions.sync(identity, session)

        assert not bot.sessions.pending
        assert bot.authorizer.authorized(identity)
        assert [s.prefix for s in bot.authorizer.records.values()] == [identity]

    async def test_new_session_replaces_pending_revocation(self) -> None:
        """Never retry an old revocation after a newer session write succeeds."""
        bot, _, coordinator = bot_with_coordinator()
        old_identity = "Owner!user@host.example"
        identity = old_identity.casefold()
        expires_at = time.time() + 100
        session = bot.authorizer.create(
            identity,
            expires_at,
            bot.authorizer.issuer,
            2,
        )
        revocation = bot.authorizer.create(
            old_identity,
            expires_at,
            bot.authorizer.issuer,
            1,
            revoked=True,
        )

        async def put_session(payload: dict[str, object]) -> dict[str, object]:
            if payload.get("revoked") is True:
                msg = "unavailable"
                raise NatsError(msg)

            coordinator.session_puts.append(payload)
            return payload

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            assert not await bot.sessions.sync(old_identity, revocation)
            assert await bot.sessions.sync(identity, session)
            await bot.sessions.retry()

        assert put.await_count == 2
        assert coordinator.session_puts == [asdict(session)]
        assert not bot.sessions.pending

    async def test_session_write_applies_authoritative_winner(self) -> None:
        """Converge local authorization when a newer durable mutation wins."""
        bot, _, coordinator = bot_with_coordinator()
        identity = "owner!user@host.example"
        active = bot.authorizer.grant(identity)
        winner = bot.authorizer.create(
            identity,
            active.expires_at,
            active.issuer,
            active.version + 1,
            revoked=True,
        )
        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(return_value=asdict(winner)),
        ):
            assert await bot.sessions.sync(identity, active)

        assert not bot.authorizer.authorized(identity)

    async def test_revocation_queued_during_write_is_kept(self) -> None:
        """Keep a revocation queued while an older write for the identity runs."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        session = bot.authorizer.grant(prefix.render())
        writing = asyncio.Event()
        release = asyncio.Event()
        written: list[dict[str, object]] = []

        async def slow_put(record: dict[str, object]) -> dict[str, object]:
            if not record["revoked"]:
                writing.set()
                await release.wait()

            written.append(record)
            return record

        with patch.object(coordinator, "put_session", AsyncMock(side_effect=slow_put)):
            grant = asyncio.create_task(
                bot.sessions.sync(prefix.render(), session),
            )
            async with asyncio.timeout(1):
                await writing.wait()
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            release.set()
            await grant
            await drain_session_writes(bot)

        assert [record["revoked"] for record in written] == [False, True]
        assert not bot.sessions.pending

    async def test_revocation_retries_authoritative_active_winner(self) -> None:
        """Revoke a newer active session returned by the durable store."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        active = bot.authorizer.grant(prefix.render())
        winner = bot.authorizer.create(
            prefix.render(),
            active.expires_at + 1,
            "beta",
            active.version,
        )
        attempts: list[dict[str, object]] = []

        async def put_session(session: dict[str, object]) -> dict[str, object]:
            attempts.append(session)
            return asdict(winner) if len(attempts) == 1 else session

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ):
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.sessions.pending
            await bot.sessions.retry()

        # The retry revokes the winner itself, not the original session.
        escalated = bot.authorizer.create(
            winner.prefix,
            winner.expires_at,
            winner.issuer,
            winner.version + 1,
            revoked=True,
        )
        assert len(attempts) == 2
        assert attempts[-1] == asdict(escalated)
        assert not bot.sessions.pending

    async def test_revocation_retries_failed_publish(self) -> None:
        """Retry a session revocation after JetStream recovers."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=NatsError("unavailable")),
        ) as put:
            await bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert bot.sessions.pending
            put.side_effect = None
            put.return_value = next(iter(bot.sessions.pending.values()))
            await bot.sessions.retry()

        assert not bot.sessions.pending
        assert put.await_count == 2

    async def test_revocation_uses_session_prefix_across_case_folding(self) -> None:
        """File a revocation under its session's prefix, not the observed one.

        Under rfc1459, foo[ and foo{ fold together, so a QUIT seen as foo{
        revokes the session granted to foo[; the store rejects a record filed
        under a key that differs from its own prefix.
        """
        bot, _, coordinator = bot_with_coordinator()
        store = SessionStore("efnet", 1, COORDINATION_KEY, 3600)
        bot.authorizer.grant("foo[!u@h")

        bot.sessions.revoke(Prefix("foo{", "u", "h"))
        with patch.object(coordinator, "put_session", store.put):
            await bot.sessions.retry()

        key, record = next(iter(bot.sessions.pending.items()))
        assert record.prefix == "foo[!u@h"
        assert key == casefold("foo[!u@h", "ascii")
        assert store.parse(store.key("foo[!u@h"), asdict(record)) is not None
        await bot.tasks.drain()

    async def test_requeued_revocation_does_not_block_later_writes(self) -> None:
        """Write a later grant when an earlier revocation meets a newer grant."""
        bot, _, coordinator = bot_with_coordinator()
        bot.authorizer.grant("x!u@h")
        revoked = bot.authorizer.revoke("x!u@h")
        assert revoked is not None
        bot.sessions.queue(revoked.prefix, revoked)
        newer = bot.authorizer.create(
            revoked.prefix,
            revoked.expires_at,
            revoked.issuer,
            revoked.version + 1,
        )

        async def put_session(record: dict[str, object]) -> dict[str, object]:
            if record["prefix"] == revoked.prefix:
                return asdict(newer)

            return record

        grant = bot.authorizer.grant("y!u@h")
        with patch.object(coordinator, "put_session", put_session):
            assert await bot.sessions.sync("y!u@h", grant)

        replacement = bot.sessions.pending[casefold("x!u@h", "ascii")]
        assert replacement.revoked
        assert replacement.version == newer.version + 1


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
        sessions = SessionSync(authorizer(), FakeCoordinator(), Tasks())
        now = time.time()
        sessions.watched["expired"] = ("expired!user@host", now - 1)
        expiry = now + 60
        key = "opaque"

        sessions.observe(key, session_value(expiry), replaying=False)

        assert sessions.watched == {key: ("owner!user@host", expiry)}

    def test_session_identity_cache_does_not_prune_during_replay(self) -> None:
        """Avoid rescanning the growing cache for every replayed session."""
        sessions = SessionSync(authorizer(), FakeCoordinator(), Tasks())
        record = session_value(time.time() + 60)

        with patch.object(sessions, "prune", wraps=sessions.prune) as prune:
            sessions.observe("opaque", record, replaying=True)

        prune.assert_not_called()
