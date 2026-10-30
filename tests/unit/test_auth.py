# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for TOTP authorization and session management."""

import asyncio
import json
import time
import unittest
from dataclasses import asdict
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, call, patch

from nats.errors import Error as NatsError

from botnats import Tasks
from botnats.auth import TOTP_PERIOD, SessionSync, TotpAuthorizer, totp
from botnats.channel import ChannelRecord
from botnats.irc.protocol import IRCMessage, Prefix, casefold
from botnats.nats.store import (
    ATTEMPT_LIMIT,
    SESSION_EXPIRY_GRACE,
    SESSION_TTL,
    Session,
)
from tests.unit.helpers import (
    AUTH_KEY,
    COORDINATION_KEY,
    OWNER,
    FailingWriteCoordinator,
    FakeCoordinator,
    FakeIRC,
    FakeKV,
    bot_with_coordinator,
    bot_with_irc,
    bounded,
    drain_session_writes,
    make_bot,
    send_command,
    session_value,
)


def authorizer(issuer: str = "alpha") -> TotpAuthorizer:
    """Create a TotpAuthorizer with test credentials."""
    return TotpAuthorizer(
        AUTH_KEY,
        coordination_secret=COORDINATION_KEY,
        identity_fold=lambda value: casefold(value, "ascii"),
        scope=(issuer, "efnet"),
    )


class TotpAuthorizerTests(unittest.TestCase):
    """Tests for TOTP code matching, session binding, and record ordering."""

    def test_rfc_vector_and_invalid_codes(self) -> None:
        """Match the RFC 4226 test vector and reject malformed or wrong codes."""
        auth = authorizer()

        assert totp(AUTH_KEY, 1) == "287082"
        # A code keeps its leading zeros.
        assert totp(AUTH_KEY, 36) == "003784"
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
        auth.rekey()

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
        auth.rekey()

        assert [record.revoked for record in auth.records.values()] == [True]
        assert not auth.authorized("Owner[!user@host", now=15)
        assert not auth.authorized("Owner{!user@host", now=15)

    def test_outlasting_revocation_blocks_grant(self) -> None:
        """Keep a held revocation that expires after a new session would."""
        auth = authorizer()
        prefix = "owner!user@example.test"
        auth.keep(auth.create(prefix, 10 + SESSION_TTL + 1, "beta", revoked=True))

        auth.grant(prefix, now=10)

        assert not auth.authorized(prefix, now=20)

    def test_dropped_key_keeps_revocation(self) -> None:
        """Keep a revocation when its durable key is deleted.

        drop_session forgets only a live session: forgetting the revocation
        would let the stale grant it revoked be kept again.
        """
        auth = authorizer("alpha")
        prefix = "owner!user@example.test"
        now = time.time()
        session = auth.grant(prefix, now=now)
        revoked = auth.revoke(prefix)

        assert auth.drop_session(prefix) == revoked
        auth.keep(session)

        assert [record.revoked for record in auth.records.values()] == [True]
        assert not auth.authorized(prefix, now=now + 11)
        # The stale grant is still kept where no revocation is held.
        fresh = authorizer("beta")
        fresh.keep(session)
        assert fresh.authorized(prefix, now=now + 11)

    def test_durable_revocation_blocks_stale_session(self) -> None:
        """Keep a watched revocation authoritative over its original session."""
        source = authorizer("alpha")
        target = authorizer("beta")
        prefix = "owner!user@example.test"
        session = source.grant(prefix, now=10)
        revoked = source.revoke(prefix)
        assert revoked is not None

        target.keep(revoked)
        target.keep(session)

        assert not target.authorized(prefix, now=21)

    def test_session_binding_and_expiry(self) -> None:
        """Bind a session to its prefix, expire it after an hour, and prune it."""
        auth = authorizer()
        prefix = "owner!user@example.test"

        auth.grant(prefix, now=11)
        assert not auth.authorized("other!user@example.test", now=12)
        # Every bot grants the same lifetime, so a changed one must fail here.
        assert auth.authorized(prefix, now=11 + 3599.9)
        assert not auth.authorized(prefix, now=11 + 3600)
        assert not auth.records

    def test_prune_drops_only_expired_records(self) -> None:
        """Prune expired sessions and revocations, and keep live ones."""
        auth = authorizer()
        now = time.time()
        for nick, granted in (("expired", now - SESSION_TTL - 30), ("live", now)):
            auth.grant(f"{nick}!user@example.test", now=granted)
            auth.grant(f"{nick}-revoked!user@example.test", now=granted)
            auth.revoke(f"{nick}-revoked!user@example.test")

        auth.prune()

        assert sorted(auth.records) == [
            "live!user@example.test",
            "live-revoked!user@example.test",
        ]

    def test_session_import(self) -> None:
        """Keep a session granted by another authorizer until it expires."""
        first = authorizer("alpha")
        second = authorizer("beta")
        prefix = "owner!user@example.test"

        session = first.grant(prefix, now=10)
        second.keep(session)

        assert second.authorized(prefix, now=10 + SESSION_TTL - 0.1)
        assert not second.authorized(prefix, now=10 + SESSION_TTL)

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
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == [("#test", "+o", ("owner",))]

    async def test_auth_auto_op_skips_already_opped(self) -> None:
        """Verify auto-op skips users who already have operator status."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER
        runtime.member("owner").modes.add("o")

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_mismatched_identity(self) -> None:
        """Do not op a nickname held by a different IRC identity."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = Prefix("owner", "other", "other.host")

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_auto_op_skips_channels_without_identity(self) -> None:
        """Op in #test though channels before it lack the user or their userhost."""
        fake_irc = FakeIRC()
        bot = make_bot(irc=fake_irc)
        runtimes = {}
        for channel in ("#absent", "#names", "#test"):
            record = ChannelRecord.new(channel, None, present=True)
            bot.channel_mgr.apply_record(record)
            runtime = bot.channel_mgr.channels[casefold(channel, "rfc1459")]
            runtime.member("alpha").modes.add("o")
            runtimes[channel] = runtime

        # NAMES without userhost-in-names lists a nickname alone.
        runtimes["#names"].member("owner")
        runtimes["#test"].member("owner").prefix = OWNER

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == [("#test", "+o", ("owner",))]

    async def test_auth_auto_op_survives_disconnect(self) -> None:
        """Attempt the MODE, and raise nothing, once IRC has disconnected."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("owner").prefix = OWNER
        fake_irc.connected = False

        with patch.object(fake_irc, "send", MagicMock(wraps=fake_irc.send)) as send:
            bot.auth_flow.auto_op(OWNER)

        assert send.call_args_list == [call("MODE", "#test", "+o", "owner")]

    async def test_auth_auto_op_skips_when_not_opped(self) -> None:
        """Verify auto-op skips channels where bot is not opped."""
        bot, fake_irc = bot_with_irc()
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("owner").prefix = OWNER

        bot.auth_flow.auto_op(OWNER)

        assert fake_irc.modes == []

    async def test_auth_claim_publish_failure_revokes(self) -> None:
        """Verify a publish failure after claim success revokes the session."""
        bot, fake_irc, _ = bot_with_coordinator(FailingWriteCoordinator())
        prefix = Prefix("owner", "user", "host.example")
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        pending = next(iter(bot.sessions.pending.values()))
        assert pending.prefix == prefix.render()
        assert pending.revoked
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]

    async def test_auth_failure_revokes_grant_over_equivalent_session(self) -> None:
        """Revoke the failed grant itself, not an equivalent prefix's session.

        foo{ and foo[ fold together under rfc1459 but have their own durable
        keys. A peer whose clock runs ahead holds a live foo{ session that
        outranks any grant for foo[; unless the grant replaces it, AUTH's
        revocation lands on foo{'s key, and the retry writes the foo[ grant
        live after AUTH reported failure.
        """
        coordinator = FailingWriteCoordinator()
        bot, fake_irc, _ = bot_with_coordinator(coordinator)
        bot.authorizer.keep(
            bot.authorizer.create("foo{!u@h", time.time() + SESSION_TTL + 30, "beta"),
        )
        prefix = Prefix("foo[", "u", "h")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))

        await send_command(bot, prefix, f"AUTH {valid_code}")
        coordinator.failing = False
        async with asyncio.timeout(1):
            await bot.sessions.retry()

        assert fake_irc.privmsgs == [("foo[", "Authorization failed")]
        puts = [(put["prefix"], put["revoked"]) for put in coordinator.session_puts]
        assert puts == [("foo[!u@h", True)]
        assert not bot.sessions.pending

    async def test_auth_grant_does_not_replace_queued_revocation(self) -> None:
        """Persist a QUIT's revocation queued while AUTH waits for the lock."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // 30))
        syncing = asyncio.Event()
        sync = bot.sessions.sync

        async def signal_sync(session: Session) -> bool:
            syncing.set()
            return await sync(session)

        # Bounded: a QUIT whose revocation waited on the held lock would hang.
        with patch.object(bot.sessions, "sync", signal_sync):
            async with asyncio.timeout(1):
                async with bot.sessions.lock:
                    auth = asyncio.create_task(
                        send_command(bot, prefix, f"AUTH {valid_code}"),
                    )
                    await syncing.wait()
                    # AUTH has granted locally and now waits for the lock.
                    bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))

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
                bot.events.on_irc_disconnect()
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

        async def disconnect_during_put(record: dict[str, Any]) -> Session:
            bot.events.on_irc_disconnect()
            return await put_session(record)

        valid_code = totp(bot.authorizer.secret, int(time.time() // 30))
        with patch.object(coordinator, "put_session", disconnect_during_put):
            await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts[-1]["revoked"] is True

    async def test_auth_revokes_grant_when_shutdown_cancels_write(self) -> None:
        """Leave a revocation stored when shutdown cancels AUTH's grant write.

        The cancelled write has already landed, so shutdown's final flush
        must write a revocation over it, not leave or rewrite the grant.
        An earlier session's revocation is still held: the grant must
        replace it, or the cancellation would find no session to revoke.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.keep(
            bot.authorizer.create(
                prefix.render(), time.time() + 60, "alpha", revoked=True
            ),
        )
        put_session = coordinator.put_session
        writing = asyncio.Event()

        async def hang_after_first_put(record: dict[str, Any]) -> Session:
            stored = await put_session(record)
            if not writing.is_set():
                writing.set()
                await asyncio.Event().wait()

            return stored

        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))
        with patch.object(coordinator, "put_session", hang_after_first_put):
            bot.events.on_irc_message(
                IRCMessage("PRIVMSG", ("alpha", f"AUTH {valid_code}"), prefix),
            )
            async with asyncio.timeout(1):
                await writing.wait()
                # A SIGTERM ends the IRC loop, which reports the disconnect,
                # then closes the bot.
                bot.events.on_irc_disconnect()
                await bot.close()

        key = coordinator.sessions.key(prefix.render())
        kv = cast("FakeKV", coordinator.sessions.kv)
        stored = coordinator.sessions.parse(key, json.loads(kv.entries[key][1]))
        assert stored is not None
        assert stored.revoked
        assert stored.version == 1
        assert not bot.authorizer.authorized(prefix.render())
        assert not bot.sessions.pending

    async def test_auth_stays_cancelled_behind_outranking_revocation(self) -> None:
        """End cancelled when shutdown cancels a grant write a revocation outranks.

        The held revocation expires after any grant AUTH can make, so the
        grant leaves it in place and there is no session left to revoke.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.keep(
            bot.authorizer.create(
                prefix.render(),
                time.time() + SESSION_TTL + 60,
                "beta",
                revoked=True,
            ),
        )
        writing = asyncio.Event()

        async def hang(record: dict[str, Any]) -> Session:
            del record
            writing.set()
            never: asyncio.Future[Session] = asyncio.get_running_loop().create_future()
            return await never

        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))
        with patch.object(coordinator, "put_session", hang):
            bot.events.on_irc_message(
                IRCMessage("PRIVMSG", ("alpha", f"AUTH {valid_code}"), prefix),
            )
            task = next(t for t in bot.tasks if t.get_name() == "admin-command")
            async with asyncio.timeout(1):
                await writing.wait()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        assert task.cancelled()

    async def test_auth_revocation_survives_shutdown_awaiting_lock(self) -> None:
        """Store AUTH's revocation though shutdown cancels its wait for the lock.

        IRC disconnects while the grant is written, so AUTH revokes it, but a
        background write holds the lock until shutdown cancels both.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        put_session = coordinator.put_session
        holding = asyncio.Event()

        async def hold_lock() -> None:
            async with bot.sessions.lock:
                holding.set()
                await asyncio.Event().wait()

        async def disconnect_during_put(record: dict[str, Any]) -> Session:
            stored = await put_session(record)
            bot.events.on_irc_disconnect()
            # Start waiting for the lock ahead of AUTH's revocation.
            bot.tasks.spawn(hold_lock(), "hold-lock")
            await asyncio.sleep(0)
            return stored

        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))
        with patch.object(coordinator, "put_session", disconnect_during_put):
            bot.events.on_irc_message(
                IRCMessage("PRIVMSG", ("alpha", f"AUTH {valid_code}"), prefix),
            )
            async with asyncio.timeout(1):
                await holding.wait()

        async with asyncio.timeout(1):
            await bot.close()

        key = coordinator.sessions.key(prefix.render())
        kv = cast("FakeKV", coordinator.sessions.kv)
        stored = coordinator.sessions.parse(key, json.loads(kv.entries[key][1]))
        assert stored is not None
        assert stored.revoked
        assert stored.version == 1
        assert not bot.sessions.pending

    async def test_auth_refuses_identity_invalidated_mid_auth(self) -> None:
        """Grant nothing when the user quits while AUTH waits on JetStream."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        # Mixed case and "[", as watches key identities ASCII-folded.
        prefix = Prefix("Owner[", "user", "host.example")
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
                bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
                release.set()
                await auth

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("Owner[", "Authorization failed")]
        assert coordinator.session_puts == []

    async def test_quit_invalidates_queued_auth(self) -> None:
        """Refuse an AUTH that was still queued behind another command at QUIT.

        The earlier command's watch ends first; that must not clear the
        invalidation the QUIT left for the AUTH still queued.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("Owner", "user", "host.example")
        counter = int(time.time() // TOTP_PERIOD)
        valid_code = totp(bot.authorizer.secret, counter)

        async with asyncio.timeout(1):
            # Nothing yields before the QUIT, so both commands are still queued.
            for text in ("XYZZY", f"AUTH {valid_code}"):
                bot.events.on_irc_message(
                    IRCMessage("PRIVMSG", ("alpha", text), prefix),
                )

            bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await asyncio.gather(*tuple(bot.tasks))

        # The code was valid and claimed; only the QUIT refused it.
        assert coordinator.claim_requests == [counter]
        assert fake_irc.privmsgs == [("Owner", "Authorization failed")]
        assert not bot.authorizer.authorized(prefix.render())
        assert not bot.sessions.watched_identities

    async def test_queued_auth_stays_invalid_after_sender_returns(self) -> None:
        """Refuse a queued AUTH whose sender quit and returned as the same prefix.

        The returning user's message watches the prefix again; that must not
        clear the invalidation the QUIT left for the AUTH still queued.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))

        async with asyncio.timeout(1):
            # Nothing yields, so the AUTH is still queued while its sender
            # quits, reconnects as the same prefix, and sends another message.
            bot.events.on_irc_message(
                IRCMessage("PRIVMSG", ("alpha", f"AUTH {valid_code}"), prefix),
            )
            bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            bot.events.on_irc_message(
                IRCMessage("PRIVMSG", ("alpha", "XYZZY"), prefix),
            )
            await asyncio.gather(*tuple(bot.tasks))

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert coordinator.session_puts == []
        assert not bot.sessions.watched_identities

    async def test_auth_queued_behind_own_command_is_granted(self) -> None:
        """Grant an AUTH queued behind another command from the same identity.

        The earlier command's watch ends first; the AUTH's own watch must
        outlive it, or the AUTH would see its identity as unwatched.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))

        # Both arrive before either runs.
        bot.events.on_irc_message(IRCMessage("PRIVMSG", ("alpha", "XYZZY"), prefix))
        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorized")]
        assert len(coordinator.session_puts) == 1
        assert not bot.sessions.watched_identities

    async def test_quit_without_queued_command_leaves_no_watch(self) -> None:
        """Grant an AUTH sent after a QUIT that had no command to invalidate.

        A QUIT must not start a watch: every user's QUIT would leave one
        behind, and its flag would refuse the AUTH of a user who reconnects
        as the same prefix.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))

        bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
        assert not bot.sessions.watched_identities
        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorized")]
        assert len(coordinator.session_puts) == 1
        assert not bot.sessions.watched_identities

    async def test_auth_success_grants_session(self) -> None:
        """Grant a session for a valid TOTP code, then op the user where opped."""
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("Owner[", "user", "host.example")
        runtime = bot.channel_mgr.channels[casefold("#test", "rfc1459")]
        runtime.member("alpha").modes.add("o")
        runtime.member("Owner[").prefix = prefix
        counter = int(time.time() // 30)
        valid_code = totp(bot.authorizer.secret, counter)

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("Owner[", "Authorized")]
        assert fake_irc.modes == [("#test", "+o", ("Owner[",))]
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
        # A peer's revocation, stored but not yet watched here, outlasts any
        # session this AUTH can grant.
        revocation = bot.authorizer.create(
            prefix.render(),
            time.time() + SESSION_TTL + 30,
            "beta",
            revoked=True,
        )
        async with asyncio.timeout(1):
            await coordinator.sessions.put(asdict(revocation))

        await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert [put["revoked"] for put in coordinator.session_puts] == [False]

    async def test_auth_revokes_grant_past_store_horizon(self) -> None:
        """Revoke and refuse a grant the store rejects after the clock steps back.

        The store's clock is two minutes behind the one that granted, so the
        session expires past the store's horizon.
        """
        bot, fake_irc, _ = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        valid_code = totp(bot.authorizer.secret, int(time.time() // TOTP_PERIOD))

        with patch("botnats.nats.store.time") as clock:
            clock.time.return_value = time.time() - 120
            await send_command(bot, prefix, f"AUTH {valid_code}")

        assert not bot.authorizer.authorized(prefix.render())
        assert fake_irc.privmsgs == [("owner", "Authorization failed")]
        assert next(iter(bot.sessions.pending.values())).revoked

    async def test_auth_attempt_limit(self) -> None:
        """Answer only the AUTH attempts the limit allows, however nicks cycle.

        The limit keys on the host, so a new nick on the same host gets no
        fresh attempts, whatever its ASCII case. Only ASCII case folds, so été
        is another host than Été.
        """
        fake_irc = FakeIRC()
        coordinator = FakeCoordinator()
        bot = make_bot(irc=fake_irc, coordinator=coordinator)
        nicks = [f"nick{index}" for index in range(ATTEMPT_LIMIT + 2)]

        # Fewer attempts than the 8-per-10 s command limit, so only the
        # coordinator's AttemptStore can silence the surplus.
        with patch.object(bot.authorizer, "match", return_value=None):
            for nick in nicks:
                host = "Été.EXAMPLE" if nick[-1] in "13" else "Été.example"
                prefix = Prefix(nick, "user", host)
                await send_command(bot, prefix, "AUTH 000000")

            other = Prefix("other", "user", "été.example")
            await send_command(bot, other, "AUTH 000000")

        assert fake_irc.privmsgs == [
            (nick, "Authorization failed") for nick in (*nicks[:ATTEMPT_LIMIT], "other")
        ]

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

    async def test_wrong_auth_code_skips_claim(self) -> None:
        """Deny an unmatched code without claiming any counter.

        The code goes through the IRC command queue, which watches the
        identity, so only the unmatched code can deny it.
        """
        bot, fake_irc, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")

        with patch.object(bot.authorizer, "match", return_value=None):
            await send_command(bot, prefix, "AUTH 000000")

        assert coordinator.claim_requests == []
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
            AsyncMock(return_value=winner),
        ):
            async with asyncio.timeout(1):
                synced = await bot.sessions.sync(stale)

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

        async with asyncio.timeout(1):
            assert not await bot.sessions.sync(session)
            assert bot.sessions.pending

            coordinator.duplicate = False
            await bot.sessions.retry()

        assert coordinator.session_puts == [asdict(session)]
        assert not bot.sessions.pending

    async def test_queue_keeps_ascii_distinct_identities_apart(self) -> None:
        """Keep queued mutations of identities with distinct ASCII folds apart.

        The store keys sessions ASCII-folded, so Été and été, and foo{ and
        foo[, which rfc1459 folds together, each have their own key: a
        revocation for one must not replace the other's queued grant.
        """
        for granted, revoked in (("été!u@h", "Été!u@h"), ("foo{!u@h", "foo[!u@h")):
            bot, _, coordinator = bot_with_coordinator()
            with self.subTest(granted=granted):
                coordinator.duplicate = True
                grant = bot.authorizer.grant(granted)
                revocation = bot.authorizer.create(
                    revoked,
                    grant.expires_at,
                    grant.issuer,
                    grant.version + 1,
                    revoked=True,
                )

                async with asyncio.timeout(1):
                    assert not await bot.sessions.sync(grant)
                    assert not await bot.sessions.sync(revocation)
                    coordinator.duplicate = False
                    await bot.sessions.retry()

                assert coordinator.session_puts == [asdict(grant), asdict(revocation)]

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

        async def put_session(payload: dict[str, Any]) -> Session:
            if payload == asdict(blocked):
                msg = "unavailable"
                raise NatsError(msg)

            return Session(**payload)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            async with asyncio.timeout(1):
                assert not await bot.sessions.sync(blocked)
                assert not await bot.sessions.sync(session)

        assert put.await_count == 2
        assert all(call.args[0] == asdict(blocked) for call in put.await_args_list)
        assert casefold(identity, "ascii") in bot.sessions.pending

    async def test_expired_revocation_drains_from_pending_queue(self) -> None:
        """Drain a pending revocation whose stored record has already expired.

        The store returns the expired record, which is no winner: the queue
        must still drop it and write the next identity, without caching it.
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
                side_effect=[NatsError("unavailable"), revocation, session],
            ),
        ):
            async with asyncio.timeout(1):
                assert not await bot.sessions.sync(revocation)
                assert bot.sessions.pending
                assert await bot.sessions.sync(session)

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

        async def put_session(payload: dict[str, Any]) -> Session:
            if payload.get("revoked") is True:
                msg = "unavailable"
                raise NatsError(msg)

            coordinator.session_puts.append(payload)
            return Session(**payload)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ) as put:
            async with asyncio.timeout(1):
                assert not await bot.sessions.sync(revocation)
                assert await bot.sessions.sync(session)
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
            AsyncMock(return_value=winner),
        ):
            async with asyncio.timeout(1):
                assert await bot.sessions.sync(active)

        assert not bot.authorizer.authorized(identity)

    async def test_revocation_queued_during_write_is_kept(self) -> None:
        """Keep a revocation queued while an older write for the identity runs."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        session = bot.authorizer.grant(prefix.render())
        writing = asyncio.Event()
        release = asyncio.Event()
        written: list[dict[str, Any]] = []

        async def slow_put(record: dict[str, Any]) -> Session:
            if not record["revoked"]:
                writing.set()
                await release.wait()

            written.append(record)
            return Session(**record)

        # Bounded: a QUIT whose revocation waited on the held lock would hang.
        with patch.object(coordinator, "put_session", AsyncMock(side_effect=slow_put)):
            async with asyncio.timeout(1):
                grant = asyncio.create_task(
                    bot.sessions.sync(session),
                )
                await writing.wait()
                bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
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
        attempts: list[dict[str, Any]] = []

        async def put_session(session: dict[str, Any]) -> Session:
            attempts.append(session)
            return winner if len(attempts) == 1 else Session(**session)

        with patch.object(
            coordinator,
            "put_session",
            AsyncMock(side_effect=put_session),
        ):
            bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert not bot.authorizer.authorized(prefix.render())
            assert bot.sessions.pending
            async with asyncio.timeout(1):
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
            bot.events.on_irc_message(IRCMessage("QUIT", (), prefix))
            await drain_session_writes(bot)
            assert bot.sessions.pending
            put.side_effect = None
            put.return_value = next(iter(bot.sessions.pending.values()))
            async with asyncio.timeout(1):
                await bot.sessions.retry()

        assert not bot.sessions.pending
        assert put.await_count == 2

    async def test_revoke_does_not_wait_for_durable_write(self) -> None:
        """Revoke a QUIT's session locally at once and write it in background.

        The IRC read loop calls revoke(), so it must not wait on JetStream.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        bot.authorizer.grant(prefix.render())

        bot.sessions.revoke(prefix)
        # Nothing has yielded, so the write has not started.
        assert not bot.authorizer.authorized(prefix.render())
        assert bot.sessions.pending
        await drain_session_writes(bot)

        assert not bot.sessions.pending
        assert [put["revoked"] for put in coordinator.session_puts] == [True]

    async def test_revocation_uses_session_prefix_across_case_folding(self) -> None:
        """File a revocation under its session's prefix, not the observed one.

        Under rfc1459, foo{ and foo[ fold together, so a QUIT seen as foo[
        revokes the session granted to foo{; an ASCII fold would miss it. The
        store keys a record by its own prefix, so only a revocation carrying
        foo{ replaces that session's durable record.
        """
        bot, _, coordinator = bot_with_coordinator()
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(bot.authorizer.grant("foo{!u@h"))

        bot.sessions.revoke(Prefix("foo[", "u", "h"))
        await drain_session_writes(bot)

        puts = [(put["prefix"], put["revoked"]) for put in coordinator.session_puts]
        assert puts == [("foo{!u@h", False), ("foo{!u@h", True)]
        assert not bot.sessions.pending

    async def test_requeued_revocation_does_not_block_later_writes(self) -> None:
        """Write a later grant when an earlier revocation meets a newer grant."""
        bot, _, coordinator = bot_with_coordinator()
        bot.authorizer.grant("x!u@h")
        revoked = bot.authorizer.revoke("x!u@h")
        assert revoked is not None
        bot.sessions.queue(revoked)
        newer = bot.authorizer.create(
            revoked.prefix,
            revoked.expires_at,
            revoked.issuer,
            revoked.version + 1,
        )

        async def put_session(record: dict[str, Any]) -> Session:
            if record["prefix"] == revoked.prefix:
                return newer

            return Session(**record)

        grant = bot.authorizer.grant("y!u@h")
        with patch.object(coordinator, "put_session", put_session):
            async with asyncio.timeout(1):
                assert await bot.sessions.sync(grant)

        replacement = bot.sessions.pending[casefold("x!u@h", "ascii")]
        assert replacement.revoked
        assert replacement.version == newer.version + 1

    async def test_rolled_back_grant_rewrites_held_revocation(self) -> None:
        """Write a held revocation again when its key rolls back to the grant.

        A NATS writer without the coordination secret can re-put the earlier
        signed grant; a bot started later would replay only that grant.
        """
        bot, _, coordinator = bot_with_coordinator()
        # Mixed case and "[", as the write-back compares identities ASCII-folded.
        prefix = "Owner[!user@host.example"
        grant = bot.authorizer.grant(prefix)
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)
            revocation = bot.authorizer.revoke(prefix)
            assert revocation is not None
            assert await bot.sessions.sync(revocation)

        key = coordinator.sessions.key(prefix)
        # The watch echoing this bot's own write is no rollback.
        bot.sessions.observe(key, revocation, replaying=False)
        assert not bot.tasks

        kv = cast("FakeKV", coordinator.sessions.kv)
        kv.store(key, json.dumps(asdict(grant)).encode())

        bot.sessions.observe(key, grant, replaying=False)
        await drain_session_writes(bot)

        stored = json.loads(kv.entries[key][1])
        assert coordinator.sessions.parse(key, stored) == revocation
        assert not bot.authorizer.authorized(prefix)
        assert not bot.sessions.pending

    async def test_lost_key_rewrites_held_revocation(self) -> None:
        """Write a held revocation again when its key is deleted or garbled.

        A NATS writer without the coordination secret can drop the record,
        wait for every bot to be replaced, then re-put the earlier signed
        grant; bots started after the loss would accept it.
        """
        prefix = "owner!user@host.example"
        for loss in ("deleted", "unreplayed", "garbled"):
            with self.subTest(loss=loss):
                bot, _, coordinator = bot_with_coordinator()
                grant = bot.authorizer.grant(prefix)
                assert await bounded(bot.sessions.sync(grant))
                revocation = bot.authorizer.revoke(prefix)
                assert revocation is not None
                assert await bounded(bot.sessions.sync(revocation))
                key = coordinator.sessions.key(prefix)
                bot.sessions.observe(key, revocation, replaying=False)
                kv = cast("FakeKV", coordinator.sessions.kv)
                if loss == "garbled":
                    kv.store(key, b"not json")
                else:
                    del kv.entries[key]

                if loss == "deleted":
                    bot.sessions.forget(key)
                else:
                    # A replay reports only the keys holding a valid record.
                    bot.sessions.replayed(set())

                await drain_session_writes(bot)

                assert coordinator.session_puts[2:] == [asdict(revocation)]
                stored = json.loads(kv.entries[key][1])
                assert coordinator.sessions.parse(key, stored) == revocation
                assert not bot.sessions.pending

    async def test_lost_key_writes_back_only_live_revocations(self) -> None:
        """Drop a lost key's grant or expired revocation without writing it."""
        bot, _, coordinator = bot_with_coordinator()
        granted = bot.authorizer.grant("granted!user@host.example")
        expired = bot.authorizer.create(
            "expired!user@host.example",
            time.time() - 1,
            "beta",
            1,
            revoked=True,
        )
        bot.authorizer.keep(expired)
        # A delete can arrive before an expired key mapping is pruned.
        for session in (granted, expired):
            key = coordinator.sessions.key(session.prefix)
            bot.sessions.watched[key] = (session.prefix, session.expires_at)
            bot.sessions.forget(key)

        assert not bot.sessions.pending
        assert not bot.tasks
        assert not bot.authorizer.authorized(granted.prefix)

    async def test_lost_key_keeps_queued_mutation(self) -> None:
        """Leave a queued revocation as it is when its key is lost.

        Marked as a write-back, it would no longer escalate over a newer grant.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        grant = bot.authorizer.grant(prefix.render())
        assert await bounded(bot.sessions.sync(grant))
        key = coordinator.sessions.key(prefix.render())
        bot.sessions.observe(key, grant, replaying=False)
        coordinator.duplicate = True
        bot.sessions.revoke(prefix)
        await drain_session_writes(bot)
        queued = dict(bot.sessions.pending)
        assert queued

        bot.sessions.forget(key)

        assert bot.sessions.pending == queued
        assert not bot.sessions.restoring

    async def test_written_back_revocation_yields_to_newer_grant(self) -> None:
        """Drop, never escalate, a written-back revocation a newer grant outranks.

        The watch may deliver this bot's grant only after its revocation is
        stored, which writes the revocation back; if that write fails, the
        user may authenticate again on a peer before the retry.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = "owner!user@host.example"
        grant = bot.authorizer.grant(prefix)
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)
            revocation = bot.authorizer.revoke(prefix)
            assert revocation is not None
            assert await bot.sessions.sync(revocation)
            key = coordinator.sessions.key(prefix)
            coordinator.duplicate = True
            bot.sessions.observe(key, grant, replaying=False)
            await drain_session_writes(bot)
            assert bot.sessions.pending

            later = bot.authorizer.create(prefix, revocation.expires_at + 30, "beta")
            await coordinator.sessions.put(asdict(later))
            bot.sessions.observe(key, later, replaying=False)
            coordinator.duplicate = False
            await bot.sessions.retry()

        assert coordinator.session_puts[-1] == asdict(revocation)
        assert bot.authorizer.authorized(prefix)
        assert not bot.sessions.pending
        assert not bot.sessions.restoring

    async def test_revocation_queued_over_write_back_escalates(self) -> None:
        """Escalate a QUIT's revocation that replaced a queued write-back."""
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        grant = bot.authorizer.grant(prefix.render())
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)
            revocation = bot.authorizer.revoke(prefix.render())
            assert revocation is not None
            assert await bot.sessions.sync(revocation)
            key = coordinator.sessions.key(prefix.render())
            coordinator.duplicate = True
            bot.sessions.observe(key, grant, replaying=False)
            later = bot.authorizer.create(
                prefix.render(),
                grant.expires_at + 30,
                "beta",
            )
            await coordinator.sessions.put(asdict(later))
            bot.sessions.observe(key, later, replaying=False)
            bot.sessions.revoke(prefix)
            await drain_session_writes(bot)
            # A peer grants again before the QUIT's revocation is written.
            latest = bot.authorizer.create(
                prefix.render(),
                later.expires_at + 10,
                "beta",
            )
            await coordinator.sessions.put(asdict(latest))

            coordinator.duplicate = False
            await bot.sessions.retry()
            await bot.sessions.retry()

        assert not bot.authorizer.authorized(prefix.render())
        last = coordinator.session_puts[-1]
        assert (last["expires_at"], last["revoked"]) == (latest.expires_at, True)
        assert not bot.sessions.pending

    async def test_write_back_keeps_queued_revocation(self) -> None:
        """Never replace a queued revocation with a held record to write back.

        The queued revocation must still meet the newer grant and escalate.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = Prefix("owner", "user", "host.example")
        grant = bot.authorizer.grant(prefix.render())
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)
            coordinator.duplicate = True
            bot.sessions.revoke(prefix)
            await drain_session_writes(bot)
            key = coordinator.sessions.key(prefix.render())
            later = bot.authorizer.create(
                prefix.render(),
                grant.expires_at + 30,
                "beta",
            )
            await coordinator.sessions.put(asdict(later))
            bot.sessions.observe(key, later, replaying=False)

            # The earlier grant, re-put over the newer one, ranks below it.
            bot.sessions.observe(key, grant, replaying=False)
            coordinator.duplicate = False
            await drain_session_writes(bot)
            await bot.sessions.retry()
            await bot.sessions.retry()

        assert not bot.authorizer.authorized(prefix.render())
        last = coordinator.session_puts[-1]
        assert last["revoked"] is True
        assert last["version"] == later.version + 1

    async def test_drain_skips_mutation_replaced_during_earlier_write(self) -> None:
        """Write the revocation that replaced a grant during an earlier write."""
        bot, _, coordinator = bot_with_coordinator()
        bot.authorizer.grant("other!user@host.example")
        earlier = bot.authorizer.revoke("other!user@host.example")
        assert earlier is not None
        bot.sessions.queue(earlier)
        owner = Prefix("owner", "user", "host.example")
        grant = bot.authorizer.grant(owner.render())
        writing = asyncio.Event()
        release = asyncio.Event()
        put_session = coordinator.put_session

        async def slow_put(record: dict[str, Any]) -> Session:
            if record["prefix"] == earlier.prefix:
                writing.set()
                await release.wait()

            return await put_session(record)

        with patch.object(coordinator, "put_session", slow_put):
            async with asyncio.timeout(1):
                sync = asyncio.create_task(bot.sessions.sync(grant))
                await writing.wait()
                # The owner quits while the earlier identity's write runs.
                bot.sessions.revoke(owner)
                release.set()
                await sync

            await drain_session_writes(bot)

        owner_puts = [
            put["revoked"]
            for put in coordinator.session_puts
            if put["prefix"] == owner.render()
        ]
        assert owner_puts == [True]
        assert not bot.sessions.pending

    async def test_sync_settles_before_later_writes(self) -> None:
        """Report a written grant settled though a later write queues it back.

        While the drain writes an identity queued after the grant's, the watch
        may deliver an older record for the grant's identity, such as a peer's
        write of the revocation the grant replaced, which queues the stored
        grant to write back. AUTH would otherwise revoke that stored grant.
        """
        bot, _, coordinator = bot_with_coordinator()
        owner = "owner!user@host.example"
        grant = bot.authorizer.grant(owner)
        # Revocations an outage left queued, the owner's first.
        stale = bot.authorizer.create(
            owner,
            grant.expires_at - 1,
            "beta",
            1,
            revoked=True,
        )
        other = bot.authorizer.create(
            "other!user@host.example",
            grant.expires_at,
            "beta",
            1,
            revoked=True,
        )
        bot.sessions.queue(stale)
        bot.sessions.queue(other)
        key = coordinator.sessions.key(owner)
        put_session = coordinator.put_session

        async def late_echo(record: dict[str, Any]) -> Session:
            stored = await put_session(record)
            if record["prefix"] == other.prefix:
                bot.sessions.observe(key, stale, replaying=False)

            return stored

        with patch.object(coordinator, "put_session", late_echo):
            async with asyncio.timeout(1):
                assert await bot.sessions.sync(grant)
                await drain_session_writes(bot)

        kv = cast("FakeKV", coordinator.sessions.kv)
        assert coordinator.sessions.parse(key, json.loads(kv.entries[key][1])) == grant
        assert bot.authorizer.authorized(owner)
        assert not bot.sessions.pending

    async def test_unwritable_session_does_not_block_later_writes(self) -> None:
        """Keep a record the store refuses queued, and write the ones after it.

        A record expiring past the store's horizon, as after the wall clock
        steps back, is refused until the clock catches up.
        """
        bot, _, coordinator = bot_with_coordinator()
        refused = bot.authorizer.create(
            "other!user@host.example",
            time.time() + SESSION_TTL + SESSION_EXPIRY_GRACE + 60,
            bot.authorizer.issuer,
            1,
            revoked=True,
        )
        bot.sessions.queue(refused)
        grant = bot.authorizer.grant("owner!user@host.example")

        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)

        assert list(bot.sessions.pending.values()) == [refused]
        assert [put["prefix"] for put in coordinator.session_puts] == [
            refused.prefix,
            grant.prefix,
        ]

    async def test_flush_stops_when_jetstream_fails(self) -> None:
        """End the shutdown flush at a pass that writes nothing, not at its bound."""
        bot, _, coordinator = bot_with_coordinator()
        bot.sessions.queue(bot.authorizer.grant("owner!user@host.example"))
        attempts = 0

        async def unavailable(record: dict[str, Any]) -> Session:
            del record
            nonlocal attempts
            attempts += 1
            # Yield, so the timeout ends a flush that keeps retrying.
            await asyncio.sleep(0)
            msg = "NATS unavailable"
            raise NatsError(msg)

        with patch.object(coordinator, "put_session", unavailable):
            async with asyncio.timeout(1):
                await bot.sessions.flush()

        assert attempts == 1
        assert bot.sessions.pending

    async def test_flush_writes_escalated_revocation(self) -> None:
        """Write the escalation a queued revocation meets at shutdown.

        A peer granted the identity again, unseen by this bot, so the queued
        revocation loses to that grant. Its escalation would wait for the
        next retry, which shutdown never makes.
        """
        bot, _, coordinator = bot_with_coordinator()
        prefix = "owner!user@host.example"
        grant = bot.authorizer.grant(prefix)
        newer = bot.authorizer.create(prefix, grant.expires_at + 30, "beta")
        async with asyncio.timeout(1):
            assert await bot.sessions.sync(grant)
            await coordinator.sessions.put(asdict(newer))
            revoked = bot.authorizer.revoke(prefix)
            assert revoked is not None
            bot.sessions.queue(revoked)
            await bot.sessions.flush()

        escalated = bot.authorizer.create(
            prefix,
            newer.expires_at,
            newer.issuer,
            newer.version + 1,
            revoked=True,
        )
        assert coordinator.session_puts[-1] == asdict(escalated)
        assert not bot.sessions.pending


class SessionSyncWatchTests(unittest.TestCase):
    """Tests for the watched session records SessionSync owns."""

    def test_identity_watch_survives_casemapping_change(self) -> None:
        """Release a watch taken before the casemapping changed."""
        identity = "nick[!user@host"
        for first, second in (("ascii", "rfc1459"), ("rfc1459", "ascii")):
            bot, _ = bot_with_irc()
            with self.subTest(first=first):
                bot.channel_mgr.set_casemapping(first)
                bot.sessions.watch_identity(identity)

                bot.channel_mgr.set_casemapping(second)
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

    def test_expired_record_forgets_key(self) -> None:
        """Treat an expired record as a delete of the session its key held."""
        auth = authorizer()
        sessions = SessionSync(auth, FakeCoordinator(), Tasks())
        sessions.observe("opaque", session_value(time.time() + 60), replaying=False)
        assert auth.authorized("owner!user@host")

        sessions.observe("opaque", session_value(time.time() - 1), replaying=False)

        assert sessions.watched == {}
        assert not auth.authorized("owner!user@host")

    def test_delete_forgets_key(self) -> None:
        """Drop the session a deleted key held, and ignore an unknown key."""
        auth = authorizer()
        sessions = SessionSync(auth, FakeCoordinator(), Tasks())
        sessions.observe("opaque", session_value(time.time() + 60), replaying=False)

        sessions.forget("opaque")
        sessions.forget("unknown")

        assert sessions.watched == {}
        assert not auth.authorized("owner!user@host")

    def test_replay_drops_missing_keys(self) -> None:
        """Drop sessions whose keys a completed replay no longer contains."""
        auth = authorizer()
        sessions = SessionSync(auth, FakeCoordinator(), Tasks())
        expiry = time.time() + 60
        kept = auth.create("kept!user@host", expiry, "beta")
        gone = auth.create("gone!user@host", expiry, "beta")
        sessions.observe("kept-key", kept, replaying=True)
        sessions.observe("gone-key", gone, replaying=True)

        sessions.replayed({"kept-key"})

        assert sessions.watched == {"kept-key": (kept.prefix, expiry)}
        assert auth.authorized(kept.prefix)
        assert not auth.authorized(gone.prefix)

    def test_replay_keeps_grant_behind_expired_key(self) -> None:
        """Keep a newer local grant for a prefix an expired, unreplayed key held.

        An expired record gets no TTL delete and is missing from the replay;
        forgetting its key would drop the grant this bot has yet to write.
        """
        auth = authorizer()
        sessions = SessionSync(auth, FakeCoordinator(), Tasks())
        prefix = "owner!user@host"
        sessions.watched["expired-key"] = (prefix, time.time() - 1)
        auth.grant(prefix)

        sessions.replayed(set())

        assert sessions.watched == {}
        assert auth.authorized(prefix)

    def test_session_identity_cache_does_not_prune_during_replay(self) -> None:
        """Avoid rescanning the growing cache for every replayed session."""
        sessions = SessionSync(authorizer(), FakeCoordinator(), Tasks())
        record = session_value(time.time() + 60)

        with patch.object(sessions, "prune", wraps=sessions.prune) as prune:
            sessions.observe("opaque", record, replaying=True)

        prune.assert_not_called()

    def test_equivalent_identity_record_is_not_written_back(self) -> None:
        """Leave an IRC-equivalent identity's lower record under its own key.

        foo[ and foo{ fold together under rfc1459, so the held grant outranks
        the observed record, but each has its own durable key: writing the
        grant back would not restore the key the record came from.
        """
        bot, _ = bot_with_irc()
        held = bot.authorizer.grant("foo[!u@h")
        lower = bot.authorizer.create("foo{!u@h", held.expires_at - 60, "beta")

        bot.sessions.observe("foo{-key", lower, replaying=False)

        assert not bot.sessions.pending
        assert not bot.sessions.restoring
        assert not bot.tasks

    def test_session_delete_keeps_colliding_live_identity(self) -> None:
        """Delete only the ASCII durable identity represented by a KV key."""
        bot, _ = bot_with_irc()
        first = "Owner{!user@host"
        second = "Owner[!user@host"
        # The prefixes collide under the IRC fold but not under the ASCII fold.
        assert bot.caps.fold_identity(first) == bot.caps.fold_identity(second)
        assert casefold(first, "ascii") != casefold(second, "ascii")
        now = time.time()
        bot.authorizer.grant(first, now=now)
        bot.authorizer.grant(second, now=now + 1)
        # Each prefix has its own ASCII-folded KV key; deletes arrive by key.
        expiry = now + 60
        bot.sessions.watched["first-key"] = (first, expiry)
        bot.sessions.watched["second-key"] = (second, expiry)

        bot.sessions.forget("first-key")

        assert [s.prefix for s in bot.authorizer.records.values()] == [second]
        assert bot.authorizer.authorized(second)

        # The live session is held under second's IRC fold, not its ASCII fold.
        bot.sessions.forget("second-key")
        assert not bot.authorizer.records
