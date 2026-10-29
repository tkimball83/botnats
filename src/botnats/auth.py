# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""TOTP authentication, signed sessions, and their mesh-wide synchronization."""

import asyncio
import hmac
import time
from dataclasses import asdict
from typing import TYPE_CHECKING

from botnats.irc.protocol import casefold
from botnats.nats.store import PUBLISH_ERRORS, Session, session_signature

if TYPE_CHECKING:
    from collections.abc import Callable

    from botnats import Tasks
    from botnats.bot import Bot
    from botnats.irc.protocol import Prefix
    from botnats.nats.coordinator import SessionWriter

TOTP_CODE_LENGTH = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1


class AuthFlow:
    """Handles AUTH attempts, claim deduplication, and post-auth auto-op."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    async def authenticate(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Validate a TOTP code and establish an authorized session."""
        bot = self.bot
        coordinator = bot.coordinator
        rendered = prefix.render()
        identity = limit_identity(prefix)
        # Over the attempt limit, or without NATS to enforce it, AUTH stays
        # silent, even malformed: a reply would only tell a guesser that the
        # bot is listening.
        if not await coordinator.request_auth(identity):
            return

        if len(arguments) != 1:
            bot.commands.reply(prefix.nick, "AUTH <totp-code>")
            return

        counter = bot.authorizer.match(arguments[0])
        claimed = counter is not None and await coordinator.request_claim(counter)
        # AUTH runs off the IRC read loop, so the user may QUIT or change
        # identity while it waits; a grant after that would authorize an
        # identity that is already gone.
        if claimed and bot.sessions.watched_valid(rendered):
            session = bot.authorizer.grant(rendered)
            try:
                synced = await bot.sessions.sync(session)
            except asyncio.CancelledError:
                # Shutdown cancels AUTH mid-write, before the check below can
                # deny it, and its final flush would write the grant still
                # queued. The cancelled write may already have landed, so
                # only a revocation supersedes it.
                revoked = bot.authorizer.revoke(rendered)
                if revoked is not None:
                    bot.sessions.queue(revoked)

                raise

            # The identity must still hold after the write: IRC may have
            # disconnected while it waited on JetStream.
            if (
                not synced
                or not bot.authorizer.authorized(rendered)
                or not bot.sessions.watched_valid(rendered)
            ):
                revoked = bot.authorizer.revoke(rendered)
                if revoked is not None:
                    # Queued before waiting on the lock: shutdown may cancel
                    # the wait, and its final flush writes only what is queued.
                    bot.sessions.queue(revoked)
                    await bot.sessions.retry()

                bot.commands.reply(prefix.nick, "Authorization failed")
                return

            bot.commands.reply(prefix.nick, "Authorized")
            self.auto_op(prefix)
        else:
            bot.commands.reply(prefix.nick, "Authorization failed")

    def auto_op(self, prefix: Prefix) -> None:
        """Grant operator status on all channels where this bot is opped."""
        bot = self.bot
        for runtime in tuple(bot.channel_mgr.channels.values()):
            channel = runtime.channel
            if not bot.channel_mgr.is_self_opped(runtime):
                continue

            member = runtime.members.get(bot.caps.fold(prefix.nick))
            if (
                member is None
                or member.prefix is None
                or not prefix.matches(member.prefix, bot.caps.casemapping)
                or bot.caps.is_opped(member.modes)
            ):
                continue

            try:
                bot.irc.send(
                    "MODE",
                    channel,
                    f"+{bot.caps.op_mode}",
                    member.nick,
                )
            except ConnectionError:
                continue


class SessionSync:
    """Own session state shared with peers: durable writes and watched records.

    Writes: IRC handlers apply a revocation locally at once and queue its
    durable write, which a background drain performs, so the IRC read loop
    never waits on JetStream. AUTH awaits sync() because it replies with the
    outcome. A drain stops at the first write JetStream fails; the next retry
    resumes.

    Watched records: the coordinator reports validated records by KV key.
    A delete carries only the key, so the prefix each key holds is kept here
    until the record expires, is deleted, or is missing from a replay.
    """

    def __init__(
        self,
        authorizer: TotpAuthorizer,
        coordinator: SessionWriter,
        tasks: Tasks,
    ) -> None:
        self.authorizer = authorizer
        self.coordinator = coordinator
        self.lock = asyncio.Lock()
        self.pending: dict[str, Session] = {}
        # Identity -> held record queued to write back over a rollback, not a
        # new mutation: a newer grant supersedes it unrevoked.
        self.restoring: dict[str, Session] = {}
        # KV key -> (prefix, expiry) for each unexpired watched session.
        self.watched: dict[str, tuple[str, float]] = {}
        # ASCII-folded identity -> (commands in flight, invalidated since the
        # first arrived). A command counts from the moment it is queued, so a
        # QUIT while an AUTH waits in the command queue still invalidates it.
        # The key ignores IRC casemapping, which can change while a command is
        # queued; a key folded under the old mapping would never be released.
        self.watched_identities: dict[str, tuple[int, bool]] = {}
        self.tasks = tasks

    def watch_identity(self, identity: str) -> None:
        """Start watching an identity for invalidation while a command runs."""
        key = casefold(identity, "ascii")
        count, invalidated = self.watched_identities.get(key, (0, False))
        self.watched_identities[key] = (count + 1, invalidated)

    def unwatch_identity(self, identity: str) -> None:
        """Stop one watch once its command finishes.

        The flag lasts until the identity's last command finishes, so a user
        reconnecting as the same prefix meanwhile fails closed until then.
        """
        key = casefold(identity, "ascii")
        count, invalidated = self.watched_identities.pop(key)
        if count > 1:
            self.watched_identities[key] = (count - 1, invalidated)

    def watched_valid(self, identity: str) -> bool:
        """Return whether a watched identity is still valid; unwatched is not."""
        key = casefold(identity, "ascii")
        watched = self.watched_identities.get(key)
        return watched is not None and not watched[1]

    def invalidate(self, identity: str) -> None:
        """Mark an identity that quit or changed as invalid for pending commands."""
        key = casefold(identity, "ascii")
        if key in self.watched_identities:
            count, _ = self.watched_identities[key]
            self.watched_identities[key] = (count, True)

    def invalidate_all(self) -> None:
        """Invalidate every pending command's identity after IRC disconnects.

        This bot can no longer see QUIT or NICK for them, so it cannot vouch
        that the identity still holds the prefix a pending AUTH would grant.
        """
        self.watched_identities = {
            key: (count, True) for key, (count, _) in self.watched_identities.items()
        }

    def observe(self, key: str, session: Session, *, replaying: bool) -> None:
        """Apply a validated watched record: keep it, or drop it if expired.

        A record below the one held for its key was rolled back, as when a
        NATS writer without the coordination secret re-puts the grant a
        revocation replaced. Bots that start later replay only that record,
        so the held one is written again unless a mutation for its identity
        is already queued. The record may instead be a late echo of this
        bot's own write, so the write-back never escalates over a newer grant.
        """
        now = time.time()
        if not replaying:
            self.prune(now)

        if session.expires_at > now:
            self.watched[key] = (session.prefix, session.expires_at)
            held = self.authorizer.keep(session)
            # A record of an IRC-equivalent identity lives under another key.
            identity = casefold(session.prefix, "ascii")
            if (
                held is not None
                and casefold(held.prefix, "ascii") == identity
                and identity not in self.pending
            ):
                self.pending[identity] = self.restoring[identity] = held
                self.tasks.spawn(self.retry(), "session-sync")
        else:
            self.forget(key)

    def forget(self, key: str) -> None:
        """Drop the local session a deleted or expired KV key held."""
        mapped = self.watched.pop(key, None)
        if mapped is not None:
            self.authorizer.drop_session(mapped[0])

    def replayed(self, keys: set[str]) -> None:
        """Drop sessions a completed watch replay no longer contains."""
        self.prune()
        for key in self.watched.keys() - keys:
            self.forget(key)

    def prune(self, now: float | None = None) -> None:
        """Discard expired key mappings, which receive no TTL delete event."""
        current = time.time() if now is None else now
        for key in [k for k, mapped in self.watched.items() if mapped[1] <= current]:
            del self.watched[key]

    def queue(self, session: Session) -> str:
        """Queue a mutation unless an unwritten one for its identity outranks it.

        AUTH grants before it waits for the lock, so a revocation queued
        meanwhile by a QUIT must not be replaced by the older grant. The
        identity is the session's own prefix, which the store keys it by.
        """
        key = casefold(session.prefix, "ascii")
        queued = self.pending.get(key)
        if queued is None or session.order > queued.order:
            self.pending[key] = session

        return key

    async def sync(self, session: Session) -> bool:
        """Queue and write one mutation now.

        Returns whether nothing remained unwritten for its identity once its
        write finished; a queued revocation that outranks the session drops it.
        """
        async with self.lock:
            return await self.drain(self.queue(session))

    async def retry(self) -> None:
        """Retry queued writes that failed while JetStream was unavailable."""
        async with self.lock:
            await self.drain()

    async def flush(self) -> None:
        """Write everything queued at shutdown, escalations included.

        A drain leaves an escalated revocation for the next retry, which
        shutdown never makes, so drain again until the queue is empty or a
        pass changes nothing, as when JetStream fails or the store refuses
        the rest.
        """
        async with self.lock:
            while self.pending:
                queued = dict(self.pending)
                await self.drain()
                if self.pending == queued:
                    return

    def revoke(self, prefix: Prefix) -> None:
        """Revoke a session locally now and write the revocation in background."""
        identity = prefix.render()
        self.invalidate(identity)
        revoked = self.authorizer.revoke(identity)
        if revoked is not None:
            self.queue(revoked)
            self.tasks.spawn(self.retry(), "session-sync")

    async def drain(self, key: str | None = None) -> bool:
        """Write queued mutations in order while holding the lock.

        Each entry is read when its turn comes: revoke() may replace one
        during an earlier write, and the superseded one must not be written.
        Returns whether key's write left nothing queued for it, checked
        before later writes: the watch may meanwhile deliver an older record
        for key and queue the record just written to write back.
        """
        settled = False
        for identity in tuple(self.pending):
            if not await self.write(identity, self.pending[identity]):
                break

            if identity == key:
                settled = key not in self.pending

        return settled

    async def write(self, identity: str, session: Session) -> bool:
        """Write one queued mutation; re-queue a revocation that met a newer grant.

        Returns False only when JetStream fails, which stops the drain. A
        record the store refuses, expiring past its horizon after the wall
        clock stepped back, stays queued until the clock catches up without
        holding later writes.
        """
        try:
            stored = await self.coordinator.put_session(asdict(session))
        except PUBLISH_ERRORS:
            return False
        except ValueError:
            return True

        # The store returns a validated record; an expired one is no winner.
        winner = stored if stored.expires_at > time.time() else None
        if winner is not None:
            self.authorizer.keep(winner)

        # revoke() queues without the lock, so a newer mutation for
        # this identity may have replaced this entry during the write; it is
        # still unwritten and must stay queued for its own drain.
        if self.pending.get(identity) is not session:
            return True

        if (
            session.revoked
            and winner is not None
            and not winner.revoked
            and self.restoring.get(identity) is not session
        ):
            replacement = self.authorizer.create(
                winner.prefix,
                winner.expires_at,
                winner.issuer,
                winner.version + 1,
                revoked=True,
            )
            # The write succeeded; the replacement waits for the next
            # retry so later identities are not held behind it.
            self.authorizer.keep(replacement)
            self.pending[identity] = replacement
            return True

        del self.pending[identity]
        self.restoring.pop(identity, None)
        return True


class TotpAuthorizer:
    """TOTP verification and short-lived sessions bound to IRC prefixes."""

    def __init__(
        self,
        secret: bytes,
        *,
        coordination_secret: bytes,
        identity_fold: Callable[[str], str],
        scope: tuple[str, str],
        session_ttl: float,
    ) -> None:
        self.coordination_key = coordination_secret
        self.identity_fold = identity_fold
        self.issuer, self.network = scope
        self.secret = secret
        # Each identity's highest-ranked session or revocation, except that a
        # grant replaces a held live session whatever its rank.
        self.records: dict[str, Session] = {}
        self.session_ttl = session_ttl

    def authorized(self, prefix: str, *, now: float | None = None) -> bool:
        """Return whether the prefix has a valid, unexpired session.

        An expired record is pruned on the way.
        """
        key = self.identity_fold(prefix)
        record = self.records.get(key)
        current = time.time() if now is None else now
        if record is None or record.expires_at <= current:
            self.records.pop(key, None)
            return False

        return not record.revoked

    def create(
        self,
        prefix: str,
        expires_at: float,
        issuer: str,
        version: int = 0,
        *,
        revoked: bool = False,
    ) -> Session:
        """Create a signed session value."""
        record: dict[str, object] = {
            "expires_at": expires_at,
            "issuer": issuer,
            "prefix": prefix,
            "revoked": revoked,
            "version": version,
        }
        return Session(
            expires_at=expires_at,
            issuer=issuer,
            prefix=prefix,
            revoked=revoked,
            version=version,
            signature=session_signature(self.coordination_key, self.network, record),
        )

    def drop_session(self, prefix: str) -> None:
        """Remove a cached session whose durable record was deleted."""
        key = self.identity_fold(prefix)
        record = self.records.get(key)
        if (
            record is not None
            and not record.revoked
            and casefold(record.prefix, "ascii") == casefold(prefix, "ascii")
        ):
            del self.records[key]

    def grant(
        self,
        prefix: str,
        *,
        now: float | None = None,
    ) -> Session:
        """Create an authenticated session for the given IRC prefix."""
        current = time.time() if now is None else now
        expires_at = current + self.session_ttl
        session = self.create(prefix, expires_at, self.issuer)
        key = self.identity_fold(prefix)
        existing = self.records.get(key)
        # Only a revocation that outranks the new session blocks it. A held
        # live session gives way even to a lower-ranked grant, so revoking
        # the prefix when AUTH fails revokes this grant under its own key.
        if existing is None or not existing.revoked or session.order > existing.order:
            self.records[key] = session

        return session

    def keep(self, incoming: Session) -> Session | None:
        """Keep a session or revocation if it outranks the identity's record.

        Returns the identity's record instead when that outranks incoming.
        """
        key = self.identity_fold(incoming.prefix)
        existing = self.records.get(key)
        if existing is None or incoming.order > existing.order:
            self.records[key] = incoming
            return None

        return existing if existing.order > incoming.order else None

    def match(self, code: str, *, now: float | None = None) -> int | None:
        """Return the TOTP counter that produced the code, or None."""
        if not code.isascii() or len(code) != TOTP_CODE_LENGTH or not code.isdigit():
            return None

        current_counter = int((time.time() if now is None else now) // TOTP_PERIOD)
        for offset in (
            0,
            *range(-1, -TOTP_WINDOW - 1, -1),
            *range(1, TOTP_WINDOW + 1),
        ):
            counter = current_counter + offset
            if hmac.compare_digest(totp(self.secret, counter), code):
                return counter

        return None

    def prune(self) -> None:
        """Remove expired sessions and revocations."""
        cutoff = time.time()
        for key in [k for k, r in self.records.items() if r.expires_at <= cutoff]:
            del self.records[key]

    def rekey(self) -> None:
        """Collapse records onto a new identity fold, keeping the highest rank."""
        records, self.records = self.records, {}
        for record in records.values():
            self.keep(record)

    def revoke(self, prefix: str) -> Session | None:
        """Replace the prefix's session with a signed revocation; return it."""
        key = self.identity_fold(prefix)
        record = self.records.get(key)
        if record is None or record.revoked:
            return None

        revoked = self.create(
            record.prefix,
            record.expires_at,
            record.issuer,
            record.version + 1,
            revoked=True,
        )
        self.records[key] = revoked
        return revoked


def limit_identity(prefix: Prefix) -> str:
    """Return the rate-limit key for a complete prefix, shared by both limiters."""
    return casefold(prefix.host or "", "ascii")


def totp(secret: bytes, counter: int) -> str:
    """Generate a six-digit TOTP code for the given counter value."""
    digest = hmac.digest(secret, counter.to_bytes(8), "sha1")
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4]) & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"
