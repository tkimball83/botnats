# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""TOTP authentication, signed sessions, and their mesh-wide synchronization."""

import asyncio
import base64
import binascii
import hmac
import time
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from botnats.config import MIN_COORDINATION_KEY_BYTES
from botnats.irc.protocol import casefold
from botnats.nats.store import (
    PUBLISH_ERRORS,
    SESSION_EXPIRY_GRACE,
    Session,
    parse_session_record,
    session_signature,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from botnats import Tasks
    from botnats.bot import Bot
    from botnats.irc.protocol import Prefix
    from botnats.nats.coordinator import CoordinatorProtocol

MIN_TOTP_SECRET_BYTES = 20
TOTP_CODE_LENGTH = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1


class AuthFlow:
    """Handles AUTH attempts, claim deduplication, and post-auth auto-op."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    async def authenticate(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Validate a TOTP code and establish an authorized session."""
        if not prefix.complete:
            return

        bot = self.bot
        coordinator = bot.coordinator
        if len(arguments) != 1:
            await bot.commands.reply(prefix.nick, "AUTH <totp-code>")
            return

        rendered = prefix.render()
        identity = limit_identity(prefix)
        if not await coordinator.request_auth(identity):
            return

        counter = bot.authorizer.match(arguments[0])
        # A wrong code still performs the claim round trip so response
        # timing cannot distinguish it from a valid-but-replayed code.
        claimed = await coordinator.request_claim(
            counter if counter is not None else -1,
        )
        # AUTH runs off the IRC read loop, so the user may QUIT or change
        # identity while it waits; a grant after that would authorize an
        # identity that is already gone.
        if counter is not None and claimed and bot.sessions.watched_valid(rendered):
            session = bot.authorizer.grant(rendered)
            # The identity must still hold after the write: IRC may have
            # disconnected while it waited on JetStream.
            if (
                not await bot.sessions.sync(rendered, asdict(session))
                or not bot.authorizer.authorized(rendered)
                or not bot.sessions.watched_valid(rendered)
            ):
                revoked = bot.authorizer.revoke(rendered)
                if revoked is not None:
                    await bot.sessions.sync(revoked.prefix, asdict(revoked))

                await bot.commands.reply(prefix.nick, "Authorization failed")
                return

            await bot.commands.reply(prefix.nick, "Authorized")
            bot.tasks.spawn(self.auto_op(prefix), "admin-auto-op")
        else:
            await bot.commands.reply(prefix.nick, "Authorization failed")

    async def auto_op(self, prefix: Prefix) -> None:
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
                await bot.irc.send(
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
    outcome. A drain stops at the first failed write; the next retry resumes.

    Watched records: the coordinator reports validated records by KV key.
    A delete carries only the key, so the prefix each key holds is kept here
    until the record expires, is deleted, or is missing from a replay.
    """

    def __init__(
        self,
        authorizer: TotpAuthorizer,
        coordinator: CoordinatorProtocol,
        tasks: Tasks,
    ) -> None:
        self.authorizer = authorizer
        self.coordinator = coordinator
        self.lock = asyncio.Lock()
        self.pending: dict[str, dict[str, object]] = {}
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
        count, invalidated = self.watched_identities.pop(key, (1, True))
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

    def observe(
        self,
        key: str,
        record: dict[str, Any],
        *,
        replaying: bool,
    ) -> None:
        """Apply a validated watched record: import it, or drop it if expired."""
        now = time.time()
        if not replaying:
            self.prune(now)

        expiry = float(record["expires_at"])
        if expiry > now:
            self.watched[key] = (record["prefix"], expiry)
            self.authorizer.import_session(record)
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
        self.watched = {
            key: mapped for key, mapped in self.watched.items() if mapped[1] > current
        }

    def queue(self, identity: str, session: dict[str, object]) -> str:
        """Queue a mutation unless an unwritten one for the identity outranks it.

        AUTH grants before it waits for the lock, so a revocation queued
        meanwhile by a QUIT must not be replaced by the older grant.
        """
        key = casefold(identity, "ascii")
        now = time.time()
        incoming = self.authorizer.parse(session, now)
        queued = self.authorizer.parse(self.pending.get(key), now)
        if queued is None or (incoming is not None and incoming.order > queued.order):
            self.pending[key] = session

        return key

    async def sync(self, identity: str, session: dict[str, object]) -> bool:
        """Queue and write one mutation now; report whether it was written."""
        async with self.lock:
            key = self.queue(identity, session)
            await self.drain()
            return key not in self.pending

    async def retry(self) -> None:
        """Retry queued writes that failed while JetStream was unavailable."""
        async with self.lock:
            await self.drain()

    def revoke(self, prefix: Prefix) -> None:
        """Revoke a session locally now and write the revocation in background."""
        identity = prefix.render()
        self.invalidate(identity)
        revoked = self.authorizer.revoke(identity)
        if revoked is not None:
            # File it under the session's own prefix: the observed prefix can
            # differ in IRC-case-equivalent characters, and the store keys and
            # validates sessions by their own prefix.
            self.queue(revoked.prefix, asdict(revoked))
            self.tasks.spawn(self.retry(), "session-sync")

    async def drain(self) -> None:
        """Write queued mutations in order while holding the lock."""
        for identity, session in tuple(self.pending.items()):
            if not await self.write(identity, session):
                return

    async def write(self, identity: str, session: dict[str, object]) -> bool:
        """Write one queued mutation; re-queue a revocation that met a newer grant."""
        try:
            stored = await self.coordinator.put_session(identity, session)
        except PUBLISH_ERRORS:
            return False

        self.authorizer.import_session(stored)
        # revoke() queues without the lock, so a newer mutation for
        # this identity may have replaced this entry during the write; it is
        # still unwritten and must stay queued for its own drain.
        if self.pending.get(identity) is not session:
            return True

        if session.get("revoked") is True:
            winner = self.authorizer.parse(stored, time.time())
            if winner is not None and not winner.revoked:
                replacement = asdict(
                    self.authorizer.create(
                        winner.prefix,
                        winner.expires_at,
                        winner.issuer,
                        winner.version + 1,
                        revoked=True,
                    ),
                )
                # The write succeeded; the replacement waits for the next
                # retry so later identities are not held behind it.
                self.authorizer.import_session(replacement)
                self.pending[identity] = replacement
                return True

        del self.pending[identity]
        return True


class TotpAuthorizer:
    """TOTP verification and short-lived sessions bound to IRC prefixes."""

    def __init__(
        self,
        secret: str,
        *,
        coordination_secret: bytes,
        identity_fold: Callable[[str], str],
        scope: tuple[str, str],
        session_ttl: float,
    ) -> None:
        normalized = "".join(secret.split()).upper()
        try:
            padding = "=" * (-len(normalized) % 8)
            decoded = base64.b32decode(normalized + padding, casefold=True)
        except (binascii.Error, ValueError) as error:
            msg = "TOTP secret must be valid base32"
            raise ValueError(msg) from error

        if len(decoded) < MIN_TOTP_SECRET_BYTES:
            msg = "TOTP secret must contain at least 160 bits"
            raise ValueError(msg)

        if len(coordination_secret) < MIN_COORDINATION_KEY_BYTES:
            msg = "coordination secret must contain at least 32 bytes"
            raise ValueError(msg)

        issuer, network = scope
        if not issuer:
            msg = "authorization issuer must not be empty"
            raise ValueError(msg)

        if not network:
            msg = "authorization network must not be empty"
            raise ValueError(msg)

        self.coordination_key = coordination_secret
        self.identity_fold = identity_fold
        self.issuer = issuer
        self.network = network
        self.secret = decoded
        # The highest-ranked session or revocation per identity.
        self.records: dict[str, Session] = {}
        self.session_ttl = session_ttl

    def authorized(self, prefix: str, *, now: float | None = None) -> bool:
        """Return whether the prefix has a valid, unexpired session."""
        return self.get(prefix, now) is not None

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

    def get(self, prefix: str, now: float | None = None) -> Session | None:
        """Return an active session, pruning the record when expired."""
        key = self.identity_fold(prefix)
        record = self.records.get(key)
        current = time.time() if now is None else now
        if record is None or record.expires_at <= current:
            self.records.pop(key, None)
            return None

        return None if record.revoked else record

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
        # Only a revocation that outranks the new session blocks it.
        if existing is None or not existing.revoked or session.order > existing.order:
            self.records[key] = session

        return session

    def import_session(self, value: object, *, now: float | None = None) -> None:
        """Import a single session from a KV watch update into local cache."""
        if not isinstance(value, dict):
            return

        current = time.time() if now is None else now
        incoming = self.parse(value, current)
        if incoming is not None:
            self.keep(incoming)

    def keep(self, incoming: Session) -> None:
        """Keep a session or revocation if it outranks the identity's record."""
        key = self.identity_fold(incoming.prefix)
        existing = self.records.get(key)
        if existing is None or incoming.order > existing.order:
            self.records[key] = incoming

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

    def parse(self, value: object, current: float) -> Session | None:
        """Validate and parse a remotely supplied authorization session."""
        if not isinstance(value, dict):
            return None

        parsed = parse_session_record(self.coordination_key, self.network, value)
        if parsed is None or not (
            current
            < parsed.expires_at
            <= current + self.session_ttl + SESSION_EXPIRY_GRACE
        ):
            return None

        return parsed

    def prune(self, current: float | None = None) -> None:
        """Remove expired sessions and revocations."""
        cutoff = time.time() if current is None else current
        self.records = {k: r for k, r in self.records.items() if r.expires_at > cutoff}

    def rekey(self, *, now: float | None = None) -> None:
        """Collapse records onto a new identity fold, keeping the highest rank."""
        self.prune(now)
        records, self.records = self.records, {}
        for record in records.values():
            self.keep(record)

    def revoke(self, prefix: str) -> Session | None:
        """Destroy the session associated with the given prefix."""
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
    """Return the rate-limit key for a prefix, shared by both limiters."""
    return casefold(prefix.host or prefix.render(), "ascii")


def totp(secret: bytes, counter: int) -> str:
    """Generate a six-digit TOTP code for the given counter value."""
    digest = hmac.digest(secret, counter.to_bytes(8), "sha1")
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4]) & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"
