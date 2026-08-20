# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""TOTP authorization, session management, and admin command handling."""

import asyncio
import base64
import binascii
import hmac
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from botnats.channel import ChannelRecord
from botnats.config import MIN_COORDINATION_KEY_BYTES
from botnats.irc.protocol import casefold, format_message
from botnats.nats.coordinator import PUBLISH_ERRORS
from botnats.nats.store import (
    SESSION_EXPIRY_GRACE,
    parse_session_record,
    session_signature,
)
from botnats.validators import validate_channel, validate_key, validate_target

if TYPE_CHECKING:
    from collections.abc import Callable

    from botnats.bot import Bot
    from botnats.channel import ChannelRuntime
    from botnats.irc.protocol import Prefix

ADMIN_COMMAND_ARGS = 2
INVALID_CLAIM_COUNTER = -1
MAX_JOIN_ARGS = 2
MAX_RATE_BUCKETS = 8192
MIN_TOTP_SECRET_BYTES = 20
TOTP_CODE_LENGTH = 6


class AuthFlow:
    """Handles AUTH attempts, claim deduplication, and post-auth auto-op."""

    def __init__(self, bot: Bot) -> None:
        """Bind authentication flow to its bot."""
        self.bot = bot

    async def authenticate(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Validate a TOTP code and establish an authorized session."""
        if not prefix.complete:
            return
        bot = self.bot
        coordinator = bot.coordinator
        if len(arguments) != 1:
            await bot.safe_privmsg(prefix.nick, "AUTH <totp-code>")
            return
        rendered = prefix.render()
        identity = limit_identity(prefix)
        if not await coordinator.request_auth(identity):
            return
        counter = bot.authorizer.match(arguments[0])
        # A wrong code still performs the claim round trip so response
        # timing cannot distinguish it from a valid-but-replayed code.
        claimed = await coordinator.request_claim(
            counter if counter is not None else INVALID_CLAIM_COUNTER,
        )
        if counter is not None and claimed:
            session = bot.authorizer.grant(rendered)
            if not await bot.events.sync_session(
                rendered,
                session.to_dict(),
            ) or not bot.authorizer.authorized(rendered):
                revoked = bot.authorizer.revoke(rendered)
                if revoked is not None:
                    await bot.events.sync_session(rendered, revoked.to_dict())
                await bot.safe_privmsg(prefix.nick, "Authorization failed")
                return
            await bot.safe_privmsg(prefix.nick, "Authorized")
            bot.spawn(self.auto_op(prefix), "admin-auto-op")
        else:
            await bot.safe_privmsg(prefix.nick, "Authorization failed")

    async def auto_op(self, prefix: Prefix) -> None:
        """Grant operator status on all channels where this bot is opped."""
        bot = self.bot
        for channel in tuple(bot.channel_mgr.desired_channels.values()):
            runtime = bot.runtime(channel)
            if runtime is None or not bot.is_self_opped(runtime):
                continue
            member = runtime.members.get(bot.fold(prefix.nick))
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


class CommandHandler:
    """Processes authenticated admin commands from IRC private messages."""

    def __init__(self, bot: Bot) -> None:
        """Initialize the handler with the bot and register command mappings."""
        self.bot = bot
        self.command_limiter = RateLimiter()
        self.handlers = {
            "BAN": self.cmd_ban,
            "BANS": self.cmd_bans,
            "DEOP": self.cmd_deop,
            "INVITE": self.cmd_invite,
            "JOIN": self.cmd_join,
            "KEY": self.cmd_key,
            "OP": self.cmd_op,
            "PART": self.cmd_part,
            "STATUS": self.cmd_status,
            "UNBAN": self.cmd_unban,
        }

    async def channel_update(
        self,
        prefix: Prefix,
        channel: str,
        key: str | None,
        *,
        present: bool,
    ) -> None:
        """Publish a channel record update and apply it locally."""
        if present and self.bot.config.channel_modes:
            # Validation only: reject the join before the durable write when
            # the enforced MODE line cannot fit this channel name in 512 bytes.
            format_message(
                "MODE",
                (channel, self.bot.config.channel_modes),
                None,
            )
        current = self.bot.channel_mgr.channel_records.get(self.bot.fold(channel))
        if present and key is None:
            runtime = self.bot.runtime(channel)
            if runtime is not None:
                key = runtime.key
        record = ChannelRecord.new(
            channel,
            key,
            present=present,
            after=current.revision if current else None,
        )
        stored = await self.bot.coordinator.put_channel(
            channel,
            record.to_dict(),
        )
        authoritative = ChannelRecord.from_dict(stored)
        await self.bot.channel_mgr.apply_record(authoritative)
        if authoritative != record:
            await self.bot.safe_privmsg(prefix.nick, f"Update superseded for {channel}")
            return
        action = "Joining" if present else "Parting"
        await self.bot.safe_privmsg(prefix.nick, f"{action} {channel}")

    async def cmd_ban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Set a ban mask on a channel."""
        if len(arguments) != ADMIN_COMMAND_ARGS:
            msg = "BAN <channel> <mask>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        mask = validate_target(arguments[1])
        self.opped_channel(channel)
        await self.bot.irc.send("MODE", channel, "+b", mask)
        await self.bot.safe_privmsg(prefix.nick, f"Banned {mask} on {channel}")

    async def cmd_bans(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """List all tracked ban masks for a channel."""
        if len(arguments) != 1:
            msg = "BANS <channel>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        runtime = self.bot.runtime(channel)
        if runtime is None:
            await self.bot.safe_privmsg(prefix.nick, f"No record for {channel}")
        elif runtime.bans:
            for mask in sorted(runtime.bans.values()):
                await self.bot.safe_privmsg(prefix.nick, f"{channel} +b {mask}")
        else:
            await self.bot.safe_privmsg(prefix.nick, f"No bans tracked for {channel}")

    async def cmd_deop(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove operator status from a user on a channel."""
        if len(arguments) != ADMIN_COMMAND_ARGS:
            msg = "DEOP <channel> <nick>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.fold(target))
        if member is None or not self.bot.caps.is_opped(member.modes):
            await self.bot.safe_privmsg(
                prefix.nick,
                f"{target} is not opped on {channel}",
            )
            return
        operator_modes = self.bot.caps.operator_modes
        highest = next(
            index for index, mode in enumerate(operator_modes) if mode in member.modes
        )
        for mode in operator_modes[highest:]:
            await self.bot.irc.send("MODE", channel, f"-{mode}", member.nick)
        await self.bot.safe_privmsg(
            prefix.nick,
            f"Deopped {member.nick} on {channel}",
        )

    async def cmd_invite(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Invite a user to a channel."""
        if len(arguments) != ADMIN_COMMAND_ARGS:
            msg = "INVITE <channel> <nick>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        self.opped_channel(channel)
        await self.bot.irc.send("INVITE", target, channel)
        await self.bot.safe_privmsg(prefix.nick, f"Invited {target} to {channel}")

    async def cmd_join(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Add a channel to the desired set and begin joining it."""
        if not 1 <= len(arguments) <= MAX_JOIN_ARGS:
            msg = "JOIN <channel> [key]"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        key = validate_key(arguments[1]) if len(arguments) == MAX_JOIN_ARGS else None
        await self.channel_update(prefix, channel, key, present=True)

    async def cmd_key(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Display the stored key for a channel."""
        if len(arguments) != 1:
            msg = "KEY <channel>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        runtime = self.bot.runtime(channel)
        if runtime is None:
            await self.bot.safe_privmsg(prefix.nick, f"No record for {channel}")
        elif runtime.key:
            await self.bot.safe_privmsg(
                prefix.nick,
                f"Key for {channel}: {runtime.key}",
            )
        else:
            await self.bot.safe_privmsg(prefix.nick, f"No key set for {channel}")

    async def cmd_op(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Grant operator status to a user on a channel."""
        if len(arguments) != ADMIN_COMMAND_ARGS:
            msg = "OP <channel> <nick>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        target = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        member = runtime.members.get(self.bot.fold(target))
        if member is None or member.prefix is None or not member.prefix.complete:
            await self.bot.safe_privmsg(
                prefix.nick,
                f"{target} not found on {channel}",
            )
            return
        if self.bot.caps.is_opped(member.modes):
            await self.bot.safe_privmsg(
                prefix.nick,
                f"{member.nick} is already opped on {channel}",
            )
            return
        await self.bot.irc.send(
            "MODE",
            channel,
            f"+{self.bot.caps.op_mode}",
            member.nick,
        )
        await self.bot.safe_privmsg(
            prefix.nick,
            f"Opped {member.nick} on {channel}",
        )

    async def cmd_part(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove a channel from the desired set and leave it."""
        if len(arguments) != 1:
            msg = "PART <channel>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        await self.channel_update(prefix, channel, None, present=False)

    async def cmd_status(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Report the bot's current connection and channel status."""
        if arguments:
            msg = "STATUS takes no arguments"
            raise ValueError(msg)
        joined = sum(
            runtime.joined for runtime in self.bot.channel_mgr.channels.values()
        )
        own_id = self.bot.config.bot_id.casefold()
        peers = sum(
            peer.bot_id.casefold() != own_id for peer in self.bot.presence.active()
        )
        await self.bot.safe_privmsg(
            prefix.nick,
            f"bot id={self.bot.config.bot_id} nick={self.bot.irc.current_nick} "
            f"peers={peers} channels={joined}",
        )
        status = await self.bot.coordinator.status()
        await self.bot.safe_privmsg(prefix.nick, status.render())

    async def cmd_unban(self, prefix: Prefix, arguments: tuple[str, ...]) -> None:
        """Remove a ban mask from a channel."""
        if len(arguments) != ADMIN_COMMAND_ARGS:
            msg = "UNBAN <channel> <mask>"
            raise ValueError(msg)
        channel = validate_channel(arguments[0])
        mask = validate_target(arguments[1])
        runtime = self.opped_channel(channel)
        stored = runtime.bans.get(self.bot.fold(mask))
        if stored is None:
            await self.bot.safe_privmsg(
                prefix.nick,
                f"No matching ban for {mask} on {channel}",
            )
            return
        await self.bot.irc.send("MODE", channel, "-b", stored)
        await self.bot.safe_privmsg(prefix.nick, f"Unbanned {stored} on {channel}")

    async def dispatch(self, prefix: Prefix, text: str) -> None:
        """Route an incoming private message to the appropriate command handler."""
        identity = limit_identity(prefix)
        if not self.command_limiter.check(identity, limit=8, window=10.0):
            return
        try:
            name, arguments = parse_command(text)
        except ValueError as error:
            # Unauthenticated senders get silence, not a parse-error reply
            # that would confirm a bot is listening.
            if self.bot.authorizer.authorized(prefix.render()):
                await self.bot.safe_privmsg(
                    prefix.nick,
                    str(error) or "Command failed",
                )
            return

        if name == "AUTH":
            await self.bot.auth_flow.authenticate(prefix, arguments)
            return
        if not self.bot.authorizer.authorized(prefix.render()):
            return

        handler = self.handlers.get(name)
        if handler is None:
            await self.bot.safe_privmsg(prefix.nick, "Unknown command")
            return
        try:
            await handler(prefix, arguments)
        except (*PUBLISH_ERRORS, ValueError) as error:
            await self.bot.safe_privmsg(prefix.nick, str(error) or "Command failed")

    def opped_channel(self, channel: str) -> ChannelRuntime:
        """Return a tracked channel where this bot has operator status."""
        runtime = self.bot.runtime(channel)
        if runtime is None or not self.bot.is_self_opped(runtime):
            msg = f"Not opped on {channel}"
            raise ValueError(msg)
        return runtime


class RateLimiter:
    """Sliding-window rate limiter keyed by identity string."""

    def __init__(self) -> None:
        """Initialize empty rate-limit buckets."""
        self.buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def check(self, key: str, *, limit: int, window: float) -> bool:
        """Record an event and return whether the key is within its rate limit."""
        now = asyncio.get_running_loop().time()
        cutoff = now - window
        bucket = self.buckets.get(key)
        if bucket is None:
            if len(self.buckets) >= MAX_RATE_BUCKETS and not self.evict_stale(cutoff):
                # Fail closed: evicting a fresh bucket would let identity
                # churn reset an actively limited key's budget.
                return False
            bucket = deque()
            self.buckets[key] = bucket
        else:
            self.buckets.move_to_end(key)
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    def evict_stale(self, cutoff: float) -> bool:
        """Evict the least-recently-used bucket only if it has fully expired."""
        key, bucket = next(iter(self.buckets.items()))
        if bucket and bucket[-1] > cutoff:
            return False
        del self.buckets[key]
        return True


@dataclass(frozen=True, slots=True)
class Session:
    """Represent an authenticated administrator session bound to an IRC prefix."""

    expires_at: float
    issuer: str
    prefix: str
    revoked: bool
    version: int
    signature: str

    @property
    def order(self) -> tuple[float, int, bool]:
        """Return the durable mutation order for this session."""
        return self.expires_at, self.version, self.revoked

    def to_dict(self) -> dict[str, object]:
        """Return a serializable dictionary of session fields."""
        return asdict(self)


class TotpAuthorizer:
    """TOTP verification and short-lived sessions bound to IRC prefixes."""

    period = 30
    window = 1

    def __init__(
        self,
        secret: str,
        *,
        coordination_secret: bytes,
        identity_fold: Callable[[str], str],
        scope: tuple[str, str],
        session_ttl: float,
    ) -> None:
        """Decode the TOTP secret and validate configuration parameters."""
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
        self.revocations: dict[str, Session] = {}
        self.sessions: dict[str, Session] = {}
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
        session = self.sessions.get(key)
        if session is not None and casefold(session.prefix, "ascii") == casefold(
            prefix,
            "ascii",
        ):
            self.sessions.pop(key, None)

    def get(self, prefix: str, now: float | None = None) -> Session | None:
        """Return an active session, pruning it when expired."""
        key = self.identity_fold(prefix)
        session = self.sessions.get(key)
        current = time.time() if now is None else now
        if session is None or session.expires_at <= current:
            self.sessions.pop(key, None)
            return None
        return session

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
        revoked = self.revocations.get(key)
        if revoked is None or session.order > revoked.order:
            self.revocations.pop(key, None)
            self.sessions[key] = session
        return session

    def import_session(self, value: object, *, now: float | None = None) -> None:
        """Import a single session from a KV watch update into local cache."""
        if not isinstance(value, dict):
            return
        current = time.time() if now is None else now
        incoming = self.parse(value, current)
        if incoming is None:
            return
        key = self.identity_fold(incoming.prefix)
        if incoming.revoked:
            existing = self.sessions.get(key)
            if existing is not None and existing.order <= incoming.order:
                self.sessions.pop(key, None)
            revoked = self.revocations.get(key)
            if revoked is None or incoming.order > revoked.order:
                self.revocations[key] = incoming
            return
        revoked = self.revocations.get(key)
        if revoked is not None and revoked.order >= incoming.order:
            return
        existing = self.sessions.get(key)
        if existing is None or incoming.order > existing.order:
            self.sessions[key] = incoming

    def match(self, code: str, *, now: float | None = None) -> int | None:
        """Return the TOTP counter that produced the code, or None."""
        if not code.isascii() or len(code) != TOTP_CODE_LENGTH or not code.isdigit():
            return None
        current_counter = int((time.time() if now is None else now) // self.period)
        for offset in (
            0,
            *range(-1, -self.window - 1, -1),
            *range(1, self.window + 1),
        ):
            counter = current_counter + offset
            if hmac.compare_digest(totp(self.secret, counter), code):
                return counter
        return None

    def move(
        self,
        old_prefix: str,
        new_prefix: str,
        *,
        now: float | None = None,
    ) -> tuple[Session, Session] | None:
        """Move an active session after an observed nickname change."""
        current = time.time() if now is None else now
        session = self.get(old_prefix, current)
        if session is None:
            return None
        old_key = self.identity_fold(old_prefix)
        new_key = self.identity_fold(new_prefix)
        revoked_session = self.create(
            old_prefix,
            session.expires_at,
            session.issuer,
            session.version + 1,
            revoked=True,
        )
        moved = self.create(
            new_prefix,
            session.expires_at,
            session.issuer,
            session.version + 2,
        )
        self.sessions.pop(old_key, None)
        self.revocations[old_key] = revoked_session
        existing = self.sessions.get(new_key)
        revoked = self.revocations.get(new_key)
        if (existing is None or moved.order > existing.order) and (
            revoked is None or moved.order > revoked.order
        ):
            self.revocations.pop(new_key, None)
            self.sessions[new_key] = moved
        return revoked_session, moved

    def parse(self, value: object, current: float) -> Session | None:
        """Validate and parse a remotely supplied authorization session."""
        if not isinstance(value, dict):
            return None
        parsed = parse_session_record(self.coordination_key, self.network, value)
        if parsed is None or not (
            current < parsed[0] <= current + self.session_ttl + SESSION_EXPIRY_GRACE
        ):
            return None
        return Session(*parsed)

    def prune(self, current: float | None = None) -> None:
        """Remove expired sessions and revocations."""
        cutoff = time.time() if current is None else current
        self.sessions = {
            k: s for k, s in self.sessions.items() if s.expires_at > cutoff
        }
        self.revocations = {
            k: s for k, s in self.revocations.items() if s.expires_at > cutoff
        }

    def _refold(self, records: dict[str, Session]) -> dict[str, Session]:
        """Collapse records onto the current identity fold, keeping the newest."""
        folded: dict[str, Session] = {}
        for session in records.values():
            key = self.identity_fold(session.prefix)
            existing = folded.get(key)
            if existing is None or session.order > existing.order:
                folded[key] = session
        return folded

    def rekey(self, *, now: float | None = None) -> None:
        """Deduplicate sessions after an identity folding change."""
        self.prune(time.time() if now is None else now)
        self.sessions = self._refold(self.sessions)
        self.revocations = self._refold(self.revocations)
        for key, session in tuple(self.sessions.items()):
            revoked = self.revocations.get(key)
            if revoked is not None and revoked.order >= session.order:
                del self.sessions[key]

    def revoke(self, prefix: str) -> Session | None:
        """Destroy the session associated with the given prefix."""
        key = self.identity_fold(prefix)
        session = self.sessions.pop(key, None)
        if session is not None:
            session = self.create(
                session.prefix,
                session.expires_at,
                session.issuer,
                session.version + 1,
                revoked=True,
            )
            self.revocations[key] = session
        return session


def limit_identity(prefix: Prefix) -> str:
    """Return the rate-limit key for a prefix, shared by both limiters."""
    return casefold(prefix.host or prefix.render(), "ascii")


def parse_command(value: str) -> tuple[str, tuple[str, ...]]:
    """Split raw text into a command name and arguments."""
    words = value.split()
    if not words:
        msg = "empty command"
        raise ValueError(msg)
    return words[0].upper(), tuple(words[1:])


def totp(secret: bytes, counter: int) -> str:
    """Generate a six-digit TOTP code for the given counter value."""
    digest = hmac.digest(secret, counter.to_bytes(8), "sha1")
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4]) & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"
