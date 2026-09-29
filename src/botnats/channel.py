# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC channel state, membership, and lifecycle management."""

import asyncio
import logging
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from botnats import error_label
from botnats.config import mode_intent
from botnats.irc.protocol import (
    CASEMAPPINGS,
    DEFAULT_CASEMAPPING,
    Prefix,
    casefold,
    mask_matches,
    mode_requires_argument,
)
from botnats.nats.store import PUBLISH_ERRORS
from botnats.presence import BotPresence
from botnats.validators import (
    MAX_CHANNEL_REVISION,
    parse_channel_record,
    validate_channel_revision,
    validate_join,
    validate_key,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from botnats.bot import Bot

LOGGER = logging.getLogger(__name__)

# Resend a JOIN that got no reply the bot handles: a lost JOIN, or a refusal
# such as 477 (registered nicks only). A duplicate JOIN is harmless.
JOIN_REPLY_TIMEOUT = 60.0
# Upper bound of the random wait before answering a peer's help request.
PEER_HELP_DELAY = 1.0
PEER_REQUEST_COOLDOWN = 0.5


class ChannelManager:
    """Manages channel joins, parts, mode enforcement, and peer requests."""

    def __init__(self, bot: Bot) -> None:
        self.bot = bot
        # Durable records, including part tombstones, under the IRC fold and
        # under the ASCII fold that keys the store.
        self.channel_records: dict[str, ChannelRecord] = {}
        self.source_records: dict[str, ChannelRecord] = {}
        # One live owner per desired channel: its state, joins, and requests.
        self.channels: dict[str, ChannelRuntime] = {}
        self.mode_intent = mode_intent(bot.config.channel_modes)
        # Channels no longer desired whose PART could not be sent yet.
        self.pending_parts: dict[str, str] = {}
        # ASCII-folded channel -> channel whose key write failed. A retry
        # writes the key this bot sees on IRC at that moment, never the one
        # it saw when the write failed, so a superseded change is not replayed.
        self.pending_keys: dict[str, str] = {}
        # Key writes and their retries run one at a time, so each compares
        # against the record the previous write left.
        self.key_lock = asyncio.Lock()
        # Highest revision this bot has minted: concurrent local changes to
        # one channel (two admin commands, say) get distinct, ordered revisions.
        self.last_revision = 0
        # Each peer help request kind, and the action that answers it.
        self.help_actions: dict[str, Callable[[dict[str, Any]], Awaitable[None]]] = {
            "invite": self.invite_peer,
            "limit": self.make_room,
            "op": self.op_peer,
            "unban": self.unban_peer,
        }

    async def apply_record(self, record: ChannelRecord) -> None:
        """Apply a channel configuration record, joining or parting as needed."""
        source_key = casefold(record.channel, "ascii")
        source = self.source_records.get(source_key)
        if source is not None and source.revision >= record.revision:
            return

        self.source_records[source_key] = record
        folded = self.bot.caps.fold(record.channel)
        current = self.channel_records.get(folded)
        if current is not None and current.revision >= record.revision:
            return

        self.channel_records[folded] = record
        if record.present:
            self.pending_parts.pop(folded, None)
            existing = self.channels.get(folded)
            runtime = existing or ChannelRuntime(casemapping=self.bot.caps.casemapping)
            self.channels[folded] = runtime
            runtime.channel = record.channel
            # Take the key only from a record that changes it: a record that
            # carries the old key over must not clobber a newer key this bot
            # observed on IRC and is still writing.
            if existing is None or current is None or current.key != record.key:
                runtime.key = record.key

            if (
                self.bot.identity.registered
                and self.bot.identity.current is not None
                and runtime.join_due()
            ):
                await self.safe_join(runtime)

            return

        parted = self.channels.pop(folded, None)
        if parted is not None:
            try:
                await self.bot.irc.send("PART", record.channel)
            except ConnectionError:
                self.pending_parts[folded] = record.channel

    async def enforce_modes(self, channel: str) -> None:
        """Set the configured channel modes when the bot has operator status."""
        if not self.bot.config.channel_modes:
            return

        required, forbidden = self.mode_intent
        caps = self.bot.caps
        if any(
            mode_requires_argument(
                mode,
                adding=adding,
                chanmodes=caps.chanmodes,
                membership=caps.membership_modes,
            )
            for adding, modes in ((True, required), (False, forbidden))
            for mode in modes
        ):
            LOGGER.warning(
                "cannot enforce modes on %s: configured mode requires an argument",
                channel,
            )
            return

        try:
            await self.bot.irc.send(
                "MODE",
                channel,
                self.bot.config.channel_modes,
            )
        except ConnectionError:
            return
        except ValueError as error:
            LOGGER.warning(
                "cannot enforce modes on %s: %s", channel, error_label(error)
            )

    async def join_desired(self) -> None:
        """Attempt to join all desired channels not yet entered."""
        if self.bot.identity.current is None:
            return

        for runtime in tuple(self.channels.values()):
            if runtime.join_due():
                await self.safe_join(runtime)

    async def record_key(self, channel: str, key: str | None) -> None:
        """Record and broadcast a versioned channel key update."""
        async with self.key_lock:
            await self.write_key(channel, key)

    async def write_key(self, channel: str, key: str | None) -> bool:
        """Write a key change after the current record; return False on failure.

        A failed write is not applied locally, where it would shadow newer
        remote records; the channel is marked for a retry instead.
        """
        source_key = casefold(channel, "ascii")
        current = self.channel_records.get(self.bot.caps.fold(channel))
        if current is None or not current.present or current.key == key:
            self.pending_keys.pop(source_key, None)
            return True

        record = self.new_record(
            channel,
            key,
            present=True,
            after=current.revision,
        )
        try:
            stored = await self.bot.coordinator.put_channel(
                channel,
                asdict(record),
                expected=self.durable_revision(channel),
            )
        except PUBLISH_ERRORS:
            self.pending_keys[source_key] = channel
            return False

        self.pending_keys.pop(source_key, None)
        await self.apply_record(ChannelRecord.from_dict(stored))
        return True

    def durable_revision(self, channel: str) -> str | None:
        """Return the stored revision of this exact channel name, if any.

        The store keys records by ASCII fold, while the local view merges
        IRC-equivalent names (#a[ and #a{ under rfc1459); a write must name
        the record under its own key, or the store can never accept it.
        """
        record = self.source_records.get(casefold(channel, "ascii"))
        return record.revision if record is not None else None

    def new_record(
        self,
        channel: str,
        key: str | None,
        *,
        present: bool,
        after: str | None = None,
    ) -> ChannelRecord:
        """Mint a record ordered after both after and this bot's earlier records."""
        record = ChannelRecord.new(
            channel,
            key,
            present=present,
            after=after,
            floor=self.last_revision,
        )
        self.last_revision = revision_number(record.revision)
        return record

    def any_peer_opped(self, runtime: ChannelRuntime) -> bool:
        """Return whether any known peer bot holds operator status."""
        self_folded = self.bot.caps.fold(self.bot.irc.current_nick)
        peers = self.bot.presence.active()
        for folded, member in runtime.members.items():
            if folded == self_folded or not self.bot.caps.is_opped(member.modes):
                continue

            if member.prefix is None:
                # Optimism before WHO answers: peers recheck before acting, so
                # a needless request is harmless, while pessimism would delay
                # coordination.
                return True

            if any(
                peer.matches(member.prefix, self.bot.caps.casemapping) for peer in peers
            ):
                return True

        return False

    def is_self_opped(self, runtime: ChannelRuntime) -> bool:
        """Check whether this bot holds operator status in the channel."""
        member = runtime.members.get(self.bot.caps.fold(self.bot.irc.current_nick))
        return member is not None and self.bot.caps.is_opped(member.modes)

    def runtime(self, channel: str) -> ChannelRuntime | None:
        """Return the live owner of a desired channel, by IRC case folding."""
        return self.channels.get(self.bot.caps.fold(channel))

    def forget_member(self, nick: str) -> None:
        """Remove a user who quit IRC from every channel."""
        for runtime in self.channels.values():
            runtime.remove(nick)

    def rename_member(self, prefix: Prefix, new_nick: str) -> Prefix:
        """Rekey a user's membership after NICK; return their full old prefix.

        A nick-only NICK prefix is completed from member state before the
        members are renamed, since that would otherwise lose the only copy.
        """
        old_folded = self.bot.caps.fold(prefix.nick)
        new_folded = self.bot.caps.fold(new_nick)
        old_prefix = prefix
        for runtime in self.channels.values():
            member = runtime.members.pop(old_folded, None)
            if member is None:
                continue

            member.nick = new_nick
            member_prefix = member.prefix
            if member_prefix is not None:
                if not old_prefix.complete and member_prefix.complete:
                    old_prefix = member_prefix

                member.prefix = Prefix(new_nick, member_prefix.user, member_prefix.host)

            runtime.members[new_folded] = member

        return old_prefix

    def change_member_host(self, prefix: Prefix, new_prefix: Prefix) -> Prefix:
        """Apply a CHGHOST to a user's membership; return their full old prefix.

        A nick-only CHGHOST prefix is completed from member state before it is
        overwritten, since that would otherwise lose the only copy.
        """
        folded = self.bot.caps.fold(prefix.nick)
        old_prefix = prefix
        for runtime in self.channels.values():
            member = runtime.members.get(folded)
            if member is None:
                continue

            if (
                not old_prefix.complete
                and member.prefix is not None
                and member.prefix.complete
            ):
                old_prefix = member.prefix

            member.prefix = new_prefix

        return old_prefix

    def help_eligible(
        self,
        payload: dict[str, Any],
        *,
        require_member: bool = True,
    ) -> tuple[str, BotPresence, ChannelRuntime] | None:
        """Return a validated peer action this bot can fulfill."""
        try:
            channel = payload["channel"]
            presence = BotPresence.from_dict(payload["presence"])
            if not isinstance(channel, str):
                return None
        except KeyError, TypeError, ValueError:
            return None

        runtime = self.runtime(channel)
        if (
            runtime is None
            or not self.bot.presence.has(presence)
            or not self.bot.irc.connected
            or not self.is_self_opped(runtime)
        ):
            return None

        if require_member:
            member = runtime.members.get(self.bot.caps.fold(presence.nick))
            if (
                member is None
                or self.bot.caps.is_opped(member.modes)
                or member.prefix is None
                or not presence.matches(member.prefix, self.bot.caps.casemapping)
            ):
                return None

        return channel, presence, runtime

    async def invite_peer(self, payload: dict[str, Any]) -> None:
        """Invite a peer bot into a channel this bot holds operator status in."""
        parsed = self.help_eligible(payload, require_member=False)
        if parsed is None:
            return

        channel, presence, _ = parsed
        try:
            await self.bot.irc.send("INVITE", presence.nick, channel)
        except ConnectionError:
            return

        LOGGER.info("invited bot %s to %s", presence.bot_id, channel)

    async def op_peer(self, payload: dict[str, Any]) -> None:
        """Grant operator status to a peer bot."""
        parsed = self.help_eligible(payload)
        if parsed is None:
            return

        channel, presence, _ = parsed
        try:
            await self.bot.irc.send(
                "MODE",
                channel,
                f"+{self.bot.caps.op_mode}",
                presence.nick,
            )
        except ConnectionError:
            return

        LOGGER.info("opped %s on %s", presence.nick, channel)

    async def unban_peer(self, payload: dict[str, Any]) -> None:
        """Remove channel bans matching a peer bot's hostmask."""
        parsed = self.help_eligible(payload, require_member=False)
        if parsed is None:
            return

        channel, presence, runtime = parsed
        prefix = presence.to_prefix()
        for mask in sorted(runtime.bans.values()):
            if not mask_matches(mask, prefix, self.bot.caps.casemapping):
                continue

            try:
                await self.bot.irc.send("MODE", channel, "-b", mask)
            except ConnectionError:
                return

            LOGGER.info(
                "removed ban %s for bot %s on %s", mask, presence.bot_id, channel
            )

    async def help_after_delay(self, kind: str, payload: dict[str, Any]) -> None:
        """Wait a random moment so answering peers spread out, then act.

        The action rechecks eligibility against live IRC state, so a peer that
        another peer already helped sends nothing, or a harmless duplicate.
        """
        action = self.help_actions.get(kind)
        if action is None:
            return

        await asyncio.sleep(secrets.randbelow(1000) / 1000 * PEER_HELP_DELAY)
        await action(payload)

    async def make_room(self, payload: dict[str, Any]) -> None:
        """Raise a full channel's limit so every bot left out can join.

        The target is absolute (members plus bots left out), so peers answering
        at once send the same limit, and a peer that sees it already set skips.
        """
        parsed = self.help_eligible(payload, require_member=False)
        if parsed is None:
            return

        channel, _, runtime = parsed
        if runtime.limit is None:
            return

        own_id = self.bot.config.bot_id.casefold()
        left_out = sum(
            peer.bot_id.casefold() != own_id
            and self.bot.caps.fold(peer.nick) not in runtime.members
            for peer in self.bot.presence.active()
        )
        target = len(runtime.members) + left_out
        if left_out == 0 or runtime.limit >= target:
            return

        try:
            await self.bot.irc.send("MODE", channel, "+l", str(target))
        except ConnectionError:
            return

        LOGGER.info("raised limit on %s to %d for %d bot(s)", channel, target, left_out)

    async def request_peer(self, kind: str, channel: str) -> None:
        """Send a coordination request to peers, respecting cooldown limits."""
        identity = self.bot.identity.current
        if identity is None:
            return

        folded = self.bot.caps.fold(channel)
        runtime = self.channels.get(folded)
        if runtime is None or (runtime.joined and not self.any_peer_opped(runtime)):
            return

        loop_time = asyncio.get_running_loop().time()
        if loop_time - runtime.cooldowns.get(kind, 0) < PEER_REQUEST_COOLDOWN:
            return

        runtime.cooldowns[kind] = loop_time
        await self.bot.coordinator.request_help(
            kind,
            {"channel": channel, "presence": asdict(identity)},
        )

    async def retry_pending_keys(self) -> None:
        """Retry failed key writes with the key this bot sees on IRC now.

        A bot no longer in the channel cannot see its key; the peers still in
        it observe the same MODE changes and record them.
        """
        async with self.key_lock:
            for source_key, channel in tuple(self.pending_keys.items()):
                runtime = self.runtime(channel)
                if runtime is None or not runtime.joined:
                    self.pending_keys.pop(source_key, None)
                elif not await self.write_key(channel, runtime.key):
                    return

    def reset(self) -> None:
        """Clear all runtime state and cooldowns after a reconnection."""
        for runtime in self.channels.values():
            runtime.reset()

        self.pending_parts.clear()

    async def retry_pending_parts(self) -> None:
        """Reattempt PART for channels that failed to leave previously."""
        for folded, channel in tuple(self.pending_parts.items()):
            if folded in self.channels:
                self.pending_parts.pop(folded, None)
                continue

            try:
                await self.bot.irc.send("PART", channel)
            except ConnectionError:
                continue

            self.pending_parts.pop(folded, None)

    async def safe_join(self, runtime: ChannelRuntime) -> None:
        """Send JOIN, silently handling connection and validation errors."""
        try:
            params = (
                (runtime.channel, runtime.key) if runtime.key else (runtime.channel,)
            )
            await self.bot.irc.send("JOIN", *params)
        except ConnectionError:
            return
        except ValueError as error:
            LOGGER.warning(
                "cannot join %s: %s",
                runtime.channel,
                error_label(error),
            )
            return
        # Only a JOIN that actually reached the send queue is in flight.
        runtime.start_join()

    def set_casemapping(self, casemapping: str) -> None:
        """Rebuild channel lookups under a new casemapping.

        Servers advertise CASEMAPPING while registering, before this bot joins
        anything, and a disconnect resets channel state anyway; so live state
        is rebuilt from the durable records rather than rekeyed.
        """
        if casemapping not in CASEMAPPINGS or casemapping == self.bot.caps.casemapping:
            return

        self.bot.caps.casemapping = casemapping
        self.bot.authorizer.rekey()
        self.bot.irc.set_casemapping(casemapping)

        records: dict[str, ChannelRecord] = {}
        for record in self.source_records.values():
            folded = self.bot.caps.fold(record.channel)
            current = records.get(folded)
            if current is None or record.revision > current.revision:
                records[folded] = record

        joined = [
            runtime.channel for runtime in self.channels.values() if runtime.joined
        ]
        self.channel_records = records
        self.channels = {
            folded: ChannelRuntime(
                casemapping=casemapping,
                channel=record.channel,
                key=record.key,
            )
            for folded, record in records.items()
            if record.present
        }
        # Leave any joined channel that no longer folds onto a desired one.
        self.pending_parts = {
            self.bot.caps.fold(channel): channel
            for channel in (*self.pending_parts.values(), *joined)
            if self.bot.caps.fold(channel) not in self.channels
        }


def revision_number(revision: str) -> int:
    """Return the counter part of a validated channel revision."""
    return int(validate_channel_revision(revision).partition("-")[0])


@dataclass(slots=True)
class ChannelMember:
    """Track a single member's nick, prefix, and channel modes."""

    nick: str
    modes: set[str] = field(default_factory=set)
    prefix: Prefix | None = None


@dataclass(frozen=True, slots=True)
class ChannelRecord:
    """A channel update, including part tombstones for offline peers."""

    channel: str
    key: str | None
    present: bool
    revision: str

    @classmethod
    def from_dict(cls, value: object) -> ChannelRecord:
        """Deserialize a channel record from a dictionary."""
        return cls(*parse_channel_record(value))

    @classmethod
    def new(
        cls,
        channel: str,
        key: str | None,
        *,
        present: bool,
        after: str | None = None,
        floor: int = 0,
    ) -> ChannelRecord:
        """Create a record whose revision follows both after and floor."""
        previous = floor
        if after is not None:
            previous = max(previous, revision_number(after))

        number = previous + 1
        if number > MAX_CHANNEL_REVISION:
            msg = "channel revision counter is exhausted"
            raise ValueError(msg)

        channel, key = validate_join(channel, key)
        return cls(
            channel=channel,
            key=key,
            present=present,
            revision=f"{number:020d}-{uuid.uuid4().hex}",
        )


class JoinState(Enum):
    """Where this bot stands in joining a desired channel."""

    IDLE = auto()
    JOINING = auto()
    JOINED = auto()


@dataclass(slots=True)
class ChannelRuntime:
    """Own one desired channel: live state, joining, and peer requests."""

    bans: dict[str, str] = field(default_factory=dict)
    casemapping: str = DEFAULT_CASEMAPPING
    channel: str = ""
    cooldowns: dict[str, float] = field(default_factory=dict)
    join: JoinState = JoinState.IDLE
    # The last unhandled refusal logged for a pending JOIN, so it logs once.
    join_error: str | None = None
    join_sent_at: float = 0.0
    key: str | None = None
    limit: int | None = None
    members: dict[str, ChannelMember] = field(default_factory=dict)
    modes: str = ""

    @property
    def joined(self) -> bool:
        """Return whether the server has confirmed this bot's JOIN."""
        return self.join is JoinState.JOINED

    def join_due(self) -> bool:
        """Return whether to send JOIN: idle, or a JOIN that got no reply."""
        if self.join is JoinState.IDLE:
            return True

        return (
            self.join is JoinState.JOINING
            and asyncio.get_running_loop().time() - self.join_sent_at
            >= JOIN_REPLY_TIMEOUT
        )

    def start_join(self) -> None:
        """Record a JOIN queued for the server."""
        self.join = JoinState.JOINING
        self.join_sent_at = asyncio.get_running_loop().time()

    def refuse_join(self) -> None:
        """Record a refused JOIN so the next tick may try again."""
        if self.join is JoinState.JOINING:
            self.join = JoinState.IDLE

    def add_ban(self, mask: str) -> None:
        """Track a ban mask keyed by its folded form for O(1) lookup."""
        self.bans[casefold(mask, self.casemapping)] = mask

    def member(self, nickname: str) -> ChannelMember:
        """Return the member for a nickname, creating one if absent."""
        folded = casefold(nickname, self.casemapping)
        member = self.members.get(folded)
        if member is None:
            member = ChannelMember(nickname)
            self.members[folded] = member

        member.nick = nickname
        return member

    def remove(self, nickname: str) -> None:
        """Drop a member from the channel by nickname."""
        self.members.pop(casefold(nickname, self.casemapping), None)

    def remove_ban(self, mask: str) -> None:
        """Delete a ban mask from the channel ban list."""
        self.bans.pop(casefold(mask, self.casemapping), None)

    def reset(self) -> None:
        """Clear connection-specific channel state."""
        self.bans.clear()
        self.cooldowns.clear()
        self.join = JoinState.IDLE
        self.join_error = None
        self.limit = None
        self.members.clear()
        self.modes = ""

    def set_limit(self, value: str | None) -> None:
        """Record the +l member limit; None or a non-count value clears it."""
        if value is not None and value.isascii() and value.isdigit():
            self.limit = int(value)
        else:
            self.limit = None

    def set_key(self, key: str | None) -> bool:
        """Set the channel key, validating a non-None key.

        Returns False without changing the current key when a key is present
        but unusable, so the IRC MODE path can reject it the same way the
        durable path rejects it through ChannelRecord.new's validation.
        """
        if key is not None:
            try:
                validate_key(key)
            except ValueError:
                return False

        self.key = key
        return True
