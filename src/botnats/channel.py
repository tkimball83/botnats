# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC channel state, membership, and lifecycle management."""

import asyncio
import logging
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from botnats import error_label
from botnats.irc.protocol import (
    CASEMAPPINGS,
    ISupportState,
    Prefix,
    casefold,
    mask_matches,
    mode_requires_argument,
)
from botnats.nats.store import PUBLISH_ERRORS
from botnats.validators import MAX_CHANNEL_REVISION, validate_join

if TYPE_CHECKING:
    from collections.abc import Callable

    from botnats.bot import Bot
    from botnats.presence import BotPresence

LOGGER = logging.getLogger(__name__)

# Resend a JOIN that got no reply the bot handles: a lost JOIN, or a refusal
# such as 477 (registered nicks only). A duplicate JOIN is harmless.
JOIN_REPLY_TIMEOUT = 60.0
# Resend a JOIN refused as full, invite-only, banned, or keyed this long
# after the refusal: soon after a peer's help, but not on every tick.
JOIN_RETRY_DELAY = 10.0
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
        # Channels no longer desired whose PART could not be sent yet; this
        # bot is still in them.
        self.pending_parts: dict[str, str] = {}
        # Key writes and their retries run one at a time, so each compares
        # against the record the previous write left.
        self.key_lock = asyncio.Lock()
        # Highest revision this bot has minted: concurrent local changes to
        # one channel (two admin commands, say) get distinct, ordered revisions.
        self.last_revision = 0
        # Revisions of this bot's writes in flight: the KV watch can deliver
        # one before the store's reply reaches the writer.
        self.writing: set[str] = set()
        # Each peer help request kind, and the action that answers it.
        self.help_actions: dict[str, Callable[[str, BotPresence], None]] = {
            "invite": self.invite_peer,
            "limit": self.make_room,
            "op": self.op_peer,
            "unban": self.unban_peer,
        }

    def apply_record(self, record: ChannelRecord) -> None:
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
            unparted = self.pending_parts.pop(folded, None) is not None
            runtime = self.channels.get(folded) or ChannelRuntime(caps=self.bot.caps)
            self.channels[folded] = runtime
            runtime.channel = record.channel
            # A joined channel keeps the key this bot sees on IRC against its
            # own write, whose key IRC may have replaced while it was in
            # flight, and against any record while a key it saw awaits its
            # write. Otherwise the record knows best: IRC can hide a key
            # change behind "*".
            own_write = record.revision in self.writing
            if not (runtime.joined and (own_write or runtime.key_pending)):
                runtime.key = record.key

            if unparted:
                # Wanted again before its PART went out, so never left: the
                # server would ignore a JOIN, and NAMES relearns its state.
                runtime.join = JoinState.JOINED
                self.refresh_names(runtime)
            elif self.bot.identity.current is not None and runtime.join_due():
                self.safe_join(runtime)

            return

        dropped = self.channels.pop(folded, None)
        # A JOIN still in flight is left when its echo arrives: only a joined
        # channel needs a PART, so a pending PART always means membership.
        if dropped is not None and dropped.joined:
            self.part(record.channel)

    def enforce_modes(self, runtime: ChannelRuntime) -> None:
        """Set the configured channel modes when the bot has operator status."""
        if not self.bot.config.channel_modes:
            return

        required, forbidden = self.bot.config.enforced_modes
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
                runtime.channel,
            )
            return

        try:
            self.bot.irc.send(
                "MODE",
                runtime.channel,
                self.bot.config.channel_modes,
            )
        except ConnectionError:
            # The next tick resends NAMES, whose end reply enforces again.
            runtime.names_due = True
        except ValueError as error:
            LOGGER.warning(
                "cannot enforce modes on %s: %s", runtime.channel, error_label(error)
            )

    def join_desired(self) -> None:
        """Join desired channels not yet entered; resend NAMES where due."""
        if self.bot.identity.current is None:
            return

        for runtime in tuple(self.channels.values()):
            if runtime.join_due():
                self.safe_join(runtime)
            elif runtime.names_due:
                self.refresh_names(runtime)

    def record_key(self, runtime: ChannelRuntime) -> None:
        """Record the key this bot now sees on IRC in its durable record.

        The key is pending from this moment, not from when its write gets a
        turn: no record applied in between may replace it.
        """
        runtime.key_pending = True
        self.bot.tasks.spawn(self.retry_pending_keys(), "record-channel-key")

    def refuse_key(self, runtime: ChannelRuntime) -> None:
        """Take the stored key once the server refuses the one this bot tried.

        A record held back while this bot had a key of its own pending is not
        applied again; a bad-key refusal proves the key it kept wrong.
        """
        runtime.key = self.channel_records[self.bot.caps.fold(runtime.channel)].key

    async def write_key(self, runtime: ChannelRuntime) -> bool:
        """Write the key this bot sees on IRC now; return False on failure.

        A failed write is not applied locally, where it would shadow newer
        remote records. The key stays pending until its record holds it: a
        failed or lost write is retried, and a key that changed while the
        write was in flight is written next.
        """
        if not self.key_recorded(runtime):
            try:
                await self.write_record(runtime.channel, runtime.key, present=True)
            except PUBLISH_ERRORS:
                return False

        if self.key_recorded(runtime):
            runtime.key_pending = False

        return True

    def key_recorded(self, runtime: ChannelRuntime) -> bool:
        """Return whether the record holds the key this bot sees on IRC.

        A bot no longer in the channel sees no key; the peers still in it
        observe the same MODE changes and record them. A channel parted
        meanwhile is not written back.
        """
        if not runtime.joined or self.runtime(runtime.channel) is not runtime:
            return True

        record = self.channel_records[self.bot.caps.fold(runtime.channel)]
        return record.key == runtime.key

    async def write_record(
        self,
        channel: str,
        key: str | None,
        *,
        present: bool,
    ) -> bool:
        """Write a record after the current one; return whether it won.

        The stored winner is applied, never the attempt: a concurrent write
        from another bot can win instead. A failed write raises and applies
        nothing.
        """
        current = self.channel_records.get(self.bot.caps.fold(channel))
        record = self.new_record(
            channel,
            key,
            present=present,
            after=current.revision if current is not None else None,
        )
        self.writing.add(record.revision)
        try:
            stored = await self.bot.coordinator.put_channel(
                asdict(record),
                after=self.durable_revision(channel),
            )
            authoritative = ChannelRecord(*stored)
            self.apply_record(authoritative)
        finally:
            self.writing.discard(record.revision)

        return authoritative == record

    def durable_revision(self, channel: str) -> str | None:
        """Return the stored revision of this exact channel name, if any.

        The store keys records by ASCII fold, while the local view merges
        IRC-equivalent names (#a[ and #a{ under rfc1459); a write must follow
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
                peer.to_prefix().matches(member.prefix, self.bot.caps.casemapping)
                for peer in peers
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

    def forget_member(self, prefix: Prefix) -> Prefix:
        """Remove a user who quit IRC from every channel; return their full prefix.

        A QUIT prefix lacking a user or host is completed from member state
        before the members are removed, since that would lose the only copy.
        """
        folded = self.bot.caps.fold(prefix.nick)
        full_prefix = prefix
        for runtime in self.channels.values():
            member = runtime.members.pop(folded, None)
            if (
                member is not None
                and not full_prefix.complete
                and member.prefix is not None
                and member.prefix.complete
            ):
                full_prefix = member.prefix

        return full_prefix

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
        channel: str,
        presence: BotPresence,
        *,
        require_member: bool = True,
    ) -> ChannelRuntime | None:
        """Return the channel's runtime when this bot can help the peer now."""
        runtime = self.runtime(channel)
        if (
            runtime is None
            or not self.bot.presence.has(presence)
            or not self.is_self_opped(runtime)
        ):
            return None

        if require_member:
            member = runtime.members.get(self.bot.caps.fold(presence.nick))
            if (
                member is None
                or self.bot.caps.is_opped(member.modes)
                or member.prefix is None
                or not presence.to_prefix().matches(
                    member.prefix,
                    self.bot.caps.casemapping,
                )
            ):
                return None

        return runtime

    def invite_peer(self, channel: str, presence: BotPresence) -> None:
        """Invite a peer bot into a channel this bot holds operator status in."""
        runtime = self.help_eligible(channel, presence, require_member=False)
        if runtime is None or self.bot.caps.fold(presence.nick) in runtime.members:
            return

        try:
            self.bot.irc.send("INVITE", presence.nick, channel)
        except ConnectionError:
            return

        LOGGER.info("invited bot %s to %s", presence.bot_id, channel)

    def op_peer(self, channel: str, presence: BotPresence) -> None:
        """Grant operator status to a peer bot."""
        if self.help_eligible(channel, presence) is None:
            return

        try:
            self.bot.irc.send(
                "MODE",
                channel,
                f"+{self.bot.caps.op_mode}",
                presence.nick,
            )
        except ConnectionError:
            return

        LOGGER.info("opped %s on %s", presence.nick, channel)

    def unban_peer(self, channel: str, presence: BotPresence) -> None:
        """Remove channel bans matching a peer bot's hostmask."""
        runtime = self.help_eligible(channel, presence, require_member=False)
        if runtime is None:
            return

        prefix = presence.to_prefix()
        for mask in sorted(runtime.bans.values()):
            if not mask_matches(mask, prefix, self.bot.caps.casemapping):
                continue

            try:
                self.bot.irc.send("MODE", channel, "-b", mask)
            except ConnectionError:
                return

            LOGGER.info(
                "removed ban %s for bot %s on %s", mask, presence.bot_id, channel
            )

    async def help_after_delay(
        self,
        kind: str,
        channel: str,
        presence: BotPresence,
    ) -> None:
        """Wait a random moment so answering peers spread out, then act.

        The action rechecks eligibility against live IRC state, so a peer that
        another peer already helped sends nothing, or a harmless duplicate.
        """
        action = self.help_actions.get(kind)
        if action is None:
            return

        await asyncio.sleep(secrets.randbelow(1000) / 1000 * PEER_HELP_DELAY)
        action(channel, presence)

    def make_room(self, channel: str, presence: BotPresence) -> None:
        """Raise a full channel's limit so every bot left out can join.

        The target is absolute (members plus bots left out), so peers answering
        at once send the same limit, and a peer that sees it already set skips.
        """
        runtime = self.help_eligible(channel, presence, require_member=False)
        if runtime is None or runtime.limit is None:
            return

        left_out = sum(
            self.bot.caps.fold(peer.nick) not in runtime.members
            for peer in self.bot.presence.peers(self.bot.config.bot_id)
        )
        target = len(runtime.members) + left_out
        if left_out == 0 or runtime.limit >= target:
            return

        try:
            self.bot.irc.send("MODE", channel, "+l", str(target))
        except ConnectionError:
            return

        LOGGER.info("raised limit on %s to %d for %d bot(s)", channel, target, left_out)

    async def request_peer(self, kind: str, channel: str) -> None:
        """Send a coordination request to peers, respecting cooldown limits."""
        identity = self.bot.identity.current
        if identity is None:
            return

        runtime = self.runtime(channel)
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

    async def request_ops(self) -> None:
        """Ask peers for op in every joined channel where this bot lacks it."""
        for runtime in tuple(self.channels.values()):
            if runtime.joined and not self.is_self_opped(runtime):
                await self.request_peer("op", runtime.channel)

    async def retry_pending_keys(self) -> None:
        """Write each pending key as this bot sees it on IRC now."""
        async with self.key_lock:
            for runtime in tuple(self.channels.values()):
                # Checked at its turn: IRC can hide a key during earlier writes.
                if runtime.key_pending and not await self.write_key(runtime):
                    return

    def part(self, channel: str) -> None:
        """Send PART, or keep it pending for the next tick while IRC is down."""
        try:
            self.bot.irc.send("PART", channel)
        except ConnectionError:
            self.pending_parts[self.bot.caps.fold(channel)] = channel

    def parted(self, channel: str) -> None:
        """Drop a pending PART for a channel this bot has left anyway."""
        self.pending_parts.pop(self.bot.caps.fold(channel), None)

    def refresh_names(self, runtime: ChannelRuntime) -> None:
        """Send NAMES to relearn a channel, or keep it due for the next tick."""
        try:
            self.bot.irc.send("NAMES", runtime.channel)
        except ConnectionError:
            runtime.names_due = True
            return

        runtime.names_due = False

    def reset(self) -> None:
        """Clear all runtime state and cooldowns after a reconnection."""
        for runtime in self.channels.values():
            runtime.reset()

        self.pending_parts.clear()

    def retry_pending_parts(self) -> None:
        """Reattempt PART for channels that failed to leave previously."""
        for folded, channel in tuple(self.pending_parts.items()):
            try:
                self.bot.irc.send("PART", channel)
            except ConnectionError:
                continue

            self.pending_parts.pop(folded, None)

    def safe_join(self, runtime: ChannelRuntime) -> None:
        """Send JOIN, or leave it due for the next tick while IRC is down."""
        try:
            params = (
                (runtime.channel, runtime.key) if runtime.key else (runtime.channel,)
            )
            self.bot.irc.send("JOIN", *params)
        except ConnectionError:
            return
        # Only a JOIN that actually reached the send queue is in flight.
        runtime.start_join(self.bot.irc.queue_delay)

    def set_casemapping(self, casemapping: str) -> None:
        """Rekey channel lookups under a new casemapping.

        Records are regrouped from their ASCII-keyed durable copies. A desired
        channel keeps its live runtime: the server sends no JOIN for a channel
        this bot is already in, so a fresh runtime would never become joined.
        """
        if casemapping not in CASEMAPPINGS or casemapping == self.bot.caps.casemapping:
            return

        self.bot.caps.casemapping = casemapping
        self.bot.authorizer.rekey()

        records: dict[str, ChannelRecord] = {}
        for record in self.source_records.values():
            folded = self.bot.caps.fold(record.channel)
            current = records.get(folded)
            if current is None or record.revision > current.revision:
                records[folded] = record

        previous = {runtime.channel: runtime for runtime in self.channels.values()}
        self.channel_records = records
        self.channels = {}
        for folded, record in records.items():
            if not record.present:
                continue

            runtime = previous.pop(record.channel, None)
            if runtime is None:
                runtime = ChannelRuntime(
                    caps=self.bot.caps,
                    channel=record.channel,
                    key=record.key,
                )
            else:
                runtime.rekey()

            self.channels[folded] = runtime

        joined = [runtime.channel for runtime in previous.values() if runtime.joined]
        # Leave any joined channel that no longer folds onto a desired one.
        self.pending_parts = {
            self.bot.caps.fold(channel): channel
            for channel in (*self.pending_parts.values(), *joined)
            if self.bot.caps.fold(channel) not in self.channels
        }


def revision_number(revision: str) -> int:
    """Return the counter part of an already validated channel revision."""
    return int(revision.partition("-")[0])


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

    caps: ISupportState
    bans: dict[str, str] = field(default_factory=dict)
    channel: str = ""
    cooldowns: dict[str, float] = field(default_factory=dict)
    join: JoinState = JoinState.IDLE
    # The last unhandled refusal logged for a pending JOIN, so it logs once.
    join_error: str | None = None
    # When a pending JOIN, unanswered or refused, is due to be sent again.
    join_retry_at: float = 0.0
    key: str | None = None
    # A key seen on IRC that this bot has yet to record: its write is queued,
    # in flight, or failed. Each write takes the key seen at that moment, so
    # a superseded change is never replayed.
    key_pending: bool = False
    limit: int | None = None
    members: dict[str, ChannelMember] = field(default_factory=dict)
    modes: str = ""
    # A NAMES, or a query or enforcement its end reply sends, that could not
    # be sent; the next tick resends NAMES, and its end reply the rest.
    names_due: bool = False

    @property
    def joined(self) -> bool:
        """Return whether the server has confirmed this bot's JOIN."""
        return self.join is JoinState.JOINED

    def join_due(self) -> bool:
        """Return whether to send JOIN: idle, or pending past its retry time."""
        if self.join is JoinState.IDLE:
            return True

        return (
            self.join is JoinState.JOINING
            and asyncio.get_running_loop().time() >= self.join_retry_at
        )

    def start_join(self, queue_delay: float) -> None:
        """Record a JOIN queued for the server, due to go out in queue_delay.

        Its reply is awaited from then on: a JOIN deep in a join burst's queue
        is not queued again before it has even gone out.
        """
        self.join = JoinState.JOINING
        self.join_retry_at = (
            asyncio.get_running_loop().time() + queue_delay + JOIN_REPLY_TIMEOUT
        )

    def refuse_join(self) -> None:
        """Keep a refused JOIN pending until JOIN_RETRY_DELAY has passed.

        A refusal comes back at once, so a JOIN retried on every tick would be
        refused, and ask peers for help, on every tick.
        """
        self.join_retry_at = asyncio.get_running_loop().time() + JOIN_RETRY_DELAY

    def add_ban(self, mask: str) -> None:
        """Track a ban mask keyed by its folded form for O(1) lookup."""
        self.bans[self.caps.fold(mask)] = mask

    def hide_key(self) -> None:
        """Record a key change IRC hid: drop the key this bot has yet to record.

        The key it saw stays, since a netsplit can resend an unchanged key as
        "*". Peers that see a new key record it, and with nothing pending here
        their records set it.
        """
        self.key_pending = False

    def member(self, nickname: str) -> ChannelMember:
        """Return the member for a nickname, creating one if absent."""
        folded = self.caps.fold(nickname)
        member = self.members.get(folded)
        if member is None:
            member = ChannelMember(nickname)
            self.members[folded] = member

        member.nick = nickname
        return member

    def remove(self, nickname: str) -> None:
        """Drop a member from the channel by nickname."""
        self.members.pop(self.caps.fold(nickname), None)

    def remove_ban(self, mask: str) -> None:
        """Delete a ban mask from the channel ban list."""
        self.bans.pop(self.caps.fold(mask), None)

    def update_mode(self, mode: str, *, adding: bool) -> None:
        """Add or remove a mode letter from the channel mode string."""
        current = self.modes.lstrip("+")
        if adding:
            if mode not in current:
                self.modes = f"+{current}{mode}"
        elif mode in current:
            remaining = current.replace(mode, "")
            self.modes = f"+{remaining}" if remaining else ""

    def rekey(self) -> None:
        """Refold member and ban lookups after the casemapping changes."""
        self.members = {self.caps.fold(m.nick): m for m in self.members.values()}
        self.bans = {self.caps.fold(mask): mask for mask in self.bans.values()}

    def reset(self) -> None:
        """Clear connection-specific channel state."""
        self.bans.clear()
        self.cooldowns.clear()
        self.join = JoinState.IDLE
        self.join_error = None
        self.key_pending = False
        self.limit = None
        self.members.clear()
        self.modes = ""
        self.names_due = False

    def set_limit(self, value: str | None) -> None:
        """Record the +l member limit; None or a non-count value clears it."""
        if value is not None and value.isascii() and value.isdigit():
            self.limit = int(value)
        else:
            self.limit = None

    def set_key(self, key: str | None) -> bool:
        """Set the channel key, validating a non-None key.

        Returns False without changing the current key when a key is present
        but unusable, so the IRC MODE path rejects it the same way the store
        rejects an unusable record.
        """
        if key is not None:
            try:
                validate_join(self.channel, key)
            except ValueError:
                return False

        self.key = key
        return True
