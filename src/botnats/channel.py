# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC channel state, membership, and lifecycle management."""

import asyncio
import logging
import uuid
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, ClassVar

from botnats import error_label
from botnats.config import mode_intent
from botnats.irc.protocol import (
    CASEMAPPINGS,
    DEFAULT_CASEMAPPING,
    Prefix,
    casefold,
    mode_requires_argument,
)
from botnats.nats.coordinator import PUBLISH_ERRORS
from botnats.validators import (
    MAX_CHANNEL_REVISION,
    parse_channel_record,
    validate_channel_revision,
    validate_join,
    validate_key,
)

if TYPE_CHECKING:
    from botnats.bot import Bot
    from botnats.presence import BotPresence

LOGGER = logging.getLogger(__name__)

OP_BATCH_COALESCE_DELAY = 0.05
PEER_REQUEST_COOLDOWN = 0.5


class ChannelManager:
    """Manages channel joins, parts, mode enforcement, and peer requests."""

    def __init__(self, bot: Bot) -> None:
        """Initialize channel tracking state and cooldown timers."""
        self.bot = bot
        self.channel_records: dict[str, ChannelRecord] = {}
        self.source_records: dict[str, ChannelRecord] = {}
        self.channels: dict[str, ChannelRuntime] = {}
        self.cooldowns: dict[tuple[str, str], float] = {}
        self.desired_channels: dict[str, str] = {}
        self.pending_op_flushes: set[str] = set()
        self.pending_ops: dict[str, dict[str, BotPresence]] = {}
        self.pending_parts: dict[str, str] = {}
        self.pending_records: dict[str, ChannelRecord] = {}

    async def apply_record(self, record: ChannelRecord) -> None:
        """Apply a channel configuration record, joining or parting as needed."""
        source_key = casefold(record.channel, "ascii")
        source = self.source_records.get(source_key)
        if source is not None and source.revision >= record.revision:
            return
        self.source_records[source_key] = record
        folded = self.bot.fold(record.channel)
        current = self.channel_records.get(folded)
        if current is not None and current.revision >= record.revision:
            return
        self.channel_records[folded] = record
        if record.present:
            self.desired_channels[folded] = record.channel
            self.pending_parts.pop(folded, None)
            existing = self.channels.get(folded)
            runtime = existing or ChannelRuntime(casemapping=self.bot.caps.casemapping)
            self.channels[folded] = runtime
            runtime.key = record.key
            if (
                self.bot.registered
                and self.bot.identity is not None
                and not runtime.joined
            ):
                await self.safe_join(record.channel, record.key)
            return

        self.desired_channels.pop(folded, None)
        self.cooldowns = {k: v for k, v in self.cooldowns.items() if k[1] != folded}
        self.pending_ops.pop(folded, None)
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
        required, forbidden = mode_intent(self.bot.config.channel_modes)
        if any(
            mode_requires_argument(
                mode,
                adding=True,
                chanmodes=self.bot.caps.chanmodes,
                membership=self.bot.caps.membership_modes,
            )
            for mode in required
        ) or any(
            mode_requires_argument(
                mode,
                adding=False,
                chanmodes=self.bot.caps.chanmodes,
                membership=self.bot.caps.membership_modes,
            )
            for mode in forbidden
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

    async def flush_pending_ops(self, folded_channel: str) -> None:
        """Send batched operator mode grants after a short coalescing delay."""
        cancelled = False
        try:
            await asyncio.sleep(OP_BATCH_COALESCE_DELAY)
            channel = self.desired_channels.get(folded_channel)
            runtime = self.channels.get(folded_channel)
            # Drop the batch if we lost op during the coalescing window rather
            # than re-queue: retrying here would busy-spin while unopped, and
            # the requesting peer re-asks on its own maintenance tick.
            queued = self.pending_ops.pop(folded_channel, {})
            if (
                channel is not None
                and runtime is not None
                and self.bot.is_self_opped(runtime)
            ):
                targets = self.grantable_targets(runtime, queued)
                await self.bot.batch_mode(
                    channel,
                    "+",
                    self.bot.caps.op_mode,
                    targets,
                    "opped",
                )
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            self.pending_op_flushes.discard(folded_channel)
            if not cancelled and self.pending_ops.get(folded_channel):
                self.pending_op_flushes.add(folded_channel)
                self.bot.spawn(self.flush_pending_ops(folded_channel), "op-batch")

    def grantable_targets(
        self,
        runtime: ChannelRuntime,
        queued: dict[str, BotPresence],
    ) -> list[str]:
        """Return queued peers that are present, unopped, and identity-matched."""
        targets: list[str] = []
        for presence in queued.values():
            member = runtime.members.get(self.bot.fold(presence.nick))
            if (
                member is not None
                and not self.bot.caps.is_opped(member.modes)
                and member.prefix is not None
                and presence.matches(member.prefix, self.bot.caps.casemapping)
            ):
                targets.append(presence.nick)
        return targets

    async def join_desired(self) -> None:
        """Attempt to join all desired channels not yet entered."""
        if self.bot.identity is None:
            return
        for folded, channel in tuple(self.desired_channels.items()):
            runtime = self.channels.get(folded)
            if runtime is not None and not runtime.joined:
                await self.safe_join(channel, runtime.key)

    def queue_pending_op(self, folded: str, presence: BotPresence) -> None:
        """Add a peer bot to the pending operator grant batch."""
        self.pending_ops.setdefault(folded, {})[presence.bot_id.casefold()] = presence
        if folded not in self.pending_op_flushes:
            self.pending_op_flushes.add(folded)
            self.bot.spawn(self.flush_pending_ops(folded), "op-batch")

    async def record_key(self, channel: str, key: str | None) -> None:
        """Record and broadcast a versioned channel key update."""
        folded = self.bot.fold(channel)
        current = self.channel_records.get(folded)
        if current is None or not current.present or current.key == key:
            return
        record = ChannelRecord.new(
            channel,
            key,
            present=True,
            after=current.revision,
        )
        try:
            stored = await self.bot.coordinator.put_channel(
                channel,
                record.to_dict(),
            )
        except PUBLISH_ERRORS:
            # Keep the observed IRC key locally and queue the durable write;
            # retry_pending_records drops the entry if a newer record lands.
            await self.apply_record(record)
            self.pending_records[casefold(record.channel, "ascii")] = record
        else:
            await self.apply_record(ChannelRecord.from_dict(stored))

    async def request_peer(self, kind: str, channel: str) -> None:
        """Send a coordination request to peers, respecting cooldown limits."""
        if self.bot.identity is None:
            return
        folded = self.bot.fold(channel)
        runtime = self.channels.get(folded)
        if runtime is None or (runtime.joined and not self.bot.any_peer_opped(runtime)):
            return
        loop_time = asyncio.get_running_loop().time()
        key = (kind, folded)
        if loop_time - self.cooldowns.get(key, 0) < PEER_REQUEST_COOLDOWN:
            return
        self.cooldowns[key] = loop_time
        await self.bot.coordinator.request_offer(
            kind,
            {"channel": channel, "presence": self.bot.identity.to_dict()},
        )

    async def retry_pending_records(self) -> None:
        """Republish channel records whose JetStream writes failed."""
        for source_key, record in tuple(self.pending_records.items()):
            if self.source_records.get(source_key) != record:
                self.pending_records.pop(source_key, None)
                continue
            try:
                stored = await self.bot.coordinator.put_channel(
                    record.channel,
                    record.to_dict(),
                )
            except PUBLISH_ERRORS:
                return
            await self.apply_record(ChannelRecord.from_dict(stored))
            if self.pending_records.get(source_key) == record:
                self.pending_records.pop(source_key, None)

    def reset(self) -> None:
        """Clear all runtime state and cooldowns after a reconnection."""
        for runtime in self.channels.values():
            runtime.reset()
        self.cooldowns.clear()
        self.pending_op_flushes.clear()
        self.pending_ops.clear()
        self.pending_parts.clear()

    def schedule_part(self, channel: str) -> None:
        """Queue a channel part for retry after a failed PART send."""
        self.pending_parts[self.bot.fold(channel)] = channel

    async def retry_pending_parts(self) -> None:
        """Reattempt PART for channels that failed to leave previously."""
        for folded, channel in tuple(self.pending_parts.items()):
            if folded in self.desired_channels:
                self.pending_parts.pop(folded, None)
                continue
            try:
                await self.bot.irc.send("PART", channel)
            except ConnectionError:
                continue
            self.pending_parts.pop(folded, None)

    async def safe_join(self, channel: str, key: str | None) -> None:
        """Join a channel, silently handling connection and validation errors."""
        try:
            params = (channel, key) if key else (channel,)
            await self.bot.irc.send("JOIN", *params)
        except ConnectionError:
            return
        except ValueError as error:
            LOGGER.warning(
                "cannot join %s: %s",
                channel,
                error_label(error),
            )

    def _migrate_runtimes(
        self,
        casemapping: str,
        old_channels: dict[str, ChannelRuntime],
        old_desired: dict[str, str],
        old_records: dict[str, ChannelRecord],
    ) -> dict[str, ChannelRuntime]:
        """Rekey channel runtimes under the new casemapping."""
        channels: dict[str, ChannelRuntime] = {}
        for old_folded, runtime in old_channels.items():
            channel = old_desired.get(old_folded)
            if channel is None:
                fallback = old_records.get(old_folded)
                channel = fallback.channel if fallback is not None else None
            if channel is None:
                continue
            folded = self.bot.fold(channel)
            if folded in channels:
                LOGGER.warning(
                    "casemapping %s folds %s onto an existing channel; "
                    "dropping duplicate tracking",
                    casemapping,
                    channel,
                )
                continue
            runtime.set_casemapping(casemapping)
            channels[folded] = runtime
        return channels

    def set_casemapping(self, casemapping: str) -> None:
        """Rekey all channel lookups when the server's casemapping changes."""
        if casemapping not in CASEMAPPINGS:
            return
        if casemapping == self.bot.caps.casemapping:
            return

        old_channels = self.channels
        old_desired = self.desired_channels
        old_records = self.channel_records
        self.bot.caps.casemapping = casemapping
        self.bot.authorizer.rekey()
        self.bot.irc.set_casemapping(casemapping)

        records: dict[str, ChannelRecord] = {}
        for record in self.source_records.values():
            folded = self.bot.fold(record.channel)
            current = records.get(folded)
            if current is None or record.revision > current.revision:
                records[folded] = record
        self.channel_records = records
        self.desired_channels = {
            folded: record.channel
            for folded, record in records.items()
            if record.present
        }

        channels = self._migrate_runtimes(
            casemapping, old_channels, old_desired, old_records
        )
        parted = {
            folded: records[folded].channel
            for folded, runtime in channels.items()
            if folded not in self.desired_channels
            and runtime.joined
            and folded in records
        }
        channels = {
            folded: runtime
            for folded, runtime in channels.items()
            if folded in self.desired_channels
        }
        for folded in self.desired_channels:
            record = records[folded]
            runtime = channels.setdefault(
                folded,
                ChannelRuntime(casemapping=casemapping),
            )
            runtime.key = record.key
        self.channels = channels
        self.pending_parts = {
            self.bot.fold(channel): channel for channel in self.pending_parts.values()
        }
        self.pending_parts.update(parted)
        self.cooldowns.clear()
        self.pending_op_flushes.clear()
        self.pending_ops.clear()


@dataclass(slots=True)
class ChannelMember:
    """Track a single member's nick, prefix, and channel modes."""

    nick: str
    modes: set[str] = field(default_factory=set)
    prefix: Prefix | None = None


@dataclass(frozen=True, slots=True)
class ChannelRecord:
    """A channel update, including part tombstones for offline peers."""

    # Process-wide by design: one bot per process, and every locally minted
    # record must share one monotonic revision order.
    last_revision: ClassVar[int] = 0

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
    ) -> ChannelRecord:
        """Create a channel record with a monotonic revision."""
        previous = 0
        if after is not None:
            previous = int(validate_channel_revision(after).partition("-")[0])
        cls.last_revision = max(cls.last_revision + 1, previous + 1)
        if cls.last_revision > MAX_CHANNEL_REVISION:
            msg = "channel revision counter is exhausted"
            raise ValueError(msg)
        channel, key = validate_join(channel, key)
        return cls(
            channel=channel,
            key=key,
            present=present,
            revision=f"{cls.last_revision:020d}-{uuid.uuid4().hex}",
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the channel record to a dictionary."""
        return asdict(self)


@dataclass(slots=True)
class ChannelRuntime:
    """Maintain live channel state including members, bans, and keys."""

    bans: dict[str, str] = field(default_factory=dict)
    casemapping: str = DEFAULT_CASEMAPPING
    joined: bool = False
    key: str | None = None
    members: dict[str, ChannelMember] = field(default_factory=dict)

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
        self.joined = False
        self.members.clear()

    def set_casemapping(self, casemapping: str) -> None:
        """Apply a new casemapping and re-key members and bans."""
        self.casemapping = casemapping
        members: dict[str, ChannelMember] = {}
        for member in self.members.values():
            if not member.nick:
                continue
            folded = casefold(member.nick, casemapping)
            members.setdefault(folded, member)
        self.members = members
        rekeyed: dict[str, str] = {}
        for mask in self.bans.values():
            rekeyed.setdefault(casefold(mask, casemapping), mask)
        self.bans = rekeyed

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
