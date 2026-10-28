# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Data types, casemapping, message parsing, and server capability state for IRC."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator

STRICT_RFC1459_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\",
    "abcdefghijklmnopqrstuvwxyz{}|",
)
CASEMAP_TABLES = {
    "ascii": str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
    ),
    "rfc1459": str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\^",
        "abcdefghijklmnopqrstuvwxyz{}|~",
    ),
    # The modern ISUPPORT spelling, which Ergo advertises.
    "rfc1459-strict": STRICT_RFC1459_TABLE,
    "strict-rfc1459": STRICT_RFC1459_TABLE,
}
CASEMAPPINGS = frozenset(CASEMAP_TABLES)
DEFAULT_CASEMAPPING = "rfc1459"
DEFAULT_CHANMODES = ("beI", "k", "l", "imnst")
DEFAULT_MEMBERSHIP_MODES = "qaohv"
DEFAULT_OP_MODE = "o"
DEFAULT_MEMBER_PREFIXES = {
    "%": "h",
    "&": "a",
    "+": "v",
    "@": "o",
    "~": "q",
}
ILLEGAL_PARAM_CHARS = frozenset(" \x00\r\n")
ILLEGAL_TRAILING_CHARS = frozenset("\x00\r\n")
MAX_IRC_MESSAGE_BYTES = 512


@dataclass(frozen=True, slots=True)
class IRCMessage:
    """Parsed IRC message with command, parameters, and prefix."""

    command: str
    params: tuple[str, ...]
    prefix: Prefix | None = None


class IRCSender(Protocol):
    """Sends commands as this bot's current nick, reconnecting on demand."""

    current_nick: str

    def reconnect(self) -> None:
        """Force a reconnection."""
        ...

    def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
        unless_waiting: bool = False,
    ) -> bool:
        """Enqueue an IRC command, unless asked to skip a copy still waiting.

        Return whether it was queued.
        """
        ...


class IRCProtocol(IRCSender, Protocol):
    """Interface for IRC client implementations."""

    async def close(self) -> None:
        """Close the connection."""
        ...

    @property
    def connected(self) -> bool:
        """Return whether the socket is open."""
        ...

    def is_self(self, nickname: str) -> bool:
        """Return whether a nickname identifies this client."""
        ...

    @property
    def queue_delay(self) -> float:
        """Return about how long the lines queued now take to go out."""
        ...

    async def run_forever(self) -> None:
        """Maintain a persistent connection."""
        ...


@dataclass(slots=True)
class ISupportState:
    """Tracks server capabilities advertised via ISUPPORT tokens."""

    casemapping: str = DEFAULT_CASEMAPPING
    chanmodes: tuple[str, str, str, str] = DEFAULT_CHANMODES
    member_prefixes: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_MEMBER_PREFIXES),
    )
    membership_modes: str = DEFAULT_MEMBERSHIP_MODES
    monitor: bool = False
    op_mode: str = DEFAULT_OP_MODE

    @property
    def operator_modes(self) -> str:
        """Return membership modes with at least channel operator privileges."""
        op_index = self.membership_modes.find(self.op_mode)
        return self.membership_modes[: op_index + 1]

    def apply(self, name: str, value: str) -> None:
        """Apply one advertised ISUPPORT token other than CASEMAPPING."""
        match name:
            case "CHANMODES":
                self.parse_chanmodes(value)
            case "MONITOR":
                # The value is only a target limit, and this bot monitors one.
                self.monitor = True
            case "PREFIX":
                self.parse_prefix(value)

    def forget(self, name: str) -> None:
        """Restore the default for one withdrawn ISUPPORT token."""
        default = ISupportState()
        match name:
            case "CHANMODES":
                self.chanmodes = default.chanmodes
            case "MONITOR":
                self.monitor = default.monitor
            case "PREFIX":
                self.member_prefixes = default.member_prefixes
                self.membership_modes = default.membership_modes
                self.op_mode = default.op_mode

    def fold(self, value: str) -> str:
        """Normalize a string using the server's casemapping rules."""
        return casefold(value, self.casemapping)

    def fold_identity(self, prefix: str) -> str:
        """Normalize a nick!user@host identity for case-insensitive comparison."""
        nick, _, rest = prefix.partition("!")
        return self.fold(nick) + "!" + casefold(rest, "ascii")

    def is_opped(self, modes: set[str]) -> bool:
        """Return whether the given mode set includes channel operator status."""
        return not modes.isdisjoint(self.operator_modes)

    def parse_chanmodes(self, value: str) -> None:
        """Extract the four CHANMODES categories from an ISUPPORT value."""
        groups = value.split(",")
        if len(groups) >= 4:
            self.chanmodes = (groups[0], groups[1], groups[2], groups[3])

    def parse_prefix(self, value: str) -> None:
        """Map membership symbols to modes from an ISUPPORT PREFIX value."""
        if not value:
            self.member_prefixes = {}
            self.membership_modes = ""
            self.op_mode = DEFAULT_OP_MODE
            return

        if not value.startswith("(") or ")" not in value:
            return

        modes, symbols = value[1:].split(")", 1)
        if len(modes) != len(symbols):
            return

        self.member_prefixes = dict(zip(symbols, modes, strict=True))
        self.membership_modes = modes
        # Without "@" fall back through the conventional operator tiers; a
        # PREFIX advertising only sub-operator modes (e.g. "(v)+") must not
        # count its highest rank as opped.
        fallback = next(
            (mode for mode in (DEFAULT_OP_MODE, "a", "q") if mode in modes),
            DEFAULT_OP_MODE,
        )
        self.op_mode = self.member_prefixes.get("@", fallback)

    def reset(self) -> None:
        """Reset capabilities learned from the previous server connection."""
        ISupportState.__init__(self)


@dataclass(frozen=True, slots=True)
class Prefix:
    """Decomposed nick!user@host identity."""

    nick: str
    user: str | None = None
    host: str | None = None

    @property
    def complete(self) -> bool:
        """Return whether nick, user, and host are all present."""
        return self.user is not None and self.host is not None

    def matches(self, other: Prefix, casemapping: str) -> bool:
        """Check whether two complete prefixes identify the same user."""
        s_user = self.user
        s_host = self.host
        o_user = other.user
        o_host = other.host
        if s_user is None or s_host is None or o_user is None or o_host is None:
            return False

        return (
            casefold(self.nick, casemapping) == casefold(other.nick, casemapping)
            and casefold(s_user, "ascii") == casefold(o_user, "ascii")
            and casefold(s_host, "ascii") == casefold(o_host, "ascii")
        )

    @classmethod
    def parse(cls, value: str) -> Prefix:
        """Construct a Prefix from a nick!user@host string."""
        nick, bang, remainder = value.partition("!")
        if not bang:
            nick, _, host = value.partition("@")
            return cls(nick=nick, host=host or None)

        user, _, host = remainder.partition("@")
        return cls(nick=nick, user=user or None, host=host or None)

    def render(self) -> str:
        """Format the prefix as a nick!user@host string."""
        if not self.complete:
            return self.nick

        return f"{self.nick}!{self.user}@{self.host}"


def casefold(value: str, casemapping: str) -> str:
    """Fold an IRC identifier using a server-advertised casemapping."""
    return value.translate(CASEMAP_TABLES[casemapping])


def format_message(
    command: str,
    params: tuple[str, ...],
    trailing: str | None,
) -> bytes:
    """Encode an IRC command, parameters, and trailing text into bytes."""
    for param in params:
        if not param or param[0] == ":" or not ILLEGAL_PARAM_CHARS.isdisjoint(param):
            msg = "IRC parameter contains unsupported characters"
            raise ValueError(msg)

    if trailing is not None and not ILLEGAL_TRAILING_CHARS.isdisjoint(trailing):
        msg = "IRC trailing parameter contains unsupported characters"
        raise ValueError(msg)

    components = [command, *params]
    if trailing is not None:
        components.append(f":{trailing}")

    encoded = (" ".join(components) + "\r\n").encode()
    if len(encoded) > MAX_IRC_MESSAGE_BYTES:
        msg = "IRC message exceeds 512 bytes"
        raise ValueError(msg)

    return encoded


def _glob_matches(pattern: str, value: str) -> bool:
    """Match a glob pattern with * and ? wildcards without backtracking blowup."""
    pattern_index = 0
    value_index = 0
    star_index = -1
    star_value_index = 0
    while value_index < len(value):
        # A wildcard is tried first, so a literal "*" in the value cannot
        # consume it as a plain character and lose the backtrack point.
        if pattern_index < len(pattern) and pattern[pattern_index] == "*":
            star_index = pattern_index
            star_value_index = value_index
            pattern_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] in (
            value[value_index],
            "?",
        ):
            pattern_index += 1
            value_index += 1
        elif star_index >= 0:
            pattern_index = star_index + 1
            star_value_index += 1
            value_index = star_value_index
        else:
            return False

    while pattern_index < len(pattern) and pattern[pattern_index] == "*":
        pattern_index += 1

    return pattern_index == len(pattern)


def iter_mode_changes(
    modes: str,
    arguments: tuple[str, ...],
    chanmodes: tuple[str, str, str, str],
    membership: str,
) -> Iterator[tuple[bool, str, str | None]]:
    """Yield channel mode changes with their consumed arguments."""
    adding = True
    changes: list[tuple[bool, str]] = []
    for mode in modes:
        if mode == "+":
            adding = True
            continue

        if mode == "-":
            adding = False
            continue

        changes.append((adding, mode))

    consumes = [
        mode_requires_argument(
            mode,
            adding=adding,
            chanmodes=chanmodes,
            membership=membership,
        )
        for adding, mode in changes
    ]
    # A server that strips the key argument from -k leaves the batch exactly
    # one argument short; letting that -k consume nothing keeps the remaining
    # arguments paired with their modes.
    if sum(consumes) == len(arguments) + 1:
        for position, (adding, mode) in enumerate(changes):
            if mode == "k" and not adding and consumes[position]:
                consumes[position] = False
                break

    argument_index = 0
    for (adding, mode), consume in zip(changes, consumes, strict=True):
        argument = None
        if consume and argument_index < len(arguments):
            argument = arguments[argument_index]
            argument_index += 1

        yield adding, mode, argument


def mode_requires_argument(
    mode: str,
    *,
    adding: bool,
    chanmodes: tuple[str, str, str, str] = DEFAULT_CHANMODES,
    membership: str = DEFAULT_MEMBERSHIP_MODES,
) -> bool:
    """Return whether a channel mode change consumes an argument."""
    return mode in chanmodes[0] + chanmodes[1] + membership or (
        adding and mode in chanmodes[2]
    )


def mask_matches(
    mask: str,
    prefix: Prefix,
    casemapping: str,
) -> bool:
    """Match a standard IRC nick!user@host mask using only * and ? wildcards."""
    mask_prefix = Prefix.parse(mask)
    nick = casefold(prefix.nick, casemapping)
    mask_nick = casefold(mask_prefix.nick, casemapping)
    user = casefold(prefix.user or "", "ascii")
    mask_user = casefold(mask_prefix.user or "*", "ascii")
    host = casefold(prefix.host or "", "ascii")
    mask_host = casefold(mask_prefix.host or "*", "ascii")
    return (
        _glob_matches(mask_nick, nick)
        and _glob_matches(mask_user, user)
        and _glob_matches(mask_host, host)
    )


def parse_message(line: str) -> IRCMessage:
    """Parse a raw IRC line whose wire length the transport has bounded."""
    rest = line.removesuffix("\n").removesuffix("\r")
    if not ILLEGAL_TRAILING_CHARS.isdisjoint(rest):
        msg = "IRC message contains control characters"
        raise ValueError(msg)

    prefix: Prefix | None = None

    if rest.startswith("@"):
        rest = rest.partition(" ")[2].lstrip(" ")

    if rest.startswith(":"):
        raw_prefix, _, rest = rest[1:].partition(" ")
        prefix = Prefix.parse(raw_prefix)

    middle, separator, trailing = rest.partition(" :")
    words = [word for word in middle.split(" ") if word]
    if not words:
        msg = "IRC message has no command"
        raise ValueError(msg)

    params = words[1:]
    if separator:
        params.append(trailing)

    return IRCMessage(
        command=words[0].upper(),
        params=tuple(params),
        prefix=prefix,
    )
