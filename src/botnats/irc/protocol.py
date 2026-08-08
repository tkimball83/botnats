# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Data types, casemapping, message parsing, and server capability state for IRC."""

from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from botnats.validators import MAX_IRC_MESSAGE_BYTES

if TYPE_CHECKING:
    from collections.abc import Iterator

CASEMAPPINGS = frozenset({"ascii", "rfc1459", "strict-rfc1459"})
CASEMAP_ASCII = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)
CASEMAP_RFC1459 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\^",
    "abcdefghijklmnopqrstuvwxyz{}|~",
)
CASEMAP_STRICT = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]\\",
    "abcdefghijklmnopqrstuvwxyz{}|",
)
CHANMODE_GROUP_COUNT = 4
DEFAULT_CASEMAPPING = "rfc1459"
DEFAULT_MEMBER_PREFIXES = {
    "%": "h",
    "&": "a",
    "+": "v",
    "@": "o",
    "~": "q",
}
ILLEGAL_PARAM_CHARS = frozenset(" \x00\r\n")
ILLEGAL_TRAILING_CHARS = frozenset("\x00\r\n")
TAG_ESCAPES = str.maketrans(
    {":": ";", "\\": "\\", "n": "\n", "r": "\r", "s": " "},
)


@dataclass(frozen=True, slots=True)
class IRCMessage:
    """Parsed IRC message with command, parameters, prefix, and tags."""

    command: str
    params: tuple[str, ...]
    prefix: Prefix | None = None
    tags: dict[str, str | None] = field(default_factory=dict)


class IRCProtocol(Protocol):
    """Interface for IRC client implementations."""

    current_nick: str
    desired_nick: str

    async def close(self) -> None:
        """Close the connection."""
        ...

    @property
    def connected(self) -> bool:
        """Return whether the socket is open."""
        ...

    async def reconnect(self) -> None:
        """Force a reconnection."""
        ...

    def reset_caps(self) -> None:
        """Reset server capabilities."""
        ...

    async def run_forever(self) -> None:
        """Maintain a persistent connection."""
        ...

    async def send(
        self,
        command: str,
        *params: str,
        trailing: str | None = None,
    ) -> None:
        """Enqueue an IRC command."""
        ...

    def set_casemapping(self, casemapping: str) -> None:
        """Apply a casemapping."""
        ...

    def set_nickname_length(self, length: int) -> None:
        """Record the nickname length limit."""
        ...


@dataclass(slots=True)
class ISupportState:
    """Tracks server capabilities advertised via ISUPPORT tokens."""

    casemapping: str = DEFAULT_CASEMAPPING
    chanmodes: tuple[str, str, str, str] = ("beI", "k", "l", "imnst")
    member_prefixes: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_MEMBER_PREFIXES),
    )
    membership_modes: str = "qaohv"
    mode_limit: int = 1
    op_mode: str = "o"

    @property
    def operator_modes(self) -> str:
        """Return membership modes with at least channel operator privileges."""
        op_index = self.membership_modes.find(self.op_mode)
        return self.membership_modes[: op_index + 1] if op_index >= 0 else self.op_mode

    def is_opped(self, modes: set[str]) -> bool:
        """Return whether the given mode set includes channel operator status."""
        return not modes.isdisjoint(self.operator_modes)

    def parse_chanmodes(self, value: str) -> None:
        """Extract the four CHANMODES categories from an ISUPPORT value."""
        groups = value.split(",")
        if len(groups) >= CHANMODE_GROUP_COUNT:
            self.chanmodes = (groups[0], groups[1], groups[2], groups[3])

    def parse_modes(self, value: str) -> None:
        """Set the per-command mode-change limit from an ISUPPORT value."""
        with suppress(ValueError):
            self.mode_limit = max(1, int(value))

    def parse_prefix(self, value: str) -> None:
        """Map membership symbols to modes from an ISUPPORT PREFIX value."""
        if value in {"", "()"}:
            self.member_prefixes = {}
            self.membership_modes = ""
            self.op_mode = "o"
            return
        if not value.startswith("(") or ")" not in value:
            return
        modes, symbols = value[1:].split(")", 1)
        if not modes or len(modes) != len(symbols):
            return
        self.member_prefixes = dict(zip(symbols, modes, strict=True))
        self.membership_modes = modes
        self.op_mode = self.member_prefixes.get(
            "@",
            "o" if "o" in modes else modes[0],
        )

    def reset(self) -> None:
        """Reset capabilities learned from the previous server connection."""
        self.casemapping = DEFAULT_CASEMAPPING
        self.chanmodes = ("beI", "k", "l", "imnst")
        self.member_prefixes = dict(DEFAULT_MEMBER_PREFIXES)
        self.membership_modes = "qaohv"
        self.mode_limit = 1
        self.op_mode = "o"


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

    def matches(self, other: Prefix, casemapping: str = DEFAULT_CASEMAPPING) -> bool:
        """Check whether two complete prefixes identify the same user."""
        return (
            self.complete
            and other.complete
            and casefold(self.nick, casemapping) == casefold(other.nick, casemapping)
            and self.host is not None
            and other.host is not None
            and self.user is not None
            and other.user is not None
            and casefold(self.user, "ascii") == casefold(other.user, "ascii")
            and casefold(self.host, "ascii") == casefold(other.host, "ascii")
        )

    @classmethod
    def parse(cls, value: str) -> Prefix:
        """Construct a Prefix from a nick!user@host string."""
        nick, bang, remainder = value.partition("!")
        if not bang:
            return cls(nick=nick)
        user, at, host = remainder.partition("@")
        return cls(nick=nick, user=user or None, host=(host or None) if at else None)

    def render(self) -> str:
        """Format the prefix as a nick!user@host string."""
        if not self.complete:
            return self.nick
        return f"{self.nick}!{self.user}@{self.host}"


def casefold(value: str, casemapping: str = DEFAULT_CASEMAPPING) -> str:
    """Fold an IRC identifier using a server-advertised casemapping."""
    match casemapping:
        case "ascii":
            return value.translate(CASEMAP_ASCII)
        case "rfc1459":
            return value.translate(CASEMAP_RFC1459)
        case "strict-rfc1459":
            return value.translate(CASEMAP_STRICT)
        case _:
            msg = f"unsupported casemapping: {casemapping!r}"
            raise ValueError(msg)


def format_message(
    command: str,
    params: tuple[str, ...],
    trailing: str | None,
) -> bytes:
    """Encode an IRC command, parameters, and trailing text into bytes."""
    if not command or not command.isascii() or not command.isalnum():
        msg = "IRC command contains unsupported characters"
        raise ValueError(msg)
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


def glob_matches(pattern: str, value: str) -> bool:
    """Match a glob pattern with * and ? wildcards without backtracking blowup."""
    pattern_index = 0
    value_index = 0
    star_index = -1
    star_value_index = 0
    while value_index < len(value):
        if pattern_index < len(pattern) and pattern[pattern_index] in (
            value[value_index],
            "?",
        ):
            pattern_index += 1
            value_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == "*":
            star_index = pattern_index
            star_value_index = value_index
            pattern_index += 1
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
    chanmodes: tuple[str, str, str, str] = ("beI", "k", "l", "imnst"),
    membership: str = "qaohv",
) -> Iterator[tuple[bool, str, str | None]]:
    """Yield channel mode changes with their consumed arguments."""
    adding = True
    argument_index = 0
    for mode in modes:
        if mode == "+":
            adding = True
            continue
        if mode == "-":
            adding = False
            continue
        argument = None
        if mode_requires_argument(
            mode,
            adding=adding,
            chanmodes=chanmodes,
            membership=membership,
        ) and argument_index < len(arguments):
            argument = arguments[argument_index]
            argument_index += 1
        yield adding, mode, argument


def mode_requires_argument(
    mode: str,
    *,
    adding: bool,
    chanmodes: tuple[str, str, str, str] = ("beI", "k", "l", "imnst"),
    membership: str = "qaohv",
) -> bool:
    """Return whether a channel mode change consumes an argument."""
    return mode in chanmodes[0] + chanmodes[1] + membership or (
        adding and mode in chanmodes[2]
    )


def mask_matches(
    mask: str,
    prefix: Prefix,
    casemapping: str = DEFAULT_CASEMAPPING,
) -> bool:
    """Match a standard IRC nick!user@host mask using only * and ? wildcards."""
    return glob_matches(
        casefold(mask, casemapping),
        casefold(prefix.render(), casemapping),
    )


def parse_message(line: str) -> IRCMessage:
    """Parse a raw IRC line into a structured message."""
    if len(line.encode()) > MAX_IRC_MESSAGE_BYTES:
        msg = "IRC message exceeds 512 bytes"
        raise ValueError(msg)
    rest = line.removesuffix("\n").removesuffix("\r")
    if not ILLEGAL_TRAILING_CHARS.isdisjoint(rest):
        msg = "IRC message contains control characters"
        raise ValueError(msg)
    tags: dict[str, str | None] = {}
    prefix: Prefix | None = None

    if rest.startswith("@"):
        raw_tags, separator, rest = rest[1:].partition(" ")
        if not separator:
            msg = "IRC tags were not followed by a command"
            raise ValueError(msg)
        for raw_tag in raw_tags.split(";"):
            key, equals, value = raw_tag.partition("=")
            tags[key] = unescape_tag(value) if equals else None

    if rest.startswith(":"):
        raw_prefix, separator, rest = rest[1:].partition(" ")
        if not separator:
            msg = "IRC prefix was not followed by a command"
            raise ValueError(msg)
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
        tags=tags,
    )


def unescape_tag(value: str) -> str:
    """Decode backslash escape sequences in an IRCv3 tag value."""
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            result.append(value[index + 1].translate(TAG_ESCAPES))
            index += 2
        elif value[index] == "\\":
            index += 1
        else:
            result.append(value[index])
            index += 1
    return "".join(result)
