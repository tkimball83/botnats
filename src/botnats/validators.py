# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""IRC names, keys, targets, and server URL validation."""

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from botnats.irc.protocol import format_message

if TYPE_CHECKING:
    from collections.abc import Collection
MAX_CHANNEL_REVISION = (1 << 63) - 1
CHANNEL_REVISION_RE = re.compile(r"\d{20}-[0-9a-f]{32}")


def _has_control_chars(value: str) -> bool:
    return any(c.isspace() or c == "\x00" for c in value)


def validate_channel(value: str) -> str:
    """Verify an IRC channel name is well-formed and return it."""
    if len(value) < 2 or not value.startswith(("#", "&", "+", "!")):
        msg = "channel must start with #, &, +, or !"
        raise ValueError(msg)
    if "," in value or "\x07" in value or _has_control_chars(value):
        msg = "channel contains unsupported characters"
        raise ValueError(msg)
    return value


def validate_key(value: str) -> str:
    """Verify an IRC channel key is well-formed and return it."""
    if not value:
        msg = "channel key must not be empty"
        raise ValueError(msg)
    if value.startswith(":") or "," in value or _has_control_chars(value):
        msg = "channel key contains unsupported characters"
        raise ValueError(msg)
    return value


def validate_join(channel: str, key: str | None) -> tuple[str, str | None]:
    """Validate a channel JOIN and return its normalized parameters."""
    channel = validate_channel(channel)
    key = validate_key(key) if key is not None else None
    format_message("JOIN", (channel, key) if key is not None else (channel,), None)
    return channel, key


def validate_channel_revision(value: object) -> str:
    """Verify a durable channel revision and return it."""
    if (
        not isinstance(value, str)
        or CHANNEL_REVISION_RE.fullmatch(value) is None
        or int(value.partition("-")[0]) > MAX_CHANNEL_REVISION
    ):
        msg = "channel record has an invalid revision"
        raise ValueError(msg)
    return value


def parse_channel_record(value: object) -> tuple[str, str | None, bool, str]:
    """Validate and extract a durable channel record."""
    if not isinstance(value, dict):
        msg = "channel record must be an object"
        raise TypeError(msg)
    channel = value.get("channel")
    key = value.get("key")
    present = value.get("present")
    if not isinstance(channel, str):
        msg = "channel record has an invalid channel"
        raise TypeError(msg)
    if "key" not in value or (key is not None and not isinstance(key, str)):
        msg = "channel record has an invalid key"
        raise ValueError(msg)
    if not isinstance(present, bool):
        msg = "channel record has an invalid presence flag"
        raise TypeError(msg)
    channel, key = validate_join(channel, key)
    return channel, key, present, validate_channel_revision(value.get("revision"))


def validate_server_url(
    value: str,
    schemes: Collection[str],
    label: str,
) -> tuple[str, str, int | None]:
    """Parse and validate a connection URL."""
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
        if hostname is not None:
            hostname.encode("idna")
    except ValueError as error:
        msg = f"invalid {label} server URL"
        raise ValueError(msg) from error
    if (
        parsed.scheme not in schemes
        or not hostname
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
        or any(
            character.isspace() or character < " " or character == "\x7f"
            for character in value
        )
    ):
        msg = f"invalid {label} server URL"
        raise ValueError(msg)
    return parsed.scheme, hostname, port


def validate_target(value: str) -> str:
    """Verify an IRC command target or ban mask is a single safe parameter."""
    if not value:
        msg = "target must not be empty"
        raise ValueError(msg)
    if value.startswith(":") or _has_control_chars(value):
        msg = "target contains unsupported characters"
        raise ValueError(msg)
    return value
