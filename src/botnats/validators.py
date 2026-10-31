# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Validation of IRC names and keys, server URLs, and durable channel records."""

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from botnats.irc.protocol import format_message

if TYPE_CHECKING:
    from collections.abc import Collection

IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_-]+")
CHANNEL_REVISION_RE = re.compile(r"[0-9]{20}-[0-9a-f]{32}")
# A safe channel's full name starts with its 5-character channel ID (RFC 2811
# 3.2 and 5.2.1). The server answers a JOIN by short name under the full name,
# which would match no desired channel.
SAFE_CHANNEL_RE = re.compile(r"![A-Z0-9]{5}.")

# A durable channel record's channel, key, presence flag, and revision.
type ChannelFields = tuple[str, str | None, bool, str]


def _has_space_or_nul(value: str) -> bool:
    return any(c.isspace() or c == "\x00" for c in value)


def validate_channel(value: str) -> str:
    """Verify an IRC channel name is well-formed and return it."""
    if not value.startswith(("#", "&", "+")) and not SAFE_CHANNEL_RE.match(value):
        msg = "channel must start with #, &, +, or ! and a 5-character channel ID"
        raise ValueError(msg)

    if len(value) < 2:
        msg = "channel name is empty"
        raise ValueError(msg)

    if "," in value or "\x07" in value or _has_space_or_nul(value):
        msg = "channel contains unsupported characters"
        raise ValueError(msg)

    return value


def validate_key(value: str) -> str:
    """Verify an IRC channel key is well-formed and return it."""
    if not value:
        msg = "channel key must not be empty"
        raise ValueError(msg)

    if value.startswith(":") or "," in value or _has_space_or_nul(value):
        msg = "channel key contains unsupported characters"
        raise ValueError(msg)

    return value


def validate_join(channel: str, key: str | None) -> tuple[str, str | None]:
    """Validate a channel JOIN that fits one IRC line; return channel and key."""
    channel = validate_channel(channel)
    key = validate_key(key) if key is not None else None
    format_message("JOIN", (channel, key) if key is not None else (channel,), None)
    return channel, key


def validate_channel_revision(value: object) -> str:
    """Verify a durable channel revision and return it."""
    if not isinstance(value, str) or CHANNEL_REVISION_RE.fullmatch(value) is None:
        msg = "channel record has an invalid revision"
        raise ValueError(msg)

    return value


def parse_channel_record(value: dict[str, Any]) -> ChannelFields:
    """Validate and extract a durable channel record."""
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
