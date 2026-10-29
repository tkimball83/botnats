# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Immutable application configuration."""

import base64
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from botnats.irc.client import IRCServer
from botnats.irc.protocol import format_message, mode_requires_argument
from botnats.validators import IDENTIFIER_RE, validate_server_url

if TYPE_CHECKING:
    from collections.abc import Collection

MODE_STRING_RE = re.compile(r"(?:[+-][A-Za-z]+)+")
# RFC 1459's NICKLEN, which every server family accepts: some truncate a
# longer NICK and others refuse it, so the bot could never hold its nick.
MAX_NICKNAME_LENGTH = 9
MIN_COORDINATION_KEY_BYTES = 32
MIN_TOTP_SECRET_BYTES = 20
NATS_SCHEMES = frozenset({"nats", "tls"})
NICKNAME_RE = re.compile(r"[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]*")


@dataclass(frozen=True, slots=True)
class BotConfig:
    """Validated configuration used by one bot process."""

    bot_id: str
    channel_modes: str
    coordination_secret: bytes = field(repr=False)
    # The channel modes to keep set and to keep unset.
    enforced_modes: tuple[frozenset[str], frozenset[str]]
    health_port: int
    irc_connect_timeout: float
    irc_servers: tuple[IRCServer, ...]
    irc_verify_tls: bool
    jetstream_replicas: int
    maintenance_interval: float
    nats_monitor_port: int
    nats_servers: tuple[str, ...]
    nats_token: str = field(repr=False)
    network: str
    nickname: str
    presence_ttl: float
    totp_secret: bytes = field(repr=False)

    @classmethod
    def load(cls, path: str | Path) -> BotConfig:
        """Read and validate a configuration file and environment secrets."""
        with Path(path).open() as stream:
            raw = json.load(stream)

        if not isinstance(raw, dict):
            msg = "configuration must be an object"
            raise TypeError(msg)

        bot = table(raw, "bot", "health_port", "id", "network", "nickname")
        coordination = table(
            raw,
            "coordination",
            "maintenance_interval_seconds",
            "presence_ttl_seconds",
        )
        irc = table(
            raw,
            "irc",
            "channel_modes",
            "connect_timeout_seconds",
            "servers",
            "verify_tls",
        )
        nats_section = table(
            raw,
            "nats",
            "jetstream_replicas",
            "monitor_port",
            "servers",
        )
        unsupported(raw, "root")

        bot_id = identifier(bot, "id")
        network = identifier(bot, "network")
        servers = irc_servers(irc)
        nats_servers = nats_urls(nats_section)
        totp_secret, nats_token, coordination_secret = load_secrets()
        channel_modes, enforced_modes = mode_string(irc)
        maintenance_interval = positive_float(
            coordination,
            "maintenance_interval_seconds",
            "coordination",
            3,
        )
        presence_ttl = positive_float(
            coordination,
            "presence_ttl_seconds",
            "coordination",
            15,
        )
        if presence_ttl <= maintenance_interval:
            msg = (
                "coordination.presence_ttl_seconds must exceed "
                "coordination.maintenance_interval_seconds"
            )
            raise ValueError(msg)

        return cls(
            bot_id=bot_id,
            channel_modes=channel_modes,
            coordination_secret=coordination_secret,
            enforced_modes=enforced_modes,
            health_port=port(bot, "health_port", "bot", 8080),
            irc_connect_timeout=positive_float(
                irc,
                "connect_timeout_seconds",
                "irc",
                30,
            ),
            irc_servers=servers,
            irc_verify_tls=verify_tls(irc),
            jetstream_replicas=replica_count(nats_section),
            maintenance_interval=maintenance_interval,
            nats_monitor_port=port(nats_section, "monitor_port", "nats", 8222),
            nats_servers=nats_servers,
            nats_token=nats_token,
            network=network,
            nickname=nickname(bot),
            presence_ttl=presence_ttl,
            totp_secret=totp_secret,
        )


def bot_text(section: dict[str, Any], key: str) -> str:
    """Extract a required non-empty string from the bot section."""
    value = section.get(key)
    if not isinstance(value, str) or not value:
        msg = f"bot.{key} must be a non-empty string"
        raise ValueError(msg)

    return value


def identifier(section: dict[str, Any], key: str) -> str:
    """Extract and validate an identifier from the bot section."""
    value = bot_text(section, key)
    if not IDENTIFIER_RE.fullmatch(value):
        msg = f"bot.{key} contains unsupported characters"
        raise ValueError(msg)

    return value


def irc_servers(section: dict[str, Any]) -> tuple[IRCServer, ...]:
    """Parse and validate the IRC server list from a config section."""
    servers = tuple(IRCServer.parse(value) for value in server_list(section, "irc"))
    if not servers:
        msg = "irc.servers must not be empty"
        raise ValueError(msg)

    return servers


def load_secrets() -> tuple[bytes, str, bytes]:
    """Load and validate required secrets from environment variables."""
    totp_secret = totp_key(os.environ.get("BOTNATS_TOTP_SECRET", ""))
    nats_token = os.environ.get("BOTNATS_NATS_TOKEN", "")
    if not nats_token:
        msg = "BOTNATS_NATS_TOKEN is required"
        raise ValueError(msg)

    try:
        coordination_secret = os.environ.get("BOTNATS_COORDINATION_SECRET", "").encode()
    except UnicodeEncodeError:
        msg = "BOTNATS_COORDINATION_SECRET must be valid UTF-8"
        raise ValueError(msg) from None

    if len(coordination_secret) < MIN_COORDINATION_KEY_BYTES:
        msg = "BOTNATS_COORDINATION_SECRET must contain at least 32 bytes"
        raise ValueError(msg)

    return totp_secret, nats_token, coordination_secret


def mode_string(
    section: dict[str, Any],
) -> tuple[str, tuple[frozenset[str], frozenset[str]]]:
    """Extract the enforced channel modes from the irc section, and their intent."""
    value = section.get("channel_modes", "")
    if not isinstance(value, str):
        msg = "irc.channel_modes must be a string"
        raise TypeError(msg)

    required, forbidden = mode_intent(value)
    if any(mode_requires_argument(mode, adding=True) for mode in required) or any(
        mode_requires_argument(mode, adding=False) for mode in forbidden
    ):
        msg = "irc.channel_modes contains a mode that requires an argument"
        raise ValueError(msg)

    if value:
        format_message("MODE", ("#x", value), None)

    return value, (required, forbidden)


def mode_intent(value: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return modes required to be set and unset, rejecting contradictions."""
    if value and MODE_STRING_RE.fullmatch(value) is None:
        msg = "irc.channel_modes contains unsupported characters"
        raise ValueError(msg)

    required: set[str] = set()
    forbidden: set[str] = set()
    adding = True
    for character in value:
        if character == "+":
            adding = True
        elif character == "-":
            adding = False
        else:
            (required if adding else forbidden).add(character)

    if required & forbidden:
        msg = "irc.channel_modes cannot require and forbid the same mode"
        raise ValueError(msg)

    return frozenset(required), frozenset(forbidden)


def nats_urls(section: dict[str, Any]) -> tuple[str, ...]:
    """Parse and validate the NATS server list from a config section."""
    servers = server_list(section, "nats")
    if not servers:
        msg = "nats.servers must not be empty"
        raise ValueError(msg)

    for server in servers:
        validate_server_url(server, NATS_SCHEMES, "NATS")

    return servers


def nickname(section: dict[str, Any]) -> str:
    """Extract and validate the IRC nickname from the bot section."""
    value = bot_text(section, "nickname")
    if not NICKNAME_RE.fullmatch(value):
        msg = "bot.nickname is not a valid IRC nickname"
        raise ValueError(msg)

    if len(value) > MAX_NICKNAME_LENGTH:
        msg = f"bot.nickname must not exceed {MAX_NICKNAME_LENGTH} characters"
        raise ValueError(msg)

    return value


def port(section: dict[str, Any], key: str, label: str, default: int) -> int:
    """Extract a valid TCP port number."""
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        msg = f"{label}.{key} must be an integer between 1 and 65535"
        raise ValueError(msg)

    return value


def positive_float(
    section: dict[str, Any],
    key: str,
    label: str,
    default: float,
) -> float:
    """Extract a positive numeric value from a config section."""
    msg = f"{label}.{key} must be a positive number"
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(msg)

    try:
        number = float(value)
    except OverflowError as error:
        raise ValueError(msg) from error

    if not math.isfinite(number) or number <= 0:
        raise ValueError(msg)

    return number


def replica_count(section: dict[str, Any]) -> int:
    """Extract a valid JetStream replica count."""
    value = section.get("jetstream_replicas", 1)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
        msg = "nats.jetstream_replicas must be an integer between 1 and 5"
        raise ValueError(msg)

    return value


def server_list(section: dict[str, Any], label: str) -> tuple[str, ...]:
    """Extract a section's servers: a required list of non-empty strings."""
    value = section.get("servers")
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        msg = f"{label}.servers must be a list of non-empty strings"
        raise ValueError(msg)

    return tuple(value)


def table(raw: dict[str, Any], key: str, *allowed: str) -> dict[str, Any]:
    """Extract a configuration section and reject unsupported fields.

    A missing section reads as empty so tables whose keys all have defaults
    can be omitted; required keys still fail with their own messages.
    """
    value = raw.pop(key, {})
    if not isinstance(value, dict):
        msg = f"{key} must be a JSON object"
        raise TypeError(msg)

    unsupported(set(value).difference(allowed), key)
    return value


def totp_key(value: str) -> bytes:
    """Decode the base32 TOTP secret and require at least 160 bits."""
    if not value:
        msg = "BOTNATS_TOTP_SECRET is required"
        raise ValueError(msg)

    normalized = "".join(value.split()).upper()
    padding = "=" * (-len(normalized) % 8)
    try:
        decoded = base64.b32decode(normalized + padding)
    except ValueError as error:
        msg = "BOTNATS_TOTP_SECRET must be valid base32"
        raise ValueError(msg) from error

    if len(decoded) < MIN_TOTP_SECRET_BYTES:
        msg = "BOTNATS_TOTP_SECRET must contain at least 160 bits"
        raise ValueError(msg)

    return decoded


def unsupported(fields: Collection[str], label: str) -> None:
    """Reject unsupported configuration fields."""
    if fields:
        names = ", ".join(sorted(fields))
        msg = f"unsupported {label} configuration key(s): {names}"
        raise ValueError(msg)


def verify_tls(section: dict[str, Any]) -> bool:
    """Extract irc.verify_tls, which defaults to verifying certificates."""
    value = section.get("verify_tls", True)
    if not isinstance(value, bool):
        msg = "irc.verify_tls must be a boolean"
        raise TypeError(msg)

    return value
