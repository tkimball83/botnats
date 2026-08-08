# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Immutable application configuration."""

import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from botnats.irc.client import IRCServer
from botnats.irc.protocol import format_message, mode_requires_argument
from botnats.validators import validate_server_url

if TYPE_CHECKING:
    from collections.abc import Collection

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MODE_STRING_RE = re.compile(r"^(?:[+-][A-Za-z]+)+$")
MAX_JETSTREAM_REPLICAS = 5
MAX_PORT = 65535
MAX_SESSION_TTL = 86400
MIN_COORDINATION_KEY_BYTES = 32
NATS_SCHEMES = frozenset({"nats", "tls"})
NICKNAME_RE = re.compile(r"^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]*$")


@dataclass(frozen=True, slots=True)
class BotConfig:
    """Validated configuration used by one bot process."""

    auth_session_ttl: float
    bot_id: str
    channel_modes: str
    coordination_secret: str = field(repr=False)
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
    totp_secret: str = field(repr=False)

    @classmethod
    def load(cls, path: str | Path) -> BotConfig:
        """Read and validate a configuration file and environment secrets."""
        with Path(path).open() as stream:
            raw = json.load(stream)
        if not isinstance(raw, dict):
            msg = "configuration must be an object"
            raise TypeError(msg)

        authorization = table(raw, "authorization", "session_ttl_seconds")
        bot = table(raw, "bot", "id", "network", "nickname")
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
        nickname = nick(bot, "nickname")
        servers = irc_servers(irc)
        nats_servers = nats_urls(nats_section)
        totp_secret, nats_token, coordination_secret = load_secrets()
        channel_modes = mode_string(irc, "channel_modes", "")
        maintenance_interval = positive_float(
            coordination,
            "maintenance_interval_seconds",
            3,
        )
        presence_ttl = positive_float(coordination, "presence_ttl_seconds", 15)
        if presence_ttl <= maintenance_interval:
            msg = "presence_ttl_seconds must exceed maintenance_interval_seconds"
            raise ValueError(msg)

        session_ttl = positive_float(authorization, "session_ttl_seconds", 3600)
        if session_ttl > MAX_SESSION_TTL:
            msg = f"session_ttl_seconds must not exceed {MAX_SESSION_TTL}"
            raise ValueError(msg)

        return cls(
            auth_session_ttl=session_ttl,
            bot_id=bot_id,
            channel_modes=channel_modes,
            coordination_secret=coordination_secret,
            irc_connect_timeout=positive_float(irc, "connect_timeout_seconds", 30),
            irc_servers=servers,
            irc_verify_tls=boolean(irc, "verify_tls", default=True),
            jetstream_replicas=replica_count(nats_section),
            maintenance_interval=maintenance_interval,
            nats_monitor_port=port(nats_section, "monitor_port", 8222),
            nats_servers=nats_servers,
            nats_token=nats_token,
            network=network,
            nickname=nickname,
            presence_ttl=presence_ttl,
            totp_secret=totp_secret,
        )


def boolean(section: dict[str, Any], key: str, *, default: bool) -> bool:
    """Extract a boolean value from a config section."""
    value = section.get(key, default)
    if not isinstance(value, bool):
        msg = f"{key} must be a boolean"
        raise TypeError(msg)
    return value


def identifier(section: dict[str, Any], key: str) -> str:
    """Extract and validate an identifier from a config section."""
    value = text(section, key)
    if not IDENTIFIER_RE.fullmatch(value):
        msg = f"{key} contains unsupported characters"
        raise ValueError(msg)
    return value


def irc_servers(section: dict[str, Any]) -> tuple[IRCServer, ...]:
    """Parse and validate the IRC server list from a config section."""
    servers = tuple(IRCServer.parse(value) for value in text_list(section, "servers"))
    if not servers:
        msg = "irc.servers must not be empty"
        raise ValueError(msg)
    return servers


def load_secrets() -> tuple[str, str, str]:
    """Load and validate required secrets from environment variables."""
    totp_secret = os.environ.get("BOTNATS_TOTP_SECRET", "")
    nats_token = os.environ.get("BOTNATS_NATS_TOKEN", "")
    coordination_secret = os.environ.get("BOTNATS_COORDINATION_SECRET", "")
    if not totp_secret:
        msg = "BOTNATS_TOTP_SECRET is required"
        raise ValueError(msg)
    if not nats_token:
        msg = "BOTNATS_NATS_TOKEN is required"
        raise ValueError(msg)
    if len(coordination_secret.encode()) < MIN_COORDINATION_KEY_BYTES:
        msg = "BOTNATS_COORDINATION_SECRET must contain at least 32 bytes"
        raise ValueError(msg)
    return totp_secret, nats_token, coordination_secret


def mode_string(section: dict[str, Any], key: str, default: str) -> str:
    """Extract and validate a channel mode string from a config section."""
    value = section.get(key, default)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    required, forbidden = mode_intent(value)
    if any(mode_requires_argument(mode, adding=True) for mode in required) or any(
        mode_requires_argument(mode, adding=False) for mode in forbidden
    ):
        msg = f"{key} contains a mode that requires an argument"
        raise ValueError(msg)
    if value:
        format_message("MODE", ("#x", value), None)
    return value


def mode_intent(value: str) -> tuple[frozenset[str], frozenset[str]]:
    """Return modes required to be set and unset, rejecting contradictions."""
    if value and MODE_STRING_RE.fullmatch(value) is None:
        msg = "channel_modes contains unsupported characters"
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
        msg = "channel_modes cannot require and forbid the same mode"
        raise ValueError(msg)
    return frozenset(required), frozenset(forbidden)


def nats_urls(section: dict[str, Any]) -> tuple[str, ...]:
    """Parse and validate the NATS server list from a config section."""
    servers = text_list(section, "servers")
    if not servers:
        msg = "nats.servers must not be empty"
        raise ValueError(msg)
    for server in servers:
        validate_server_url(server, NATS_SCHEMES, "NATS")
    return servers


def nick(section: dict[str, Any], key: str) -> str:
    """Extract and validate an IRC nickname from a config section."""
    value = text(section, key)
    if not NICKNAME_RE.fullmatch(value):
        msg = f"{key} is not a valid IRC nickname"
        raise ValueError(msg)
    return value


def port(section: dict[str, Any], key: str, default: int) -> int:
    """Extract a valid TCP port number."""
    value = section.get(key, default)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_PORT
    ):
        msg = f"{key} must be an integer between 1 and 65535"
        raise ValueError(msg)
    return value


def positive_float(section: dict[str, Any], key: str, default: float) -> float:
    """Extract a positive numeric value from a config section."""
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"{key} must be a positive number"
        raise TypeError(msg)
    try:
        number = float(value)
    except OverflowError as error:
        msg = f"{key} must be a positive number"
        raise ValueError(msg) from error
    if not math.isfinite(number) or number <= 0:
        msg = f"{key} must be a positive number"
        raise ValueError(msg)
    return number


def replica_count(section: dict[str, Any]) -> int:
    """Extract a valid JetStream replica count."""
    value = section.get("jetstream_replicas", 1)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_JETSTREAM_REPLICAS
    ):
        msg = "jetstream_replicas must be an integer between 1 and 5"
        raise ValueError(msg)
    return value


def table(raw: dict[str, Any], key: str, *allowed: str) -> dict[str, Any]:
    """Extract a configuration section and reject unsupported fields."""
    value = raw.pop(key, None)
    if not isinstance(value, dict):
        msg = f"missing [{key}] configuration table"
        raise TypeError(msg)
    unsupported(set(value).difference(allowed), key)
    return value


def text(section: dict[str, Any], key: str) -> str:
    """Extract a required non-empty string from a config section."""
    value = section.get(key)
    if not isinstance(value, str) or not value:
        msg = f"{key} must be a non-empty string"
        raise ValueError(msg)
    return value


def text_list(section: dict[str, Any], key: str) -> tuple[str, ...]:
    """Extract a required list of non-empty strings from a config section."""
    value = section.get(key)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        msg = f"{key} must be a list of non-empty strings"
        raise ValueError(msg)
    return tuple(value)


def unsupported(fields: Collection[str], label: str) -> None:
    """Reject unsupported configuration fields."""
    if fields:
        names = ", ".join(sorted(fields))
        msg = f"unsupported {label} configuration key(s): {names}"
        raise ValueError(msg)
