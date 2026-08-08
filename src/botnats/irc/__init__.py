# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Minimal asynchronous IRC protocol transport and parser."""

from botnats.irc.client import IRCClient, IRCClientConfig
from botnats.irc.protocol import (
    CASEMAPPINGS,
    DEFAULT_CASEMAPPING,
    IRCMessage,
    IRCProtocol,
    Prefix,
    casefold,
    format_message,
    iter_mode_changes,
    mask_matches,
    parse_message,
)

__all__ = [
    "CASEMAPPINGS",
    "DEFAULT_CASEMAPPING",
    "IRCClient",
    "IRCClientConfig",
    "IRCMessage",
    "IRCProtocol",
    "Prefix",
    "casefold",
    "format_message",
    "iter_mode_changes",
    "mask_matches",
    "parse_message",
]
