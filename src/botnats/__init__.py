# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Ephemeral IRC bot coordination over NATS."""


def error_label(error: Exception) -> str:
    """Return a description of the error, falling back to the type name."""
    return str(error) or type(error).__name__
