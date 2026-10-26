# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for package-level helpers."""

import unittest

from botnats import error_label


class ErrorLabelTests(unittest.TestCase):
    """Tests for the error_label helper."""

    def test_error_with_message(self) -> None:
        """Verify error_label returns the message when present."""
        assert error_label(ValueError("boom")) == "boom"

    def test_error_without_message(self) -> None:
        """Verify error_label falls back to the type name."""
        assert error_label(RuntimeError()) == "RuntimeError"
