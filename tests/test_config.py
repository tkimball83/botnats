# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for bot configuration loading."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from botnats.config import (
    BotConfig,
    mode_string,
    nats_urls,
    port,
    positive_float,
    replica_count,
)
from botnats.irc.client import IRCServer

CONFIG = b"""{
  "authorization": {
    "session_ttl_seconds": 600
  },
  "bot": {
    "id": "botnats",
    "network": "efnet",
    "nickname": "botnats"
  },
  "coordination": {
    "maintenance_interval_seconds": 2,
    "presence_ttl_seconds": 10
  },
  "irc": {
    "servers": ["ircs://irc.example.test:6697"],
    "verify_tls": false
  },
  "nats": {
    "jetstream_replicas": 3,
    "servers": ["nats://nats.internal:4222"]
  }
}
"""
DEFAULT_FLOAT = 2.5
EXPECTED_COORDINATION_KEY = "coordination-secret-used-only-for-tests"
EXPECTED_MONITOR_PORT = 8222
EXPECTED_NATS_CREDENTIAL = "nats-token"
EXPECTED_REPLICAS = 3
OVERSIZED_NUMBER = 10**400
SECRETS = {
    "BOTNATS_COORDINATION_SECRET": "coordination-secret-used-only-for-tests",
    "BOTNATS_NATS_TOKEN": "nats-token",
    "BOTNATS_TOTP_SECRET": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
}


class ConfigTests(unittest.TestCase):
    """Tests for JSON configuration file loading."""

    def test_config_loading(self) -> None:
        """Verify configuration loads from JSON with environment overrides."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_bytes(CONFIG)
            with patch.dict(os.environ, SECRETS):
                config = BotConfig.load(path)

        assert config.bot_id == "botnats"
        assert config.coordination_secret == EXPECTED_COORDINATION_KEY
        assert config.nickname == "botnats"
        assert not config.irc_verify_tls
        assert config.nats_token == EXPECTED_NATS_CREDENTIAL
        assert config.nats_monitor_port == EXPECTED_MONITOR_PORT
        assert config.jetstream_replicas == EXPECTED_REPLICAS
        assert config.irc_servers == (IRCServer("irc.example.test", 6697, tls=True),)

    def test_config_requires_object(self) -> None:
        """Verify a non-object JSON document produces a clear config error."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_text("[]")
            with self.assertRaisesRegex(TypeError, "configuration must be an object"):
                BotConfig.load(path)

    def test_channel_modes_reject_contradictions(self) -> None:
        """Reject modes configured as both required and forbidden."""
        with self.assertRaisesRegex(ValueError, "require and forbid"):
            mode_string({"channel_modes": "+n-n"}, "channel_modes", "")

    def test_channel_modes_reject_oversized_message(self) -> None:
        """Reject channel modes that cannot fit in an IRC MODE command."""
        with self.assertRaisesRegex(ValueError, "512 bytes"):
            mode_string({"channel_modes": "+" + "n" * 510}, "channel_modes", "")

    def test_channel_modes_reject_unusable_syntax(self) -> None:
        """Reject unsigned, empty, and argument-consuming channel modes."""
        for value in ("nt", "+", "+k", "-b", "+o"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mode_string({"channel_modes": value}, "channel_modes", "")

    def test_port_validation(self) -> None:
        """Verify monitoring ports default and stay in the TCP port range."""
        assert port({}, "monitor_port", EXPECTED_MONITOR_PORT) == EXPECTED_MONITOR_PORT
        for bad in (True, 0, 65536, 8222.0, "8222"):
            with self.assertRaisesRegex(ValueError, "integer between 1 and 65535"):
                port({"monitor_port": bad}, "monitor_port", EXPECTED_MONITOR_PORT)

    def test_positive_float_rejects_non_finite(self) -> None:
        """Verify positive_float rejects NaN, infinities, and non-positive values."""
        for bad in (
            float("nan"),
            float("inf"),
            float("-inf"),
            OVERSIZED_NUMBER,
            0,
            -1,
        ):
            with self.assertRaisesRegex(ValueError, "positive number"):
                positive_float({"value": bad}, "value", 1.0)
        assert positive_float({}, "value", DEFAULT_FLOAT) == DEFAULT_FLOAT

    def test_presence_ttl_exceeds_maintenance_interval(self) -> None:
        """Reject presence expiry that is no longer than its heartbeat interval."""
        raw = json.loads(CONFIG)
        raw["coordination"]["presence_ttl_seconds"] = 2
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_text(json.dumps(raw))
            with (
                patch.dict(os.environ, SECRETS),
                self.assertRaisesRegex(
                    ValueError,
                    "presence_ttl_seconds must exceed",
                ),
            ):
                BotConfig.load(path)

    def test_replica_count_validation(self) -> None:
        """Verify JetStream replicas default to one and stay in range."""
        assert replica_count({}) == 1
        for bad in (True, 0, 6, 1.0, "3"):
            with self.assertRaisesRegex(ValueError, "integer between 1 and 5"):
                replica_count({"jetstream_replicas": bad})

    def test_server_url_validation(self) -> None:
        """Verify IRC and NATS URLs reject unsupported components and ports."""
        invalid_nats = (
            "nats://host:bad",
            "nats://host:0",
            "nats://host:70000",
            "nats://host/stream",
            "nats://token@host:4222",
            "nats://ho\x1bst:4222",
            "nats://" + chr(0xD800) + ":4222",
        )
        invalid_irc = (
            "irc://host:bad",
            "irc://host:0",
            "irc://host:70000",
            "irc://host/channel",
            "irc://user@host:6667",
            "irc://ho\x7fst:6667",
            "irc://" + chr(0xD800) + ":6667",
        )
        for value in invalid_nats:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "invalid NATS server URL",
                ) as raised:
                    nats_urls({"servers": [value]})
                assert value not in str(raised.exception)
        for value in invalid_irc:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "invalid IRC server URL",
                ) as raised:
                    IRCServer.parse(value)
                assert value not in str(raised.exception)

    def test_unknown_keys(self) -> None:
        """Verify configuration typos fail instead of selecting defaults."""
        raw = json.loads(CONFIG)
        raw["nats"]["jetsteam_replicas"] = 3
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bot.json")
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError, "jetsteam_replicas"):
                BotConfig.load(path)
