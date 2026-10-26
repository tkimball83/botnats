# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

"""Tests for bot configuration loading."""

import base64
import json
import os
import tempfile
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from botnats.config import (
    BotConfig,
    mode_string,
    nats_urls,
    nickname,
    port,
    positive_float,
    replica_count,
)
from botnats.irc.client import IRCServer
from tests.unit.helpers import (
    AUTH_KEY,
    CONFIG,
    COORDINATION_KEY,
    NATS_CREDENTIAL,
    SECRETS,
)


def load_config(document: object, **environment: str) -> BotConfig:
    """Load a JSON document from a file, with SECRETS and overrides set."""
    with (
        tempfile.TemporaryDirectory() as directory,
        patch.dict(os.environ, {**SECRETS, **environment}),
    ):
        path = Path(directory, "bot.json")
        path.write_text(json.dumps(document))
        return BotConfig.load(path)


class ConfigTests(unittest.TestCase):
    """Tests for JSON configuration file loading."""

    def test_config_loading(self) -> None:
        """Load every field from the JSON file and secrets from the environment."""
        config = load_config(json.loads(CONFIG))

        assert config == BotConfig(
            auth_session_ttl=600,
            bot_id="botnats-1",
            channel_modes="+nt-s",
            coordination_secret=COORDINATION_KEY,
            enforced_modes=(frozenset("nt"), frozenset("s")),
            health_port=9080,
            irc_connect_timeout=45,
            irc_servers=(
                IRCServer("irc.example.test", 6697, tls=True),
                IRCServer("irc2.example.test", 6668, tls=False),
            ),
            irc_verify_tls=False,
            jetstream_replicas=3,
            maintenance_interval=2,
            nats_monitor_port=9222,
            nats_servers=("nats://nats.internal:4222", "tls://nats2.internal:4223"),
            nats_token=NATS_CREDENTIAL,
            network="libera",
            nickname="botnick",
            presence_ttl=10,
            totp_secret=AUTH_KEY,
        )

    def test_secret_validation(self) -> None:
        """Reject a missing, malformed, too-short, or non-UTF-8 secret."""
        for variable, value, message in (
            ("BOTNATS_TOTP_SECRET", "", "BOTNATS_TOTP_SECRET is required"),
            ("BOTNATS_TOTP_SECRET", "not base32!", "valid base32"),
            ("BOTNATS_TOTP_SECRET", "GEZDGNBV", "at least 160 bits"),
            ("BOTNATS_NATS_TOKEN", "", "BOTNATS_NATS_TOKEN is required"),
            ("BOTNATS_COORDINATION_SECRET", "x" * 31, "at least 32 bytes"),
        ):
            with (
                self.subTest(variable=variable, value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                load_config(json.loads(CONFIG), **{variable: value})

        # The minimum counts encoded bytes, not characters.
        for secret in ("x" * 32, "é" * 16):
            with self.subTest(secret=secret):
                config = load_config(
                    json.loads(CONFIG),
                    BOTNATS_COORDINATION_SECRET=secret,
                )
                assert config.coordination_secret == secret.encode()

        # Bytes that are not UTF-8 reach os.environ as lone surrogates. The
        # ASCII part alone exceeds the minimum, so only the UTF-8 check can
        # reject the value, and the single surrogate is one that a chained
        # UnicodeEncodeError would quote.
        secret = "canary-" * 5 + "\udcff"
        with self.assertRaisesRegex(
            ValueError,
            "^BOTNATS_COORDINATION_SECRET must be valid UTF-8$",
        ) as raised:
            load_config(json.loads(CONFIG), BOTNATS_COORDINATION_SECRET=secret)

        rendered = "".join(traceback.format_exception(raised.exception))
        for fragment in ("canary", "udcff"):
            with self.subTest(fragment=fragment):
                assert fragment not in rendered

    def test_totp_secret_normalization(self) -> None:
        """Decode a TOTP secret written in lowercase groups split by whitespace."""
        encoded = base64.b32encode(AUTH_KEY).decode().lower()
        grouped = " ".join(encoded[i : i + 4] for i in range(0, len(encoded), 4))

        config = load_config(
            json.loads(CONFIG),
            BOTNATS_TOTP_SECRET=f"\t{grouped}\n",
        )

        assert config.totp_secret == AUTH_KEY

    def test_nickname_must_fit_registration(self) -> None:
        """Reject a nickname whose USER registration line exceeds 512 bytes."""
        with self.assertRaisesRegex(ValueError, "512 bytes"):
            nickname({"nickname": "n" * 300})

    def test_optional_settings_default(self) -> None:
        """Load defaults for omitted optional keys, IRC ports, and tables."""
        raw = json.loads(CONFIG)
        del raw["authorization"]
        del raw["coordination"]
        del raw["bot"]["health_port"]
        for key in ("channel_modes", "connect_timeout_seconds", "verify_tls"):
            del raw["irc"][key]

        for key in ("jetstream_replicas", "monitor_port"):
            del raw["nats"][key]

        raw["irc"]["servers"] = ["ircs://irc.example.test", "irc://irc2.example.test"]

        # CONFIG sets every optional key away from its default.
        assert load_config(raw) == replace(
            load_config(json.loads(CONFIG)),
            auth_session_ttl=3600,
            channel_modes="",
            enforced_modes=(frozenset(), frozenset()),
            health_port=8080,
            irc_connect_timeout=30,
            # Each scheme defaults to its own port.
            irc_servers=(
                IRCServer("irc.example.test", 6697, tls=True),
                IRCServer("irc2.example.test", 6667, tls=False),
            ),
            irc_verify_tls=True,
            jetstream_replicas=1,
            maintenance_interval=3,
            nats_monitor_port=8222,
            presence_ttl=15,
        )

    def test_durations_must_be_numbers(self) -> None:
        """Reject a timeout or interval written as a string or a boolean."""
        durations = (
            ("authorization", "session_ttl_seconds"),
            ("coordination", "maintenance_interval_seconds"),
            ("coordination", "presence_ttl_seconds"),
            ("irc", "connect_timeout_seconds"),
        )
        for section, key in durations:
            # Each would read as a valid duration if converted to float.
            for value in ("30", True):
                raw = json.loads(CONFIG)
                raw[section][key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaisesRegex(
                        TypeError,
                        rf"^{section}\.{key} must be a positive number$",
                    ),
                ):
                    load_config(raw)

    def test_session_ttl_has_no_maximum(self) -> None:
        """Accept a session lifetime longer than a day."""
        raw = json.loads(CONFIG)
        raw["authorization"]["session_ttl_seconds"] = 172800

        config = load_config(raw)

        assert config.auth_session_ttl == 172800

    def test_session_ttl_must_expire(self) -> None:
        """Reject a session lifetime of zero or less: sessions always expire."""
        for ttl in (0, -1):
            raw = json.loads(CONFIG)
            raw["authorization"]["session_ttl_seconds"] = ttl
            with (
                self.subTest(ttl=ttl),
                self.assertRaisesRegex(
                    ValueError,
                    r"authorization\.session_ttl_seconds must be a positive",
                ),
            ):
                load_config(raw)

    def test_required_key_errors_name_their_section(self) -> None:
        """Qualify required-key errors with their configuration table."""
        cases = (
            ("bot", r"bot\.id must be a non-empty string"),
            ("irc", r"irc\.servers must be a list of non-empty strings"),
            ("nats", r"nats\.servers must be a list of non-empty strings"),
        )
        for section, message in cases:
            raw = json.loads(CONFIG)
            del raw[section]
            with (
                self.subTest(section=section),
                self.assertRaisesRegex(ValueError, message),
            ):
                load_config(raw)

    def test_invalid_value_errors_name_their_section(self) -> None:
        """Qualify invalid-value errors with their configuration table."""
        cases = (
            ("bot", "id", "botnats.1", r"bot\.id contains unsupported characters"),
            (
                "bot",
                "network",
                "libera*",
                r"bot\.network contains unsupported characters",
            ),
            ("bot", "nickname", "1bad", r"bot\.nickname is not a valid IRC nickname"),
            ("bot", "health_port", 0, r"bot\.health_port must be an integer"),
            ("irc", "verify_tls", "yes", r"irc\.verify_tls must be a boolean"),
            ("irc", "channel_modes", 1, r"irc\.channel_modes must be a string"),
            (
                "coordination",
                "presence_ttl_seconds",
                -1,
                r"coordination\.presence_ttl_seconds must be a positive number",
            ),
            (
                "nats",
                "jetstream_replicas",
                9,
                r"nats\.jetstream_replicas must be an integer",
            ),
        )
        for section, key, value, message in cases:
            raw = json.loads(CONFIG)
            raw[section][key] = value
            with (
                self.subTest(key=key),
                self.assertRaisesRegex((TypeError, ValueError), message),
            ):
                load_config(raw)

    def test_non_table_section_is_rejected(self) -> None:
        """Reject a section that is present but not an object."""
        raw = json.loads(CONFIG)
        raw["authorization"] = []
        with self.assertRaisesRegex(TypeError, "authorization must be a JSON object"):
            load_config(raw)

    def test_config_requires_object(self) -> None:
        """Verify a non-object JSON document produces a clear config error."""
        with self.assertRaisesRegex(TypeError, "configuration must be an object"):
            load_config([])

    def test_channel_modes_intent(self) -> None:
        """Return the mode string with the modes it requires and forbids."""
        assert mode_string({"channel_modes": "-s+nt"}) == (
            "-s+nt",
            (frozenset("nt"), frozenset("s")),
        )

    def test_channel_modes_reject_contradictions(self) -> None:
        """Reject modes configured as both required and forbidden."""
        with self.assertRaisesRegex(
            ValueError,
            r"^irc\.channel_modes cannot require and forbid the same mode$",
        ):
            mode_string({"channel_modes": "+n-n"})

    def test_channel_modes_reject_oversized_message(self) -> None:
        """Reject channel modes that cannot fit in an IRC MODE command."""
        with self.assertRaisesRegex(ValueError, "512 bytes"):
            mode_string({"channel_modes": "+" + "n" * 510})

    def test_channel_modes_reject_unusable_syntax(self) -> None:
        """Reject unsigned, empty, and argument-consuming channel modes."""
        for value, message in (
            ("nt", "contains unsupported characters"),
            ("+", "contains unsupported characters"),
            ("+k", "contains a mode that requires an argument"),
            ("-b", "contains a mode that requires an argument"),
            ("+o", "contains a mode that requires an argument"),
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                mode_string({"channel_modes": value})

    def test_port_validation(self) -> None:
        """Verify monitoring ports default and stay in the TCP port range."""
        assert port({}, "monitor_port", "nats", 8222) == 8222
        for bad in (True, 0, 65536, 8222.0, "8222"):
            with self.assertRaisesRegex(ValueError, "integer between 1 and 65535"):
                port({"monitor_port": bad}, "monitor_port", "nats", 8222)

    def test_positive_float_rejects_non_finite(self) -> None:
        """Verify positive_float rejects NaN, infinities, and non-positive values."""
        for bad in (
            float("nan"),
            float("inf"),
            float("-inf"),
            10**400,
            0,
            -1,
        ):
            with self.assertRaisesRegex(ValueError, "positive number"):
                positive_float({"value": bad}, "value", "test", 1.0)

        assert positive_float({}, "value", "test", 2.5) == 2.5

    def test_presence_ttl_exceeds_maintenance_interval(self) -> None:
        """Reject presence expiry that is no longer than its heartbeat interval."""
        # Each expiry exceeds the default interval, so only the configured
        # interval can reject it.
        for ttl in (10, 20):
            raw = json.loads(CONFIG)
            raw["coordination"] = {
                "maintenance_interval_seconds": 20,
                "presence_ttl_seconds": ttl,
            }
            with (
                self.subTest(ttl=ttl),
                self.assertRaisesRegex(ValueError, "presence_ttl_seconds must exceed"),
            ):
                load_config(raw)

    def test_replica_count_validation(self) -> None:
        """Verify JetStream replicas default to one and stay in range."""
        assert replica_count({}) == 1
        for bad in (True, 0, 6, 1.0, "3"):
            with self.assertRaisesRegex(ValueError, "integer between 1 and 5"):
                replica_count({"jetstream_replicas": bad})

    def test_server_url_validation(self) -> None:
        """Verify IRC and NATS URLs reject unsupported components and ports."""
        invalid_nats = (
            "http://host:4222",
            "irc://host:4222",
            "nats://host:4222?name=x",
            "nats://host:4222#x",
            "nats://host:",
            "nats://host:bad",
            "nats://host:0",
            "nats://host:70000",
            "nats://host/stream",
            f"nats://{NATS_CREDENTIAL}@host:4222",
            "nats://ho\x1bst:4222",
            "nats://" + chr(0xD800) + ":4222",
        )
        invalid_irc = (
            "nats://host:6667",
            "irc://host:6667?name=x",
            "ircs://host:6697#x",
            "irc://host:",
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
                assert NATS_CREDENTIAL not in str(raised.exception)

        for value in invalid_irc:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "invalid IRC server URL",
                ) as raised:
                    IRCServer.parse(value)

                assert value not in str(raised.exception)

    def test_server_lists_must_hold_urls(self) -> None:
        """Reject an empty server list or one with a non-string or empty entry."""
        for section in ("irc", "nats"):
            for servers, message in (
                ([], "must not be empty"),
                ([1], "must be a list of non-empty strings"),
                ([""], "must be a list of non-empty strings"),
            ):
                raw = json.loads(CONFIG)
                raw[section]["servers"] = servers
                with (
                    self.subTest(section=section, servers=servers),
                    self.assertRaisesRegex(
                        ValueError,
                        rf"^{section}\.servers {message}$",
                    ),
                ):
                    load_config(raw)

    def test_unknown_keys(self) -> None:
        """Verify configuration typos fail instead of selecting defaults."""
        nested = json.loads(CONFIG)
        nested["nats"]["jetsteam_replicas"] = 3
        top = json.loads(CONFIG)
        top["coordinaton"] = top.pop("coordination")
        for raw, message in (
            (nested, r"unsupported nats configuration key\(s\): jetsteam_replicas$"),
            (top, r"unsupported root configuration key\(s\): coordinaton$"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                load_config(raw)
