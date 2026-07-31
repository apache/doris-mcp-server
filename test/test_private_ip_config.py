"""Offline tests for configured node-IP addresses and startup wiring."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import main as app_main  # noqa: E402
import server  # noqa: E402
from config.loader import McpConfig  # noqa: E402


class McpConfigPrivateIpTests(unittest.TestCase):
    def test_documented_private_ip_is_read_and_stripped(self) -> None:
        config = McpConfig({"server": {"privateIp": "  10.23.45.67\t"}})
        self.assertEqual(config.private_ip, "10.23.45.67")

    def test_missing_empty_and_null_private_ip_become_empty_string(self) -> None:
        for value in (None, ""):
            with self.subTest(value=value):
                self.assertEqual(McpConfig({"server": {"privateIp": value}}).private_ip, "")
        self.assertEqual(McpConfig({"server": {}}).private_ip, "")

    def test_legacy_private_ip_is_supported_but_documented_key_wins(self) -> None:
        self.assertEqual(
            McpConfig({"server": {"private_ip": " 172.16.1.2 "}}).private_ip,
            "172.16.1.2",
        )
        self.assertEqual(
            McpConfig({"server": {"privateIp": "10.0.0.1", "private_ip": "192.168.1.1"}}).private_ip,
            "10.0.0.1",
        )

    def test_non_string_private_ip_is_rejected(self) -> None:
        for value in (123, True, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    McpConfig({"server": {"privateIp": value}})


class ResolveMachineIpTests(unittest.TestCase):
    def test_configured_rfc1918_ranges_are_normalized_without_detection(self) -> None:
        cases = {
            " 10.23.45.67 ": "10.23.45.67",
            "172.16.0.1": "172.16.0.1",
            "192.168.255.254": "192.168.255.254",
        }
        for configured, expected in cases.items():
            with self.subTest(configured=configured), patch.object(server, "get_machine_ip") as detected:
                self.assertEqual(server.resolve_machine_ip(configured), expected)
                detected.assert_not_called()

    def test_configured_non_rfc1918_ipv4_is_accepted_without_detection(self) -> None:
        # Public / loopback / link-local IPv4 are usable (with a warning) —
        # startup must not require a private address.
        for configured in ("8.8.8.8", "127.0.0.1", "169.254.1.1"):
            with self.subTest(configured=configured), patch.object(server, "get_machine_ip") as detected:
                self.assertEqual(server.resolve_machine_ip(configured), configured)
                detected.assert_not_called()

    def test_blank_configurations_detect_an_rfc1918_address(self) -> None:
        for configured in ("", " \t\n ", None):
            with self.subTest(configured=configured), patch.object(server, "get_machine_ip", return_value="10.9.8.7") as detected:
                self.assertEqual(server.resolve_machine_ip(configured), "10.9.8.7")
                detected.assert_called_once_with()

    def test_invalid_configurations_are_rejected_without_detection(self) -> None:
        invalid = ("not-an-ip", "2001:db8::1")
        for configured in invalid:
            with self.subTest(configured=configured), patch.object(server, "get_machine_ip") as detected:
                with self.assertRaises(ValueError):
                    server.resolve_machine_ip(configured)
                detected.assert_not_called()

    def test_detected_public_ipv4_is_accepted(self) -> None:
        with patch.object(server, "get_machine_ip", return_value="8.8.8.8") as detected:
            self.assertEqual(server.resolve_machine_ip(""), "8.8.8.8")
            detected.assert_called_once_with()

    def test_failed_or_garbage_detection_falls_back_to_loopback(self) -> None:
        for detected_ip in (None, "not-an-ip", "2001:db8::1"):
            with self.subTest(detected_ip=detected_ip), patch.object(server, "get_machine_ip", return_value=detected_ip) as detected:
                self.assertEqual(server.resolve_machine_ip(""), "127.0.0.1")
                detected.assert_called_once_with()


class MainPrivateIpFlowTests(unittest.TestCase):
    def test_main_resolves_cfg_mcp_private_ip_and_passes_config_to_server(self) -> None:
        cfg = SimpleNamespace(mcp=SimpleNamespace(private_ip="10.20.30.40", host="127.0.0.1", port=3000))
        mcp = MagicMock()
        with (
            patch.object(app_main, "AppConfig", return_value=cfg),
            patch.object(app_main, "resolve_machine_ip", return_value="10.20.30.40") as resolve,
            patch.object(app_main, "create_server", return_value=mcp) as create,
            patch.object(sys, "argv", ["main.py", "--config-dir", "/offline-config"]),
        ):
            app_main.main()

        # Node identity resolved once from the configured privateIp; the
        # already-parsed config is handed to create_server (no second parse).
        resolve.assert_called_once_with(cfg.mcp.private_ip)
        create.assert_called_once_with(
            config_dir="/offline-config", env_file=None,
            machine_ip="10.20.30.40", config=cfg,
        )
        mcp.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
