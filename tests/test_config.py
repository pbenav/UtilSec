"""Tests for ConfigManager: input validation, ban targets and safe persistence."""

import json
import os
import tempfile
import unittest

from core.config import ConfigManager, parse_ip_or_network

VALID_CONFIG = """{
    "log_file": "test.log",
    "firewall_backend": "dummy",
    "dry_run": true,
    "default_ban_duration": 10,
    "threshold_404": 2,
    "threshold_403": 1,
    "window_seconds": 60,
    "whitelist": ["127.0.0.1", "::1", "10.0.0.0/8"],
    "user_patterns": []
}"""


class TestParseIpOrNetwork(unittest.TestCase):

    def test_accepts_addresses_and_cidr(self):
        self.assertEqual(parse_ip_or_network("1.2.3.4"), "1.2.3.4")
        self.assertEqual(parse_ip_or_network(" 1.2.3.4 "), "1.2.3.4")
        self.assertEqual(parse_ip_or_network("1.2.3.7/24"), "1.2.3.0/24")
        self.assertEqual(parse_ip_or_network("2001:db8::1"), "2001:db8::1")
        self.assertEqual(parse_ip_or_network("2001:db8::1/64"), "2001:db8::/64")

    def test_rejects_injection_payloads(self):
        payloads = [
            "1.2.3.4; rm -rf /",
            "1.2.3.4 && reboot",
            "1.2.3.4$(whoami)",
            "1.2.3.4`id`",
            "1.2.3.4\niptables -F",
            "1.2.3.4 -o /etc/passwd",
            "",
            "   ",
            "not-an-ip",
            None,
            42,
            ["1.2.3.4"],
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(parse_ip_or_network(payload))


class TestConfigPersistence(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(VALID_CONFIG)
        os.chmod(self.config_path, 0o640)
        self.config = ConfigManager(self.config_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_get_ban_target_returns_empty_string_for_invalid_input(self):
        self.assertEqual(self.config.get_ban_target("1.2.3.4; rm -rf /"), "")
        self.assertEqual(self.config.get_ban_target("<script>"), "")
        self.assertEqual(self.config.get_ban_target(""), "")

    def test_get_ban_target_builds_subnet(self):
        self.assertEqual(self.config.get_ban_target("1.2.3.4"), "1.2.3.0/24")
        self.assertEqual(self.config.get_ban_target("1.2.3.0/24"), "1.2.3.0/24")

    def test_get_ban_target_never_returns_a_whitelisted_range(self):
        # 10.0.0.0/8 is whitelisted in the test config
        self.assertEqual(self.config.get_ban_target("10.9.9.9"), "10.9.9.9")

    def test_save_is_atomic_and_leaves_no_temp_files(self):
        self.config.raw_config["threshold_404"] = 7
        self.config.save()

        with open(self.config_path, "r", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["threshold_404"], 7)

        leftovers = [n for n in os.listdir(self.tmp_dir.name) if n != "config.json"]
        self.assertEqual(leftovers, [])

    def test_save_preserves_file_mode(self):
        self.config.raw_config["threshold_404"] = 9
        self.config.save()
        self.assertEqual(os.stat(self.config_path).st_mode & 0o777, 0o640)

    @staticmethod
    def _read(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def test_save_reports_failure_without_clobbering_the_file(self):
        before = self._read(self.config_path)
        original_dump = json.dump

        def boom(*args, **kwargs):
            raise OSError("disk full")

        json.dump = boom
        try:
            self.config.save()
        finally:
            json.dump = original_dump

        self.assertEqual(self._read(self.config_path), before)
        leftovers = [n for n in os.listdir(self.tmp_dir.name) if n != "config.json"]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
