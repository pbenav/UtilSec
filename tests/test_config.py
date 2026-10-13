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

    def test_add_and_remove_whitelist(self):
        # Adding a valid new IP
        self.assertTrue(self.config.add_whitelist("192.168.1.50", persist=True))
        self.assertTrue(self.config.is_ip_whitelisted("192.168.1.50"))
        # Verify persistence on disk
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertIn("192.168.1.50", data["whitelist"])

        # Duplicate addition returns False
        self.assertFalse(self.config.add_whitelist("192.168.1.50", persist=True))

        # Invalid IP returns False
        self.assertFalse(self.config.add_whitelist("not_an_ip; rm -rf /", persist=True))

        # Removing whitelist entry
        self.assertTrue(self.config.remove_whitelist("192.168.1.50", persist=True))
        self.assertFalse(self.config.is_ip_whitelisted("192.168.1.50"))
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertNotIn("192.168.1.50", data["whitelist"])

    def test_update_setting(self):
        # Valid integer setting
        self.assertTrue(self.config.update_setting("threshold_404", 5, persist=True))
        self.assertEqual(self.config.threshold_404, 5)
        with open(self.config_path, "r", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["threshold_404"], 5)

        # Invalid integer setting (e.g. <= 0)
        self.assertFalse(self.config.update_setting("threshold_404", 0, persist=True))
        self.assertEqual(self.config.threshold_404, 5)

        # Boolean setting toggle
        self.assertTrue(self.config.update_setting("ban_subnet", False, persist=True))
        self.assertFalse(self.config.ban_subnet)

    def test_check_and_reload_if_modified(self):
        import time

        # No change
        self.assertFalse(self.config.check_and_reload_if_modified())

        # Internal save should not trigger reload
        self.config.save()
        self.assertFalse(self.config.check_and_reload_if_modified())

        # Simulate external modification with valid JSON
        time.sleep(0.05)
        with open(self.config_path, "r", encoding="utf-8") as f:
            cur_data = json.load(f)
        cur_data["threshold_404"] = 99
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cur_data, f)
        # Force mtime update ahead
        os.utime(self.config_path, (time.time() + 10, time.time() + 10))

        # Check and reload detects change
        self.assertTrue(self.config.check_and_reload_if_modified())
        self.assertEqual(self.config.threshold_404, 99)

        # Simulate external edit with malformed/incomplete JSON (e.g. mid-write in nano)
        time.sleep(0.05)
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("{ incomplete json: ")
        os.utime(self.config_path, (time.time() + 20, time.time() + 20))

        # Malformed JSON should be ignored and retain current in-memory config
        self.assertFalse(self.config.check_and_reload_if_modified())
        self.assertEqual(self.config.threshold_404, 99)


if __name__ == "__main__":
    unittest.main()
