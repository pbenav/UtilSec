"""Tests for the attack detector, focused on rate-limit window bookkeeping."""

import os
import tempfile
import time
import unittest
import ipaddress

from core.config import ConfigManager
from core.detector import AttackDetector, HISTORY_MAX_TRACKED_IPS, HISTORY_SWEEP_INTERVAL


class TestRateLimitEviction(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 2,
                "threshold_403": 1,
                "window_seconds": 60,
                "whitelist": ["127.0.0.1", "::1"],
                "user_patterns": []
            }""")
        self.config = ConfigManager(self.config_path)
        self.detector = AttackDetector(self.config)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_aged_out_ips_are_evicted(self):
        now = time.time()
        self.detector.ip_404_history["1.2.3.4"].extend([now - 600, now - 500])
        self.detector.ip_404_history["5.6.7.8"].append(now)
        self.detector.ip_403_history["9.9.9.9"].extend([now - 600])
        # Left empty by a ban that already fired
        self.detector.ip_403_history["10.0.0.1"]

        self.detector._sweep_histories(now)

        self.assertNotIn("1.2.3.4", self.detector.ip_404_history)
        self.assertNotIn("9.9.9.9", self.detector.ip_403_history)
        self.assertNotIn("10.0.0.1", self.detector.ip_403_history)
        self.assertIn("5.6.7.8", self.detector.ip_404_history)

    def test_tracked_ip_count_is_capped(self):
        now = time.time()
        limit = HISTORY_MAX_TRACKED_IPS
        # Distinct, still-in-window IPs: oldest activity first so the survivor
        # is predictable once the cap kicks in.
        keys = []
        for i in range(limit + 10):
            key = str(ipaddress.ip_address(i + 1))
            keys.append(key)
            self.detector.ip_404_history[key].append(now - 55 + i * 0.0005)

        self.detector._sweep_histories(now)

        self.assertLessEqual(len(self.detector.ip_404_history), limit)
        self.assertIn(keys[-1], self.detector.ip_404_history)
        self.assertNotIn(keys[0], self.detector.ip_404_history)

    def test_sweep_runs_from_the_request_path_but_not_every_request(self):
        self.detector._last_history_sweep = time.time() - HISTORY_SWEEP_INTERVAL - 1
        self.detector.ip_404_history["1.2.3.4"].append(time.time() - 600)

        self.detector.analyze_request("5.6.7.8", "GET", "/index.html", 200)

        self.assertGreater(self.detector._last_history_sweep, time.time() - 5)
        self.assertNotIn("1.2.3.4", self.detector.ip_404_history)

        # Back-to-back requests must not rescan every tracked IP
        before = self.detector._last_history_sweep
        self.detector.analyze_request("5.6.7.8", "GET", "/index.html", 200)
        self.assertEqual(self.detector._last_history_sweep, before)

    def test_404_window_still_triggers_after_eviction(self):
        event, should_ban, reason = self.detector.analyze_request(
            "203.0.113.5", "GET", "/missing", 404)
        self.assertIsNotNone(event)
        self.assertFalse(should_ban)

        event, should_ban, reason = self.detector.analyze_request(
            "203.0.113.5", "GET", "/missing2", 404)
        self.assertTrue(should_ban)
        # Window was cleared, so the counter starts fresh
        self.assertEqual(len(self.detector.ip_404_history["203.0.113.5"]), 0)


if __name__ == "__main__":
    unittest.main()
