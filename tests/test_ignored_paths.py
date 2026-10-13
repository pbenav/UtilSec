"""Tests for ignored_paths support in ConfigManager and AttackDetector."""

import json
import os
import tempfile
import unittest

from core.config import ConfigManager
from core.detector import AttackDetector


class TestIgnoredPathsConfig(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump({
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": True,
                "default_ban_duration": 10,
                "threshold_404": 2,
                "threshold_403": 1,
                "window_seconds": 60,
                "whitelist": ["127.0.0.1"],
                "ignored_paths": [
                    "/ocs/v2.php/",
                    "/remote.php/",
                    "/index.php/core/preview"
                ]
            }, f)
        self.config = ConfigManager(self.config_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_loads_ignored_paths(self):
        self.assertEqual(len(self.config.ignored_paths), 3)
        self.assertIn("/ocs/v2.php/", self.config.ignored_paths)
        self.assertIn("/remote.php/", self.config.ignored_paths)
        self.assertIn("/index.php/core/preview", self.config.ignored_paths)

    def test_is_path_ignored(self):
        # Case insensitive substring matching
        self.assertTrue(self.config.is_path_ignored("/ocs/v2.php/apps/notifications/api/v2/notifications"))
        self.assertTrue(self.config.is_path_ignored("/OCS/V2.PHP/apps/notifications"))
        self.assertTrue(self.config.is_path_ignored("/remote.php/dav/files/pablo/"))
        self.assertTrue(self.config.is_path_ignored("/index.php/core/preview?fileId=123"))

        # Unrelated paths
        self.assertFalse(self.config.is_path_ignored("/admin.php"))
        self.assertFalse(self.config.is_path_ignored("/login"))
        self.assertFalse(self.config.is_path_ignored(""))

    def test_add_and_remove_ignored_path_with_persistence(self):
        self.assertTrue(self.config.add_ignored_path("/api/v1/health", persist=True))
        self.assertIn("/api/v1/health", self.config.ignored_paths)

        # Reload from disk
        reloaded = ConfigManager(self.config_path)
        self.assertIn("/api/v1/health", reloaded.ignored_paths)

        # Remove
        self.assertTrue(self.config.remove_ignored_path("/api/v1/health", persist=True))
        self.assertNotIn("/api/v1/health", self.config.ignored_paths)

        # Reload from disk
        reloaded2 = ConfigManager(self.config_path)
        self.assertNotIn("/api/v1/health", reloaded2.ignored_paths)


class TestIgnoredPathsDetection(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump({
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": True,
                "default_ban_duration": 10,
                "threshold_404": 2,
                "threshold_403": 1,
                "window_seconds": 60,
                "whitelist": ["127.0.0.1"],
                "ignored_paths": [
                    "/ocs/v2.php/",
                    "/remote.php/",
                    "/index.php/core/preview"
                ],
                "heuristic_rules": [
                    {
                        "id": "env_leaks",
                        "name": "Environment / Config Leaks",
                        "pattern": "\\.env",
                        "is_regex": True,
                        "critical": True,
                        "category": "credentials"
                    }
                ]
            }, f)
        self.config = ConfigManager(self.config_path)
        self.detector = AttackDetector(self.config)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_404_on_ignored_path_does_not_ban(self):
        ip = "90.167.31.189"
        # 10 consecutive 404s on ignored Nextcloud notification path
        for i in range(10):
            event, should_ban, reason = self.detector.analyze_request(
                ip=ip,
                method="GET",
                url="/ocs/v2.php/apps/notifications/api/v2/notifications?format=json",
                status_code=404,
                raw_line=f"GET /ocs/v2.php/apps/notifications/api/v2/notifications?format=json HTTP/1.1 404",
            )
            self.assertIsNone(event, f"Hit {i} should be ignored")
            self.assertFalse(should_ban, f"Hit {i} should not trigger a ban")

        # History should remain completely empty for this IP
        self.assertEqual(len(self.detector.ip_404_history[ip]), 0)

    def test_403_on_ignored_path_does_not_ban(self):
        ip = "90.167.31.189"
        event, should_ban, reason = self.detector.analyze_request(
            ip=ip,
            method="GET",
            url="/remote.php/dav/files/pablo/private.txt",
            status_code=403,
            raw_line="GET /remote.php/dav/files/pablo/private.txt HTTP/1.1 403",
        )
        self.assertIsNone(event)
        self.assertFalse(should_ban)
        self.assertEqual(len(self.detector.ip_403_history[ip]), 0)

    def test_banned_host_activity_not_triggered_for_ignored_path(self):
        ip = "90.167.31.189"
        # Host is currently banned (is_banned=True) and Nextcloud returns 500 on WebDAV
        event, should_ban, reason = self.detector.analyze_request(
            ip=ip,
            method="PROPFIND",
            url="/remote.php/dav/files/pablo/",
            status_code=500,
            raw_line="PROPFIND /remote.php/dav/files/pablo/ HTTP/1.1 500",
            is_banned=True,
        )
        self.assertIsNone(event)
        self.assertFalse(should_ban)

    def test_exploit_rule_still_detected_even_on_ignored_path(self):
        ip = "90.167.31.189"
        # Attack trying to probe .env through an ignored path prefix
        event, should_ban, reason = self.detector.analyze_request(
            ip=ip,
            method="GET",
            url="/remote.php/.env",
            status_code=404,
            raw_line="GET /remote.php/.env HTTP/1.1 404",
        )
        self.assertIsNotNone(event)
        self.assertTrue(should_ban)
        self.assertIn("Environment / Config Leaks", reason)


if __name__ == "__main__":
    unittest.main()

