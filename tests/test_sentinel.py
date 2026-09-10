"""Unit tests for UtilSec Sentinel."""

import os
import tempfile
import time
import unittest

from core.config import ConfigManager
from core.detector import AttackDetector
from core.firewall import FirewallManager
from core.models import AttackEvent, BanRecord, Rule
from core.storage import StorageManager
from core.watcher import LogWatcher


class TestSentinelCore(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "test_config.json")
        self.db_path = os.path.join(self.tmp_dir.name, "test_history.db")

        # Create basic test config
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 3,
                "window_seconds": 5,
                "whitelist": ["127.0.0.1", "192.168.1.0/24"],
                "user_patterns": ["/blocked-test-url"],
                "heuristic_rules": [
                    {
                        "id": "env_test",
                        "name": "Env Test",
                        "pattern": "\\\\.env",
                        "is_regex": true,
                        "critical": true,
                        "category": "credentials"
                    }
                ]
            }""")

        self.config = ConfigManager(self.config_path)
        self.storage = StorageManager(self.db_path)
        self.firewall = FirewallManager(dry_run=True, storage=self.storage)
        self.detector = AttackDetector(self.config)

    def tearDown(self):
        self.firewall.stop()
        self.tmp_dir.cleanup()

    def test_whitelist(self):
        self.assertTrue(self.config.is_ip_whitelisted("127.0.0.1"))
        self.assertTrue(self.config.is_ip_whitelisted("192.168.1.55"))
        self.assertFalse(self.config.is_ip_whitelisted("45.156.128.112"))

    def test_detector_critical_pattern(self):
        # Whitelisted IP hitting .env should be ignored
        event, should_ban, reason = self.detector.analyze_request(
            ip="127.0.0.1", method="GET", url="/.env", status_code=404
        )
        self.assertIsNone(event)
        self.assertFalse(should_ban)

        # Attacker IP hitting .env should trigger instant ban
        event, should_ban, reason = self.detector.analyze_request(
            ip="149.118.48.45", method="GET", url="/.env", status_code=404
        )
        self.assertIsNotNone(event)
        self.assertTrue(should_ban)
        self.assertIn("Env Test", reason)

    def test_detector_user_pattern(self):
        # Attacker hitting custom pattern
        event, should_ban, reason = self.detector.analyze_request(
            ip="20.48.147.90", method="GET", url="/blocked-test-url", status_code=404
        )
        self.assertIsNotNone(event)
        self.assertTrue(should_ban)
        self.assertIn("User Pattern", reason)

    def test_detector_rate_limiting(self):
        ip = "185.220.101.5"
        # 1st generic 404
        ev1, ban1, _ = self.detector.analyze_request(ip, "GET", "/page1.html", 404)
        self.assertFalse(ban1)

        # 2nd generic 404
        ev2, ban2, _ = self.detector.analyze_request(ip, "GET", "/page2.html", 404)
        self.assertFalse(ban2)

        # 3rd generic 404 -> triggers threshold (threshold_404 = 3)
        ev3, ban3, reason = self.detector.analyze_request(ip, "GET", "/page3.html", 404)
        self.assertTrue(ban3)
        self.assertIn("Exceeded 404 limit", reason)

    def test_firewall_ban_and_unban(self):
        ip = "89.187.169.100"
        self.firewall.ban_ip(
            ip=ip,
            reason="Test Attack",
            matched_pattern="/test",
            duration=3600,
            last_url="/test",
        )
        subnet = "89.187.169.0/24"
        self.assertIn(subnet, self.firewall.active_bans)
        self.assertEqual(self.firewall.active_bans[subnet].status, "SIMULATED")

        # Repeat attack should renew banned_at timestamp and increase attack count
        t1 = self.firewall.active_bans[subnet].banned_at
        time.sleep(0.01)
        self.firewall.ban_ip(ip=ip, reason="Repeat Attack", matched_pattern="/test2", duration=3600)
        self.assertEqual(self.firewall.active_bans[subnet].attack_count, 2)
        self.assertGreater(self.firewall.active_bans[subnet].banned_at, t1)

        # Test unban using original IP (should automatically resolve to subnet)
        unbanned = self.firewall.unban_ip(ip, manual=True)
        self.assertTrue(unbanned)
        self.assertNotIn(subnet, self.firewall.active_bans)

    def test_subnet_banning(self):
        # Calculate /24 subnet target
        target = self.config.get_ban_target("149.118.48.45")
        self.assertEqual(target, "149.118.48.0/24")

        # Ban the /24 subnet
        self.firewall.ban_ip(
            ip=target,
            reason="Subnet Test Attack",
            matched_pattern="/.env",
            duration=3600,
        )
        self.assertIn("149.118.48.0/24", self.firewall.active_bans)

        # Other IP in the same /24 should be recognized as banned!
        banned_rec = self.firewall.is_ip_banned("149.118.48.99")
        self.assertIsNotNone(banned_rec)
        self.assertEqual(banned_rec.ip, "149.118.48.0/24")

        # IP in different subnet should NOT be banned
        self.assertIsNone(self.firewall.is_ip_banned("149.118.49.1"))

        # Whitelist protection: local subnet should not ban whitelisted IP
        target_local = self.config.get_ban_target("127.0.0.1")
        self.assertEqual(target_local, "127.0.0.1")  # falls back to IP to protect whitelist

    def test_watcher_parsing(self):
        watcher = LogWatcher(
            log_path="dummy.log",
            on_request=lambda *args: None,
        )

        # Access log line
        line1 = '149.118.48.45 - - [30/Aug/2026:00:42:40 +0200] "GET /.env HTTP/2.0" 404 61501 "-" "Mozilla/5.0"'
        p1 = watcher.parse_line(line1)
        self.assertIsNotNone(p1)
        ip, method, url, status = p1
        self.assertEqual(ip, "149.118.48.45")
        self.assertEqual(method, "GET")
        self.assertEqual(url, "/.env")
        self.assertEqual(status, 404)

        # Error log line
        line2 = "[Thu Sep 10 16:13:38.360021 2026] [proxy_fcgi:error] [pid 627195:tid 627298] [client 31.223.2.90:64204] AH01071: Got error 'Primary script unknown'"
        p2 = watcher.parse_line(line2)
        self.assertIsNotNone(p2)
        ip, method, url, status = p2
        self.assertEqual(ip, "31.223.2.90")
        self.assertEqual(method, "ERR")
        self.assertIn("Primary script unknown", url)
        self.assertEqual(status, 404)

        # Dirty line with null bytes
        line3 = "\x00\x0092.187.27.165 - - [30/Aug/2026:00:02:00 +0200] \"POST /wp-cron.php HTTP/1.1\" 200 5732 \"-\" \"WordPress\""
        p3 = watcher.parse_line(line3)
        self.assertIsNotNone(p3)
        self.assertEqual(p3[0], "92.187.27.165")


if __name__ == "__main__":
    unittest.main()

