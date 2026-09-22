"""Unit tests for UtilSec Sentinel."""

import ipaddress
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

    def test_multi_log_config(self):
        cfg_file = os.path.join(self.tmp_dir.name, "multi_cfg.json")
        with open(cfg_file, "w", encoding="utf-8") as f:
            f.write("""{
                "log_files": [
                    {"name": "site_access", "path": "/var/log/access.log"},
                    {"name": "site_error", "path": "/var/log/error.log"}
                ]
            }""")
        cfg = ConfigManager(cfg_file)
        self.assertEqual(len(cfg.log_files), 2)
        self.assertEqual(cfg.log_files[0]["name"], "site_access")
        self.assertEqual(cfg.log_files[1]["name"], "site_error")

        # Test add_log_file
        cfg.add_log_file("site_ssl", "/var/log/ssl.log", persist=True)
        self.assertEqual(len(cfg.log_files), 3)

        # Reload from disk to verify persistence
        cfg_reloaded = ConfigManager(cfg_file)
        self.assertEqual(len(cfg_reloaded.log_files), 3)
        self.assertEqual(cfg_reloaded.log_files[2]["name"], "site_ssl")

        # Test remove_log_file
        removed = cfg_reloaded.remove_log_file("site_error", persist=True)
        self.assertTrue(removed)
        self.assertEqual(len(cfg_reloaded.log_files), 2)

    def test_storage_source_log_filtering(self):
        ev1 = AttackEvent(
            ip="100.1.1.1", method="GET", url="/.env", status_code=404,
            matched_rule="Env Test", category="credentials", source_log="siteA"
        )
        ev2 = AttackEvent(
            ip="100.1.1.2", method="GET", url="/shell.php", status_code=404,
            matched_rule="WebShell", category="webshell", source_log="siteB"
        )
        self.storage.log_event(ev1)
        self.storage.log_event(ev2)

        # Load all
        all_events = self.storage.load_recent_events(limit=10)
        self.assertEqual(len(all_events), 2)

        # Load filtered by siteA
        siteA_events = self.storage.load_recent_events(limit=10, source_log="siteA")
        self.assertEqual(len(siteA_events), 1)
        self.assertEqual(siteA_events[0].ip, "100.1.1.1")
        self.assertEqual(siteA_events[0].source_log, "siteA")

        # Load filtered by siteB
        siteB_events = self.storage.load_recent_events(limit=10, source_log="siteB")
        self.assertEqual(len(siteB_events), 1)
        self.assertEqual(siteB_events[0].ip, "100.1.1.2")
        self.assertEqual(siteB_events[0].source_log, "siteB")

    def test_log_watcher_manager(self):
        from core.watcher import LogWatcherManager
        log1 = os.path.join(self.tmp_dir.name, "log1.log")
        log2 = os.path.join(self.tmp_dir.name, "log2.log")

        with open(log1, "w", encoding="utf-8") as f:
            f.write("")
        with open(log2, "w", encoding="utf-8") as f:
            f.write("")

        received = []

        def on_req(ip, method, url, status, raw_line, source_log="default"):
            received.append((ip, source_log))

        mgr = LogWatcherManager(on_request=on_req, default_replay_lines=0)
        mgr.add_watcher("log1", log1, auto_start=True)
        mgr.add_watcher("log2", log2, auto_start=True)

        time.sleep(0.1)

        # Append to log1
        with open(log1, "a", encoding="utf-8") as f:
            f.write('1.1.1.1 - - [30/Aug/2026:00:00:01 +0200] "GET /test1 HTTP/1.1" 200 100 "-" "-"\n')
        # Append to log2
        with open(log2, "a", encoding="utf-8") as f:
            f.write('2.2.2.2 - - [30/Aug/2026:00:00:02 +0200] "GET /test2 HTTP/1.1" 200 100 "-" "-"\n')

        time.sleep(0.3)
        mgr.stop_all()

        self.assertIn(("1.1.1.1", "log1"), received)
        self.assertIn(("2.2.2.2", "log2"), received)
        self.assertGreaterEqual(mgr.total_lines_processed, 2)

    def test_tui_screens_and_event_segregation(self):
        from core.watcher import LogWatcherManager
        from ui.tui import SentinelTUI

        mgr = LogWatcherManager(on_request=lambda *args: None)
        log_a = os.path.join(self.tmp_dir.name, "a.log")
        log_b = os.path.join(self.tmp_dir.name, "b.log")
        open(log_a, "w").close()
        open(log_b, "w").close()

        mgr.add_watcher("screenA", log_a, auto_start=False)
        mgr.add_watcher("screenB", log_b, auto_start=False)

        tui = SentinelTUI(
            config=self.config,
            detector=self.detector,
            firewall=self.firewall,
            watcher_manager=mgr,
            storage=self.storage,
        )

        screens = tui.get_screens()
        self.assertEqual(len(screens), 3)  # 0: GLOBAL, 1: screenA, 2: screenB
        self.assertEqual(screens[0]["name"], "GLOBAL")
        self.assertEqual(screens[1]["name"], "screenA")
        self.assertEqual(screens[2]["name"], "screenB")

        # Dispatch events
        evA = AttackEvent(
            ip="10.0.0.1", method="GET", url="/wp-admin", status_code=404,
            matched_rule="WP", category="admin", source_log="screenA"
        )
        evB = AttackEvent(
            ip="10.0.0.2", method="GET", url="/phpmyadmin", status_code=404,
            matched_rule="PMA", category="admin", source_log="screenB"
        )
        tui.add_attack_event(evA)
        tui.add_attack_event(evB)

        # Global stream has both
        self.assertEqual(len(tui.recent_attacks), 2)

        # Per screen segregated
        self.assertEqual(len(tui.screen_attacks["screenA"]), 1)
        self.assertEqual(tui.screen_attacks["screenA"][0].ip, "10.0.0.1")

        self.assertEqual(len(tui.screen_attacks["screenB"]), 1)
        self.assertEqual(tui.screen_attacks["screenB"][0].ip, "10.0.0.2")

        # Verify paths in screens
        self.assertEqual(screens[1]["path"], log_a)
        self.assertEqual(screens[2]["path"], log_b)

    def test_file_browser_scanning_and_filtering(self):
        # Create a directory structure to test browser scanning
        browser_dir = os.path.join(self.tmp_dir.name, "test_browse")
        os.makedirs(os.path.join(browser_dir, "apache2"), exist_ok=True)
        os.makedirs(os.path.join(browser_dir, "nginx"), exist_ok=True)
        with open(os.path.join(browser_dir, "access.log"), "w") as f:
            f.write("test log data\n")
        with open(os.path.join(browser_dir, "error.log"), "w") as f:
            f.write("error log data\n")

        raw_entries = os.scandir(browser_dir)
        names = [e.name for e in raw_entries]
        self.assertIn("apache2", names)
        self.assertIn("nginx", names)
        self.assertIn("access.log", names)
        self.assertIn("error.log", names)

        # Verify filter logic
        filter_str = "acc"
        filtered = [n for n in names if filter_str in n]
        self.assertEqual(filtered, ["access.log"])

    def test_firewall_toggle_dry_run(self):
        is_dry, msg = self.firewall.toggle_dry_run()
        # Non-root environment: should safely refuse or provide clear feedback
        self.assertIsInstance(is_dry, bool)
        self.assertIsInstance(msg, str)
        self.assertTrue(len(msg) > 0)

    def test_tui_about_modal_method_exists(self):
        from ui.tui import SentinelTUI
        from core.watcher import LogWatcherManager

        mgr = LogWatcherManager(on_request=lambda *args: None)
        tui = SentinelTUI(
            config=self.config,
            detector=self.detector,
            firewall=self.firewall,
            watcher_manager=mgr,
            storage=self.storage,
        )
        # Verify the about modal method exists and is callable
        self.assertTrue(hasattr(tui, "_show_about_modal"))
        self.assertTrue(callable(getattr(tui, "_show_about_modal")))

    def test_whitelist_subnet_splitting(self):
        import ipaddress
        # Config with a whitelisted IP inside a potential /24 range
        cfg_path = os.path.join(self.tmp_dir.name, "split_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 3,
                "window_seconds": 5,
                "whitelist": ["185.204.62.36"],
                "user_patterns": ["/blocked-test-url"],
                "heuristic_rules": []
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage)

        # _get_safe_subnets should exclude whitelisted IPs from ban ranges
        full_subnet = ipaddress.ip_network("185.204.62.0/24", strict=False)
        safe = fw._get_safe_subnets(full_subnet, cfg.whitelist_networks)

        # Should return subnets that don't include .36
        all_ips = set()
        for s in safe:
            all_ips.update(s)
        self.assertNotIn(ipaddress.ip_address("185.204.62.36"), all_ips)

        # The attacker IP should still be covered by some safe subnet
        attacker = ipaddress.ip_address("185.204.62.31")
        covered = any(attacker in s for s in safe)
        self.assertTrue(covered)

        # Ban should not create a ban record for the whitelisted IP
        fw.ban_ip(
            ip="185.204.62.31",
            reason="Test Split Ban",
            matched_pattern="/.env",
            duration=3600,
            config=cfg,
        )

        # The /24 itself should NOT be in active bans
        self.assertNotIn("185.204.62.0/24", fw.active_bans)

        # But some safe subnets should be present
        self.assertGreater(len(fw.active_bans), 0)

        # Whitelisted IP should not be covered by any ban
        self.assertIsNone(fw.is_ip_banned("185.204.62.36"))

        # Attacker IP should be covered
        self.assertIsNotNone(fw.is_ip_banned("185.204.62.31"))

    def test_whitelist_full_overlap_no_ban(self):
        # Config where the attacker IP is itself whitelisted
        cfg_path = os.path.join(self.tmp_dir.name, "full_overlap_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 3,
                "window_seconds": 5,
                "whitelist": ["10.0.0.50"],
                "user_patterns": ["/blocked-test-url"],
                "heuristic_rules": []
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage)

        # _get_safe_subnets with a network entirely whitelisted
        full_subnet = ipaddress.ip_network("10.0.0.0/24", strict=False)
        safe = fw._get_safe_subnets(full_subnet, cfg.whitelist_networks)

        # Only the whitelisted IP should be excluded
        all_ips = set()
        for s in safe:
            all_ips.update(s)
        self.assertNotIn(ipaddress.ip_address("10.0.0.50"), all_ips)
        # Other IPs in the /24 should be covered
        self.assertIn(ipaddress.ip_address("10.0.0.1"), all_ips)

    def test_firewall_ban_with_whitelist_config(self):
        # Config with whitelisted IP in range 192.168.1.0/24
        cfg_path = os.path.join(self.tmp_dir.name, "range_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 3,
                "window_seconds": 5,
                "whitelist": ["192.168.1.100"],
                "user_patterns": ["/blocked-test-url"],
                "heuristic_rules": []
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage)

        # Ban IP 192.168.1.50 — should split and exclude .100
        fw.ban_ip(
            ip="192.168.1.50",
            reason="Test Range Ban",
            matched_pattern="/test",
            duration=3600,
            config=cfg,
        )

        # The full /24 should NOT be banned
        self.assertNotIn("192.168.1.0/24", fw.active_bans)

        # Whitelisted IP should not be banned
        self.assertIsNone(fw.is_ip_banned("192.168.1.100"))

        # Attacker IP should be banned
        self.assertIsNotNone(fw.is_ip_banned("192.168.1.50"))

    def test_whitelist_subnet_isolation_user_scenario(self):
        """Reproduce user bug: 185.204.62.36 is whitelisted, 185.204.62.50 attacks.
        185.204.62.36 must NEVER be blocked even if ban_subnet is True and ban_ip
        is called without passing config explicitly.
        """
        cfg_path = os.path.join(self.tmp_dir.name, "user_whitelist_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "ban_subnet": true,
                "whitelist": ["185.204.62.36"]
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage, config=cfg)

        # 1. get_ban_target must return single IP when subnet overlaps whitelist
        self.assertEqual(cfg.get_ban_target("185.204.62.50"), "185.204.62.50")

        # 2. Ban attacker without passing config explicitly
        banned = fw.ban_ip(
            ip="185.204.62.50",
            reason="Malicious scanner",
            matched_pattern="/wp-admin",
            duration=3600,
        )
        self.assertTrue(banned)

        # 3. Whitelisted IP must NOT be banned
        self.assertIsNone(fw.is_ip_banned("185.204.62.36"))
        self.assertNotIn("185.204.62.0/24", fw.active_bans)
        self.assertNotIn("185.204.62.36", fw.active_bans)

        # 4. Attacker must be banned
        self.assertIsNotNone(fw.is_ip_banned("185.204.62.50"))

    def test_whitelist_direct_ban_refused(self):
        """Calling ban_ip directly on a whitelisted IP or range must return False and refuse ban."""
        cfg_path = os.path.join(self.tmp_dir.name, "whitelist_refuse_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "whitelist": ["10.20.30.40"]
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage, config=cfg)

        result = fw.ban_ip(
            ip="10.20.30.40",
            reason="Manual mistake",
            matched_pattern="manual",
            duration=3600,
        )
        self.assertFalse(result)
        self.assertIsNone(fw.is_ip_banned("10.20.30.40"))
        self.assertNotIn("10.20.30.40", fw.active_bans)

    def test_storage_startup_sanitization(self):
        """Stored bans that conflict with current whitelist must be purged on startup."""
        from core.models import BanRecord
        import time

        db_path = os.path.join(self.tmp_dir.name, "sanitization_test.db")
        storage = StorageManager(db_path)

        # Store a ban that contains 185.204.62.36
        bad_rec = BanRecord(
            ip="185.204.62.0/24",
            reason="Old wide ban",
            matched_pattern="/test",
            attack_count=5,
            banned_at=time.time(),
            ban_duration=3600,
            status="BANNED",
            backend="dummy",
        )
        storage.save_ban(bad_rec)

        cfg_path = os.path.join(self.tmp_dir.name, "sanitization_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "whitelist": ["185.204.62.36"]
            }""")
        cfg = ConfigManager(cfg_path)

        # Initializing FirewallManager with this storage & config
        fw = FirewallManager(dry_run=True, storage=storage, config=cfg)

        # The subnet /24 overlapping whitelist should NOT be in active_bans
        self.assertNotIn("185.204.62.0/24", fw.active_bans)
        self.assertIsNone(fw.is_ip_banned("185.204.62.36"))

    def test_is_ip_banned_defense_in_depth(self):
        """Even if an overlapping ban exists in memory, is_ip_banned always returns None for whitelisted IPs."""
        cfg_path = os.path.join(self.tmp_dir.name, "did_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "whitelist": ["1.2.3.4"]
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage, config=cfg)

        # Manually inject an aggressive rule in active_bans
        from core.models import BanRecord
        import time
        fw.active_bans["0.0.0.0/0"] = BanRecord(
            ip="0.0.0.0/0", reason="Extreme", matched_pattern="*", attack_count=1,
            banned_at=time.time(), ban_duration=3600, status="SIMULATED", backend="dummy"
        )

        # Regular IP is considered banned by 0.0.0.0/0
        self.assertIsNotNone(fw.is_ip_banned("8.8.8.8"))
        # Whitelisted IP is NEVER considered banned!
        self.assertIsNone(fw.is_ip_banned("1.2.3.4"))

    def test_kill_active_connections_protection(self):
        """kill_active_connections must refuse to kill sockets for whitelisted IPs."""
        cfg_path = os.path.join(self.tmp_dir.name, "kill_cfg.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": false,
                "whitelist": ["185.204.62.36"]
            }""")
        cfg = ConfigManager(cfg_path)
        fw = FirewallManager(dry_run=True, storage=self.storage, config=cfg)
        fw.dry_run = False

        import unittest.mock as mock
        with mock.patch("subprocess.run") as mock_run:
            # 1. Calling on whitelisted IP must do nothing
            fw.kill_active_connections("185.204.62.36")
            mock_run.assert_not_called()

            # 2. Calling on attacker IP must execute ss -K for native and IPv4-mapped IPv6
            fw.kill_active_connections("185.204.62.50")
            self.assertEqual(mock_run.call_count, 2)
            first_cmd = mock_run.call_args_list[0][0][0]
            second_cmd = mock_run.call_args_list[1][0][0]
            self.assertIn("185.204.62.50", first_cmd)
            self.assertIn("[::ffff:185.204.62.50]", second_cmd)

    def test_banned_host_activity_classification(self):
        """When an IP is already banned, any subsequent probe must be classified as repeat_attack, not probe."""
        from core.detector import AttackDetector
        cfg = ConfigManager("config.json")
        detector = AttackDetector(cfg)

        # 1. Unknown 404 from non-banned IP produces category 'probe'
        ev, should_ban, reason = detector.analyze_request("99.99.99.99", "GET", "/random-unknown.html", 404, is_banned=False)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.category, "probe")
        self.assertFalse(should_ban)

        # 2. Unknown 404 from already-banned IP produces category 'repeat_attack' and triggers ban
        ev, should_ban, reason = detector.analyze_request("99.99.99.99", "GET", "/random-unknown.html", 404, is_banned=True)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.category, "repeat_attack")
        self.assertTrue(should_ban)

        # 3. New patterns (.env~ and .git-credentials) are recognized as critical attacks
        ev1, ban1, _ = detector.analyze_request("99.99.99.99", "GET", "/.env~", 404)
        self.assertEqual(ev1.category, "credentials")
        self.assertTrue(ban1)

        ev2, ban2, _ = detector.analyze_request("99.99.99.99", "GET", "/.git-credentials", 404)
        self.assertEqual(ev2.category, "credentials")
        self.assertTrue(ban2)

    def test_kill_active_connections_cidr(self):
        """kill_active_connections must preserve CIDR masks for both IPv4 and IPv6-mapped dual stack."""
        from core.firewall import FirewallManager
        cfg = ConfigManager("config.json")
        fw = FirewallManager(config=cfg)
        fw.dry_run = False

        import unittest.mock as mock
        with mock.patch("subprocess.run") as mock_run:
            fw.kill_active_connections("35.205.254.0/24")
            self.assertEqual(mock_run.call_count, 2)
            first_cmd = mock_run.call_args_list[0][0][0]
            second_cmd = mock_run.call_args_list[1][0][0]
            # Native IPv4 must retain /24
            self.assertIn("35.205.254.0/24", first_cmd)
            # Dual-stack IPv6 must convert /24 to /120 (96 + 24)
            self.assertIn("[::ffff:35.205.254.0/120]", second_cmd)

    def test_cloud_and_ai_credential_leak_detection(self):
        """Cloud and AI API credential leak attempts must trigger instant critical bans on hit 1."""
        from core.detector import AttackDetector
        cfg = ConfigManager("config.json")
        detector = AttackDetector(cfg)

        probes = [
            "/.docker/secret",
            "/.docker/",
            "/.aws/credentials",
            "/.aws/config",
            "/.amplifyrc",
            "/.config/gcloud",
            "/.config/anthropic",
            "/.claude/settings",
            "/.aws/.env",
            "/.anthropic/config",
            "/.kube/config",
            "/.azure/credentials",
            "/.boto",
        ]

        for url in probes:
            ev, should_ban, reason = detector.analyze_request("35.205.254.119", "GET", url, 404)
            self.assertIsNotNone(ev, f"Expected event for {url}")
            self.assertEqual(ev.category, "credentials", f"Expected credentials category for {url}")
            self.assertTrue(should_ban, f"Expected instant ban for {url}")

    def test_dedicated_iptables_chains(self):
        """FirewallManager must configure dedicated UTILSEC-WHITELIST and UTILSEC-BAN chains and use DROP."""
        from core.firewall import FirewallManager
        cfg = ConfigManager("config.json")
        fw = FirewallManager(config=cfg)
        fw.dry_run = False
        fw.active_backend = "iptables"

        import unittest.mock as mock
        with mock.patch("subprocess.run") as mock_run:
            def fake_run(cmd, *args, **kwargs):
                m = mock.MagicMock()
                if "-C" in cmd:
                    m.returncode = 1  # Rule does not exist yet
                else:
                    m.returncode = 0
                if "-S" in cmd:
                    m.stdout = b"-A INPUT -j UTILSEC-WHITELIST\n-A INPUT -j UTILSEC-BAN\n"
                return m

            mock_run.side_effect = fake_run

            # 1. Chain initialization
            count = fw._init_iptables_chains()
            self.assertGreater(count, 0)

            # 2. Ban execution must target UTILSEC-BAN with -j DROP
            mock_run.reset_mock()
            from core.models import BanRecord
            rec = BanRecord(
                ip="45.138.12.0/24",
                reason="Test Cloud Leak",
                matched_pattern="cloud_leaks",
                attack_count=1,
                banned_at=time.time(),
                ban_duration=3600,
                backend="iptables"
            )
            fw._exec_ban_system(rec)

            called_cmds = [call[0][0] for call in mock_run.call_args_list]
            ban_cmd = next((c for c in called_cmds if "UTILSEC-BAN" in c and "-I" in c), None)
            self.assertIsNotNone(ban_cmd, "Ban command must target UTILSEC-BAN chain")
            self.assertIn("-j", ban_cmd)
            self.assertIn("DROP", ban_cmd)
            self.assertIn("45.138.12.0/24", ban_cmd)

            # 3. Unban execution must target UTILSEC-BAN
            mock_run.reset_mock()
            fw._exec_unban_system(rec)
            unban_called_cmds = [call[0][0] for call in mock_run.call_args_list]
            unban_cmd = next((c for c in unban_called_cmds if "UTILSEC-BAN" in c and "-D" in c), None)
            self.assertIsNotNone(unban_cmd, "Unban command must target UTILSEC-BAN chain")
            self.assertIn("DROP", unban_cmd)
