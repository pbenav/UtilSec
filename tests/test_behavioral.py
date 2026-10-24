"""Unit tests for the Behavioral and Early-Stage Reconnaissance Detection Engine."""

import os
import tempfile
import time
import unittest

from core.behavioral import (
    EarlyStageReconEngine,
    ParameterAnomaly,
    PreventiveMitigationFeedbackLoop,
    ShannonEntropyCalculator,
    SlidingWindowTracker,
    UserJourneyTracker,
)
from core.config import ConfigManager
from core.detector import AttackDetector


class TestShannonEntropyCalculator(unittest.TestCase):
    """Tests for mathematical entropy calculation and structural parameter analysis."""

    def test_homogeneous_string_entropy(self):
        # A uniform sequence has zero information entropy
        self.assertEqual(ShannonEntropyCalculator.calculate_entropy("aaaaaaa"), 0.0)
        self.assertEqual(ShannonEntropyCalculator.calculate_entropy(""), 0.0)

    def test_natural_language_entropy(self):
        # Normal usernames and identifiers usually have low-to-moderate entropy (2.0 to 3.5)
        entropy = ShannonEntropyCalculator.calculate_entropy("john_doe_profile")
        self.assertGreater(entropy, 1.5)
        self.assertLess(entropy, 4.0)

    def test_obfuscated_high_entropy_payload(self):
        # Base64 encoded payload, shellcode, or encrypted tokens have high entropy (>= 4.2)
        payload = "VVRJTFNFQ19QTEFURk9STV9SRUNPTk5BSVNTQU5DRV9FWFBMT0lUX1BBWUxPQUQ="
        entropy = ShannonEntropyCalculator.calculate_entropy(payload)
        self.assertGreaterEqual(entropy, 4.2)

    def test_special_char_density(self):
        normal_str = "user_account_id_99"
        self.assertLess(ShannonEntropyCalculator.special_char_density(normal_str), 0.15)

        injection_payload = "';DROP TABLE users;--/**/<![CDATA["
        density = ShannonEntropyCalculator.special_char_density(injection_payload)
        self.assertGreater(density, 0.25)

    def test_base64_candidate_detection(self):
        valid_b64 = "U2VudGluZWxBdHRhY2tEZXRlY3RvcjIwMjY="
        self.assertTrue(ShannonEntropyCalculator.is_base64_like(valid_b64))

        invalid_b64 = "not-a-base64-string!#$%"
        self.assertFalse(ShannonEntropyCalculator.is_base64_like(invalid_b64))

    def test_extract_and_analyze_parameters(self):
        # URL with a benign ID parameter and an obfuscated Base64 parameter
        url = "/search.php?id=12345&data=U2VudGluZWxBdHRhY2tEZXRlY3RvcjIwMjYwOTEwQWJjZGVmZw=="
        anomalies = ShannonEntropyCalculator.extract_and_analyze_parameters(url=url)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].param_name, "data")
        self.assertTrue(anomalies[0].is_base64_candidate)
        self.assertGreaterEqual(anomalies[0].entropy, 4.0)

        # URL with high special-character injection
        url_inj = "/search.php?query=%27%3B%20DROP%20TABLE%20users%3B--%2F**%2F"
        anomalies_inj = ShannonEntropyCalculator.extract_and_analyze_parameters(url=url_inj)
        self.assertGreaterEqual(len(anomalies_inj), 1)


class TestUserJourneyTracker(unittest.TestCase):
    """Tests for navigation journey tracking and forced-browsing detection."""

    def setUp(self):
        self.tracker = UserJourneyTracker()

    def test_legitimate_user_navigation(self):
        ip = "192.168.1.100"
        # 1. User visits landing page first
        anomaly = self.tracker.evaluate_request(ip, "GET", "/", 200)
        self.assertIsNone(anomaly)
        self.assertTrue(self.tracker.profiles[ip].visited_entry_point)

        # 2. User then proceeds to an administrative login page with a referer
        raw_line = f'{ip} - - [10/Sep/2026:12:00:00 +0200] "GET /wp-admin/login.php HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"'
        anomaly2 = self.tracker.evaluate_request(ip, "GET", "/wp-admin/login.php", 200, raw_line=raw_line)
        self.assertIsNone(anomaly2)

    def test_attacker_forced_browsing_direct_admin_skip(self):
        ip = "45.156.128.99"
        # Attacker immediately attacks /wp-admin or /admin on first request without prior landing page
        raw_line = f'{ip} - - [10/Sep/2026:12:00:00 +0200] "GET /admin/dashboard.php HTTP/1.1" 403 500 "-" "curl/7.81.0"'
        anomaly = self.tracker.evaluate_request(ip, "GET", "/admin/dashboard.php", 403, raw_line=raw_line)
        self.assertIsNotNone(anomaly)
        self.assertIn("Forced browsing", anomaly)


class TestSlidingWindowTracker(unittest.TestCase):
    """Tests for sliding time window aggregation, 404 storms, and dynamic reputation scoring."""

    def setUp(self):
        self.tracker = SlidingWindowTracker(window_seconds=10, burst_404_threshold=3)

    def test_404_storm_detection(self):
        ip = "198.51.100.25"
        now = time.time()

        # Send 3 rapid 404 requests (DirBuster/Gobuster scan simulation)
        score1, _, storm1 = self.tracker.record_and_score(ip, "GET", "/non_existent_1", 404, now=now)
        self.assertFalse(storm1)

        score2, _, storm2 = self.tracker.record_and_score(ip, "GET", "/non_existent_2", 404, now=now + 0.1)
        self.assertFalse(storm2)

        score3, reasons, storm3 = self.tracker.record_and_score(ip, "GET", "/non_existent_3", 404, now=now + 0.2)
        self.assertTrue(storm3)
        self.assertGreaterEqual(score3, 45.0)
        self.assertTrue(any("404 Storm" in r for r in reasons))

    def test_sensitive_file_probe_scoring(self):
        ip = "198.51.100.30"
        now = time.time()

        # Probing .git and composer.json
        score, reasons, _ = self.tracker.record_and_score(ip, "GET", "/.git/config", 404, now=now)
        self.assertGreaterEqual(score, 25.0)
        self.assertTrue(any("sensitive file" in r.lower() for r in reasons))

    def test_window_aging_and_eviction(self):
        ip = "198.51.100.40"
        t0 = 1000.0
        self.tracker.record_and_score(ip, "GET", "/missing", 404, now=t0)
        self.assertEqual(self.tracker.ip_windows[ip].error_404_count, 1)

        # Move time forward by 15s (window is 10s)
        self.tracker.sweep_stale(now=t0 + 15.0)
        self.assertNotIn(ip, self.tracker.ip_windows)


class TestPreventiveMitigationFeedbackLoop(unittest.TestCase):
    """Tests for automated mitigation, preventive blacklisting and threshold enforcement."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.blacklist_path = os.path.join(self.tmp_dir.name, "test_blacklist.txt")
        self.feedback = PreventiveMitigationFeedbackLoop(blacklist_file=self.blacklist_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_mitigation_record_and_blacklist_file(self):
        ip = "203.0.113.88"
        self.assertFalse(self.feedback.is_preventively_blocked(ip))

        reasons = ["404 Storm detected", "Sensitive probe: .git", "High entropy parameter"]
        recorded = self.feedback.record_mitigation(ip=ip, score=110.0, reasons=reasons)
        self.assertTrue(recorded)
        self.assertTrue(self.feedback.is_preventively_blocked(ip))

        # Check blacklist file contents
        with open(self.blacklist_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("203.0.113.88", content)
        self.assertIn("Score=110.0", content)


class TestEarlyStageReconEngineIntegration(unittest.TestCase):
    """Integration tests for the full Early-Stage Recon Engine and AttackDetector."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.blacklist_path = os.path.join(self.tmp_dir.name, "preventive_blacklist.txt")
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(f"""{{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 60,
                "threshold_404": 10,
                "threshold_403": 5,
                "window_seconds": 60,
                "whitelist": ["127.0.0.1", "::1"],
                "behavioral_defense_enabled": true,
                "recon_window_seconds": 60,
                "suspicion_ban_threshold": 100.0,
                "burst_404_rate_limit": 4,
                "preventive_mitigation_file": "{self.blacklist_path}"
            }}""")

        self.config = ConfigManager(self.config_path)
        self.detector = AttackDetector(self.config)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_recon_accumulation_triggers_preventive_ban(self):
        attacker_ip = "194.26.29.110"
        now = time.time()

        # Step 1: Attacker scans sensitive files (.git, .env, composer.json)
        # Even if individual 404 threshold is 10, behavioral defense tracks recon accumulation!
        ev1, ban1, _ = self.detector.analyze_request(
            attacker_ip, "GET", "/.git/config", 404, raw_line="", source_log="test"
        )
        self.assertFalse(ban1)

        ev2, ban2, _ = self.detector.analyze_request(
            attacker_ip, "GET", "/composer.json", 404, raw_line="", source_log="test"
        )
        self.assertFalse(ban2)

        ev3, ban3, _ = self.detector.analyze_request(
            attacker_ip, "GET", "/wp-config.php", 404, raw_line="", source_log="test"
        )
        self.assertFalse(ban3)

        # Step 2: Attacker launches forced browsing to /admin with an obfuscated base64 parameter
        # This will push suspicion score over the threshold (80.0) -> BAN BEFORE EXPLOIT!
        payload_url = "/admin/login.php?token=VVRJTFNFQ19SRUNPTl9PVkVSRkxPV19FWFBMT0lUX1ZBTFVFXzEyMw=="
        ev4, ban4, reason = self.detector.analyze_request(
            attacker_ip, "GET", payload_url, 404, raw_line="", source_log="test"
        )
        self.assertTrue(ban4)
        self.assertIn("Proactive Recon Mitigation", reason)
        self.assertIsNotNone(ev4)

        # Verify blacklist file was generated
        with open(self.blacklist_path, "r", encoding="utf-8") as f:
            saved_content = f.read()
        self.assertIn(attacker_ip, saved_content)

    def test_single_obfuscated_parameter_generates_structural_event(self):
        client_ip = "185.100.87.12"
        # 200 OK request containing an obfuscated Base64 parameter
        url = "/api/v1/profile?data=U2VudGluZWxBdHRhY2tEZXRlY3RvcjIwMjYwOTEwQWJjZGVmZw=="
        ev, should_ban, _ = self.detector.analyze_request(
            client_ip, "GET", url, 200, raw_line="", source_log="test"
        )
        self.assertFalse(should_ban)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.category, "structural_anomaly")
        self.assertIn("Structural Anomaly", ev.matched_rule)

    def test_scanner_user_agent_detection(self):
        scanner_ip = "192.0.2.77"
        raw_line = f'{scanner_ip} - - [10/Sep/2026:12:00:00 +0200] "GET /test HTTP/1.1" 404 123 "-" "Nikto/2.1.6"'
        # 1st probe from Nikto
        ev1, ban1, _ = self.detector.analyze_request(scanner_ip, "GET", "/test", 404, raw_line=raw_line)
        self.assertFalse(ban1)

        # 2nd probe from Nikto with sensitive file
        ev2, ban2, reason = self.detector.analyze_request(
            scanner_ip, "GET", "/.git/HEAD", 404, raw_line=raw_line
        )
        # Scanner UA (+40) + 404s + Sensitive Probe (+25) reaches or approaches threshold rapidly
        score = self.detector.recon_engine.get_reputation(scanner_ip)
        self.assertGreaterEqual(score, 70.0)

    def test_detector_reset_counters(self):
        test_ip = "192.0.2.88"
        self.detector.analyze_request(test_ip, "GET", "/.git/config", 404)
        self.assertGreater(self.detector.recon_engine.get_reputation(test_ip), 0.0)

        self.detector.reset_counters()
        self.assertEqual(self.detector.recon_engine.get_reputation(test_ip), 0.0)
        self.assertEqual(self.detector.total_attacks_detected, 0)


if __name__ == "__main__":
    unittest.main()
