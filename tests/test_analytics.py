"""Unit tests for UtilSec Sentinel Analytics and Statistics module."""

import tempfile
import time
import unittest
from collections import deque
from datetime import datetime

from core.analytics import AttackAnalytics
from core.config import ConfigManager
from core.detector import AttackDetector
from core.models import AttackEvent
from core.storage import StorageManager


class TestAnalytics(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = f"{self.tmp_dir.name}/test_analytics.db"
        self.storage = StorageManager(self.db_path)
        self.config = ConfigManager()
        self.detector = AttackDetector(self.config)
        self.recent_attacks = deque(maxlen=100)
        self.screen_attacks = {}

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_overall_stats_keys_and_values(self):
        # Simulate some detector counts
        self.detector.total_analyzed = 500
        self.detector.total_attacks_detected = 25
        self.detector.total_404s = 40
        self.detector.total_403s = 5

        analytics = AttackAnalytics(
            detector=self.detector,
            recent_attacks=self.recent_attacks,
            screen_attacks=self.screen_attacks,
            storage=self.storage,
        )
        stats = analytics.get_overall_stats()

        # Both keys must be present for backward compatibility
        self.assertIn("total_attacks", stats)
        self.assertIn("total_attacks_detected", stats)
        self.assertEqual(stats["total_attacks"], 25)
        self.assertEqual(stats["total_attacks_detected"], 25)
        self.assertEqual(stats["total_analyzed"], 500)
        self.assertEqual(stats["attack_rate"], 5.0)
        self.assertEqual(stats["total_404s"], 40)
        self.assertEqual(stats["total_403s"], 5)

    def test_storage_integration_with_historical_events(self):
        # Log several events in storage
        for i in range(10):
            ev = AttackEvent(
                timestamp=datetime.now(),
                ip=f"192.168.1.{10 + (i % 3)}",
                method="GET",
                url="/.env",
                status_code=404,
                matched_rule="Env Leaks",
                category="credentials",
            )
            self.storage.log_event(ev)

        analytics = AttackAnalytics(
            detector=self.detector,
            recent_attacks=self.recent_attacks,
            screen_attacks=self.screen_attacks,
            storage=self.storage,
        )

        overall = analytics.get_overall_stats()
        self.assertEqual(overall["total_attacks"], 10)
        self.assertEqual(overall["unique_ips"], 3)

        categories = analytics.get_category_breakdown()
        self.assertEqual(len(categories), 1)
        self.assertEqual(categories[0][0], "credentials")
        self.assertEqual(categories[0][1], 10)

        top_ips = analytics.get_top_ips(top_n=5)
        self.assertEqual(len(top_ips), 3)

        top_rules = analytics.get_top_rules(top_n=5)
        self.assertEqual(len(top_rules), 1)
        self.assertEqual(top_rules[0][0], "Env Leaks")

    def test_geolocation_non_blocking_performance(self):
        for i in range(20):
            ev = AttackEvent(
                timestamp=datetime.now(),
                ip=f"45.156.128.{i}",
                method="GET",
                url="/test",
                status_code=404,
                matched_rule="Test",
                category="probe",
            )
            self.recent_attacks.append(ev)

        analytics = AttackAnalytics(
            detector=self.detector,
            recent_attacks=self.recent_attacks,
            screen_attacks=self.screen_attacks,
            storage=None,
        )

        # Pre-seed cache for one IP
        analytics._set_cached_geo("45.156.128.0", "ES")

        t0 = time.time()
        geo_stats = analytics.get_geolocation_stats(top_n=10)
        duration = time.time() - t0

        # Must return in under 50ms without blocking on network/DNS
        self.assertLess(duration, 0.05)
        self.assertTrue(len(geo_stats) > 0)

        # Check ES is found and remaining are XX/Other
        countries = [g[0] for g in geo_stats]
        self.assertIn("ES", countries)

    def test_get_all_stats_latency(self):
        # Insert 50 events in storage
        for i in range(50):
            ev = AttackEvent(
                timestamp=datetime.now(),
                ip=f"10.0.0.{i % 10}",
                method="POST",
                url="/xmlrpc.php",
                status_code=403,
                matched_rule="XMLRPC",
                category="exploit",
            )
            self.storage.log_event(ev)

        analytics = AttackAnalytics(
            detector=self.detector,
            recent_attacks=self.recent_attacks,
            screen_attacks=self.screen_attacks,
            storage=self.storage,
        )

        t0 = time.time()
        all_stats = analytics.get_all_stats()
        duration = time.time() - t0

        self.assertLess(duration, 0.05)
        self.assertIn("overall", all_stats)
        self.assertIn("categories", all_stats)
        self.assertIn("top_ips", all_stats)
        self.assertIn("top_rules", all_stats)
        self.assertIn("hourly_evolution", all_stats)
        self.assertIn("geolocation", all_stats)


if __name__ == "__main__":
    unittest.main()

