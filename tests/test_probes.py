"""Tests for the long-horizon probe watchdog.

A scanner that spreads 404s over hours never reaches `threshold_404` inside
`window_seconds`, so it is stored forever as `probe` rows and never banned.
`ProbeWatchdog` accumulates those rows over `probe_ban_window` and restores
them from SQLite after a restart.
"""

import os
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

from core.config import ConfigManager
from core.models import AttackEvent
from core.probes import ProbeWatchdog
from core.storage import StorageManager


def _write_config(path, threshold, window, **extra):
    import json
    data = {
        "log_file": "test.log",
        "firewall_backend": "dummy",
        "dry_run": True,
        "default_ban_duration": 600,
        "threshold_404": 50,
        "threshold_403": 50,
        "window_seconds": 60,
        "probe_ban_threshold": threshold,
        "probe_ban_window": window,
        "whitelist": ["127.0.0.1"],
        "user_patterns": [],
    }
    data.update(extra)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


class TestProbeWatchdog(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.tmp_dir.name, "config.json")
        _write_config(self.config_path, threshold=3, window=3600)
        self.config = ConfigManager(self.config_path)
        self.storage = StorageManager(os.path.join(self.tmp_dir.name, "probes.db"))

    def tearDown(self):
        self.storage.close()
        self.tmp_dir.cleanup()

    def _watchdog(self) -> ProbeWatchdog:
        return ProbeWatchdog(config=self.config, storage=self.storage)

    def _log_probe(self, ip, ts, category="probe"):
        self.storage.log_event(AttackEvent(
            timestamp=datetime.fromtimestamp(ts), ip=ip, method="GET",
            url="/does-not-exist", status_code=404,
            matched_rule="HTTP 404 Probe", category=category,
        ))

    # ------------------------------------------------------------------
    # Threshold / window
    # ------------------------------------------------------------------
    def test_fires_exactly_at_threshold(self):
        wd = self._watchdog()
        base = time.time()
        self.assertIsNone(wd.record("203.0.113.1", now=base))
        self.assertIsNone(wd.record("203.0.113.1", now=base + 10))
        fired = wd.record("203.0.113.1", now=base + 20)
        self.assertEqual(fired, (3, 3600))

    def test_counter_starts_over_after_firing(self):
        wd = self._watchdog()
        base = time.time()
        for offset in (0, 10, 20):
            wd.record("203.0.113.2", now=base + offset)
        # Third call fired and cleared the counter: two more must not fire.
        self.assertIsNone(wd.record("203.0.113.2", now=base + 30))
        self.assertIsNone(wd.record("203.0.113.2", now=base + 40))
        self.assertEqual(len(wd._hits["203.0.113.2"]), 2)

    def test_probes_older_than_the_window_are_dropped(self):
        wd = self._watchdog()
        base = time.time()
        wd.record("203.0.113.3", now=base)
        wd.record("203.0.113.3", now=base + 10)
        # Beyond probe_ban_window (3600s): the sweep must evict them, so the
        # next probe counts as the first of a fresh window.
        wd.record("203.0.113.3", now=base + 5000)
        self.assertEqual(len(wd._hits["203.0.113.3"]), 1)
        self.assertIsNone(wd.record("203.0.113.3", now=base + 5010))

    def test_disabled_when_threshold_is_zero(self):
        _write_config(self.config_path, threshold=0, window=3600)
        config = ConfigManager(self.config_path)
        wd = ProbeWatchdog(config=config, storage=self.storage)
        self.assertFalse(wd.enabled)
        self.assertIsNone(wd.record("203.0.113.4", now=time.time()))
        self.assertEqual(wd._hits, {})

    def test_config_values_are_clamped(self):
        _write_config(self.config_path, threshold=-5, window=5)
        config = ConfigManager(self.config_path)
        self.assertEqual(config.probe_ban_threshold, 0)
        self.assertEqual(config.probe_ban_window, 60)

    def test_ips_are_capped(self):
        wd = self._watchdog()
        base = time.time()
        with mock.patch("core.probes.PROBE_MAX_TRACKED_IPS", 3):
            for i in range(6):
                wd.record(f"10.0.0.{i}", now=base + i)
        self.assertLessEqual(len(wd._hits), 3)

    # ------------------------------------------------------------------
    # Persistence across restarts
    # ------------------------------------------------------------------
    def test_restores_probes_from_the_database(self):
        base = time.time()
        self._log_probe("203.0.113.5", base - 100)
        self._log_probe("203.0.113.5", base - 50)
        # Rows outside the window must not count.
        self._log_probe("203.0.113.5", base - 7200)
        # Non-probe events must not count either.
        self._log_probe("203.0.113.5", base - 10, category="credentials")

        wd = self._watchdog()
        fired = wd.record("203.0.113.5", now=base)
        self.assertEqual(fired, (3, 3600))

    def test_history_is_seeded_only_once(self):
        base = time.time()
        self._log_probe("203.0.113.6", base - 100)
        # Threshold above what the database plus two fresh probes can reach.
        _write_config(self.config_path, threshold=5, window=3600)
        wd = ProbeWatchdog(config=ConfigManager(self.config_path), storage=self.storage)
        self.assertIsNone(wd.record("203.0.113.6", now=base))
        self.assertEqual(len(wd._hits["203.0.113.6"]), 2)
        # A second record must not re-import the same database row.
        self.assertIsNone(wd.record("203.0.113.6", now=base + 1))
        self.assertEqual(len(wd._hits["203.0.113.6"]), 3)

    def test_storage_failure_does_not_break_recording(self):
        wd = self._watchdog()
        wd.storage = mock.Mock()
        wd.storage.probe_history.side_effect = RuntimeError("db gone")
        self.assertIsNone(wd.record("203.0.113.7", now=time.time()))
        self.assertIn("203.0.113.7", wd._hits)

    def test_works_without_storage(self):
        wd = ProbeWatchdog(config=self.config, storage=None)
        base = time.time()
        self.assertIsNone(wd.record("203.0.113.8", now=base))
        self.assertIsNone(wd.record("203.0.113.8", now=base + 1))
        self.assertEqual(wd.record("203.0.113.8", now=base + 2), (3, 3600))


class TestProbeHistoryQuery(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.storage = StorageManager(os.path.join(self.tmp_dir.name, "hist.db"))

    def tearDown(self):
        self.storage.close()
        self.tmp_dir.cleanup()

    def test_returns_only_probes_inside_the_window(self):
        base = time.time()
        for ts, cat in ((base - 600, "probe"), (base - 100, "probe"),
                        (base - 300, "credentials"), (base - 3600, "probe")):
            self.storage.log_event(AttackEvent(
                timestamp=datetime.fromtimestamp(ts), ip="198.51.100.9",
                method="GET", url="/x", status_code=404,
                matched_rule="r", category=cat,
            ))
        rows = self.storage.probe_history("198.51.100.9", since=base - 720)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows, sorted(rows))
        self.assertTrue(all(base - 720 <= ts < base for ts in rows))

    def test_returns_empty_for_unknown_ip(self):
        self.assertEqual(self.storage.probe_history("198.51.100.10", since=0), [])


if __name__ == "__main__":
    unittest.main()
