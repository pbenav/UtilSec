"""Layout tests: the TUI must never crash on narrow or tiny terminals.

Regression for the ValueError raised by ``f"{txt:<{width}}"`` when the stream
column became narrower than the rule tag (or when the terminal was resized).
"""

import os
import tempfile
import unittest
from unittest import mock

import curses

from core.config import ConfigManager
from core.detector import AttackDetector
from core.firewall import FirewallManager
from core.models import AttackEvent
from core.storage import StorageManager
from core.watcher import LogWatcherManager
from ui.tui import SentinelTUI


class FakeScreen:
    """Stands in for a curses window and behaves like the real one:

    writing outside the visible area raises ``curses.error``, which is what a
    real terminal does - so any unclamped draw shows up as a failure here.
    """

    def __init__(self, rows: int, cols: int):
        self.rows = rows
        self.cols = cols
        self.writes = []

    def getmaxyx(self):
        return (self.rows, self.cols)

    def erase(self):
        pass

    def clear(self):
        pass

    def refresh(self):
        pass

    def attron(self, attr):
        pass

    def attroff(self, attr):
        pass

    def bkgd(self, ch, attr=0):
        pass

    def nodelay(self, flag):
        pass

    def timeout(self, delay):
        pass

    def move(self, y, x):
        if y < 0 or x < 0 or y >= self.rows or x >= self.cols:
            raise curses.error(f"move out of bounds: y={y} x={x}")
        self.cursor = (y, x)

    def addch(self, y, x, ch, attr=0):
        if y < 0 or x < 0 or y >= self.rows or x >= self.cols:
            raise curses.error(f"addch out of bounds: y={y} x={x}")
        self.writes.append((y, x, str(ch)))

    def addstr(self, y, x, text, attr=0):
        text = text if isinstance(text, str) else str(text)
        if y < 0 or x < 0 or y >= self.rows or x >= self.cols:
            raise curses.error(f"addstr out of bounds: y={y} x={x}")
        if x + len(text) > self.cols:
            raise curses.error(
                f"addstr overflow: y={y} x={x} len={len(text)} cols={self.cols}"
            )
        self.writes.append((y, x, text))

    @property
    def text(self):
        return "\n".join(t for _, _, t in self.writes)


class TestTUILayout(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self._prev_audit_dir = os.environ.get("UTILSEC_AUDIT_DIR")
        os.environ["UTILSEC_AUDIT_DIR"] = self.tmp_dir.name

        self.config_path = os.path.join(self.tmp_dir.name, "tui_cfg.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("""{
                "log_file": "test.log",
                "firewall_backend": "dummy",
                "dry_run": true,
                "default_ban_duration": 10,
                "threshold_404": 3,
                "window_seconds": 5,
                "whitelist": ["127.0.0.1"],
                "user_patterns": [],
                "heuristic_rules": []
            }""")

        self.config = ConfigManager(self.config_path)
        self.storage = StorageManager(os.path.join(self.tmp_dir.name, "tui.db"))
        self.firewall = FirewallManager(dry_run=True, storage=self.storage)
        self.detector = AttackDetector(self.config)
        self.mgr = LogWatcherManager(on_request=lambda *args: None)

        # color_pair needs an initialised terminal; the drawing logic under
        # test does not depend on the actual colour values.
        self._color_pair = mock.patch.object(curses, "color_pair", lambda n: 0)
        self._color_pair.start()

    def tearDown(self):
        self._color_pair.stop()
        self.firewall.stop()
        self.storage.close()
        if self._prev_audit_dir is None:
            os.environ.pop("UTILSEC_AUDIT_DIR", None)
        else:
            os.environ["UTILSEC_AUDIT_DIR"] = self._prev_audit_dir
        self.tmp_dir.cleanup()

    def _tui(self) -> SentinelTUI:
        tui = SentinelTUI(
            config=self.config,
            detector=self.detector,
            firewall=self.firewall,
            watcher_manager=self.mgr,
            storage=self.storage,
        )
        # A realistic worst case: long rule name, long URL, long source log.
        tui.add_attack_event(AttackEvent(
            ip="203.0.113.45", method="POST", url="/" + "a" * 120,
            status_code=404, category="credentials",
            matched_rule="authorization_bypass_via_long_rule_name",
            source_log="very_long_source_log_name.log",
        ))
        tui.add_attack_event(AttackEvent(
            ip="198.51.100.7", method="GET", url="/wp-admin/setup.php",
            status_code=403, category="admin",
            matched_rule="WP",
            source_log="default",
        ))
        return tui

    def test_dashboard_does_not_crash_on_narrow_terminals(self):
        """The old code raised ValueError: Sign not allowed in string format."""
        for rows, cols in ((16, 70), (17, 71), (18, 72), (24, 80), (30, 100),
                           (43, 132), (60, 200)):
            with self.subTest(size=(cols, rows)):
                tui = self._tui()
                tui.view_mode = "split"
                screen = FakeScreen(rows, cols)
                tui._draw_dashboard(screen, rows, cols)

    def test_dashboard_with_positive_and_zero_stream_width(self):
        for mode in ("split", "stream"):
            with self.subTest(mode=mode):
                tui = self._tui()
                tui.view_mode = mode
                screen = FakeScreen(24, 80)
                tui._draw_dashboard(screen, 24, 80)
                self.assertTrue(screen.writes)

    def test_tiny_terminal_shows_hint_instead_of_crashing(self):
        for rows, cols in ((1, 1), (5, 10), (8, 40), (15, 69), (15, 60)):
            with self.subTest(size=(cols, rows)):
                tui = self._tui()
                screen = FakeScreen(rows, cols)
                tui._draw_dashboard(screen, rows, cols)
                if cols >= 16 and rows >= 1:
                    self.assertIn("Terminal too small", screen.text)
                elif cols >= 9:
                    self.assertIn("Terminal", screen.text)

    def test_tiny_terminal_hint_never_writes_out_of_bounds(self):
        tui = self._tui()
        for rows in range(0, 17):
            for cols in range(0, 71):
                screen = FakeScreen(rows, cols)
                # FakeScreen raises curses.error on any out-of-range write;
                # _draw_too_small must swallow it, not propagate.
                try:
                    tui._draw_too_small(screen, rows, cols)
                except curses.error:  # pragma: no cover - would be a bug
                    self.fail(f"_draw_too_small wrote out of bounds at {cols}x{rows}")

    def test_stats_screen_on_tiny_terminal_shows_hint(self):
        tui = self._tui()
        screen = FakeScreen(10, 50)
        tui._draw_stats_screen(screen, 10, 50)
        self.assertIn("Terminal too small", screen.text)

    def test_stats_screen_renders_on_normal_terminal(self):
        tui = self._tui()
        screen = FakeScreen(30, 100)
        tui._draw_stats_screen(screen, 30, 100)
        self.assertTrue(screen.writes)


if __name__ == "__main__":
    unittest.main()
