"""Terminal User Interface (TUI) for UtilSec Sentinel using standard curses."""

import curses
import os
import sys
import time
from collections import deque
from typing import Any, Callable, Deque, List, Optional

from core.config import ConfigManager
from core.detector import AttackDetector
from core.firewall import FirewallManager
from core.models import AttackEvent, BanRecord
from core.storage import StorageManager
from core.watcher import LogWatcher


class SentinelTUI:
    """Full-featured interactive curses dashboard for Sentinel."""

    def __init__(
        self,
        config: ConfigManager,
        detector: AttackDetector,
        firewall: FirewallManager,
        watcher: LogWatcher,
        storage: Optional[Any] = None,
    ):
        self.config = config
        self.detector = detector
        self.firewall = firewall
        self.watcher = watcher
        self.storage = storage

        self.running = True
        self.paused = False
        self.view_mode = "split"  # "split", "bans", "stream"
        self.recent_attacks: Deque[AttackEvent] = deque(maxlen=100)

        # Pre-load recent events from database so stream is never empty
        if self.storage:
            try:
                for ev in self.storage.load_recent_events(limit=50):
                    self.recent_attacks.append(ev)
            except Exception:
                pass

        self.status_msg = "Ready. Monitoring logs..."
        self.status_msg_time = time.time()

        # Table navigation
        self.selected_idx = 0
        self.scroll_offset = 0

        # Colors
        self.C_DEFAULT = 1
        self.C_HEADER = 2
        self.C_ALERT = 3
        self.C_WARN = 4
        self.C_SUCCESS = 5
        self.C_INFO = 6
        self.C_MUTED = 7

    def add_attack_event(self, event: AttackEvent) -> None:
        if not self.paused:
            self.recent_attacks.appendleft(event)

    def set_status(self, msg: str) -> None:
        self.status_msg = msg
        self.status_msg_time = time.time()

    def start(self) -> None:
        """Initializes curses and runs the event loop."""
        # Ensure valid TERM
        if not os.environ.get("TERM") or os.environ.get("TERM") == "dumb":
            os.environ["TERM"] = "xterm-256color"

        try:
            curses.wrapper(self._main_loop)
        except KeyboardInterrupt:
            pass

    def _init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(self.C_DEFAULT, curses.COLOR_WHITE, -1)
        curses.init_pair(self.C_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(self.C_ALERT, curses.COLOR_RED, -1)
        curses.init_pair(self.C_WARN, curses.COLOR_YELLOW, -1)
        curses.init_pair(self.C_SUCCESS, curses.COLOR_GREEN, -1)
        curses.init_pair(self.C_INFO, curses.COLOR_CYAN, -1)
        curses.init_pair(self.C_MUTED, curses.COLOR_BLUE, -1)

    def _main_loop(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.timeout(100)  # 100ms refresh rate
        self._init_colors()

        while self.running:
            try:
                max_y, max_x = stdscr.getmaxyx()
                if max_y < 16 or max_x < 70:
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Terminal too small ({max_x}x{max_y}). Min: 70x16.", curses.color_pair(self.C_WARN))
                    stdscr.refresh()
                    time.sleep(0.2)
                    key = stdscr.getch()
                    if key in (ord("q"), ord("Q")):
                        break
                    continue

                self._draw_dashboard(stdscr, max_y, max_x)
                key = stdscr.getch()
                if key != -1:
                    self._handle_key(stdscr, key)

            except curses.error:
                pass

    def _draw_dashboard(self, stdscr, max_y: int, max_x: int) -> None:
        stdscr.erase()

        # 1. Header (Line 0)
        mode_str = f"[SIMULATION]" if self.firewall.dry_run else f"[LIVE: {self.firewall.active_backend.upper()}]"
        mode_color = self.C_WARN if self.firewall.dry_run else self.C_ALERT
        title = " UTILSEC SENTINEL "
        speed_str = f"{self.watcher.lines_per_sec:.0f} lines/s | File: {os.path.basename(self.watcher.log_path)}"
        speed_str = f"{self.watcher.lines_per_sec:.1f} lines/s | File: {os.path.basename(self.watcher.log_path)}"

        stdscr.attron(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, " " * (max_x - 1))
        stdscr.addstr(0, 2, title)
        stdscr.attroff(curses.color_pair(self.C_HEADER) | curses.A_BOLD)

        stdscr.addstr(0, len(title) + 4, mode_str, curses.color_pair(mode_color) | curses.A_BOLD)
        stdscr.addstr(0, max_x - len(speed_str) - 2, speed_str, curses.color_pair(self.C_DEFAULT))

        # 2. Stat Cards (Lines 1-3)
        bans_list = self.firewall.get_active_bans_list()
        active_bans_count = len(bans_list)
        total_attacks = self.detector.total_attacks_detected
        total_404s = self.detector.total_404s
        total_scanned = self.detector.total_analyzed

        stats_line = (
            f" [ACTIVE BANS: {active_bans_count}]  "
            f" [ATTACKS CAUGHT: {total_attacks}]  "
            f" [404/403 ERRORS: {total_404s}]  "
            f" [TOTAL SCANNED: {total_scanned}]  "
            f" [PAUSED: {'YES' if self.paused else 'NO'}]"
        )
        stdscr.addstr(2, 1, stats_line[: max_x - 2], curses.color_pair(self.C_INFO) | curses.A_BOLD)

        # Separator (Line 3)
        stdscr.addstr(3, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        # 3. Main Area (Line 4 to max_y - 4)
        table_h = max_y - 8

        # Mode indicator in title bar
        view_label = f"[VIEW: {self.view_mode.upper()}]"
        stdscr.addstr(4, max_x - len(view_label) - 2, view_label, curses.color_pair(self.C_INFO) | curses.A_BOLD)

        if self.view_mode in ("split", "bans"):
            split_x = max(35, int(max_x * 0.52)) if self.view_mode == "split" else max_x - 1

            # Left Header: Banned IPs
            stdscr.addstr(4, 2, " BANNED SUBNETS / ATTACKERS ", curses.color_pair(self.C_ALERT) | curses.A_BOLD)
            tbl_hdr = f"  {'TARGET / SUBNET':<18} {'REASON / RULE':<20} {'HITS':<5} {'TTL':<8} {'STATUS':<7}"
            stdscr.addstr(5, 1, tbl_hdr[: split_x - 1], curses.color_pair(self.C_DEFAULT) | curses.A_UNDERLINE)

            # Draw Banned IPs Table
            if not bans_list:
                stdscr.addstr(7, 4, "No active bans yet.", curses.color_pair(self.C_MUTED))
            else:
                if self.selected_idx >= len(bans_list):
                    self.selected_idx = max(0, len(bans_list) - 1)

                if self.selected_idx < self.scroll_offset:
                    self.scroll_offset = self.selected_idx
                elif self.selected_idx >= self.scroll_offset + table_h:
                    self.scroll_offset = self.selected_idx - table_h + 1

                visible_bans = bans_list[self.scroll_offset : self.scroll_offset + table_h]
                for row_i, ban in enumerate(visible_bans):
                    abs_i = self.scroll_offset + row_i
                    y = 6 + row_i
                    is_sel = abs_i == self.selected_idx

                    rem = f"{ban.remaining_seconds}s" if ban.ban_duration > 0 else "PERM"
                    rule_disp = (ban.reason[:18] + "..") if len(ban.reason) > 20 else ban.reason
                    line_str = f" {ban.ip:<18} {rule_disp:<20} {ban.attack_count:<5} {rem:<8} {ban.status:<7}"
                    line_str = line_str[: split_x - 1].ljust(split_x - 1)

                    attr = curses.A_REVERSE if is_sel else curses.A_NORMAL
                    color = self.C_ALERT if ban.status == "BANNED" else self.C_WARN
                    if is_sel:
                        stdscr.addstr(y, 1, line_str, curses.color_pair(color) | attr | curses.A_BOLD)
                    else:
                        stdscr.addstr(y, 1, line_str, curses.color_pair(color) | attr)

        if self.view_mode in ("split", "stream"):
            start_x = (split_x + 2) if self.view_mode == "split" else 2
            stream_w = (max_x - split_x - 4) if self.view_mode == "split" else (max_x - 4)

            # Draw vertical separator if split
            if self.view_mode == "split":
                for y in range(4, max_y - 3):
                    stdscr.addstr(y, split_x, "│", curses.color_pair(self.C_MUTED))

            # Stream Header
            stdscr.addstr(4, start_x, " LIVE ATTACK STREAM ", curses.color_pair(self.C_INFO) | curses.A_BOLD)
            attacks_to_show = list(self.recent_attacks)[:table_h]

            if not attacks_to_show:
                stdscr.addstr(7, start_x, "Waiting for attack events in log...", curses.color_pair(self.C_MUTED))
            else:
                for row_i, ev in enumerate(attacks_to_show):
                    y = 6 + row_i
                    t_str = ev.timestamp.strftime("%H:%M:%S")
                    txt = f"{t_str} [{ev.ip}] {ev.method} {ev.url}"
                    tag = f"({ev.matched_rule})"
                    if len(txt) + len(tag) + 2 > stream_w:
                        txt = txt[: max(10, stream_w - len(tag) - 3)] + ".."
                    disp = f"{txt:<{stream_w - len(tag) - 1}} {tag}"[:stream_w]
                    color = self.C_ALERT if ev.category in ("credentials", "webshell", "traversal", "rate_limit") else self.C_WARN
                    stdscr.addstr(y, start_x, disp, curses.color_pair(color))

        # Separator before status bar
        stdscr.addstr(max_y - 3, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        # Status Line (Line max_y - 2)
        stdscr.addstr(max_y - 2, 1, f"STATUS: {self.status_msg}"[: max_x - 2], curses.color_pair(self.C_INFO))

        # Hotkeys Bar (Line max_y - 1)
        help_bar = "[Q]uit  [Tab/V]iew  [U]nban  [B]an IP  [A]dd Rule  [M]ode  [P]ause  [C]lear  [↑/↓] Nav"
        stdscr.addstr(max_y - 1, 0, help_bar[: max_x - 1], curses.color_pair(self.C_HEADER) | curses.A_BOLD)

        stdscr.refresh()

    def _handle_key(self, stdscr, key: int) -> None:
        if key in (ord("q"), ord("Q")):
            self.running = False

        elif key in (ord("\t"), ord("v"), ord("V")):
            # Cycle view mode
            if self.view_mode == "split":
                self.view_mode = "bans"
            elif self.view_mode == "bans":
                self.view_mode = "stream"
            else:
                self.view_mode = "split"
            self.set_status(f"Switched view to: {self.view_mode.upper()}")

        elif key == curses.KEY_UP:
            if self.selected_idx > 0:
                self.selected_idx -= 1

        elif key == curses.KEY_DOWN:
            bans_count = len(self.firewall.active_bans)
            if self.selected_idx < bans_count - 1:
                self.selected_idx += 1

        elif key in (ord("u"), ord("U")):
            # Unban currently selected IP
            bans = self.firewall.get_active_bans_list()
            if bans and 0 <= self.selected_idx < len(bans):
                target_ip = bans[self.selected_idx].ip
                self.firewall.unban_ip(target_ip, manual=True)
                self.set_status(f"Unbanned IP: {target_ip}")
            else:
                self.set_status("No IP selected to unban.")

        elif key in (ord("b"), ord("B")):
            # Manual ban modal
            inp = self._prompt_input(stdscr, "Enter IP or Subnet to BAN (e.g. 1.2.3.4 or 1.2.3.0/24): ")
            if inp:
                target = self.config.get_ban_target(inp)
                self.firewall.ban_ip(
                    ip=target,
                    reason="Manual Ban via TUI",
                    matched_pattern="manual",
                    duration=self.config.default_ban_duration,
                )
                self.set_status(f"Manually banned target: {target}")

        elif key in (ord("a"), ord("A")):
            # Add custom attack rule
            pattern = self._prompt_input(stdscr, "Enter attack string/path to block (e.g. /my-admin): ")
            if pattern:
                added = self.config.add_user_pattern(pattern)
                if added:
                    self.detector.reload_rules()
                    self.set_status(f"Added and saved rule: {pattern}")
                else:
                    self.set_status(f"Rule already exists: {pattern}")

        elif key in (ord("m"), ord("M")):
            # Toggle dry-run / live mode
            is_dry = self.firewall.toggle_dry_run()
            mode_name = "SIMULATION (Dry-run)" if is_dry else f"LIVE ({self.firewall.active_backend})"
            self.set_status(f"Switched firewall mode to: {mode_name}")

        elif key in (ord("p"), ord("P")):
            self.paused = not self.paused
            self.set_status("Stream PAUSED" if self.paused else "Stream RESUMED")

        elif key in (ord("c"), ord("C")):
            # Clear expired / unbanned records from memory
            self.firewall.active_bans = {
                ip: b for ip, b in self.firewall.active_bans.items() if not b.is_expired
            }
            self.set_status("Cleaned expired records from display.")

    def _prompt_input(self, stdscr, prompt: str) -> str:
        """Displays an inline input prompt in the status bar."""
        max_y, max_x = stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)

        stdscr.attron(curses.color_pair(self.C_WARN) | curses.A_BOLD)
        stdscr.addstr(max_y - 2, 0, " " * (max_x - 1))
        stdscr.addstr(max_y - 2, 1, prompt)
        stdscr.attroff(curses.color_pair(self.C_WARN) | curses.A_BOLD)
        stdscr.refresh()

        buf = []
        x_pos = len(prompt) + 1
        stdscr.timeout(-1)  # blocking for input

        while True:
            ch = stdscr.getch()
            if ch in (curses.KEY_ENTER, 10, 13):
                break
            elif ch in (27,):  # ESC
                buf.clear()
                break
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if buf:
                    buf.pop()
                    x_pos -= 1
                    stdscr.addstr(max_y - 2, x_pos, " ")
                    stdscr.move(max_y - 2, x_pos)
            elif 32 <= ch <= 126 and x_pos < max_x - 2:
                char = chr(ch)
                buf.append(char)
                stdscr.addstr(max_y - 2, x_pos, char)
                x_pos += 1
            stdscr.refresh()

        curses.noecho()
        curses.curs_set(0)
        stdscr.timeout(100)
        return "".join(buf).strip()

