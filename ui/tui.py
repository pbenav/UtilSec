"""Terminal User Interface (TUI) for UtilSec Sentinel using standard curses."""

import curses
import os
import sys
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from core.analytics import AttackAnalytics
from core.config import ConfigManager
from core.detector import AttackDetector
from core.firewall import FirewallManager
from core.models import AttackEvent, BanRecord
from core.storage import StorageManager
from core.watcher import LogWatcher, LogWatcherManager


class SentinelTUI:
    """Full-featured interactive curses dashboard for Sentinel with multi-screen monitoring."""

    def __init__(
        self,
        config: ConfigManager,
        detector: AttackDetector,
        firewall: FirewallManager,
        watcher: Optional[LogWatcher] = None,
        watcher_manager: Optional[LogWatcherManager] = None,
        storage: Optional[Any] = None,
    ):
        self.config = config
        self.detector = detector
        self.firewall = firewall
        self.watcher = watcher
        self.watcher_manager = watcher_manager
        self.storage = storage

        # Backwards compatibility: if only watcher is provided, wrap in manager
        if not self.watcher_manager and self.watcher:
            self.watcher_manager = LogWatcherManager(on_request=lambda *args: None)
            self.watcher_manager.watchers[self.watcher.name] = self.watcher

        self.running = True
        self.paused = False
        self.view_mode = "split"  # "split", "bans", "stream"
        self.recent_attacks: Deque[AttackEvent] = deque(maxlen=200)
        self.screen_attacks: Dict[str, Deque[AttackEvent]] = {}
        self.active_screen_idx = 0
        self._showing_stats = False
        self._analytics_lock = __import__("threading").Lock()
        self._stats_data = None
        self._stats_loading = False

        # Pre-load recent events from database so stream is never empty
        if self.storage:
            try:
                for ev in self.storage.load_recent_events(limit=100):
                    self.recent_attacks.append(ev)
                    if ev.source_log:
                        if ev.source_log not in self.screen_attacks:
                            self.screen_attacks[ev.source_log] = deque(maxlen=200)
                        self.screen_attacks[ev.source_log].append(ev)
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

    def get_screens(self) -> List[Dict[str, Any]]:
        """Returns the list of screens: Screen 0 is GLOBAL, followed by individual log screens."""
        screens = [{"id": "global", "name": "GLOBAL", "watcher": None}]
        if self.watcher_manager:
            for name, w in self.watcher_manager.watchers.items():
                screens.append({"id": name, "name": name, "watcher": w, "path": w.log_path})
        elif self.watcher:
            screens.append({"id": self.watcher.name, "name": self.watcher.name, "watcher": self.watcher, "path": self.watcher.log_path})
        return screens

    def add_attack_event(self, event: AttackEvent) -> None:
        if not self.paused:
            self.recent_attacks.appendleft(event)
            if event.source_log:
                if event.source_log not in self.screen_attacks:
                    self.screen_attacks[event.source_log] = deque(maxlen=200)
                self.screen_attacks[event.source_log].appendleft(event)

    def set_status(self, msg: str) -> None:
        self.status_msg = msg
        self.status_msg_time = time.time()

    def start(self) -> None:
        """Initializes curses and runs the event loop."""
        if not os.environ.get("TERM") or os.environ.get("TERM") == "dumb":
            os.environ["TERM"] = "xterm-256color"

        try:
            curses.wrapper(self._main_loop)
        except KeyboardInterrupt:
            pass

    def _init_colors(self) -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        bg = -1
        try:
            curses.use_default_colors()
        except Exception:
            bg = curses.COLOR_BLACK

        try:
            curses.init_pair(self.C_DEFAULT, curses.COLOR_WHITE, bg)
            curses.init_pair(self.C_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(self.C_ALERT, curses.COLOR_RED, bg)
            curses.init_pair(self.C_WARN, curses.COLOR_YELLOW, bg)
            curses.init_pair(self.C_SUCCESS, curses.COLOR_GREEN, bg)
            curses.init_pair(self.C_INFO, curses.COLOR_CYAN, bg)
            curses.init_pair(self.C_MUTED, curses.COLOR_BLUE, bg)
        except Exception:
            pass

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

                if self._showing_stats:
                    self._update_stats_async()
                    self._draw_stats_screen(stdscr, max_y, max_x)
                else:
                    self._draw_dashboard(stdscr, max_y, max_x)
                key = stdscr.getch()
                if key != -1:
                    self._handle_key(stdscr, key)

            except curses.error:
                pass

    def _draw_dashboard(self, stdscr, max_y: int, max_x: int) -> None:
        stdscr.erase()

        screens = self.get_screens()
        if self.active_screen_idx >= len(screens):
            self.active_screen_idx = max(0, len(screens) - 1)

        current_screen = screens[self.active_screen_idx]
        is_global = (self.active_screen_idx == 0)

        # 1. Header (Line 0)
        mode_str = f"[SIMULATION]" if self.firewall.dry_run else f"[LIVE: {self.firewall.active_backend.upper()}]"
        mode_color = self.C_WARN if self.firewall.dry_run else self.C_ALERT
        title = " UTILSEC SENTINEL "

        if is_global:
            total_lps = (
                self.watcher_manager.total_lines_per_sec
                if self.watcher_manager
                else (self.watcher.lines_per_sec if self.watcher else 0.0)
            )
            total_logs = len(self.watcher_manager.watchers) if self.watcher_manager else 1
            speed_str = f"{total_lps:.1f} l/s (total) | {total_logs} logs active"
        else:
            w = current_screen.get("watcher")
            w_lps = w.lines_per_sec if w else 0.0
            log_fname = os.path.basename(w.log_path) if w else current_screen["name"]
            speed_str = f"{w_lps:.1f} l/s | {log_fname}"

        stdscr.attron(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, " " * (max_x - 1))
        stdscr.addstr(0, 2, title)
        stdscr.attroff(curses.color_pair(self.C_HEADER) | curses.A_BOLD)

        stdscr.addstr(0, len(title) + 4, mode_str, curses.color_pair(mode_color) | curses.A_BOLD)
        if len(speed_str) < max_x - (len(title) + len(mode_str) + 6):
            stdscr.addstr(0, max_x - len(speed_str) - 2, speed_str, curses.color_pair(self.C_DEFAULT))

        # 2. Screens Tabs Bar (Line 1 - GNU screen / tmux style)
        stdscr.addstr(1, 0, " " * (max_x - 1))
        tab_x = 1
        for idx, scr in enumerate(screens):
            is_active = (idx == self.active_screen_idx)
            star = "*" if is_active else ""
            tab_label = f" [{idx}: {scr['name']}{star}] "
            if tab_x + len(tab_label) >= max_x - 15:
                stdscr.addstr(1, tab_x, ".. ", curses.color_pair(self.C_MUTED))
                tab_x += 3
                break

            if is_active:
                stdscr.addstr(1, tab_x, tab_label, curses.color_pair(self.C_INFO) | curses.A_REVERSE | curses.A_BOLD)
            else:
                stdscr.addstr(1, tab_x, tab_label, curses.color_pair(self.C_DEFAULT))
            tab_x += len(tab_label) + 1

        add_btn = "[+] Add Log"
        if max_x - len(add_btn) - 2 > tab_x:
            stdscr.addstr(1, max_x - len(add_btn) - 2, add_btn, curses.color_pair(self.C_SUCCESS) | curses.A_BOLD)

        # 3. Stat Cards / File Path Line (Line 2)
        bans_list = self.firewall.get_active_bans_list()
        active_bans_count = len(bans_list)
        total_attacks = self.detector.total_attacks_detected
        total_404s = self.detector.total_404s
        total_scanned = self.detector.total_analyzed

        if is_global:
            log_names = [s["name"] for s in screens if s["id"] != "global"]
            names_summary = ", ".join(log_names)
            if len(names_summary) > 28:
                names_summary = names_summary[:25] + ".."
            stats_line = (
                f" [GLOBAL BANS: {active_bans_count}]  "
                f" [ATTACKS: {total_attacks}]  "
                f" [SCANNED: {total_scanned:,}]  "
                f" [LOGS ({len(log_names)}): {names_summary or 'None'}]  "
                f" [PAUSED: {'YES' if self.paused else 'NO'}]"
            )
            stdscr.addstr(2, 1, stats_line[: max_x - 2], curses.color_pair(self.C_INFO) | curses.A_BOLD)
        else:
            w = current_screen.get("watcher")
            w_lines = w.lines_processed if w else 0
            w_attacks = len(self.screen_attacks.get(current_screen["id"], []))
            full_path = w.log_path if w else current_screen.get("path", current_screen["name"])

            # Prominently display the exact log file path in Yellow/Bold
            file_tag = f" 📄 FILE: {full_path} "
            stats_rest = (
                f"  [SPEED: {w_lps:.1f} l/s]  "
                f"[LINES: {w_lines:,}]  "
                f"[ATTACKS: {w_attacks}]  "
                f"[BANS: {active_bans_count}]"
            )

            # Draw FILE tag first so it's always visible
            stdscr.addstr(2, 1, file_tag[: max_x - 2], curses.color_pair(self.C_WARN) | curses.A_BOLD)
            tag_len = len(file_tag) + 1
            if tag_len < max_x - 2:
                stdscr.addstr(2, tag_len, stats_rest[: max_x - tag_len - 1], curses.color_pair(self.C_INFO))

        # Separator (Line 3)
        stdscr.addstr(3, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        # 4. Main Area (Lines 4 to max_y - 4)
        table_h = max(1, max_y - 9)

        # For bans-only mode, use full height (no stream panel)
        if self.view_mode == "bans":
            bans_available_h = max(1, max_y - 7)  # lines 4-5 header + data down to line before help bar
        else:
            bans_available_h = table_h - 1

        # Mode indicator in title bar
        view_label = f"[VIEW: {self.view_mode.upper()}]"
        stdscr.addstr(4, max_x - len(view_label) - 2, view_label, curses.color_pair(self.C_INFO) | curses.A_BOLD)

        if self.view_mode in ("split", "bans"):
            split_x = max(35, int(max_x * 0.52)) if self.view_mode == "split" else max_x - 1

            # Left Header: Banned IPs
            stdscr.addstr(4, 2, " BANNED SUBNETS / ATTACKERS ", curses.color_pair(self.C_ALERT) | curses.A_BOLD)
            tbl_hdr = f"  {'TARGET/SUBNET':<18} {'REASON/RULE':<22} {'HITS':<5} {'TTL':<8} {'STATUS':<8}"
            stdscr.addstr(5, 1, tbl_hdr[: split_x - 1], curses.color_pair(self.C_DEFAULT) | curses.A_UNDERLINE)

            # Draw Banned IPs Table
            if not bans_list:
                stdscr.addstr(7, 4, "No active bans yet.", curses.color_pair(self.C_MUTED))
            else:
                if self.selected_idx >= len(bans_list):
                    self.selected_idx = max(0, len(bans_list) - 1)

                # Available rows for ban entries (header at line 5, so start at line 6)
                ban_content_h = bans_available_h - 1  # reserve 1 row for header within bans_available_h
                if self.selected_idx < self.scroll_offset:
                    self.scroll_offset = self.selected_idx
                elif self.selected_idx >= self.scroll_offset + ban_content_h:
                    self.scroll_offset = self.selected_idx - ban_content_h + 1

                visible_bans = bans_list[self.scroll_offset : self.scroll_offset + ban_content_h]
                for row_i, ban in enumerate(visible_bans):
                    abs_i = self.scroll_offset + row_i
                    y = 6 + row_i
                    is_sel = abs_i == self.selected_idx

                    rem = f"{ban.remaining_seconds}s" if ban.ban_duration > 0 else "PERM"
                    rule_disp = ban.reason[:22]
                    if len(ban.reason) > 22:
                        rule_disp += ".."
                    line_str = f" {ban.ip:<18} {rule_disp:<22} {ban.attack_count:<5} {rem:<8} {ban.status:<8}"
                    line_str = line_str[: split_x - 1].ljust(split_x - 1)

                    attr = curses.A_REVERSE if is_sel else curses.A_NORMAL
                    color = self.C_ALERT if ban.status == "BANNED" else self.C_WARN
                    if is_sel:
                        stdscr.addstr(y, 1, line_str, curses.color_pair(color) | attr | curses.A_BOLD)
                    else:
                        stdscr.addstr(y, 1, line_str, curses.color_pair(color) | attr)

                # Scroll indicator
                if len(bans_list) > ban_content_h:
                    page_num = (self.scroll_offset // ban_content_h) + 1
                    total_pages = (len(bans_list) + ban_content_h - 1) // ban_content_h
                    scroll_info = f"  [{self.selected_idx + 1}/{len(bans_list)}] Page {page_num}/{total_pages}"
                    footer_y = 6 + ban_content_h
                    if footer_y < max_y - 3:
                        stdscr.addstr(footer_y, 1, scroll_info[:split_x - 1], curses.color_pair(self.C_MUTED))

        if self.view_mode in ("split", "stream"):
            start_x = (split_x + 2) if self.view_mode == "split" else 2
            stream_w = (max_x - split_x - 4) if self.view_mode == "split" else (max_x - 4)

            # Draw vertical separator if split
            if self.view_mode == "split":
                for y in range(4, max_y - 3):
                    stdscr.addstr(y, split_x, "│", curses.color_pair(self.C_MUTED))

            # Stream Header showing current monitored log name
            if is_global:
                stream_title = " LIVE ATTACK STREAM [GLOBAL - ALL LOGS] "
            else:
                log_disp = os.path.basename(w.log_path) if w else current_screen["name"]
                stream_title = f" LIVE ATTACK STREAM ── [{log_disp}] "
            stdscr.addstr(4, start_x, stream_title[:stream_w], curses.color_pair(self.C_INFO) | curses.A_BOLD)

            if is_global:
                attacks_to_show = list(self.recent_attacks)[:table_h]
            else:
                attacks_to_show = list(self.screen_attacks.get(current_screen["id"], []))[:table_h]

            if not attacks_to_show:
                empty_msg = (
                    "Waiting for attack events in logs..."
                    if is_global
                    else f"Waiting for attack events in {current_screen['name']}..."
                )
                stdscr.addstr(7, start_x, empty_msg, curses.color_pair(self.C_MUTED))
            else:
                for row_i, ev in enumerate(attacks_to_show):
                    y = 6 + row_i
                    t_str = ev.timestamp.strftime("%H:%M:%S")
                    src_tag = f"[{ev.source_log}] " if is_global and ev.source_log and ev.source_log != "default" else ""
                    txt = f"{t_str} {src_tag}[{ev.ip}] {ev.method} {ev.url}"
                    tag = f"({ev.matched_rule})"
                    if len(txt) + len(tag) + 2 > stream_w:
                        txt = txt[: max(10, stream_w - len(tag) - 3)] + ".."
                    disp = f"{txt:<{stream_w - len(tag) - 1}} {tag}"[:stream_w]
                    color = (
                        self.C_ALERT
                        if ev.category in ("credentials", "webshell", "traversal", "rate_limit", "heuristic", "user")
                        else self.C_WARN
                    )
                    stdscr.addstr(y, start_x, disp, curses.color_pair(color))

        # Separator before status bar
        stdscr.addstr(max_y - 3, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        # Status Line (Line max_y - 2)
        stdscr.addstr(max_y - 2, 1, f"STATUS: {self.status_msg}"[: max_x - 2], curses.color_pair(self.C_INFO))

        # Hotkeys Bar (Line max_y - 1)
        help_bar = "[Q]uit [0-9/[]]Screen [Tab/V]iew [M]ode(Live/Sim) [u]nban [U]xternal Rules [-]Del [B]an [A]Rule [D]elRule [E]stats [P]ause [I]Info"
        stdscr.addstr(max_y - 1, 0, help_bar[: max_x - 1], curses.color_pair(self.C_HEADER) | curses.A_BOLD)

        # Watermark / branding in bottom-right corner
        if max_x > 50:
            watermark = "UtilSec by Sientia Labs"
            wm_x = max_x - len(watermark) - 1
            if wm_x > 30:
                stdscr.addstr(max_y - 1, wm_x, watermark, curses.color_pair(self.C_MUTED))

        stdscr.refresh()

    def _browse_file(self, stdscr, initial_dir: Optional[str] = None) -> Optional[str]:
        """Interactive modal file browser for selecting log files in curses."""
        # Determine starting directory
        current_dir = None
        if initial_dir and os.path.isdir(initial_dir):
            current_dir = os.path.abspath(initial_dir)
        elif self.watcher_manager and self.watcher_manager.watchers:
            first_w = next(iter(self.watcher_manager.watchers.values()), None)
            if first_w and os.path.isdir(os.path.dirname(first_w.log_path)):
                current_dir = os.path.dirname(os.path.abspath(first_w.log_path))
        if not current_dir:
            if os.path.isdir("/var/log"):
                current_dir = "/var/log"
            else:
                current_dir = os.getcwd()

        def _format_size(size_bytes: int) -> str:
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

        def _scan_dir(path: str, filter_str: str) -> Tuple[List[Tuple[str, bool, int]], Optional[str]]:
            try:
                raw_entries = os.scandir(path)
                dirs = []
                files = []
                for e in raw_entries:
                    try:
                        name = e.name
                        if name.startswith(".") and name != "..":
                            continue
                        if filter_str and filter_str.lower() not in name.lower():
                            continue
                        if e.is_dir(follow_symlinks=True):
                            dirs.append((name, True, 0))
                        else:
                            try:
                                size = e.stat().st_size
                            except Exception:
                                size = 0
                            files.append((name, False, size))
                    except (PermissionError, FileNotFoundError):
                        continue
                dirs.sort(key=lambda x: x[0].lower())
                files.sort(key=lambda x: x[0].lower())
                parent_entry = []
                parent_dir = os.path.dirname(os.path.abspath(path))
                if parent_dir != os.path.abspath(path):
                    parent_entry = [("..", True, 0)]
                return parent_entry + dirs + files, None
            except PermissionError:
                return [], "Permission Denied: Unable to read directory"
            except Exception as ex:
                return [], str(ex)

        filter_text = ""
        selected_idx = 0
        scroll_offset = 0
        status_err = ""

        stdscr.timeout(-1)  # blocking input for modal
        curses.curs_set(0)

        while True:
            max_y, max_x = stdscr.getmaxyx()
            if max_y < 16 or max_x < 65:
                stdscr.timeout(100)
                return None

            entries, scan_err = _scan_dir(current_dir, filter_text)
            if scan_err:
                status_err = scan_err

            if selected_idx >= len(entries):
                selected_idx = max(0, len(entries) - 1)

            win_h = max(14, min(22, max_y - 2))
            win_w = max(58, min(80, max_x - 4))
            win_y = max(0, (max_y - win_h) // 2)
            win_x = max(0, (max_x - win_w) // 2)
            content_h = win_h - 7

            if selected_idx < scroll_offset:
                scroll_offset = selected_idx
            elif selected_idx >= scroll_offset + content_h:
                scroll_offset = selected_idx - content_h + 1

            # Fill modal background
            for r in range(win_h):
                stdscr.addstr(win_y + r, win_x, " " * (win_w - 1), curses.color_pair(self.C_DEFAULT))

            # Top border + Title
            border_top = "┌" + ("─" * (win_w - 3)) + "┐"
            stdscr.addstr(win_y, win_x, border_top[: win_w - 1], curses.color_pair(self.C_INFO))
            title = " SELECT LOG FILE (FILE BROWSER) "
            if len(title) < win_w - 4:
                stdscr.addstr(
                    win_y,
                    win_x + (win_w - len(title)) // 2,
                    title,
                    curses.color_pair(self.C_HEADER) | curses.A_BOLD,
                )

            # Line 1: Current Directory Path
            path_display = f" Path: {current_dir}"
            if len(path_display) > win_w - 4:
                path_display = " Path: .." + path_display[-(win_w - 10):]
            stdscr.addstr(win_y + 1, win_x, "│", curses.color_pair(self.C_INFO))
            stdscr.addstr(win_y + 1, win_x + 1, path_display[: win_w - 3], curses.color_pair(self.C_WARN) | curses.A_BOLD)
            stdscr.addstr(win_y + 1, win_x + win_w - 2, "│", curses.color_pair(self.C_INFO))

            # Line 2: Filter input
            filter_disp = f" Filter: [{filter_text}]"
            stdscr.addstr(win_y + 2, win_x, "│", curses.color_pair(self.C_INFO))
            stdscr.addstr(win_y + 2, win_x + 1, filter_disp[: win_w - 3], curses.color_pair(self.C_DEFAULT))
            tip = "(Type to filter, Tab auto)"
            if len(filter_disp) + len(tip) + 4 < win_w:
                stdscr.addstr(win_y + 2, win_x + win_w - len(tip) - 3, tip, curses.color_pair(self.C_MUTED))
            stdscr.addstr(win_y + 2, win_x + win_w - 2, "│", curses.color_pair(self.C_INFO))

            # Line 3: Separator
            border_sep = "├" + ("─" * (win_w - 3)) + "┤"
            stdscr.addstr(win_y + 3, win_x, border_sep[: win_w - 1], curses.color_pair(self.C_INFO))

            # Lines 4 to 4 + content_h: Directory entries
            visible_entries = entries[scroll_offset : scroll_offset + content_h]
            for row_i in range(content_h):
                curr_y = win_y + 4 + row_i
                stdscr.addstr(curr_y, win_x, "│", curses.color_pair(self.C_INFO))
                stdscr.addstr(curr_y, win_x + win_w - 2, "│", curses.color_pair(self.C_INFO))

                if row_i < len(visible_entries):
                    abs_i = scroll_offset + row_i
                    name, is_dir, size = visible_entries[row_i]
                    is_sel = (abs_i == selected_idx)

                    if is_dir:
                        icon = "📁 "
                        disp_name = ".. (Up one level)" if name == ".." else f"{name}/"
                        size_str = "<DIR>"
                        entry_color = self.C_INFO
                    else:
                        icon = "📄 "
                        disp_name = name
                        size_str = _format_size(size)
                        entry_color = (
                            self.C_SUCCESS
                            if any(name.endswith(s) for s in (".log", "_log", ".txt"))
                            else self.C_DEFAULT
                        )

                    avail_w = win_w - 4
                    name_max = max(10, avail_w - len(size_str) - 6)
                    if len(disp_name) > name_max:
                        disp_name = disp_name[: name_max - 2] + ".."
                    row_text = f" {icon}{disp_name:<{name_max}}  {size_str:>8} "
                    row_text = row_text[:avail_w].ljust(avail_w)

                    attr = curses.A_REVERSE if is_sel else curses.A_NORMAL
                    if is_sel:
                        stdscr.addstr(curr_y, win_x + 1, row_text, curses.color_pair(entry_color) | attr | curses.A_BOLD)
                    else:
                        stdscr.addstr(curr_y, win_x + 1, row_text, curses.color_pair(entry_color) | attr)

            # Line win_h - 3: Separator
            stdscr.addstr(win_y + win_h - 3, win_x, border_sep[: win_w - 1], curses.color_pair(self.C_INFO))

            # Line win_h - 2: Status / Selection preview
            stdscr.addstr(win_y + win_h - 2, win_x, "│", curses.color_pair(self.C_INFO))
            stdscr.addstr(win_y + win_h - 2, win_x + win_w - 2, "│", curses.color_pair(self.C_INFO))
            if status_err:
                err_msg = f" ! {status_err}"
                stdscr.addstr(win_y + win_h - 2, win_x + 1, err_msg[: win_w - 3], curses.color_pair(self.C_ALERT) | curses.A_BOLD)
            elif entries and 0 <= selected_idx < len(entries):
                sel_item = entries[selected_idx]
                if sel_item[1]:
                    sel_msg = f" Folder: {sel_item[0]}"
                else:
                    sel_msg = f" Target: {os.path.join(current_dir, sel_item[0])}"
                stdscr.addstr(win_y + win_h - 2, win_x + 1, sel_msg[: win_w - 3], curses.color_pair(self.C_MUTED))

            # Line win_h - 1: Bottom Help Bar
            help_text = "[↑/↓] Move [Enter] Pick [←/BS] Up [Tab] Auto [G] Path [Esc] Cancel"
            border_bot = "└" + ("─" * (win_w - 3)) + "┘"
            stdscr.addstr(win_y + win_h - 1, win_x, border_bot[: win_w - 1], curses.color_pair(self.C_INFO))
            if len(help_text) < win_w - 4:
                stdscr.addstr(
                    win_y + win_h - 1,
                    win_x + (win_w - len(help_text)) // 2,
                    help_text,
                    curses.color_pair(self.C_HEADER) | curses.A_BOLD,
                )

            stdscr.refresh()

            # Handle Keypress
            ch = stdscr.getch()
            if ch in (27,):  # Escape
                stdscr.timeout(100)
                return None

            elif ch == curses.KEY_UP:
                if selected_idx > 0:
                    selected_idx -= 1
                status_err = ""

            elif ch == curses.KEY_DOWN:
                if selected_idx < len(entries) - 1:
                    selected_idx += 1
                status_err = ""

            elif ch in (curses.KEY_PPAGE,):
                selected_idx = max(0, selected_idx - content_h)
                status_err = ""

            elif ch in (curses.KEY_NPAGE,):
                selected_idx = min(max(0, len(entries) - 1), selected_idx + content_h)
                status_err = ""

            elif ch in (curses.KEY_ENTER, 10, 13):
                status_err = ""
                if entries and 0 <= selected_idx < len(entries):
                    name, is_dir, _ = entries[selected_idx]
                    if is_dir:
                        if name == "..":
                            current_dir = os.path.dirname(os.path.abspath(current_dir))
                        else:
                            current_dir = os.path.abspath(os.path.join(current_dir, name))
                        filter_text = ""
                        selected_idx = 0
                        scroll_offset = 0
                    else:
                        chosen = os.path.abspath(os.path.join(current_dir, name))
                        stdscr.timeout(100)
                        return chosen

            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                status_err = ""
                if filter_text:
                    filter_text = filter_text[:-1]
                    selected_idx = 0
                    scroll_offset = 0
                else:
                    parent = os.path.dirname(os.path.abspath(current_dir))
                    if parent != os.path.abspath(current_dir):
                        current_dir = parent
                        selected_idx = 0
                        scroll_offset = 0

            elif ch == curses.KEY_LEFT:
                status_err = ""
                parent = os.path.dirname(os.path.abspath(current_dir))
                if parent != os.path.abspath(current_dir):
                    current_dir = parent
                    filter_text = ""
                    selected_idx = 0
                    scroll_offset = 0

            elif ch == ord("\t"):
                # Tab autocomplete
                candidates = [name for name, _, _ in entries if name != ".."]
                if candidates:
                    if len(candidates) == 1:
                        c_name = candidates[0]
                        c_isdir = entries[[e[0] for e in entries].index(c_name)][1]
                        if c_isdir:
                            current_dir = os.path.abspath(os.path.join(current_dir, c_name))
                            filter_text = ""
                            selected_idx = 0
                            scroll_offset = 0
                        else:
                            filter_text = c_name
                    else:
                        common = os.path.commonprefix(candidates)
                        if len(common) > len(filter_text):
                            filter_text = common

            elif ch in (ord("g"), ord("G")):
                # Direct path prompt
                manual = self._prompt_input(stdscr, "Enter manual file or directory path: ")
                if manual:
                    manual = os.path.expanduser(manual.strip())
                    if os.path.isfile(manual):
                        stdscr.timeout(100)
                        return os.path.abspath(manual)
                    elif os.path.isdir(manual):
                        current_dir = os.path.abspath(manual)
                        filter_text = ""
                        selected_idx = 0
                        scroll_offset = 0
                        status_err = ""
                    else:
                        status_err = f"Path not found: {manual}"

            elif 32 <= ch <= 126:
                filter_text += chr(ch)
                selected_idx = 0
                scroll_offset = 0
                status_err = ""

    def _handle_key(self, stdscr, key: int) -> None:
        screens = self.get_screens()

        if key in (ord("q"), ord("Q")):
            self.running = False

        elif ord("0") <= key <= ord("9"):
            # Direct screen jump (0 = Global, 1..N = log screens)
            idx = key - ord("0")
            if idx < len(screens):
                self.active_screen_idx = idx
                self.set_status(f"Switched to screen {idx}: {screens[idx]['name']}")
            else:
                self.set_status(f"Screen {idx} does not exist (max: {len(screens) - 1})")

        elif key in (ord("]"), ord("n"), ord("N"), curses.KEY_RIGHT):
            # Next screen
            if screens:
                self.active_screen_idx = (self.active_screen_idx + 1) % len(screens)
                self.set_status(f"Switched to screen {self.active_screen_idx}: {screens[self.active_screen_idx]['name']}")

        elif key in (ord("["), curses.KEY_LEFT):
            # Previous screen
            if screens:
                self.active_screen_idx = (self.active_screen_idx - 1) % len(screens)
                self.set_status(f"Switched to screen {self.active_screen_idx}: {screens[self.active_screen_idx]['name']}")

        elif key in (ord("+"), ord("o"), ord("O")):
            # Dynamically add log file using the interactive file browser
            selected_path = self._browse_file(stdscr)
            if selected_path:
                default_alias = os.path.basename(selected_path)
                alias = self._prompt_input(stdscr, f"Screen alias (default: {default_alias}): ")
                alias = alias.strip() if alias else default_alias
                if not alias:
                    alias = default_alias

                if self.watcher_manager and alias in self.watcher_manager.watchers:
                    self.set_status(f"Screen '{alias}' is already being monitored.")
                else:
                    if self.watcher_manager:
                        self.watcher_manager.add_watcher(name=alias, path=selected_path, auto_start=True)
                    self.config.add_log_file(alias, selected_path, persist=True)
                    new_screens = self.get_screens()
                    for idx, scr in enumerate(new_screens):
                        if scr["name"] == alias:
                            self.active_screen_idx = idx
                            break
                    self.set_status(f"Added and switched to: {alias} ({selected_path})")
            else:
                self.set_status("Log file selection cancelled.")

        elif key in (ord("-"), ord("x"), ord("X")):
            # Close current screen (disallowed on screen 0)
            if self.active_screen_idx == 0:
                self.set_status("Cannot close Screen 0 (GLOBAL).")
            elif self.active_screen_idx < len(screens):
                cur_name = screens[self.active_screen_idx]["name"]
                confirm = self._prompt_input(stdscr, f"Close screen '{cur_name}'? (y/N): ")
                if confirm.lower() in ("y", "yes"):
                    if self.watcher_manager:
                        self.watcher_manager.remove_watcher(cur_name)
                    self.config.remove_log_file(cur_name, persist=True)
                    self.active_screen_idx = 0
                    self.set_status(f"Closed screen '{cur_name}'. Switched to GLOBAL.")

        elif key in (ord("\t"), ord("v"), ord("V")):
            # Cycle view mode
            if self.view_mode == "split":
                self.view_mode = "bans"
            elif self.view_mode == "bans":
                self.view_mode = "stream"
            else:
                self.view_mode = "split"
            self.set_status(f"Switched view to: {self.view_mode.upper()}")

        elif key in (ord("e"), ord("E")):
            # Toggle statistics screen
            if hasattr(self, '_showing_stats') and self._showing_stats:
                self._showing_stats = False
                self.set_status("Statistics panel closed.")
            else:
                self._showing_stats = True
                self.set_status("Opening statistics panel...")

        elif key == 27 or key == 255:
            # ESC key - close stats screen
            if hasattr(self, '_showing_stats') and self._showing_stats:
                self._showing_stats = False
                self.set_status("Statistics panel closed.")

        elif key == curses.KEY_UP:
            if self.selected_idx > 0:
                self.selected_idx -= 1

        elif key == curses.KEY_DOWN:
            bans_count = len(self.firewall.get_active_bans_list())
            if self.selected_idx < bans_count - 1:
                self.selected_idx += 1

        elif key == ord("u"):
            # Unban currently selected IP from active list
            bans = self.firewall.get_active_bans_list()
            if bans and 0 <= self.selected_idx < len(bans):
                target_ip = bans[self.selected_idx].ip
                self.firewall.unban_ip(target_ip, manual=True)
                self.set_status(f"Unbanned IP: {target_ip}")
            else:
                self.set_status("No IP selected to unban.")

        elif key == ord("U"):
            # External rules panel: show fail2ban/manual rules and allow unban
            self._show_external_rules_panel(stdscr)

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

        elif key in (ord("d"), ord("D")):
            # Remove custom attack rule
            user_patterns = self.config.raw_config.get("user_patterns", [])
            if not user_patterns:
                self.set_status("No user-defined rules to remove.")
                return

            max_y, max_x = stdscr.getmaxyx()
            if max_y < 12 or max_x < 50:
                self.set_status("Screen too small for rule list.")
                return

            selected_idx = 0
            scroll_offset = 0

            while True:
                stdscr.timeout(200)
                max_y, max_x = stdscr.getmaxyx()
                if max_y < 12 or max_x < 50:
                    self.set_status("Screen too small for rule list.")
                    break

                modal_h = min(len(user_patterns) + 8, max_y - 4)
                modal_y = max(0, (max_y - modal_h) // 2)
                modal_x = max(0, (max_x - 50) // 2)

                # Clear modal area
                for r in range(max_y):
                    stdscr.addstr(r, 0, " " * (max_x - 1))

                stdscr.addstr(modal_y, modal_x, " REMOVE USER RULE ", curses.color_pair(self.C_ALERT) | curses.A_BOLD)
                stdscr.addstr(modal_y + 1, modal_x, "─" * 48, curses.color_pair(self.C_ALERT))

                display_count = min(len(user_patterns), modal_h - 5)
                if display_count < 1:
                    display_count = 1

                if selected_idx < scroll_offset:
                    scroll_offset = selected_idx
                elif selected_idx >= scroll_offset + display_count:
                    scroll_offset = selected_idx - display_count + 1

                for i in range(display_count):
                    list_idx = scroll_offset + i
                    if list_idx >= len(user_patterns):
                        break
                    y = modal_y + 2 + i
                    idx_str = f"  {list_idx + 1:>3}. "
                    line = f"{idx_str}{user_patterns[list_idx]}"[:max_x - modal_x - 2]
                    if list_idx == selected_idx:
                        stdscr.addstr(y, modal_x, line[:max_x - modal_x - 1], curses.color_pair(self.C_ALERT) | curses.A_REVERSE | curses.A_BOLD)
                    else:
                        stdscr.addstr(y, modal_x, line[:max_x - modal_x - 1], curses.color_pair(self.C_DEFAULT))

                footer_y = modal_y + display_count + 2
                if footer_y < max_y - 1:
                    stdscr.addstr(footer_y, modal_x, " [Enter] Remove   [Esc] Cancel ", curses.color_pair(self.C_WARN))

                stdscr.refresh()

                key = stdscr.getch()
                if key in (curses.KEY_UP, ord("k")):
                    selected_idx = max(0, selected_idx - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    selected_idx = min(len(user_patterns) - 1, selected_idx + 1)
                elif key in (curses.KEY_ENTER, 10, 13):
                    chosen = user_patterns[selected_idx]
                    removed = self.config.remove_user_pattern(chosen)
                    if removed:
                        self.detector.reload_rules()
                        user_patterns = self.config.raw_config.get("user_patterns", [])
                        self.set_status(f"Removed rule: {chosen}")
                        break
                    else:
                        self.set_status(f"Failed to remove: {chosen}")
                elif key in (27, ord("q")):
                    break

            stdscr.timeout(100)

        elif key in (ord("m"), ord("M")):
            # Toggle dry-run / live mode
            is_dry, status_msg = self.firewall.toggle_dry_run()
            self.set_status(status_msg)

        elif key in (ord("p"), ord("P")):
            self.paused = not self.paused
            self.set_status("Stream PAUSED" if self.paused else "Stream RESUMED")

        elif key in (ord("c"), ord("C")):
            # Clear expired / unbanned records from memory
            self.firewall.active_bans = {
                ip: b for ip, b in self.firewall.active_bans.items() if not b.is_expired
            }
            self.set_status("Cleaned expired records from display.")

        elif key in (ord("i"), ord("I")):
            # Show copyright / about modal
            self._show_about_modal(stdscr)

    def _show_about_modal(self, stdscr) -> None:
        """Display copyright / about information modal."""
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 12 or max_x < 50:
            self.set_status("Screen too small for info panel.")
            return

        # Store current state
        prev_running = self.running
        prev_status = self.status_msg

        # Draw overlay background
        for r in range(max_y):
            stdscr.addstr(r, 0, " " * (max_x - 1), curses.color_pair(self.C_MUTED))

        # Title
        title = " ABOUT UTILSEC SENTINEL "
        border_line = "─" * (len(title) + 2)
        stdscr.addstr(max_y // 2 - 6, 0, " " * (max_x - 1))
        stdscr.addstr(max_y // 2 - 6, (max_x - len(title)) // 2, f" {title} ", curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(max_y // 2 - 5, (max_x - len(border_line)) // 2, border_line, curses.color_pair(self.C_INFO))

        lines = [
            "",
            "  UtilSec Sentinel - Real-time Web Security Monitor",
            "  & Automatic Firewall Ban Tool",
            "",
            "  Developed by Sientia Open Source Labs",
            "  https://github.com/sientia",
            "",
            "  Licensed under GNU Affero General Public License v3.0 (AGPL-3.0)",
            "  Copyright (C) 2025-2026 Sientia Open Source Labs",
            "",
            "  This is free software: you are free to change and redistribute it",
            "  under the terms of the AGPL-3.0 license.",
            "",
            "  Support open source development:",
            "  Patreon:  https://www.patreon.com/cw/sientia",
            "  Buy Me:   https://buymeacoffee.com/sientia",
            "",
            "  Press [Esc] or [I] to close",
        ]

        start_y = max_y // 2 - 4
        for i, line in enumerate(lines):
            y = start_y + i
            if 0 <= y < max_y - 1:
                x = (max_x - len(line)) // 2
                if x < 1:
                    x = 1
                if len(line) > max_x - 2:
                    line = line[: max_x - 4] + ".."
                attr = curses.color_pair(self.C_DEFAULT)
                if "Sientia Open Source Labs" in line:
                    attr = curses.color_pair(self.C_SUCCESS) | curses.A_BOLD
                elif "AGPL-3.0" in line:
                    attr = curses.color_pair(self.C_WARN) | curses.A_BOLD
                elif "Patreon" in line or "Buy Me" in line:
                    attr = curses.color_pair(self.C_INFO)
                stdscr.addstr(y, x, line, attr)

        stdscr.refresh()

        # Wait for escape or 'i' to close
        while True:
            ch = stdscr.getch()
            if ch in (27, ord("i"), ord("I")):
                break

        # Restore state
        self.status_msg = prev_status
        self.running = prev_running

    def _show_unban_modal(self, stdscr) -> None:
        """Display interactive modal to unban an IP from the firewall ban list."""
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 12 or max_x < 50:
            self.set_status("Screen too small for unban panel.")
            return

        prev_running = self.running
        prev_status = self.status_msg
        bans = self.firewall.get_active_bans_list()
        selected_idx = 0
        scroll_offset = 0

        while True:
            stdscr.erase()
            stdscr.bkgd(' ', curses.color_pair(self.C_DEFAULT))

            # Calculate modal dimensions
            modal_h = min(len(bans) + 10, max_y - 4)
            modal_w = min(80, max_x - 4)
            start_y = (max_y - modal_h) // 2
            start_x = (max_x - modal_w) // 2

            # Draw modal background
            for r in range(modal_h):
                for c in range(modal_w):
                    if 0 <= start_y + r < max_y and 0 <= start_x + c < max_x:
                        stdscr.addch(start_y + r, start_x + c, ' ', curses.color_pair(self.C_MUTED))

            # Title
            title = " UNBAN FROM FIREWALL "
            border_line = "─" * len(title)
            stdscr.addstr(start_y, start_x + (len(border_line) - len(title)) // 2,
                          f" {title} ", curses.color_pair(self.C_HEADER) | curses.A_BOLD)
            stdscr.addstr(start_y + 1, start_x + (len(border_line) - len(border_line)) // 2,
                          border_line, curses.color_pair(self.C_INFO))

            # Column widths
            col_ip = 18
            col_reason = 30
            col_status = 8
            col_hits = 5

            # Column headers
            hdr_row = start_y + 3
            stdscr.addstr(hdr_row, start_x + 1, 
                          f"  {'#':>4} {'IP/NET':<{col_ip}} {'REASON':<{col_reason}} {'HITS':>{col_hits}}  {'STATUS':<{col_status}}",
                          curses.color_pair(self.C_INFO) | curses.A_UNDERLINE)
            
            # Instructions
            instr_y = start_y + 4
            stdscr.addstr(instr_y, start_x + 2, "↑/↓ Navigate  Enter Unban  [Esc] Cancel  [M] Manual",
                          curses.color_pair(self.C_MUTED))

            # List bans with scroll
            list_start_y = start_y + 6
            display_count = min(len(bans), modal_h - 9)
            
            # Adjust scroll offset to keep selected item visible
            if selected_idx < scroll_offset:
                scroll_offset = selected_idx
            elif selected_idx >= scroll_offset + display_count:
                scroll_offset = selected_idx - display_count + 1

            for i in range(display_count):
                list_idx = scroll_offset + i
                if list_idx < len(bans):
                    ban = bans[list_idx]
                    reason_disp = ban.reason[:col_reason]
                    if len(ban.reason) > col_reason:
                        reason_disp += ".."
                    line = f"  {list_idx + 1:>4}. {ban.ip:<{col_ip}} {reason_disp:<{col_reason}} {ban.attack_count:>{col_hits}}  {ban.status:<{col_status}}"
                    if len(line) > modal_w - 2:
                        line = line[:modal_w - 4] + ".."
                    y = list_start_y + i
                    if 0 <= y < max_y - 1:
                        if list_idx == selected_idx:
                            stdscr.addstr(y, start_x + 1, f" {line} ",
                                          curses.color_pair(self.C_WARN) | curses.A_BOLD)
                        else:
                            stdscr.addstr(y, start_x + 1, line, curses.color_pair(self.C_DEFAULT))

            # Show scroll indicator
            if len(bans) > display_count:
                scroll_info = f"  [{selected_idx + 1}/{len(bans)}] Page {scroll_offset // display_count + 1}"
                stdscr.addstr(list_start_y + display_count, start_x + 1, scroll_info,
                              curses.color_pair(self.C_MUTED))

            # If no bans, show message
            if not bans:
                msg = "  No active bans in firewall"
                stdscr.addstr(list_start_y, start_x + 2, msg, curses.color_pair(self.C_MUTED))

            # Manual input hint
            hint_y = list_start_y + display_count + 1
            if hint_y < max_y - 1:
                stdscr.addstr(hint_y, start_x + 2, "[M] Enter IP manually to unban",
                              curses.color_pair(self.C_INFO))

            stdscr.refresh()

            # Wait for key
            stdscr.nodelay(False)
            ch = stdscr.getch()
            stdscr.nodelay(True)

            if ch == 27:
                # Escape — cancel
                break
            elif ch == curses.KEY_UP:
                if selected_idx > 0:
                    selected_idx -= 1
            elif ch == curses.KEY_DOWN:
                if selected_idx < len(bans) - 1:
                    selected_idx += 1
            elif ch == curses.KEY_PPAGE:
                # Page Up
                selected_idx = max(0, selected_idx - display_count)
            elif ch == curses.KEY_NPAGE:
                # Page Down
                selected_idx = min(len(bans) - 1, selected_idx + display_count)
            elif ch == curses.KEY_HOME:
                selected_idx = 0
            elif ch == curses.KEY_END:
                selected_idx = len(bans) - 1
            elif ch in (10, 13, 27 - 64, curses.KEY_ENTER):
                # Enter — unban selected IP
                if bans:
                    target_ip = bans[selected_idx].ip
                    self.firewall.unban_ip(target_ip, manual=True)
                    self.status_msg = f"Unbanned: {target_ip}"
                    break
            elif ch in (ord("m"), ord("M")):
                # Manual input mode
                stdscr.nodelay(False)
                stdscr.erase()
                stdscr.bkgd(' ', curses.color_pair(self.C_DEFAULT))

                manual_title = " MANUAL UNBAN "
                manual_border = "─" * len(manual_title)
                stdscr.addstr(start_y, start_x + (len(manual_border) - len(manual_title)) // 2,
                              f" {manual_title} ", curses.color_pair(self.C_WARN) | curses.A_BOLD)
                stdscr.addstr(start_y + 1, start_x + (len(manual_border) - len(manual_border)) // 2,
                              manual_border, curses.color_pair(self.C_INFO))

                prompt_line = "  Enter IP or Subnet to UNBAN (e.g. 1.2.3.4 or 1.2.3.0/24):"
                stdscr.addstr(start_y + 3, start_x + 1, prompt_line, curses.color_pair(self.C_INFO))
                stdscr.addstr(start_y + 4, start_x + 1, "  " + "_" * 40, curses.color_pair(self.C_MUTED))
                stdscr.refresh()

                # Read input
                input_val = ""
                cursor_y = start_y + 4
                cursor_x = start_x + 3
                while True:
                    stdscr.nodelay(False)
                    ch = stdscr.getch()
                    stdscr.nodelay(True)

                    if ch in (27, 10, 13, curses.KEY_ENTER):
                        # Escape or Enter to confirm
                        break
                    elif ch in (curses.KEY_BACKSPACE, 127, 8):
                        if input_val:
                            input_val = input_val[:-1]
                    elif 32 <= ch <= 126:
                        input_val += chr(ch)

                    # Update display
                    stdscr.addstr(cursor_y, cursor_x, input_val.ljust(40)[:40] + " ",
                                  curses.color_pair(self.C_SUCCESS) | curses.A_BOLD)
                    stdscr.refresh()

                if input_val:
                    result = self.firewall.unban_ip(input_val, manual=True)
                    if result:
                        self.status_msg = f"Unbanned: {input_val}"
                    else:
                        self.status_msg = f"No active ban found for: {input_val}"
                    break

        # Restore state
        self.status_msg = prev_status
        self.running = prev_running

    def _show_external_rules_panel(self, stdscr) -> None:
        """Display external firewall rules (fail2ban, manual) not managed by UtilSec.
        
        Shows rules that were created by fail2ban or manual iptables/ufw commands.
        Allows unban via fail2ban-client for fail2ban rules, or direct iptables/ufw delete.
        """
        max_y, max_x = stdscr.getmaxyx()
        if max_y < 12 or max_x < 70:
            self.set_status("Screen too small for external rules panel.")
            return

        prev_running = self.running
        prev_status = self.status_msg

        # Get external firewall rules (fail2ban, manual)
        fw_rules = self.firewall.get_firewall_rules()
        selected_idx = 0
        scroll_offset = 0

        while True:
            stdscr.erase()
            stdscr.bkgd(' ', curses.color_pair(self.C_DEFAULT))

            # Calculate modal dimensions
            modal_h = min(len(fw_rules) + 10, max_y - 4)
            modal_w = min(80, max_x - 4)
            start_y = (max_y - modal_h) // 2
            start_x = (max_x - modal_w) // 2

            # Draw modal background
            for r in range(modal_h):
                for c in range(modal_w):
                    if 0 <= start_y + r < max_y and 0 <= start_x + c < max_x:
                        stdscr.addch(start_y + r, start_x + c, ' ', curses.color_pair(self.C_MUTED))

            # Title
            title = " EXTERNAL FIREWALL RULES "
            border_line = "─" * len(title)
            stdscr.addstr(start_y, start_x + (len(border_line) - len(title)) // 2,
                          f" {title} ", curses.color_pair(self.C_HEADER) | curses.A_BOLD)
            stdscr.addstr(start_y + 1, start_x + (len(border_line) - len(border_line)) // 2,
                          border_line, curses.color_pair(self.C_INFO))

            # Column widths
            col_ip = 18
            col_source = 12
            col_reason = 28
            col_rule = 5

            # Column headers
            hdr_row = start_y + 3
            stdscr.addstr(hdr_row, start_x + 1,
                          f"  {'#':>4} {'IP/NET':<{col_ip}} {'SOURCE':<{col_source}} {'REASON':<{col_reason}} {'RULE':>{col_rule}}",
                          curses.color_pair(self.C_INFO) | curses.A_UNDERLINE)

            # Instructions
            instr_y = start_y + 4
            stdscr.addstr(instr_y, start_x + 2,
                          "↑/↓ Navigate  Enter Unban  [Esc] Cancel  [F]ail2ban  [I]ptables",
                          curses.color_pair(self.C_MUTED))

            # List rules with scroll
            list_start_y = start_y + 6
            display_count = min(len(fw_rules), modal_h - 9)

            # Adjust scroll offset
            if selected_idx < scroll_offset:
                scroll_offset = selected_idx
            elif selected_idx >= scroll_offset + display_count:
                scroll_offset = selected_idx - display_count + 1

            for i in range(display_count):
                list_idx = scroll_offset + i
                if list_idx < len(fw_rules):
                    rule = fw_rules[list_idx]
                    source_disp = rule.source.upper()[:col_source]
                    reason_disp = rule.reason[:col_reason]
                    if len(rule.reason) > col_reason:
                        reason_disp += ".."
                    line = f"  {list_idx + 1:>4}. {rule.ip:<{col_ip}} {source_disp:<{col_source}} {reason_disp:<{col_reason}} {rule.rule_num:>{col_rule}}"
                    if len(line) > modal_w - 2:
                        line = line[:modal_w - 4] + ".."
                    y = list_start_y + i
                    if 0 <= y < max_y - 1:
                        if list_idx == selected_idx:
                            stdscr.addstr(y, start_x + 1, f" {line} ",
                                          curses.color_pair(self.C_WARN) | curses.A_BOLD)
                        else:
                            stdscr.addstr(y, start_x + 1, line, curses.color_pair(self.C_DEFAULT))

            # Show scroll indicator
            if len(fw_rules) > display_count:
                scroll_info = f"  [{selected_idx + 1}/{len(fw_rules)}] Page {scroll_offset // display_count + 1}"
                stdscr.addstr(list_start_y + display_count, start_x + 1, scroll_info,
                              curses.color_pair(self.C_MUTED))

            # If no rules, show message
            if not fw_rules:
                msg = "  No external firewall rules detected"
                stdscr.addstr(list_start_y, start_x + 2, msg, curses.color_pair(self.C_MUTED))

            # Status hint
            hint_y = list_start_y + display_count + 1
            if hint_y < max_y - 1:
                stdscr.addstr(hint_y, start_x + 2,
                              f"Rules detected: {len(fw_rules)} (fail2ban/manual only)",
                              curses.color_pair(self.C_INFO))

            stdscr.refresh()

            # Wait for key
            stdscr.nodelay(False)
            ch = stdscr.getch()
            stdscr.nodelay(True)

            if ch == 27:
                # Escape — cancel
                break
            elif ch == curses.KEY_UP:
                if selected_idx > 0:
                    selected_idx -= 1
            elif ch == curses.KEY_DOWN:
                if selected_idx < len(fw_rules) - 1:
                    selected_idx += 1
            elif ch == curses.KEY_PPAGE:
                selected_idx = max(0, selected_idx - display_count)
            elif ch == curses.KEY_NPAGE:
                selected_idx = min(len(fw_rules) - 1, selected_idx + display_count)
            elif ch == curses.KEY_HOME:
                selected_idx = 0
            elif ch == curses.KEY_END:
                selected_idx = len(fw_rules) - 1
            elif ch in (10, 13, 27 - 64, curses.KEY_ENTER):
                # Enter — unban selected rule
                if fw_rules:
                    rule = fw_rules[selected_idx]
                    success = False

                    if rule.source == "fail2ban":
                        success = self.firewall.unban_fail2ban(rule.ip, rule.jail_name)
                        if success:
                            self.status_msg = f"Unbanned {rule.ip} from fail2ban jail {rule.jail_name}"
                        else:
                            self.status_msg = f"Failed to unban {rule.ip} from fail2ban"
                    elif rule.source == "manual":
                        success = self.firewall.unban_manual_rule(rule.ip, rule.rule_num, rule.backend)
                        if success:
                            self.status_msg = f"Removed manual rule {rule.rule_num} for {rule.ip}"
                        else:
                            self.status_msg = f"Failed to remove manual rule for {rule.ip}"

                    # Refresh the list
                    fw_rules = self.firewall.get_firewall_rules()
                    if selected_idx >= len(fw_rules):
                        selected_idx = max(0, len(fw_rules) - 1)
                    continue
            elif ch in (ord("f"), ord("F")):
                # Force fail2ban unban for selected rule
                if fw_rules:
                    rule = fw_rules[selected_idx]
                    jail_name = self._prompt_input(stdscr, f"Enter fail2ban jail name for {rule.ip}: ")
                    if jail_name:
                        success = self.firewall.unban_fail2ban(rule.ip, jail_name.strip())
                        if success:
                            self.status_msg = f"Unbanned {rule.ip} from jail {jail_name.strip()}"
                        else:
                            self.status_msg = f"Failed to unban {rule.ip} from jail {jail_name.strip()}"
                        # Refresh
                        fw_rules = self.firewall.get_firewall_rules()
            elif ch in (ord("i"), ord("I")):
                # Force iptables/ufw delete for selected rule
                if fw_rules:
                    rule = fw_rules[selected_idx]
                    success = self.firewall.unban_manual_rule(rule.ip, rule.rule_num, rule.backend)
                    if success:
                        self.status_msg = f"Removed rule {rule.rule_num} ({rule.backend}) for {rule.ip}"
                    else:
                        self.status_msg = f"Failed to remove rule for {rule.ip}"
                    # Refresh
                    fw_rules = self.firewall.get_firewall_rules()

        # Restore state
        self.status_msg = prev_status
        self.running = prev_running

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

    def _update_stats_async(self) -> None:
        """Updates statistics in background thread to avoid blocking TUI."""
        if self._stats_loading:
            return
        if self._analytics_lock.locked():
            return

        def _fetch():
            with self._analytics_lock:
                self._stats_loading = True
            try:
                all_attacks: Deque[AttackEvent] = deque()
                all_attacks.extend(self.recent_attacks)
                for dq in self.screen_attacks.values():
                    all_attacks.extend(dq)

                analytics = AttackAnalytics(
                    detector=self.detector,
                    recent_attacks=self.recent_attacks,
                    screen_attacks=self.screen_attacks,
                )

                if len(all_attacks) == 0:
                    stats = {
                        "overall": analytics.get_overall_stats(),
                        "categories": [],
                        "top_ips": [],
                        "top_rules": [],
                        "hourly": {},
                        "geolocation": [],
                        "empty": True,
                    }
                else:
                    stats = {
                        "overall": analytics.get_overall_stats(),
                        "categories": analytics.get_category_breakdown(),
                        "top_ips": analytics.get_top_ips(),
                        "top_rules": analytics.get_top_rules(),
                        "hourly": analytics.get_hourly_evolution(),
                        "geolocation": analytics.get_geolocation_stats(),
                        "empty": False,
                    }
                with self._analytics_lock:
                    self._stats_data = stats
                    self._stats_loading = False
            except Exception as e:
                with self._analytics_lock:
                    self._stats_loading = False
                    self._stats_data = {"error": str(e), "empty": True}

        import threading
        t = threading.Thread(target=_fetch, daemon=True)
        t.start()

    def _draw_stats_screen(self, stdscr, max_y: int, max_x: int) -> None:
        """Draws the dedicated statistics screen."""
        stdscr.erase()

        # Header
        title = " UTILSEC SENTINEL - ESTADÍSTICAS "
        mode_str = f"[SIMULACIÓN]" if self.firewall.dry_run else f"[EN VIVO: {self.firewall.active_backend.upper()}]"
        stdscr.attron(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, " " * (max_x - 1))
        stdscr.addstr(0, 2, title)
        stdscr.attroff(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, max_x - len(mode_str) - 2, mode_str, curses.color_pair(self.C_WARN) | curses.A_BOLD)

        # Separator
        stdscr.addstr(1, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        # Help bar
        help_text = " [ESC] Cerrar  [E] Actualizar "
        stdscr.addstr(max_y - 2, 0, " " * (max_x - 1), curses.color_pair(self.C_MUTED))
        stdscr.addstr(max_y - 2, 2, help_text, curses.color_pair(self.C_MUTED) | curses.A_BOLD)

        # Check for error or loading
        with self._analytics_lock:
            data = self._stats_data

        if data is None or self._stats_loading:
            loading_text = " Cargando estadísticas..."
            stdscr.addstr(3, 2, loading_text, curses.color_pair(self.C_INFO) | curses.A_BOLD)
            stdscr.refresh()
            return

        if "error" in data:
            err_text = f" Error: {data['error']}"
            stdscr.addstr(3, 2, err_text, curses.color_pair(self.C_ALERT))
            stdscr.refresh()
            return

        # Draw full-screen stats
        self._draw_stats_screen_full(stdscr, max_y, max_x)

    def _draw_stats_column(self, stdscr, data, start_y, start_x, max_w, max_h, left: bool) -> None:
        """Draws one column of the statistics screen."""
        y = start_y
        available_h = max_h - 1

        # Overall stats
        overall = data.get("overall", {})
        total_analyzed = overall.get("total_analyzed", 0)
        total_attacks = overall.get("total_attacks", 0)
        attack_rate = overall.get("attack_rate", 0.0)
        total_404 = overall.get("total_404s", 0)
        total_403 = overall.get("total_403s", 0)

        box_h = min(6, available_h)
        if box_h < 4:
            return

        # Box header
        header_text = " RESUMEN GENERAL "
        stdscr.attron(curses.color_pair(self.C_INFO) | curses.A_BOLD)
        stdscr.addstr(start_y, start_x, " " * max_w)
        if left:
            stdscr.addstr(start_y, start_x + 1, header_text)
        else:
            center_x = start_x + (max_w - len(header_text)) // 2
            stdscr.addstr(start_y, center_x, header_text)
        stdscr.attroff(curses.color_pair(self.C_INFO) | curses.A_BOLD)

        # Box border
        for i in range(1, box_h):
            if start_y + i <= start_y + box_h - 1:
                stdscr.addstr(start_y + i, start_x, "│", curses.color_pair(self.C_MUTED))
                if start_x + max_w - 1 < 200:
                    stdscr.addstr(start_y + i, start_x + max_w - 1, "│", curses.color_pair(self.C_MUTED))

        # Bottom border
        stdscr.addstr(start_y + box_h - 1, start_x, "─" * max_w, curses.color_pair(self.C_MUTED))

        # Stats lines
        stat_lines = [
            (f"Peticiones analizadas: {total_analyzed:,}", self.C_DEFAULT),
            (f"Ataques detectados:    {total_attacks:,}", self.C_ALERT if total_attacks > 0 else self.C_DEFAULT),
            (f"Tasa de ataque:        {attack_rate:.1f}%", self.C_WARN if attack_rate > 10 else self.C_SUCCESS),
            (f"Errores 404:           {total_404:,}", self.C_DEFAULT),
            (f"Errores 403:           {total_403:,}", self.C_DEFAULT),
        ]

        for i, (text, color) in enumerate(stat_lines):
            ly = start_y + i + 1
            if ly < start_y + box_h - 1:
                stdscr.addstr(ly, start_x + 1, text[:max_w - 2], color)

        # Category breakdown (if space)
        categories = data.get("categories", [])
        if categories and available_h > box_h + 2:
            cat_y = start_y + box_h + 1
            cat_h = min(8, available_h - (cat_y - start_y))
            if cat_h >= 3:
                cat_header = " CATEGORÍAS "
                stdscr.attron(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                stdscr.addstr(cat_y, start_x, " " * max_w)
                if left:
                    stdscr.addstr(cat_y, start_x + 1, cat_header)
                else:
                    center_x = start_x + (max_w - len(cat_header)) // 2
                    stdscr.addstr(cat_y, center_x, cat_header)
                stdscr.attroff(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                stdscr.addstr(cat_y + cat_h - 1, start_x, "─" * max_w, curses.color_pair(self.C_MUTED))

                cat_colors = {
                    "credentials": self.C_ALERT,
                    "webshell": self.C_ALERT,
                    "traversal": self.C_ALERT,
                    "rate_limit": self.C_WARN,
                    "heuristic": self.C_WARN,
                    "user": self.C_WARN,
                    "forbidden": self.C_INFO,
                    "probe": self.C_DEFAULT,
                }

                for i, (cat, count, pct) in enumerate(categories[:cat_h - 2]):
                    cy = cat_y + i + 1
                    if cy < cat_y + cat_h - 1:
                        cat_label = cat.replace("_", " ").title()
                        pct_str = f"{pct:.1f}%"
                        bar_len = max(5, int(pct * (max_w - 40) / 100))
                        bar = "█" * bar_len
                        color = cat_colors.get(cat, self.C_DEFAULT)
                        line = f"  {cat_label:<18s} {count:>6d}  {pct_str:>6s}  {bar}"
                        stdscr.addstr(cy, start_x + 1, line[:max_w - 2], color)

        # Top IPs (if space and right column)
        if not left:
            top_ips = data.get("top_ips", [])
            if top_ips and available_h > box_h + 2:
                ip_y = start_y + box_h + 1
                ip_h = min(8, available_h - (ip_y - start_y))
                if ip_h >= 3:
                    ip_header = " TOP 10 IPs "
                    stdscr.attron(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                    stdscr.addstr(ip_y, start_x, " " * max_w)
                    stdscr.addstr(ip_y, start_x + 1, ip_header)
                    stdscr.attroff(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                    stdscr.addstr(ip_y + ip_h - 1, start_x, "─" * max_w, curses.color_pair(self.C_MUTED))

                    for i, (ip, count, pct) in enumerate(top_ips[:ip_h - 2]):
                        iy = ip_y + i + 1
                        if iy < ip_y + ip_h - 1:
                            pct_str = f"{pct:.1f}%"
                            line = f"  {ip:<22s} {count:>6d}  {pct_str:>6s}"
                            stdscr.addstr(iy, start_x + 1, line[:max_w - 2], self.C_ALERT)

        # Geolocation (if space and left column)
        if left:
            geo = data.get("geolocation", [])
            if geo and available_h > box_h + 2:
                geo_y = start_y + box_h + 1
                geo_h = min(8, available_h - (geo_y - start_y))
                if geo_h >= 3:
                    geo_header = " GEOLOCALIZACIÓN "
                    stdscr.attron(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                    stdscr.addstr(geo_y, start_x, " " * max_w)
                    stdscr.addstr(geo_y, start_x + 1, geo_header)
                    stdscr.attroff(curses.color_pair(self.C_INFO) | curses.A_BOLD)
                    stdscr.addstr(geo_y + geo_h - 1, start_x, "─" * max_w, curses.color_pair(self.C_MUTED))

                    for i, (country, count, pct, ips) in enumerate(geo[:geo_h - 2]):
                        gy = geo_y + i + 1
                        if gy < geo_y + geo_h - 1:
                            pct_str = f"{pct:.1f}%"
                            ip_count = len(ips) if ips else 0
                            line = f"  {country:<6s} {count:>6d}  {pct_str:>6s}  {ip_count} IPs"
                            stdscr.addstr(gy, start_x + 1, line[:max_w - 2], self.C_WARN)

    def _draw_stats_screen_full(self, stdscr, max_y: int, max_x: int) -> None:
        """Fallback: draws statistics in full-screen single column mode."""
        stdscr.erase()

        title = " UTILSEC SENTINEL - ESTADÍSTICAS "
        mode_str = f"[SIMULACIÓN]" if self.firewall.dry_run else f"[EN VIVO: {self.firewall.active_backend.upper()}]"
        stdscr.attron(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, 0, " " * (max_x - 1))
        stdscr.addstr(0, 2, title)
        stdscr.attroff(curses.color_pair(self.C_HEADER) | curses.A_BOLD)
        stdscr.addstr(0, max_x - len(mode_str) - 2, mode_str, curses.color_pair(self.C_WARN) | curses.A_BOLD)
        stdscr.addstr(1, 0, "─" * (max_x - 1), curses.color_pair(self.C_MUTED))

        with self._analytics_lock:
            data = self._stats_data

        if data is None or self._stats_loading:
            stdscr.addstr(3, 2, " Cargando estadísticas...", curses.color_pair(self.C_INFO) | curses.A_BOLD)
            stdscr.refresh()
            return

        help_text = " [ESC] Cerrar  [E] Actualizar "
        stdscr.addstr(max_y - 2, 0, " " * (max_x - 1), curses.color_pair(self.C_MUTED))
        stdscr.addstr(max_y - 2, 2, help_text, curses.color_pair(self.C_MUTED) | curses.A_BOLD)

        y = 3
        max_w = max_x - 4

        if "error" in data:
            stdscr.addstr(y, 2, f" Error: {data['error']}", curses.color_pair(self.C_ALERT))
            stdscr.refresh()
            return

        # Overall stats box
        overall = data.get("overall", {})
        box_h = min(7, max_y - 10)
        lines = [
            "── RESUMEN GENERAL ───────────────────────────────────────",
            f"  Peticiones analizadas: {overall.get('total_analyzed', 0):,}",
            f"  Ataques detectados:    {overall.get('total_attacks', 0):,}",
            f"  Tasa de ataque:        {overall.get('attack_rate', 0.0):.1f}%",
            f"  Errores 404:           {overall.get('total_404s', 0):,}",
            f"  Errores 403:           {overall.get('total_403s', 0):,}",
        ]
        for i, line in enumerate(lines[:box_h]):
            if y + i < max_y - 4:
                color = self.C_WARN if "Tasa" in line and float(overall.get("attack_rate", 0)) > 10 else self.C_DEFAULT
                stdscr.addstr(y + i, 1, line[:max_w], color)
        y += box_h + 1

        # Categories
        categories = data.get("categories", [])
        if categories:
            cat_h = min(10, max_y - y - 15)
            if cat_h > 0:
                stdscr.addstr(y, 1, "── CATEGORÍAS DE ATAQUE ─────────────────────────────────", curses.color_pair(self.C_INFO))
                y += 1
                cat_colors = {
                    "credentials": self.C_ALERT,
                    "webshell": self.C_ALERT,
                    "traversal": self.C_ALERT,
                    "rate_limit": self.C_WARN,
                    "heuristic": self.C_WARN,
                    "user": self.C_WARN,
                    "forbidden": self.C_INFO,
                    "probe": self.C_DEFAULT,
                }
                for cat, count, pct in categories[:cat_h]:
                    if y < max_y - 12:
                        cat_label = cat.replace("_", " ").title()
                        bar_len = max(3, int(pct * (max_w - 50) / 100))
                        bar = "█" * bar_len
                        color = cat_colors.get(cat, self.C_DEFAULT)
                        line = f"  {cat_label:<18s} {count:>6d}  {pct:>6.1f}%  {bar}"
                        stdscr.addstr(y, 2, line[:max_w], color)
                        y += 1
                y += 1

        # Top IPs
        top_ips = data.get("top_ips", [])
        if top_ips:
            ip_h = min(10, max_y - y - 12)
            if ip_h > 0:
                stdscr.addstr(y, 1, "── TOP 10 IPs ATACANTES ─────────────────────────────────", curses.color_pair(self.C_INFO))
                y += 1
                for ip, count, pct in top_ips[:ip_h]:
                    if y < max_y - 10:
                        pct_str = f"{pct:.1f}%"
                        line = f"  {ip:<22s} {count:>6d}  {pct_str:>6s}"
                        stdscr.addstr(y, 2, line[:max_w], self.C_ALERT)
                        y += 1
                y += 1

        # Geolocation
        geo = data.get("geolocation", [])
        if geo:
            geo_h = min(10, max_y - y - 8)
            if geo_h > 0:
                stdscr.addstr(y, 1, "── GEOLOCALIZACIÓN POR PAÍS ─────────────────────────────", curses.color_pair(self.C_INFO))
                y += 1
                for country, count, pct, ips in geo[:geo_h]:
                    if y < max_y - 6:
                        pct_str = f"{pct:.1f}%"
                        ip_count = len(ips) if ips else 0
                        line = f"  {country:<6s} {count:>6d}  {pct_str:>6s}  {ip_count} IPs únicas"
                        stdscr.addstr(y, 2, line[:max_w], self.C_WARN)
                        y += 1

        # Top rules
        top_rules = data.get("top_rules", [])
        if top_rules:
            rule_h = min(8, max_y - y - 4)
            if rule_h > 0:
                stdscr.addstr(y, 1, "── TOP 10 REGLAS MÁS ACTIVAS ────────────────────────────", curses.color_pair(self.C_INFO))
                y += 1
                for rule, count, pct in top_rules[:rule_h]:
                    if y < max_y - 3:
                        pct_str = f"{pct:.1f}%"
                        line = f"  {rule:<30s} {count:>6d}  {pct_str:>6s}"
                        stdscr.addstr(y, 2, line[:max_w], self.C_SUCCESS)
                        y += 1

        stdscr.refresh()
