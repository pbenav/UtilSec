"""High-performance real-time log tailer and parser."""

import os
import re
import time
from typing import Callable, Generator, Optional, Tuple


class LogWatcher:
    """Follows and parses web server log files in real time."""

    def __init__(
        self,
        log_path: str,
        on_request: Callable[[str, str, str, int, str], None],
        replay_lines: int = 0,
    ):
        self.log_path = log_path
        self.on_request = on_request
        self.replay_lines = replay_lines
        self.running = True
        self.lines_processed = 0
        self.lines_per_sec = 0.0

        self._re_access = re.compile(
            r'^([0-9a-fA-F\.:]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Za-z]+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})\s+'
        )
        self._re_error = re.compile(
            r'\[client\s+([0-9a-fA-F\.:\[\]]+?)(?::\d+)?\]\s+(.*)'
        )

    def parse_line(self, line: str) -> Optional[Tuple[str, str, str, int]]:
        """Parses a log line into (ip, method, url, status_code)."""
        line = line.strip()
        if not line:
            return None

        # Clean null bytes if any
        if "\x00" in line:
            line = line.replace("\x00", "")

        # Try access log format first
        m = self._re_access.match(line)
        if m:
            ip, _date, method, url, status = m.groups()
            return ip, method.upper(), url, int(status)

        # Try Apache/FastCGI error log format
        m_err = self._re_error.search(line)
        if m_err:
            raw_ip, err_msg = m_err.groups()
            ip = self._clean_ip(raw_ip)
            # Error logs represent failed requests / attack probes
            return ip, "ERR", err_msg, 404

        return None

    def _clean_ip(self, s: str) -> str:
        s = s.strip()
        if ":" in s and "." in s:
            return s.split(":")[0]
        if s.startswith("[") and "]" in s:
            return s[1:s.index("]")]
        return s

    def run(self) -> None:
        """Main loop that follows the log file."""
        last_metric_time = time.time()
        last_metric_count = 0

        while self.running and not os.path.exists(self.log_path):
            time.sleep(0.5)

        if not self.running:
            return

        with open(self.log_path, "rb") as f:
            # Handle start position
            if self.replay_lines > 0:
                self._read_last_n_lines(f, self.replay_lines)
            elif self.replay_lines == 0:
                f.seek(0, os.SEEK_END)

            inode = os.fstat(f.fileno()).st_ino

            while self.running:
                raw_line = f.readline()
                if raw_line:
                    # Incomplete write: if line does not end with newline, wait for full line
                    if not raw_line.endswith(b"\n"):
                        f.seek(-len(raw_line), os.SEEK_CUR)
                        time.sleep(0.05)
                        continue

                    line = raw_line.decode("utf-8", errors="replace")
                    self.lines_processed += 1
                    parsed = self.parse_line(line)
                    if parsed:
                        ip, method, url, status = parsed
                        try:
                            self.on_request(ip, method, url, status, line)
                        except Exception:
                            pass

                    # Update throughput metric every second
                    now = time.time()
                    elapsed = now - last_metric_time
                    if elapsed >= 1.0:
                        count_diff = self.lines_processed - last_metric_count
                        self.lines_per_sec = count_diff / elapsed
                        last_metric_time = now
                        last_metric_count = self.lines_processed
                else:
                    # Check for log rotation or truncation
                    try:
                        cur_stat = os.stat(self.log_path)
                        if cur_stat.st_ino != inode or cur_stat.st_size < f.tell():
                            # File rotated or truncated, reopen
                            f.close()
                            f = open(self.log_path, "rb")
                            inode = os.fstat(f.fileno()).st_ino
                            continue
                    except Exception:
                        pass

                    time.sleep(0.05)

    def _read_last_n_lines(self, f, n: int, block_size: int = 65536) -> None:
        """Efficiently seeks backward to read the last n lines in binary mode."""
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        lines_found = []
        buffer = b""

        pos = file_size
        while pos > 0 and len(lines_found) <= n:
            read_size = min(block_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size)
            buffer = chunk + buffer
            lines = buffer.splitlines(keepends=True)
            if len(lines) > 1:
                buffer = lines[0]
                lines_found = lines[1:] + lines_found
            else:
                buffer = lines[0]

        if buffer:
            lines_found = [buffer] + lines_found

        target_lines = lines_found[-n:]
        for raw_line in target_lines:
            if not self.running:
                break
            line = raw_line.decode("utf-8", errors="replace")
            self.lines_processed += 1
            parsed = self.parse_line(line)
            if parsed:
                ip, method, url, status = parsed
                try:
                    self.on_request(ip, method, url, status, line)
                except Exception:
                    pass

        # Ensure file pointer is at the very end to watch for live new lines
        f.seek(0, os.SEEK_END)

    def stop(self) -> None:
        self.running = False

