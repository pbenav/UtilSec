"""SQLite persistence layer for bans, events, and audit logs."""

import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from core.models import AttackEvent, BanRecord


class StorageManager:
    """Manages SQLite database for persistence across runs."""

    def __init__(self, db_path: str = "sentinel_history.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10.0)

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    matched_pattern TEXT,
                    attack_count INTEGER,
                    banned_at REAL,
                    ban_duration INTEGER,
                    status TEXT,
                    backend TEXT,
                    last_url TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    ip TEXT,
                    method TEXT,
                    url TEXT,
                    status_code INTEGER,
                    matched_rule TEXT,
                    category TEXT,
                    source_log TEXT
                )
            """)
            # Auto-migrate if source_log column does not exist
            cursor.execute("PRAGMA table_info(events)")
            cols = [r[1] for r in cursor.fetchall()]
            if "source_log" not in cols:
                try:
                    cursor.execute("ALTER TABLE events ADD COLUMN source_log TEXT")
                except Exception:
                    pass

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events (timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src ON events (source_log)")

            # Log configuration persistence
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS log_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)

            conn.commit()

    def save_ban(self, ban: BanRecord) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO bans (ip, reason, matched_pattern, attack_count, banned_at, ban_duration, status, backend, last_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason=excluded.reason,
                    matched_pattern=excluded.matched_pattern,
                    attack_count=excluded.attack_count,
                    banned_at=excluded.banned_at,
                    ban_duration=excluded.ban_duration,
                    status=excluded.status,
                    backend=excluded.backend,
                    last_url=excluded.last_url
            """, (
                ban.ip, ban.reason, ban.matched_pattern, ban.attack_count,
                ban.banned_at, ban.ban_duration, ban.status, ban.backend, ban.last_url
            ))
            conn.commit()

    def update_ban_status(self, ip: str, status: str) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE bans SET status = ? WHERE ip = ?", (status, ip))
            conn.commit()

    def load_active_bans(self) -> Dict[str, BanRecord]:
        active_bans: Dict[str, BanRecord] = {}
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, reason, matched_pattern, attack_count, banned_at, ban_duration, status, backend, last_url FROM bans WHERE status IN ('BANNED', 'SIMULATED')")
            for row in cursor.fetchall():
                ban = BanRecord(
                    ip=row[0],
                    reason=row[1],
                    matched_pattern=row[2],
                    attack_count=row[3],
                    banned_at=row[4],
                    ban_duration=row[5],
                    status=row[6],
                    backend=row[7],
                    last_url=row[8],
                )
                active_bans[ban.ip] = ban
        return active_bans

    def log_event(self, event: AttackEvent) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (timestamp, ip, method, url, status_code, matched_rule, category, source_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp.timestamp(),
                event.ip,
                event.method,
                event.url,
                event.status_code,
                event.matched_rule,
                event.category,
                event.source_log
            ))
            conn.commit()

    def load_recent_events(self, limit: int = 100, source_log: Optional[str] = None) -> List[AttackEvent]:
        events = []
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if source_log:
                cursor.execute("""
                    SELECT timestamp, ip, method, url, status_code, matched_rule, category, source_log
                    FROM events
                    WHERE source_log = ?
                    ORDER BY id DESC LIMIT ?
                """, (source_log, limit))
            else:
                cursor.execute("""
                    SELECT timestamp, ip, method, url, status_code, matched_rule, category, source_log
                    FROM events
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
            for row in cursor.fetchall():
                ev = AttackEvent(
                    timestamp=datetime.fromtimestamp(row[0]),
                    ip=row[1],
                    method=row[2],
                    url=row[3],
                    status_code=row[4],
                    matched_rule=row[5],
                    category=row[6],
                    source_log=row[7] if len(row) > 7 and row[7] else ""
                )
                events.append(ev)
        return events

    def get_stats(self) -> Dict[str, int]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM bans WHERE status IN ('BANNED', 'SIMULATED')")
            active_bans = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM bans")
            total_banned = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]
            return {
                "active_bans": active_bans,
                "total_banned": total_banned,
                "total_events": total_events
            }

    # --- Log Configuration Persistence ---

    def save_log_config(self, logs: List[Dict[str, str]]) -> None:
        """Persist the list of configured log files."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # Clear existing config
            cursor.execute("DELETE FROM log_config")
            # Insert all logs
            for item in logs:
                cursor.execute(
                    "INSERT INTO log_config (name, path, enabled) VALUES (?, ?, 1)",
                    (item.get("name", ""), item["path"])
                )
            conn.commit()

    def load_log_config(self) -> List[Dict[str, str]]:
        """Load persisted log configuration."""
        logs: List[Dict[str, str]] = []
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, path FROM log_config WHERE enabled = 1 ORDER BY created_at")
            for row in cursor.fetchall():
                logs.append({"name": row[0], "path": row[1]})
        return logs

    def add_log_config(self, name: str, path: str) -> bool:
        """Add a single log to the persisted configuration."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # Check if already exists
            cursor.execute("SELECT id FROM log_config WHERE path = ?", (path,))
            existing = cursor.fetchone()
            if existing:
                # Update existing
                cursor.execute("UPDATE log_config SET name = ?, enabled = 1 WHERE id = ?", (name, existing[0]))
            else:
                cursor.execute(
                    "INSERT INTO log_config (name, path, enabled) VALUES (?, ?, 1)",
                    (name, path)
                )
            conn.commit()
            return True

    def remove_log_config(self, path: str) -> bool:
        """Remove a log from the persisted configuration."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE log_config SET enabled = 0 WHERE path = ?", (path,))
            conn.commit()
            return cursor.rowcount > 0


