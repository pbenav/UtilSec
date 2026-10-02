"""SQLite persistence layer for bans, events, and audit logs."""

import logging
import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from core.models import AttackEvent, BanRecord

logger = logging.getLogger("UtilSec.Storage")

DEFAULT_BATCH_SIZE = 200
DEFAULT_BATCH_MAX_AGE = 1.0


class StorageManager:
    """Manages SQLite database for persistence across runs.

    A single shared connection (WAL journal) is reused for the whole process
    and event inserts are written in batches. The previous implementation
    opened a connection and issued a ``COMMIT`` (two fsyncs) per event, which
    capped ingest at ~64 events/s and made the watcher threads the bottleneck
    exactly when an attack was generating the most events.

    Writes are buffered in memory; :meth:`flush` is called automatically before
    every read and on :meth:`close`, so readers always see their own writes.
    At most ``batch_size`` events can be lost on a hard kill (SIGKILL).
    """

    def __init__(
        self,
        db_path: str = "sentinel_history.db",
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_max_age: float = DEFAULT_BATCH_MAX_AGE,
    ):
        self.db_path = db_path
        self.batch_size = max(1, int(batch_size))
        self.batch_max_age = float(batch_max_age)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._pending: List[AttackEvent] = []
        self._pending_since = 0.0
        self._init_db()

    # ------------------------------------------------------------------
    # Connection management (callers must hold self._lock)
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        # WAL allows readers while a writer commits and removes the per-commit
        # fsync cost of the default rollback journal.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _get_conn(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is None:
                self._conn = self._connect()
            return self._conn

    def close(self) -> None:
        """Flush buffered events and release the database connection."""
        with self._lock:
            if self._conn is None:
                return
            try:
                self._flush_locked()
            finally:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def __enter__(self) -> "StorageManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Batched event ingestion
    # ------------------------------------------------------------------

    def log_event(self, event: AttackEvent) -> None:
        """Buffer an attack event; flushed in batches (cheap, non-blocking)."""
        with self._lock:
            if not self._pending:
                self._pending_since = time.time()
            self._pending.append(event)
            if len(self._pending) >= self.batch_size:
                self._flush_locked()
            elif (time.time() - self._pending_since) >= self.batch_max_age:
                self._flush_locked()

    def flush(self) -> None:
        """Force any buffered events to disk."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        self._pending_since = 0.0
        try:
            conn = self._get_conn()
            conn.executemany(
                """
                INSERT INTO events (timestamp, ip, method, url, status_code, matched_rule, category, source_log, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        ev.timestamp.timestamp(),
                        ev.ip,
                        ev.method,
                        ev.url,
                        ev.status_code,
                        ev.matched_rule,
                        ev.category,
                        ev.source_log,
                        getattr(ev, "country", "??"),
                    )
                    for ev in batch
                ],
            )
            conn.commit()
        except Exception as exc:
            logger.error("Failed to persist %d event(s): %s", len(batch), exc)
            # A failing commit must not stall the ingest loop (the log watcher
            # shares this lock); the batch is dropped rather than retried forever.

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
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
            conn.execute("""
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
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(events)")
            cols = [r[1] for r in cursor.fetchall()]
            if "source_log" not in cols:
                try:
                    cursor.execute("ALTER TABLE events ADD COLUMN source_log TEXT")
                except sqlite3.Error:
                    pass

            # Auto-migrate if country column does not exist in bans
            cursor.execute("PRAGMA table_info(bans)")
            cols = [r[1] for r in cursor.fetchall()]
            if "country" not in cols:
                try:
                    cursor.execute("ALTER TABLE bans ADD COLUMN country TEXT DEFAULT '??'")
                except Exception:
                    pass

            # Auto-migrate if country column does not exist in events
            cursor.execute("PRAGMA table_info(events)")
            cols = [r[1] for r in cursor.fetchall()]
            if "country" not in cols:
                try:
                    cursor.execute("ALTER TABLE events ADD COLUMN country TEXT DEFAULT '??'")
                except Exception:
                    pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events (timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src ON events (source_log)")

            # Log configuration persistence
            conn.execute("""
                CREATE TABLE IF NOT EXISTS log_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)

            conn.commit()

    # ------------------------------------------------------------------
    # Bans
    # ------------------------------------------------------------------

    def save_ban(self, ban: BanRecord) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO bans (ip, reason, matched_pattern, attack_count, banned_at, ban_duration, status, backend, last_url, country)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason=excluded.reason,
                    matched_pattern=excluded.matched_pattern,
                    attack_count=excluded.attack_count,
                    banned_at=excluded.banned_at,
                    ban_duration=excluded.ban_duration,
                    status=excluded.status,
                    backend=excluded.backend,
                    last_url=excluded.last_url,
                    country=excluded.country
            """, (
                ban.ip, ban.reason, ban.matched_pattern, ban.attack_count,
                ban.banned_at, ban.ban_duration, ban.status, ban.backend, ban.last_url,
                getattr(ban, "country", "??")
            ))
            conn.commit()

    def update_ban_status(self, ip: str, status: str) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("UPDATE bans SET status = ? WHERE ip = ?", (status, ip))
            conn.commit()

    def load_active_bans(self) -> Dict[str, BanRecord]:
        active_bans: Dict[str, BanRecord] = {}
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "SELECT ip, reason, matched_pattern, attack_count, banned_at, ban_duration, "
                "status, backend, last_url, country FROM bans "
                "WHERE status IN ('BANNED', 'SIMULATED')"
            )
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
                    country=row[9] if len(row) > 9 else "??",
                )
                active_bans[ban.ip] = ban
        return active_bans

    # ------------------------------------------------------------------
    # Events / analytics
    # ------------------------------------------------------------------

    def load_recent_events(self, limit: int = 100, source_log: Optional[str] = None) -> List[AttackEvent]:
        events = []
        with self._lock:
            self._flush_locked()
            conn = self._get_conn()
            if source_log:
                cursor = conn.execute("""
                    SELECT timestamp, ip, method, url, status_code, matched_rule, category, source_log, country
                    FROM events
                    WHERE source_log = ?
                    ORDER BY id DESC LIMIT ?
                """, (source_log, limit))
            else:
                cursor = conn.execute("""
                    SELECT timestamp, ip, method, url, status_code, matched_rule, category, source_log, country
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
                    source_log=row[7] if len(row) > 7 and row[7] else "",
                    country=row[8] if len(row) > 8 and row[8] else "??"
                )
                events.append(ev)
        return events

    def reset_stats(self) -> None:
        """Clears all attack events and statistics from the database (does not affect active bans or logs)."""
        with self._lock:
            self._flush_locked()
            try:
                conn = self._get_conn()
                conn.execute("DELETE FROM attack_events")
                conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Failed to reset stats in DB: {e}")

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            self._flush_locked()
            conn = self._get_conn()
            active_bans = conn.execute(
                "SELECT COUNT(*) FROM bans WHERE status IN ('BANNED', 'SIMULATED')"
            ).fetchone()[0]
            total_banned = conn.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            return {
                "active_bans": active_bans,
                "total_banned": total_banned,
                "total_events": total_events
            }

    def get_analytics_summary(self, top_n: int = 10, hours: int = 24) -> Dict:
        """Returns pre-aggregated analytics data directly from SQLite for high performance."""
        with self._lock:
            self._flush_locked()
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT ip) FROM events")
            unique_ips = cursor.fetchone()[0]

            cursor.execute("SELECT category, COUNT(*) FROM events WHERE category IS NOT NULL GROUP BY category ORDER BY 2 DESC")
            categories = [(row[0], row[1]) for row in cursor.fetchall()]

            cursor.execute("SELECT ip, COUNT(*) FROM events WHERE ip IS NOT NULL GROUP BY ip ORDER BY 2 DESC LIMIT ?", (top_n,))
            top_ips = [(row[0], row[1]) for row in cursor.fetchall()]

            cursor.execute("SELECT matched_rule, COUNT(*) FROM events WHERE matched_rule IS NOT NULL GROUP BY matched_rule ORDER BY 2 DESC LIMIT ?", (top_n,))
            top_rules = [(row[0], row[1]) for row in cursor.fetchall()]

            cutoff = time.time() - (hours * 3600)
            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:00', timestamp, 'unixepoch') as hr, COUNT(*)
                FROM events
                WHERE timestamp >= ?
                GROUP BY hr
                ORDER BY hr ASC
            """, (cutoff,))
            hourly = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM bans WHERE status IN ('BANNED', 'SIMULATED')")
            active_bans = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM bans")
            total_banned = cursor.fetchone()[0]

            return {
                "total_events": total_events,
                "unique_ips": unique_ips,
                "categories": categories,
                "top_ips": top_ips,
                "top_rules": top_rules,
                "hourly": hourly,
                "active_bans": active_bans,
                "total_banned": total_banned,
            }

    # --- Log Configuration Persistence ---

    def save_log_config(self, logs: List[Dict[str, str]]) -> None:
        """Persist the list of configured log files."""
        with self._lock:
            conn = self._get_conn()
            # Clear existing config
            conn.execute("DELETE FROM log_config")
            # Insert all logs
            conn.executemany(
                "INSERT INTO log_config (name, path, enabled) VALUES (?, ?, 1)",
                [(item.get("name", ""), item["path"]) for item in logs],
            )
            conn.commit()

    def load_log_config(self) -> List[Dict[str, str]]:
        """Load persisted log configuration."""
        logs: List[Dict[str, str]] = []
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "SELECT name, path FROM log_config WHERE enabled = 1 ORDER BY created_at"
            )
            for row in cursor.fetchall():
                logs.append({"name": row[0], "path": row[1]})
        return logs

    def add_log_config(self, name: str, path: str) -> bool:
        """Add a single log to the persisted configuration."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT id FROM log_config WHERE path = ?", (path,))
            existing = cursor.fetchone()
            if existing:
                conn.execute("UPDATE log_config SET name = ?, enabled = 1 WHERE id = ?", (name, existing[0]))
            else:
                conn.execute(
                    "INSERT INTO log_config (name, path, enabled) VALUES (?, ?, 1)",
                    (name, path)
                )
            conn.commit()
            return True

    def remove_log_config(self, path: str) -> bool:
        """Remove a log from the persisted configuration."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("UPDATE log_config SET enabled = 0 WHERE path = ?", (path,))
            conn.commit()
            return cursor.rowcount > 0
