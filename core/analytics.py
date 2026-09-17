"""Statistics and analytics module for UtilSec Sentinel TUI dashboard."""

import collections
import json
import logging
import socket
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from http.client import HTTPResponse
from typing import Deque, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from core.models import AttackEvent, Rule

logger = logging.getLogger("UtilSec.Analytics")


class AttackAnalytics:
    """Collects and calculates attack statistics from detector, attack events, and storage."""

    def __init__(
        self,
        detector,
        recent_attacks: Deque[AttackEvent],
        screen_attacks: Dict[str, Deque[AttackEvent]],
        storage=None,
    ) -> None:
        self.detector = detector
        self.recent_attacks = recent_attacks
        self.screen_attacks = screen_attacks
        self.storage = storage

        # Geolocation cache: ip -> country_code
        self._geo_cache: Dict[str, str] = {}
        self._geo_cache_lock = threading.Lock()
        self._geo_cache_ttl: Dict[str, float] = {}
        self._geo_cache_ttl_lock = threading.Lock()
        self._geo_resolving_ips: set = set()
        self._geo_resolving_lock = threading.Lock()

        # Time-to-live for cache entries (24 hours for valid geo)
        self._geo_ttl_seconds = 86400

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_all_attacks(self) -> List[AttackEvent]:
        """Return all attacks combined (recent + per-screen), deduplicated by identity."""
        seen: set = set()
        attacks: List[AttackEvent] = []
        for ev in self.recent_attacks:
            key = (ev.ip, ev.url, ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp))
            if key not in seen:
                seen.add(key)
                attacks.append(ev)
        for screen_deque in self.screen_attacks.values():
            for ev in screen_deque:
                key = (ev.ip, ev.url, ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp))
                if key not in seen:
                    seen.add(key)
                    attacks.append(ev)
        return attacks

    @staticmethod
    def _safe_percentage(count: int, total: int) -> float:
        if total == 0:
            return 0.0
        return round((count / total) * 100, 1)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_overall_stats(self) -> dict:
        """Return overall statistics dict with session and historical metrics."""
        session_attacks = self.detector.total_attacks_detected
        session_analyzed = self.detector.total_analyzed
        session_404s = self.detector.total_404s
        session_403s = self.detector.total_403s

        total_events = session_attacks
        active_bans = 0
        total_banned = 0
        unique_ips = 0

        if self.storage:
            try:
                summary = self.storage.get_analytics_summary()
                total_events = max(session_attacks, summary.get("total_events", 0))
                active_bans = summary.get("active_bans", 0)
                total_banned = summary.get("total_banned", 0)
                unique_ips = summary.get("unique_ips", 0)
            except Exception:
                pass
        else:
            all_attacks = self._get_all_attacks()
            total_events = max(session_attacks, len(all_attacks))
            unique_ips = len(set(ev.ip for ev in all_attacks))

        attack_rate = self._safe_percentage(session_attacks, session_analyzed)

        return {
            "total_analyzed": session_analyzed,
            "total_attacks": total_events,
            "total_attacks_detected": total_events,
            "session_attacks": session_attacks,
            "attack_rate": attack_rate,
            "total_404s": session_404s,
            "total_403s": session_403s,
            "active_bans": active_bans,
            "total_banned": total_banned,
            "unique_ips": unique_ips,
        }

    def get_category_breakdown(self) -> List[Tuple[str, int, float]]:
        """Return list of (category, count, percentage) sorted by count descending."""
        if self.storage:
            try:
                summary = self.storage.get_analytics_summary()
                if summary.get("total_events", 0) > 0:
                    total = summary["total_events"]
                    return [
                        (cat, cnt, self._safe_percentage(cnt, total))
                        for cat, cnt in summary.get("categories", [])
                    ]
            except Exception:
                pass

        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.category for ev in attacks)
        total = sum(counter.values())
        return [
            (cat, cnt, self._safe_percentage(cnt, total))
            for cat, cnt in counter.most_common()
        ]

    def get_top_ips(self, top_n: int = 10) -> List[Tuple[str, int, float]]:
        """Return list of (ip, count, percentage) sorted by count descending."""
        if self.storage:
            try:
                summary = self.storage.get_analytics_summary(top_n=top_n)
                if summary.get("total_events", 0) > 0:
                    total = summary["total_events"]
                    return [
                        (ip, cnt, self._safe_percentage(cnt, total))
                        for ip, cnt in summary.get("top_ips", [])
                    ]
            except Exception:
                pass

        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.ip for ev in attacks)
        total = sum(counter.values())
        return [
            (ip, cnt, self._safe_percentage(cnt, total))
            for ip, cnt in counter.most_common(top_n)
        ]

    def get_top_rules(self, top_n: int = 10) -> List[Tuple[str, int, float]]:
        """Return list of (rule_name, count, percentage) sorted by count descending."""
        if self.storage:
            try:
                summary = self.storage.get_analytics_summary(top_n=top_n)
                if summary.get("total_events", 0) > 0:
                    total = summary["total_events"]
                    return [
                        (rule, cnt, self._safe_percentage(cnt, total))
                        for rule, cnt in summary.get("top_rules", [])
                    ]
            except Exception:
                pass

        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.matched_rule for ev in attacks)
        total = sum(counter.values())
        return [
            (rule, cnt, self._safe_percentage(cnt, total))
            for rule, cnt in counter.most_common(top_n)
        ]

    def get_hourly_evolution(self, hours: int = 24) -> Dict[str, int]:
        """Return dict of {hour_str: count} for the last N hours."""
        if self.storage:
            try:
                summary = self.storage.get_analytics_summary(hours=hours)
                hourly_data = summary.get("hourly", {})
                if hourly_data:
                    now = datetime.now()
                    result: Dict[str, int] = {}
                    for h in range(hours):
                        dt = now - timedelta(hours=h)
                        k = dt.strftime("%Y-%m-%d %H:00")
                        result[k] = hourly_data.get(k, 0)
                    return result
            except Exception:
                pass

        now = datetime.now()
        cutoff = now - timedelta(hours=hours)
        attacks = self._get_all_attacks()

        hourly: Dict[str, int] = {}
        for h in range(hours):
            hour_dt = now - timedelta(hours=h)
            hour_key = hour_dt.strftime("%Y-%m-%d %H:00")
            hourly[hour_key] = 0

        for ev in attacks:
            ts = ev.timestamp if isinstance(ev.timestamp, datetime) else datetime.fromtimestamp(ev.timestamp)
            if ts >= cutoff:
                key = ts.strftime("%Y-%m-%d %H:00")
                if key in hourly:
                    hourly[key] += 1
                else:
                    hourly[key] = 1

        return hourly

    def get_geolocation_stats(self, top_n: int = 10) -> List[Tuple[str, int, float, List[str]]]:
        """Return list of (country_code, count, percentage, [ips]) sorted by count descending.

        Non-blocking: reads from in-memory cache immediately.
        Missing IPs are queued for asynchronous background resolution.
        """
        top_ips = self.get_top_ips(top_n * 2)
        if not top_ips:
            return []

        country_data: Dict[str, dict] = {}
        missing_ips: List[str] = []

        for ip, count, pct in top_ips:
            code = self._get_cached_geo(ip)
            if code is None:
                code = "XX"
                missing_ips.append(ip)

            if code not in country_data:
                country_data[code] = {"count": 0, "ips": []}
            country_data[code]["count"] += count
            if ip not in country_data[code]["ips"]:
                country_data[code]["ips"].append(ip)

        # Trigger background resolution for missing IPs without blocking
        if missing_ips:
            self._queue_geo_lookups(missing_ips)

        total = sum(d["count"] for d in country_data.values())
        result = [
            (code, d["count"], self._safe_percentage(d["count"], total), d["ips"])
            for code, d in country_data.items()
        ]
        result.sort(key=lambda x: x[1], reverse=True)
        return result[:top_n]

    def get_all_stats(self) -> dict:
        """Return complete statistics dict with all sections."""
        return {
            "overall": self.get_overall_stats(),
            "categories": self.get_category_breakdown(),
            "top_ips": self.get_top_ips(),
            "top_rules": self.get_top_rules(),
            "hourly_evolution": self.get_hourly_evolution(),
            "geolocation": self.get_geolocation_stats(),
        }

    # ------------------------------------------------------------------
    # Geolocation helpers
    # ------------------------------------------------------------------

    def _queue_geo_lookups(self, ips: List[str]) -> None:
        """Trigger background resolution for IPs not yet cached or currently resolving."""
        with self._geo_resolving_lock:
            to_resolve = [ip for ip in ips if ip not in self._geo_resolving_ips]
            for ip in to_resolve:
                self._geo_resolving_ips.add(ip)

        if not to_resolve:
            return

        def _worker():
            for ip in to_resolve:
                try:
                    code = self._query_ripe_ncc(ip)
                    if code:
                        self._set_cached_geo(ip, code)
                    else:
                        # Cache negative for 10 minutes to avoid repeatedly hammering network
                        self._set_cached_geo(ip, "XX", ttl=600)
                except Exception:
                    self._set_cached_geo(ip, "XX", ttl=600)
                finally:
                    with self._geo_resolving_lock:
                        self._geo_resolving_ips.discard(ip)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _get_cached_geo(self, ip: str) -> Optional[str]:
        """Return cached country code or None if not cached / expired."""
        with self._geo_cache_lock:
            if ip not in self._geo_cache:
                return None
            code = self._geo_cache[ip]

        with self._geo_cache_ttl_lock:
            expires = self._geo_cache_ttl.get(ip, 0)
            if time.time() > expires:
                with self._geo_cache_lock:
                    self._geo_cache.pop(ip, None)
                return None

        return code

    def _set_cached_geo(self, ip: str, code: str, ttl: Optional[float] = None) -> None:
        """Store a geolocation result in the cache."""
        duration = ttl if ttl is not None else self._geo_ttl_seconds
        with self._geo_cache_lock:
            self._geo_cache[ip] = code
        with self._geo_cache_ttl_lock:
            self._geo_cache_ttl[ip] = time.time() + duration

    def _query_ripe_ncc(self, ip: str) -> Optional[str]:
        """Query RIPE NCC Statistics API for country information with strict fast timeout."""
        url = f"https://stat.ripe.net/data/geo-data/api.json?resource={ip}"
        try:
            req = Request(url, method="GET")
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "UtilSec-Sentinel/1.0")

            with urlopen(req, timeout=2.0) as resp:
                if resp.status != 200:
                    return None
                body = json.loads(resp.read().decode("utf-8"))

            response_data = body.get("response", {})
            geo = response_data.get("geo", {})
            country = geo.get("country")

            if country and isinstance(country, str):
                return country.upper()

            notice = response_data.get("notice", {})
            title = notice.get("title", "")
            for c_name, c_code in [("Spain", "ES"), ("Russia", "RU"), ("China", "CN"), ("United States", "US")]:
                if c_name in title:
                    return c_code

            return None
        except Exception as exc:
            logger.debug("RIPE NCC API failed for %s: %s", ip, exc)
            return None
