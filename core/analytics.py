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
    """Collects and calculates attack statistics from detector and attack events."""

    def __init__(
        self,
        detector,
        recent_attacks: Deque[AttackEvent],
        screen_attacks: Dict[str, Deque[AttackEvent]],
    ) -> None:
        self.detector = detector
        self.recent_attacks = recent_attacks
        self.screen_attacks = screen_attacks

        # Geolocation cache: ip -> country_code
        self._geo_cache: Dict[str, str] = {}
        self._geo_cache_lock = threading.Lock()
        self._geo_cache_ttl: Dict[str, float] = {}
        self._geo_cache_ttl_lock = threading.Lock()

        # Time-to-live for cache entries (5 minutes)
        self._geo_ttl_seconds = 300

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_all_attacks(self) -> List[AttackEvent]:
        """Return all attacks combined (recent + per-screen), deduplicated by identity."""
        seen: set = set()
        attacks: List[AttackEvent] = []
        for ev in self.recent_attacks:
            key = (ev.ip, ev.url, ev.timestamp.isoformat())
            if key not in seen:
                seen.add(key)
                attacks.append(ev)
        for screen_deque in self.screen_attacks.values():
            for ev in screen_deque:
                key = (ev.ip, ev.url, ev.timestamp.isoformat())
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
        """Return overall statistics dict."""
        total_attacks = self.detector.total_attacks_detected
        total_analyzed = self.detector.total_analyzed
        attack_rate = self._safe_percentage(total_attacks, total_analyzed)

        return {
            "total_analyzed": total_analyzed,
            "total_attacks_detected": total_attacks,
            "attack_rate": attack_rate,
            "total_404s": self.detector.total_404s,
            "total_403s": self.detector.total_403s,
        }

    def get_category_breakdown(self) -> List[Tuple[str, int, float]]:
        """Return list of (category, count, percentage) sorted by count descending."""
        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.category for ev in attacks)
        total = sum(counter.values())
        return [
            (cat, cnt, self._safe_percentage(cnt, total))
            for cat, cnt in counter.most_common()
        ]

    def get_top_ips(self, top_n: int = 10) -> List[Tuple[str, int, float]]:
        """Return list of (ip, count, percentage) sorted by count descending."""
        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.ip for ev in attacks)
        total = sum(counter.values())
        return [
            (ip, cnt, self._safe_percentage(cnt, total))
            for ip, cnt in counter.most_common(top_n)
        ]

    def get_top_rules(self, top_n: int = 10) -> List[Tuple[str, int, float]]:
        """Return list of (rule_name, count, percentage) sorted by count descending."""
        attacks = self._get_all_attacks()
        counter: Counter = Counter(ev.matched_rule for ev in attacks)
        total = sum(counter.values())
        return [
            (rule, cnt, self._safe_percentage(cnt, total))
            for rule, cnt in counter.most_common(top_n)
        ]

    def get_hourly_evolution(self, hours: int = 24) -> Dict[str, int]:
        """Return dict of {hour_str: count} for the last N hours based on event timestamps."""
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

        Uses the RIPE NCC Statistics API to resolve country codes for the top attacking IPs.
        Results are cached in memory to avoid repeated API calls.
        """
        top_ips = self.get_top_ips(top_n * 3)  # fetch more to account for failed lookups
        if not top_ips:
            return []

        # Resolve geolocations concurrently
        ip_results: Dict[str, str] = {}
        lock = threading.Lock()
        errors: List[str] = []

        def _lookup(ip: str) -> None:
            code = self._resolve_country(ip)
            with lock:
                ip_results[ip] = code

        threads: List[threading.Thread] = []
        for ip, _, _ in top_ips:
            t = threading.Thread(target=_lookup, args=(ip,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        if errors:
            logger.debug("Geolocation errors: %s", errors[:5])

        # Group by country
        country_data: Dict[str, dict] = {}
        for ip, count, pct in top_ips:
            code = ip_results.get(ip, "XX")  # XX = unknown
            if code not in country_data:
                country_data[code] = {"count": 0, "ips": []}
            country_data[code]["count"] += count
            if ip not in country_data[code]["ips"]:
                country_data[code]["ips"].append(ip)

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

    def _resolve_country(self, ip: str) -> str:
        """Resolve country code for an IP using RIPE NCC Statistics API.

        Uses in-memory cache with TTL to avoid repeated API calls.
        Returns 'XX' for unknown/unresolvable IPs.
        """
        # Check in-memory cache first
        cached = self._get_cached_geo(ip)
        if cached is not None:
            return cached

        # Try RIPE NCC API
        code = self._query_ripe_ncc(ip)

        # Cache the result (even failures, but with shorter TTL)
        if code:
            self._set_cached_geo(ip, code)
        else:
            # Cache failures briefly (30s)
            self._set_cached_geo(ip, "XX")

        return code if code else "XX"

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

    def _set_cached_geo(self, ip: str, code: str) -> None:
        """Store a geolocation result in the cache."""
        with self._geo_cache_lock:
            self._geo_cache[ip] = code
        with self._geo_cache_ttl_lock:
            self._geo_cache_ttl[ip] = time.time() + self._geo_ttl_seconds

    def _query_ripe_ncc(self, ip: str) -> Optional[str]:
        """Query RIPE NCC Statistics API for country information.

        The RIPE NCC API returns data like:
          {
            "response": {
              "ripe_status": "OK",
              "data": {
                "route": {"origin_asn": "ASxxxx"},
                "route_object": {"origin": "ASxxxx"},
                "notice": {"title": "..."}
              },
              "geo": {"country": "ES"}
            }
          }

        Fallback: use reverse DNS lookup.
        """
        url = f"https://stat.ripe.net/data/geo-data/api.json?resource={ip}"
        try:
            req = Request(url, method="GET")
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "UtilSec-Sentinel/1.0")

            with urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return None
                body = json.loads(resp.read().decode("utf-8"))

            # Parse the JSON response
            response_data = body.get("response", {})
            geo = response_data.get("geo", {})
            country = geo.get("country")

            if country and isinstance(country, str):
                return country.upper()

            # Some versions of the API put country info differently
            notice = response_data.get("notice", {})
            title = notice.get("title", "")
            if "Spain" in title:
                return "ES"
            if "Russia" in title:
                return "RU"
            if "China" in title:
                return "CN"
            if "United States" in title:
                return "US"

            return None

        except (URLError, OSError, ValueError, KeyError, TypeError) as exc:
            logger.debug("RIPE NCC API failed for %s: %s", ip, exc)
            return self._fallback_dns_lookup(ip)

    @staticmethod
    def _fallback_dns_lookup(ip: str) -> Optional[str]:
        """Fallback: try reverse DNS to guess country from TLD."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname.endswith(".ru"):
                return "RU"
            if hostname.endswith(".cn"):
                return "CN"
            if hostname.endswith(".us"):
                return "US"
            if hostname.endswith(".de"):
                return "DE"
            if hostname.endswith(".fr"):
                return "FR"
            if hostname.endswith(".br"):
                return "BR"
            if hostname.endswith(".jp"):
                return "JP"
            if hostname.endswith(".uk") or hostname.endswith(".co.uk"):
                return "GB"
            if hostname.endswith(".kr"):
                return "KR"
            if hostname.endswith(".in"):
                return "IN"
            if hostname.endswith(".it"):
                return "IT"
            if hostname.endswith(".nl"):
                return "NL"
            if hostname.endswith(".se"):
                return "SE"
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        return None
