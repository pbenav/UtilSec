"""Attack detection engine evaluating rules, heuristics, and 404 rate-limiting."""

import collections
import re
import time
from typing import Deque, Dict, List, Optional, Tuple

from core.config import ConfigManager
from core.models import AttackEvent, Rule

# Rate-limit bookkeeping is bounded on purpose: a scanner rotating through
# millions of source addresses would otherwise grow these dicts without limit.
# Entries used to be pruned only when the very same IP came back, so every
# single-hit probe left a permanent dict entry behind.
HISTORY_SWEEP_INTERVAL = 30.0
HISTORY_MAX_TRACKED_IPS = 100_000


class AttackDetector:
    """Detects malicious requests using string patterns, regex heuristics, and rate limiting."""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.compiled_rules: List[Tuple[Rule, Optional[re.Pattern]]] = []
        self._compile_rules()

        # Sliding windows for rate limiting: IP -> deque of timestamps
        self.ip_404_history: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self.ip_403_history: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self.total_analyzed = 0
        self.total_404s = 0
        self.total_403s = 0
        self.total_attacks_detected = 0
        self._last_history_sweep = time.time()

    def _sweep_histories(self, now: float) -> None:
        """Evict rate-limit entries whose window aged out, then enforce a cap.

        Must be called from the request path only once every
        ``HISTORY_SWEEP_INTERVAL`` seconds: it is O(tracked IPs).
        """
        self._last_history_sweep = now
        cutoff = now - self.config.window_seconds
        for store in (self.ip_403_history, self.ip_404_history):
            for stale_ip in [ip for ip, hits in store.items() if not hits or hits[-1] < cutoff]:
                del store[stale_ip]

            excess = len(store) - HISTORY_MAX_TRACKED_IPS
            if excess <= 0:
                continue
            # Least recently active IPs first.
            for stale_ip, _ in sorted(store.items(), key=lambda kv: kv[1][-1])[:excess]:
                del store[stale_ip]

    def _compile_rules(self) -> None:
        """Compile regex rules for ultra-fast matching."""
        self.compiled_rules = []
        for r in self.config.rules:
            if not r.enabled:
                continue
            if r.is_regex:
                try:
                    c = re.compile(r.pattern, re.IGNORECASE)
                    self.compiled_rules.append((r, c))
                except re.error:
                    pass
            else:
                self.compiled_rules.append((r, None))

    def reload_rules(self) -> None:
        self.config.load()
        self._compile_rules()

    def analyze_request(
        self,
        ip: str,
        method: str,
        url: str,
        status_code: int,
        raw_line: str = "",
        source_log: str = "",
        is_banned: bool = False,
    ) -> Tuple[Optional[AttackEvent], bool, str]:
        """
        Analyzes an HTTP request.
        Returns: (event, should_ban, ban_reason)
        """
        self.total_analyzed += 1

        if status_code == 404:
            self.total_404s += 1
        elif status_code == 403:
            self.total_403s += 1

        # Check whitelist first
        if self.config.is_ip_whitelisted(ip):
            return None, False, ""

        now = time.time()
        if now - self._last_history_sweep >= HISTORY_SWEEP_INTERVAL:
            self._sweep_histories(now)

        # 1. Match against configured rules and AI heuristics
        for rule, comp_regex in self.compiled_rules:
            matched = False
            if comp_regex:
                if comp_regex.search(url):
                    matched = True
            else:
                if rule.pattern.lower() in url.lower():
                    matched = True

            if matched:
                rule.hits += 1
                self.total_attacks_detected += 1
                event = AttackEvent(
                    ip=ip,
                    method=method,
                    url=url,
                    status_code=status_code,
                    matched_rule=rule.name,
                    category=rule.category,
                    raw_line=raw_line,
                    source_log=source_log,
                )
                # If rule is critical, host is already banned, or status is 404/403/500, ban immediately!
                if rule.critical or is_banned or status_code in (404, 403):
                    return event, True, f"Attack Signature: {rule.name}"
                return event, False, ""

        # 1b. If the host is already known to be banned, any probe/error is a confirmed repeat attack!
        if is_banned and status_code in (400, 401, 403, 404, 405, 500):
            self.total_attacks_detected += 1
            event = AttackEvent(
                ip=ip,
                method=method,
                url=url,
                status_code=status_code,
                matched_rule=f"Banned Host Activity ({status_code})",
                category="repeat_attack",
                raw_line=raw_line,
                source_log=source_log,
            )
            return event, True, f"Repeat Attack from Banned IP ({status_code})"

        # 2. HTTP 403 Forbidden Access Handling (Default: Instant ban on 1st attempt!)
        if status_code == 403:
            history = self.ip_403_history[ip]
            cutoff = now - self.config.window_seconds
            while history and history[0] < cutoff:
                history.popleft()
            history.append(now)

            count = len(history)
            if count >= self.config.threshold_403:
                self.total_attacks_detected += 1
                event = AttackEvent(
                    ip=ip,
                    method=method,
                    url=url,
                    status_code=status_code,
                    matched_rule="HTTP 403 Forbidden Access",
                    category="forbidden",
                    raw_line=raw_line,
                    source_log=source_log,
                )
                reason = f"HTTP 403 Forbidden ({count} hit{'s' if count > 1 else ''})"
                history.clear()
                return event, True, reason
            else:
                event = AttackEvent(
                    ip=ip,
                    method=method,
                    url=url,
                    status_code=status_code,
                    matched_rule=f"HTTP 403 Probe ({count}/{self.config.threshold_403})",
                    category="probe",
                    raw_line=raw_line,
                    source_log=source_log,
                )
                return event, False, ""

        # 3. HTTP 404 Not Found Rate Limiting (Default: Strict threshold of 2 attempts)
        if status_code == 404:
            history = self.ip_404_history[ip]
            cutoff = now - self.config.window_seconds
            while history and history[0] < cutoff:
                history.popleft()
            history.append(now)

            count = len(history)
            if count >= self.config.threshold_404:
                self.total_attacks_detected += 1
                event = AttackEvent(
                    ip=ip,
                    method=method,
                    url=url,
                    status_code=status_code,
                    matched_rule="HTTP 404 Scanner Rate-Limit",
                    category="rate_limit",
                    raw_line=raw_line,
                    source_log=source_log,
                )
                reason = f"Exceeded 404 limit: {count} hits in {self.config.window_seconds}s"
                history.clear()
                return event, True, reason
            else:
                event = AttackEvent(
                    ip=ip,
                    method=method,
                    url=url,
                    status_code=status_code,
                    matched_rule=f"HTTP 404 Probe ({count}/{self.config.threshold_404})",
                    category="probe",
                    raw_line=raw_line,
                    source_log=source_log,
                )
                return event, False, ""

        return None, False, ""

