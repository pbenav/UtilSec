"""Behavioral and Early-Stage Reconnaissance Detection Engine for UtilSec Sentinel.

Transitions UtilSec from a purely reactive signature-matching tool to a proactive,
predictive behavioral defense system by identifying early-stage reconnaissance
(scanning, parameter fuzzing, obfuscated payloads, and anomalous user journeys)
before final exploit execution.
"""

import collections
import ipaddress
import logging
import math
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("UtilSec.Behavioral")

# Bounds for memory protection against state exhaustion DoS
MAX_TRACKED_BEHAVIORAL_IPS = 100_000
SWEEP_INTERVAL_SECONDS = 30.0

# Base64 regex pattern (standard base64 with or without padding)
RE_BASE64_CANDIDATE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")

# Suspicious scanners User-Agent signatures for early reconnaissance
RE_SCANNER_UA = re.compile(
    r"(?:dirbuster|gobuster|nikto|wpscan|sqlmap|ffuf|feroxbuster|masscan|zgrab|acunetix|nessus|nmap|whatweb|openvas)",
    re.IGNORECASE,
)

# Common entry point paths for legitimate user journeys
DEFAULT_ENTRY_ROUTES: Set[str] = {
    "/",
    "",
    "/index.html",
    "/index.htm",
    "/index.php",
    "/home",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
}

# Critical deep administrative/backend routes requiring legitimate navigation
DEFAULT_DEEP_SENSITIVE_ROUTES: List[re.Pattern] = [
    re.compile(r"^/(?:admin|administrator|wp-admin|backend|cpanel|manager|controlpanel)(?:/|$|\?)", re.IGNORECASE),
    re.compile(r"^/api/v\d+/(?:admin|internal|management)(?:/|$|\?)", re.IGNORECASE),
    re.compile(r"^/(?:server-status|server-info|phpmyadmin|pma|adminer|xmlrpc\.php)", re.IGNORECASE),
    re.compile(r"^/(?:setup|install|update|upgrade)\.php", re.IGNORECASE),
]

# Sensitive files probed during early recon phases
DEFAULT_SENSITIVE_PROBE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.git(?:/|config|ignore|modules|$)", re.IGNORECASE),
    re.compile(r"\.env(?:\.[a-zA-Z0-9_-]+)?$", re.IGNORECASE),
    re.compile(r"(?:composer\.json|composer\.lock|package\.json|package-lock\.json)$", re.IGNORECASE),
    re.compile(r"(?:wp-config\.php|configuration\.php|config\.inc\.php|local\.settings\.php)$", re.IGNORECASE),
    re.compile(r"(?:docker-compose\.ya?ml|Dockerfile|\.dockerignore)$", re.IGNORECASE),
    re.compile(r"(?:phpinfo\.php|info\.php|test\.php|dump\.sql|backup\.sql|db\.sql)$", re.IGNORECASE),
    re.compile(r"\.(?:aws|azure|kube)/", re.IGNORECASE),
    re.compile(r"(?:web\.config|\.htaccess|\.htpasswd)$", re.IGNORECASE),
    re.compile(r"(?:storage/logs|app/etc/env\.php|bootstrap/cache)", re.IGNORECASE),
]


# ==============================================================================
# 1. Parameter Entropy & Structural Anomaly Detection
# ==============================================================================


@dataclass
class ParameterAnomaly:
    """Represents an anomaly found within a parameter's structure."""

    param_name: str
    param_value: str
    entropy: float
    special_char_ratio: float
    is_base64_candidate: bool
    anomaly_reasons: List[str]


class ShannonEntropyCalculator:
    """Calculates Shannon entropy, character distribution and obfuscation in parameters."""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon Entropy in bits per character.

        H(X) = - sum( P(x_i) * log2(P(x_i)) )
        Range: 0.0 (homogeneous) to ~6.0+ (random/base64/encrypted).
        """
        if not text:
            return 0.0
        length = len(text)
        counts = collections.Counter(text)
        entropy = 0.0
        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    @staticmethod
    def special_char_density(text: str) -> float:
        """Calculates the ratio of special/escape characters to total length.

        High density of non-alphanumeric chars often indicates payload injection
        or escape-heavy obfuscation.
        """
        if not text:
            return 0.0
        # Common special symbols in injection & obfuscation (excluding benign id separators _ and -)
        hostile_symbols = set("`'\"<>;%\\{}()$|&^!~*+=/#@:[]?\x00")
        special_count = sum(
            1 for ch in text if ch in hostile_symbols or ord(ch) < 32 or ord(ch) > 126
        )
        return round(special_count / len(text), 4)

    @staticmethod
    def is_base64_like(text: str) -> bool:
        """Tests if a parameter value resembles encoded Base64 with high confidence."""
        if len(text) < 16:
            return False
        # Remove URL encoding if present
        clean_val = urllib.parse.unquote(text)
        if len(clean_val) % 4 != 0 and len(clean_val) % 4 != 1:
            return False
        return bool(RE_BASE64_CANDIDATE.match(clean_val))

    @classmethod
    def analyze_parameter(
        cls,
        name: str,
        value: str,
        entropy_threshold: float = 4.2,
        min_param_len: int = 14,
        special_char_ratio_threshold: float = 0.25,
    ) -> Optional[ParameterAnomaly]:
        """Analyzes a single parameter for structural and entropy anomalies."""
        if not value or len(value) < min_param_len:
            return None

        # Exclude common benign high-entropy parameters (e.g. CSRF tokens, session IDs)
        # if they match expected alphanumeric hex/uuid shapes
        name_lower = name.lower()
        if any(ign in name_lower for ign in ["csrf", "token", "nonce", "_wpnonce", "session", "key", "auth"]):
            # Still inspect if excessive special characters or null bytes exist
            special_ratio = cls.special_char_density(value)
            if special_ratio > 0.35 or "\x00" in value:
                return ParameterAnomaly(
                    param_name=name,
                    param_value=value[:120],
                    entropy=cls.calculate_entropy(value),
                    special_char_ratio=special_ratio,
                    is_base64_candidate=False,
                    anomaly_reasons=["Hostile character injection in security token"],
                )
            return None

        entropy = cls.calculate_entropy(value)
        special_ratio = cls.special_char_density(value)
        is_b64 = cls.is_base64_like(value)

        reasons = []
        if entropy >= entropy_threshold:
            reasons.append(f"High Shannon entropy ({entropy:.2f} >= {entropy_threshold:.2f})")
        if special_ratio >= special_char_ratio_threshold:
            reasons.append(f"High special character density ({special_ratio:.2%} >= {special_char_ratio_threshold:.2%})")
        if is_b64 and len(value) >= 24 and entropy >= 4.0:
            reasons.append(f"Potential obfuscated Base64 payload (len={len(value)})")

        if reasons:
            return ParameterAnomaly(
                param_name=name,
                param_value=value[:120],
                entropy=entropy,
                special_char_ratio=special_ratio,
                is_base64_candidate=is_b64,
                anomaly_reasons=reasons,
            )
        return None

    @classmethod
    def extract_and_analyze_parameters(
        cls,
        url: str,
        raw_line: str = "",
        entropy_threshold: float = 4.2,
        min_param_len: int = 14,
        special_char_ratio_threshold: float = 0.25,
    ) -> List[ParameterAnomaly]:
        """Extracts GET query parameters and payload fragments from URL/raw_line and analyzes them."""
        anomalies: List[ParameterAnomaly] = []
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            try:
                params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                for k, v in params:
                    anomaly = cls.analyze_parameter(
                        name=k,
                        value=v,
                        entropy_threshold=entropy_threshold,
                        min_param_len=min_param_len,
                        special_char_ratio_threshold=special_char_ratio_threshold,
                    )
                    if anomaly:
                        anomalies.append(anomaly)
            except Exception:
                pass

        # Also inspect path segments for suspicious encoded payloads (e.g., /view/base64==)
        path = parsed.path
        if "/" in path:
            segments = [seg for seg in path.split("/") if len(seg) >= min_param_len]
            for seg in segments:
                # If segment looks like a file with normal extension, skip
                if any(seg.lower().endswith(ext) for ext in [".html", ".htm", ".php", ".js", ".css", ".png", ".jpg"]):
                    continue
                anomaly = cls.analyze_parameter(
                    name="url_path_segment",
                    value=seg,
                    entropy_threshold=entropy_threshold,
                    min_param_len=min_param_len,
                    special_char_ratio_threshold=special_char_ratio_threshold,
                )
                if anomaly:
                    anomalies.append(anomaly)

        return anomalies


# ==============================================================================
# 2. User Journey & Navigation State Transition Tracker
# ==============================================================================


@dataclass
class UserJourneyProfile:
    """Tracks the state and progression of a client IP's navigation journey."""

    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_requests: int = 0
    visited_entry_point: bool = False
    visited_paths: Set[str] = field(default_factory=set)
    journey_anomalies_count: int = 0


class UserJourneyTracker:
    """Analyzes client navigation sequences to detect forced browsing and state skips."""

    def __init__(
        self,
        entry_routes: Optional[Set[str]] = None,
        deep_sensitive_routes: Optional[List[re.Pattern]] = None,
    ):
        self.entry_routes = entry_routes or set(DEFAULT_ENTRY_ROUTES)
        self.deep_sensitive_routes = deep_sensitive_routes or list(DEFAULT_DEEP_SENSITIVE_ROUTES)
        self.profiles: Dict[str, UserJourneyProfile] = {}

    def is_entry_route(self, path: str) -> bool:
        """Checks if a requested path corresponds to an entry/landing page."""
        clean_path = path.split("?")[0].rstrip("/")
        return clean_path in self.entry_routes or clean_path == ""

    def is_deep_sensitive_route(self, path: str) -> bool:
        """Checks if the route is a deep administrative or backend endpoint."""
        for pattern in self.deep_sensitive_routes:
            if pattern.search(path):
                return True
        return False

    @staticmethod
    def extract_referer(raw_line: str) -> Optional[str]:
        """Extracts Referer header from an Apache combined access log line."""
        # Apache combined format: "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
        if not raw_line:
            return None
        parts = raw_line.split('"')
        if len(parts) >= 5:
            ref = parts[3].strip()
            return ref if ref and ref != "-" else None
        return None

    @staticmethod
    def extract_user_agent(raw_line: str) -> Optional[str]:
        """Extracts User-Agent header from an Apache combined access log line."""
        if not raw_line:
            return None
        parts = raw_line.split('"')
        if len(parts) >= 6:
            ua = parts[5].strip()
            return ua if ua and ua != "-" else None
        return None

    def evaluate_request(
        self,
        ip: str,
        method: str,
        url: str,
        status_code: int,
        raw_line: str = "",
        now: Optional[float] = None,
    ) -> Optional[str]:
        """Evaluates whether the request violates legitimate user journey transitions.

        Returns an anomaly reason string if a violation is detected, None otherwise.
        """
        now = now or time.time()
        profile = self.profiles.get(ip)
        if profile is None:
            profile = UserJourneyProfile(ip=ip, first_seen=now, last_seen=now)
            self.profiles[ip] = profile

        profile.last_seen = now
        profile.total_requests += 1

        path = url.split("?")[0]
        if self.is_entry_route(path) and status_code in (200, 301, 302, 304):
            profile.visited_entry_point = True

        profile.visited_paths.add(path)

        # Check for direct deep-route execution anomaly (Forced Browsing)
        if self.is_deep_sensitive_route(path):
            referer = self.extract_referer(raw_line)
            # If the user has never visited an entry point, has few prior requests (<= 2),
            # and provides no internal referer -> High confidence Forced Browsing / Admin Probe
            if not profile.visited_entry_point and profile.total_requests <= 2 and not referer:
                profile.journey_anomalies_count += 1
                return f"Forced browsing to sensitive administrative endpoint '{path}' without prior navigation or referer"

        return None

    def prune(self, cutoff: float) -> None:
        """Removes journey profiles older than cutoff timestamp."""
        stale = [ip for ip, prof in self.profiles.items() if prof.last_seen < cutoff]
        for ip in stale:
            del self.profiles[ip]


# ==============================================================================
# 3. Temporal Sliding Windows & Dynamic Reputation/Suspicion Scoring
# ==============================================================================


@dataclass
class RequestRecord:
    """Record of a request within an IP's sliding window."""

    timestamp: float
    method: str
    url: str
    status_code: int
    is_404: bool
    is_403: bool
    is_sensitive_probe: bool
    has_entropy_anomaly: bool
    is_journey_anomaly: bool


@dataclass
class IPBehaviorWindow:
    """Sliding window tracking recent requests and computing dynamic reputation."""

    ip: str
    history: Deque[RequestRecord] = field(default_factory=collections.deque)
    suspicion_score: float = 0.0
    sensitive_probes_count: int = 0
    error_404_count: int = 0
    error_403_count: int = 0
    entropy_anomaly_count: int = 0
    journey_anomaly_count: int = 0
    last_activity: float = field(default_factory=time.time)
    reasons: List[str] = field(default_factory=list)


class SlidingWindowTracker:
    """In-memory sliding window manager tracking IP activity, 404 storms, and reputation."""

    def __init__(
        self,
        window_seconds: int = 60,
        burst_404_threshold: int = 4,
        sensitive_probe_patterns: Optional[List[re.Pattern]] = None,
        max_tracked_ips: int = MAX_TRACKED_BEHAVIORAL_IPS,
    ):
        self.window_seconds = max(10, window_seconds)
        self.burst_404_threshold = burst_404_threshold
        self.sensitive_patterns = sensitive_probe_patterns or list(DEFAULT_SENSITIVE_PROBE_PATTERNS)
        self.max_tracked_ips = max_tracked_ips
        self.ip_windows: Dict[str, IPBehaviorWindow] = {}
        self.last_sweep: float = time.time()

    def is_sensitive_probe(self, url: str) -> bool:
        """Checks if URL matches known sensitive reconnaissance targets."""
        for pat in self.sensitive_patterns:
            if pat.search(url):
                return True
        return False

    def sweep_stale(self, now: float) -> None:
        """Evicts expired records and stale IPs outside the sliding window."""
        self.last_sweep = now
        cutoff = now - self.window_seconds

        stale_ips = []
        for ip, window in self.ip_windows.items():
            # Evict old records from deque
            while window.history and window.history[0].timestamp < cutoff:
                rec = window.history.popleft()
                if rec.is_404:
                    window.error_404_count = max(0, window.error_404_count - 1)
                if rec.is_403:
                    window.error_403_count = max(0, window.error_403_count - 1)
                if rec.is_sensitive_probe:
                    window.sensitive_probes_count = max(0, window.sensitive_probes_count - 1)
                if rec.has_entropy_anomaly:
                    window.entropy_anomaly_count = max(0, window.entropy_anomaly_count - 1)
                if rec.is_journey_anomaly:
                    window.journey_anomaly_count = max(0, window.journey_anomaly_count - 1)

            if not window.history and (now - window.last_activity > self.window_seconds):
                stale_ips.append(ip)

        for ip in stale_ips:
            del self.ip_windows[ip]

        # Enforce memory cap (LRU based on last_activity)
        excess = len(self.ip_windows) - self.max_tracked_ips
        if excess > 0:
            sorted_ips = sorted(self.ip_windows.items(), key=lambda kv: kv[1].last_activity)
            for stale_ip, _ in sorted_ips[:excess]:
                del self.ip_windows[stale_ip]

    def record_and_score(
        self,
        ip: str,
        method: str,
        url: str,
        status_code: int,
        has_entropy_anomaly: bool = False,
        journey_anomaly_reason: Optional[str] = None,
        raw_line: str = "",
        now: Optional[float] = None,
    ) -> Tuple[float, List[str], bool]:
        """Records an HTTP event in the IP's sliding window and recalculates suspicion score.

        Returns: (current_suspicion_score, list_of_active_reasons, is_404_storm)
        """
        now = now or time.time()
        if now - self.last_sweep >= SWEEP_INTERVAL_SECONDS:
            self.sweep_stale(now)

        window = self.ip_windows.get(ip)
        if window is None:
            window = IPBehaviorWindow(ip=ip, last_activity=now)
            self.ip_windows[ip] = window

        window.last_activity = now

        # Prune records in this window that aged out
        cutoff = now - self.window_seconds
        while window.history and window.history[0].timestamp < cutoff:
            rec = window.history.popleft()
            if rec.is_404:
                window.error_404_count = max(0, window.error_404_count - 1)
            if rec.is_403:
                window.error_403_count = max(0, window.error_403_count - 1)
            if rec.is_sensitive_probe:
                window.sensitive_probes_count = max(0, window.sensitive_probes_count - 1)
            if rec.has_entropy_anomaly:
                window.entropy_anomaly_count = max(0, window.entropy_anomaly_count - 1)
            if rec.is_journey_anomaly:
                window.journey_anomaly_count = max(0, window.journey_anomaly_count - 1)

        is_404 = (status_code == 404)
        is_403 = (status_code == 403)
        is_sensitive = self.is_sensitive_probe(url)
        is_journey = bool(journey_anomaly_reason)

        if is_404:
            window.error_404_count += 1
        if is_403:
            window.error_403_count += 1
        if is_sensitive:
            window.sensitive_probes_count += 1
        if has_entropy_anomaly:
            window.entropy_anomaly_count += 1
        if is_journey:
            window.journey_anomaly_count += 1

        window.history.append(
            RequestRecord(
                timestamp=now,
                method=method,
                url=url,
                status_code=status_code,
                is_404=is_404,
                is_403=is_403,
                is_sensitive_probe=is_sensitive,
                has_entropy_anomaly=has_entropy_anomaly,
                is_journey_anomaly=is_journey,
            )
        )

        # Detect 404 Storm (massive probing in sliding window)
        is_404_storm = window.error_404_count >= self.burst_404_threshold

        # Compute dynamic suspicion score based on weighted factors
        score = 0.0
        reasons: List[str] = []

        # 1. 404 Storm or individual 404 errors
        if is_404_storm:
            score += 45.0
            reasons.append(f"404 Storm ({window.error_404_count} not-found errors in {self.window_seconds}s)")
        elif window.error_404_count > 0:
            score += min(30.0, window.error_404_count * 8.0)
            reasons.append(f"{window.error_404_count}x 404 probes")

        # 2. 403 Forbidden errors
        if window.error_403_count > 0:
            score += min(40.0, window.error_403_count * 15.0)
            reasons.append(f"{window.error_403_count}x 403 forbidden access")

        # 3. Sensitive file probes (.git, .env, wp-config, etc.)
        if window.sensitive_probes_count > 0:
            probe_score = min(75.0, window.sensitive_probes_count * 25.0)
            score += probe_score
            reasons.append(f"{window.sensitive_probes_count}x sensitive file recon probes (.git/config/.env)")

        # 4. Parameter entropy / Structural payload anomaly
        if window.entropy_anomaly_count > 0:
            entropy_score = min(60.0, window.entropy_anomaly_count * 30.0)
            score += entropy_score
            reasons.append(f"{window.entropy_anomaly_count}x obfuscated/high-entropy parameter payload")

        # 5. User journey transition anomaly
        if window.journey_anomaly_count > 0:
            journey_score = min(50.0, window.journey_anomaly_count * 25.0)
            score += journey_score
            reasons.append(f"User journey anomaly ({journey_anomaly_reason or 'forced browsing'})")

        # 6. Scanner User-Agent detected in raw line
        ua = UserJourneyTracker.extract_user_agent(raw_line)
        if ua and RE_SCANNER_UA.search(ua):
            score += 40.0
            reasons.append(f"Known scanner tool User-Agent: {ua[:30]}")

        window.suspicion_score = round(score, 2)
        window.reasons = reasons

        return window.suspicion_score, reasons, is_404_storm

    def clear_ip(self, ip: str) -> None:
        """Clears an IP from tracking upon ban or whitelisting."""
        self.ip_windows.pop(ip, None)


# ==============================================================================
# 4. Mitigation Feedback Loop (Local Blacklist & Preventive Action)
# ==============================================================================


class PreventiveMitigationFeedbackLoop:
    """Manages proactive mitigation actions when an IP's suspicion score exceeds critical thresholds."""

    def __init__(self, blacklist_file: str = "preventive_blacklist.txt"):
        self.blacklist_file = blacklist_file
        self._mitigated_ips: Set[str] = set()
        self._ensure_file()

    def _ensure_file(self) -> None:
        try:
            if not os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, "w", encoding="utf-8") as f:
                    f.write("# UtilSec Sentinel - Preventive Mitigation Blacklist\n")
                    f.write(f"# Initialized at {datetime.now().isoformat()}\n")
            else:
                # Load existing IPs into cache
                with open(self.blacklist_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if parts:
                                self._mitigated_ips.add(parts[0])
        except Exception as exc:
            logger.warning("Could not initialize preventive blacklist file: %s", exc)

    def is_preventively_blocked(self, ip: str) -> bool:
        return ip in self._mitigated_ips

    def record_mitigation(self, ip: str, score: float, reasons: List[str]) -> bool:
        """Appends the suspicious IP to the preventive blacklist file."""
        if ip in self._mitigated_ips:
            return False
        self._mitigated_ips.add(ip)
        try:
            reason_str = "; ".join(reasons)
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.blacklist_file, "a", encoding="utf-8") as f:
                f.write(f"{ip:40s} # [{timestamp_str}] Score={score:.1f} - {reason_str}\n")
            return True
        except Exception as exc:
            logger.error("Failed to write IP %s to preventive blacklist: %s", ip, exc)
            return False


# ==============================================================================
# 5. Master Early-Stage Reconnaissance Engine
# ==============================================================================


@dataclass
class ReconEvaluationResult:
    """Result of comprehensive behavioral evaluation for a single request."""

    is_suspicious: bool
    should_ban_preventively: bool
    suspicion_score: float
    reasons: List[str]
    category: str
    parameter_anomalies: List[ParameterAnomaly]
    journey_anomaly: Optional[str]
    is_404_storm: bool


class EarlyStageReconEngine:
    """Orchestrates early-stage reconnaissance detection, parameter entropy analysis,

    user journey verification, and dynamic reputation scoring.
    """

    def __init__(
        self,
        config=None,
        window_seconds: int = 60,
        suspicion_ban_threshold: float = 100.0,
        entropy_threshold: float = 4.2,
        min_param_len: int = 14,
        burst_404_threshold: int = 4,
        special_char_ratio_threshold: float = 0.30,
        blacklist_file: str = "preventive_blacklist.txt",
    ):
        self.config = config
        self.window_seconds = getattr(config, "recon_window_seconds", window_seconds)
        self.suspicion_ban_threshold = getattr(config, "suspicion_ban_threshold", suspicion_ban_threshold)
        self.entropy_threshold = getattr(config, "entropy_threshold", entropy_threshold)
        self.min_param_len = getattr(config, "entropy_min_param_len", min_param_len)
        self.burst_404_threshold = getattr(config, "burst_404_rate_limit", burst_404_threshold)
        self.special_char_ratio_threshold = getattr(
            config, "special_char_ratio_threshold", special_char_ratio_threshold
        )
        self.blacklist_file = getattr(config, "preventive_mitigation_file", blacklist_file)

        # Components
        self.entropy_calc = ShannonEntropyCalculator()
        self.journey_tracker = UserJourneyTracker()
        self.sliding_tracker = SlidingWindowTracker(
            window_seconds=self.window_seconds,
            burst_404_threshold=self.burst_404_threshold,
        )
        self.mitigation_loop = PreventiveMitigationFeedbackLoop(blacklist_file=self.blacklist_file)

    def process_request(
        self,
        ip: str,
        method: str,
        url: str,
        status_code: int,
        raw_line: str = "",
        now: Optional[float] = None,
    ) -> ReconEvaluationResult:
        """Performs end-to-end behavioral evaluation for a single request.

        1. Inspects parameter entropy & structural anomalies.
        2. Evaluates user journey transition state.
        3. Updates sliding window and recalculates dynamic suspicion score.
        4. Triggers proactive mitigation feedback loop if threshold is reached.
        """
        now = now or time.time()

        # 1. Parameter Entropy & Obfuscation Analysis
        param_anomalies = self.entropy_calc.extract_and_analyze_parameters(
            url=url,
            raw_line=raw_line,
            entropy_threshold=self.entropy_threshold,
            min_param_len=self.min_param_len,
            special_char_ratio_threshold=self.special_char_ratio_threshold,
        )
        has_entropy_anomaly = len(param_anomalies) > 0

        # 2. User Journey State Analysis
        journey_anomaly = self.journey_tracker.evaluate_request(
            ip=ip,
            method=method,
            url=url,
            status_code=status_code,
            raw_line=raw_line,
            now=now,
        )

        # 3. Sliding Window Tracking & Dynamic Reputation Scoring
        score, reasons, is_404_storm = self.sliding_tracker.record_and_score(
            ip=ip,
            method=method,
            url=url,
            status_code=status_code,
            has_entropy_anomaly=has_entropy_anomaly,
            journey_anomaly_reason=journey_anomaly,
            raw_line=raw_line,
            now=now,
        )

        # Determine if threshold is crossed for preventive ban
        should_ban = score >= self.suspicion_ban_threshold
        is_suspicious = score >= 35.0 or has_entropy_anomaly or bool(journey_anomaly) or is_404_storm

        category = "behavioral"
        if is_404_storm:
            category = "404_storm"
        elif has_entropy_anomaly:
            category = "structural_anomaly"
        elif journey_anomaly:
            category = "journey_anomaly"
        elif self.sliding_tracker.is_sensitive_probe(url):
            category = "sensitive_probe"

        if should_ban:
            # Trigger mitigation feedback loop
            self.mitigation_loop.record_mitigation(ip=ip, score=score, reasons=reasons)
            # Clear IP window so counter starts fresh post-ban
            self.sliding_tracker.clear_ip(ip)

        return ReconEvaluationResult(
            is_suspicious=is_suspicious,
            should_ban_preventively=should_ban,
            suspicion_score=score,
            reasons=reasons,
            category=category,
            parameter_anomalies=param_anomalies,
            journey_anomaly=journey_anomaly,
            is_404_storm=is_404_storm,
        )

    def get_reputation(self, ip: str) -> float:
        """Returns the current suspicion score for an IP."""
        win = self.sliding_tracker.ip_windows.get(ip)
        return win.suspicion_score if win else 0.0

    def reset(self) -> None:
        """Resets all in-memory tracking windows."""
        self.sliding_tracker.ip_windows.clear()
        self.journey_tracker.profiles.clear()
