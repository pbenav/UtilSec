"""Long-horizon watchdog for slow scanners.

The 403/404 rate limiter in :mod:`core.detector` only looks at a short
in-memory window (``window_seconds``, typically 60s). A scanner that spreads
its probes over hours never reaches ``threshold_404``/``threshold_403``, so it
is recorded forever as ``probe`` events and never banned.

This watchdog accumulates those probes over a much longer horizon
(``probe_ban_window``, default 24h) and fires when ``probe_ban_threshold``
(default 100) is reached. Counts are restored from the events table on the
first hit after a restart, otherwise every reboot would reset the budget.
"""

import collections
import logging
import time
from typing import Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("UtilSec.Probes")

PROBE_SWEEP_INTERVAL = 30.0
PROBE_MAX_TRACKED_IPS = 100_000
# Bound for the per-IP history restored from SQLite: a row per probe would be
# pointless for an IP with tens of thousands of hits in the window.
PROBE_MAX_SEEDED = 5000


class ProbeWatchdog:
    """Counts ``probe`` events per IP over a long window and calls a ban."""

    def __init__(self, config, storage=None):
        self.config = config
        self.storage = storage
        self._hits: Dict[str, Deque[float]] = {}
        self._seeded: Set[str] = set()
        self._last_sweep = 0.0

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------
    @property
    def threshold(self) -> int:
        return max(0, int(getattr(self.config, "probe_ban_threshold", 0) or 0))

    @property
    def window(self) -> int:
        return max(60, int(getattr(self.config, "probe_ban_window", 86400) or 86400))

    @property
    def enabled(self) -> bool:
        return self.threshold > 0

    # ------------------------------------------------------------------
    # Bookkeeping
    # ------------------------------------------------------------------
    def _sweep(self, now: float) -> None:
        self._last_sweep = now
        cutoff = now - self.window
        for stale_ip in [ip for ip, hits in self._hits.items() if not hits or hits[-1] < cutoff]:
            del self._hits[stale_ip]
            self._seeded.discard(stale_ip)

    def _enforce_cap(self, keep_ip: str) -> None:
        """Bound memory: drop least recently active IPs, never the new one."""
        excess = len(self._hits) - PROBE_MAX_TRACKED_IPS
        if excess <= 0:
            return
        candidates = [ip for ip in self._hits if ip != keep_ip]
        for stale_ip in sorted(
            candidates, key=lambda ip: self._hits[ip][-1] if self._hits[ip] else 0.0
        )[:excess]:
            del self._hits[stale_ip]
            self._seeded.discard(stale_ip)

    def _seed(self, ip: str, hits: Deque[float], since: float, now: float) -> None:
        """Load the probes already persisted for this IP (once per IP)."""
        if ip in self._seeded:
            return
        self._seeded.add(ip)
        if self.storage is None:
            return
        try:
            restored: List[float] = self.storage.probe_history(ip, since, limit=PROBE_MAX_SEEDED)
        except Exception as exc:  # pragma: no cover - storage failures must not break ingest
            logger.warning("Could not restore probe history for %s: %s", ip, exc)
            return
        for ts in restored:
            if since <= ts < now:
                hits.append(ts)
        if len(restored) >= PROBE_MAX_SEEDED:
            logger.info("Probe history for %s was capped at %d rows", ip, PROBE_MAX_SEEDED)


    def record(self, ip: str, now: Optional[float] = None) -> Optional[Tuple[int, int]]:
        """Register one probe for `ip`.

        Returns ``(count, window)`` when the ban must fire, ``None`` otherwise
        (disabled, below threshold, or no storage to seed from).
        """
        thr = self.threshold
        if thr <= 0:
            return None

        now = time.time() if now is None else now
        if now - self._last_sweep >= PROBE_SWEEP_INTERVAL:
            self._sweep(now)

        hits = self._hits.get(ip)
        if hits is None:
            hits = collections.deque()
            self._hits[ip] = hits
            self._enforce_cap(ip)
        self._seed(ip, hits, now - self.window, now)

        hits.append(now)
        count = len(hits)
        if count < thr:
            return None

        # Clear before the ban is applied so the next window starts clean and
        # the watchdog does not re-ban on every subsequent probe.
        hits.clear()
        return (count, self.window)

    def reset(self) -> None:
        self._hits.clear()
        self._seeded.clear()
