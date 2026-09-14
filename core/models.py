"""Data models for UtilSec Sentinel."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AttackEvent:
    ip: str
    method: str
    url: str
    status_code: int
    matched_rule: str
    category: str
    timestamp: datetime = field(default_factory=datetime.now)
    raw_line: str = ""
    source_log: str = ""

    def summary(self) -> str:
        time_str = self.timestamp.strftime("%H:%M:%S")
        src = f"[{self.source_log}] " if self.source_log else ""
        return f"[{time_str}] {src}{self.ip} -> {self.method} {self.url} [{self.status_code}] ({self.matched_rule})"


@dataclass
class BanRecord:
    ip: str
    reason: str
    matched_pattern: str
    attack_count: int
    banned_at: float  # epoch timestamp
    ban_duration: int  # in seconds
    status: str = "BANNED"  # BANNED, SIMULATED, UNBANNED, EXPIRED
    backend: str = "dry-run"
    last_url: str = ""

    @property
    def unban_at(self) -> float:
        if self.ban_duration <= 0:
            return float("inf")  # permanent ban
        return self.banned_at + self.ban_duration

    @property
    def remaining_seconds(self) -> int:
        if self.ban_duration <= 0:
            return 999999
        rem = int(self.unban_at - datetime.now().timestamp())
        return max(0, rem)

    @property
    def is_expired(self) -> bool:
        if self.ban_duration <= 0:
            return False
        return datetime.now().timestamp() >= self.unban_at


@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    is_regex: bool = False
    critical: bool = True  # True = ban on 1st hit; False = count towards threshold
    category: str = "heuristic"
    enabled: bool = True
    hits: int = 0

