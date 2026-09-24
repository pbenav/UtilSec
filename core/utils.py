"""Utility helpers for IP validation and normalization."""

import ipaddress
from typing import Optional


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except Exception:
        return False


def normalize_ip(ip_str: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except Exception:
        return None
