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
    s = ip_str.strip()
    if not s:
        return None
    # Remove surrounding brackets [::1]:port -> ::1
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    # If IPv4 with port like 1.2.3.4:12345, strip port
    if "." in s and ":" in s:
        tail = s.rsplit(":", 1)[1]
        if tail.isdigit():
            s = s.rsplit(":", 1)[0]
    # Accept CIDR/network forms as-is
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            return str(net)
        ip = ipaddress.ip_address(s)
        return str(ip)
    except Exception:
        return None
