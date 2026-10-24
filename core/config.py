"""Configuration manager for UtilSec Sentinel."""

import ipaddress
import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional, Set, Union

from core.models import Rule


def parse_ip_or_network(value: Any) -> Optional[str]:
    """Validate and normalize an IP address or CIDR network.

    Returns the canonical string form, or ``None`` when the input is not a
    well-formed IPv4/IPv6 address or network. This is the single choke point
    used before anything reaches the firewall or the generated audit scripts,
    so arbitrary text (``1.2.3.4; rm -rf /``) can never travel further.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch.isspace() for ch in value):
        return None
    # ipaddress rejects shell metacharacters, quotes, $, backticks, etc.
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


class ConfigManager:
    """Loads, saves and provides access to configuration options and rules."""

    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.resolved_config_path: str = os.path.abspath(config_path) if os.path.exists(config_path) else config_path
        self._last_mtime: float = 0.0
        self.raw_config: Dict[str, Any] = {}
        self.rules: List[Rule] = []
        self.whitelist_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.load()

    def load(self) -> None:
        """Loads configuration from JSON file or sets defaults."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        alt_path = os.path.join(repo_root, self.config_path)
        example_path = f"{self.config_path}.example"
        example_repo = os.path.join(repo_root, f"{self.config_path}.example")

        chosen_path = None
        if os.path.exists(self.config_path):
            chosen_path = self.config_path
        elif os.path.exists(alt_path):
            chosen_path = alt_path
        elif os.path.exists(example_path):
            chosen_path = example_path
        elif os.path.exists(example_repo):
            chosen_path = example_repo

        if chosen_path:
            try:
                with open(chosen_path, "r", encoding="utf-8") as f:
                    self.raw_config = json.load(f)
                self.resolved_config_path = os.path.abspath(chosen_path)
                try:
                    self._last_mtime = os.path.getmtime(self.resolved_config_path)
                except OSError:
                    pass
                logging.getLogger("UtilSec.Config").info("Loaded configuration from %s", chosen_path)
            except Exception as e:
                logging.getLogger("UtilSec.Config").warning(
                    "Error loading %s: %s. Using fallback defaults.", chosen_path, e
                )
                self.raw_config = {}
        else:
            self.raw_config = {}

        # Set default values if missing
        self.log_file = self.raw_config.get("log_file", "logs")
        raw_log_files = self.raw_config.get("log_files", [])
        self.log_files: List[Dict[str, str]] = []
        if raw_log_files:
            for item in raw_log_files:
                if isinstance(item, dict) and "path" in item:
                    name = item.get("name") or os.path.basename(item["path"])
                    self.log_files.append({"name": name, "path": item["path"]})
                elif isinstance(item, str):
                    self.log_files.append({"name": os.path.basename(item), "path": item})
        else:
            self.log_files.append({"name": os.path.basename(self.log_file), "path": self.log_file})

        # Emit a concise log of loaded log_files for debugging/visibility
        try:
            logging.getLogger("UtilSec.Config").info("Configured log_files: %s", self.log_files)
        except Exception:
            pass

        self.firewall_backend = self.raw_config.get("firewall_backend", "auto")
        self.dry_run = self.raw_config.get("dry_run", True)
        self.default_ban_duration = int(self.raw_config.get("default_ban_duration", 3600))
        self.threshold_404 = int(self.raw_config.get("threshold_404", 2))
        self.threshold_403 = int(self.raw_config.get("threshold_403", 1))
        self.window_seconds = int(self.raw_config.get("window_seconds", 60))
        # Long-horizon ban for slow scanners: the 403/404 windows above are
        # in-memory and only cover `window_seconds`, so an IP that spreads its
        # probes over hours is never banned. 0 disables the watchdog.
        self.probe_ban_threshold = max(0, int(self.raw_config.get("probe_ban_threshold", 100)))
        self.probe_ban_window = max(60, int(self.raw_config.get("probe_ban_window", 86400)))
        self.ban_subnet = bool(self.raw_config.get("ban_subnet", True))
        self.subnet_cidr_ipv4 = int(self.raw_config.get("subnet_cidr_ipv4", 24))
        self.subnet_cidr_ipv6 = int(self.raw_config.get("subnet_cidr_ipv6", 64))

        # Behavioral & Early-Stage Reconnaissance Configuration
        self.behavioral_defense_enabled = bool(self.raw_config.get("behavioral_defense_enabled", True))
        self.recon_window_seconds = int(self.raw_config.get("recon_window_seconds", 60))
        self.suspicion_ban_threshold = float(self.raw_config.get("suspicion_ban_threshold", 100.0))
        self.entropy_threshold = float(self.raw_config.get("entropy_threshold", 4.2))
        self.entropy_min_param_len = int(self.raw_config.get("entropy_min_param_len", 14))
        self.special_char_ratio_threshold = float(self.raw_config.get("special_char_ratio_threshold", 0.25))
        self.burst_404_rate_limit = int(self.raw_config.get("burst_404_rate_limit", 4))
        self.preventive_mitigation_file = str(self.raw_config.get("preventive_mitigation_file", "preventive_blacklist.txt"))

        # Ignored paths: list of URL substrings/prefixes exempt from 404/403 rate-limiting and repeat-attack bans
        self.ignored_paths: List[str] = [
            str(p).strip().lower() for p in self.raw_config.get("ignored_paths", []) if str(p).strip()
        ]

        # Parse whitelist
        self.whitelist_raw = self.raw_config.get("whitelist", [
            "127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        ])
        self._parse_whitelist()

        # Build rules list
        self._build_rules()

    def _parse_whitelist(self) -> None:
        self.whitelist_networks = []
        for entry in self.whitelist_raw:
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                else:
                    ip = ipaddress.ip_address(entry)
                    net = ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}")
                self.whitelist_networks.append(net)
            except ValueError:
                pass

    def _build_rules(self) -> None:
        self.rules = []
        # User defined patterns (instant ban or high priority)
        user_patterns = self.raw_config.get("user_patterns", [])
        for idx, pat in enumerate(user_patterns):
            self.rules.append(
                Rule(
                    id=f"user_pat_{idx}",
                    name=f"User Pattern: {pat}",
                    pattern=pat,
                    is_regex=False,
                    critical=True,
                    category="user",
                    enabled=True,
                )
            )

        # Heuristic rules
        heuristic_rules = self.raw_config.get("heuristic_rules", [])
        # Inject WAF / ModSecurity rule automatically if not present
        has_waf = any(h.get("id") == "modsecurity_waf" for h in heuristic_rules)
        if not has_waf:
            heuristic_rules.append({
                "id": "modsecurity_waf",
                "name": "WAF Block (ModSecurity / OWASP)",
                "pattern": "ModSecurity: Access denied|ModSecurity: Warning",
                "is_regex": True,
                "critical": True,
                "category": "exploit"
            })
        for h in heuristic_rules:
            self.rules.append(
                Rule(
                    id=h.get("id", f"heur_{len(self.rules)}"),
                    name=h.get("name", "Unknown heuristic"),
                    pattern=h.get("pattern", ""),
                    is_regex=h.get("is_regex", True),
                    critical=h.get("critical", True),
                    category=h.get("category", "heuristic"),
                    enabled=h.get("enabled", True),
                )
            )

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP is in the whitelist networks."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            for net in self.whitelist_networks:
                if ip in net:
                    return True
        except ValueError:
            return False
        return False

    def get_ban_target(self, ip_str: str) -> str:
        """
        Calculates the ban target. If ban_subnet is True, returns the subnet
        (e.g. /24 for IPv4, /64 for IPv6) to eliminate the entire subnet.

        Returns an empty string when the input is not a valid IP/network, so
        callers can refuse the ban instead of forwarding untrusted text.
        """
        normalized = parse_ip_or_network(ip_str)
        if normalized is None:
            return ""
        if not self.ban_subnet:
            return normalized
        try:
            if "/" in normalized:
                net = ipaddress.ip_network(normalized, strict=False)
            else:
                ip = ipaddress.ip_address(normalized)
                cidr = self.subnet_cidr_ipv4 if ip.version == 4 else self.subnet_cidr_ipv6
                net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
            # Whitelist protection: if subnet overlaps with any whitelisted network, fallback to single IP
            for wnet in self.whitelist_networks:
                if net.overlaps(wnet):
                    return normalized
            return str(net)
        except ValueError:
            return normalized

    def add_user_pattern(self, pattern: str) -> bool:
        """Add a custom attack string dynamically and persist to config."""
        pattern = pattern.strip()
        if not pattern:
            return False
        patterns = self.raw_config.get("user_patterns", [])
        if pattern not in patterns:
            patterns.append(pattern)
            self.raw_config["user_patterns"] = patterns
            self.save()
            self._build_rules()
            return True
        return False

    def remove_user_pattern(self, pattern: str) -> bool:
        """Remove a custom attack string from config and persist changes."""
        pattern = pattern.strip()
        if not pattern:
            return False
        patterns = self.raw_config.get("user_patterns", [])
        if pattern in patterns:
            patterns.remove(pattern)
            self.raw_config["user_patterns"] = patterns
            self.save()
            self._build_rules()
            return True
        return False

    def is_path_ignored(self, url: str) -> bool:
        """Check if a URL matches any configured ignored path."""
        if not getattr(self, "ignored_paths", None) or not url:
            return False
        url_lower = url.lower()
        return any(ignored in url_lower for ignored in self.ignored_paths)

    def add_ignored_path(self, path: str, persist: bool = False) -> bool:
        """Add a path to ignored_paths and optionally persist changes."""
        path_clean = path.strip().lower()
        if not path_clean:
            return False
        if path_clean not in self.ignored_paths:
            self.ignored_paths.append(path_clean)
            if persist:
                raw_paths = self.raw_config.get("ignored_paths", [])
                if path.strip() not in raw_paths:
                    raw_paths.append(path.strip())
                self.raw_config["ignored_paths"] = raw_paths
                self.save()
            return True
        return False

    def remove_ignored_path(self, path: str, persist: bool = False) -> bool:
        """Remove a path from ignored_paths and optionally persist changes."""
        path_clean = path.strip().lower()
        if not path_clean:
            return False
        if path_clean in self.ignored_paths:
            self.ignored_paths.remove(path_clean)
            if persist:
                raw_paths = [p for p in self.raw_config.get("ignored_paths", []) if p.strip().lower() != path_clean]
                self.raw_config["ignored_paths"] = raw_paths
                self.save()
            return True
        return False

    def add_log_file(self, name: str, path: str, persist: bool = False) -> bool:
        """Add a log file to configuration."""
        name = name.strip() or os.path.basename(path.strip())
        path = path.strip()
        for item in self.log_files:
            if item["path"] == path or item["name"] == name:
                return False
        self.log_files.append({"name": name, "path": path})
        if persist:
            self.raw_config["log_files"] = self.log_files
            self.save()
        return True

    def remove_log_file(self, name: str, persist: bool = False) -> bool:
        """Remove a log file from configuration."""
        new_list = [f for f in self.log_files if f["name"] != name and f["path"] != name]
        if len(new_list) < len(self.log_files):
            self.log_files = new_list
            if persist:
                self.raw_config["log_files"] = self.log_files
                self.save()
            return True
        return False

    def save(self) -> None:
        """Atomically save the configuration to disk.

        The file used to be truncated in place, so a crash or power loss in the
        middle of the write left a corrupt config.json. The next start then
        silently fell back to defaults - losing the whitelist, which is exactly
        what stops the server from banning itself.
        """
        target_path = getattr(self, "resolved_config_path", self.config_path) or self.config_path
        directory = os.path.dirname(os.path.abspath(target_path)) or "."
        tmp_path = None
        try:
            mode = 0o644
            try:
                mode = os.stat(target_path).st_mode & 0o777
            except OSError:
                pass

            fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.raw_config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, target_path)
            tmp_path = None
            try:
                self._last_mtime = os.path.getmtime(target_path)
            except OSError:
                pass

            # Persist the rename itself, not just the file contents.
            try:
                dir_fd = os.open(directory, os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except Exception as e:
            logging.getLogger("UtilSec.Config").error("Could not save configuration: %s", e)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def add_whitelist(self, ip_or_net: str, persist: bool = True) -> bool:
        """Add an IP or CIDR network to the whitelist."""
        normalized = parse_ip_or_network(ip_or_net)
        if not normalized:
            return False
        if normalized not in self.whitelist_raw:
            self.whitelist_raw.append(normalized)
            self.raw_config["whitelist"] = list(self.whitelist_raw)
            self._parse_whitelist()
            if persist:
                self.save()
            return True
        return False

    def remove_whitelist(self, ip_or_net: str, persist: bool = True) -> bool:
        """Remove an IP or CIDR network from the whitelist."""
        normalized = parse_ip_or_network(ip_or_net)
        target = normalized or (ip_or_net.strip() if isinstance(ip_or_net, str) else "")
        if target and target in self.whitelist_raw:
            self.whitelist_raw.remove(target)
            self.raw_config["whitelist"] = list(self.whitelist_raw)
            self._parse_whitelist()
            if persist:
                self.save()
            return True
        return False

    def update_setting(self, key: str, value: Any, persist: bool = True) -> bool:
        """Update a configuration setting in memory and optionally persist to disk."""
        int_fields = {
            "default_ban_duration": (1, 86400 * 365),
            "threshold_404": (1, 100000),
            "threshold_403": (1, 100000),
            "window_seconds": (1, 86400 * 7),
            "probe_ban_threshold": (0, 1000000),
            "probe_ban_window": (60, 86400 * 365),
            "subnet_cidr_ipv4": (8, 32),
            "subnet_cidr_ipv6": (16, 128),
        }
        if key in int_fields:
            try:
                val = int(value)
                min_v, max_v = int_fields[key]
                if not (min_v <= val <= max_v):
                    return False
                setattr(self, key, val)
                self.raw_config[key] = val
            except (ValueError, TypeError):
                return False
        elif key in ("ban_subnet", "dry_run"):
            val = bool(value)
            setattr(self, key, val)
            self.raw_config[key] = val
        elif key in ("firewall_backend", "log_file"):
            val = str(value).strip()
            if not val:
                return False
            setattr(self, key, val)
            self.raw_config[key] = val
        else:
            setattr(self, key, value)
            self.raw_config[key] = value

        if persist:
            self.save()
        return True

    def check_and_reload_if_modified(self) -> bool:
        """Check if the configuration file has been modified externally and reload if so.

        Returns True if a valid modification was detected and loaded, False otherwise.
        """
        target_path = getattr(self, "resolved_config_path", self.config_path)
        if not target_path or not os.path.exists(target_path):
            return False
        try:
            mtime = os.path.getmtime(target_path)
        except OSError:
            return False

        if mtime <= getattr(self, "_last_mtime", 0.0):
            return False

        # Verify that the file contains valid JSON before loading
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                new_data = json.load(f)
            if not isinstance(new_data, dict):
                return False
        except Exception as e:
            logging.getLogger("UtilSec.Config").warning(
                "External change detected on %s, but file contains invalid JSON (%s). Retaining active config.",
                target_path, e
            )
            return False

        self.load()
        return True

