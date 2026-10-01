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
        self.raw_config: Dict[str, Any] = {}
        self.rules: List[Rule] = []
        self.whitelist_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.load()

    def load(self) -> None:
        """Loads configuration from JSON file or sets defaults."""
        # 1) Try given path as-is
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.raw_config = json.load(f)
                logging.getLogger("UtilSec.Config").info("Loaded configuration from %s", self.config_path)
            except Exception as e:
                logging.getLogger("UtilSec.Config").warning(
                    "Error loading %s: %s. Using fallback defaults.", self.config_path, e
                )
                self.raw_config = {}
        else:
            # 2) Try repo-relative path (useful when sentinel is started from another CWD)
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            alt_path = os.path.join(repo_root, self.config_path)
            if os.path.exists(alt_path):
                try:
                    with open(alt_path, "r", encoding="utf-8") as f:
                        self.raw_config = json.load(f)
                    logging.getLogger("UtilSec.Config").info("Loaded configuration from %s", alt_path)
                except Exception as e:
                    logging.getLogger("UtilSec.Config").warning(
                        "Error loading %s: %s. Using fallback defaults.", alt_path, e
                    )
                    self.raw_config = {}
            else:
                # 3) Try trailing .example next to requested path or repo root
                example_path = f"{self.config_path}.example"
                if os.path.exists(example_path):
                    try:
                        with open(example_path, "r", encoding="utf-8") as f:
                            self.raw_config = json.load(f)
                        logging.getLogger("UtilSec.Config").info("Loaded configuration from %s", example_path)
                    except Exception as e:
                        logging.getLogger("UtilSec.Config").warning(
                            "Error loading %s: %s. Using fallback defaults.", example_path, e
                        )
                        self.raw_config = {}
                else:
                    example_repo = os.path.join(repo_root, f"{self.config_path}.example")
                    if os.path.exists(example_repo):
                        try:
                            with open(example_repo, "r", encoding="utf-8") as f:
                                self.raw_config = json.load(f)
                            logging.getLogger("UtilSec.Config").info("Loaded configuration from %s", example_repo)
                        except Exception as e:
                            logging.getLogger("UtilSec.Config").warning(
                                "Error loading %s: %s. Using fallback defaults.", example_repo, e
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
        self.ban_subnet = bool(self.raw_config.get("ban_subnet", True))
        self.subnet_cidr_ipv4 = int(self.raw_config.get("subnet_cidr_ipv4", 24))
        self.subnet_cidr_ipv6 = int(self.raw_config.get("subnet_cidr_ipv6", 64))

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
        directory = os.path.dirname(os.path.abspath(self.config_path)) or "."
        tmp_path = None
        try:
            mode = 0o644
            try:
                mode = os.stat(self.config_path).st_mode & 0o777
            except OSError:
                pass

            fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.raw_config, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, self.config_path)
            tmp_path = None

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

