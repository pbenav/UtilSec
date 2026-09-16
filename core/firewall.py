import ipaddress
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from core.models import BanRecord
from core.storage import StorageManager

logger = logging.getLogger("UtilSec.Firewall")


class FirewallManager:
    """Manages IP and Subnet banning, unbanning, and expiration across various backends."""

    def __init__(
        self,
        backend: str = "auto",
        dry_run: bool = True,
        storage: Optional[StorageManager] = None,
        on_ban_change: Optional[Callable[[BanRecord, str], None]] = None,
        ban_subnet: bool = True,
        subnet_cidr: int = 24,
    ):
        self.requested_backend = backend
        self.dry_run = dry_run
        self.storage = storage
        self.on_ban_change = on_ban_change
        self.ban_subnet = ban_subnet
        self.subnet_cidr = subnet_cidr

        self.lock = threading.Lock()
        self.active_bans: Dict[str, BanRecord] = {}
        self.running = True

        self.active_backend = self._detect_backend()
        self._init_scripts()

        # Load existing active bans from storage and normalize to /24 subnets
        if self.storage:
            loaded = self.storage.load_active_bans()
            now = time.time()
            with self.lock:
                for orig_ip, record in loaded.items():
                    target = self.to_subnet(orig_ip)
                    record.ip = target
                    # If already expired while app was offline, mark as EXPIRED
                    if record.ban_duration > 0 and now >= record.unban_at:
                        self.storage.update_ban_status(target, "EXPIRED")
                        continue

                    # If starting in LIVE mode, ensure the system firewall rule is active in kernel
                    if not self.dry_run:
                        record.status = "BANNED"
                        record.backend = self.active_backend
                        self._exec_ban_system(record)
                        self.storage.save_ban(record)

                    self.active_bans[target] = record

        # Start expiration reaper thread
        self.reaper_thread = threading.Thread(target=self._expiration_loop, daemon=True)
        self.reaper_thread.start()

    def _detect_backend(self) -> str:
        """Determines whether real firewall or dry-run should be used."""
        if self.dry_run:
            return "dry-run"

        is_root = os.geteuid() == 0
        pref = self.requested_backend.lower()
        if pref in ("iptables", "ufw", "nft"):
            bin_path = shutil.which(pref)
            if bin_path and (is_root or self._check_sudo(pref)):
                return pref
            logger.warning("Requested backend %s requires root/sudo privileges. Falling back to dry-run.", pref)
            self.dry_run = True
            return "dry-run"

        for cand in ["iptables", "ufw", "nft"]:
            if shutil.which(cand) and (is_root or self._check_sudo(cand)):
                return cand

        self.dry_run = True
        return "dry-run"

    def _check_sudo(self, cmd: str) -> bool:
        try:
            res = subprocess.run(["sudo", "-n", cmd, "-V" if cmd == "iptables" else "--version"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return res.returncode == 0
        except Exception:
            return False

    def _init_scripts(self) -> None:
        """Create shell scripts for audit and manual execution in dry-run mode."""
        for filename in ["banned_ips.sh", "unban_ips.sh"]:
            if not os.path.exists(filename):
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("#!/bin/bash\n# UtilSec Sentinel Generated Firewall Script\n\n")
                os.chmod(filename, 0o755)

    def to_subnet(self, ip_str: str) -> str:
        """Converts an IP into its /24 subnet (or /64 for IPv6) if ban_subnet is enabled."""
        ip_str = ip_str.strip()
        if not self.ban_subnet or "/" in ip_str:
            return ip_str
        try:
            addr = ipaddress.ip_address(ip_str)
            cidr = self.subnet_cidr if addr.version == 4 else 64
            net = ipaddress.ip_network(f"{addr}/{cidr}", strict=False)
            return str(net)
        except ValueError:
            return ip_str

    def is_ip_banned(self, ip_str: str) -> Optional[BanRecord]:
        """Checks if an IP matches an active ban or belongs to a banned subnet."""
        ip_str = ip_str.strip()
        with self.lock:
            if ip_str in self.active_bans:
                return self.active_bans[ip_str]
            try:
                addr = ipaddress.ip_address(ip_str)
                for target, record in self.active_bans.items():
                    if "/" in target:
                        try:
                            if addr in ipaddress.ip_network(target, strict=False):
                                return record
                        except ValueError:
                            pass
            except ValueError:
                pass
        return None

    def _get_safe_subnets(self, network, whitelist_nets: List) -> List:
        """Split a network into subnets that don't overlap with any whitelisted network.

        Recursively splits the network until all resulting subnets are either
        fully outside whitelisted ranges or are single IPs that are whitelisted.
        """
        safe = []
        stack = [network]
        while stack:
            net = stack.pop()
            # Check if this network overlaps with any whitelisted network
            overlaps_whitelist = False
            for wnet in whitelist_nets:
                if net.overlaps(wnet):
                    overlaps_whitelist = True
                    break

            if not overlaps_whitelist:
                # Entire network is safe
                safe.append(net)
            elif net.prefixlen == (net.version == 4 and 32 or 128):
                # Single IP and it overlaps — it's whitelisted, skip it
                pass
            else:
                # Split in half and check each half
                try:
                    stack.extend(net.subnets())
                except (ValueError, TypeError):
                    # Last resort: skip this network
                    pass
        return safe

    def ban_ip(
        self,
        ip: str,
        reason: str,
        matched_pattern: str,
        duration: int,
        last_url: str = "",
        count: int = 1,
        config=None,
    ) -> bool:
        """Bans an IP or Subnet (e.g. /24) for `duration` seconds.

        If ban_subnet is enabled and the target subnet contains whitelisted IPs,
        the subnet is automatically split into safe sub-ranges that exclude them.
        """
        # Resolve target subnet
        target = self.to_subnet(ip)

        # Whitelist-aware splitting: if the /24 overlaps with whitelisted networks,
        # compute safe sub-ranges that exclude those whitelisted IPs
        if config and self.ban_subnet and "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                safe_subnets = self._get_safe_subnets(net, config.whitelist_networks)
                if safe_subnets:
                    # Ban each safe subnet individually
                    for subnet in safe_subnets:
                        self._do_ban(
                            ip=str(subnet),
                            reason=reason,
                            matched_pattern=matched_pattern,
                            duration=duration,
                            last_url=last_url,
                            count=count,
                        )
                    # Report the first safe subnet as the primary result
                    return True
                else:
                    # Entire subnet is whitelisted — don't ban anything
                    logger.warning(
                        "Refusing to ban %s: entire range overlaps with whitelisted networks",
                        target,
                    )
                    return False
            except (ValueError, TypeError):
                pass

        # No whitelist conflict or single IP — ban directly
        return self._do_ban(target, reason, matched_pattern, duration, last_url, count)

    def _do_ban(self, ip: str, reason: str, matched_pattern: str, duration: int,
                last_url: str, count: int) -> bool:
        """Internal: create a ban record and execute firewall rules for a single target."""
        now = time.time()
        with self.lock:
            if ip in self.active_bans:
                record = self.active_bans[ip]
                record.attack_count += count
                record.last_url = last_url or record.last_url
                record.banned_at = now
                if duration > record.ban_duration:
                    record.ban_duration = duration

                if not self.dry_run:
                    record.status = "BANNED"
                    record.backend = self.active_backend
                    self._exec_ban_system(record)

                if self.storage:
                    self.storage.save_ban(record)
                return True

            record = BanRecord(
                ip=ip,
                reason=reason,
                matched_pattern=matched_pattern,
                attack_count=count,
                banned_at=now,
                ban_duration=duration,
                status="SIMULATED" if self.dry_run else "BANNED",
                backend=self.active_backend,
                last_url=last_url,
            )
            self.active_bans[ip] = record

        self._exec_ban_system(record)

        if self.storage:
            self.storage.save_ban(record)

        if self.on_ban_change:
            self.on_ban_change(record, "BAN")

        return True

    def unban_ip(self, ip: str, manual: bool = False) -> bool:
        """Unbans an IP address or subnet."""
        record: Optional[BanRecord] = None
        target = ip.strip()
        with self.lock:
            if target not in self.active_bans:
                target = self.to_subnet(target)

            if target in self.active_bans:
                record = self.active_bans.pop(target)
                record.status = "UNBANNED" if manual else "EXPIRED"

        if not record:
            return False

        # Execute system firewall remove command
        self._exec_unban_system(record)

        if self.storage:
            self.storage.update_ban_status(record.ip, record.status)

        if self.on_ban_change:
            self.on_ban_change(record, "UNBAN")

        return True

    def _exec_ban_system(self, record: BanRecord) -> None:
        ip = record.ip
        cmd = []
        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]

        if self.active_backend == "iptables":
            check_cmd = prefix + ["iptables", "-w", "5", "-C", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
            cmd = prefix + ["iptables", "-w", "5", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
            if not self.dry_run:
                try:
                    exists = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                    if exists:
                        return
                except Exception:
                    pass
        elif self.active_backend == "ufw":
            cmd = prefix + ["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", "UtilSec"]
        elif self.active_backend == "nft":
            cmd = prefix + ["nft", "add", "element", "inet", "filter", "utilsec_bans", f"{{ {ip} }}"]

        # If dry-run or failed execution, log to script
        cmd_str = " ".join(cmd) if cmd else f"iptables -I INPUT -s {ip} -j DROP # UtilSec ({record.reason})"
        with open("banned_ips.sh", "a", encoding="utf-8") as f:
            f.write(f"# [{datetime.now().isoformat()}] {record.reason} (URL: {record.last_url})\n{cmd_str}\n")

        if not self.dry_run and cmd:
            try:
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode("utf-8", errors="replace").strip()
                logger.error("Failed to execute ban on %s: %s (stderr: %s)", ip, e, err_msg)
                record.status = "ERROR"
            except Exception as e:
                logger.error("Failed to execute ban on %s: %s", ip, e)
                record.status = "ERROR"

    def _exec_unban_system(self, record: BanRecord) -> None:
        ip = record.ip
        cmd = []
        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]

        if self.active_backend == "iptables":
            cmd = prefix + ["iptables", "-w", "5", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
        elif self.active_backend == "ufw":
            cmd = prefix + ["ufw", "delete", "deny", "from", ip, "to", "any"]
        elif self.active_backend == "nft":
            cmd = prefix + ["nft", "delete", "element", "inet", "filter", "utilsec_bans", f"{{ {ip} }}"]

        cmd_str = " ".join(cmd) if cmd else f"iptables -D INPUT -s {ip} -j DROP # UtilSec unban"
        with open("unban_ips.sh", "a", encoding="utf-8") as f:
            f.write(f"# [{datetime.now().isoformat()}] Unban {ip}\n{cmd_str}\n")

        if not self.dry_run and cmd:
            try:
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except Exception as e:
                logger.error("Failed to execute unban on %s: %s", ip, e)

    def _expiration_loop(self) -> None:
        """Periodically checks for expired bans and removes them."""
        while self.running:
            try:
                expired: List[str] = []
                now = time.time()
                with self.lock:
                    for ip, record in list(self.active_bans.items()):
                        if record.ban_duration > 0 and now >= record.unban_at:
                            expired.append(ip)

                for ip in expired:
                    self.unban_ip(ip, manual=False)

            except Exception as e:
                logger.error("Error in expiration loop: %s", e)

            time.sleep(1.0)

    def _scan_iptables_rules(self) -> List[BanRecord]:
        """Scan iptables for UtilSec DROP/REJECT rules not in active_bans."""
        records: List[BanRecord] = []
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return records
            lines = result.stdout.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                line = line.strip()
                if "DROP" not in line and "REJECT" not in line:
                    continue
                if "UtilSec" not in line:
                    continue
                # Format: "DROP       all  --  17.166.23.0/24       0.0.0.0/0            /* UtilSec */"
                # The source IP is always the first IP-like token after the action
                parts = line.split()
                for i, part in enumerate(parts):
                    # Skip action words and protocol markers
                    if part in ("DROP", "REJECT", "all", "--", "0.0.0.0/0", "0.0.0.0"):
                        continue
                    try:
                        ipaddress.ip_network(part, strict=False)
                        # Extract the actual IP (first host in the network)
                        network = ipaddress.ip_network(part, strict=False)
                        ip = str(network.network_address)
                        # Only accept /32 or /24 networks (individual IPs or subnets)
                        if network.prefixlen in (24, 32) and ip not in self.active_bans:
                            records.append(BanRecord(
                                ip=ip,
                                reason="External iptables rule (UtilSec)",
                                matched_pattern="manual",
                                attack_count=0,
                                banned_at=0.0,
                                ban_duration=0,
                                status="BANNED",
                                backend="iptables",
                            ))
                        break
                    except ValueError:
                        continue
        except Exception as e:
            logger.debug("Error scanning iptables: %s", e)
        return records

    def _scan_ufw_rules(self) -> List[BanRecord]:
        """Scan ufw for UtilSec deny rules not in active_bans."""
        records: List[BanRecord] = []
        try:
            result = subprocess.run(
                ["ufw", "status", "numbered"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return records
            lines = result.stdout.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                if "deny" not in line.lower() and "reject" not in line.lower():
                    continue
                if "UtilSec" not in line:
                    continue
                # Extract IP from: "from <IP>"
                parts = line.split()
                ip = None
                for i, part in enumerate(parts):
                    if part == "from" and i + 1 < len(parts):
                        candidate = parts[i + 1]
                        try:
                            ipaddress.ip_address(candidate)
                            ip = candidate
                            break
                        except ValueError:
                            continue
                if ip and ip not in self.active_bans:
                    records.append(BanRecord(
                        ip=ip,
                        reason="External ufw rule (UtilSec)",
                        matched_pattern="manual",
                        attack_count=0,
                        banned_at=0.0,
                        ban_duration=0,
                        status="BANNED",
                        backend="ufw",
                    ))
        except Exception as e:
            logger.debug("Error scanning ufw: %s", e)
        return records

    def _scan_nft_rules(self) -> List[BanRecord]:
        """Scan nftables for UtilSec ban rules not in active_bans."""
        records: List[BanRecord] = []
        try:
            result = subprocess.run(
                ["nft", "list", "table", "inet", "filter"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return records
            output = result.stdout.decode("utf-8", errors="replace")
            if "utilsec_bans" not in output:
                return records
            # Extract IPs from the set
            in_set = False
            for line in output.splitlines():
                if "utilsec_bans" in line and "{" in line:
                    in_set = True
                    continue
                if in_set:
                    if "}" in line:
                        break
                    for token in line.replace("{", " ").replace("}", " ").replace(",", " ").split():
                        token = token.strip()
                        if not token or token.startswith('"') or token.startswith("'"):
                            continue
                        try:
                            ipaddress.ip_address(token)
                            if token not in self.active_bans:
                                records.append(BanRecord(
                                    ip=token,
                                    reason="External nft rule (UtilSec)",
                                    matched_pattern="manual",
                                    attack_count=0,
                                    banned_at=0.0,
                                    ban_duration=0,
                                    status="BANNED",
                                    backend="nft",
                                ))
                        except ValueError:
                            continue
        except Exception as e:
            logger.debug("Error scanning nftables: %s", e)
        return records

    def get_active_bans_list(self, sort_by_ip: bool = False) -> List[BanRecord]:
        with self.lock:
            # Start with internal (dynamic) bans from Sentinel
            internal_bans: Dict[str, BanRecord] = {}
            for b in self.active_bans.values():
                internal_bans[b.ip] = b

            # Collect external firewall rules (always scan, even in dry-run)
            external_bans: List[BanRecord] = []
            if self.active_backend == "iptables":
                external_bans = self._scan_iptables_rules()
            elif self.active_backend == "ufw":
                external_bans = self._scan_ufw_rules()
            elif self.active_backend == "nft":
                external_bans = self._scan_nft_rules()

            # External bans indexed by IP
            external_by_ip: Dict[str, BanRecord] = {}
            for b in external_bans:
                if b.ip not in external_by_ip:
                    external_by_ip[b.ip] = b

            # Merge: internal bans take priority over external rules for same IP
            result: List[BanRecord] = list(internal_bans.values())
            for ip, ext_ban in external_by_ip.items():
                if ip not in internal_bans:
                    result.append(ext_ban)

            if sort_by_ip:
                return sorted(result, key=lambda r: ipaddress.ip_address(r.ip.split('/')[0]))
            return sorted(result, key=lambda r: r.banned_at, reverse=True)

    def clean_all_utilsec_rules(self) -> int:
        """Remove ALL iptables/ufw/nft rules created by UtilSec.
        
        Called on startup to clear stale firewall state.
        Returns: number of rules removed.
        """
        removed = 0
        if self.dry_run:
            return 0
        
        try:
            if self.active_backend == "iptables":
                result = subprocess.run(
                    ["iptables", "-L", "INPUT", "-n", "--line-numbers", "-v"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
                    # Find chain header
                    chain_idx = None
                    for i, line in enumerate(lines):
                        if "chain input" in line.lower():
                            chain_idx = i
                            break
                    if chain_idx is None:
                        return 0
                    
                    # Scan from chain header for UtilSec rules
                    for i in range(chain_idx + 1, len(lines)):
                        line = lines[i].strip()
                        if not line or line.startswith("chain ") or "target" in line.lower():
                            continue
                        if "utilsec" not in line.lower():
                            continue
                        # Extract rule number (first field)
                        parts = line.split()
                        if parts:
                            try:
                                rule_num = int(parts[0])
                                subprocess.run(
                                    ["iptables", "-D", "INPUT", str(rule_num)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                                )
                                removed += 1
                            except (ValueError, IndexError):
                                continue
            
            elif self.active_backend == "ufw":
                result = subprocess.run(
                    ["ufw", "status", "numbered"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                )
                if result.returncode == 0:
                    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
                    rule_nums = []
                    for line in lines:
                        if "utilsec" not in line.lower():
                            continue
                        try:
                            num_str = line.split(")")[0].strip().split("[")[-1].strip()
                            rule_nums.append(int(num_str))
                        except (ValueError, IndexError):
                            continue
                    # Delete in reverse order to avoid shifting numbers
                    for num in reversed(rule_nums):
                        subprocess.run(
                            ["ufw", "delete", str(num)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                        )
                        removed += 1
            
            elif self.active_backend == "nft":
                result = subprocess.run(
                    ["nft", "list", "table", "inet", "filter"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                )
                if result.returncode == 0 and "utilsec_bans" in result.stdout.decode("utf-8", errors="replace"):
                    subprocess.run(
                        ["nft", "delete", "table", "inet", "filter", "utilsec_bans"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                    )
                    removed += 1
                    
        except Exception as e:
            logger.error("Error cleaning firewall rules: %s", e)
        
        return removed

    def toggle_dry_run(self) -> Tuple[bool, str]:
        """Toggle between dry-run and live system firewall mode.
        Returns: (is_dry_run, message_description)
        """
        if self.dry_run:
            # Want to switch to LIVE
            is_root = os.geteuid() == 0
            live_backend = None
            pref = self.requested_backend.lower()
            candidates = [pref] if pref in ("iptables", "ufw", "nft") else ["iptables", "ufw", "nft"]
            for cand in candidates:
                if shutil.which(cand) and (is_root or self._check_sudo(cand)):
                    live_backend = cand
                    break

            if not live_backend:
                return (
                    True,
                    "⚠️ Cannot switch to LIVE: Requires root/sudo! (Launch: sudo ./sentinel.py --live)",
                )

            self.dry_run = False
            self.active_backend = live_backend
            with self.lock:
                for record in self.active_bans.values():
                    if record.status == "SIMULATED":
                        record.status = "BANNED"
                        record.backend = self.active_backend
                        self._exec_ban_system(record)
                        if self.storage:
                            self.storage.save_ban(record)
            return (False, f"Switched firewall mode to: LIVE ({self.active_backend.upper()})")
        else:
            # Switching from LIVE to SIMULATION
            self.dry_run = True
            self.active_backend = "dry-run"
            return (True, "Switched firewall mode to: SIMULATION (Dry-run)")

    def stop(self) -> None:
        self.running = False

