import ipaddress
from core.utils import is_valid_ip, normalize_ip
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
from core.backends import DryRunBackend, IptablesBackend

logger = logging.getLogger("UtilSec.Firewall")


class FirewallRuleInfo:
    """Represents a classified firewall rule found during scan."""
    def __init__(self, ip: str, source: str, reason: str, rule_num: int = 0,
                 backend: str = "iptables", jail_name: str = ""):
        self.ip = ip
        self.source = source  # "utilsec", "fail2ban", "manual"
        self.reason = reason
        self.rule_num = rule_num
        self.backend = backend
        self.jail_name = jail_name


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
        config=None,
        whitelist_networks: Optional[List] = None,
    ):
        self.requested_backend = backend
        self.dry_run = dry_run
        self.storage = storage
        self.on_ban_change = on_ban_change
        self.ban_subnet = ban_subnet
        self.subnet_cidr = subnet_cidr
        self.config = config
        self.whitelist_networks = []
        if whitelist_networks is not None:
            self.whitelist_networks = list(whitelist_networks)
        elif config and hasattr(config, "whitelist_networks"):
            self.whitelist_networks = list(config.whitelist_networks)

        self.lock = threading.Lock()
        self.active_bans: Dict[str, BanRecord] = {}
        self.running = True

        self.active_backend = self._detect_backend()
        self._init_scripts()
        # Initialize backend abstraction
        if self.active_backend == "iptables":
            self.backend = IptablesBackend(dry_run=self.dry_run, whitelist_nets=self.whitelist_networks)
        else:
            self.backend = DryRunBackend(dry_run=self.dry_run, whitelist_nets=self.whitelist_networks)

        # Step 1: Load existing active bans from storage and normalize to /24 subnets
        if self.storage:
            loaded = self.storage.load_active_bans()
            now = time.time()
            with self.lock:
                for orig_ip, record in loaded.items():
                    # Whitelist check: if stored ban overlaps current whitelist, mark as WHITELISTED and skip
                    if self.is_ip_whitelisted(orig_ip):
                        logger.warning("Stored ban %s is whitelisted! Marking as WHITELISTED in DB.", orig_ip)
                        self.storage.update_ban_status(orig_ip, "WHITELISTED")
                        continue

                    target = self.to_subnet(orig_ip)
                    if self.is_ip_whitelisted(target):
                        logger.warning("Subnet %s for stored ban %s overlaps whitelist! Reverting to single IP.", target, orig_ip)
                        target = orig_ip

                    record.ip = target
                    # If already expired while app was offline, mark as EXPIRED
                    if record.ban_duration > 0 and now >= record.unban_at:
                        self.storage.update_ban_status(target, "EXPIRED")
                        continue

                    self.active_bans[target] = record

        # Step 1.5: If starting in LIVE mode, ensure dedicated chains and whitelist rules are active first
        if not self.dry_run:
            # Delegate to backend
            try:
                self.backend.ensure_whitelist_rules()
            except Exception:
                self._ensure_whitelist_rules()

        # Step 2: Sync with actual firewall state (restore bans that exist in firewall but not in memory)
        if not self.dry_run:
            self._sync_bans_with_firewall()

        # Step 3: If starting in LIVE mode, ensure the system firewall rule is active for all loaded bans
        if not self.dry_run and self.active_bans:
            with self.lock:
                for record in self.active_bans.values():
                    if self.is_ip_whitelisted(record.ip):
                        continue
                    record.status = "BANNED"
                    record.backend = self.active_backend
                    # Delegate to backend for actual system ban
                    try:
                        self.backend.exec_ban(record.ip)
                    except Exception:
                        self._exec_ban_system(record)
                    if self.storage:
                        self.storage.save_ban(record)

        # Start expiration reaper thread
        self.reaper_thread = threading.Thread(target=self._expiration_loop, daemon=True)
        self.reaper_thread.start()

    def _sync_bans_with_firewall(self) -> None:
        """Synchronize active_bans with the actual firewall state at startup.
        
        Compares firewall rules with in-memory bans and storage:
        1. Finds bans in firewall that are NOT in active_bans (process died without cleanup)
        2. Restores them to active_bans with preserved TTL (not reset)
        3. Removes bans whose TTL already expired
        """
        now = time.time()
        fw_rules = self.get_firewall_rules()
        
        # Find UtilSec rules currently in the firewall
        firewall_utilsec_ips = set()
        for rule in fw_rules:
            if rule.source == "utilsec":
                firewall_utilsec_ips.add(rule.ip)
        
        # Also check active_bans from memory
        with self.lock:
            memory_bans = dict(self.active_bans)
        
        # For each UtilSec rule in firewall, check if it exists in memory/storage
        for ip in firewall_utilsec_ips:
            # Check if this rule matches or overlaps with whitelist!
            if self.is_ip_whitelisted(ip):
                logger.warning("[SYNC] Firewall rule for %s overlaps with whitelist! Removing rule immediately.", ip)
                temp_rec = BanRecord(
                    ip=ip, reason="Whitelisted rule removal", matched_pattern="",
                    attack_count=0, banned_at=now, ban_duration=0, backend=self.active_backend
                )
                self._exec_unban_system(temp_rec)
                if self.storage:
                    self.storage.update_ban_status(ip, "WHITELISTED")
                continue

            if ip in memory_bans:
                # Already in memory, skip
                continue
            
            # Check storage for this ban
            record = None
            if self.storage:
                loaded = self.storage.load_active_bans()
                if ip in loaded:
                    record = loaded[ip]
            
            if record is None:
                # No storage record - this is an orphaned rule, leave it (user can clean it manually)
                logger.info("[SYNC] Found orphaned firewall rule for %s (no storage record). Leaving in place.", ip)
                continue
            
            # Check if TTL expired
            if record.ban_duration > 0 and now >= record.unban_at:
                # Expired while app was offline - mark as EXPIRED
                self.storage.update_ban_status(ip, "EXPIRED")
                logger.info("[SYNC] Ban %s has expired (unban_at=%s). Marked as EXPIRED.", ip, record.unban_at)
                continue
            
            # Valid ban - restore to active_bans with original TTL preserved
            subnet_ip = self.to_subnet(ip)
            if self.is_ip_whitelisted(subnet_ip):
                subnet_ip = ip
            record.ip = subnet_ip
            record.status = "BANNED"
            record.backend = self.active_backend
            self.active_bans[subnet_ip] = record
            
            logger.info("[SYNC] Restored ban for %s (unban_at=%s, ttl_remaining=%.0fs)",
                        subnet_ip, record.unban_at, record.unban_at - now)
        
        # Clean up: remove from active_bans any ban whose TTL expired
        expired_ips = []
        with self.lock:
            for ip, record in self.active_bans.items():
                if record.ban_duration > 0 and now >= record.unban_at:
                    expired_ips.append(ip)
        
        for ip in expired_ips:
            record = self.active_bans.pop(ip, None)
            if record and self.storage:
                self.storage.update_ban_status(ip, "EXPIRED")
            logger.info("[SYNC] Removed expired ban for %s from active_bans", ip)

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

    def _get_whitelist_networks(self, config=None) -> List:
        """Returns the current list of whitelisted ip_network objects."""
        cfg = config or self.config
        if cfg and hasattr(cfg, "whitelist_networks"):
            return cfg.whitelist_networks
        return self.whitelist_networks

    def is_ip_whitelisted(self, ip_str: str, config=None) -> bool:
        """Checks if an IP or subnet belongs to or overlaps with any whitelisted network."""
        ip_str = ip_str.strip()
        # Normalize common forms (strip ports / brackets)
        try:
            n = normalize_ip(ip_str)
            if n:
                ip_str = n
        except Exception:
            pass
        whitelist = self._get_whitelist_networks(config)
        if not whitelist:
            return False
        # Reject invalid IPs early (after normalization)
        if not is_valid_ip(ip_str) and "/" not in ip_str:
            return False
        try:
            if "/" in ip_str:
                net = ipaddress.ip_network(ip_str, strict=False)
                for wnet in whitelist:
                    if net.overlaps(wnet):
                        return True
            else:
                addr = ipaddress.ip_address(ip_str)
                for wnet in whitelist:
                    if addr in wnet:
                        return True
        except ValueError:
            return False
        return False

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
        """Checks if an IP matches an active ban or belongs to a banned subnet.
        
        Defense-in-depth: Any IP in the whitelist is NEVER considered banned.
        """
        ip_str = ip_str.strip()
        if self.is_ip_whitelisted(ip_str):
            return None

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
        cfg = config or self.config
        whitelist = self._get_whitelist_networks(cfg)

        # 1. Whitelist protection: refuse immediately if IP or range is whitelisted
        if self.is_ip_whitelisted(ip, config=cfg):
            logger.warning("Refusing to ban %s: IP or range is in whitelist!", ip)
            return False

        # 2. Resolve target subnet
        target = self.to_subnet(ip)

        # 3. Whitelist-aware splitting: if the /24 overlaps with whitelisted networks,
        # compute safe sub-ranges that exclude those whitelisted IPs
        if self.ban_subnet and "/" in target and whitelist:
            try:
                net = ipaddress.ip_network(target, strict=False)
                if any(net.overlaps(wnet) for wnet in whitelist):
                    safe_subnets = self._get_safe_subnets(net, whitelist)
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

        if self.is_ip_whitelisted(target, config=cfg):
            logger.warning("Refusing to ban target %s: overlaps with whitelisted networks", target)
            return False

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
                    self.kill_active_connections(ip)

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
        """Unbans an IP address or subnet (UtilSec-managed ban)."""
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

    def unban_fail2ban(self, ip: str, jail_name: str = "") -> bool:
        """Unbans an IP that was banned by fail2ban.
        
        Uses fail2ban-client to unban the IP from the specified jail.
        If jail_name is empty, tries to detect it from iptables chain names.
        """
        if self.dry_run:
            logger.info("[DRY-RUN] Would unban %s from fail2ban jail %s", ip, jail_name)
            return True

        try:
            # Try to detect jail from iptables if not provided
            if not jail_name:
                jail_name = self._detect_fail2ban_jail(ip)

            if not jail_name:
                logger.error("Cannot detect fail2ban jail for IP %s", ip)
                return False

            # Use fail2ban-client to unban
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            cmd = prefix + ["fail2ban-client", "set", jail_name, "unban", ip]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

            if result.returncode == 0:
                logger.info("Successfully unbanned %s from fail2ban jail %s", ip, jail_name)
                return True
            else:
                logger.error("Failed to unban %s from fail2ban jail %s: %s", ip, jail_name, result.stderr.decode("utf-8", errors="replace").strip())
                return False

        except FileNotFoundError:
            logger.error("fail2ban-client not found. Is fail2ban installed?")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout while trying to unban %s from fail2ban", ip)
            return False
        except Exception as e:
            logger.error("Error unbanning %s from fail2ban: %s", ip, e)
            return False

    def unban_manual_rule(self, ip: str, rule_num: int = 0, backend: str = "iptables") -> bool:
        """Unbans an IP that was banned by a manual firewall rule (not UtilSec, not fail2ban).
        
        Directly removes the rule from iptables or ufw by rule number.
        """
        if self.dry_run:
            logger.info("[DRY-RUN] Would remove manual rule %d from %s for IP %s", rule_num, backend, ip)
            return True

        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]

            if backend == "iptables":
                cmd = prefix + ["iptables", "-D", "INPUT", str(rule_num)]
            elif backend == "ufw":
                cmd = prefix + ["ufw", "delete", str(rule_num)]
            else:
                logger.error("Unsupported backend for manual unban: %s", backend)
                return False

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

            if result.returncode == 0:
                logger.info("Successfully removed manual firewall rule for IP %s", ip)
                return True
            else:
                logger.error("Failed to remove manual firewall rule for IP %s: %s", ip, result.stderr.decode("utf-8", errors="replace").strip())
                return False

        except FileNotFoundError:
            logger.error("%s command not found", backend)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Timeout while removing manual firewall rule for IP %s", ip)
            return False
        except Exception as e:
            logger.error("Error removing manual firewall rule for IP %s: %s", ip, e)
            return False

    def _detect_fail2ban_jail(self, ip: str) -> str:
        """Try to detect which fail2ban jail banned this IP by scanning iptables chains."""
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            result = subprocess.run(
                prefix + ["iptables", "-L", "-n"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return ""

            output = result.stdout.decode("utf-8", errors="replace")
            lines = output.splitlines()

            current_chain = ""
            for line in lines:
                # Detect chain name (fail2ban chains are like "fail2ban-<jail>")
                if line.startswith("CHAIN") or line.strip().startswith("fail2ban-"):
                    current_chain = line.strip().split()[0]
                    if current_chain.startswith("fail2ban-"):
                        jail_name = current_chain[11:]  # Remove "fail2ban-" prefix
                elif current_chain and ip in line and ("DROP" in line or "REJECT" in line):
                    return jail_name

            return ""
        except Exception as e:
            logger.debug("Error detecting fail2ban jail: %s", e)
            return ""

    def _init_iptables_chains(self, whitelist_nets: Optional[List] = None) -> int:
        """Initializes dedicated UtilSec chains in iptables for 100% reliable traffic isolation:

        INPUT Chain Layout:
          Position 1: -j UTILSEC-WHITELIST (ACCEPT whitelisted traffic, never blocked)
          Position 2: -j UTILSEC-BAN       (DROP banned traffic immediately before any port/service ACCEPT)
          Position 3+: System rules        (UFW, Apache, ESTABLISHED, SSH, etc.)
        """
        if self.dry_run or self.active_backend != "iptables":
            return 0

        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]
        if whitelist_nets is None:
            whitelist_nets = self._get_whitelist_networks()

        try:
            # 1. Ensure custom chains exist (-N)
            for chain in ("UTILSEC-WHITELIST", "UTILSEC-BAN"):
                subprocess.run(
                    prefix + ["iptables", "-w", "5", "-N", chain],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )

            # 2. Check if jumps exist in INPUT
            res_wl = subprocess.run(
                prefix + ["iptables", "-w", "5", "-C", "INPUT", "-j", "UTILSEC-WHITELIST"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )
            if res_wl.returncode != 0:
                subprocess.run(
                    prefix + ["iptables", "-w", "5", "-I", "INPUT", "1", "-j", "UTILSEC-WHITELIST"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )

            res_ban = subprocess.run(
                prefix + ["iptables", "-w", "5", "-C", "INPUT", "-j", "UTILSEC-BAN"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )
            if res_ban.returncode != 0:
                subprocess.run(
                    prefix + ["iptables", "-w", "5", "-I", "INPUT", "2", "-j", "UTILSEC-BAN"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )

            # 3. Ensure exact order in INPUT: rule 1 must be UTILSEC-WHITELIST, rule 2 must be UTILSEC-BAN
            res_s = subprocess.run(
                prefix + ["iptables", "-w", "5", "-S", "INPUT"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
            )
            if res_s.returncode == 0:
                lines = [line.strip() for line in res_s.stdout.decode("utf-8", errors="replace").splitlines() if line.strip().startswith("-A INPUT")]
                need_reorder = False
                if len(lines) >= 1 and "-j UTILSEC-WHITELIST" not in lines[0]:
                    need_reorder = True
                if len(lines) >= 2 and "-j UTILSEC-BAN" not in lines[1]:
                    need_reorder = True

                if need_reorder:
                    # Remove any existing jumps to UTILSEC chains from INPUT
                    for _ in range(5):
                        del_wl = subprocess.run(prefix + ["iptables", "-w", "5", "-D", "INPUT", "-j", "UTILSEC-WHITELIST"],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                        if del_wl.returncode != 0:
                            break
                    for _ in range(5):
                        del_ban = subprocess.run(prefix + ["iptables", "-w", "5", "-D", "INPUT", "-j", "UTILSEC-BAN"],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                        if del_ban.returncode != 0:
                            break
                    # Re-insert in exact order: UTILSEC-BAN first, then UTILSEC-WHITELIST at 1 (so WHITELIST is 1, BAN is 2)
                    subprocess.run(prefix + ["iptables", "-w", "5", "-I", "INPUT", "1", "-j", "UTILSEC-BAN"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    subprocess.run(prefix + ["iptables", "-w", "5", "-I", "INPUT", "1", "-j", "UTILSEC-WHITELIST"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                    logger.info("Ensured UTILSEC-WHITELIST at INPUT position 1 and UTILSEC-BAN at position 2")

            # 4. Sync the UTILSEC-WHITELIST chain
            return self._sync_whitelist_chain(whitelist_nets)

        except Exception as e:
            logger.error("Error setting up dedicated iptables chains: %s", e)
            return 0

    def _sync_whitelist_chain(self, whitelist_nets: Optional[List] = None) -> int:
        """Populates the UTILSEC-WHITELIST chain with all whitelisted networks."""
        if self.dry_run or self.active_backend != "iptables":
            return 0
        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]
        if whitelist_nets is None:
            whitelist_nets = self._get_whitelist_networks()
        count = 0
        try:
            # Flush existing rules in UTILSEC-WHITELIST
            subprocess.run(prefix + ["iptables", "-w", "5", "-F", "UTILSEC-WHITELIST"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            # Add each whitelisted network with -j ACCEPT
            for wnet in whitelist_nets:
                wnet_str = str(wnet)
                subprocess.run(
                    prefix + ["iptables", "-w", "5", "-A", "UTILSEC-WHITELIST", "-s", wnet_str, "-j", "ACCEPT",
                              "-m", "comment", "--comment", "UtilSec-Whitelist"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
                )
                count += 1
            logger.info("UTILSEC-WHITELIST chain populated with %d networks", count)
        except Exception as e:
            logger.error("Error syncing UTILSEC-WHITELIST chain: %s", e)
        return count

    def _ensure_whitelist_rules(self, whitelist_nets: Optional[List] = None) -> int:
        """Ensure whitelist IPs have ACCEPT rules evaluated before any ban rules.
        
        For iptables: initializes dedicated UTILSEC-WHITELIST and UTILSEC-BAN chains.
        For ufw: inserts allow rules at the top of ufw rules.
        """
        if self.dry_run:
            return 0

        if whitelist_nets is None:
            whitelist_nets = self._get_whitelist_networks()

        if not whitelist_nets:
            return 0

        if self.active_backend == "iptables":
            return self._init_iptables_chains(whitelist_nets)

        elif self.active_backend == "ufw":
            count = 0
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            try:
                res = subprocess.run(
                    prefix + ["ufw", "status"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                )
                output = res.stdout.decode("utf-8", errors="replace") if res.returncode == 0 else ""
                for wnet in reversed(whitelist_nets):
                    wnet_str = str(wnet)
                    if wnet_str not in output:
                        cmd = prefix + ["ufw", "insert", "1", "allow", "from", wnet_str, "comment", "UtilSec-Whitelist"]
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                        count += 1
                        logger.info("Added ufw whitelist ALLOW rule for %s", wnet_str)
                    else:
                        count += 1
            except Exception as e:
                logger.error("Error ensuring ufw whitelist rules: %s", e)
            return count

        return len(whitelist_nets)

    def kill_active_connections(self, ip: str) -> None:
        """Forcibly close active TCP sockets (Keep-Alive) for an attacking IP or subnet.

        Terminates both native IPv4/IPv6 and IPv4-mapped IPv6 sockets (::ffff:x.x.x.x),
        which are standard when web servers like Apache or Nginx listen on dual-stack [::].
        Supports CIDR notation (e.g. 35.205.254.0/24) to terminate all sockets across the subnet.
        """
        if self.dry_run or not shutil.which("ss"):
            return

        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]
        kill_target = ip.strip()

        # Never kill sockets belonging to whitelisted IPs
        if self.is_ip_whitelisted(kill_target):
            return

        try:
            # 1. Terminate native TCP destination socket (-t is strictly required by kernel inet_diag)
            # ss natively accepts CIDR notation (e.g. 35.205.254.0/24) to kill all sockets matching the range
            subprocess.run(
                prefix + ["ss", "-t", "-K", "dst", kill_target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            # 2. Terminate IPv4-mapped IPv6 socket if target is IPv4 (brackets required by ss IPv6 parser)
            if ":" not in kill_target:
                if "/" in kill_target:
                    v4_ip, prefix_len = kill_target.split("/")
                    v6_prefix = 96 + int(prefix_len)
                    subprocess.run(
                        prefix + ["ss", "-t", "-K", "dst", f"[::ffff:{v4_ip}/{v6_prefix}]"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
                    )
                else:
                    subprocess.run(
                        prefix + ["ss", "-t", "-K", "dst", f"[::ffff:{kill_target}]"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
                    )
            # 3. If conntrack CLI is available, purge state tracking entry
            if shutil.which("conntrack"):
                clean_target = kill_target.split("/")[0] if "/" in kill_target else kill_target
                subprocess.run(
                    prefix + ["conntrack", "-D", "-s", clean_target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
                )
                subprocess.run(
                    prefix + ["conntrack", "-D", "-d", clean_target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
                )
            logger.info("Executed connection kill (ss -t -K) for attacker IP/subnet %s", kill_target)
        except Exception as e:
            logger.debug("Failed to terminate active sockets for %s: %s", kill_target, e)

    def _exec_ban_system(self, record: BanRecord) -> None:
        ip = record.ip
        if self.is_ip_whitelisted(ip):
            logger.warning("Refusing _exec_ban_system for %s: IP or range is whitelisted!", ip)
            record.status = "WHITELISTED"
            return

        cmd = []
        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]
        whitelist_offset = len(self._get_whitelist_networks())
        insert_pos = str(whitelist_offset + 1)

        if self.active_backend == "iptables":
            # Primary target is the dedicated UTILSEC-BAN chain (guaranteed evaluated at INPUT position 2)
            check_cmd = prefix + ["iptables", "-w", "5", "-C", "UTILSEC-BAN", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
            cmd = prefix + ["iptables", "-w", "5", "-I", "UTILSEC-BAN", "1", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
            if not self.dry_run:
                try:
                    exists = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                    if exists:
                        # Rule already exists in firewall, but kill lingering or new sockets in burst attack!
                        self.kill_active_connections(ip)
                        return
                except Exception:
                    pass
        elif self.active_backend == "ufw":
            cmd = prefix + ["ufw", "insert", insert_pos, "deny", "from", ip, "to", "any", "comment", "UtilSec"]
        elif self.active_backend == "nft":
            cmd = prefix + ["nft", "add", "element", "inet", "filter", "utilsec_bans", f"{{ {ip} }}"]

        # If dry-run or failed execution, log to script
        cmd_str = " ".join(cmd) if cmd else f"iptables -I UTILSEC-BAN 1 -s {ip} -j DROP # UtilSec ({record.reason})"
        with open("banned_ips.sh", "a", encoding="utf-8") as f:
            f.write(f"# [{datetime.now().isoformat()}] {record.reason} (URL: {record.last_url})\n{cmd_str}\n")

        if not self.dry_run and cmd:
            try:
                subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except subprocess.CalledProcessError as e:
                err_msg = e.stderr.decode("utf-8", errors="replace").strip()
                # Fallback to direct INPUT chain insertion if custom chain is not present
                if self.active_backend == "iptables" and "No chain/target/match by that name" in err_msg:
                    try:
                        fallback_cmd = prefix + ["iptables", "-w", "5", "-I", "INPUT", insert_pos, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
                        subprocess.run(fallback_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                        logger.info("Fell back to INPUT chain insertion for %s", ip)
                    except Exception as fb_err:
                        logger.error("Fallback ban failed for %s: %s", ip, fb_err)
                        record.status = "ERROR"
                else:
                    logger.error("Failed to execute ban on %s: %s (stderr: %s)", ip, e, err_msg)
                    record.status = "ERROR"
            except Exception as e:
                logger.error("Failed to execute ban on %s: %s", ip, e)
                record.status = "ERROR"

            # Kill existing active TCP connections (Keep-Alive) from banned IP/subnet
            if record.status != "ERROR":
                self.kill_active_connections(ip)

    def _exec_unban_system(self, record: BanRecord) -> None:
        ip = record.ip
        cmd = []
        is_root = os.geteuid() == 0
        prefix = [] if is_root else ["sudo", "-n"]

        if self.active_backend == "iptables":
            cmd = prefix + ["iptables", "-w", "5", "-D", "UTILSEC-BAN", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"]
        elif self.active_backend == "ufw":
            cmd = prefix + ["ufw", "delete", "deny", "from", ip, "to", "any"]
        elif self.active_backend == "nft":
            cmd = prefix + ["nft", "delete", "element", "inet", "filter", "utilsec_bans", f"{{ {ip} }}"]

        cmd_str = " ".join(cmd) if cmd else f"iptables -D UTILSEC-BAN -s {ip} -j DROP # UtilSec unban"
        with open("unban_ips.sh", "a", encoding="utf-8") as f:
            f.write(f"# [{datetime.now().isoformat()}] Unban {ip}\n{cmd_str}\n")

        if not self.dry_run and cmd:
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if self.active_backend == "iptables":
                    # Fallback / cleanup: also remove from INPUT chain in case rule was inserted there previously
                    subprocess.run(prefix + ["iptables", "-w", "5", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(prefix + ["iptables", "-w", "5", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    def _scan_iptables_rules(self) -> List[FirewallRuleInfo]:
        """Scan iptables for UtilSec, fail2ban, and manual rules.
        
        Returns a list of FirewallRuleInfo objects classified by source.
        """
        rules: List[FirewallRuleInfo] = []
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]

            # 1. Scan dedicated UTILSEC-BAN chain if it exists
            res_ban = subprocess.run(
                prefix + ["iptables", "-L", "UTILSEC-BAN", "-n", "--line-numbers", "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if res_ban.returncode == 0:
                lines = res_ban.stdout.decode("utf-8", errors="replace").splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("Chain ") or "target" in line.lower() or "pkts" in line.lower():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            rule_num = int(parts[0])
                        except (ValueError, IndexError):
                            continue
                        ip = self._extract_ip_from_iptables_line(line)
                        if ip:
                            rules.append(FirewallRuleInfo(
                                ip=ip,
                                source="utilsec",
                                reason="UtilSec ban rule",
                                rule_num=rule_num,
                                backend="iptables",
                            ))

            # 2. Scan INPUT chain for fail2ban, manual, and any legacy UtilSec rules
            result = subprocess.run(
                prefix + ["iptables", "-L", "INPUT", "-n", "--line-numbers", "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            if result.returncode != 0:
                return rules

            lines = result.stdout.decode("utf-8", errors="replace").splitlines()
            chain_idx = None
            for i, line in enumerate(lines):
                if "chain input" in line.lower():
                    chain_idx = i
                    break
            if chain_idx is None:
                return rules

            for i in range(chain_idx + 1, len(lines)):
                line = lines[i].strip()
                if not line or line.startswith("Chain ") or "target" in line.lower() or "pkts" in line.lower():
                    continue

                parts = line.split()
                if not parts:
                    continue
                try:
                    rule_num = int(parts[0])
                except (ValueError, IndexError):
                    continue

                # Skip jump rules to UTILSEC chains
                if "UTILSEC-" in line:
                    continue

                if "UtilSec" in line:
                    ip = self._extract_ip_from_iptables_line(line)
                    if ip and not any(r.ip == ip for r in rules):
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="utilsec",
                            reason="UtilSec ban rule (legacy INPUT)",
                            rule_num=rule_num,
                            backend="iptables",
                        ))
                elif "fail2ban" in line:
                    ip = self._extract_ip_from_iptables_line(line)
                    if ip:
                        jail_name = ""
                        if "fail2ban-" in line:
                            jail_name = line.split("fail2ban-")[1].split()[0].rstrip(",")
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="fail2ban",
                            reason=f"Fail2ban rule (jail: {jail_name or 'unknown'})",
                            rule_num=rule_num,
                            backend="iptables",
                            jail_name=jail_name,
                        ))
                elif "DROP" in line or "REJECT" in line:
                    ip = self._extract_ip_from_iptables_line(line)
                    if ip and not any(r.ip == ip for r in rules):
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="manual",
                            reason="Manual firewall rule",
                            rule_num=rule_num,
                            backend="iptables",
                        ))

        except Exception as e:
            logger.debug("Error scanning iptables: %s", e)
        return rules

    def _scan_ufw_rules(self) -> List[FirewallRuleInfo]:
        """Scan ufw for UtilSec, fail2ban, and manual rules.
        
        Returns a list of FirewallRuleInfo objects classified by source.
        """
        rules: List[FirewallRuleInfo] = []
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            result = subprocess.run(
                prefix + ["ufw", "status", "numbered"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return rules

            lines = result.stdout.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                if "deny" not in line.lower() and "reject" not in line.lower():
                    continue

                # Extract rule number
                rule_num = 0
                try:
                    rule_num = int(line.split(")")[0].strip().split("[")[-1].strip())
                except (ValueError, IndexError):
                    continue

                # Classify by comment
                if "UtilSec" in line:
                    ip = self._extract_ip_from_ufw_line(line)
                    if ip:
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="utilsec",
                            reason="UtilSec ban rule",
                            rule_num=rule_num,
                            backend="ufw",
                        ))
                elif "fail2ban" in line.lower():
                    ip = self._extract_ip_from_ufw_line(line)
                    if ip:
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="fail2ban",
                            reason="Fail2ban rule (ufw)",
                            rule_num=rule_num,
                            backend="ufw",
                        ))
                elif "deny" in line.lower() or "reject" in line.lower():
                    ip = self._extract_ip_from_ufw_line(line)
                    if ip:
                        rules.append(FirewallRuleInfo(
                            ip=ip,
                            source="manual",
                            reason="Manual ufw rule",
                            rule_num=rule_num,
                            backend="ufw",
                        ))

        except Exception as e:
            logger.debug("Error scanning ufw: %s", e)
        return rules

    def _scan_nft_rules(self) -> List[FirewallRuleInfo]:
        """Scan nftables for UtilSec ban rules."""
        rules: List[FirewallRuleInfo] = []
        try:
            result = subprocess.run(
                ["nft", "list", "table", "inet", "filter"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
            )
            if result.returncode != 0:
                return rules
            output = result.stdout.decode("utf-8", errors="replace")
            if "utilsec_bans" not in output:
                return rules
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
                            rules.append(FirewallRuleInfo(
                                ip=token,
                                source="utilsec",
                                reason="UtilSec nft rule",
                                backend="nft",
                            ))
                        except ValueError:
                            continue
        except Exception as e:
            logger.debug("Error scanning nftables: %s", e)
        return rules

    def _extract_ip_from_iptables_line(self, line: str) -> str:
        """Extract IP address from an iptables -L output line."""
        parts = line.split()
        for part in parts:
            if part in ("DROP", "REJECT", "all", "--", "0.0.0.0/0", "0.0.0.0"):
                continue
            try:
                network = ipaddress.ip_network(part, strict=False)
                ip = str(network.network_address)
                if network.prefixlen in (24, 32):
                    return ip
            except ValueError:
                continue
        return ""

    def _extract_ip_from_ufw_line(self, line: str) -> str:
        """Extract IP address from a ufw status output line."""
        parts = line.split()
        for i, part in enumerate(parts):
            if part == "from" and i + 1 < len(parts):
                candidate = parts[i + 1]
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    continue
        return ""

    def get_active_bans_list(self, sort_by_ip: bool = False) -> List[BanRecord]:
        """Returns only the bans managed by Sentinel (active_bans).
        
        External firewall rules (fail2ban, manual) are NOT included here.
        They are shown separately in the [U] panel via get_firewall_rules().
        """
        with self.lock:
            result = list(self.active_bans.values())
            if sort_by_ip:
                return sorted(result, key=lambda r: ipaddress.ip_address(r.ip.split('/')[0]))
            return sorted(result, key=lambda r: r.banned_at, reverse=True)

    def get_firewall_rules(self) -> List[FirewallRuleInfo]:
        """Get all external firewall rules (fail2ban, manual) not managed by UtilSec.
        
        This is used by the [U] panel to show rules that need manual attention.
        """
        # Note: allow scanning of external firewall rules even when running in
        # dry-run mode so operators can inspect fail2ban/manual rules without
        # switching to LIVE mode. Scanners handle missing commands / permissions
        # and will return an empty list if scanning is not possible.

        rules = []
        if self.active_backend == "iptables":
            rules = self._scan_iptables_rules()
        elif self.active_backend == "ufw":
            rules = self._scan_ufw_rules()
        elif self.active_backend == "nft":
            rules = self._scan_nft_rules()

        # Filter out rules that are already in active_bans (UtilSec bans)
        with self.lock:
            active_ips = set(self.active_bans.keys())

        filtered = []
        for rule in rules:
            # Only show non-UtilSec rules
            if rule.source != "utilsec" and rule.ip not in active_ips:
                filtered.append(rule)

        return filtered

    def find_rules_for(self, target: str) -> List[FirewallRuleInfo]:
        """Return firewall rules that match or overlap the `target` IP or network."""
        try:
            # Normalize target to ip or network
            if "/" in target:
                tgt_net = ipaddress.ip_network(target.strip(), strict=False)
                is_net = True
            else:
                tgt_addr = ipaddress.ip_address(target.strip())
                is_net = False
        except Exception:
            return []

        rules = self.get_firewall_rules()
        matches: List[FirewallRuleInfo] = []
        for r in rules:
            try:
                if "/" in r.ip:
                    r_net = ipaddress.ip_network(r.ip, strict=False)
                    if is_net:
                        if r_net.overlaps(tgt_net):
                            matches.append(r)
                    else:
                        if tgt_addr in r_net:
                            matches.append(r)
                else:
                    r_addr = ipaddress.ip_address(r.ip)
                    if is_net:
                        if r_addr in tgt_net:
                            matches.append(r)
                    else:
                        if r_addr == tgt_addr:
                            matches.append(r)
            except Exception:
                continue
        return matches

    def unban_anywhere(self, target: str) -> bool:
        """Attempt to remove any firewall rules (fail2ban/manual/utilsec) that block `target`.

        Returns True if at least one removal succeeded.
        """
        matches = self.find_rules_for(target)
        if not matches:
            logger.info("No external firewall rules matched %s", target)
            return False

        any_success = False
        for rule in matches:
            try:
                if rule.source == "fail2ban":
                    ok = self.unban_fail2ban(rule.ip, rule.jail_name)
                elif rule.source == "manual":
                    ok = self.unban_manual_rule(rule.ip, rule.rule_num, rule.backend)
                elif rule.source == "utilsec":
                    ok = self.unban_ip(rule.ip, manual=True)
                else:
                    ok = False
                any_success = any_success or bool(ok)
            except Exception as e:
                logger.debug("Error removing rule for %s: %s", rule.ip, e)

        return any_success

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
            self._ensure_whitelist_rules()
            with self.lock:
                for record in self.active_bans.values():
                    if self.is_ip_whitelisted(record.ip):
                        continue
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
