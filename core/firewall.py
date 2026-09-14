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

    def ban_ip(
        self,
        ip: str,
        reason: str,
        matched_pattern: str,
        duration: int,
        last_url: str = "",
        count: int = 1,
    ) -> bool:
        """Bans an IP or Subnet (e.g. /24) for `duration` seconds."""
        # Always enforce /24 subnet!
        ip = self.to_subnet(ip)
        now = time.time()
        with self.lock:
            if ip in self.active_bans:
                record = self.active_bans[ip]
                record.attack_count += count
                record.last_url = last_url or record.last_url
                # Reset penalty TTL so repeat attackers don't get unbanned mid-attack
                record.banned_at = now
                if duration > record.ban_duration:
                    record.ban_duration = duration

                # In live mode, ensure the ban is enforced in the kernel firewall
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

        # Execute system firewall command
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

    def get_active_bans_list(self) -> List[BanRecord]:
        with self.lock:
            # Return sorted by banned_at desc
            return sorted(self.active_bans.values(), key=lambda r: r.banned_at, reverse=True)

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

