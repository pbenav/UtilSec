"""Firewall backend abstractions for executing bans/unbans and whitelist sync."""

from typing import List, Optional
import logging
import subprocess
import shutil
import os

logger = logging.getLogger("UtilSec.Backend")


class FirewallBackend:
    """Base interface for firewall backends."""

    def __init__(self, dry_run: bool = True, whitelist_nets: Optional[List] = None):
        self.dry_run = dry_run
        self.whitelist_nets = whitelist_nets or []

    def ensure_whitelist_rules(self) -> int:
        raise NotImplementedError()

    def exec_ban(self, ip: str) -> None:
        raise NotImplementedError()

    def exec_unban(self, ip: str) -> None:
        raise NotImplementedError()


class DryRunBackend(FirewallBackend):
    def ensure_whitelist_rules(self) -> int:
        logger.debug("DryRunBackend.ensure_whitelist_rules called")
        return len(self.whitelist_nets)

    def exec_ban(self, ip: str) -> None:
        logger.info("[DRY-RUN] Ban would be applied for %s", ip)

    def exec_unban(self, ip: str) -> None:
        logger.info("[DRY-RUN] Unban would be applied for %s", ip)


class IptablesBackend(FirewallBackend):
    def __init__(self, dry_run: bool = True, whitelist_nets: Optional[List] = None):
        super().__init__(dry_run=dry_run, whitelist_nets=whitelist_nets)

    def ensure_whitelist_rules(self) -> int:
        if self.dry_run:
            return len(self.whitelist_nets)
        # Call system iptables commands to create chains and populate whitelist
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            # Ensure chains exist
            for chain in ("UTILSEC-WHITELIST", "UTILSEC-BAN"):
                subprocess.run(prefix + ["iptables", "-w", "5", "-N", chain], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            # Populate whitelist
            for wnet in self.whitelist_nets:
                wnet_str = str(wnet)
                subprocess.run(prefix + ["iptables", "-w", "5", "-C", "UTILSEC-WHITELIST", "-s", wnet_str, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            return len(self.whitelist_nets)
        except Exception as e:
            logger.error("Iptables ensure_whitelist failed: %s", e)
            return 0

    def exec_ban(self, ip: str) -> None:
        if self.dry_run:
            logger.info("[DRY-RUN] Would apply iptables DROP for %s", ip)
            return
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            subprocess.run(prefix + ["iptables", "-w", "5", "-A", "UTILSEC-BAN", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "UtilSec"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            logger.info("Applied iptables DROP for %s", ip)
        except Exception as e:
            logger.error("Failed to apply iptables ban for %s: %s", ip, e)

    def exec_unban(self, ip: str) -> None:
        if self.dry_run:
            logger.info("[DRY-RUN] Would remove iptables DROP for %s", ip)
            return
        try:
            is_root = os.geteuid() == 0
            prefix = [] if is_root else ["sudo", "-n"]
            subprocess.run(prefix + ["iptables", "-w", "5", "-D", "UTILSEC-BAN", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            logger.info("Removed iptables DROP for %s", ip)
        except Exception as e:
            logger.error("Failed to remove iptables ban for %s: %s", ip, e)
