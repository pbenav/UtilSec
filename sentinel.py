#!/usr/bin/env python3
"""
UtilSec Sentinel - Real-Time Web Server Attack Monitor & Firewall Auto-Ban
Author: UtilSec Team
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time

from core.config import ConfigManager
from core.detector import AttackDetector
from core.firewall import FirewallManager
from core.models import AttackEvent, BanRecord
from core.storage import StorageManager
from core.watcher import LogWatcher, LogWatcherManager
from ui.tui import SentinelTUI


def setup_logger(log_file: str = "sentinel.log") -> logging.Logger:
    logger = logging.getLogger("UtilSec")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger


def main():
    parser = argparse.ArgumentParser(
        description="UtilSec Sentinel: Real-Time Web Server Attack Monitor & Firewall Auto-Ban"
    )
    parser.add_argument(
        "--log", "-l", action="append",
        help="Path to web server log file (can be specified multiple times, supports optional name=path format, e.g. -l site1=/var/log/site1.log)"
    )
    parser.add_argument("--config", "-c", default="config.json", help="Path to configuration file")
    parser.add_argument("--dry-run", action="store_true", help="Force dry-run simulation mode")
    parser.add_argument("--live", action="store_true", help="Force live firewall mode (requires root/sudo)")
    parser.add_argument("--backend", choices=["auto", "iptables", "ufw", "nft"], help="Firewall backend")
    parser.add_argument("--ban-time", type=int, help="Ban duration in seconds")
    parser.add_argument("--threshold", type=int, help="Number of 404s within window to trigger ban (default: 2)")
    parser.add_argument("--threshold-403", type=int, help="Number of 403s within window to trigger ban (default: 1)")
    parser.add_argument("--replay", type=int, default=100, help="Replay last N lines from existing log (default: 100 lines)")
    parser.add_argument("--headless", action="store_true", help="Run without TUI (headless/daemon console mode)")
    parser.add_argument("--subnet", dest="subnet", action="store_true", default=None, help="Ban /24 subnet instead of single IP (default)")
    parser.add_argument("--no-subnet", dest="subnet", action="store_false", help="Ban single IP address only")
    parser.add_argument("--mask", type=int, default=24, help="Subnet mask prefix (default: 24)")

    args = parser.parse_args()

    # 1. Setup storage first (needed for log config persistence)
    storage = StorageManager(db_path="sentinel_history.db")

    # 2. Load configuration
    config = ConfigManager(config_path=args.config)
    logging.getLogger("UtilSec").info("Loaded config: %s", args.config)
    logging.getLogger("UtilSec").info("Configured log files: %s", config.log_files)
    if args.log:
        config.log_files = []
        for entry in args.log:
            if "=" in entry:
                name, path = entry.split("=", 1)
            else:
                path = entry
                name = os.path.basename(path)
            config.log_files.append({"name": name, "path": path})
        if config.log_files:
            config.log_file = config.log_files[0]["path"]
    else:
        # No command-line logs: try to load persisted config from storage
        persisted_logs = storage.load_log_config()
        if persisted_logs:
            config.log_files = persisted_logs
            config.log_file = persisted_logs[0]["path"]

    if args.backend:
        config.firewall_backend = args.backend
    if args.ban_time:
        config.default_ban_duration = args.ban_time
    if args.threshold:
        config.threshold_404 = args.threshold
    if args.threshold_403:
        config.threshold_403 = args.threshold_403
    if args.subnet is not None:
        config.ban_subnet = args.subnet
    if args.mask:
        config.subnet_cidr_ipv4 = args.mask

    # Determine dry-run
    dry_run = True
    if args.live:
        dry_run = False
    elif args.dry_run:
        dry_run = True
    else:
        dry_run = config.dry_run

    # 3. Setup logger
    logger = setup_logger()

    # 4. Setup Firewall Manager
    tui_ref = [None]  # holder for TUI instance

    def on_ban_change(record: BanRecord, action: str):
        logger.info(f"[{action}] IP {record.ip} - Reason: {record.reason} (Backend: {record.backend})")
        if tui_ref[0]:
            tui_ref[0].set_status(f"{action}: {record.ip} ({record.reason})")

    firewall = FirewallManager(
        backend=config.firewall_backend,
        dry_run=dry_run,
        storage=storage,
        on_ban_change=on_ban_change,
        config=config,
    )

    # CRITICAL: Ensure whitelist IPs have ACCEPT rules at the TOP of INPUT chain
    if not dry_run:
        whitelist_count = firewall._ensure_whitelist_rules(config.whitelist_networks)
        logger.info("Whitelist protection: %d ACCEPT rules ensured at top of INPUT chain", whitelist_count)

    # 4. Setup Attack Detector
    detector = AttackDetector(config=config)

    # 5. Handler for parsed requests
    def on_request(ip: str, method: str, url: str, status: int, raw_line: str, source_log: str = "default"):
        try:
            # Check if this IP is already banned (e.g. burst attack arriving on existing socket)
            already_banned = firewall.is_ip_banned(ip)
            if already_banned:
                firewall.kill_active_connections(ip)

            event, should_ban, ban_reason = detector.analyze_request(
                ip=ip, method=method, url=url, status_code=status, raw_line=raw_line, source_log=source_log,
                is_banned=bool(already_banned)
            )

            if event:
                storage.log_event(event)
                if tui_ref[0]:
                    tui_ref[0].add_attack_event(event)
                elif args.headless:
                    logger.warning("%s", event.summary())

                if should_ban or already_banned:
                    target = config.get_ban_target(ip)
                    firewall.ban_ip(
                        ip=target,
                        reason=ban_reason if should_ban else f"Burst Attack while Banned: {event.matched_rule}",
                        matched_pattern=event.matched_rule,
                        duration=config.default_ban_duration,
                        last_url=url,
                        config=config,
                    )
                    firewall.kill_active_connections(ip)
        except Exception as e:
            logger.error(f"Error processing request ({ip}, {method}, {url}): {e}")

    # 6. Setup Log Watcher Manager
    valid_logs = []
    for item in config.log_files:
        if os.path.exists(item["path"]):
            valid_logs.append(item)
        else:
            logger = logging.getLogger("UtilSec")
            logger.warning("Warning: Log file '%s' does not exist (skipping initially).", item["path"])

    if not valid_logs:
        logging.getLogger("UtilSec").error("Error: None of the configured log files exist! Please check your paths.")
        sys.exit(1)

    watcher_mgr = LogWatcherManager(
        on_request=on_request,
        default_replay_lines=args.replay,
    )
    for item in valid_logs:
        watcher_mgr.add_watcher(name=item["name"], path=item["path"], auto_start=False)

    # Persist log configuration to storage
    if valid_logs:
        storage.save_log_config(valid_logs)

    is_tty = sys.stdout.isatty() and not args.headless

    if is_tty:
        tui = SentinelTUI(
            config=config,
            detector=detector,
            firewall=firewall,
            watcher_manager=watcher_mgr,
            storage=storage,
        )
        tui_ref[0] = tui

    # 7. Start Watchers
    watcher_mgr.start_all()

    # 8. Run Headless or TUI
    has_shutdown = [False]

    def shutdown(sig=None, frame=None):
        if has_shutdown[0]:
            return
        has_shutdown[0] = True

        watcher_mgr.stop_all()
        firewall.stop()
        if tui_ref[0]:
            tui_ref[0].running = False

        # Clear terminal screen cleanly and reset scrollback
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()

        active_bans = len(firewall.get_active_bans_list())
        fw_status = "SIMULATION (Dry-run)" if firewall.dry_run else f"LIVE ({firewall.active_backend.upper()})"

        logger = logging.getLogger("UtilSec")
        logger.info("%s", "=" * 64)
        logger.info("  🛡️  UtilSec Sentinel - Servicio detenido correctamente")
        logger.info("%s", "=" * 64)
        logger.info("  • Estado Cortafuegos:    %s", fw_status)
        logger.info("  • Subredes/IPs Baneadas:  %d", active_bans)
        logger.info("  • Ataques Detectados:     %d", detector.total_attacks_detected)
        logger.info("  • Líneas Analizadas:      %s", f"{detector.total_analyzed:,}")
        logger.info("  • Logs Monitorizados:     %d", len(valid_logs))
        logger.info("  • Base de datos:          sentinel_history.db")
        if firewall.dry_run and active_bans > 0:
            logger.info("  • Script de reglas:       banned_ips.sh")
        logger.info("%s", "=" * 64)
        logger.info("  ¡Sesión finalizada con éxito! Hasta pronto.\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if is_tty:
        try:
            tui_ref[0].start()
        except KeyboardInterrupt:
            shutdown()
        except Exception as e:
            logger.exception("Error en TUI: %s", e)
            watcher_mgr.stop_all()
            firewall.stop()
            import traceback
            logger.error("Se produjo un error en la interfaz TUI:")
            traceback.print_exc()
            sys.exit(1)
        else:
            shutdown()
    else:
        logger = logging.getLogger("UtilSec")
        logger.info("[*] UtilSec Sentinel running in HEADLESS mode.")
        logger.info("[*] Watching %d log file(s):", len(valid_logs))
        for item in valid_logs:
            logger.info("    - [%s] %s", item["name"], item["path"])
        logger.info("[*] Firewall: %s", 'SIMULATION' if firewall.dry_run else firewall.active_backend.upper())
        logger.info("[*] Ban duration: %ss | 404 Threshold: %d", config.default_ban_duration, config.threshold_404)
        logger.info("[*] Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            shutdown()


if __name__ == "__main__":
    main()

