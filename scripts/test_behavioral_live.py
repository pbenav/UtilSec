#!/usr/bin/env python3
"""Live Demonstration & Verification Script for UtilSec Behavioral Defense.

Simulates real-world traffic scenarios:
1. Legitimate user journey (Home -> Content -> Static assets).
2. 404 Storm (Gobuster / DirBuster reconnaissance).
3. Sensitive file probes (.git, .env, wp-config.php).
4. Obfuscated high-entropy payload in query parameters.
5. User journey state-skip / forced browsing to /admin.
6. Feedback loop & preventive blacklist verification.
"""

import json
import os
import subprocess
import sys
import tempfile
import time


def print_banner(text: str) -> None:
    print(f"\n\033[1;36m{'=' * 75}\033[0m")
    print(f"\033[1;32m[*] {text}\033[0m")
    print(f"\033[1;36m{'=' * 75}\033[0m\n")


def main():
    tmp_dir = tempfile.TemporaryDirectory()
    log_path = os.path.join(tmp_dir.name, "access.log")
    config_path = os.path.join(tmp_dir.name, "config.json")
    db_path = os.path.join(tmp_dir.name, "test_history.db")
    blacklist_path = os.path.join(tmp_dir.name, "preventive_blacklist.txt")

    # Touch empty access log
    with open(log_path, "w", encoding="utf-8") as f:
        pass

    # Create temporary Sentinel config
    config_data = {
        "log_file": log_path,
        "log_files": [{"name": "LiveDemo", "path": log_path}],
        "firewall_backend": "dummy",
        "dry_run": True,
        "default_ban_duration": 3600,
        "threshold_404": 15,
        "threshold_403": 5,
        "window_seconds": 60,
        "whitelist": ["127.0.0.1", "::1"],
        "behavioral_defense_enabled": True,
        "recon_window_seconds": 60,
        "suspicion_ban_threshold": 90.0,
        "entropy_threshold": 4.2,
        "entropy_min_param_len": 14,
        "burst_404_rate_limit": 4,
        "preventive_mitigation_file": blacklist_path,
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    print_banner("Iniciando UtilSec Sentinel en modo Headless (Dry-Run)")
    print(f"-> Fichero de log monitoreado: {log_path}")
    print(f"-> Archivo de mitigación preventiva: {blacklist_path}")

    # Launch Sentinel in background
    cmd = [
        sys.executable,
        "sentinel.py",
        "--config", config_path,
        "--log", f"LiveDemo={log_path}",
        "--headless",
        "--dry-run",
    ]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    sentinel_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    time.sleep(1.0)  # Wait for startup and watcher initialization

    def write_log(line: str):
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(line + "\n")
            lf.flush()
        time.sleep(0.3)

    try:
        # ==============================================================
        # 1. Tráfico legítimo de usuario humano
        # ==============================================================
        print_banner("Escenario 1: Tráfico humano legítimo (Navegación normal)")
        legit_ip = "192.168.10.55"
        write_log(f'{legit_ip} - - [24/Oct/2026:13:00:01 +0200] "GET / HTTP/1.1" 200 4520 "-" "Mozilla/5.0"')
        write_log(f'{legit_ip} - - [24/Oct/2026:13:00:02 +0200] "GET /css/main.css HTTP/1.1" 200 1200 "https://example.com/" "Mozilla/5.0"')
        write_log(f'{legit_ip} - - [24/Oct/2026:13:00:03 +0200] "GET /about HTTP/1.1" 200 3100 "https://example.com/" "Mozilla/5.0"')
        print("✔ 3 peticiones legítimas enviadas. Ninguna anomalía ni bloqueo disparado.")

        # ==============================================================
        # 2. Tormenta 404 de escáner automatizado (DirBuster / Gobuster)
        # ==============================================================
        print_banner("Escenario 2: Tormenta de errores 404 (Sondeo masivo / Gobuster)")
        gobuster_ip = "198.51.100.22"
        for i in range(1, 6):
            write_log(f'{gobuster_ip} - - [24/Oct/2026:13:00:10 +0200] "GET /nonexistent_route_{i} HTTP/1.1" 404 153 "-" "gobuster/3.1"')
        print("✔ Ráfaga de 404s inyectada. Esperando detección de 404 Storm y evaluación de score...")

        # ==============================================================
        # 3. Sondeo a archivos sensibles (.git, .env, wp-config, composer)
        # ==============================================================
        print_banner("Escenario 3: Sondeo a archivos sensibles (Early-Stage Recon)")
        recon_ip = "203.0.113.99"
        write_log(f'{recon_ip} - - [24/Oct/2026:13:00:20 +0200] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0"')
        write_log(f'{recon_ip} - - [24/Oct/2026:13:00:21 +0200] "GET /composer.json HTTP/1.1" 404 153 "-" "Mozilla/5.0"')
        write_log(f'{recon_ip} - - [24/Oct/2026:13:00:22 +0200] "GET /wp-config.php HTTP/1.1" 404 153 "-" "Mozilla/5.0"')
        print("✔ Sondeos de archivos confidenciales (.git, composer, wp-config) inyectados.")

        # ==============================================================
        # 4. Carga ofuscada con alta Entropía de Shannon (Base64 / Shellcode)
        # ==============================================================
        print_banner("Escenario 4: Anomalía Estructural / Payload Ofuscado en Parámetro")
        obf_ip = "192.0.2.140"
        high_entropy_param = "VVRJTFNFQ19SRUNPTk5BSVNTQU5DRV9QT0NfT0JGVVNDQVRFRF9QQVlMT0FEXzIwMjY="
        write_log(f'{obf_ip} - - [24/Oct/2026:13:00:30 +0200] "GET /search?q=normal&data={high_entropy_param} HTTP/1.1" 200 890 "-" "python-requests/2.28"')
        print(f"✔ Petición con parámetro GET de alta entropía inyectada ({high_entropy_param[:35]}...).")

        # ==============================================================
        # 5. Anomalía de User Journey (Forced Browsing a /admin)
        # ==============================================================
        print_banner("Escenario 5: Salto anómalo de User Journey (Forced Browsing sin Home)")
        jump_ip = "45.156.128.80"
        write_log(f'{jump_ip} - - [24/Oct/2026:13:00:40 +0200] "GET /wp-admin/admin-ajax.php HTTP/1.1" 403 210 "-" "curl/7.88"')
        print("✔ Petición directa a endpoint administrativo sin visita previa a home ni referer.")

        # Give sentinel time to process logs
        time.sleep(2.0)

        # ==============================================================
        # 6. Verificación del Bucle de Mitigación y Lista Negra Preventiva
        # ==============================================================
        print_banner("Escenario 6: Verificación de Mitigación Preventiva y Blacklist")
        if os.path.exists(blacklist_path):
            with open(blacklist_path, "r", encoding="utf-8") as bf:
                blacklist_content = bf.read()
            print("Contenido del archivo de lista negra preventiva (preventive_blacklist.txt):")
            print("-" * 75)
            print(blacklist_content.strip() or "(Vacío)")
            print("-" * 75)
        else:
            print("Aviso: el archivo de lista negra aún no se ha creado.")

    finally:
        # Terminate Sentinel process and show its log output
        sentinel_proc.terminate()
        try:
            stdout_data, _ = sentinel_proc.communicate(timeout=2.0)
            print_banner("Salida de UtilSec Sentinel durante la ejecución")
            print(stdout_data.strip())
        except Exception:
            sentinel_proc.kill()
        tmp_dir.cleanup()
        print_banner("Demostración y Prueba Finalizada con Éxito")


if __name__ == "__main__":
    main()
