# UtilSec Sentinel 🛡️

**UtilSec Sentinel** es un monitor de seguridad y cortafuegos en tiempo real con interfaz de terminal interactiva (**TUI**) diseñado para analizar logs de servidores web (Apache / Nginx / PHP-FPM FastCGI), identificar atacantes y bloquear automáticamente sus direcciones IP.

---

## Características Principales

- **Interfaz TUI Interactiva y Moderna**:
  - Panel dividido con tabla interactiva de atacantes bloqueados y stream en vivo de peticiones maliciosas.
  - Navegación fluida con flechas (`↑` / `↓`), tarjetas de métricas en tiempo real y atajos de teclado de acción directa.
- **Análisis en Tiempo Real de Alto Rendimiento**:
  - Seguimiento ultrarrápido tipo `tail -f` con latencia de detección inferior a 5 milisegundos.
  - Tolerancia a archivos masivos (probado con éxito sobre logs de más de 2.79 GB y 10.4 millones de líneas).
  - Tolerancia a payloads binarios, caracteres nulos y rotaciones automáticas de logs (`logrotate`).
  - Soporta simultáneamente logs de acceso combinado HTTP y logs de error FastCGI / Apache (`Primary script unknown`).
- **Detección Inteligente en 3 Capas**:
  1. **Reglas del Usuario**: Cadenas personalizables (ej. `/admin.php`, `/phpmyadmin`, `/wp-login.php`, `/xmlrpc.php`) editables desde `config.json` o al vuelo desde la TUI (`[A]`).
  2. **Firmas Heurísticas / IA de Baneo Inmediato (1 solo intento)**:
     - Fugas de credenciales: `/.env*`, `/.aws/credentials`, `/rclone.conf`, `/.vscode/sftp.json`, `wp-config.php`, `id_rsa`.
     - Fugas de repositorios: `/.git/`, `/.gitignore`, `/.DS_Store`.
     - Escáneres de WebShells PHP: `hellopress`, `wp_filemanager.php`, `this_is_a_new_hello_world.php`, `alfa.php`, `cxs.php`, `wso.php`, etc.
     - Directory Traversal: `../`, `..%2f`, `@fs/..`.
     - Exploits de frameworks y paneles: `actuator/env`, `telescope/requests`, `debug/default/view`, `/@vite/env`, `pom.properties`, `v2/_catalog`, etc.
  3. **Control de Ráfagas (Rate-Limiting de 404s)**:
     - Bloquea atacantes que generen ráfagas de errores 404 (ej. más de 5 en 60 segundos), incluso si buscan rutas no catalogadas.
- **Baneo por Subred /24 (Máscara de 24 bits)**:
  - Al detectar un ataque, **bloquea la subred `/24` completa** del atacante (256 direcciones IP simultáneas) para frustrar ataques rotativos o proxies distribuidos dentro del mismo rango.
- **Gestión Avanzada de Cortafuegos**:
  - Compatible con `iptables`, `ufw`, `nftables`.
  - Modo **Simulación / Dry-Run** activo por defecto para pruebas seguras sin necesidad de privilegios root.
  - Generación automática de scripts de auditoría: `banned_ips.sh` y `unban_ips.sh`.
  - Temporizador de desbaneo automático (TTL) en segundo plano (por defecto 3600 segundos).
  - Lista blanca (*whitelist*) para IPs locales (`127.0.0.1`, RFC 1918) y rangos de red seguros (protegidas ante baneos de subred).
  - Persistencia en base de datos SQLite (`sentinel_history.db`).

---

## Requisitos

- Linux
- Python 3.10+ (utiliza la biblioteca nativa `curses`, no requiere instalar librerías externas vía pip).

---

## Modo de Uso

### 1. Iniciar en modo Interactivo (TUI)
Para iniciar la interfaz interactiva con el archivo de logs por defecto:
```bash
./sentinel.py
```

Para especificar una ruta de log diferente:
```bash
./sentinel.py --log /var/log/nginx/access.log
```

Para procesar las últimas 1.000 líneas existentes antes de quedarse monitorizando en vivo:
```bash
./sentinel.py --replay 1000
```

Para ejecutar en modo **Cortafuegos Real** (aplica las reglas reales con `iptables`/`ufw`/`nft`):
```bash
sudo ./sentinel.py --live
```

### 2. Modo Sin Interfaz / Demonio (Headless)
Ideal para ejecutar en servidores en segundo plano o como servicio `systemd`:
```bash
./sentinel.py --headless
```

---

## Controles en la Interfaz TUI

| Tecla | Acción |
|---|---|
| `↑` / `↓` | Navegar y seleccionar una subred/IP de la tabla de baneados |
| `[Tab]` / `[V]` | **Alternar vista**: Dividida, Solo Stream a pantalla completa o Solo Baneados |
| `[U]` | **Desbanear** inmediatamente la subred/IP seleccionada |
| `[B]` | **Banear** manualmente cualquier IP o subred (ej. `1.2.3.4` o `1.2.3.0/24`) |
| `[A]` | **Añadir nueva regla/cadena de ataque** en caliente y guardarla en `config.json` |
| `[M]` | **Cambiar modo** entre Simulación (Dry-Run) y Cortafuegos Real (Live) |
| `[P]` | **Pausar / Reanudar** el flujo de eventos en pantalla |
| `[C]` | **Limpiar** registros expirados de la vista |
| `[Q]` | **Salir** de la aplicación de forma segura |

---

## Configuración (`config.json`)

El archivo `config.json` permite personalizar todos los parámetros:

```json
{
  "log_file": "logs",
  "firewall_backend": "auto",
  "dry_run": true,
  "threshold_404": 2,
  "threshold_403": 1,
  "window_seconds": 60,
  "whitelist": [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "user_patterns": [
    "/admin.php",
    "/phpmyadmin",
    "/pma",
    "/wp-login.php",
    "/xmlrpc.php"
  ]
}
```

---

## Ejecutar Pruebas Automatizadas

```bash
python3 -m unittest tests/test_sentinel.py
```

