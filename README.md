# UtilSec Sentinel 🛡️

**UtilSec Sentinel** es un monitor de seguridad y cortafuegos en tiempo real con interfaz de terminal interactiva (**TUI**) diseñado para analizar registros de servidores web (Apache / Nginx / PHP-FPM FastCGI), identificar atacantes y bloquear automáticamente sus direcciones IP.

**Desarrollado por [Sientia Open Source Labs](https://github.com/pbenav)**

> **¿Te gusta este proyecto?** Apoya el desarrollo de software libre y de código abierto:
> - **[Patreon](https://www.patreon.com/cw/sientia)** — Suscripción mensual
> - **[Buy Me a Coffee](https://buymeacoffee.com/sientia)** — Donación única

---

## Licencia

Este proyecto se distribuye bajo la licencia **GNU Affero General Public License v3.0 (AGPL-3.0)**.
Puedes modificarlo, distribuirlo y usarlo en redes, siempre que cualquier trabajo derivado también se distribuya bajo la misma licencia y se ponga el código fuente a disposición.

Consulta [LICENSE](LICENSE) para más detalles.

---

## Características Principales

- **Interfaz TUI Interactiva y Moderna**:
  - Panel dividido con tabla interactiva de atacantes bloqueados y transmisión en vivo (*stream*) de peticiones maliciosas.
  - Navegación fluida con flechas (`↑` / `↓`), tarjetas de métricas en tiempo real y atajos de teclado de acción directa.
- **Análisis en Tiempo Real de Alto Rendimiento**:
  - Seguimiento ultrarrápido tipo `tail -f` con latencia de detección inferior a 5 milisegundos.
  - Tolerancia a archivos masivos (probado con éxito sobre registros de más de 2,79 GB y 10,4 millones de líneas).
  - Tolerancia a cargas útiles (*payloads*) binarias, caracteres nulos y rotaciones automáticas de registros (`logrotate`).
  - Soporta simultáneamente registros de acceso combinado HTTP y registros de error FastCGI / Apache (`Primary script unknown`).
- **Detección Inteligente en 3 Capas**:
  1. **Reglas del Usuario**: Cadenas personalizables (ej. `/admin.php`, `/phpmyadmin`, `/wp-login.php`, `/xmlrpc.php`) editables desde `config.json` o sobre la marcha desde la TUI (`[A]` para añadir, `[D]` para eliminar).
  2. **Firmas Heurísticas / IA de Bloqueo Inmediato (1 solo intento)**:
     - Fugas de credenciales: `/.env*`, `/.aws/credentials`, `/rclone.conf`, `/.vscode/sftp.json`, `wp-config.php`, `id_rsa`.
     - Fugas de repositorios: `/.git/`, `/.gitignore`, `/.DS_Store`.
     - Escáneres de WebShells PHP: `hellopress`, `wp_filemanager.php`, `this_is_a_new_hello_world.php`, `alfa.php`, `cxs.php`, `wso.php`, etc.
     - Salto de directorio (*Directory Traversal*): `../`, `..%2f`, `@fs/..`.
     - Vulnerabilidades (*exploits*) de entornos y paneles: `actuator/env`, `telescope/requests`, `debug/default/view`, `/@vite/env`, `pom.properties`, `v2/_catalog`, etc.
  3. **Control de Ráfagas (Limitación de tasa de 404s)**:
     - Bloquea atacantes que generen ráfagas de errores 404 (ej. más de 5 en 60 segundos), incluso si buscan rutas no catalogadas.
- **Bloqueo por Subred /24 (Máscara de 24 bits)**:
  - Al detectar un ataque, **bloquea la subred `/24` completa** del atacante (256 direcciones IP simultáneas) para frustrar ataques rotativos o proxies distribuidos dentro del mismo rango.
- **Gestión Avanzada de Cortafuegos**:
  - Compatible con `iptables`, `ufw`, `nftables`.
  - Modo **Simulación / Dry-Run** activo por defecto para pruebas seguras sin necesidad de privilegios de superusuario (*root*).
  - Generación automática de scripts de auditoría: `banned_ips.sh` y `unban_ips.sh`.
  - Temporizador de desbloqueo automático (TTL) en segundo plano (por defecto 3600 segundos).
  - Lista blanca (*whitelist*) para IPs locales (`127.0.0.1`, RFC 1918) y rangos de red seguros (protegidas ante bloqueos de subred).
- **Persistencia de Estado**:
  - **Persistencia de Bans**: Los bloqueos se restauran automáticamente al reiniciar el proceso. Si existen reglas en iptables/ufw que no estaban en memoria, se recuperan conservando su tiempo original de expiración (TTL). Los bans expirados se marcan como `EXPIRED` y se eliminan de la memoria.
  - **Persistencia de Configuración de Registros de Log**: Las rutas de archivos de log configuradas se guardan en SQLite y se cargan automáticamente al iniciar (a menos que se especifique con el parámetro `--log`).
- **Persistencia en base de datos SQLite** (`sentinel_history.db`).

---

## Requisitos

- Linux
- Python 3.10+ (utiliza la librería nativa `curses`, no requiere instalar librerías externas vía pip).

---

## Modo de Uso

### 1. Iniciar en modo Interactivo (TUI)
Para iniciar la interfaz interactiva con el archivo de registros por defecto:
```bash
./sentinel.py
```

Para especificar una ruta de registro diferente:
```bash
./sentinel.py --log /var/log/nginx/access.log
```

Para procesar las últimas 1000 líneas existentes antes de quedarse monitorizando en vivo:
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
| `↑` / `↓` | Navegar y seleccionar una subred/IP de la tabla de bloqueados |
| `[Tab]` / `[V]` | **Alternar vista**: Dividida, Solo transmisión (*stream*) a pantalla completa o Solo Bloqueados |
| `[U]` | **Desbloquear** inmediatamente la subred/IP seleccionada |
| `[B]` | **Bloquear** manualmente cualquier IP o subred (ej. `1.2.3.4` o `1.2.3.0/24`) |
| `[A]` | **Añadir nueva regla/cadena de ataque** en caliente y guardarla en `config.json` |
| `[D]` | **Eliminar regla/cadena de ataque** definida por el usuario |
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
