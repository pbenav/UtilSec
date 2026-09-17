# Instrucciones para el asistente

## Idioma
- Todos los textos, mensajes, documentación y comentarios de código deben estar en **español de España**.
- Si el usuario escribe en español, responder siempre en español de España.
- Los términos técnicos pueden mantenerse en inglés cuando no exista una traducción común (ej: "deploy", "commit", "branch", "pull request").

## Proyecto: UtilSec Sentinel
- Ruta: `~/Desarrollo/Python/UtilSec`
- Es un monitor de seguridad para registros web con interfaz TUI en curses.
- Usa Python 3.10+ sin dependencias externas.
- Configuración en `config.json`, base de datos en `sentinel_history.db`.

### Funcionalidades principales
- Análisis en tiempo real de logs Apache/Nginx
- Detección de ataques (firmas, heurísticas, rate-limiting)
- Bloqueo automático de IPs/subredes con iptables/ufw/nftables
- Interfaz TUI interactiva con panel dividido
- Persistencia de bans y configuración de logs en SQLite
- Reglas manuales: añadir con `[A]`, eliminar con `[D]`
