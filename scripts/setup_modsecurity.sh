#!/usr/bin/env bash
# ==============================================================================
# UtilSec Sentinel - ModSecurity & OWASP CRS Auto-Setup & Hardening
# Author: UtilSec Team (https://github.com/pbenav/UtilSec)
# ==============================================================================

set -euo pipefail

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'

log_info() { echo -e "${C_BLUE}[INFO]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
log_error() { echo -e "${C_RED}[ERROR]${C_RESET} $*"; }

echo -e "${C_CYAN}${C_BOLD}"
echo "======================================================================"
echo "    UTILSEC SENTINEL - MODSECURITY & WAF HARDENING SETUP"
echo "======================================================================"
echo -e "${C_RESET}"

# 1. Root check
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse con privilegios de root (sudo)."
    echo "Uso: sudo $0"
    exit 1
fi

# 2. Check Apache installation
if ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
    log_error "Apache no parece estar instalado en el sistema."
    exit 1
fi

log_info "Actualizando repositorios e instalando paquetes necesarios..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq libapache2-mod-security2 modsecurity-crs curl

# 3. Base ModSecurity configuration
MODSEC_DIR="/etc/modsecurity"
MODSEC_CONF="$MODSEC_DIR/modsecurity.conf"
MODSEC_REC="$MODSEC_DIR/modsecurity.conf-recommended"

mkdir -p "$MODSEC_DIR"

if [[ ! -f "$MODSEC_CONF" ]]; then
    if [[ -f "$MODSEC_REC" ]]; then
        log_info "Creando $MODSEC_CONF a partir de $MODSEC_REC..."
        cp "$MODSEC_REC" "$MODSEC_CONF"
    else
        log_warn "Plantilla $MODSEC_REC no encontrada. Creando configuración básica..."
        cat << 'EOF' > "$MODSEC_CONF"
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecResponseBodyMimeType text/plain text/html text/xml
SecTmpDir /tmp/
SecDataDir /var/cache/modsecurity/
SecUploadDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/apache2/modsec_audit.log
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine Off
EOF
    fi
fi

# 4. Enforce SecRuleEngine On and performance tuning
log_info "Configurando SecRuleEngine en modo bloqueo ('On')..."
sed -i 's/^[[:space:]]*SecRuleEngine[[:space:]].*/SecRuleEngine On/' "$MODSEC_CONF"

# Performance optimization: disable SecResponseBodyAccess to avoid high CPU overhead
sed -i 's/^[[:space:]]*SecResponseBodyAccess[[:space:]].*/SecResponseBodyAccess Off/' "$MODSEC_CONF" || true
sed -i 's/^[[:space:]]*SecStatusEngine[[:space:]].*/SecStatusEngine Off/' "$MODSEC_CONF" || true

log_success "SecRuleEngine configurado en modo On (bloqueo activo)."

# 5. Configure security2.conf to properly load CRS rules
SEC2_CONF="/etc/apache2/mods-available/security2.conf"
if [[ -f "$SEC2_CONF" ]]; then
    log_info "Revisando configuración de inclusión de reglas en $SEC2_CONF..."
    
    # Ensure cache directory exists
    mkdir -p /var/cache/modsecurity
    chown -R www-data:www-data /var/cache/modsecurity 2>/dev/null || true

    # Check if CRS rules are referenced; configure cleanly
    cat << 'EOF' > "$SEC2_CONF"
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all configuration files in /etc/modsecurity
        IncludeOptional /etc/modsecurity/*.conf

        # Include OWASP ModSecurity CRS setup if available
        IncludeOptional /etc/modsecurity/crs/crs-setup.conf
        IncludeOptional /etc/modsecurity/crs/*.conf

        # Include OWASP ModSecurity CRS rules (CRS v3 and legacy v2 paths)
        IncludeOptional /usr/share/modsecurity-crs/*.load
        IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
</IfModule>
EOF
    log_success "$SEC2_CONF actualizado con soporte para OWASP CRS v2 y v3."
fi

# 6. Install UtilSec Phase-1 Instant Shield Rules
UTILSEC_RULES_FILE="$MODSEC_DIR/utilsec_shield.conf"
log_info "Instalando reglas de intercepción inmediata en Fase 1 ($UTILSEC_RULES_FILE)..."

cat << 'EOF' > "$UTILSEC_RULES_FILE"
# ==============================================================================
# UtilSec Shield - Instant Phase-1 Interception Rules
# Intercepts automated vulnerability scanners before filesystem or worker lookup
# ==============================================================================

# Rule 1000001: Cloud, Docker, Git, and Sensitive Environment Files
SecRule REQUEST_URI "@rx /(?:\.env|\.git|\.aws|\.docker|\.kube|\.ssh|\.terraform|\.claude|\.azure|\.config|\.boto|\.amplifyrc)(?:/|\?|$|[.~a-zA-Z0-9_-])" \
    "id:1000001,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'UtilSec Shield: Malicious scanner attempt blocked in Phase 1 (Credentials/Cloud/VCS)',\
    tag:'utilsec',\
    tag:'attack-scanner'"

# Rule 1000002: Common Web Backdoors & Shells in Phase 1
SecRule REQUEST_URI "@rx /(?:hellopress|wp_filemanager|coffexium|alfa|wso|b374k|c99|r57|simattacker|c100)\.php" \
    "id:1000002,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'UtilSec Shield: Known WebShell attempt blocked in Phase 1',\
    tag:'utilsec',\
    tag:'attack-webshell'"

# Rule 1000003: Path Traversal attempts in Phase 1
SecRule REQUEST_URI "@rx (?:\.\./|\.\.%2f|@fs/|/etc/passwd|/proc/self)" \
    "id:1000003,\
    phase:1,\
    deny,\
    status:403,\
    log,\
    msg:'UtilSec Shield: Path Traversal attempt blocked in Phase 1',\
    tag:'utilsec',\
    tag:'attack-traversal'"
EOF

chmod 644 "$UTILSEC_RULES_FILE"
log_success "Reglas UtilSec Phase 1 instaladas correctamente."

# 7. Enable Apache modules
log_info "Habilitando módulo security2 en Apache..."
a2enmod -q security2 || true
a2enmod -q unique_id || true

# 8. Test Apache configuration
log_info "Verificando sintaxis de configuración de Apache..."
if apache2ctl configtest >/dev/null 2>&1; then
    log_success "Sintaxis de Apache: OK."
else
    log_error "Error en la sintaxis de Apache:"
    apache2ctl configtest
    exit 1
fi

# 9. Restart Apache
log_info "Reiniciando servicio Apache..."
systemctl restart apache2
log_success "Apache reiniciado con ModSecurity activo."

# 10. Automated Self-Test Verification
echo ""
echo -e "${C_CYAN}----------------------------------------------------------------------"
echo "               VERIFICACIÓN AUTOMATIZADA EN VIVO"
echo -e "----------------------------------------------------------------------${C_RESET}"

TEST_ENV_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/.env" 2>/dev/null || echo "000")
TEST_BASH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/?exec=/bin/bash" 2>/dev/null || echo "000")

ALL_OK=true

if [[ "$TEST_ENV_CODE" == "403" ]]; then
    log_success "Prueba 1 (http://localhost/.env) -> Código 403 Forbidden [BLOQUEO ACTIVO]"
else
    log_warn "Prueba 1 (http://localhost/.env) -> Código recibido: $TEST_ENV_CODE (Esperado: 403)"
    ALL_OK=false
fi

if [[ "$TEST_BASH_CODE" == "403" ]]; then
    log_success "Prueba 2 (http://localhost/?exec=/bin/bash) -> Código 403 Forbidden [BLOQUEO ACTIVO]"
else
    log_warn "Prueba 2 (http://localhost/?exec=/bin/bash) -> Código recibido: $TEST_BASH_CODE"
fi

echo ""
if [[ "$ALL_OK" == "true" ]]; then
    echo -e "${C_GREEN}${C_BOLD}✔ ModSecurity está 100% operativo, en modo bloqueo activo y blindado con UtilSec Shield.${C_RESET}"
    echo -e "Las peticiones maliciosas ahora serán abortadas en milisegundos con HTTP 403 antes de tocar tus webs."
else
    echo -e "${C_YELLOW}${C_BOLD}⚠ ModSecurity se reinició. Si alguna prueba devolvió un código diferente a 403, revisa /var/log/apache2/error.log.${C_RESET}"
fi
echo ""
