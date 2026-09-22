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
apt-get update -qq || true
apt-get install -y -qq libapache2-mod-security2 modsecurity-crs curl || true

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
if grep -qE "^[[:space:]]*#?[[:space:]]*SecRuleEngine" "$MODSEC_CONF"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*SecRuleEngine[[:space:]].*/SecRuleEngine On/' "$MODSEC_CONF"
else
    echo "SecRuleEngine On" >> "$MODSEC_CONF"
fi

# Performance optimization: disable SecResponseBodyAccess to avoid high CPU overhead
sed -i 's/^[[:space:]]*SecResponseBodyAccess[[:space:]].*/SecResponseBodyAccess Off/' "$MODSEC_CONF" || true
sed -i 's/^[[:space:]]*SecStatusEngine[[:space:]].*/SecStatusEngine Off/' "$MODSEC_CONF" || true

# Clean any legacy Include directives inside modsecurity.conf that could cause double-loading
sed -i '/^[[:space:]]*Include[[:space:]]/d' "$MODSEC_CONF" || true
sed -i '/^[[:space:]]*IncludeOptional[[:space:]]/d' "$MODSEC_CONF" || true

log_success "SecRuleEngine configurado en modo On (bloqueo activo)."

# 5. Clean rogue manual CRS includes from global Apache configurations (apache2.conf, httpd.conf)
log_info "Limpiando posibles inclusiones manuales conflictivas en apache2.conf..."

# If previous run disabled crs-setup.conf in /usr/share, restore it
if [[ -f "/usr/share/modsecurity-crs/crs-setup.conf.disabled" ]]; then
    mv -f "/usr/share/modsecurity-crs/crs-setup.conf.disabled" "/usr/share/modsecurity-crs/crs-setup.conf"
fi

python3 - << 'PYEOF'
import re, os, shutil

for path in ['/etc/apache2/apache2.conf', '/etc/apache2/httpd.conf']:
    if not os.path.isfile(path):
        continue
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    orig_content = content
    # Remove any manual IfModule security2_module blocks inside main apache config
    content = re.sub(r'<IfModule\s+security2_module>.*?</IfModule>', '', content, flags=re.DOTALL)
    
    # Filter out individual rogue Include directives for CRS or ModSecurity
    lines = content.splitlines()
    filtered = []
    for line in lines:
        if re.search(r'^\s*Include(Optional)?\s+.*(modsecurity|crs-setup|modsecurity-crs)', line, re.IGNORECASE):
            continue
        filtered.append(line)
    
    new_content = '\n'.join(filtered) + '\n'
    if new_content != orig_content:
        shutil.copyfile(path, path + '.bak_utilsec')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"[OK] Inclusiones manuales eliminadas de {path} (respaldo en {path}.bak_utilsec)")
PYEOF

# 6. Resolve and isolate OWASP CRS Setup file
mkdir -p "$MODSEC_DIR/crs"
CRS_SETUP="$MODSEC_DIR/crs/crs-setup.conf"

if [[ ! -f "$CRS_SETUP" ]]; then
    if [[ -f "$MODSEC_DIR/crs-setup.conf" ]]; then
        log_info "Moviendo $MODSEC_DIR/crs-setup.conf a $CRS_SETUP..."
        mv -f "$MODSEC_DIR/crs-setup.conf" "$CRS_SETUP"
    elif [[ -f "/usr/share/modsecurity-crs/crs-setup.conf" ]]; then
        log_info "Copiando /usr/share/modsecurity-crs/crs-setup.conf a $CRS_SETUP..."
        cp -f "/usr/share/modsecurity-crs/crs-setup.conf" "$CRS_SETUP"
    elif [[ -f "$MODSEC_DIR/crs/crs-setup.conf.example" ]]; then
        cp -f "$MODSEC_DIR/crs/crs-setup.conf.example" "$CRS_SETUP"
    elif [[ -f "/usr/share/modsecurity-crs/crs-setup.conf.example" ]]; then
        cp -f "/usr/share/modsecurity-crs/crs-setup.conf.example" "$CRS_SETUP"
    fi
fi

# Clean any stray crs-setup.conf directly under /etc/modsecurity to prevent wildcard double-loading
if [[ -f "$MODSEC_DIR/crs-setup.conf" ]]; then
    rm -f "$MODSEC_DIR/crs-setup.conf"
fi

# Ensure cache directory exists and has correct permissions
mkdir -p /var/cache/modsecurity
chown -R www-data:www-data /var/cache/modsecurity 2>/dev/null || true

# Configure security2.conf with explicit, non-overlapping includes
SEC2_AVAILABLE="/etc/apache2/mods-available/security2.conf"
SEC2_ENABLED="/etc/apache2/mods-enabled/security2.conf"

log_info "Configurando inclusión limpia y determinista en security2.conf..."

CRS_RULES_DIR=""
if [[ -d "/usr/share/modsecurity-crs/rules" ]]; then
    CRS_RULES_DIR="/usr/share/modsecurity-crs/rules/*.conf"
elif [[ -d "/etc/modsecurity/crs/rules" ]]; then
    CRS_RULES_DIR="/etc/modsecurity/crs/rules/*.conf"
fi

cat << EOF > "$SEC2_AVAILABLE"
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Ensure SecRuleEngine is active globally
        SecRuleEngine On
        SecRequestBodyAccess On
        SecResponseBodyAccess Off
        SecStatusEngine Off

        # 1. Base ModSecurity engine configuration
        IncludeOptional /etc/modsecurity/modsecurity.conf

        # 2. UtilSec Instant Phase-1 Shield Rules
        IncludeOptional /etc/modsecurity/utilsec_shield.conf

        # 3. OWASP CRS Setup configuration (loaded exactly once)
        IncludeOptional /etc/modsecurity/crs/crs-setup.conf

        # 4. OWASP CRS Detection Rules
        IncludeOptional $CRS_RULES_DIR
</IfModule>
EOF

# Ensure mods-enabled points directly to mods-available
mkdir -p /etc/apache2/mods-enabled
ln -sf "$SEC2_AVAILABLE" "$SEC2_ENABLED"

log_success "security2.conf configurado con inclusión explícita (sin duplicados)."

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

# 7. Enable Apache modules in correct dependency order
log_info "Habilitando módulos necesarios en Apache (unique_id y security2)..."
a2enmod unique_id || true
a2enmod security2 || true

# Force symlinks in mods-enabled to guarantee they are loaded
mkdir -p /etc/apache2/mods-enabled
for mod in unique_id security2; do
    if [[ -f "/etc/apache2/mods-available/${mod}.load" ]]; then
        ln -sf "/etc/apache2/mods-available/${mod}.load" "/etc/apache2/mods-enabled/${mod}.load"
    fi
    if [[ -f "/etc/apache2/mods-available/${mod}.conf" ]]; then
        ln -sf "/etc/apache2/mods-available/${mod}.conf" "/etc/apache2/mods-enabled/${mod}.conf"
    fi
done

# Remove any SecRuleEngine Off overrides from sites-enabled
if grep -rnE "SecRuleEngine[[:space:]]+Off" /etc/apache2/sites-enabled/ >/dev/null 2>&1; then
    log_warn "Detectado 'SecRuleEngine Off' en sitios habilitados. Eliminando override..."
    sed -i -E 's/^[[:space:]]*SecRuleEngine[[:space:]]+Off/SecRuleEngine On/' /etc/apache2/sites-enabled/*.conf 2>/dev/null || true
fi

# 8. Clean up any redundant conf files in conf-enabled that might load rules a second time
if compgen -G "/etc/apache2/conf-enabled/*modsec*.conf" > /dev/null 2>&1 || compgen -G "/etc/apache2/conf-enabled/*crs*.conf" > /dev/null 2>&1; then
    for f in /etc/apache2/conf-enabled/*modsec*.conf /etc/apache2/conf-enabled/*crs*.conf; do
        if [[ -f "$f" ]]; then
            log_warn "Deshabilitando configuración redundante en conf-enabled: $(basename "$f")..."
            rm -f "$f" || true
        fi
    done
fi

# 9. Test Apache configuration with automated diagnostics
log_info "Verificando sintaxis de configuración de Apache..."
if apache2ctl configtest >/dev/null 2>&1; then
    log_success "Sintaxis de Apache: OK."
else
    log_warn "Fallo en verificación de sintaxis de Apache. Mostrando diagnóstico..."
    TEST_OUTPUT=$(apache2ctl configtest 2>&1 || true)
    echo "$TEST_OUTPUT"

    if echo "$TEST_OUTPUT" | grep -qE "(Found another rule with the same id|No such file)"; then
        log_info "Inclusiones activas de CRS en /etc/apache2 y /etc/modsecurity:"
        grep -rnE "Include(Optional)?[[:space:]]+.*(crs|modsec)" /etc/apache2/ /etc/modsecurity/ 2>/dev/null || true
    fi

    log_error "Error en la sintaxis de Apache:"
    apache2ctl configtest
    exit 1
fi

# 10. Restart Apache
log_info "Reiniciando servicio Apache..."
systemctl restart apache2
log_success "Apache reiniciado."

# Verify module loaded in running Apache
log_info "Comprobando que mod_security2 esté activo en Apache..."
if apache2ctl -M 2>/dev/null | grep -q "security2_module"; then
    log_success "Módulo security2_module cargado y activo en Apache."
else
    log_warn "security2_module no figura en la lista de módulos cargados (apache2ctl -M)."
    apache2ctl -M 2>/dev/null | grep -E "(security|unique)" || true
fi

# 11. Automated Self-Test Verification
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
    echo -e "${C_YELLOW}${C_BOLD}⚠ ModSecurity se reinició, pero las pruebas devolvieron un código diferente a 403.${C_RESET}"
    echo -e "${C_CYAN}Últimas líneas relevantes en /var/log/apache2/error.log:${C_RESET}"
    tail -n 15 /var/log/apache2/error.log 2>/dev/null || true
fi
echo ""

