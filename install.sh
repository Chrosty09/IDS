#!/usr/bin/env bash
# install.sh — Instalador del IDS Institucional
# Universidad Autónoma de Aguascalientes
# Uso: ./install.sh  (como usuario normal, NO como root)

set -euo pipefail

# ─── Directorio base (funciona sin importar desde dónde se llame) ─────────────
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# ─── Colores ANSI (solo si el terminal los soporta) ───────────────────────────
if [ -t 1 ]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ─── Log de instalación ───────────────────────────────────────────────────────
mkdir -p "$DIR/logs"
LOG_INSTALL="$DIR/logs/install.log"
exec > >(tee -a "$LOG_INSTALL") 2>&1  # Todo va al log Y a pantalla

echo ""
{
    echo "═══════════════════════════════════════════════════════"
    echo "  Instalación iniciada : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Usuario              : $(whoami)"
    echo "  Directorio           : $DIR"
    echo "═══════════════════════════════════════════════════════"
    echo ""
}

# ─── Variables de configuración (se poblan en paso 4) ────────────────────────
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="465"
SMTP_USER=""
SMTP_PASSWORD=""
ADMIN_EMAIL=""
NETWORK_INTERFACE="eth0"
ORG_NAME="Universidad Autónoma de Aguascalientes"
NETLIFY_INGEST_URL=""
IDS_API_KEY=""

# ─── Helpers ──────────────────────────────────────────────────────────────────
_PASO=0
_ERRORES_CHECK=0

paso() {
    _PASO=$(( _PASO + 1 ))
    echo ""
    echo -e "${BOLD}${BLUE}┌─[ Paso $_PASO/9 ] $1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────${NC}"
}

ok()         { echo -e "  ${GREEN}✓${NC}  $*"; }
advertencia(){ echo -e "  ${YELLOW}⚠${NC}  $*"; }
info()       { echo -e "  ${CYAN}→${NC}  $*"; }

error() {
    echo ""
    echo -e "  ${RED}${BOLD}✗  ERROR: $*${NC}"
    echo ""
    echo "  Revisa el log completo en: $LOG_INSTALL"
    exit 1
}

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        ok "$desc"
    else
        echo -e "  ${RED}✗${NC}  $desc"
        _ERRORES_CHECK=$(( _ERRORES_CHECK + 1 ))
    fi
}

confirmar() {
    local msg="$1" default="${2:-n}" opts respuesta
    [ "$default" = "s" ] && opts="[S/n]" || opts="[s/N]"
    read -rp "  $msg $opts: " respuesta || respuesta=""
    respuesta="${respuesta:-$default}"
    [[ "$respuesta" =~ ^[Ss]$ ]]
}

# ═══════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        IDS INSTITUCIONAL — Instalación               ║"
echo "  ║        Universidad Autónoma de Aguascalientes        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${YELLOW}Este proceso toma ~5 minutos en conexión lenta.${NC}"
echo -e "  Directorio: ${BOLD}$DIR${NC}"
echo ""

# ═══════════════════════════════════════════════════════
#  PASO 1 — Verificaciones iniciales
# ═══════════════════════════════════════════════════════
paso "Verificaciones iniciales"

[[ "$(uname -s)" == "Linux" ]] || error "Este instalador solo es compatible con Linux. Detectado: $(uname -s)"
ok "Sistema operativo: Linux $(uname -r)"

[ "$EUID" -ne 0 ] || error "No ejecutes install.sh como root. El script usa sudo internamente."
ok "Usuario: $(whoami) (no root)"

if ! sudo -n true 2>/dev/null; then
    info "Se solicitará tu contraseña de sudo una sola vez para instalar dependencias."
    sudo -v || error "No se pudo verificar acceso sudo."
fi
ok "Acceso sudo disponible"

# ═══════════════════════════════════════════════════════
#  PASO 2 — Dependencias del sistema
# ═══════════════════════════════════════════════════════
paso "Dependencias del sistema (apt)"

info "Actualizando lista de paquetes..."
sudo apt-get update -qq

PAQUETES=(
    python3 python3-pip python3-venv
    libpcap-dev tcpdump
    dbus-x11
    openssl
    git
)

for pkg in "${PAQUETES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg — ya instalado"
    else
        info "Instalando $pkg..."
        sudo apt-get install -y -q "$pkg"
        ok "$pkg — instalado"
    fi
done

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    error "Python $PYTHON_VER detectado. Se requiere >= 3.11.\n  Instala con: sudo apt install python3.11"
fi
ok "Python $PYTHON_VER (>= 3.11 ✓)"

# ═══════════════════════════════════════════════════════
#  PASO 3 — Entorno virtual Python
# ═══════════════════════════════════════════════════════
paso "Entorno virtual Python"

if [ ! -d "$DIR/venv" ]; then
    info "Creando entorno virtual..."
    python3 -m venv "$DIR/venv"
    ok "Entorno virtual creado en $DIR/venv"
else
    ok "Entorno virtual ya existe"
fi

PYTHON="$DIR/venv/bin/python"
PIP="$DIR/venv/bin/pip"

info "Actualizando pip..."
"$PIP" install --upgrade pip -q
ok "pip actualizado"

if [ -f "$DIR/requirements.txt" ]; then
    info "Instalando dependencias desde requirements.txt..."
    "$PIP" install -r "$DIR/requirements.txt" -q
    ok "Dependencias de requirements.txt instaladas"
else
    advertencia "requirements.txt no encontrado — instalando paquetes base manualmente."
    "$PIP" install scapy python-dotenv requests ipwhois -q
fi

if ! "$PYTHON" -c "import PyQt6" 2>/dev/null; then
    info "PyQt6 no encontrado en venv. Instalando..."
    if ! "$PIP" install PyQt6 -q 2>/dev/null; then
        advertencia "pip falló para PyQt6. Intentando python3-pyqt6 desde apt..."
        sudo apt-get install -y -q python3-pyqt6 || true
    fi
    "$PYTHON" -c "import PyQt6" 2>/dev/null || error "No se pudo instalar PyQt6. La GUI no funcionará."
fi
ok "PyQt6 disponible"

# ═══════════════════════════════════════════════════════
#  PASO 4 — Configuración del archivo .env
# ═══════════════════════════════════════════════════════
paso "Configuración del archivo .env"

_formulario_env() {
    echo ""
    echo -e "  ${BOLD}──── Correo (Gmail) ────────────────────────────────────${NC}"
    echo ""

    read -rp "  Servidor SMTP [smtp.gmail.com]: " SMTP_HOST || true
    SMTP_HOST="${SMTP_HOST:-smtp.gmail.com}"

    echo -e "  ${YELLOW}  Puerto: 465 = SSL (recomendado)  |  587 = STARTTLS${NC}"
    read -rp "  Puerto SMTP [465]: " SMTP_PORT || true
    SMTP_PORT="${SMTP_PORT:-465}"

    SMTP_USER=""
    while [ -z "$SMTP_USER" ]; do
        read -rp "  Correo que envía alertas (SMTP_USER): " SMTP_USER || true
        [ -z "$SMTP_USER" ] && echo -e "  ${RED}  Campo obligatorio.${NC}"
    done

    echo ""
    echo -e "  ${YELLOW}  App Password de Gmail (16 caracteres sin espacios):${NC}"
    echo -e "  ${YELLOW}  Gmail → Mi Cuenta → Seguridad → Contraseñas de aplicación${NC}"
    SMTP_PASSWORD=""
    while [ -z "$SMTP_PASSWORD" ]; do
        read -rsp "  Contraseña de aplicación (oculta): " SMTP_PASSWORD || true
        echo ""
        [ -z "$SMTP_PASSWORD" ] && echo -e "  ${RED}  Campo obligatorio.${NC}"
    done

    ADMIN_EMAIL=""
    while [ -z "$ADMIN_EMAIL" ]; do
        read -rp "  Correo del administrador que recibe alertas (ADMIN_EMAIL): " ADMIN_EMAIL || true
        [ -z "$ADMIN_EMAIL" ] && echo -e "  ${RED}  Campo obligatorio.${NC}"
    done

    echo ""
    echo -e "  ${BOLD}──── Red ───────────────────────────────────────────────${NC}"
    echo ""
    echo "  Interfaces de red disponibles:"
    ip link show 2>/dev/null | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':' | grep -v '^lo$' | \
        while read -r iface; do echo "    · $iface"; done || true
    echo ""
    IFACE_AUTO=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1 || echo "eth0")
    read -rp "  Interfaz de red activa [$IFACE_AUTO]: " NETWORK_INTERFACE || true
    NETWORK_INTERFACE="${NETWORK_INTERFACE:-$IFACE_AUTO}"

    echo ""
    echo -e "  ${BOLD}──── Organización ──────────────────────────────────────${NC}"
    echo ""
    local ORG_DEFAULT="Universidad Autónoma de Aguascalientes"
    read -rp "  Nombre de la organización [$ORG_DEFAULT]: " ORG_NAME || true
    ORG_NAME="${ORG_NAME:-$ORG_DEFAULT}"

    echo ""
    echo -e "  ${BOLD}──── Dashboard Netlify (opcional) ──────────────────────${NC}"
    echo -e "  ${YELLOW}  Puede dejarse vacío si el dashboard no está configurado.${NC}"
    echo -e "  ${YELLOW}  El IDS funciona localmente sin esta configuración.${NC}"
    echo ""
    read -rp "  URL de ingestión Netlify (NETLIFY_INGEST_URL) [vacío]: " NETLIFY_INGEST_URL || true
    NETLIFY_INGEST_URL="${NETLIFY_INGEST_URL:-}"

    IDS_API_KEY=""
    if [ -n "$NETLIFY_INGEST_URL" ]; then
        read -rp "  Clave de API para Netlify (IDS_API_KEY): " IDS_API_KEY || true
        IDS_API_KEY="${IDS_API_KEY:-}"
    else
        advertencia "NETLIFY_INGEST_URL vacío — IDS_API_KEY omitida."
    fi

    # Resumen
    echo ""
    echo -e "  ${BOLD}──── Resumen ────────────────────────────────────────────${NC}"
    printf "  %-20s: %s\n"  "SMTP_HOST"          "$SMTP_HOST"
    printf "  %-20s: %s\n"  "SMTP_PORT"          "$SMTP_PORT"
    printf "  %-20s: %s\n"  "SMTP_USER"          "$SMTP_USER"
    printf "  %-20s: %s\n"  "SMTP_PASSWORD"      "****"
    printf "  %-20s: %s\n"  "ADMIN_EMAIL"        "$ADMIN_EMAIL"
    printf "  %-20s: %s\n"  "NETWORK_INTERFACE"  "$NETWORK_INTERFACE"
    printf "  %-20s: %s\n"  "ORG_NAME"           "$ORG_NAME"
    printf "  %-20s: %s\n"  "NETLIFY_INGEST_URL" "${NETLIFY_INGEST_URL:-[vacío]}"
    printf "  %-20s: %s\n"  "IDS_API_KEY"        "${IDS_API_KEY:+****}${IDS_API_KEY:-[vacío]}"
    echo "  ─────────────────────────────────────────────────────"
    echo ""
}

_escribir_env() {
    cat > "$DIR/.env" <<EOF
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
ADMIN_EMAIL=${ADMIN_EMAIL}
NETWORK_INTERFACE=${NETWORK_INTERFACE}
ORG_NAME=${ORG_NAME}
NETLIFY_INGEST_URL=${NETLIFY_INGEST_URL}
IDS_API_KEY=${IDS_API_KEY}
EOF
    chmod 600 "$DIR/.env"
    ok ".env escrito con permisos 600"
}

ENV_NUEVO=false

if [ -f "$DIR/.env" ] && [ -s "$DIR/.env" ]; then
    ok ".env existente encontrado"
    if confirmar "¿Deseas reconfigurar el .env?" "n"; then
        ENV_NUEVO=true
    else
        ok ".env conservado sin cambios"
        NETWORK_INTERFACE=$(grep -E '^NETWORK_INTERFACE=' "$DIR/.env" | cut -d= -f2 | tr -d '[:space:]') || true
        NETWORK_INTERFACE="${NETWORK_INTERFACE:-eth0}"
        SMTP_USER=$(grep -E '^SMTP_USER=' "$DIR/.env" | cut -d= -f2 | tr -d '[:space:]') || true
        NETLIFY_INGEST_URL=$(grep -E '^NETLIFY_INGEST_URL=' "$DIR/.env" | cut -d= -f2 | tr -d '[:space:]') || true
        NETLIFY_INGEST_URL="${NETLIFY_INGEST_URL:-}"
    fi
else
    info "No se encontró .env. Iniciando configuración interactiva..."
    ENV_NUEVO=true
fi

if [ "$ENV_NUEVO" = true ]; then
    while true; do
        _formulario_env
        if confirmar "¿Los datos son correctos?" "s"; then
            _escribir_env
            break
        fi
        echo ""
        info "Repitiendo el formulario..."
    done
fi

# ═══════════════════════════════════════════════════════
#  PASO 5 — Archivos y directorios del proyecto
# ═══════════════════════════════════════════════════════
paso "Archivos y directorios del proyecto"

for dir in logs blacklist docs; do
    mkdir -p "$DIR/$dir"
    ok "Directorio $dir/ verificado"
done

for log_file in logs/bitacora.log logs/sitios_visitados.log; do
    if [ ! -f "$DIR/$log_file" ]; then
        touch "$DIR/$log_file"
        chmod 600 "$DIR/$log_file"
        ok "$log_file creado (permisos 600)"
    else
        chmod 600 "$DIR/$log_file"
        ok "$log_file ya existe (permisos 600 verificados)"
    fi
done

if [ ! -f "$DIR/whitelist.txt" ]; then
    cat > "$DIR/whitelist.txt" << 'WEOF'
# whitelist.txt - Dispositivos autorizados en la red
# Formato: IP,MAC,DESCRIPCION
# Ejemplo: 192.168.1.100,aa:bb:cc:dd:ee:ff,Laptop-Admin
WEOF
    ok "whitelist.txt creado con plantilla"
else
    ok "whitelist.txt ya existe"
fi

if [ ! -f "$DIR/docs/aviso_privacidad.txt" ]; then
    cat > "$DIR/docs/aviso_privacidad.txt" << 'AEOF'
PENDIENTE: Agregar el aviso de privacidad antes de desplegar en producción.

Este archivo debe contener el Aviso de Privacidad institucional conforme a la
Ley Federal de Protección de Datos Personales en Posesión de los Particulares
(LFPDPPP) o la normativa aplicable.

Contacta al responsable de datos personales de la institución para obtener
el texto oficial antes de poner el IDS en operación.
AEOF
    advertencia "docs/aviso_privacidad.txt creado con placeholder — reemplázalo antes de producción"
else
    ok "docs/aviso_privacidad.txt ya existe"
fi

# Permisos de ejecución en todos los scripts
chmod +x "$DIR"/*.sh 2>/dev/null || true
ok "Permisos de ejecución verificados en *.sh"

echo ""
info "Verificando archivos de blacklist..."
_BLACKLISTS_CLAVE=(
    "blacklist/feodo_blacklist.csv"
    "blacklist/cins_blacklist.txt"
    "blacklist/blocklist_de.txt"
    "blacklist/emerging_threats.txt"
)
_FALTA_BLACKLIST=false
for _bf in "${_BLACKLISTS_CLAVE[@]}"; do
    if [ ! -s "$DIR/$_bf" ]; then
        _FALTA_BLACKLIST=true
        break
    fi
done

if [ "$_FALTA_BLACKLIST" = true ]; then
    info "Faltan archivos de blacklist. Descargando feeds de threat intelligence..."
    info "(Esto puede tardar unos minutos según la conexión)"
    if "$PYTHON" "$DIR/utils/threat_feed.py" 2>&1; then
        ok "Blacklists descargadas correctamente"
    else
        advertencia "Algunas blacklists no pudieron descargarse. El IDS las descargará al iniciar."
    fi
else
    ok "Blacklists ya presentes en disco"
    info "El IDS actualizará los feeds automáticamente al iniciar (si tienen más de 24 h)"
fi

# ═══════════════════════════════════════════════════════
#  PASO 6 — Regla sudoers NOPASSWD
# ═══════════════════════════════════════════════════════
paso "Regla sudoers NOPASSWD para ids.py"

SUDOERS_FILE="/etc/sudoers.d/ids-institucional"
SUDOERS_USER="$(whoami)"
PYTHON_BIN="$DIR/venv/bin/python"
IDS_SCRIPT="$DIR/ids.py"
SUDOERS_ENTRY="$SUDOERS_USER ALL=(ALL) NOPASSWD: $PYTHON_BIN $IDS_SCRIPT"

_aplicar_sudoers() {
    echo "$SUDOERS_ENTRY" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 440 "$SUDOERS_FILE"
    if sudo visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
        ok "Regla sudoers validada y aplicada"
    else
        sudo rm -f "$SUDOERS_FILE"
        error "La regla sudoers generada es inválida. Archivo eliminado por seguridad."
    fi
}

if sudo test -f "$SUDOERS_FILE" 2>/dev/null; then
    if sudo grep -qF "$SUDOERS_ENTRY" "$SUDOERS_FILE" 2>/dev/null; then
        ok "Regla sudoers ya configurada y correcta"
    else
        advertencia "Regla sudoers existe pero tiene rutas distintas (instalación previa). Actualizando..."
        _aplicar_sudoers
    fi
else
    _aplicar_sudoers
fi

info "Regla: $SUDOERS_ENTRY"

# ═══════════════════════════════════════════════════════
#  PASO 7 — Cifrado del .env con OpenSSL (opcional)
# ═══════════════════════════════════════════════════════
paso "Cifrado del .env con OpenSSL (opcional)"

if [ -f "$DIR/.env" ]; then
    echo ""
    if confirmar "¿Cifrar el archivo .env con OpenSSL para mayor seguridad?" "n"; then
        bash "$DIR/cifrar_env.sh"
        ok ".env.enc generado"
        echo ""
        echo -e "  ${YELLOW}El IDS puede arrancar desde .env.enc sin el .env en texto plano.${NC}"
        echo -e "  ${YELLOW}Define la contraseña: export IDS_ENV_PASSWORD='tu_contraseña'${NC}"
        echo ""
        if confirmar "¿Eliminar el .env original en texto plano?" "n"; then
            rm -f "$DIR/.env"
            ok ".env eliminado. El IDS usará .env.enc."
            advertencia "Asegúrate de tener IDS_ENV_PASSWORD definida antes de iniciar el IDS."
        else
            ok "Ambos archivos conservados (.env y .env.enc)"
        fi
    else
        ok "Cifrado omitido"
    fi
else
    advertencia "No hay .env que cifrar en este momento"
fi

# ═══════════════════════════════════════════════════════
#  PASO 8 — Inicio automático al arrancar sesión (opcional)
# ═══════════════════════════════════════════════════════
paso "Inicio automático al arrancar sesión (opcional)"

echo ""
if confirmar "¿Iniciar el IDS automáticamente al arrancar sesión?" "n"; then
    bash "$DIR/autostart.sh" activar
    ok "Inicio automático configurado"
else
    ok "Inicio automático omitido"
    info "Puedes activarlo después con: ./autostart.sh activar"
fi

# ═══════════════════════════════════════════════════════
#  PASO 9 — Verificación de conectividad y dependencias
# ═══════════════════════════════════════════════════════
paso "Verificación de conectividad y dependencias"

echo ""
check "Python en venv"        "$PYTHON" --version
check "Scapy disponible"      "$PYTHON" -c "import scapy"
check "PyQt6 disponible"      "$PYTHON" -c "import PyQt6"
check "python-dotenv"         "$PYTHON" -c "import dotenv"
check "requests"              "$PYTHON" -c "import requests"
check "OpenSSL disponible"    openssl version
check "tcpdump disponible"    tcpdump --version
check "Interfaz '$NETWORK_INTERFACE' existe" ip link show "$NETWORK_INTERFACE"
check "Conectividad internet" ping -c1 -W3 8.8.8.8

if [ -n "${NETLIFY_INGEST_URL:-}" ]; then
    check "Netlify accesible" curl -sf --max-time 5 --head "$NETLIFY_INGEST_URL"
fi

echo ""
if [ "$_ERRORES_CHECK" -gt 0 ]; then
    advertencia "$_ERRORES_CHECK verificación(es) fallaron. Revisa los elementos marcados con ✗."
else
    ok "Todas las verificaciones pasaron correctamente"
fi

# ═══════════════════════════════════════════════════════
#  MENSAJE FINAL
# ═══════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║      IDS Institucional — Instalación completada     ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Para iniciar el IDS:"
echo -e "    ${BOLD}./iniciar.sh${NC}"
echo ""
echo "  Para detenerlo:"
echo -e "    ${BOLD}./detener.sh${NC}"
echo ""
echo "  Para agregar dispositivos a la whitelist:"
echo -e "    Edita ${BOLD}whitelist.txt${NC} con formato  IP,MAC,DESCRIPCION"
echo ""
echo "  Logs en tiempo real:"
echo -e "    ${BOLD}tail -f logs/bitacora.log${NC}"
echo ""
if [ -n "${SMTP_USER:-}" ]; then
    echo "  Si el correo llega a spam:"
    echo -e "    Agrega ${BOLD}${SMTP_USER}${NC} a tus contactos"
    echo "    y marca el primer correo como \"No es spam\""
    echo ""
fi
echo "  Log de esta instalación:"
echo -e "    ${BOLD}$LOG_INSTALL${NC}"
echo ""

# ─── Cierre del log ───────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Instalación finalizada : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Verificaciones fallidas: $_ERRORES_CHECK"
echo "═══════════════════════════════════════════════════════"
