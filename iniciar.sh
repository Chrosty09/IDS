#!/bin/bash

# Colores para la terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hardening C1: si existe el despliegue protegido (root-owned), la GUI se
# ejecuta desde allí y nunca desde este directorio de desarrollo.
INSTALL_DIR="${IDS_INSTALL_DIR:-/opt/ids}"
[ -f "$INSTALL_DIR/gui.py" ] || INSTALL_DIR="$DIR"

# Resolución del directorio de estado (igual que config.py):
# entorno → .env.runtime del despliegue → valor por defecto.
_resolver_state_dir() {
    local dir="$1"
    [ -n "${IDS_STATE_DIR:-}" ] && { echo "$IDS_STATE_DIR"; return; }
    local val
    val="$(grep -E '^IDS_STATE_DIR=' "$dir/.env.runtime" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
    [ -n "$val" ] && { echo "$val"; return; }
    if [ "$dir" != "$DIR" ]; then
        echo "/var/lib/ids"
    else
        echo "$DIR/runtime"
    fi
}
STATE_DIR="$(_resolver_state_dir "$INSTALL_DIR")"

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════╗"
echo "║     IDS INSTITUCIONAL - Iniciando...     ║"
echo "║  Universidad Autónoma de Aguascalientes  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "Despliegue : ${INSTALL_DIR}"
echo -e "Estado     : ${STATE_DIR}"
echo ""

cd "$DIR"

# Verificar que el entorno virtual existe
if [ ! -d "$INSTALL_DIR/venv" ]; then
    echo -e "${RED}ERROR: No se encontró el entorno virtual en $INSTALL_DIR/venv${NC}"
    echo "Ejecuta: ./install.sh"
    exit 1
fi

# Verificar que PyQt6 está instalado (solo en desarrollo; el despliegue
# protegido se instala completo con install.sh)
if [ "$INSTALL_DIR" = "$DIR" ] && ! "$INSTALL_DIR/venv/bin/python" -c "import PyQt6" 2>/dev/null; then
    echo -e "${YELLOW}PyQt6 no encontrado. Instalando...${NC}"
    "$INSTALL_DIR/venv/bin/pip" install PyQt6 --break-system-packages
fi

# Verificar que el aviso de privacidad existe
if [ ! -f "$INSTALL_DIR/docs/aviso_privacidad.txt" ]; then
    echo -e "${RED}ADVERTENCIA: No se encontró docs/aviso_privacidad.txt${NC}"
fi

# Verificar que .ids_initialized existe para saber si es primera ejecución
if [ ! -f "$STATE_DIR/.ids_initialized" ]; then
    echo -e "${YELLOW}Primera ejecución detectada. Se mostrará la política de privacidad.${NC}"
else
    echo -e "${GREEN}Sistema previamente inicializado.${NC}"
fi

echo ""
echo -e "${GREEN}Iniciando interfaz gráfica...${NC}"
echo "(Cierra la ventana o el ícono de la bandeja para detener el IDS)"
echo ""

# Verificar si el IDS ya está corriendo
# REF: M2 — se verifica la identidad del proceso (cmdline) para no confundir
# un PID reutilizado por otro proceso con la GUI del IDS.
PID_FILE="$STATE_DIR/.ids.pid"

_es_gui_ids() {
    local pid="$1"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "/proc/$pid/cmdline" ] || return 1
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q "gui\.py"
}

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1 && _es_gui_ids "$PID"; then
        echo -e "${YELLOW}El IDS ya está corriendo (PID $PID).${NC}"
        echo -e "Para detenerlo ejecuta: ${RED}./detener.sh${NC}"
        exit 0
    else
        # Registro huérfano o PID reutilizado por otro proceso: limpiar.
        rm -f "$PID_FILE"
    fi
fi

echo -e "${GREEN}Iniciando IDS en segundo plano...${NC}"

export DISPLAY=${DISPLAY:-:0}

mkdir -p "$STATE_DIR" 2>/dev/null || {
    echo -e "${RED}ERROR: No se puede escribir en $STATE_DIR${NC}"
    echo "Si el IDS acaba de instalarse, cierra la sesión y vuelve a entrar"
    echo "para que tu usuario pertenezca al grupo 'ids', o ejecuta ./install.sh."
    exit 1
}

nohup setsid "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/gui.py" \
    > "$STATE_DIR/gui_arranque.log" 2>&1 &

# Guardar el PID para poder detenerlo después
echo $! > "$PID_FILE"
PID=$(cat "$PID_FILE")

# Verificar que arrancó correctamente
sleep 2
if ps -p "$PID" > /dev/null 2>&1; then
    echo -e "${GREEN}IDS iniciado correctamente en segundo plano (PID $PID).${NC}"
    echo -e "El ícono aparecerá en la bandeja del sistema."
    echo -e "Para detenerlo ejecuta: ${RED}./detener.sh${NC}"
else
    echo -e "${RED}Error al iniciar el IDS. Revisa $STATE_DIR/gui_arranque.log${NC}"
    rm -f "$PID_FILE"
    exit 1
fi
