#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Hardening C1: el estado (PID, centinela) vive en STATE_DIR del despliegue
# protegido, no junto al código.
INSTALL_DIR="${IDS_INSTALL_DIR:-/opt/ids}"
[ -f "$INSTALL_DIR/gui.py" ] || INSTALL_DIR="$DIR"

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
PID_FILE="$STATE_DIR/.ids.pid"

# REF: M2 — antes de enviar señales se verifica que el PID leído del archivo
# siga siendo la GUI del IDS: si la GUI murió y el PID fue reutilizado por
# otro proceso, matarlo afectaría a un proceso ajeno.
_es_gui_ids() {
    local pid="$1"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "/proc/$pid/cmdline" ] || return 1
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q "gui\.py"
}

echo -e "${BOLD}IDS Institucional — Detener sistema${NC}"
echo "──────────────────────────────────────"

if [ ! -f "$PID_FILE" ]; then
    echo -e "${YELLOW}No se encontró proceso activo del IDS.${NC}"
    exit 0
fi

PID=$(cat "$PID_FILE")

if ! ps -p "$PID" > /dev/null 2>&1; then
    echo -e "${YELLOW}El proceso $PID ya no está corriendo.${NC}"
    rm -f "$PID_FILE"
    exit 0
fi

# La GUI murió y el PID lo ocupa otro proceso: no señalizarlo jamás.
if ! _es_gui_ids "$PID"; then
    echo -e "${YELLOW}El PID $PID del registro ya no corresponde a la GUI del IDS"
    echo -e "(posible reuso de PID); no se enviarán señales a ese proceso.${NC}"
    rm -f "$PID_FILE"
    exit 1
fi

echo -e "Deteniendo IDS (PID $PID)..."

# El hijo ids.py puede correr como root: no lo matamos con señales (no tenemos
# privilegios), sino con el archivo centinela que su bucle de captura revisa.
touch "$STATE_DIR/.ids_stop" 2>/dev/null || \
    echo -e "${YELLOW}No se pudo crear el centinela en $STATE_DIR (¿pertenece tu usuario al grupo 'ids'?)${NC}"

# La GUI sí es un proceso del usuario; kill -TERM funciona sin problema.
kill -TERM "$PID" 2>/dev/null

# Esperar hasta 10 segundos a que ambos terminen limpiamente
# (el hijo root revisa el centinela cada 5 s).
for i in $(seq 1 10); do
    if ! ps -p "$PID" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Si la GUI sigue viva (y sigue siendo la GUI), forzar el cierre
if ps -p "$PID" > /dev/null 2>&1 && _es_gui_ids "$PID"; then
    echo -e "${YELLOW}El proceso no respondió. Forzando cierre...${NC}"
    kill -KILL "$PID" 2>/dev/null
fi

rm -f "$PID_FILE"
echo -e "${GREEN}IDS detenido correctamente.${NC}"
