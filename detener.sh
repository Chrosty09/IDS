#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$DIR/.ids.pid"

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

echo -e "Deteniendo IDS (PID $PID)..."

# Terminar el proceso principal de la GUI
kill -TERM "$PID" 2>/dev/null

# Esperar hasta 5 segundos a que termine limpiamente
for i in $(seq 1 5); do
    if ! ps -p "$PID" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Si sigue vivo, forzar
if ps -p "$PID" > /dev/null 2>&1; then
    echo -e "${YELLOW}El proceso no respondió. Forzando cierre...${NC}"
    kill -KILL "$PID" 2>/dev/null
fi

# Limpiar cualquier proceso hijo de ids.py que quedara huérfano
pkill -f "venv/bin/python.*ids.py" 2>/dev/null

rm -f "$PID_FILE"
echo -e "${GREEN}IDS detenido correctamente.${NC}"
