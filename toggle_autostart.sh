#!/bin/bash

# ══════════════════════════════════════════════════════
# toggle_autostart.sh - Activa/desactiva el inicio automático del IDS
# Uso: ./toggle_autostart.sh
# IDS Institucional - Universidad Autónoma de Aguascalientes
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

DESKTOP_FILE="$HOME/.config/autostart/ids-institucional.desktop"
AUTOSTART_SH="/home/kali/IDS/autostart.sh"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       IDS INSTITUCIONAL — Toggle Autostart           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ -f "$DESKTOP_FILE" ]; then
    echo -e "Autostart actualmente: ${GREEN}ACTIVO${NC}"
    echo -e "Desactivando..."
    bash "$AUTOSTART_SH" desactivar
else
    echo -e "Autostart actualmente: ${YELLOW}INACTIVO${NC}"
    echo -e "Activando..."
    bash "$AUTOSTART_SH" activar
fi
