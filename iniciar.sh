#!/bin/bash

# Colores para la terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════╗"
echo "║     IDS INSTITUCIONAL - Iniciando...     ║"
echo "║  Universidad Autónoma de Aguascalientes  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

cd "$DIR"

# Verificar que el entorno virtual existe
if [ ! -d "$DIR/venv" ]; then
    echo -e "${RED}ERROR: No se encontró el entorno virtual en $DIR/venv${NC}"
    echo "Ejecuta: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Verificar que PyQt6 está instalado
if ! "$DIR/venv/bin/python" -c "import PyQt6" 2>/dev/null; then
    echo -e "${YELLOW}PyQt6 no encontrado. Instalando...${NC}"
    "$DIR/venv/bin/pip" install PyQt6 --break-system-packages
fi

# Verificar que el aviso de privacidad existe
if [ ! -f "$DIR/docs/aviso_privacidad.txt" ]; then
    echo -e "${RED}ADVERTENCIA: No se encontró docs/aviso_privacidad.txt${NC}"
fi

# Verificar que .ids_initialized existe para saber si es primera ejecución
if [ ! -f "$DIR/.ids_initialized" ]; then
    echo -e "${YELLOW}Primera ejecución detectada. Se mostrará la política de privacidad.${NC}"
else
    echo -e "${GREEN}Sistema previamente inicializado.${NC}"
fi

echo ""
echo -e "${GREEN}Iniciando interfaz gráfica...${NC}"
echo "(Cierra la ventana o el ícono de la bandeja para detener el IDS)"
echo ""

# Verificar si el IDS ya está corriendo
PID_FILE="$DIR/.ids.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${YELLOW}El IDS ya está corriendo (PID $PID).${NC}"
        echo -e "Para detenerlo ejecuta: ${RED}./detener.sh${NC}"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

echo -e "${GREEN}Iniciando IDS en segundo plano...${NC}"

export DISPLAY=${DISPLAY:-:0}

mkdir -p "$DIR/logs"

nohup setsid "$DIR/venv/bin/python" "$DIR/gui.py" \
    > "$DIR/logs/gui_arranque.log" 2>&1 &

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
    echo -e "${RED}Error al iniciar el IDS. Revisa $DIR/logs/gui_arranque.log${NC}"
    rm -f "$PID_FILE"
    exit 1
fi
