#!/bin/bash

# ══════════════════════════════════════════════════════
# autostart.sh - Gestiona el inicio automático del IDS
# Usa XDG autostart (.desktop) + sudoers NOPASSWD
# Uso: ./autostart.sh [activar|desactivar|estado]
# IDS Institucional - Universidad Autónoma de Aguascalientes
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

AUTOSTART_DIR="$HOME/.config/autostart"
DESKTOP_FILE="$AUTOSTART_DIR/ids-institucional.desktop"
SUDOERS_FILE="/etc/sudoers.d/ids-institucional"
SUDOERS_ENTRY="kali ALL=(ALL) NOPASSWD: /home/kali/IDS/venv/bin/python /home/kali/IDS/ids.py"

# ── Helpers ────────────────────────────────────────────

esta_activo() {
    [ -f "$DESKTOP_FILE" ]
}

sudoers_configurado() {
    [ -f "$SUDOERS_FILE" ] && grep -qF "$SUDOERS_ENTRY" "$SUDOERS_FILE" 2>/dev/null
}

mostrar_estado() {
    echo -e "${BOLD}Estado del inicio automático:${NC}"
    if esta_activo; then
        echo -e "  Autostart XDG : ${GREEN}ACTIVO${NC} ($DESKTOP_FILE)"
    else
        echo -e "  Autostart XDG : ${RED}INACTIVO${NC}"
    fi
    if sudoers_configurado; then
        echo -e "  Sudoers NOPASSWD : ${GREEN}CONFIGURADO${NC} ($SUDOERS_FILE)"
    else
        echo -e "  Sudoers NOPASSWD : ${YELLOW}NO CONFIGURADO${NC} (requerido para captura de paquetes)"
    fi
}

# ── Activar ────────────────────────────────────────────

activar() {
    echo -e "${BOLD}Activando inicio automático del IDS...${NC}"
    echo ""

    # 1. Configurar sudoers NOPASSWD para ids.py
    if sudoers_configurado; then
        echo -e "${GREEN}[  OK  ]${NC}  Regla sudoers NOPASSWD ya configurada."
    else
        echo -e "${YELLOW}[  FIX ]${NC}  Configurando sudo NOPASSWD para ids.py..."
        echo "       (Se requerirá tu contraseña de sudo una sola vez)"
        echo "$SUDOERS_ENTRY" | sudo tee "$SUDOERS_FILE" > /dev/null
        if [ $? -ne 0 ]; then
            echo -e "${RED}[ FAIL ]${NC}  No se pudo configurar sudoers. El IDS necesitará contraseña al iniciar."
        else
            sudo chmod 440 "$SUDOERS_FILE"
            if sudo visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
                echo -e "${GREEN}[  OK  ]${NC}  Regla sudoers configurada correctamente."
            else
                echo -e "${RED}[ FAIL ]${NC}  Regla sudoers inválida. Eliminando..."
                sudo rm -f "$SUDOERS_FILE"
            fi
        fi
    fi

    # 2. Crear el archivo .desktop de autostart XDG
    mkdir -p "$AUTOSTART_DIR"
    cat > "$DESKTOP_FILE" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=IDS Institucional
Comment=Sistema de Detección de Intrusos - UAA
Exec=/home/kali/IDS/venv/bin/python /home/kali/IDS/gui.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
DESKTOP

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[  OK  ]${NC}  Archivo de autostart creado: $DESKTOP_FILE"
    else
        echo -e "${RED}[ FAIL ]${NC}  No se pudo crear $DESKTOP_FILE"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}${BOLD}✓ El IDS se iniciará automáticamente al iniciar sesión.${NC}"
    echo -e "  Para desactivarlo: ${YELLOW}./autostart.sh desactivar${NC}"
}

# ── Desactivar ─────────────────────────────────────────

desactivar() {
    echo -e "${BOLD}Desactivando inicio automático del IDS...${NC}"
    echo ""

    if esta_activo; then
        rm -f "$DESKTOP_FILE"
        echo -e "${GREEN}[  OK  ]${NC}  Archivo de autostart eliminado."
    else
        echo -e "${YELLOW}[ WARN ]${NC}  El autostart ya estaba desactivado."
    fi

    # Nota: se conserva la regla sudoers para no perder la configuración
    echo ""
    echo -e "${GREEN}${BOLD}✓ Inicio automático desactivado.${NC}"
    echo -e "  La regla sudoers se conserva para cuando vuelvas a activarlo."
    echo -e "  Para activarlo de nuevo: ${GREEN}./autostart.sh activar${NC}"
}

# ── Punto de entrada ───────────────────────────────────

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       IDS INSTITUCIONAL — Gestión de Autostart       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

ACCION="${1:-}"

if [ -z "$ACCION" ]; then
    mostrar_estado
    echo ""
    echo -e "Uso: ${BOLD}./autostart.sh [activar|desactivar|estado]${NC}"
    echo ""
    read -rp "¿Qué deseas hacer? [activar/desactivar/estado]: " ACCION
fi

case "$ACCION" in
    activar)
        activar
        ;;
    desactivar)
        desactivar
        ;;
    estado|status)
        mostrar_estado
        ;;
    *)
        echo -e "${RED}Opción no reconocida: '$ACCION'${NC}"
        echo -e "Uso: ${BOLD}./autostart.sh [activar|desactivar|estado]${NC}"
        exit 1
        ;;
esac
