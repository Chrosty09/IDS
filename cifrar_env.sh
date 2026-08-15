#!/bin/bash

# ══════════════════════════════════════════════════════
# cifrar_env.sh - Cifra .env con OpenSSL AES-256-CBC + PBKDF2 (600k iter.)
# IDS Institucional - Universidad Autónoma de Aguascalientes
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

ITERACIONES=600000   # REF: EO-003 — OWASP; las versiones anteriores usaban 10 000
PASS_FILE="/etc/ids/env.password"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       IDS INSTITUCIONAL — Cifrar configuración       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ ! -f ".env" ]; then
    echo -e "${RED}[ERROR]${NC} No se encontró el archivo .env en $(pwd)"
    echo "        Crea primero el .env con tus credenciales."
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} OpenSSL no está instalado."
    echo "        Instálalo con: sudo apt install openssl"
    exit 1
fi

echo -e "Se cifrará .env → .env.enc con AES-256-CBC + PBKDF2 (${ITERACIONES} iteraciones)"
echo ""

# La contraseña se lee una sola vez y viaja por stdin: nunca queda en argv
# (visible vía /proc/*/cmdline) ni en el entorno de openssl.
read -rsp "Contraseña de cifrado: " PASS
echo ""
read -rsp "Repetir contraseña: " PASS2
echo ""

if [ -z "$PASS" ]; then
    echo -e "${RED}[ERROR]${NC} La contraseña no puede estar vacía."
    unset PASS PASS2
    exit 1
fi

if [ "$PASS" != "$PASS2" ]; then
    echo -e "${RED}[ERROR]${NC} Las contraseñas no coinciden."
    unset PASS PASS2
    exit 1
fi

printf '%s\n' "$PASS" | openssl enc -aes-256-cbc -pbkdf2 -iter "$ITERACIONES" \
    -in .env -out .env.enc -pass stdin

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} No se pudo cifrar el archivo."
    unset PASS PASS2
    exit 1
fi

echo ""
echo -e "${GREEN}[  OK  ]${NC}  Archivo cifrado guardado como .env.enc"

# ── Guardar la contraseña para el IDS (root-only) ────────────────────────
# NUNCA uses /etc/environment: es legible por todos los usuarios del equipo.
# El motor IDS corre como root y lee este archivo restringido (REF: EO-004).
GUARDAR=""
if [ "$1" = "--sin-guardar" ]; then
    GUARDAR="n"
elif [ "$1" = "--guardar" ]; then
    GUARDAR="s"
fi
while [ "$GUARDAR" != "s" ] && [ "$GUARDAR" != "n" ]; do
    read -rp "¿Guardar la contraseña en ${PASS_FILE} (root:root 600) para que el IDS descifre automáticamente? [S/n]: " GUARDAR
    GUARDAR="${GUARDAR:-s}"
done

if [ "$GUARDAR" = "s" ]; then
    sudo mkdir -p /etc/ids
    printf '%s\n' "$PASS" | sudo tee "$PASS_FILE" > /dev/null
    sudo chown root:root "$PASS_FILE"
    sudo chmod 600 "$PASS_FILE"
    echo -e "${GREEN}[  OK  ]${NC}  Contraseña guardada en ${PASS_FILE} (root:root 600)"
else
    echo -e "${YELLOW}[AVISO]${NC} Sin la contraseña el IDS (root) no podrá descifrar:"
    echo -e "        guárdala luego con: sudo tee ${PASS_FILE} (y chmod 600, chown root:root)"
fi

unset PASS PASS2

echo ""
echo -e "${BOLD}PASOS SIGUIENTES:${NC}"
echo ""
echo -e "  1. ${RED}Elimina o protege el .env original si no lo necesitas en texto plano:${NC}"
echo -e "     ${YELLOW}rm .env${NC}   (el IDS usará .env.enc automáticamente)"
echo ""
echo -e "  2. Ejecuta ${YELLOW}./install.sh${NC} para desplegar la configuración protegida."
echo ""
echo -e "  3. Nunca subas .env ni .env.enc al repositorio."
echo ""
