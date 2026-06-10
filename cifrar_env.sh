#!/bin/bash

# ══════════════════════════════════════════════════════
# cifrar_env.sh - Cifra .env con OpenSSL AES-256-CBC
# IDS Institucional - Universidad Autónoma de Aguascalientes
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

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

echo -e "${YELLOW}Se cifrará .env → .env.enc con AES-256-CBC + PBKDF2${NC}"
echo "Introduce la contraseña que usarás para descifrar en producción:"
echo ""

openssl enc -aes-256-cbc -pbkdf2 -in .env -out .env.enc

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} No se pudo cifrar el archivo."
    exit 1
fi

echo ""
echo -e "${GREEN}[  OK  ]${NC}  Archivo cifrado guardado como .env.enc"
echo ""
echo -e "${BOLD}PASOS SIGUIENTES:${NC}"
echo ""
echo -e "  1. Define la contraseña como variable de entorno del sistema:"
echo -e "     ${YELLOW}echo 'IDS_ENV_PASSWORD=tu_contraseña' | sudo tee -a /etc/environment${NC}"
echo -e "     (Reinicia la sesión para que tome efecto)"
echo ""
echo -e "  2. Para autostart, agrégala también en el archivo .desktop o en sudoers."
echo ""
echo -e "  3. ${RED}Elimina o protege el .env original si no lo necesitas en texto plano:${NC}"
echo -e "     ${YELLOW}rm .env${NC}   (el IDS usará .env.enc automáticamente)"
echo ""
echo -e "  4. Nunca subas .env ni .env.enc al repositorio."
echo ""
