#!/bin/bash

# ══════════════════════════════════════════════════════
# setup.sh - Verificador e instalador de dependencias
# IDS Institucional - Universidad Autónoma de Aguascalientes
# ══════════════════════════════════════════════════════

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

OK="${GREEN}[  OK  ]${NC}"
WARN="${YELLOW}[ WARN ]${NC}"
FAIL="${RED}[ FAIL ]${NC}"
INFO="${BLUE}[ INFO ]${NC}"
FIX="${YELLOW}[  FIX ]${NC}"

ERRORES=0
ADVERTENCIAS=0

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         IDS INSTITUCIONAL — Setup y Verificación     ║"
echo "║       Universidad Autónoma de Aguascalientes         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Verificando requisitos del sistema..."
echo "──────────────────────────────────────────────────────"

# ─── 1. USUARIO Y PRIVILEGIOS ──────────────────────────────
echo ""
echo -e "${BOLD}[ 1/8 ] Usuario y privilegios${NC}"

if [ "$EUID" -eq 0 ]; then
    echo -e "$WARN  Ejecutando como root. Se recomienda ejecutar como usuario kali."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
else
    echo -e "$OK  Usuario: $(whoami)"
fi

if sudo -n true 2>/dev/null; then
    echo -e "$OK  Acceso sudo disponible (requerido para captura de paquetes)"
else
    echo -e "$WARN  sudo requiere contraseña. El IDS necesitará ingresarla al iniciar."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

SUDOERS_FILE="/etc/sudoers.d/ids-institucional"
SUDOERS_ENTRY="kali ALL=(ALL) NOPASSWD: /home/kali/IDS/venv/bin/python /home/kali/IDS/ids.py"

if [ -f "$SUDOERS_FILE" ] && grep -qF "$SUDOERS_ENTRY" "$SUDOERS_FILE" 2>/dev/null; then
    echo -e "$OK  Regla sudoers NOPASSWD para ids.py ya configurada"
else
    echo -e "$FIX   Configurando sudo NOPASSWD para ids.py (necesario para captura de paquetes)..."
    echo "$SUDOERS_ENTRY" | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 440 "$SUDOERS_FILE"
    if sudo visudo -c -f "$SUDOERS_FILE" > /dev/null 2>&1; then
        echo -e "$OK  Regla sudoers configurada y validada correctamente."
    else
        echo -e "$FAIL  La regla sudoers no es válida. Eliminando para evitar problemas."
        sudo rm -f "$SUDOERS_FILE"
        ERRORES=$((ERRORES + 1))
    fi
fi

# ─── 2. PYTHON ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}[ 2/8 ] Python${NC}"

if command -v python3 &>/dev/null; then
    PYTHON_VER=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 11 ]; then
        echo -e "$OK  Python $PYTHON_VER encontrado"
    else
        echo -e "$FAIL  Python $PYTHON_VER es demasiado antiguo. Se requiere 3.11 o superior."
        ERRORES=$((ERRORES + 1))
    fi
else
    echo -e "$FAIL  Python3 no encontrado."
    echo -e "$FIX   Instalando Python3..."
    sudo apt-get install -y python3 python3-pip
    ERRORES=$((ERRORES + 1))
fi

# ─── 3. ENTORNO VIRTUAL ────────────────────────────────────
echo ""
echo -e "${BOLD}[ 3/8 ] Entorno virtual${NC}"

VENV_PATH="/home/kali/IDS/venv"

if [ -d "$VENV_PATH" ]; then
    echo -e "$OK  Entorno virtual encontrado en $VENV_PATH"
else
    echo -e "$FIX   Entorno virtual no encontrado. Creando..."
    python3 -m venv "$VENV_PATH"
    if [ $? -eq 0 ]; then
        echo -e "$OK  Entorno virtual creado correctamente."
    else
        echo -e "$FAIL  No se pudo crear el entorno virtual."
        ERRORES=$((ERRORES + 1))
    fi
fi

PYTHON_VENV="$VENV_PATH/bin/python"
PIP_VENV="$VENV_PATH/bin/pip"

# ─── 4. DEPENDENCIAS PYTHON ────────────────────────────────
echo ""
echo -e "${BOLD}[ 4/8 ] Dependencias Python${NC}"

PAQUETES=(
    "scapy scapy"
    "dotenv python-dotenv"
    "requests requests"
    "ipwhois ipwhois"
    "PyQt6 PyQt6"
)

for entry in "${PAQUETES[@]}"; do
    IMPORT_NAME=$(echo "$entry" | awk '{print $1}')
    PIP_NAME=$(echo "$entry" | awk '{print $2}')
    if $PYTHON_VENV -c "import $IMPORT_NAME" 2>/dev/null; then
        VERSION=$($PYTHON_VENV -c "import $IMPORT_NAME; print(getattr($IMPORT_NAME, '__version__', 'ok'))" 2>/dev/null || echo "ok")
        echo -e "$OK  $PIP_NAME ($VERSION)"
    else
        echo -e "$FIX   $PIP_NAME no encontrado. Instalando..."
        $PIP_VENV install "$PIP_NAME" --break-system-packages -q
        if $PYTHON_VENV -c "import $IMPORT_NAME" 2>/dev/null; then
            echo -e "$OK  $PIP_NAME instalado correctamente."
        else
            echo -e "$FAIL  No se pudo instalar $PIP_NAME."
            ERRORES=$((ERRORES + 1))
        fi
    fi
done

# ─── 5. DEPENDENCIAS DEL SISTEMA ───────────────────────────
echo ""
echo -e "${BOLD}[ 5/8 ] Dependencias del sistema${NC}"

if ldconfig -p | grep -q libpcap; then
    echo -e "$OK  libpcap encontrada"
else
    echo -e "$FIX   libpcap no encontrada. Instalando..."
    sudo apt-get install -y libpcap-dev -q
    echo -e "$OK  libpcap instalada."
fi

if command -v tcpdump &>/dev/null; then
    echo -e "$OK  tcpdump disponible ($(tcpdump --version 2>&1 | head -1))"
else
    echo -e "$WARN  tcpdump no encontrado. Instalando..."
    sudo apt-get install -y tcpdump -q
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

if command -v dbus-launch &>/dev/null; then
    echo -e "$OK  dbus-launch disponible"
else
    echo -e "$FIX   dbus-x11 no encontrado. Instalando..."
    sudo apt-get install -y dbus-x11 -q
fi

# ─── 6. ARCHIVOS DE CONFIGURACIÓN ──────────────────────────
echo ""
echo -e "${BOLD}[ 6/8 ] Archivos de configuración${NC}"

if [ -f "/home/kali/IDS/.env" ]; then
    VARS_REQUERIDAS=("SMTP_USER" "SMTP_PASSWORD" "ADMIN_EMAIL" "NETWORK_INTERFACE")
    VARS_FALTANTES=()
    for var in "${VARS_REQUERIDAS[@]}"; do
        VAL=$(grep "^${var}=" /home/kali/IDS/.env | cut -d= -f2 | tr -d ' ')
        if [ -z "$VAL" ]; then
            VARS_FALTANTES+=("$var")
        fi
    done
    if [ ${#VARS_FALTANTES[@]} -eq 0 ]; then
        echo -e "$OK  .env encontrado y variables críticas definidas"
    else
        echo -e "$WARN  .env encontrado pero faltan variables: ${VARS_FALTANTES[*]}"
        echo -e "       Edita /home/kali/IDS/.env y completa los valores faltantes."
        ADVERTENCIAS=$((ADVERTENCIAS + 1))
    fi
else
    echo -e "$FAIL  Archivo .env no encontrado en /home/kali/IDS/"
    if [ -f "/home/kali/IDS/.env.example" ]; then
        echo -e "$FIX   Copiando .env.example como plantilla..."
        cp /home/kali/IDS/.env.example /home/kali/IDS/.env
        chmod 600 /home/kali/IDS/.env
        echo -e "$WARN  Edita /home/kali/IDS/.env con tus credenciales reales antes de continuar."
    else
        echo -e "       Crea el archivo .env con las variables requeridas."
    fi
    ERRORES=$((ERRORES + 1))
fi

if [ -f "/home/kali/IDS/whitelist.txt" ]; then
    ENTRADAS=$(grep -v "^#" /home/kali/IDS/whitelist.txt | grep -v "^$" | wc -l)
    if [ "$ENTRADAS" -gt 0 ]; then
        echo -e "$OK  whitelist.txt encontrada ($ENTRADAS dispositivos autorizados)"
    else
        echo -e "$WARN  whitelist.txt existe pero está vacía. Agrega al menos tu IP y MAC."
        ADVERTENCIAS=$((ADVERTENCIAS + 1))
    fi
else
    echo -e "$WARN  whitelist.txt no encontrada. Creando plantilla..."
    echo "# Formato: IP,MAC,DESCRIPCION" > /home/kali/IDS/whitelist.txt
    echo "# Ejemplo: 192.168.1.10,AA:BB:CC:DD:EE:FF,Mi laptop" >> /home/kali/IDS/whitelist.txt
    echo -e "$WARN  Edita /home/kali/IDS/whitelist.txt y agrega tus dispositivos."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

if [ -f "/home/kali/IDS/docs/aviso_privacidad.txt" ]; then
    echo -e "$OK  docs/aviso_privacidad.txt encontrado"
else
    echo -e "$WARN  docs/aviso_privacidad.txt no encontrado. La GUI mostrará un texto de placeholder."
    mkdir -p /home/kali/IDS/docs
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

if [ -f "/home/kali/IDS/requirements.txt" ]; then
    echo -e "$OK  requirements.txt encontrado"
else
    echo -e "$WARN  requirements.txt no encontrado. Generando desde el entorno virtual..."
    $PIP_VENV freeze > /home/kali/IDS/requirements.txt
    echo -e "$OK  requirements.txt generado."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

# ─── 7. ESTRUCTURA DE DIRECTORIOS ──────────────────────────
echo ""
echo -e "${BOLD}[ 7/8 ] Estructura de directorios y archivos principales${NC}"

ARCHIVOS_REQUERIDOS=(
    "/home/kali/IDS/ids.py"
    "/home/kali/IDS/gui.py"
    "/home/kali/IDS/config.py"
    "/home/kali/IDS/modulos/modulo_whitelist.py"
    "/home/kali/IDS/modulos/modulo_sitios.py"
    "/home/kali/IDS/modulos/modulo_threat_intel.py"
    "/home/kali/IDS/modulos/modulo_forense.py"
    "/home/kali/IDS/utils/mailer.py"
    "/home/kali/IDS/utils/logger.py"
    "/home/kali/IDS/utils/threat_feed.py"
    "/home/kali/IDS/utils/reporter.py"
    "/home/kali/IDS/detener.sh"
)

for archivo in "${ARCHIVOS_REQUERIDOS[@]}"; do
    if [ -f "$archivo" ]; then
        echo -e "$OK  $(basename $archivo)"
    else
        echo -e "$FAIL  $(basename $archivo) NO encontrado en $archivo"
        ERRORES=$((ERRORES + 1))
    fi
done

mkdir -p /home/kali/IDS/logs
mkdir -p /home/kali/IDS/blacklist
mkdir -p /home/kali/IDS/docs
echo -e "$OK  Directorios logs/, blacklist/, docs/ verificados"

# ─── 8. CONECTIVIDAD ───────────────────────────────────────
echo ""
echo -e "${BOLD}[ 8/8 ] Conectividad de red${NC}"

if nc -zw3 smtp.gmail.com 465 2>/dev/null; then
    echo -e "$OK  Puerto SMTP 465 (Gmail SSL) accesible"
else
    echo -e "$WARN  No se pudo conectar a smtp.gmail.com:465"
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

SUPABASE_HOST="wioxiacrqybwhsxueava.supabase.co"
if nc -zw3 "$SUPABASE_HOST" 443 2>/dev/null; then
    echo -e "$OK  Supabase accesible (HTTPS)"
else
    echo -e "$WARN  No se pudo conectar a Supabase. El dashboard no funcionará sin conexión."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

if curl -sf --max-time 5 https://feodotracker.abuse.ch > /dev/null 2>&1; then
    echo -e "$OK  Feeds de threat intelligence accesibles"
else
    echo -e "$WARN  No se pudo conectar a feodotracker.abuse.ch. Los feeds usarán caché local."
    ADVERTENCIAS=$((ADVERTENCIAS + 1))
fi

# ─── RESUMEN FINAL ─────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo -e "${BOLD}RESUMEN${NC}"
echo "══════════════════════════════════════════════════════"

if [ $ERRORES -eq 0 ] && [ $ADVERTENCIAS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ Sistema listo. Todo verificado sin problemas.${NC}"
elif [ $ERRORES -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}⚠ Sistema listo con $ADVERTENCIAS advertencia(s).${NC}"
    echo -e "  Revisa los elementos marcados con ${YELLOW}[ WARN ]${NC} antes de usar."
else
    echo -e "${RED}${BOLD}✗ Se encontraron $ERRORES error(es) y $ADVERTENCIAS advertencia(s).${NC}"
    echo -e "  Corrige los elementos marcados con ${RED}[ FAIL ]${NC} antes de continuar."
fi

echo ""

if [ $ERRORES -eq 0 ]; then
    echo -e "Para iniciar el IDS ejecuta:"
    echo -e "  ${GREEN}${BOLD}./iniciar.sh${NC}"
    echo ""
    echo -e "Para simular primera ejecución ejecuta:"
    echo -e "  ${YELLOW}${BOLD}./reset.sh${NC}"
fi

echo "══════════════════════════════════════════════════════"

chmod +x /home/kali/IDS/iniciar.sh 2>/dev/null
chmod +x /home/kali/IDS/reset.sh 2>/dev/null
chmod +x /home/kali/IDS/setup.sh 2>/dev/null
chmod +x /home/kali/IDS/detener.sh 2>/dev/null

exit $ERRORES
