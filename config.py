# IDS Institucional — config — GNU/GPL v3

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# ── rutas base ──

BASE_DIR = Path(__file__).resolve().parent

_ENV_FILE = BASE_DIR / ".env"
_ENC_FILE = BASE_DIR / ".env.enc"

# ── carga ──

if _ENV_FILE.is_file():
    from dotenv import load_dotenv

    load_dotenv(_ENV_FILE)

elif _ENC_FILE.is_file():
    from utils.env_openssl import cargar_env_cifrado, verificar_openssl_disponible

    if not verificar_openssl_disponible():
        print(
            "[ERROR] Se encontró .env.enc pero OpenSSL no está instalado.\n"
            "        Instálalo con: sudo apt install openssl\n"
            "        O crea un archivo .env con las credenciales para desarrollo.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        cargar_env_cifrado(str(_ENC_FILE))
    except (FileNotFoundError, EnvironmentError, ValueError) as exc:
        print(
            f"[ERROR] No se pudo cargar la configuración cifrada: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

else:
    print(
        "[ERROR] No se encontró archivo de configuración.\n"
        "        Crea un archivo .env con tus credenciales (ver .env.example),\n"
        "        o cifra uno existente con: ./cifrar_env.sh",
        file=sys.stderr,
    )
    sys.exit(1)

# ── smtp ──

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")

# ── red ──

NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")

# ── organización ──

ORG_NAME = os.getenv("ORG_NAME", "Institución")

# ── netlify ──

NETLIFY_INGEST_URL = os.getenv("NETLIFY_INGEST_URL", "")
IDS_API_KEY = os.getenv("IDS_API_KEY", "")

# REF: CF-002
if NETLIFY_INGEST_URL:
    _parsed = urlparse(NETLIFY_INGEST_URL)
    NETLIFY_BASE_URL = f"{_parsed.scheme}://{_parsed.netloc}"
else:
    NETLIFY_BASE_URL = os.getenv("NETLIFY_BASE_URL", "")

NETLIFY_REVOCAR_URL = (
    f"{NETLIFY_BASE_URL}/api/revocar-datos" if NETLIFY_BASE_URL else ""
)

# ── modo ──


MODO_LOCAL = os.getenv("IDS_MODO_LOCAL", "0") == "1"

# ── rutas internas ──

WHITELIST_FILE = BASE_DIR / "whitelist.txt"
BLACKLIST_FILE = BASE_DIR / "blacklist" / "feodo_blacklist.csv"
LOG_FILE = BASE_DIR / "logs" / "bitacora.log"
SITE_LOG_FILE = BASE_DIR / "logs" / "sitios_visitados.log"


# ── validación ──


def validar_config() -> None:
    """REF: CF-004"""
    requeridas = {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_USER": SMTP_USER,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "ADMIN_EMAIL": ADMIN_EMAIL,
        "NETWORK_INTERFACE": NETWORK_INTERFACE,
    }
    faltantes = [clave for clave, valor in requeridas.items() if not valor]
    if faltantes:
        raise EnvironmentError(
            f"Faltan las siguientes variables en el archivo de configuración: "
            f"{', '.join(faltantes)}\n"
            f"Consulta el archivo .env.example para la estructura correcta."
        )
