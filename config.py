# IDS Institucional — config — GNU/GPL v3

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# ── rutas base ──

BASE_DIR = Path(__file__).resolve().parent

_ENV_FILE = BASE_DIR / ".env"
_ENC_FILE = BASE_DIR / ".env.enc"
_RUNTIME_FILE = BASE_DIR / ".env.runtime"

# ── carga ──

# Indica si los secretos (.env/.env.enc) quedaron disponibles en este proceso.
# La GUI no los necesita (solo rutas), por lo que puede operar sin contraseña
# de descifrado; el motor IDS (root) sí los exige. REF: CF-006
SECRETOS_CARGADOS = False

if _ENV_FILE.is_file():
    from dotenv import load_dotenv

    load_dotenv(_ENV_FILE)
    SECRETOS_CARGADOS = True

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
        SECRETOS_CARGADOS = True
    except EnvironmentError:
        # Sin contraseña accesible en este proceso (p. ej. la GUI corría como
        # usuario y /etc/ids/env.password es root-only): la GUI solo necesita
        # rutas, que vienen de .env.runtime. Si es root, la falta de contraseña
        # sí es un error fatal: el motor no puede operar sin secretos.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            print(
                "[ERROR] No se pudo cargar la configuración cifrada: falta la\n"
                "        contraseña (IDS_ENV_PASSWORD o /etc/ids/env.password).",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            "[AVISO] Secretos cifrados no cargados en este proceso (sin\n"
            "        contraseña de descifrado). Es esperado en la GUI; el motor\n"
            "        IDS los carga como root desde /etc/ids/env.password.",
            file=sys.stderr,
        )
    except (FileNotFoundError, ValueError) as exc:
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

# Configuración de despliegue SIN secretos (IDS_STATE_DIR, IDS_GROUP),
# generada por el instalador. Se carga después del .env/.env.enc porque no
# puede modificarse un .env.enc cifrado; además permite override del .env.
if _RUNTIME_FILE.is_file():
    from dotenv import load_dotenv

    load_dotenv(_RUNTIME_FILE)

# REF: CF-007 — el .env contiene credenciales; en POSIX se advierte si grupo
# u otros pueden leerlo (solo es relevante donde los permisos existen).
if _ENV_FILE.is_file() and os.name == "posix":
    import stat as _stat

    _modo_env = _stat.S_IMODE(os.stat(_ENV_FILE).st_mode)
    if _modo_env & 0o077:
        print(
            f"[AVISO] {_ENV_FILE} es legible por grupo u otros "
            f"(permisos {_modo_env:o}) y contiene credenciales.\n"
            f"        Corrígelo con: chmod 600 {_ENV_FILE}",
            file=sys.stderr,
        )

# ── smtp ──

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")

# REF: CF-008 — un SMTP_PORT no numérico o fuera de rango antes reventaba con
# traceback al importar config; ahora falla con un mensaje claro.
_puerto_env = os.getenv("SMTP_PORT", "465")
try:
    SMTP_PORT = int(_puerto_env)
    if not 1 <= SMTP_PORT <= 65535:
        raise ValueError
except ValueError:
    print(
        f"[ERROR] SMTP_PORT debe ser un puerto válido (1-65535); "
        f"se recibió: '{_puerto_env}'.",
        file=sys.stderr,
    )
    sys.exit(1)
del _puerto_env

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


# REF: CF-007 — la API key y los datos de alertas (IPs, MACs, dominios)
# viajan a estas URLs: solo se acepta TLS. Un http:// filtraría la API key
# y los datos personales en tránsito.
def _exigir_https() -> None:
    for nombre, url in (
        ("NETLIFY_INGEST_URL", NETLIFY_INGEST_URL),
        ("NETLIFY_BASE_URL", NETLIFY_BASE_URL),
    ):
        if url and not url.lower().startswith("https://"):
            print(
                f"[ERROR] {nombre} debe usar https:// (se recibió: {url}).\n"
                f"        Por esta URL viajan la API key y datos de alertas.",
                file=sys.stderr,
            )
            sys.exit(1)


_exigir_https()

# ── modo ──


MODO_LOCAL = os.getenv("IDS_MODO_LOCAL", "0") == "1"

# ── estado en runtime ──

# REF: CF-005 — El estado escribible en tiempo de ejecución (logs con PII,
# consentimiento, whitelist, centinelas) NO debe vivir junto al código que se
# ejecuta como root: cualquier usuario con acceso de escritura al directorio
# podría alterar el comportamiento del IDS o preparar ataques de symlink.
# En producción el instalador define IDS_STATE_DIR=/var/lib/ids (root:ids,
# 2770). Sin esa variable se usa <proyecto>/runtime para desarrollo.
STATE_DIR = Path(os.getenv("IDS_STATE_DIR", "")) if os.getenv("IDS_STATE_DIR") else BASE_DIR / "runtime"

# Grupo de operadores creado por el instalador. Cuando el IDS corre como root
# los logs se marcan root:IDS_GROUP 0640 para que la GUI (miembro del grupo)
# pueda leerlos; sin grupo quedan 0600.
IDS_GROUP = os.getenv("IDS_GROUP", "")

# ── rutas internas ──

WHITELIST_FILE = STATE_DIR / "whitelist.txt"
BLACKLIST_FILE = BASE_DIR / "blacklist" / "feodo_blacklist.csv"
LOG_FILE = STATE_DIR / "bitacora.log"
SITE_LOG_FILE = STATE_DIR / "sitios_visitados.log"
CONSENT_FILE = STATE_DIR / ".ids_consent"
INIT_FILE = STATE_DIR / ".ids_initialized"
LOCK_FILE = STATE_DIR / ".ids.lock"
STOP_FILE = STATE_DIR / ".ids_stop"
WHITELIST_RELOAD_FILE = STATE_DIR / ".ids_whitelist_reload"
ARRANQUE_LOG_FILE = STATE_DIR / "ids_arranque.log"


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
