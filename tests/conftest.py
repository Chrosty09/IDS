# Arranque de pruebas: hace que `import config` funcione sin un .env real y
# aísla todo el estado escribible en un directorio temporal.
#
# config.py sale con sys.exit(1) al importarse si no existe .env/.env.enc, y
# todos los módulos del proyecto importan config; por eso este archivo crea un
# .env dummy ANTES de que pytest importe cualquier módulo del proyecto.
import os
import shutil
import tempfile
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent

_ENV_FILE = _BASE / ".env"
CREAMOS_ENV = not _ENV_FILE.exists()
if CREAMOS_ENV:
    _ENV_FILE.write_text(
        "SMTP_HOST=smtp.test.local\n"
        "SMTP_USER=test@example.com\n"
        "SMTP_PASSWORD=test-pass\n"
        "ADMIN_EMAIL=admin@example.com\n"
        "NETWORK_INTERFACE=eth0\n",
        encoding="utf-8",
    )
    _ENV_FILE.chmod(0o600)

# Estado aislado de la sesión: WHITELIST_FILE, LOG_FILE, SITE_LOG_FILE y los
# centinelas apuntan aquí, nunca al árbol del repositorio.
_STATE_TMP = Path(tempfile.mkdtemp(prefix="ids-tests-"))
os.environ["IDS_STATE_DIR"] = str(_STATE_TMP)

# Modo local de fábrica: las pruebas que ejercen el camino no-local cambian
# config.MODO_LOCAL por prueba con monkeypatch.
os.environ["IDS_MODO_LOCAL"] = "1"


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_STATE_TMP, ignore_errors=True)
    if CREAMOS_ENV:
        _ENV_FILE.unlink(missing_ok=True)
