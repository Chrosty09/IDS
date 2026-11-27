"""Entorno desechable para importar la aplicación en las pruebas.

`config` termina el proceso si no hay `.env` ni `.env.enc`. Aquí se crea un
`.env` de placeholders (solo si el repo no tenía uno) y se fijan variables
de entorno antes de cualquier import. Esos valores pisan lo que hubiera en
un `.env` local porque `load_dotenv` no sobrescribe el entorno.

No hay credenciales reales, red, Supabase ni interfaz gráfica.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
_ENV_FILE = RAIZ / ".env"
_CREADO_POR_TESTS = False
_ESTADO = Path(tempfile.mkdtemp(prefix="ids-ci-estado-"))

os.environ["IDS_STATE_DIR"] = str(_ESTADO)
os.environ["IDS_MODO_LOCAL"] = "1"
os.environ["IDS_GROUP"] = ""
os.environ["SMTP_HOST"] = "smtp.example.invalid"
os.environ["SMTP_PORT"] = "465"
os.environ["SMTP_USER"] = "ci@example.invalid"
os.environ["SMTP_PASSWORD"] = "ci-placeholder"
os.environ["ADMIN_EMAIL"] = "admin@example.invalid"
os.environ["NETWORK_INTERFACE"] = "lo"
os.environ["ORG_NAME"] = "CI"
# Cadena vacía: load_dotenv no la sustituye, así que un .env local con URLs
# o una API key no llega a estas pruebas.
os.environ["NETLIFY_INGEST_URL"] = ""
os.environ["NETLIFY_BASE_URL"] = ""
os.environ["IDS_API_KEY"] = ""

if not _ENV_FILE.is_file():
    _ENV_FILE.write_text(
        "\n".join(
            [
                "# Generado por tests/conftest.py. Placeholders, no son secretos.",
                "SMTP_HOST=smtp.example.invalid",
                "SMTP_PORT=465",
                "SMTP_USER=ci@example.invalid",
                "SMTP_PASSWORD=ci-placeholder",
                "ADMIN_EMAIL=admin@example.invalid",
                "NETWORK_INTERFACE=lo",
                "ORG_NAME=CI",
                "IDS_MODO_LOCAL=1",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _ENV_FILE.chmod(0o600)
    _CREADO_POR_TESTS = True


def pytest_sessionfinish(session, exitstatus):
    if _CREADO_POR_TESTS and _ENV_FILE.is_file():
        _ENV_FILE.unlink()
    shutil.rmtree(_ESTADO, ignore_errors=True)
