# IDS Institucional — env_openssl — GNU/GPL v3

import os
import shutil
import stat
import subprocess
import sys

# REF: EO-003 — OWASP recomienda >= 600_000 iteraciones para PBKDF2-SHA256.
# El conteo NO se guarda dentro del archivo cifrado: cifrar y descifrar deben
# usar exactamente el mismo valor. Los archivos legacy cifrados con el default
# de OpenSSL (10 000) se aceptan con una advertencia de migración.
_ITERACIONES = 600000

# REF: EO-004 — contraseña disponible únicamente para root, nunca en
# /etc/environment (ese archivo es legible por todos los usuarios del equipo).
_ARCHIVO_PASSWORD = "/etc/ids/env.password"


def verificar_openssl_disponible() -> bool:
    """Retorna True si el ejecutable 'openssl' está en el PATH del sistema."""
    return shutil.which("openssl") is not None


def _es_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _leer_password_archivo() -> str:
    """Lee la contraseña desde el archivo root-only /etc/ids/env.password.

    Se valida estrictamente que sea root:root 0600: un archivo con permisos o
    propietario distintos indica manipulación y se rechaza. REF: EO-004
    """
    info = os.stat(_ARCHIVO_PASSWORD)
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0:
        raise ValueError(
            f"{_ARCHIVO_PASSWORD} debe ser root:root con permisos 600 "
            f"(actual: modo {stat.S_IMODE(info.st_mode):o}, uid {info.st_uid}).\n"
            "Corrígelo con:\n"
            f"  sudo chown root:root {_ARCHIVO_PASSWORD} && "
            f"sudo chmod 600 {_ARCHIVO_PASSWORD}"
        )
    with open(_ARCHIVO_PASSWORD, encoding="utf-8") as f:
        return f.read().strip()


def _obtener_password() -> str:
    """Orden de resolución: variable de entorno (desarrollo/CI) → archivo
    root-only (producción)."""
    password = os.environ.get("IDS_ENV_PASSWORD", "")
    if password:
        return password
    if _es_root() and os.path.exists(_ARCHIVO_PASSWORD):
        return _leer_password_archivo()
    return ""


def _descifrar(ruta: str, password: str, iteraciones: int | None) -> str | None:
    """Ejecuta openssl para descifrar. Retorna el texto plano o None si el
    descifrado falló (contraseña o iteraciones incorrectas).

    La contraseña viaja por stdin: nunca aparece en argv (visible vía
    /proc/*/cmdline) ni en el entorno del subproceso.
    """
    args = ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2"]
    if iteraciones:
        args += ["-iter", str(iteraciones)]
    args += ["-in", ruta, "-pass", "stdin"]

    env_limpio = dict(os.environ)
    env_limpio.pop("IDS_ENV_PASSWORD", None)

    try:
        # Captura en bytes: con contraseña incorrecta openssl puede emitir
        # datos parcialmente descifrados (binarios) antes de fallar.
        resultado = subprocess.run(
            args,
            input=(password + "\n").encode("utf-8"),
            capture_output=True,
            env=env_limpio,
        )
    except OSError as e:
        raise ValueError(f"No se pudo ejecutar openssl: {e}") from e

    if resultado.returncode != 0:
        return None
    return resultado.stdout.decode("utf-8", errors="replace")


def cargar_env_cifrado(ruta: str) -> None:
    """REF: EO-001"""
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"Archivo cifrado no encontrado: {ruta}")

    password = _obtener_password()
    if not password:
        raise EnvironmentError(
            "No se pudo obtener la contraseña de descifrado.\n"
            "Opciones:\n"
            "  - Producción: guardarla en /etc/ids/env.password (root:root 600);\n"
            "    ./cifrar_env.sh e install.sh lo hacen automáticamente.\n"
            "  - Desarrollo: exporta IDS_ENV_PASSWORD antes de iniciar el IDS."
        )

    # REF: EO-003 — primero con las iteraciones actuales; si el archivo fue
    # cifrado por una versión anterior (default 10 000), reintentar en modo
    # legacy y advertir la migración.
    texto = _descifrar(ruta, password, _ITERACIONES)
    if texto is None:
        texto = _descifrar(ruta, password, None)
        if texto is not None:
            print(
                "[WARN] .env.enc usa PBKDF2 con 10 000 iteraciones (formato "
                "anterior). Recifra con iteraciones altas: ./cifrar_env.sh",
                file=sys.stderr,
            )

    if texto is None:
        raise ValueError(
            f"OpenSSL no pudo descifrar {ruta}.\n"
            "Verifica que la contraseña (y las iteraciones) sean correctas."
        )

    _parsear_y_cargar(texto)

    # REF: EO-002 — si la contraseña vino del entorno, sacarla de él cuanto antes
    os.environ.pop("IDS_ENV_PASSWORD", None)


def _parsear_y_cargar(contenido: str) -> None:
    """Parsea el texto plano de un .env y carga cada variable en os.environ."""
    for linea in contenido.splitlines():
        linea = linea.strip()

        if not linea or linea.startswith("#"):
            continue

        if linea.startswith("export "):
            linea = linea[7:].lstrip()

        if "=" not in linea:
            continue

        clave, _, valor = linea.partition("=")
        clave = clave.strip()

        if not clave:
            continue

        valor = valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in ('"', "'"):
            valor = valor[1:-1]

        os.environ.setdefault(clave, valor)
