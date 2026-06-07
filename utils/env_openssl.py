# IDS Institucional — env_openssl — GNU/GPL v3

import os
import shutil
import subprocess


def verificar_openssl_disponible() -> bool:
    """Retorna True si el ejecutable 'openssl' está en el PATH del sistema."""
    return shutil.which("openssl") is not None


def cargar_env_cifrado(ruta: str) -> None:
    """REF: EO-001"""
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"Archivo cifrado no encontrado: {ruta}")

    password = os.environ.get("IDS_ENV_PASSWORD")
    if not password:
        raise EnvironmentError(
            "La variable IDS_ENV_PASSWORD no está definida.\n"
            "Defínela antes de iniciar el IDS:\n"
            "  export IDS_ENV_PASSWORD='tu_contraseña'\n"
            "O agrégala a /etc/environment para que persista entre reinicios."
        )

    resultado = subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-in",
            ruta,
            "-pass",
            "env:IDS_ENV_PASSWORD",
        ],
        capture_output=True,
        text=True,
    )

    if resultado.returncode != 0:
        raise ValueError(
            f"OpenSSL no pudo descifrar {ruta}.\n"
            f"Detalle: {resultado.stderr.strip()}\n"
            "Verifica que IDS_ENV_PASSWORD sea la contraseña correcta."
        )

    _parsear_y_cargar(resultado.stdout)

    # REF: EO-002
    try:
        del os.environ["IDS_ENV_PASSWORD"]
    except KeyError:
        pass  # No estaba en el entorno (caso inusual)


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
