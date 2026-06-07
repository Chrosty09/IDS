"""
reset_prueba.py - Simula una primera ejecucion del IDS eliminando los archivos
de estado persistente. Util para pruebas del flujo de consentimiento.
No requiere sudo.

IDS Institucional - Licencia GNU/GPL v3
"""

import glob
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

ARCHIVOS_ESTADO = [
    BASE_DIR / ".ids_initialized",
    BASE_DIR / ".ids_consent",
]


def _eliminar(ruta: Path) -> bool:
    """Elimina un archivo si existe. Retorna True si lo eliminó."""
    if ruta.exists():
        os.remove(ruta)
        return True
    return False


def main() -> None:
    eliminados = []
    no_encontrados = []

    # 1. Eliminar archivos de estado fijos
    for ruta in ARCHIVOS_ESTADO:
        if _eliminar(ruta):
            eliminados.append(ruta.name)
        else:
            no_encontrados.append(ruta.name)

    # 2. Eliminar comprobantes de revocación (.revocacion_*.txt)
    patron = str(BASE_DIR / ".revocacion_*.txt")
    for ruta_str in glob.glob(patron):
        ruta = Path(ruta_str)
        os.remove(ruta)
        eliminados.append(ruta.name)

    # 3. Preguntar si también se borran los logs
    respuesta = input("\n¿Deseas también borrar los logs de prueba? (s/N): ").strip()
    if respuesta.lower() == "s":
        for nombre, clave in [
            ("bitacora.log",        "LOG_FILE"),
            ("sitios_visitados.log","SITE_LOG_FILE"),
        ]:
            ruta_log = BASE_DIR / "logs" / nombre
            if _eliminar(ruta_log):
                eliminados.append(f"logs/{nombre}")
            else:
                no_encontrados.append(f"logs/{nombre}")

    # 4. Resumen
    print()
    if eliminados:
        print("Archivos eliminados:")
        for nombre in eliminados:
            print(f"  ✓ {nombre}")
    if no_encontrados:
        print("No encontrados (ya no existían):")
        for nombre in no_encontrados:
            print(f"  - {nombre}")

    print()
    print("Sistema listo para prueba de primera ejecución.")
    print("Ejecuta ./iniciar.sh para arrancar el IDS.")


if __name__ == "__main__":
    main()
