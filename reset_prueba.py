"""
reset_prueba.py - Simula una primera ejecucion del IDS eliminando los archivos
de estado persistente. Util para pruebas del flujo de consentimiento.
No requiere sudo.

IDS Institucional - Licencia GNU/GPL v3
"""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import config  # noqa: E402
from utils import securefs  # noqa: E402


def main() -> None:
    eliminados = []
    no_encontrados = []

    # 1. Eliminar archivos de estado fijos (viven en STATE_DIR, REF: CF-005)
    for ruta in [config.INIT_FILE, config.CONSENT_FILE, config.LOCK_FILE, config.STOP_FILE]:
        if securefs.eliminar_seguro(ruta):
            eliminados.append(ruta.name)
        else:
            no_encontrados.append(ruta.name)

    # 2. Eliminar comprobantes de revocación (.revocacion_*.txt)
    for ruta in config.STATE_DIR.glob(".revocacion_*.txt"):
        if securefs.eliminar_seguro(ruta):
            eliminados.append(ruta.name)

    # 3. Preguntar si también se borran los logs
    respuesta = input("\n¿Deseas también borrar los logs de prueba? (s/N): ").strip()
    if respuesta.lower() == "s":
        for ruta_log in [config.LOG_FILE, config.SITE_LOG_FILE]:
            if securefs.eliminar_seguro(ruta_log):
                eliminados.append(ruta_log.name)
            else:
                no_encontrados.append(ruta_log.name)

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
    print(f"Estado verificado en: {config.STATE_DIR}")
    print("Sistema listo para prueba de primera ejecución.")
    print("Ejecuta ./iniciar.sh para arrancar el IDS.")


if __name__ == "__main__":
    main()
