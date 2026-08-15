# IDS Institucional — logger — GNU/GPL v3

import logging
import os
import sys

import config
from utils import securefs


class FileHandlerPrivado(logging.FileHandler):
    """FileHandler que crea y reabre el log con O_NOFOLLOW y permisos
    estrictos (0600, o 0640 root:IDS_GROUP en producción).

    Evita que la bitácora —que contiene IPs, MACs y hábitos de navegación—
    quede legible por todo el sistema, y que un symlink previamente colocado
    en STATE_DIR haga que root escriba en un archivo arbitrario. REF: LG-002
    """

    def _open(self):
        fd = securefs.abrir_log(self.baseFilename)
        return os.fdopen(fd, "a", encoding=self.encoding)


def obtener_logger(nombre: str) -> logging.Logger:
    """REF: LG-001"""
    logger = logging.getLogger(nombre)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formato = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setLevel(logging.INFO)
    handler_consola.setFormatter(formato)
    logger.addHandler(handler_consola)

    # En modo local no se escribe nada a disco: las alertas van solo a stdout,
    # que la GUI lee directamente del subproceso.
    if not config.MODO_LOCAL:
        securefs.crear_directorio_estado(config.LOG_FILE.parent)
        handler_archivo = FileHandlerPrivado(config.LOG_FILE, encoding="utf-8")
        handler_archivo.setLevel(logging.DEBUG)
        handler_archivo.setFormatter(formato)
        logger.addHandler(handler_archivo)

    return logger
