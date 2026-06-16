# IDS Institucional — logger — GNU/GPL v3

import logging
import sys

import config


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
        config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler_archivo = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
        handler_archivo.setLevel(logging.DEBUG)
        handler_archivo.setFormatter(formato)
        logger.addHandler(handler_archivo)

    return logger
