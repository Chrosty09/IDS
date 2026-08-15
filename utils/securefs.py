# IDS Institucional — securefs — GNU/GPL v3

"""Operaciones de archivo seguras para el estado en runtime. REF: SF-001

Todo archivo que el IDS (root) abre o crea dentro de STATE_DIR debe usar
O_NOFOLLOW: un symlink colocado previamente por un usuario sin privilegios
haría que root truncara o escribiera un archivo arbitrario del sistema
(p. ej. .ids.lock → /etc/shadow). unlink() nunca sigue symlinks, por lo que
eliminar centinelas es seguro sin flags extra.
"""

import os
from pathlib import Path

# O_NOFOLLOW no existe en todas las plataformas (p. ej. Windows). En desarrollo
# su ausencia es inofensiva: nada corre como root fuera de Linux.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _config():
    """Import perezoso de config: ids.py debe poder importar este módulo ANTES
    de cargar config para fijar IDS_MODO_LOCAL según el consentimiento."""
    import config

    return config


def _es_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def abrir_privado(ruta: Path | str, append: bool = True, modo: int = 0o600) -> int:
    """Abre (creando si falta) `ruta` para escritura con O_NOFOLLOW y permisos
    estrictos. Retorna el file descriptor. REF: SF-002"""
    flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW
    if append:
        flags |= os.O_APPEND
    fd = os.open(ruta, flags, modo)
    try:
        # Corrige también permisos débiles de un archivo preexistente.
        os.fchmod(fd, modo)
    except OSError:
        pass
    return fd


def abrir_log(ruta: Path | str) -> int:
    """Abre un archivo de log aplicando la política de permisos de logs.

    Producción (root + IDS_GROUP definido): 0640 root:grupo para que la GUI
    del operador pueda leerlos. Cualquier otro caso: 0600. REF: SF-003
    """
    fd = abrir_privado(ruta, append=True, modo=modo_log())
    ajustar_grupo_log(fd)
    return fd


def modo_log() -> int:
    """Permiso objetivo para los logs según configuración y privilegio."""
    if getattr(_config(), "IDS_GROUP", "") and _es_root():
        return 0o640
    return 0o600


def ajustar_grupo_log(fd: int) -> None:
    """Asigna el grupo de operadores al fd de un log (solo si somos root)."""
    grupo = getattr(_config(), "IDS_GROUP", "")
    if not (grupo and _es_root()):
        return
    try:
        import grp

        os.fchown(fd, -1, grp.getgrnam(grupo).gr_gid)
    except (KeyError, OSError, ImportError):
        pass


def escribir_privado(
    ruta: Path | str,
    contenido: str | bytes,
    append: bool = False,
    modo: int = 0o600,
) -> None:
    """Escribe `contenido` en `ruta` de forma segura (consentimiento,
    centinelas, comprobantes). REF: SF-002"""
    if isinstance(contenido, str):
        contenido = contenido.encode("utf-8")
    fd = abrir_privado(ruta, append=append, modo=modo)
    try:
        os.write(fd, contenido)
    finally:
        os.close(fd)


def leer_seguro(ruta: Path | str) -> str | None:
    """Lee un archivo de texto rechazando symlinks. None si no existe/no se
    puede leer de forma segura."""
    try:
        fd = os.open(ruta, os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def existe_sin_seguir(ruta: Path | str) -> bool:
    """True si `ruta` existe Y no es un symlink (lstat, no stat)."""
    try:
        return not os.path.islink(ruta) and os.path.exists(ruta)
    except OSError:
        return False


def eliminar_seguro(ruta: Path | str) -> bool:
    """Elimina `ruta` si existe. unlink nunca sigue symlinks, por lo que solo
    puede borrar el enlace, nunca el archivo apuntado. True si eliminó algo."""
    try:
        os.unlink(ruta)
        return True
    except OSError:
        return False


def crear_directorio_estado(ruta: Path | str | None = None) -> Path:
    """Crea STATE_DIR si no existe con permisos correctos; nunca toca un
    directorio ya existente (el instalador lo crea root:grupo 2770)."""
    ruta = Path(ruta) if ruta else _config().STATE_DIR
    if ruta.exists():
        return ruta
    ruta.mkdir(parents=True)
    grupo = getattr(_config(), "IDS_GROUP", "")
    try:
        if grupo and _es_root():
            import grp

            os.chown(ruta, 0, grp.getgrnam(grupo).gr_gid)
            os.chmod(ruta, 0o2770)
        else:
            os.chmod(ruta, 0o700)
    except OSError:
        pass
    return ruta
