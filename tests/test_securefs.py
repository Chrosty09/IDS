"""Archivos de estado: no seguir symlinks y permisos privados."""

import os
import stat

from utils import securefs


def test_roundtrip_y_permisos_privados(tmp_path):
    ruta = tmp_path / "dato.txt"
    securefs.escribir_privado(ruta, "hola")
    securefs.escribir_privado(ruta, " mundo", append=True)

    assert securefs.leer_seguro(ruta) == "hola mundo"
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600
    assert securefs.existe_sin_seguir(ruta) is True


def test_rechaza_symlink_al_leer_y_al_borrar(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("secreto", encoding="utf-8")
    enlace = tmp_path / "enlace"
    enlace.symlink_to(real)

    assert securefs.existe_sin_seguir(enlace) is False
    assert securefs.leer_seguro(enlace) is None
    assert securefs.eliminar_seguro(enlace) is True
    assert not enlace.exists()
    assert real.read_text(encoding="utf-8") == "secreto"


def test_ausente_no_existe_y_no_se_borra(tmp_path):
    ausente = tmp_path / "no-esta.txt"
    assert securefs.existe_sin_seguir(ausente) is False
    assert securefs.leer_seguro(ausente) is None
    assert securefs.eliminar_seguro(ausente) is False


def test_crea_directorio_de_estado_restringido(tmp_path):
    destino = tmp_path / "estado" / "anidado"
    creado = securefs.crear_directorio_estado(destino)

    assert creado == destino
    assert creado.is_dir()
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        assert stat.S_IMODE(creado.stat().st_mode) == 0o700
