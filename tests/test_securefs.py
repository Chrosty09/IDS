"""securefs: protecciones O_NOFOLLOW y de permisos del estado en runtime.

Estas son las operaciones que el motor (root) ejecuta sobre STATE_DIR, un
directorio con escritura de un usuario no privilegiado: un symlink colocado
allí NO debe poder hacer que root trunque/sobrescriba un archivo arbitrario.
"""

import os
import stat

import pytest

from utils import securefs


def test_existe_sin_seguir_rechaza_symlink(tmp_path):
    objetivo = tmp_path / "objetivo.txt"
    objetivo.write_text("secreto")
    enlace = tmp_path / "enlace.txt"
    enlace.symlink_to(objetivo)

    assert securefs.existe_sin_seguir(objetivo)
    assert not securefs.existe_sin_seguir(enlace)
    assert not securefs.existe_sin_seguir(tmp_path / "inexistente")


def test_leer_seguro_rechaza_symlink(tmp_path):
    objetivo = tmp_path / "objetivo.txt"
    objetivo.write_text("secreto")
    enlace = tmp_path / "enlace.txt"
    enlace.symlink_to(objetivo)

    assert securefs.leer_seguro(objetivo) == "secreto"
    assert securefs.leer_seguro(enlace) is None


def test_escribir_privado_no_sigue_symlinks(tmp_path):
    objetivo = tmp_path / "objetivo.txt"
    objetivo.write_text("secreto")
    enlace = tmp_path / "enlace.txt"
    enlace.symlink_to(objetivo)

    with pytest.raises(OSError):
        securefs.escribir_privado(enlace, "pwned")

    assert objetivo.read_text() == "secreto"


def test_abrir_privado_no_sigue_symlinks(tmp_path):
    objetivo = tmp_path / "objetivo.txt"
    objetivo.write_text("secreto")
    enlace = tmp_path / "enlace.txt"
    enlace.symlink_to(objetivo)

    with pytest.raises(OSError):
        os.close(securefs.abrir_privado(enlace))

    assert objetivo.read_text() == "secreto"


def test_eliminar_seguro_borra_solo_el_enlace(tmp_path):
    objetivo = tmp_path / "objetivo.txt"
    objetivo.write_text("secreto")
    enlace = tmp_path / "enlace.txt"
    enlace.symlink_to(objetivo)

    assert securefs.eliminar_seguro(enlace)
    assert not enlace.exists()
    assert objetivo.read_text() == "secreto"


def test_escribir_privado_fija_permisos_estrictos(tmp_path):
    ruta = tmp_path / "estado.txt"
    ruta.write_text("basura")
    ruta.chmod(0o644)

    securefs.escribir_privado(ruta, "contenido")

    assert ruta.read_text() == "contenido"
    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600


def test_abrir_privado_corrige_permisos_debiles(tmp_path):
    ruta = tmp_path / "estado.txt"
    ruta.write_text("x")
    ruta.chmod(0o666)

    fd = securefs.abrir_privado(ruta, append=True, modo=0o600)
    os.close(fd)

    assert stat.S_IMODE(ruta.stat().st_mode) == 0o600


def test_modo_log_segun_privilegio_y_grupo(monkeypatch):
    import config

    monkeypatch.setattr(config, "IDS_GROUP", "")
    assert securefs.modo_log() == 0o600

    monkeypatch.setattr(config, "IDS_GROUP", "ids")
    monkeypatch.setattr(securefs, "_es_root", lambda: True)
    assert securefs.modo_log() == 0o640

    monkeypatch.setattr(securefs, "_es_root", lambda: False)
    assert securefs.modo_log() == 0o600


def test_crear_directorio_estado_permisos_y_no_retoque(tmp_path):
    destino = tmp_path / "state"
    creado = securefs.crear_directorio_estado(destino)
    assert creado == destino
    assert destino.is_dir()
    assert stat.S_IMODE(destino.stat().st_mode) == 0o700

    # Un directorio ya existente no se retoca (el instalador crea 2770).
    destino.chmod(0o750)
    securefs.crear_directorio_estado(destino)
    assert stat.S_IMODE(destino.stat().st_mode) == 0o750
