"""ids.main(): las puertas de arranque del motor.

Root, lock único, consentimiento previo y configuración válida: cada fallo
debe terminar con sys.exit(1) y mensaje claro, nunca con traceback.
"""

import fcntl
import os

import pytest
import scapy.all as scapy_all

import ids


@pytest.fixture
def estado_tmp(monkeypatch, tmp_path):
    """Centinelas y lock únicos por prueba (flock persiste por fd abierto)."""
    for attr, nombre in (
        ("_INIT_FILE", "init"),
        ("_LOCK_FILE", "lock"),
        ("_STOP_FILE", "stop"),
    ):
        monkeypatch.setattr(ids, attr, tmp_path / f".ids_{nombre}")
    monkeypatch.setattr(ids.config, "STATE_DIR", tmp_path)
    return tmp_path


def test_main_sin_root_sale_1(monkeypatch, capsys, estado_tmp):
    monkeypatch.setattr(ids.os, "geteuid", lambda: 501)

    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 1
    assert "root" in capsys.readouterr().err


def test_main_lock_ocupado_sale_1(monkeypatch, capsys, estado_tmp):
    ruta_lock = str(estado_tmp / ".ids_lock")
    fd = os.open(ruta_lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(SystemExit) as exc:
            ids.main()
        assert exc.value.code == 1
        assert "ya esta en ejecucion" in capsys.readouterr().err
    finally:
        os.close(fd)


def test_main_sin_inicializar_sale_1(monkeypatch, capsys, estado_tmp):
    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 1
    assert "politica de privacidad" in capsys.readouterr().err


def test_main_config_invalida_sale_1(monkeypatch, capsys, estado_tmp):
    (estado_tmp / ".ids_init").write_text("ok", encoding="utf-8")

    def _rechaza():
        raise EnvironmentError("Faltan las siguientes variables: SMTP_HOST")

    monkeypatch.setattr(ids.config, "validar_config", _rechaza)

    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 1
    assert "SMTP_HOST" in capsys.readouterr().err


def _motor_listo(monkeypatch, estado_tmp):
    (estado_tmp / ".ids_init").write_text("ok", encoding="utf-8")
    monkeypatch.setattr(ids.config, "validar_config", lambda: None)
    monkeypatch.setattr(ids, "descargar_todos_los_feeds", lambda: None)


def test_main_flujo_completo_hasta_detencion(monkeypatch, caplog, estado_tmp):
    _motor_listo(monkeypatch, estado_tmp)

    def _sniff(**kwargs):
        (estado_tmp / ".ids_stop").write_text("x", encoding="utf-8")

    monkeypatch.setattr(scapy_all, "sniff", _sniff)

    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 0
    assert "Senal de detencion recibida" in caplog.text


def test_main_ctrl_c_finaliza_con_0(monkeypatch, caplog, estado_tmp):
    _motor_listo(monkeypatch, estado_tmp)
    monkeypatch.setattr(
        scapy_all, "sniff", lambda **kwargs: (_ for _ in ()).throw(KeyboardInterrupt())
    )

    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 0
    assert "Captura detenida por el operador" in caplog.text


def test_main_error_fatal_de_captura_sale_1(monkeypatch, caplog, estado_tmp):
    _motor_listo(monkeypatch, estado_tmp)
    monkeypatch.setattr(
        scapy_all, "sniff", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    with pytest.raises(SystemExit) as exc:
        ids.main()

    assert exc.value.code == 1
    assert "Error fatal" in caplog.text
