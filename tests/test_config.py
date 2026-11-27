"""config: validación de configuración al arranque del motor.

Un .env incompleto no debe dejar arrancar el motor a medias (sin admin de
correo, sin interfaz de captura): validar_config() es el último control.
"""

import pytest

import config


def _completa(monkeypatch):
    valores = {
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_USER": "user@gmail.com",
        "SMTP_PASSWORD": "app-pass",
        "ADMIN_EMAIL": "admin@inst.edu",
        "NETWORK_INTERFACE": "eth0",
    }
    for clave, valor in valores.items():
        monkeypatch.setattr(config, clave, valor)
    return valores


def test_validar_config_acepta_configuracion_completa(monkeypatch):
    _completa(monkeypatch)
    config.validar_config()  # no debe lanzar


def test_validar_config_reporta_todas_las_faltantes(monkeypatch):
    _completa(monkeypatch)
    for clave in ("SMTP_HOST", "SMTP_PASSWORD", "NETWORK_INTERFACE"):
        monkeypatch.setattr(config, clave, "")

    with pytest.raises(EnvironmentError) as exc:
        config.validar_config()

    mensaje = str(exc.value)
    assert "SMTP_HOST" in mensaje
    assert "SMTP_PASSWORD" in mensaje
    assert "NETWORK_INTERFACE" in mensaje
    assert "SMTP_USER" not in mensaje  # la que quedó puesta no se lista
