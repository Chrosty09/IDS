"""Configuración y parseo de .env, sin red ni secretos reales."""

import os

import pytest

import config
from utils.env_openssl import _parsear_y_cargar


def test_validar_config_acepta_el_entorno_de_prueba():
    config.validar_config()


def test_validar_config_reclama_variables_vacias(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_EMAIL", "")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "")

    with pytest.raises(EnvironmentError) as exc:
        config.validar_config()

    mensaje = str(exc.value)
    assert "ADMIN_EMAIL" in mensaje
    assert "SMTP_PASSWORD" in mensaje


def test_exige_https_acepta_vacio_y_https(monkeypatch):
    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "")
    monkeypatch.setattr(config, "NETLIFY_BASE_URL", "")
    config._exigir_https()

    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "https://panel.example/ingest")
    monkeypatch.setattr(config, "NETLIFY_BASE_URL", "https://panel.example")
    config._exigir_https()


def test_exige_https_rechaza_http(monkeypatch):
    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "http://panel.example/ingest")
    monkeypatch.setattr(config, "NETLIFY_BASE_URL", "")

    with pytest.raises(SystemExit):
        config._exigir_https()


def test_parsear_env_ignora_comentarios_y_no_pisa(monkeypatch):
    monkeypatch.delenv("IDS_CI_EJEMPLO", raising=False)
    _parsear_y_cargar(
        "\n".join(
            [
                "# comentario",
                "",
                'export IDS_CI_EJEMPLO="valor con espacios"',
                "SIN_IGUAL",
                "=sin_clave",
            ]
        )
    )
    assert os.environ["IDS_CI_EJEMPLO"] == "valor con espacios"

    _parsear_y_cargar("IDS_CI_EJEMPLO='otro'")
    assert os.environ["IDS_CI_EJEMPLO"] == "valor con espacios"
