"""reporter: qué llega al dashboard y cuándo (modo local / sin config).

El pipeline de reporte es la única salida hacia el panel web; el riesgo es
que un evento se pierda en silencio (payload mal construido) o que un
exceso de eventos haga crecer la memoria sin límite (cola acotada).
"""

import queue

import pytest

import config
from utils import reporter


def test_local_no_encola(monkeypatch):
    # MODO_LOCAL=1 de fábrica en la sesión: ni workers ni cola.
    monkeypatch.setattr(reporter, "_iniciar_workers", lambda: pytest.fail("no workers"))
    reporter.reportar_evento(tipo="whitelist", ip_origen="1.2.3.4")


def test_sin_url_o_api_key_no_encola(monkeypatch):
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "")
    monkeypatch.setattr(config, "IDS_API_KEY", "k")
    monkeypatch.setattr(reporter, "_iniciar_workers", lambda: pytest.fail("no workers"))
    reporter.reportar_evento(tipo="whitelist")

    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "https://x")
    monkeypatch.setattr(config, "IDS_API_KEY", "")
    reporter.reportar_evento(tipo="whitelist")


def test_encola_payload_con_dispositivo(monkeypatch):
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "https://panel.test/ingest")
    monkeypatch.setattr(config, "IDS_API_KEY", "clave")
    monkeypatch.setattr(reporter, "_iniciar_workers", lambda: None)
    cola = queue.Queue(maxsize=10)
    monkeypatch.setattr(reporter, "_cola_eventos", cola)

    reporter.reportar_evento(
        tipo="sitios",
        categoria="Phishing",
        fuente="Test",
        ip_origen="192.168.1.10",
        dominio="evil.com",
        detalles={"puerto": 80},
    )

    payload = cola.get_nowait()
    assert payload["tipo"] == "sitios"
    assert payload["dominio"] == "evil.com"
    assert payload["detalles"] == {"puerto": 80}
    assert payload["dispositivo_id"] == reporter.DISPOSITIVO_ID
    assert cola.empty()


def test_cola_llena_descarta_sin_bloquear(monkeypatch, caplog):
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "NETLIFY_INGEST_URL", "https://panel.test/ingest")
    monkeypatch.setattr(config, "IDS_API_KEY", "clave")
    monkeypatch.setattr(reporter, "_iniciar_workers", lambda: None)
    cola = queue.Queue(maxsize=1)
    cola.put_nowait({"ocupada": True})
    monkeypatch.setattr(reporter, "_cola_eventos", cola)

    reporter.reportar_evento(tipo="whitelist", ip_origen="1.2.3.4")  # no debe lanzar

    assert cola.qsize() == 1
    assert "Cola de reportes al dashboard llena" in caplog.text
