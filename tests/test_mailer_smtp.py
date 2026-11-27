"""mailer: los dos caminos SMTP (SMTPS 465 y STARTTLS 587) y sus fallos.

El envío de correo usa SMTP_USER/SMTP_PASSWORD; los modos de fallo (auth,
conexión) deben devolver False sin lanzar. También el disparo del resumen
immediato al cruzar el umbral de 10 alertas.
"""

import smtplib

import pytest

import config
from utils import mailer


class _FakeSMTPS:
    def __init__(self, host, port, timeout=None, context=None):
        self.host = host
        self.port = port
        self.context = context
        self.llamadas = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self):
        self.llamadas.append("ehlo")

    def starttls(self, context=None):
        self.llamadas.append("starttls")

    def login(self, user, password):
        self.llamadas.append(("login", user, password))

    def sendmail(self, desde, hacia, mensaje):
        self.llamadas.append(("sendmail", desde, hacia, mensaje))


class _FakeFailAuth(_FakeSMTPS):
    def login(self, user, password):
        raise smtplib.SMTPAuthenticationError(535, b"authentication failed")


class _FakeFailNet(_FakeSMTPS):
    def login(self, user, password):
        raise OSError("Connection refused")


def _smtps_falso(falso):
    """Fabrica el SMTP_SSL verificado: sin contexto TLS (MITM) no debe llamarse."""
    def crear(host, port, timeout=None, context=None):
        assert context is not None, "debe usarse el contexto TLS verificado"
        return falso

    return crear


@pytest.fixture
def conf(monkeypatch):
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(config, "SMTP_USER", "user@test")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "pw")
    monkeypatch.setattr(config, "ADMIN_EMAIL", "admin@test")
    return config


def test_enviar_sincrono_smtps_465(monkeypatch, conf):
    falso = _FakeSMTPS(None, None)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", _smtps_falso(falso))
    monkeypatch.setattr(config, "SMTP_PORT", 465)

    assert mailer.enviar_sincrono("Asunto", "<html>ok</html>") is True

    assert ("login", "user@test", "pw") in falso.llamadas
    _, desde, hacia, mensaje = falso.llamadas[-1]
    assert desde == "user@test"
    assert hacia == "admin@test"
    assert "Asunto" in mensaje


def test_enviar_sincrono_starttls_587(monkeypatch, conf):
    falso = _FakeSMTPS(None, None)
    monkeypatch.setattr(mailer.smtplib, "SMTP", lambda host, port, timeout=None: falso)
    monkeypatch.setattr(config, "SMTP_PORT", 587)

    assert mailer.enviar_sincrono("Asunto", "<html>ok</html>") is True

    assert falso.llamadas.count("ehlo") == 2
    assert "starttls" in falso.llamadas
    assert ("login", "user@test", "pw") in falso.llamadas


def test_enviar_sincrono_falla_auth_devuelve_false(monkeypatch, conf):
    falso = _FakeFailAuth(None, None)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", _smtps_falso(falso))
    monkeypatch.setattr(config, "SMTP_PORT", 465)

    assert mailer.enviar_sincrono("Asunto", "<html>ok</html>") is False


def test_enviar_sincrono_falla_red_devuelve_false(monkeypatch, conf):
    falso = _FakeFailNet(None, None)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", _smtps_falso(falso))
    monkeypatch.setattr(config, "SMTP_PORT", 465)

    assert mailer.enviar_sincrono("Asunto", "<html>ok</html>") is False


def test_enviar_sincrono_destinatario_explicito(monkeypatch, conf):
    falso = _FakeSMTPS(None, None)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", _smtps_falso(falso))
    monkeypatch.setattr(config, "SMTP_PORT", 465)

    mailer.enviar_sincrono("Asunto", "<html>ok</html>", destinatario="otro@test")

    _, _, hacia, _ = falso.llamadas[-1]
    assert hacia == "otro@test"


# ── resumen por lotes ──


class _FakeTimer:
    def __init__(self, intervalo, callback, daemon=None):
        self.intervalo = intervalo
        self.callback = callback
        self.iniciado = False

    def start(self):
        self.iniciado = True

    def cancel(self):
        self.iniciado = False

    def is_alive(self):
        return self.iniciado


class _FakeThreadSincronico:
    def __init__(self, target=None, name=None, daemon=False):
        self.target = target

    def start(self):
        self.target()


def _preparar_envio(monkeypatch):
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    enviados = []
    monkeypatch.setattr(
        mailer, "enviar_sincrono", lambda asunto, cuerpo_html: enviados.append(asunto) or True
    )
    timers = []
    monkeypatch.setattr(
        mailer.threading, "Timer", lambda intervalo, cb, daemon=None: timers.append(
            _FakeTimer(intervalo, cb, daemon)
        )
        or timers[-1]
    )
    monkeypatch.setattr(mailer.threading, "Thread", _FakeThreadSincronico)
    return enviados, timers


def test_encolar_resumen_periodico_arma_timer(monkeypatch):
    enviados, timers = _preparar_envio(monkeypatch)

    mailer.encolar_alerta_resumen("Dispositivo no autorizado", {"IP": "1.2.3.4"})

    assert len(timers) == 1
    assert timers[0].intervalo == mailer._INTERVALO_RESUMEN_SEGUNDOS
    assert enviados == []
    mailer._cola_resumen.clear()
    mailer._timer_resumen = None


def test_encolar_resumen_umbral_dispara_inmediato(monkeypatch):
    enviados, timers = _preparar_envio(monkeypatch)

    for i in range(10):
        mailer.encolar_alerta_resumen(
            "Dispositivo no autorizado", {"IP": f"10.0.0.{i}"}
        )

    assert len(enviados) == 1
    assert "Resumen inmediato" in enviados[0]
    assert "10" in enviados[0]
    mailer._cola_resumen.clear()
    mailer._timer_resumen = None
