"""modulo_forense: gate de IPs públicas y flujo RDAP → ipinfo → correo.

La investigación se lanza en segundo plano con la IP capturada; el gate de
privadas/reservadas evita consultas RDAP inútiles y el manejo de errores
decide entre fallback y correo de "sin fuente".
"""

import pytest

import config
from modulos import modulo_forense as forense

_FAKE_RDAP = {
    "asn_description": "GOOGLE, US",
    "asn_country_code": "US",
    "network": {"name": "GOOGLE"},
    "objects": {
        "ABUSE1": {"contact": {"email": [{"value": "abuse@google.com"}, {"value": ""}]}}
    },
}


class _FakeIPWhois:
    def __init__(self, ip):
        self.ip = ip

    def lookup_rdap(self, depth=1):
        return _FAKE_RDAP


@pytest.fixture
def no_local(monkeypatch):
    monkeypatch.setattr(config, "MODO_LOCAL", False)


@pytest.fixture
def enviados(monkeypatch):
    lista = []
    monkeypatch.setattr(
        forense,
        "enviar_alerta",
        lambda asunto, cuerpo_html, destinatario=None: lista.append(asunto) or True,
    )
    return lista


def test_lookup_rdap_extrae_org_pais_y_contactos(monkeypatch):
    monkeypatch.setattr(forense, "IPWhois", _FakeIPWhois)

    datos = forense._lookup_rdap("8.8.8.8")

    assert datos["org"] == "GOOGLE, US"
    assert datos["pais"] == "US"
    assert datos["red"] == "GOOGLE"
    assert datos["emails_abuso"] == "abuse@google.com"
    assert datos["fuente"] == "RDAP (ipwhois)"


def test_investigar_ip_publica_rdap_envia_informe(monkeypatch, no_local, enviados):
    monkeypatch.setattr(
        forense,
        "_lookup_rdap",
        lambda ip: {
            "org": "GOOGLE, US",
            "pais": "US",
            "red": "GOOGLE",
            "emails_abuso": "abuse@google.com",
            "fuente": "RDAP (ipwhois)",
        },
    )

    forense.investigar_ip("8.8.8.8")

    assert len(enviados) == 1
    assert "8.8.8.8" in enviados[0]


def test_investigar_omite_ips_no_publicas(monkeypatch, no_local, enviados):
    monkeypatch.setattr(
        forense, "_lookup_rdap", lambda ip: pytest.fail(f"RDAP no debe llamarse: {ip}")
    )
    monkeypatch.setattr(
        forense, "_lookup_ipinfo", lambda ip: pytest.fail(f"ipinfo no debe llamarse: {ip}")
    )

    for ip in ("10.1.2.3", "172.16.0.5", "192.168.1.1", "127.0.0.1", "224.0.0.1", "240.0.0.1"):
        forense.investigar_ip(ip)

    assert enviados == []


def test_investigar_ip_invalida_no_consulta(monkeypatch, no_local, enviados):
    monkeypatch.setattr(
        forense, "_lookup_rdap", lambda ip: pytest.fail("RDAP no debe llamarse")
    )
    forense.investigar_ip("999.1.1.1")
    forense.investigar_ip("no-es-ip")
    assert enviados == []


def test_investigar_modo_local_no_consulta_ni_envia(enviados):
    assert forense.investigar_ip("8.8.8.8") is None
    assert enviados == []


def test_investigar_ip_defined_error_omite_sin_fallback(monkeypatch, no_local, enviados):
    monkeypatch.setattr(
        forense,
        "_lookup_rdap",
        lambda ip: (_ for _ in ()).throw(forense.IPDefinedError("reservada")),
    )
    monkeypatch.setattr(
        forense, "_lookup_ipinfo", lambda ip: pytest.fail("no debe hacer fallback")
    )

    forense.investigar_ip("8.8.8.8")

    assert enviados == []


def test_investigar_fallback_ipinfo_cuando_rdap_falla(monkeypatch, no_local, enviados):
    monkeypatch.setattr(
        forense, "_lookup_rdap", lambda ip: (_ for _ in ()).throw(RuntimeError("rdap caido"))
    )
    monkeypatch.setattr(
        forense,
        "_lookup_ipinfo",
        lambda ip: {
            "org": "DIGITALOCEAN",
            "pais": "US",
            "red": "mi-host",
            "emails_abuso": "abuse@do.com",
            "fuente": "ipinfo.io (fallback)",
        },
    )

    forense.investigar_ip("8.8.8.8")

    assert len(enviados) == 1
    assert "8.8.8.8" in enviados[0]


def test_investigar_ambas_fuentes_fallan_envia_informe_sin_fuente(
    monkeypatch, no_local, enviados
):
    monkeypatch.setattr(
        forense, "_lookup_rdap", lambda ip: (_ for _ in ()).throw(RuntimeError("rdap caido"))
    )
    monkeypatch.setattr(
        forense,
        "_lookup_ipinfo",
        lambda ip: (_ for _ in ()).throw(forense.requests.ConnectionError("sin red")),
    )

    forense.investigar_ip("8.8.8.8")

    assert len(enviados) == 1
    assert "Sin fuente" in enviados[0] or "8.8.8.8" in enviados[0]
