"""Parsers de los feeds de inteligencia. No descargan nada."""

from utils.threat_feed import _parsear_adguard, _parsear_hosts, _parsear_plain


def test_parsear_adguard_extrae_el_dominio():
    assert _parsear_adguard("||Malware.Example^") == "malware.example"
    assert _parsear_adguard("||solo-dominio.example") == "solo-dominio.example"
    assert _parsear_adguard("||Evil.Example^$third-party") == "evil.example"


def test_parsear_adguard_ignora_comentarios_y_excepciones():
    assert _parsear_adguard("! comentario") == ""
    assert _parsear_adguard("# comentario") == ""
    assert _parsear_adguard("[Adblock Plus 2.0]") == ""
    assert _parsear_adguard("@@||excepcion.example^") == ""
    assert _parsear_adguard("") == ""
    assert _parsear_adguard("   ") == ""


def test_parsear_hosts_omite_localhost():
    assert _parsear_hosts("0.0.0.0 bad.example") == "bad.example"
    assert _parsear_hosts("127.0.0.1 LocalHost") == ""
    assert _parsear_hosts("0.0.0.0 0.0.0.0") == ""
    assert _parsear_hosts("# hola") == ""
    assert _parsear_hosts("solo-un-campo") == ""


def test_parsear_plain_normaliza_y_descarta_comentarios():
    assert _parsear_plain("  Phish.Example  ") == "phish.example"
    assert _parsear_plain("# no") == ""
    assert _parsear_plain("! no") == ""
    assert _parsear_plain("[seccion]") == ""
