"""Saneo de dominios y búsqueda en la lista, sin blacklists ni red."""

from modulos.modulo_sitios import ModuloSitios, _sanitizar_para_log


def test_sanitizar_quita_controles_y_acota_longitud():
    assert _sanitizar_para_log("a\r\nb\x00c\x7f") == "abc"
    assert _sanitizar_para_log("ok.example") == "ok.example"
    assert len(_sanitizar_para_log("a" * 400)) == 253


def test_buscar_dominio_exacto_o_registrable():
    modulo = ModuloSitios.__new__(ModuloSitios)
    modulo.dominios_maliciosos = {
        "evil.example": {"categoria": "Phishing", "fuente": "prueba"},
    }

    assert modulo._buscar_dominio("evil.example")["fuente"] == "prueba"
    assert modulo._buscar_dominio("a.evil.example")["categoria"] == "Phishing"
    assert modulo._buscar_dominio("otro.example") is None
    assert modulo._buscar_dominio("evil.example.otro") is None


def test_accion_recomendada_segun_categoria():
    modulo = ModuloSitios.__new__(ModuloSitios)

    assert "Bloquear" in modulo._accion_recomendada("Phishing")
    assert "Aislar" in modulo._accion_recomendada("Malware")
    assert "vigilancia" in modulo._accion_recomendada("Stalkerware")
    assert "mineria" in modulo._accion_recomendada("Cryptomining")
    assert "fraude" in modulo._accion_recomendada("Estafa")
    assert modulo._accion_recomendada("Otra") == (
        "Investigar actividad del cliente en la red"
    )
