"""modulo_sitios: extracción de dominio (DNS/HTTP) y decisión de detección.

Lo más riesgoso aquí es el parsing: los nombres reales llegan con puntos
finales, mayúsculas, prefijos www, caracteres de control y subdominios; un
parser equivocado produce falsos negativos en la blacklist o registros de
navegación corruptos.
"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

import config
from modulos import modulo_sitios as sitios
from modulos.modulo_sitios import ModuloSitios, _sanitizar_para_log


def _dns(src: str, qname: bytes, qr: int = 0):
    return (
        Ether()
        / IP(src=src, dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(qr=qr, qdcount=1, qd=DNSQR(qname=qname))
    )


def _http(src: str, host: str | None, dport: int = 80):
    payload = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        if host is not None
        else b"GET / HTTP/1.1\r\n\r\n"
    )
    return (
        Ether() / IP(src=src, dst="93.184.216.34") / TCP(dport=dport) / Raw(load=payload)
    )


def _modulo(monkeypatch, tmp_path) -> ModuloSitios:
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)  # blacklists vacías
    return ModuloSitios()


def _con_malicioso(mod: ModuloSitios) -> None:
    mod.dominios_maliciosos = {
        "evil.com": {"categoria": "Phishing", "fuente": "Test"},
        "phish.army": {"categoria": "Phishing", "fuente": "Test"},
    }


# ── sanitización ──


def test_sanitizar_elimina_controles_y_acota_longitud():
    assert _sanitizar_para_log("\x00evil\x1f.com") == "evil.com"
    assert _sanitizar_para_log("a" * 300) == "a" * 253


# ── búsqueda de dominio ──


def test_buscar_dominio_exacto_y_por_raiz(tmp_path, monkeypatch):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    assert mod._buscar_dominio("evil.com")["fuente"] == "Test"
    assert mod._buscar_dominio("sub.evil.com")["categoria"] == "Phishing"
    assert mod._buscar_dominio("a.b.sub.evil.com") is not None
    assert mod._buscar_dominio("evil.org") is None
    assert mod._buscar_dominio("evil.com.evil.org") is None  # la raíz es evil.org


# ── extracción DNS ──


def test_extraer_dominio_dns_query(tmp_path, monkeypatch):
    mod = _modulo(monkeypatch, tmp_path)
    assert mod._extraer_dominio_dns(_dns("192.168.1.10", b"example.com.")) == (
        "example.com"
    )


def test_extraer_dominio_dns_respuesta_ignorada(tmp_path, monkeypatch):
    mod = _modulo(monkeypatch, tmp_path)
    assert mod._extraer_dominio_dns(_dns("192.168.1.10", b"evil.com.", qr=1)) is None


def test_extraer_dominio_dns_sin_consulta_ignorada(tmp_path, monkeypatch):
    mod = _modulo(monkeypatch, tmp_path)
    pkt = Ether() / IP(src="192.168.1.10") / UDP() / DNS(qr=0, qdcount=0)
    assert mod._extraer_dominio_dns(pkt) is None


def test_extraer_host_http_presente_y_ausente(tmp_path, monkeypatch):
    mod = _modulo(monkeypatch, tmp_path)
    assert mod._extraer_host_http(_http("192.168.1.10", "Example.COM:8080")) == (
        "Example.COM:8080"
    )
    assert mod._extraer_host_http(_http("192.168.1.10", None)) is None


# ── procesar: detección ──


def test_procesar_detecta_dominio_malicioso_y_cooldown(monkeypatch, tmp_path, caplog):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    pkt = _dns("192.168.1.10", b"evil.com.")
    mod.procesar(pkt)
    assert "192.168.1.10|evil.com" in mod._ultimas_alertas
    assert "DOMINIO MALICIOSO DETECTADO" in caplog.text

    caplog.clear()
    mod.procesar(pkt)
    assert "DOMINIO MALICIOSO DETECTADO" not in caplog.text


def test_procesar_normaliza_www_mayusculas_y_punto_final(monkeypatch, tmp_path, caplog):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    mod.procesar(_dns("192.168.1.10", b"WWW.EVIL.COM."))
    assert "192.168.1.10|evil.com" in mod._ultimas_alertas


def test_procesar_subdominio_mapea_a_raiz_maliciosa(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    mod.procesar(_dns("192.168.1.10", b"intranet.sub.evil.com."))
    assert "192.168.1.10|intranet.sub.evil.com" in mod._ultimas_alertas


def test_procesar_detected_por_http_en_puerto_80(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    mod.procesar(_http("192.168.1.10", "evil.com"))
    assert "192.168.1.10|evil.com" in mod._ultimas_alertas


def test_procesar_http_en_otro_puerto_ignorado(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    mod.procesar(_http("192.168.1.10", "evil.com", dport=443))
    assert not mod._ultimas_alertas


def test_procesar_dominio_benigno_no_alerta_en_local(monkeypatch, tmp_path, caplog):
    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    mod.procesar(_dns("192.168.1.10", b"example.com."))
    assert not mod._ultimas_alertas
    assert "DOMINIO MALICIOSO DETECTADO" not in caplog.text


def test_procesar_no_local_envia_correo_y_reporte(monkeypatch, tmp_path):
    enviados = []
    reportados = []
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(
        "modulos.modulo_sitios.enviar_alerta",
        lambda asunto, cuerpo_html, destinatario=None: enviados.append(
            (asunto, cuerpo_html)
        )
        or True,
    )
    monkeypatch.setattr(
        "modulos.modulo_sitios.reportar_evento", lambda **kw: reportados.append(kw)
    )

    mod = _modulo(monkeypatch, tmp_path)
    _con_malicioso(mod)

    pkt = _dns("192.168.1.10", b"evil.com.")
    mod.procesar(pkt)

    assert len(enviados) == 1
    assert "evil.com" in enviados[0][0]
    assert reportados[0]["tipo"] == "sitios"
    assert reportados[0]["dominio"] == "evil.com"
    assert reportados[0]["ip_origen"] == "192.168.1.10"

    mod.procesar(pkt)
    assert len(enviados) == 1  # cooldown por cliente|dominio


# ── registro de navegación (log de sitios) ──


def test_procesar_benigno_no_local_registra_dominio_normalizado(monkeypatch, tmp_path):
    ruta_log = tmp_path / "sitios_visitados.log"
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "SITE_LOG_FILE", ruta_log)
    mod = _modulo(monkeypatch, tmp_path)

    mod.procesar(_dns("192.168.1.10", b"www.example.com."))

    assert ruta_log.exists()
    contenido = ruta_log.read_text(encoding="utf-8")
    assert "192.168.1.10" in contenido
    assert "| example.com" in contenido  # www y punto final normalizados


def test_escribir_registro_rota_log_cuando_excede_limite(monkeypatch, tmp_path):
    ruta_log = tmp_path / "sitios_visitados.log"
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(config, "SITE_LOG_FILE", ruta_log)
    monkeypatch.setattr(sitios, "_MAX_SITIOS_LOG_BYTES", 50)

    mod = ModuloSitios.__new__(ModuloSitios)
    mod._ruta_log = ruta_log
    ruta_log.write_text("x" * 100, encoding="utf-8")  # ya excede el límite

    mod._escribir_registro("192.168.1.10", "example.com")

    rotado = ruta_log.with_name(ruta_log.name + ".1")
    assert rotado.exists()
    assert rotado.read_text(encoding="utf-8") == "x" * 100
    assert "example.com" in ruta_log.read_text(encoding="utf-8")


# ── acciones recomendadas ──


def test_accion_recomendada_por_categoria():
    tabla = {
        "Phishing": "Bloquear dominio",
        "Malware": "Aislar equipo cliente",
        "Stalkerware/Spyware": "Revisar el equipo",
        "Cryptomining": "mineria sin consentimiento",
        "Scam/Estafa": "posible intento de fraude",
        "Otra": "Investigar actividad",
    }
    for categoria, esperado in tabla.items():
        assert esperado in ModuloSitios._accion_recomendada(None, categoria)
