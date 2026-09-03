"""modulo_whitelist: la decisión de autorización de dispositivos.

Cubre la validación de formato que usa la GUI (una entrada malformada nunca
matchearía contra el tráfico) y las reglas de procesar(): gate de IP local,
autorización IP+MAC, túneles sin MAC y cooldown de alertas.
"""

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

import config
from modulos.modulo_whitelist import ModuloWhitelist, validar_entrada_whitelist


def _modulo(monkeypatch, tmp_path, contenido="") -> ModuloWhitelist:
    archivo = tmp_path / "whitelist.txt"
    if contenido:
        archivo.write_text(contenido, encoding="utf-8")
    monkeypatch.setattr(config, "WHITELIST_FILE", archivo)
    return ModuloWhitelist()


def _pkt_eth(src: str, mac: str):
    return Ether(src=mac) / IP(src=src)


def _pkt_tunel(src: str):
    return IP(src=src)


# ── validar_entrada_whitelist (puerta de la GUI) ──


def test_validar_entrada_valida_ipv4_con_mac():
    assert validar_entrada_whitelist("192.168.1.1", "AA:BB:CC:DD:EE:FF") is None


def test_validar_entrada_acepta_ipv6_y_mac_con_guiones():
    assert validar_entrada_whitelist("2001:db8::1", "aa-bb-cc-dd-ee-ff") is None


def test_validar_entrada_sin_mac_es_valida():
    assert validar_entrada_whitelist(" 192.168.1.1 ", "") is None


def test_validar_entrada_rechaza_ip_vacia_o_invalida():
    assert validar_entrada_whitelist("", "") == "falta la IP"
    assert "IP inválida" in validar_entrada_whitelist("999.1.1.1", "")


def test_validar_entrada_rechaza_mac_malformada():
    error = validar_entrada_whitelist("10.0.0.1", "ZZ:11:22:33:44:55")
    assert "MAC inválida" in error
    assert validar_entrada_whitelist("10.0.0.1", "AA:BB:CC:DD:EE") is not None


# ── carga de whitelist ──


def test_cargar_whitelist_ignora_comentarios_y_lineas_malformadas(
    monkeypatch, tmp_path
):
    mod = _modulo(
        monkeypatch,
        tmp_path,
        contenido=(
            "# comentario\n"
            "192.168.1.10, aa:bb:cc:dd:ee:01\n"
            "192.168.1.11, aa:bb:cc:dd:ee:02\n"
            "linea_sin_segundo_campo\n"
            "\n"
        ),
    )
    assert mod.ips_autorizadas == {"192.168.1.10", "192.168.1.11"}
    assert mod.macs_autorizadas == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}


def test_cargar_whitelist_archivo_ausente_opera_vacia(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    assert mod.ips_autorizadas == set()
    assert mod.macs_autorizadas == set()


# ── procesar: decisión de autorización ──


def test_procesar_ignora_paquetes_sin_ip(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    mod.procesar(Ether())
    assert not mod._ultimas_alertas


def test_procesar_ignora_trafico_externo(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path)
    mod.procesar(_pkt_eth("8.8.8.8", "aa:bb:cc:dd:ee:ff"))
    assert not mod._ultimas_alertas


def test_procesar_dispositivo_autorizado_no_alerta(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path, contenido="192.168.1.50, aa:bb:cc:dd:ee:ff\n")
    mod.procesar(_pkt_eth("192.168.1.50", "AA:BB:CC:DD:EE:FF"))
    assert not mod._ultimas_alertas


def test_procesar_ip_desconocida_alerta_y_cooldown(monkeypatch, tmp_path, caplog):
    mod = _modulo(monkeypatch, tmp_path)
    pkt = _pkt_eth("192.168.1.99", "aa:bb:cc:dd:ee:ff")

    mod.procesar(pkt)
    assert "192.168.1.99|AA:BB:CC:DD:EE:FF" in mod._ultimas_alertas

    caplog.clear()
    mod.procesar(pkt)  # misma clave en cooldown -> suprimida
    assert "Dispositivo no autorizado detectado" not in caplog.text


def test_procesar_mac_desconocida_en_ip_autorizada_alerta(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path, contenido="192.168.1.50, aa:bb:cc:dd:ee:01\n")
    mod.procesar(_pkt_eth("192.168.1.50", "AA:BB:CC:DD:EE:02"))
    assert "192.168.1.50|AA:BB:CC:DD:EE:02" in mod._ultimas_alertas


def test_procesar_tunel_sin_ethernet_valida_solo_por_ip(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path, contenido="192.168.1.50, aa:bb:cc:dd:ee:ff\n")

    mod.procesar(_pkt_tunel("192.168.1.50"))
    assert not mod._ultimas_alertas  # IP autorizada basta sin MAC

    mod.procesar(_pkt_tunel("192.168.1.77"))
    assert "192.168.1.77|" in mod._ultimas_alertas


def test_procesar_mac_invalida_en_trama_tratada_como_ausencia(monkeypatch, tmp_path):
    mod = _modulo(monkeypatch, tmp_path, contenido="192.168.1.50, aa:bb:cc:dd:ee:ff\n")
    pkt = Ether(src="no-es-una-mac") / IP(src="192.168.1.50")
    mod.procesar(pkt)
    assert not mod._ultimas_alertas  # MAC no validable -> control por IP


def test_procesar_no_local_encola_y_reporta(monkeypatch, tmp_path):
    encoladas = []
    reportadas = []
    monkeypatch.setattr(
        config, "MODO_LOCAL", False
    )
    monkeypatch.setattr(
        "modulos.modulo_whitelist.encolar_alerta_resumen",
        lambda categoria, detalles: encoladas.append((categoria, detalles)),
    )
    monkeypatch.setattr(
        "modulos.modulo_whitelist.reportar_evento", lambda **kw: reportadas.append(kw)
    )

    mod = _modulo(monkeypatch, tmp_path)
    pkt = _pkt_eth("192.168.1.99", "aa:bb:cc:dd:ee:ff")
    mod.procesar(pkt)

    assert len(encoladas) == 1
    assert encoladas[0][0] == "Dispositivo no autorizado"
    assert encoladas[0][1]["IP Detectada"] == "192.168.1.99"
    assert reportadas[0]["tipo"] == "whitelist"
    assert reportadas[0]["ip_origen"] == "192.168.1.99"

    mod.procesar(pkt)
    assert len(encoladas) == 1  # cooldown también fuera de modo local
