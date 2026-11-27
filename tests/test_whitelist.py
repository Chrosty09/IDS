"""Validación de dispositivos autorizados (IP/MAC) sin captura de tráfico."""

from modulos.modulo_whitelist import ModuloWhitelist, validar_entrada_whitelist


def test_acepta_ipv4_y_mac():
    assert validar_entrada_whitelist("192.168.1.10", "AA:BB:CC:DD:EE:FF") is None
    assert validar_entrada_whitelist("10.0.0.2", "aa-bb-cc-dd-ee-ff") is None
    assert validar_entrada_whitelist(" 10.1.1.1 ", "") is None
    assert validar_entrada_whitelist("::1", "") is None


def test_rechaza_ip_mac_o_entrada_vacia():
    assert validar_entrada_whitelist("  ", "AA:BB:CC:DD:EE:FF") == "falta la IP"
    assert validar_entrada_whitelist(None, None) == "falta la IP"

    ip = validar_entrada_whitelist("999.1.1.1", "")
    assert ip is not None and "IP inválida" in ip

    mac = validar_entrada_whitelist("10.0.0.1", "no-es-mac")
    assert mac is not None and "MAC inválida" in mac


def test_distingue_direcciones_locales():
    modulo = ModuloWhitelist()

    assert modulo._es_ip_local("10.1.2.3") is True
    assert modulo._es_ip_local("172.16.0.1") is True
    assert modulo._es_ip_local("172.31.255.255") is True
    assert modulo._es_ip_local("192.168.0.5") is True
    assert modulo._es_ip_local("169.254.1.1") is True

    assert modulo._es_ip_local("8.8.8.8") is False
    assert modulo._es_ip_local("172.15.0.1") is False
    assert modulo._es_ip_local("no-es-ip") is False


def test_cooldown_suprime_la_alerta_recien_registrada():
    modulo = ModuloWhitelist()
    assert modulo._en_cooldown("10.0.0.9|AA:BB:CC:DD:EE:FF") is False
    modulo._registrar_alerta("10.0.0.9|AA:BB:CC:DD:EE:FF")
    assert modulo._en_cooldown("10.0.0.9|AA:BB:CC:DD:EE:FF") is True
