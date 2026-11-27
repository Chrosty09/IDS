"""modulo_threat_intel: carga de blacklists y detección de IPs maliciosas."""

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

import config
from modulos.modulo_threat_intel import ModuloThreatIntel


@pytest.fixture
def base_dir_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    return tmp_path


def _modulo(base_dir_tmp) -> ModuloThreatIntel:
    return ModuloThreatIntel()


# ── carga de blacklists ──


def test_cargar_txt_ips_ignora_comentarios_y_dedup(base_dir_tmp, tmp_path):
    archivo = tmp_path / "lista.txt"
    archivo.write_text("# comentario\n1.1.1.1\n2.2.2.2\n\n1.1.1.1\n", encoding="utf-8")

    mod = ModuloThreatIntel.__new__(ModuloThreatIntel)
    mod.ips_maliciosas = set()
    mod.metadata_ips = {}
    mod._cargar_txt_ips(archivo, "Amenaza", "Fuente-X")

    assert mod.ips_maliciosas == {"1.1.1.1", "2.2.2.2"}
    assert mod.metadata_ips["1.1.1.1"]["categoria"] == "Amenaza"
    assert mod.metadata_ips["1.1.1.1"]["fuente"] == "Fuente-X"


def test_cargar_txt_ips_no_sobrescribe_metadata_existente(base_dir_tmp, tmp_path):
    archivo = tmp_path / "lista.txt"
    archivo.write_text("1.1.1.1\n", encoding="utf-8")

    mod = ModuloThreatIntel.__new__(ModuloThreatIntel)
    mod.ips_maliciosas = set()
    mod.metadata_ips = {"1.1.1.1": {"categoria": "Original", "fuente": "A"}}
    mod._cargar_txt_ips(archivo, "Nueva", "B")

    assert mod.metadata_ips["1.1.1.1"]["fuente"] == "A"


def test_cargar_feodo_parsea_csv(base_dir_tmp, tmp_path):
    carpeta = tmp_path / "blacklist"
    carpeta.mkdir()
    (carpeta / "feodo_blacklist.csv").write_text(
        "# encabezado de comentario\n"
        "first_seen,dst_ip,dst_port,malware\n"
        "2026-01-01,1.2.3.4,445,Heodo\n"
        "2026-01-02,5.6.7.8,80,TrickBot\n"
        "2026-01-03,1.2.3.4,445,Heodo\n",
        encoding="utf-8",
    )

    mod = ModuloThreatIntel.__new__(ModuloThreatIntel)
    mod.ips_maliciosas = set()
    mod.metadata_ips = {}
    mod._cargar_feodo()

    assert "1.2.3.4" in mod.ips_maliciosas
    assert "5.6.7.8" in mod.ips_maliciosas
    assert mod.metadata_ips["1.2.3.4"] == {
        "categoria": "Botnet/C2",
        "malware": "Heodo",
        "puerto": "445",
        "fuente": "Feodo Tracker",
    }


# ── procesar: detección ──


def test_procesar_ignora_paquete_sin_ip(base_dir_tmp):
    mod = _modulo(base_dir_tmp)
    mod.procesar(Ether())
    assert not mod._ultimas_alertas


def test_procesar_destino_no_malicioso_no_alerta(base_dir_tmp):
    mod = _modulo(base_dir_tmp)
    mod.ips_maliciosas = {"185.100.67.130"}
    mod.procesar(IP(src="192.168.1.20", dst="8.8.8.8"))
    assert not mod._ultimas_alertas


def test_procesar_local_detecta_sin_correo_ni_forense(base_dir_tmp, monkeypatch):
    for nombre in ("enviar_alerta", "reportar_evento"):
        monkeypatch.setattr(
            f"modulos.modulo_threat_intel.{nombre}",
            lambda *a, **kw: pytest.fail(f"{nombre} no debe llamarse en modo local"),
        )
    monkeypatch.setattr(
        ModuloThreatIntel,
        "_lanzar_forense",
        lambda self, ip: pytest.fail("forense no debe lanzarse en modo local"),
    )

    mod = _modulo(base_dir_tmp)
    mod.ips_maliciosas = {"185.100.67.130"}
    mod.procesar(IP(src="192.168.1.20", dst="185.100.67.130"))

    assert "185.100.67.130" in mod._ultimas_alertas
    assert len(mod._ultimas_alertas) == 1

    # cooldown: mismo destino no vuelve a pasar por la ruta de alerta
    mod.procesar(IP(src="192.168.1.21", dst="185.100.67.130"))
    assert len(mod._ultimas_alertas) == 1


def test_procesar_no_local_correo_reporte_y_forense(base_dir_tmp, monkeypatch):
    enviados = []
    reportados = []
    forense_lanzada = []
    monkeypatch.setattr(config, "MODO_LOCAL", False)
    monkeypatch.setattr(
        "modulos.modulo_threat_intel.enviar_alerta",
        lambda asunto, cuerpo_html, destinatario=None: enviados.append(asunto) or True,
    )
    monkeypatch.setattr(
        "modulos.modulo_threat_intel.construir_html_alerta",
        lambda titulo, detalles, nivel="ADVERTENCIA": "html",
    )
    monkeypatch.setattr(
        "modulos.modulo_threat_intel.reportar_evento", lambda **kw: reportados.append(kw)
    )
    monkeypatch.setattr(
        ModuloThreatIntel,
        "_lanzar_forense",
        lambda self, ip: forense_lanzada.append(ip),
    )

    mod = _modulo(base_dir_tmp)
    mod.ips_maliciosas = {"185.100.67.130"}
    mod.metadata_ips["185.100.67.130"] = {
        "categoria": "Botnet/C2",
        "malware": "Heodo",
        "puerto": "445",
        "fuente": "Feodo Tracker",
    }

    pkt = IP(src="192.168.1.20", dst="185.100.67.130")
    mod.procesar(pkt)

    assert len(enviados) == 1
    assert enviados[0] == "EMERGENCIA Botnet/C2: 185.100.67.130"
    assert reportados[0]["tipo"] == "threat_intel"
    assert reportados[0]["ip_destino"] == "185.100.67.130"
    assert reportados[0]["detalles"]["malware"] == "Heodo"
    assert forense_lanzada == ["185.100.67.130"]

    mod.procesar(pkt)  # cooldown por IP
    assert len(enviados) == 1
    assert len(forense_lanzada) == 1
