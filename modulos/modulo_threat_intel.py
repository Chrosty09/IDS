# IDS Institucional — modulo_threat_intel — GNU/GPL v3

import csv
import threading
import time
from datetime import datetime
from pathlib import Path

import config
from utils.logger import obtener_logger
from utils.mailer import construir_html_alerta, enviar_alerta
from utils.reporter import reportar_evento

log = obtener_logger("threat_intel")


class ModuloThreatIntel:
    """Módulo de detección de comunicaciones con IPs maliciosas conocidas. REF: TI-001"""

    def __init__(self):
        """REF: TI-002"""
        self.ips_maliciosas: set[str] = set()
        self.metadata_ips: dict[str, dict] = {}
        self._ultimas_alertas: dict[str, float] = {}
        self._cooldown_segundos = 300

        self._cargar_blacklists()

    def _cargar_blacklists(self) -> None:
        """REF: TI-003"""
        self._cargar_feodo()

        fuentes_txt = [
            ("blacklist/cins_blacklist.txt", "Amenaza General", "CINS Army"),
            ("blacklist/blocklist_de.txt", "Ataques/Brute Force", "Blocklist.de"),
            ("blacklist/emerging_threats.txt", "Host Comprometido", "Emerging Threats"),
        ]

        for ruta_relativa, categoria, fuente in fuentes_txt:
            self._cargar_txt_ips(
                ruta=config.BASE_DIR / ruta_relativa,
                categoria=categoria,
                fuente=fuente,
            )

        log.info(
            f"Indice de threat intel cargado: "
            f"{len(self.ips_maliciosas)} IPs unicas de {len(fuentes_txt) + 1} fuentes."
        )

    def _cargar_feodo(self) -> None:
        """REF: TI-004"""
        ruta = config.BASE_DIR / "blacklist" / "feodo_blacklist.csv"

        if not ruta.exists():
            log.warning(f"Feodo blacklist no encontrada: {ruta}")
            return

        try:
            with ruta.open(encoding="utf-8", newline="") as archivo:
                lineas = (l for l in archivo if not l.startswith("#"))
                lector = csv.DictReader(lineas)
                conteo = 0
                for fila in lector:
                    ip = fila.get("dst_ip", "").strip()
                    if not ip:
                        continue
                    self.ips_maliciosas.add(ip)
                    if ip not in self.metadata_ips:
                        self.metadata_ips[ip] = {
                            "categoria": "Botnet/C2",
                            "malware": fila.get("malware", "Desconocido").strip(),
                            "puerto": fila.get("dst_port", "N/A").strip(),
                            "fuente": "Feodo Tracker",
                        }
                    conteo += 1
            log.info(f"Feodo Tracker: {conteo} IPs cargadas.")
        except (OSError, csv.Error) as e:
            log.error(f"Error al leer Feodo blacklist: {e}")

    def _cargar_txt_ips(self, ruta: Path, categoria: str, fuente: str) -> None:
        """REF: TI-005"""
        if not ruta.exists():
            log.warning(f"Archivo de blacklist no encontrado: {ruta.name}")
            return

        try:
            conteo = 0
            with ruta.open(encoding="utf-8") as archivo:
                for linea in archivo:
                    linea = linea.strip()
                    if not linea or linea.startswith("#"):
                        continue
                    ip = linea.split()[0]
                    if not ip:
                        continue
                    self.ips_maliciosas.add(ip)
                    if ip not in self.metadata_ips:
                        self.metadata_ips[ip] = {
                            "categoria": categoria,
                            "malware": "N/A",
                            "puerto": "N/A",
                            "fuente": fuente,
                        }
                    conteo += 1
            log.info(f"{fuente}: {conteo} IPs cargadas.")
        except OSError as e:
            log.error(f"Error al leer {ruta.name}: {e}")

    def _en_cooldown(self, ip: str) -> bool:
        """Verifica si hay una alerta reciente para esta IP."""
        ultimo = self._ultimas_alertas.get(ip)
        if ultimo is None:
            return False
        return (time.monotonic() - ultimo) < self._cooldown_segundos

    def _registrar_alerta(self, ip: str) -> None:
        """Guarda el timestamp actual para controlar duplicados de alertas."""
        self._ultimas_alertas[ip] = time.monotonic()

    def _lanzar_forense(self, ip_peligrosa: str) -> None:
        """REF: TI-007"""
        # REF: TI-007
        from modulos.modulo_forense import investigar_ip

        hilo = threading.Thread(
            target=investigar_ip,
            args=(ip_peligrosa,),
            name=f"forense-{ip_peligrosa}",
            daemon=True,
        )
        hilo.start()
        log.info(f"Investigacion forense lanzada en segundo plano para: {ip_peligrosa}")

    def procesar(self, pkt) -> None:
        """REF: TI-006"""
        if not pkt.haslayer("IP"):
            return

        ip_destino = pkt["IP"].dst
        ip_origen = pkt["IP"].src

        if ip_destino not in self.ips_maliciosas:
            return

        if self._en_cooldown(ip_destino):
            log.debug(
                f"Alerta de amenaza suprimida (cooldown activo) para {ip_destino}"
            )
            return

        if config.MODO_LOCAL:
            return

        metadata = self.metadata_ips.get(ip_destino, {})
        categoria = metadata.get("categoria", "Desconocida")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log.critical(
            f"IP MALICIOSA DETECTADA | "
            f"Tipo: {categoria} | "
            f"Fuente: {metadata.get('fuente', 'Desconocida')} | "
            f"Interno: {ip_origen} -> Externo: {ip_destino}"
        )

        detalles = {
            "Tipo de Amenaza": categoria,
            "Fuente de Inteligencia": metadata.get("fuente", "Desconocida"),
            "Malware Identificado": metadata.get("malware", "N/A"),
            "Puerto C2": metadata.get("puerto", "N/A"),
            "IP Peligrosa": ip_destino,
            "IP Interna Afectada": ip_origen,
            "Interfaz": config.NETWORK_INTERFACE,
            "Timestamp": timestamp,
        }

        html = construir_html_alerta(
            titulo=f"Comunicacion con IP maliciosa detectada: {ip_destino}",
            detalles=detalles,
            nivel="EMERGENCIA",
        )
        enviar_alerta(
            asunto=f"EMERGENCIA {categoria}: {ip_destino}",
            cuerpo_html=html,
        )
        reportar_evento(
            tipo="threat_intel",
            categoria=metadata.get("categoria", "Desconocida"),
            fuente=metadata.get("fuente", "Desconocida"),
            ip_origen=ip_origen,
            ip_destino=ip_destino,
            detalles={
                "malware": metadata.get("malware", "N/A"),
                "puerto": metadata.get("puerto", "N/A"),
            },
        )
        self._registrar_alerta(ip_destino)

        self._lanzar_forense(ip_destino)
