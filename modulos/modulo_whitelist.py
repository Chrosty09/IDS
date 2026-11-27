# IDS Institucional — modulo_whitelist — GNU/GPL v3

import ipaddress
import re
import time
from datetime import datetime
from pathlib import Path

import config
from utils.logger import obtener_logger
from utils.mailer import encolar_alerta_resumen
from utils.reporter import reportar_evento

log = obtener_logger("whitelist")

# REF: WL-004
_MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def validar_entrada_whitelist(ip: str, mac: str) -> str | None:
    """Valida el formato de una entrada IP/MAC de la whitelist. Retorna None
    si es válida, o una descripción del error. REF: WL-009

    La usa la GUI antes de guardar: una entrada malformada nunca matchearía
    al comparar contra el tráfico y dejaría un dispositivo mal autorizado o
    mal desautorizado sin aviso.
    """
    ip = (ip or "").strip()
    mac = (mac or "").strip()

    if not ip:
        return "falta la IP"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"IP inválida: {ip}"

    if mac and not _MAC_REGEX.match(mac):
        return f"MAC inválida: {mac} (formato AA:BB:CC:DD:EE:FF)"
    return None


class ModuloWhitelist:
    """Módulo de validación de dispositivos autorizados en la red. REF: WL-001

    Limitaciones conocidas (REF: WL-008), a considerar al operar el IDS:

    1. La MAC se toma de la trama Ethernet y puede suplantarse (spoofing)
       por un atacante con acceso local a la red. Este módulo es un control
       DETECTIVO —el IDS es pasivo y no bloquea tráfico—: el aislamiento
       real de un dispositivo corresponde al firewall/NAC del administrador.
    2. Las tramas sin capa Ethernet (túneles, interfaces cooked) no permiten
       validar MAC: se deja constancia en el log y la validación queda
       únicamente por IP.
    """

    def __init__(self):
        """REF: WL-002"""
        self._ultimas_alertas: dict[str, float] = {}
        self._cooldown_segundos = 300

        self.ips_autorizadas: set[str] = set()
        self.macs_autorizadas: set[str] = set()

        self._cargar_whitelist()

    def _cargar_whitelist(self) -> None:
        """Lee whitelist.txt y carga IPs y MACs autorizadas en memoria."""
        ruta = Path(config.WHITELIST_FILE)

        # Reconstruir los conjuntos en cada carga (init o recarga): una entrada
        # eliminada del archivo no debe quedar autorizada en memoria.
        self.ips_autorizadas.clear()
        self.macs_autorizadas.clear()

        if not ruta.exists():
            log.warning(
                f"Archivo whitelist no encontrado: {ruta}. Se opera sin lista blanca."
            )
            return

        try:
            with ruta.open(encoding="utf-8") as archivo:
                for numero, linea in enumerate(archivo, start=1):
                    linea = linea.strip()
                    # Ignorar lineas vacias y comentarios
                    if not linea or linea.startswith("#"):
                        continue

                    partes = [p.strip() for p in linea.split(",")]
                    if len(partes) < 2:
                        log.warning(
                            f"Linea {numero} de whitelist con formato invalido: '{linea}'"
                        )
                        continue

                    ip, mac = partes[0], partes[1].upper()
                    self.ips_autorizadas.add(ip)
                    self.macs_autorizadas.add(mac)

            log.info(
                f"Whitelist cargada: {len(self.ips_autorizadas)} IPs "
                f"y {len(self.macs_autorizadas)} MACs autorizadas."
            )
        except OSError as e:
            log.error(f"Error al leer la whitelist: {e}")

    def recargar(self) -> None:
        """Recarga la whitelist desde disco sin reiniciar el motor.

        Se invoca cuando la GUI guarda cambios y deja el centinela
        .ids_whitelist_reload (REF: WL-010). El cooldown de alertas se
        conserva para no re-alertar dispositivos recién autorizados.
        """
        self._cargar_whitelist()
        log.info("Whitelist recargada en caliente por solicitud de la GUI.")

    def _en_cooldown(self, clave: str) -> bool:
        """Verifica si hay una alerta reciente activa para esta clave."""
        ultimo = self._ultimas_alertas.get(clave)
        if ultimo is None:
            return False
        return (time.monotonic() - ultimo) < self._cooldown_segundos

    def _registrar_alerta(self, clave: str) -> None:
        """Guarda el timestamp del envio de alerta para controlar duplicados."""
        self._ultimas_alertas[clave] = time.monotonic()

    def _es_ip_local(self, ip: str) -> bool:
        """REF: WL-006"""
        _RANGOS_LOCALES = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in red for red in _RANGOS_LOCALES)
        except ValueError:
            return False

    def procesar(self, pkt) -> None:
        """REF: WL-007"""
        if not pkt.haslayer("IP"):
            return
        ip_origen = pkt["IP"].src

        if not self._es_ip_local(ip_origen):
            return

        # REF: WL-004
        mac_origen = ""
        if pkt.haslayer("Ether"):
            mac_raw = pkt["Ether"].src.upper()
            if _MAC_REGEX.match(mac_raw):
                mac_origen = mac_raw
            else:
                log.debug(
                    f"whitelist - MAC con formato inválido ignorada: {repr(mac_raw)}"
                )
        else:
            # REF: WL-008 — sin trama Ethernet no hay MAC validable
            log.debug(
                f"whitelist - trama sin capa Ethernet; MAC no validable para {ip_origen}"
            )

        ip_autorizada = ip_origen in self.ips_autorizadas
        mac_autorizada = (not mac_origen) or (mac_origen in self.macs_autorizadas)

        if ip_autorizada and mac_autorizada:
            return

        clave_alerta = f"{ip_origen}|{mac_origen}"

        if self._en_cooldown(clave_alerta):
            log.debug(f"Alerta suprimida (cooldown activo) para {clave_alerta}")
            return

        motivo = []
        if not ip_autorizada:
            motivo.append(f"IP '{ip_origen}' no registrada en whitelist")
        if mac_origen and not mac_autorizada:
            motivo.append(f"MAC '{mac_origen}' no registrada en whitelist")

        descripcion = " | ".join(motivo)

        log.warning(f"Dispositivo no autorizado detectado: {descripcion}")
        self._registrar_alerta(clave_alerta)  # cooldown también en local

        if config.MODO_LOCAL:
            return  # detectado y mostrado por stdout, sin correo/reporte

        encolar_alerta_resumen(
            categoria="Dispositivo no autorizado",
            detalles={
                "IP Detectada": ip_origen,
                "MAC Detectada": mac_origen or "No disponible",
                "Interfaz": config.NETWORK_INTERFACE,
            },
        )
        reportar_evento(
            tipo="whitelist",
            categoria="Dispositivo no autorizado",
            ip_origen=ip_origen,
            mac=mac_origen,
        )
