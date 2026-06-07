# IDS Institucional — modulo_sitios — GNU/GPL v3

import re
from datetime import datetime
from pathlib import Path

import config
from utils.logger import obtener_logger
from utils.mailer import construir_html_alerta, enviar_alerta
from utils.reporter import reportar_evento

log = obtener_logger("sitios")

# REF: SI-003
_MAX_SITIOS_LOG_BYTES = 50 * 1024 * 1024


def _sanitizar_para_log(texto: str) -> str:
    """REF: SI-002"""
    return re.sub(r"[\x00-\x1f\x7f]", "", texto)


Path(config.SITE_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

# REF: SI-001
ARCHIVOS_DOMINIOS = [
    ("blacklist/urlhaus_filter_agh.txt", "Malware (URLhaus)", "URLhaus/malware-filter"),
    ("blacklist/urlhaus_domains.txt", "Malware (URLhaus)", "URLhaus abuse.ch"),
    ("blacklist/scamblocklist_adguard.txt", "Scam/Estafa", "Scam Blocklist"),
    ("blacklist/hagezi_tif.txt", "Threat Intelligence", "Hagezi TIF"),
    ("blacklist/hagezi_hoster.txt", "Hosting Malicioso", "Hagezi Hoster"),
    ("blacklist/antimalware_agh.txt", "Malware", "Anti-Malware List"),
    ("blacklist/phishing_filter_agh.txt", "Phishing", "Phishing Filter"),
    ("blacklist/nocoin_hosts.txt", "Cryptomining", "NoCoin List"),
    ("blacklist/hacked_sites.txt", "Sitio Comprometido", "Hacked Sites DB"),
    ("blacklist/stalkerware.txt", "Stalkerware/Spyware", "Stalkerware Indicators"),
    ("blacklist/shadowwhisperer_malware.txt", "Malware", "ShadowWhisperer"),
    ("blacklist/phishing_army_extended.txt", "Phishing", "Phishing Army"),
    ("blacklist/phishing_army.txt", "Phishing", "Phishing Army"),
    ("blacklist/openphish_domains.txt", "Phishing", "OpenPhish"),
]


class ModuloSitios:
    """Módulo de registro de navegación y detección de dominios maliciosos. REF: SI-004"""

    def __init__(self):
        """Carga el índice de dominios maliciosos desde las blacklists disponibles."""
        self._ruta_log = Path(config.SITE_LOG_FILE)
        self.dominios_maliciosos: dict[str, dict] = {}

        self._cargar_dominios_maliciosos()
        log.info(f"Modulo de sitios iniciado. Registrando en: {self._ruta_log}")

    def _cargar_dominios_maliciosos(self) -> None:
        """REF: SI-005"""
        for ruta_relativa, categoria, fuente in ARCHIVOS_DOMINIOS:
            ruta = config.BASE_DIR / ruta_relativa
            try:
                with ruta.open(encoding="utf-8") as archivo:
                    for linea in archivo:
                        dominio = linea.strip().lower()
                        if not dominio or dominio.startswith("#"):
                            continue
                        if dominio not in self.dominios_maliciosos:
                            self.dominios_maliciosos[dominio] = {
                                "categoria": categoria,
                                "fuente": fuente,
                            }
            except FileNotFoundError:
                log.debug(f"Archivo de dominios no encontrado (aun): {ruta.name}")
            except OSError as e:
                log.error(f"Error al leer {ruta.name}: {e}")

        log.info(
            f"Base de dominios maliciosos cargada: "
            f"{len(self.dominios_maliciosos)} dominios unicos."
        )

    def _accion_recomendada(self, categoria: str) -> str:
        """REF: SI-006"""
        if "Phishing" in categoria:
            return "Bloquear dominio y alertar al usuario afectado"
        if "Malware" in categoria:
            return "Aislar equipo cliente de la red inmediatamente"
        if "Stalkerware" in categoria or "Spyware" in categoria:
            return "Revisar el equipo del usuario, posible vigilancia no autorizada"
        if "Cryptomining" in categoria:
            return "El equipo puede estar siendo usado para mineria sin consentimiento"
        if "Scam" in categoria or "Estafa" in categoria:
            return "Alertar al usuario sobre posible intento de fraude"
        return "Investigar actividad del cliente en la red"

    def _buscar_dominio(self, dominio: str) -> dict | None:
        """REF: SI-007"""
        if dominio in self.dominios_maliciosos:
            return self.dominios_maliciosos[dominio]

        partes = dominio.split(".")
        if len(partes) > 2:
            dominio_raiz = ".".join(partes[-2:])
            if dominio_raiz in self.dominios_maliciosos:
                return self.dominios_maliciosos[dominio_raiz]

        return None

    def _escribir_registro(self, ip_origen: str, dominio: str) -> None:
        """REF: SI-003"""
        if config.MODO_LOCAL:
            return

        try:
            if (
                self._ruta_log.exists()
                and self._ruta_log.stat().st_size > _MAX_SITIOS_LOG_BYTES
            ):
                ruta_rotada = self._ruta_log.parent / (self._ruta_log.name + ".1")
                self._ruta_log.rename(ruta_rotada)
                log.info(f"sitios - Log de sitios rotado: {ruta_rotada.name}")

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            linea = f"{timestamp} | {ip_origen} | {dominio}\n"
            with self._ruta_log.open("a", encoding="utf-8") as archivo:
                archivo.write(linea)
            log.debug(f"Sitio registrado: {ip_origen} -> {dominio}")
        except OSError as e:
            log.error(f"Error al escribir en log de sitios: {e}")

    def _extraer_dominio_dns(self, pkt) -> str | None:
        """Extrae el nombre de dominio de una consulta DNS (query, qr==0)."""
        try:
            dns = pkt["DNS"]
            if dns.qr != 0:
                return None
            if dns.qdcount < 1 or dns.qd is None:
                return None
            nombre = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
            return nombre if nombre else None
        except Exception as e:
            log.debug(f"Error al parsear DNS: {e}")
            return None

    def _extraer_host_http(self, pkt) -> str | None:
        """Extrae el header Host de una petición HTTP en texto plano."""
        try:
            payload = pkt["Raw"].load.decode("utf-8", errors="replace")
            coincidencia = re.search(
                r"^Host:\s*(.+)$", payload, re.IGNORECASE | re.MULTILINE
            )
            if coincidencia:
                return coincidencia.group(1).strip()
        except Exception as e:
            log.debug(f"Error al parsear HTTP: {e}")
        return None

    def procesar(self, pkt) -> None:
        """REF: SI-009"""
        if not pkt.haslayer("IP"):
            return

        ip_origen = pkt["IP"].src
        dominio_crudo = None

        if pkt.haslayer("DNS"):
            dominio_crudo = self._extraer_dominio_dns(pkt)

        elif pkt.haslayer("TCP") and pkt["TCP"].dport == 80 and pkt.haslayer("Raw"):
            dominio_crudo = self._extraer_host_http(pkt)

        if not dominio_crudo:
            return

        dominio = dominio_crudo.rstrip(".").lower()
        if dominio.startswith("www."):
            dominio = dominio[4:]

        if not dominio:
            return

        # REF: SI-002
        dominio = _sanitizar_para_log(dominio)
        if not dominio:
            return

        info = self._buscar_dominio(dominio)

        if info:
            if config.MODO_LOCAL:
                return

            categoria = info["categoria"]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            log.critical(
                f"DOMINIO MALICIOSO DETECTADO | "
                f"Cliente: {ip_origen} | "
                f"Dominio: {dominio} | "
                f"Tipo: {categoria} | "
                f"Fuente: {info['fuente']}"
            )

            detalles = {
                "Dominio Detectado": dominio,
                "Tipo de Amenaza": categoria,
                "Fuente de Inteligencia": info["fuente"],
                "IP del Cliente": ip_origen,
                "Accion Recomendada": self._accion_recomendada(categoria),
                "Timestamp": timestamp,
            }

            html = construir_html_alerta(
                titulo=f"Acceso a dominio malicioso detectado: {dominio}",
                detalles=detalles,
                nivel="EMERGENCIA",
            )
            enviar_alerta(
                asunto=f"ALERTA {categoria}: {dominio}",
                cuerpo_html=html,
            )
            reportar_evento(
                tipo="sitios",
                categoria=info["categoria"],
                fuente=info["fuente"],
                ip_origen=ip_origen,
                dominio=dominio,
            )
        else:
            self._escribir_registro(ip_origen, dominio)
