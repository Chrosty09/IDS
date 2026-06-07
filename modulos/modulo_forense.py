# IDS Institucional — modulo_forense — GNU/GPL v3

import html as html_module
import ipaddress

import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisRateLimitError

import config
from utils.logger import obtener_logger
from utils.mailer import construir_html_alerta, enviar_alerta

log = obtener_logger("forense")

_TIMEOUT_RED = 10


def _lookup_rdap(ip: str) -> dict:
    """REF: FO-001"""
    obj = IPWhois(ip)
    resultado = obj.lookup_rdap(depth=1)

    org = resultado.get("asn_description", "N/A")
    pais = resultado.get("asn_country_code", "N/A")
    red = resultado.get("network", {}).get("name", "N/A")

    emails_abuso: list[str] = []
    objetos = resultado.get("objects", {}) or {}
    for datos_obj in objetos.values():
        contacto = datos_obj.get("contact") or {}
        for entrada_email in contacto.get("email") or []:
            valor = entrada_email.get("value", "")
            if valor:
                emails_abuso.append(valor)

    return {
        "org": org,
        "pais": pais,
        "red": red,
        "emails_abuso": ", ".join(emails_abuso) if emails_abuso else "No disponible",
        "fuente": "RDAP (ipwhois)",
    }


def _lookup_ipinfo(ip: str) -> dict:
    """REF: FO-002"""
    url = f"https://ipinfo.io/{ip}/json"
    respuesta = requests.get(url, timeout=_TIMEOUT_RED)
    respuesta.raise_for_status()
    datos = respuesta.json()

    return {
        "org": datos.get("org", "N/A"),
        "pais": datos.get("country", "N/A"),
        "red": datos.get("hostname", "N/A"),
        "emails_abuso": datos.get("abuse", {}).get("email", "No disponible")
        if isinstance(datos.get("abuse"), dict)
        else "No disponible",
        "fuente": "ipinfo.io (fallback)",
    }


def investigar_ip(ip: str) -> None:
    """REF: FO-003"""
    if config.MODO_LOCAL:
        return

    # REF: FO-004
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
            log.warning(f"forense - IP {ip} no es pública, omitiendo consulta forense.")
            return
    except ValueError:
        log.warning(f"forense - IP malformada recibida: {repr(ip)}")
        return

    log.info(f"Iniciando investigacion forense para: {ip}")
    datos_registro: dict = {}

    try:
        datos_registro = _lookup_rdap(ip)
        log.info(f"Datos RDAP obtenidos para {ip}: org={datos_registro.get('org')}")
    except IPDefinedError:
        log.warning(f"La IP {ip} es privada o reservada; no se puede consultar RDAP.")
        return
    except WhoisRateLimitError:
        log.warning(f"Rate limit de RDAP alcanzado para {ip}. Usando fallback.")
    except Exception as e:
        log.warning(f"ipwhois fallo para {ip}: {e}. Intentando con ipinfo.io...")

    if not datos_registro:
        try:
            datos_registro = _lookup_ipinfo(ip)
            log.info(f"Datos de ipinfo.io obtenidos para {ip}")
        except requests.RequestException as e:
            log.error(f"Fallback ipinfo.io tambien fallo para {ip}: {e}")
            datos_registro = {
                "org": "No disponible",
                "pais": "No disponible",
                "red": "No disponible",
                "emails_abuso": "No disponible",
                "fuente": "Sin fuente (ambas consultas fallaron)",
            }

    # REF: FO-005
    ip_escapada = html_module.escape(str(ip))
    instrucciones = (
        f"1. Contactar al equipo de abuso del proveedor: {datos_registro.get('emails_abuso')}. "
        f"2. Adjuntar los logs del IDS (/home/kali/IDS/logs/bitacora.log) como evidencia. "
        f"3. Bloquear la IP {ip_escapada} en el firewall perimetral con: "
        f"  iptables -I FORWARD -d {ip_escapada} -j DROP &amp;&amp; "
        f"iptables -I OUTPUT -d {ip_escapada} -j DROP. "
        f"4. Documentar el incidente con timestamp y evidencia capturada."
    )

    detalles = {
        "IP investigada": ip,
        "Organizacion": datos_registro.get("org", "N/A"),
        "Pais": datos_registro.get("pais", "N/A"),
        "Red / Hostname": datos_registro.get("red", "N/A"),
        "Contactos de abuso": datos_registro.get("emails_abuso", "No disponible"),
        "Fuente de datos": datos_registro.get("fuente", "N/A"),
        "Acciones recomendadas": instrucciones,
    }

    html = construir_html_alerta(
        titulo=f"Informe forense de IP maliciosa: {ip}",
        detalles=detalles,
        nivel="EMERGENCIA",
    )
    enviar_alerta(
        asunto=f"Informe forense: {ip} ({datos_registro.get('org', 'org desconocida')})",
        cuerpo_html=html,
    )
    log.info(f"Informe forense enviado al administrador para IP: {ip}")
