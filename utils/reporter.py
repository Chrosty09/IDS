# IDS Institucional — reporter — GNU/GPL v3

import os
import re
import threading
from datetime import datetime

import requests

import config
from utils.logger import obtener_logger

log = obtener_logger("reporter")


NETLIFY_INGEST_URL = os.getenv("NETLIFY_INGEST_URL", "")
IDS_API_KEY = os.getenv("IDS_API_KEY", "")


def _obtener_dispositivo_id() -> str:
    """REF: RE-001"""
    import uuid

    iface = getattr(config, "NETWORK_INTERFACE", None) or "eth0"
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
            if mac and mac != "00:00:00:00:00:00":
                return mac.lower()
    except OSError:
        pass

    try:
        net_path = "/sys/class/net"
        for iface in os.listdir(net_path):
            if iface == "lo":
                continue
            try:
                with open(f"{net_path}/{iface}/address") as f:
                    mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    return mac.lower()
            except OSError:
                continue
    except Exception:
        pass

    mac_int = uuid.getnode()
    return ":".join(f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


# REF: RE-002
DISPOSITIVO_ID: str = _obtener_dispositivo_id()


def reportar_evento(
    tipo: str,
    categoria: str = None,
    fuente: str = None,
    ip_origen: str = None,
    ip_destino: str = None,
    dominio: str = None,
    mac: str = None,
    detalles: dict = None,
) -> None:
    """Envía un evento al dashboard en la nube de forma asíncrona. REF: RE-003"""
    if config.MODO_LOCAL:
        return

    if not NETLIFY_INGEST_URL or not IDS_API_KEY:
        return

    hilo = threading.Thread(
        target=_enviar_en_hilo,
        args=(
            tipo,
            categoria,
            fuente,
            ip_origen,
            ip_destino,
            dominio,
            mac,
            detalles,
            DISPOSITIVO_ID,
        ),
        daemon=True,
    )
    hilo.start()


def _enviar_en_hilo(
    tipo,
    categoria,
    fuente,
    ip_origen,
    ip_destino,
    dominio,
    mac,
    detalles,
    dispositivo_id,
):
    """Funcion interna ejecutada en hilo separado."""
    payload = {
        "tipo": tipo,
        "categoria": categoria,
        "fuente": fuente,
        "ip_origen": ip_origen,
        "ip_destino": ip_destino,
        "dominio": dominio,
        "mac": mac,
        "detalles": detalles or {},
        "dispositivo_id": dispositivo_id,
    }

    headers = {
        "Content-Type": "application/json",
        "X-IDS-API-Key": IDS_API_KEY,
    }

    try:
        response = requests.post(
            NETLIFY_INGEST_URL,
            json=payload,
            headers=headers,
            timeout=8,
            verify=True,
        )
        if response.status_code == 200:
            log.debug(
                f"Evento reportado al dashboard: tipo={tipo} categoria={categoria}"
            )
        else:
            log.warning(
                f"Dashboard respondio {response.status_code} para evento tipo={tipo}"
            )
    except requests.exceptions.Timeout:
        log.warning(
            "Timeout al reportar evento al dashboard. El IDS continua operando."
        )
    except requests.exceptions.ConnectionError:
        log.warning("Sin conexion al dashboard. El IDS continua operando.")
    except Exception as e:
        log.error(f"Error inesperado al reportar evento: {e}")


def revocar_datos_dispositivo() -> tuple[bool, int]:
    """REF: RE-005"""
    if not config.NETLIFY_REVOCAR_URL or not config.IDS_API_KEY:
        log.warning(
            "NETLIFY_REVOCAR_URL o IDS_API_KEY no configurados; omitiendo borrado remoto."
        )
        return False, 0

    url = config.NETLIFY_REVOCAR_URL
    headers = {
        "Content-Type": "application/json",
        "X-IDS-API-Key": config.IDS_API_KEY,
    }
    body = {"dispositivo_id": DISPOSITIVO_ID}

    try:
        resp = requests.post(url, json=body, headers=headers, timeout=10, verify=True)
        if resp.ok:
            data = resp.json()
            eliminados = 0
            match = re.search(r"(\d+) registro", data.get("mensaje", ""))
            if match:
                eliminados = int(match.group(1))
            log.info(
                f"Datos eliminados de Supabase para dispositivo {DISPOSITIVO_ID} ({eliminados} registros)."
            )
            return True, eliminados
        else:
            log.warning(f"Netlify respondió {resp.status_code} al revocar datos.")
            return False, 0
    except requests.RequestException as e:
        log.error(f"Error al contactar Netlify para revocación: {e}")
        return False, 0
