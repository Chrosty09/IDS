# IDS Institucional — reporter — GNU/GPL v3

import os
import queue
import re
import threading
import time

import requests

import config
from utils.logger import obtener_logger

log = obtener_logger("reporter")

# REF: RE-006 — antes se lanzaba un hilo por evento: una ráfaga de alertas
# (p. ej. DNS hacia decenas de dominios maliciosos) generaba miles de hilos y
# conexiones HTTPS simultáneas, agotando los recursos del propio IDS. Ahora
# los eventos van a una cola acotada consumida por un número fijo de workers.
# Si la cola se llena, los eventos se descartan con aviso: la captura de
# paquetes (quien encola) nunca debe bloquearse ni crecer sin límite.
_NUM_WORKERS = 2
_MAX_COLA_EVENTOS = 200
_INTERVALO_AVISO_COLA_LLENA = 30  # segundos entre avisos de cola llena

_cola_eventos: queue.Queue = queue.Queue(maxsize=_MAX_COLA_EVENTOS)
_workers_iniciados = False
_lock_workers = threading.Lock()
_ultimo_aviso_llena = 0.0


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


def _aviso_cola_llena() -> None:
    """Advierte que la cola está llena, como máximo una vez cada 30 s: no
    convertir la alerta de saturación en otro flood del log."""
    global _ultimo_aviso_llena
    ahora = time.monotonic()
    if ahora - _ultimo_aviso_llena >= _INTERVALO_AVISO_COLA_LLENA:
        _ultimo_aviso_llena = ahora
        log.warning(
            f"Cola de reportes al dashboard llena ({_MAX_COLA_EVENTOS} eventos); "
            "los eventos nuevos se descartan hasta drenar la cola."
        )


def _iniciar_workers() -> None:
    """Arranca los workers de envío una sola vez. REF: RE-006"""
    global _workers_iniciados
    with _lock_workers:
        if _workers_iniciados:
            return
        for i in range(_NUM_WORKERS):
            hilo = threading.Thread(
                target=_worker_reporte, name=f"reporte-{i}", daemon=True
            )
            hilo.start()
        _workers_iniciados = True
        log.debug(f"Workers de reporte iniciados: {_NUM_WORKERS}")


def _worker_reporte() -> None:
    """Hilo daemon que consume la cola y envía los eventos al dashboard."""
    while True:
        try:
            payload = _cola_eventos.get(timeout=5)
        except queue.Empty:
            continue
        try:
            _enviar_evento(payload)
        finally:
            _cola_eventos.task_done()


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
    """Encola un evento para el dashboard (no bloquea). REF: RE-003"""
    if config.MODO_LOCAL:
        return

    if not config.NETLIFY_INGEST_URL or not config.IDS_API_KEY:
        return

    payload = {
        "tipo": tipo,
        "categoria": categoria,
        "fuente": fuente,
        "ip_origen": ip_origen,
        "ip_destino": ip_destino,
        "dominio": dominio,
        "mac": mac,
        "detalles": detalles or {},
        "dispositivo_id": DISPOSITIVO_ID,
    }

    _iniciar_workers()
    try:
        _cola_eventos.put_nowait(payload)
    except queue.Full:
        _aviso_cola_llena()


def _enviar_evento(payload: dict) -> None:
    """Envía un evento al dashboard (ejecutado por un worker, nunca en el
    hilo de captura)."""
    headers = {
        "Content-Type": "application/json",
        "X-IDS-API-Key": config.IDS_API_KEY,
    }

    try:
        response = requests.post(
            config.NETLIFY_INGEST_URL,
            json=payload,
            headers=headers,
            timeout=8,
            verify=True,
        )
        if response.status_code == 200:
            log.debug(
                f"Evento reportado al dashboard: tipo={payload['tipo']} "
                f"categoria={payload.get('categoria')}"
            )
        else:
            log.warning(
                f"Dashboard respondio {response.status_code} para evento "
                f"tipo={payload['tipo']}"
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
