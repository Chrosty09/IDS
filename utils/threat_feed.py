# IDS Institucional — threat_feed — GNU/GPL v3

import csv
import io
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

import config
from utils.logger import obtener_logger

log = obtener_logger("threat_feed")

_TIMEOUT_DESCARGA = 30

# REF: TF-001
_MAX_FEED_BYTES = 50 * 1024 * 1024

# ── feeds ──

FEEDS_IPS = [
    {
        "nombre": "feodo",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "destino": "blacklist/feodo_blacklist.csv",
        "tipo_parser": "csv_ip",
        "columna_ip": "dst_ip",
        "columna_malware": "malware",
        "columna_puerto": "dst_port",
        "categoria": "Botnet/C2",
    },
    {
        "nombre": "cins_army",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "destino": "blacklist/cins_blacklist.txt",
        "tipo_parser": "txt_ip",
        "categoria": "Amenaza General",
    },
    {
        "nombre": "blocklist_de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "destino": "blacklist/blocklist_de.txt",
        "tipo_parser": "txt_ip",
        "categoria": "Ataques/Brute Force",
    },
    {
        "nombre": "emerging_threats",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "destino": "blacklist/emerging_threats.txt",
        "tipo_parser": "txt_ip",
        "categoria": "Host Comprometido",
    },
]

FEEDS_DOMINIOS = [
    {
        "nombre": "urlhaus_agh",
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt",
        "destino": "blacklist/urlhaus_filter_agh.txt",
        "tipo_parser": "adguard",
        "categoria": "Malware (URLhaus)",
    },
    {
        "nombre": "scamblocklist",
        "url": "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt",
        "destino": "blacklist/scamblocklist_adguard.txt",
        "tipo_parser": "adguard",
        "categoria": "Scam/Estafa",
    },
    {
        "nombre": "hagezi_tif",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
        "destino": "blacklist/hagezi_tif.txt",
        "tipo_parser": "adguard",
        "categoria": "Threat Intelligence (Hagezi)",
    },
    {
        "nombre": "hagezi_hoster",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
        "destino": "blacklist/hagezi_hoster.txt",
        "tipo_parser": "adguard",
        "categoria": "Hosting Malicioso",
    },
    {
        "nombre": "antimalware_agh",
        "url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt",
        "destino": "blacklist/antimalware_agh.txt",
        "tipo_parser": "adguard",
        "categoria": "Malware",
    },
    {
        "nombre": "phishing_filter_agh",
        "url": "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
        "destino": "blacklist/phishing_filter_agh.txt",
        "tipo_parser": "adguard",
        "categoria": "Phishing",
    },
    {
        "nombre": "nocoin",
        "url": "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "destino": "blacklist/nocoin_hosts.txt",
        "tipo_parser": "hosts",
        "categoria": "Cryptomining",
    },
    {
        "nombre": "hacked_sites",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hosts",
        "destino": "blacklist/hacked_sites.txt",
        "tipo_parser": "hosts",
        "categoria": "Sitio Comprometido",
    },
    {
        "nombre": "stalkerware",
        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
        "destino": "blacklist/stalkerware.txt",
        "tipo_parser": "plain",
        "categoria": "Stalkerware/Spyware",
    },
    {
        "nombre": "shadowwhisperer_malware",
        "url": "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
        "destino": "blacklist/shadowwhisperer_malware.txt",
        "tipo_parser": "plain",
        "categoria": "Malware",
    },
    {
        "nombre": "phishing_army_extended",
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "destino": "blacklist/phishing_army_extended.txt",
        "tipo_parser": "plain",
        "categoria": "Phishing",
    },
    {
        "nombre": "urlhaus_plain",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "destino": "blacklist/urlhaus_domains.txt",
        "tipo_parser": "txt_url",
        "categoria": "Malware (URLhaus)",
    },
    {
        "nombre": "phishing_army",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "destino": "blacklist/phishing_army.txt",
        "tipo_parser": "plain",
        "categoria": "Phishing",
    },
    {
        "nombre": "openphish",
        "url": "https://openphish.com/feed.txt",
        "destino": "blacklist/openphish_domains.txt",
        "tipo_parser": "txt_url",
        "categoria": "Phishing (OpenPhish)",
    },
]


# ── parsers ──


def _parsear_adguard(linea: str) -> str:
    """REF: TF-003"""
    linea = linea.strip()
    if not linea or linea[0] in ("!", "#", "[", "@"):
        return ""
    if linea.startswith("||"):
        contenido = linea[2:]
        fin = contenido.find("^")
        dominio = contenido[:fin] if fin != -1 else contenido
        return dominio.lower().strip()
    return ""


def _parsear_hosts(linea: str) -> str:
    """REF: TF-004"""
    linea = linea.strip()
    if not linea or linea.startswith("#"):
        return ""
    campos = linea.split()
    if len(campos) < 2:
        return ""
    dominio = campos[1].lower()
    if dominio in ("localhost", "0.0.0.0", "127.0.0.1"):
        return ""
    return dominio


def _parsear_plain(linea: str) -> str:
    """REF: TF-005"""
    linea = linea.strip()
    if not linea or linea[0] in ("#", "!", "["):
        return ""
    return linea.lower()


# ── descarga ──


def descargar_feed(feed: dict) -> int:
    """REF: TF-006"""
    nombre = feed["nombre"]
    categoria = feed["categoria"]
    tipo = feed["tipo_parser"]
    ruta_destino = config.BASE_DIR / feed["destino"]
    ruta_destino.parent.mkdir(parents=True, exist_ok=True)

    log.info(f"[{nombre}] Descargando feed '{categoria}' desde: {feed['url']}")

    # REF: TF-006
    try:
        with requests.get(
            feed["url"], timeout=_TIMEOUT_DESCARGA, stream=True
        ) as respuesta:
            respuesta.raise_for_status()

            content_type = respuesta.headers.get("Content-Type", "").lower()
            if "text/html" in content_type:
                log.warning(
                    f"[{nombre}] El servidor devolvió HTML "
                    f"(Content-Type: {content_type}). Feed ignorado."
                )
                return 0

            chunks: list[bytes] = []
            tamano_total = 0
            for chunk in respuesta.iter_content(chunk_size=65536):
                tamano_total += len(chunk)
                if tamano_total > _MAX_FEED_BYTES:
                    log.error(
                        f"[{nombre}] Feed supera el límite de "
                        f"{_MAX_FEED_BYTES // (1024 * 1024)} MB. "
                        "Descarga cancelada (posible feed comprometido o error de servidor)."
                    )
                    return 0
                chunks.append(chunk)
    except requests.exceptions.ConnectionError as e:
        log.error(f"[{nombre}] Error de conexion: {e}")
        return 0
    except requests.exceptions.Timeout:
        log.error(f"[{nombre}] Timeout al descargar ({_TIMEOUT_DESCARGA}s).")
        return 0
    except requests.exceptions.HTTPError as e:
        log.error(f"[{nombre}] Error HTTP {e.response.status_code}: {e}")
        return 0
    except requests.exceptions.RequestException as e:
        log.error(f"[{nombre}] Error de red inesperado: {e}")
        return 0

    contenido_bytes = b"".join(chunks)
    contenido_texto = contenido_bytes.decode("utf-8", errors="replace")

    primera_linea = contenido_texto.lstrip()[:15].lower()
    if primera_linea.startswith("<!doctype") or primera_linea.startswith("<html"):
        log.warning(
            f"[{nombre}] Contenido parece HTML (primera línea: {primera_linea!r}). Feed ignorado."
        )
        return 0

    try:
        if tipo == "csv_ip":
            with ruta_destino.open("wb") as archivo:
                archivo.write(contenido_bytes)

            col_ip = feed.get("columna_ip", "dst_ip")
            lineas_datos = (
                l for l in contenido_texto.splitlines() if not l.startswith("#")
            )
            lector = csv.DictReader(lineas_datos)
            ips = {
                fila.get(col_ip, "").strip()
                for fila in lector
                if fila.get(col_ip, "").strip()
            }
            conteo = len(ips)

        elif tipo == "txt_ip":
            ips: set[str] = set()
            for linea in contenido_texto.splitlines():
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                ip = linea.split()[0]
                if ip:
                    ips.add(ip)
            conteo = len(ips)
            with ruta_destino.open("w", encoding="utf-8") as archivo:
                archivo.write("\n".join(sorted(ips)) + "\n")

        elif tipo == "txt_url":
            dominios: set[str] = set()
            for linea in contenido_texto.splitlines():
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                parsed = urlparse(linea)
                dominio = parsed.netloc.lower()
                if not dominio:
                    dominio = linea.lower()
                dominio = dominio.split(":")[0]
                if dominio:
                    dominios.add(dominio)
            conteo = len(dominios)
            with ruta_destino.open("w", encoding="utf-8") as archivo:
                archivo.write("\n".join(sorted(dominios)) + "\n")

        elif tipo == "adguard":
            dominios: set[str] = set()
            for linea in contenido_texto.splitlines():
                d = _parsear_adguard(linea)
                if d:
                    dominios.add(d)
            conteo = len(dominios)
            with ruta_destino.open("w", encoding="utf-8") as archivo:
                archivo.write("\n".join(sorted(dominios)) + "\n")

        elif tipo == "hosts":
            dominios: set[str] = set()
            for linea in contenido_texto.splitlines():
                d = _parsear_hosts(linea)
                if d:
                    dominios.add(d)
            conteo = len(dominios)
            with ruta_destino.open("w", encoding="utf-8") as archivo:
                archivo.write("\n".join(sorted(dominios)) + "\n")

        elif tipo == "plain":
            dominios: set[str] = set()
            for linea in contenido_texto.splitlines():
                d = _parsear_plain(linea)
                if d:
                    dominios.add(d)
            conteo = len(dominios)
            with ruta_destino.open("w", encoding="utf-8") as archivo:
                archivo.write("\n".join(sorted(dominios)) + "\n")

        else:
            log.error(f"[{nombre}] Tipo de parser desconocido: '{tipo}'")
            return 0

    except OSError as e:
        log.error(f"[{nombre}] Error al guardar en disco: {e}")
        return 0

    log.info(
        f"[{nombre}] OK — {conteo} entradas unicas guardadas en: {ruta_destino.name}"
    )
    return conteo


def _necesita_actualizacion(ruta_archivo: Path) -> bool:
    """REF: TF-007"""
    if not ruta_archivo.exists():
        return True
    if ruta_archivo.stat().st_size == 0:
        return True
    antiguedad = datetime.now().timestamp() - ruta_archivo.stat().st_mtime
    return antiguedad > 86400


def descargar_todos_los_feeds(forzar: bool = False) -> dict:
    """REF: TF-008"""
    total_ips = 0
    total_dominios = 0
    descargados = 0
    omitidos = 0

    todos_los_feeds = [("ip", feed) for feed in FEEDS_IPS] + [
        ("dominio", feed) for feed in FEEDS_DOMINIOS
    ]

    log.info(
        f"Iniciando actualizacion de {len(todos_los_feeds)} feeds "
        f"({'forzada' if forzar else 'con cache de 24h'})..."
    )

    for tipo_feed, feed in todos_los_feeds:
        ruta = config.BASE_DIR / feed["destino"]

        if not forzar and not _necesita_actualizacion(ruta):
            log.debug(f"[{feed['nombre']}] Feed vigente, omitiendo descarga.")
            omitidos += 1
            continue

        conteo = descargar_feed(feed)
        descargados += 1
        if tipo_feed == "ip":
            total_ips += conteo
        else:
            total_dominios += conteo

    log.info(
        f"Actualizacion completada — "
        f"Descargados: {descargados} | Omitidos (vigentes): {omitidos} | "
        f"IPs unicas nuevas: {total_ips} | Dominios unicos nuevos: {total_dominios}"
    )
    return {
        "ips": total_ips,
        "dominios": total_dominios,
        "descargados": descargados,
        "omitidos": omitidos,
    }


def forzar_actualizacion() -> dict:
    """Descarga todos los feeds ignorando el cache local."""
    log.info("Actualizacion forzada iniciada por el administrador.")
    return descargar_todos_los_feeds(forzar=True)


def main() -> None:
    """Punto de entrada para ejecutar el descargador de forma independiente"""
    resumen = descargar_todos_los_feeds()
    print(
        f"\n[OK] Feeds procesados — "
        f"Descargados: {resumen['descargados']} | "
        f"Omitidos (vigentes): {resumen['omitidos']} | "
        f"IPs: {resumen['ips']} | Dominios: {resumen['dominios']}\n"
    )


if __name__ == "__main__":
    main()
