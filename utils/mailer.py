# IDS Institucional — mailer — GNU/GPL v3

import html as html_module
import queue
import smtplib
import threading
import time
from collections import defaultdict
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config  # noqa: E402 – importado aquí para que MODO_LOCAL esté disponible
from utils.logger import obtener_logger

log = obtener_logger("mailer")

# ── cola resumen ──
_cola_resumen: list = []
_lock_cola = threading.Lock()
_timer_resumen: threading.Timer | None = None
_INTERVALO_RESUMEN_SEGUNDOS: int = 300  # Nivel 1: resumen periodico cada 5 minutos
_UMBRAL_ENVIO_INMEDIATO: int = 10  # Nivel 2: disparo inmediato al superar este numero

# ── cola smtp ──
_cola_correos: queue.Queue = queue.Queue()
_worker_activo: bool = False


def enviar_sincrono(asunto: str, cuerpo_html: str, destinatario: str = None) -> bool:
    """REF: MA-002"""
    destino = destinatario or config.ADMIN_EMAIL

    mensaje = MIMEMultipart("alternative")
    mensaje["Subject"] = f"[IDS {config.ORG_NAME}] {asunto}"
    mensaje["From"] = config.SMTP_USER
    mensaje["To"] = destino

    parte_html = MIMEText(cuerpo_html, "html", "utf-8")
    mensaje.attach(parte_html)

    try:
        with smtplib.SMTP_SSL(
            config.SMTP_HOST, config.SMTP_PORT, timeout=10
        ) as servidor:
            servidor.ehlo()
            servidor.login(config.SMTP_USER, config.SMTP_PASSWORD)
            servidor.sendmail(config.SMTP_USER, destino, mensaje.as_string())

        log.info(f"Correo enviado a {destino} | Asunto: {asunto}")
        return True

    except smtplib.SMTPAuthenticationError:
        log.error(
            "Fallo de autenticacion SMTP. Verifica SMTP_USER y SMTP_PASSWORD en .env"
        )
        return False
    except smtplib.SMTPException as e:
        log.error(f"Error SMTP al enviar correo: {e}")
        return False
    except OSError as e:
        log.error(f"Error de red al conectar con el servidor SMTP: {e}")
        return False


def _worker_correos() -> None:
    """Hilo daemon que consume la cola de correos pendientes."""
    while True:
        try:
            item = _cola_correos.get(timeout=5)
        except queue.Empty:
            continue

        try:
            enviar_sincrono(
                asunto=item["asunto"],
                cuerpo_html=item["cuerpo_html"],
                destinatario=item.get("destinatario"),
            )
        except Exception as e:
            log.error(
                f"Error inesperado en worker al enviar correo '{item.get('asunto')}': {e}"
            )
        finally:
            _cola_correos.task_done()
            time.sleep(2)


def _iniciar_worker() -> None:
    """REF: MA-004"""
    global _worker_activo
    if not _worker_activo:
        hilo = threading.Thread(
            target=_worker_correos,
            name="worker-correos",
            daemon=True,
        )
        hilo.start()
        _worker_activo = True
        log.debug("Worker de cola de correos iniciado.")


def enviar_alerta(asunto: str, cuerpo_html: str, destinatario: str = None) -> bool:
    """REF: MA-005"""
    if config.MODO_LOCAL:
        return True

    _iniciar_worker()

    _cola_correos.put(
        {
            "asunto": asunto,
            "cuerpo_html": cuerpo_html,
            "destinatario": destinatario,
        }
    )

    log.info(f"Correo encolado para envio: {asunto}")
    return True


def construir_html_alerta(
    titulo: str, detalles: dict, nivel: str = "ADVERTENCIA"
) -> str:
    """Genera el HTML estandarizado para los correos de alerta del IDS."""
    color_nivel = "#c0392b" if nivel == "EMERGENCIA" else "#e67e22"
    titulo = html_module.escape(str(titulo))
    filas_html = "".join(
        f"<tr><td style='padding:6px 12px;font-weight:bold;'>{html_module.escape(str(k))}</td>"
        f"<td style='padding:6px 12px;'>{html_module.escape(str(v))}</td></tr>"
        for k, v in detalles.items()
    )

    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <div style="max-width:600px;margin:auto;border:1px solid #ddd;border-radius:6px;overflow:hidden;">
        <div style="background:{color_nivel};padding:18px 24px;">
          <h2 style="color:#fff;margin:0;">IDS {config.ORG_NAME} - {nivel}</h2>
          <p style="color:#fff;margin:4px 0 0;">{titulo}</p>
        </div>
        <div style="padding:20px 24px;">
          <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#f5f5f5;">
              <th style="padding:6px 12px;text-align:left;">Campo</th>
              <th style="padding:6px 12px;text-align:left;">Valor</th>
            </tr>
            {filas_html}
          </table>
          <p style="margin-top:20px;font-size:12px;color:#888;">
            Generado automaticamente el {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            por el IDS Institucional
          </p>
        </div>
      </div>
    </body></html>
    """


# ── resumen por lotes ──


def _construir_html_resumen(alertas: list, es_inmediato: bool = False) -> str:
    """REF: MA-007"""
    color_header = "#c0392b" if es_inmediato else "#e67e22"
    titulo = (
        "Resumen Inmediato - Posible Escaneo de Red"
        if es_inmediato
        else "Resumen Periodico de Alertas"
    )
    subtitulo = (
        f"{len(alertas)} dispositivos no autorizados detectados — umbral de "
        f"{_UMBRAL_ENVIO_INMEDIATO} superado"
        if es_inmediato
        else f"{len(alertas)} eventos en los ultimos {_INTERVALO_RESUMEN_SEGUNDOS // 60} minutos"
    )

    por_categoria: dict[str, list] = defaultdict(list)
    for alerta in alertas:
        por_categoria[alerta["categoria"]].append(alerta)

    estilo_th = (
        "padding:7px 10px;text-align:left;"
        "background:#f0f0f0;font-size:12px;border-bottom:2px solid #ddd;"
    )
    estilo_tabla = "width:100%;border-collapse:collapse;margin-bottom:24px;"

    secciones_html = ""
    for categoria, items in por_categoria.items():
        columnas = list(items[0]["detalles"].keys())

        encabezados = f"<th style='{estilo_th}'>Timestamp</th>" + "".join(
            f"<th style='{estilo_th}'>{html_module.escape(str(col))}</th>"
            for col in columnas
        )

        filas = ""
        for idx, item in enumerate(items):
            fondo = "#f9f9f9" if idx % 2 == 0 else "#ffffff"
            estilo_td = (
                f"padding:6px 10px;font-size:12px;"
                f"border-bottom:1px solid #eee;background:{fondo};"
            )
            celdas = (
                f"<td style='{estilo_td}'>"
                f"{html_module.escape(str(item['timestamp']))}</td>"
            ) + "".join(
                f"<td style='{estilo_td}'>"
                f"{html_module.escape(str(item['detalles'].get(col, '')))}</td>"
                for col in columnas
            )
            filas += f"<tr>{celdas}</tr>"

        secciones_html += f"""
        <h3 style="margin:20px 0 8px;color:#444;font-size:14px;border-left:4px solid {color_header};padding-left:8px;">
          {html_module.escape(str(categoria))}
          <span style="font-weight:normal;color:#888;font-size:12px;">({len(items)} eventos)</span>
        </h3>
        <table style="{estilo_tabla}">
          <tr>{encabezados}</tr>
          {filas}
        </table>"""

    generado = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
      <div style="max-width:700px;margin:auto;border:1px solid #ddd;border-radius:6px;overflow:hidden;">
        <div style="background:{color_header};padding:18px 24px;">
          <h2 style="color:#fff;margin:0;">IDS {config.ORG_NAME} - {titulo}</h2>
          <p style="color:#fff;margin:4px 0 0;">{subtitulo}</p>
        </div>
        <div style="padding:20px 24px;">
          {secciones_html}
          <p style="margin-top:16px;font-size:11px;color:#aaa;">
            Generado automaticamente el {generado} por {config.ORG_NAME}
          </p>
        </div>
      </div>
    </body></html>
    """


def _enviar_resumen_pendiente() -> None:
    """REF: MA-008"""
    global _cola_resumen, _timer_resumen

    with _lock_cola:
        alertas_pendientes = list(_cola_resumen)
        _cola_resumen = []
        _timer_resumen = None

    if not alertas_pendientes:
        return

    es_inmediato = len(alertas_pendientes) >= _UMBRAL_ENVIO_INMEDIATO

    try:
        html = _construir_html_resumen(alertas_pendientes, es_inmediato)

        if es_inmediato:
            asunto = (
                f"[ATENCION] Resumen inmediato: {len(alertas_pendientes)} "
                f"dispositivos no autorizados detectados"
            )
        else:
            minutos = _INTERVALO_RESUMEN_SEGUNDOS // 60
            asunto = (
                f"Resumen de seguridad: {len(alertas_pendientes)} eventos "
                f"en los ultimos {minutos} minutos"
            )

        enviar_sincrono(asunto=asunto, cuerpo_html=html)
        log.info(
            f"Resumen {'inmediato' if es_inmediato else 'periodico'} enviado: "
            f"{len(alertas_pendientes)} alertas."
        )
    except Exception as e:
        log.error(f"Error al construir o enviar el resumen de alertas: {e}")


def encolar_alerta_resumen(categoria: str, detalles: dict) -> None:
    """REF: MA-009"""
    if config.MODO_LOCAL:
        return

    global _timer_resumen

    with _lock_cola:
        _cola_resumen.append(
            {
                "categoria": categoria,
                "detalles": detalles,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

        if len(_cola_resumen) >= _UMBRAL_ENVIO_INMEDIATO:
            log.warning(
                f"Umbral de {_UMBRAL_ENVIO_INMEDIATO} alertas alcanzado, "
                "enviando resumen inmediato."
            )
            if _timer_resumen is not None:
                _timer_resumen.cancel()
            _timer_resumen = None
        elif _timer_resumen is None or not _timer_resumen.is_alive():
            _timer_resumen = threading.Timer(
                _INTERVALO_RESUMEN_SEGUNDOS, _enviar_resumen_pendiente
            )
            _timer_resumen.daemon = True
            _timer_resumen.start()
            log.debug(
                f"Timer de resumen iniciado ({_INTERVALO_RESUMEN_SEGUNDOS}s). "
                f"Cola: {len(_cola_resumen)} evento(s)."
            )
            return
        else:
            log.debug(f"Alerta encolada. Cola: {len(_cola_resumen)} evento(s).")
            return

    # REF: MA-009
    hilo = threading.Thread(
        target=_enviar_resumen_pendiente,
        name="resumen-smtp-inmediato",
        daemon=True,
    )
    hilo.start()
