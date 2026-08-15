# IDS Institucional — gui — GNU/GPL v3

import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
from PyQt6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import config
from modulos.modulo_whitelist import validar_entrada_whitelist
from utils import securefs
from utils.logger import obtener_logger

log = obtener_logger("gui")

# ── rutas ──
# REF: GUI-022 — el estado escribible vive en STATE_DIR (config.CF-005), no
# junto al código que corre como root.
_CONSENT_FILE = config.CONSENT_FILE
_PRIVACY_FILE = config.BASE_DIR / "docs" / "aviso_privacidad.txt"
_INIT_FILE = config.INIT_FILE

# ── estado ──
consentimiento_activo: bool = False
timestamp_consentimiento: str | None = None
modo: str = "sin_consentimiento"

# ── colores ──
# REF: GUI-002
C = {
    "bg": "#0D1117",
    "bg2": "#161B22",
    "bg3": "#21262D",
    "border": "#30363D",
    "text": "#E6EDF3",
    "text2": "#8B949E",
    "accent": "#00D9A3",
    "danger": "#FF4466",
    "warning": "#F0883E",
    "info": "#58A6FF",
    "green": "#00C853",
    "red": "#D32F2F",
    "teal": "#00BCD4",
    "row_th": "#2D0A0A",
    "row_wl": "#2D1F00",
}

STYLESHEET = f"""
QWidget {{
    background-color: {C["bg"]};
    color: {C["text"]};
    font-family: Consolas, "Courier New", monospace;
    font-size: 10pt;
}}
QMainWindow, QDialog {{
    background-color: {C["bg"]};
}}
QTabWidget::pane {{
    border: 1px solid {C["border"]};
    background-color: {C["bg2"]};
}}
QTabBar::tab {{
    background: {C["bg3"]};
    color: {C["text2"]};
    padding: 8px 18px;
    border: 1px solid {C["border"]};
    border-bottom: none;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {C["bg2"]};
    color: {C["text"]};
    border-bottom: 2px solid {C["accent"]};
}}
QTabBar::tab:hover:!selected {{
    background: {C["bg"]};
    color: {C["text"]};
}}
QPushButton {{
    background-color: {C["bg3"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    border-radius: 4px;
    padding: 6px 16px;
}}
QPushButton:hover {{
    background-color: #2D333B;
    border-color: {C["text2"]};
}}
QPushButton:pressed {{
    background-color: {C["bg"]};
}}
QPushButton:disabled {{
    color: {C["text2"]};
    border-color: {C["bg3"]};
}}
QPushButton[clase="verde"] {{
    background-color: #1B4D2E;
    color: {C["green"]};
    border-color: {C["green"]};
    font-weight: bold;
}}
QPushButton[clase="verde"]:hover {{
    background-color: #245C37;
}}
QPushButton[clase="rojo"] {{
    background-color: #4D1B1B;
    color: {C["danger"]};
    border-color: {C["danger"]};
    font-weight: bold;
}}
QPushButton[clase="rojo"]:hover {{
    background-color: #5C2020;
}}
QPushButton[clase="secundario"] {{
    background-color: transparent;
    color: {C["info"]};
    border: none;
    padding: 4px 8px;
    text-decoration: underline;
}}
QTableWidget {{
    background-color: {C["bg2"]};
    gridline-color: {C["border"]};
    border: 1px solid {C["border"]};
    alternate-background-color: {C["bg3"]};
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: #1C3A5E;
    color: {C["text"]};
}}
QHeaderView::section {{
    background-color: {C["bg3"]};
    color: {C["text2"]};
    border: 1px solid {C["border"]};
    padding: 6px 8px;
    font-weight: bold;
}}
QTextEdit, QLineEdit {{
    background-color: {C["bg2"]};
    color: {C["text"]};
    border: 1px solid {C["border"]};
    border-radius: 4px;
    padding: 4px;
    selection-background-color: #1C3A5E;
}}
QScrollBar:vertical {{
    background: {C["bg3"]};
    width: 10px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background: {C["border"]};
    border-radius: 5px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {C["text2"]};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollArea {{
    border: none;
    background-color: {C["bg2"]};
}}
QLabel {{
    background: transparent;
}}
QCheckBox {{
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {C["border"]};
    border-radius: 3px;
    background: {C["bg3"]};
}}
QCheckBox::indicator:checked {{
    background: {C["accent"]};
    border-color: {C["accent"]};
}}
QProgressBar {{
    background-color: {C["bg3"]};
    border: none;
    border-radius: 2px;
    height: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {C["accent"]};
    border-radius: 2px;
}}
QMenu {{
    background-color: {C["bg2"]};
    border: 1px solid {C["border"]};
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 20px;
    color: {C["text"]};
}}
QMenu::item:selected {{
    background-color: {C["bg3"]};
}}
QMenu::separator {{
    height: 1px;
    background: {C["border"]};
    margin: 4px 8px;
}}
"""


# ── dispositivo id ──


def _leer_mac_local() -> str:
    import uuid

    try:
        iface = getattr(config, "NETWORK_INTERFACE", "eth0")
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
            if mac and mac != "00:00:00:00:00:00":
                return mac.lower()
    except OSError:
        pass
    mac_int = uuid.getnode()
    return ":".join(f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


_IDS_DISPOSITIVO_ID: str = _leer_mac_local()


# ── helpers ──


def _cargar_estado_consentimiento() -> None:
    """Lee .ids_consent y actualiza el estado global de consentimiento."""
    global consentimiento_activo, timestamp_consentimiento, modo
    # REF: GUI-022 — lectura con O_NOFOLLOW: un symlink no cuenta como
    # consentimiento.
    contenido = securefs.leer_seguro(_CONSENT_FILE)
    if contenido is not None:
        ts = contenido.strip()
        if ts:
            consentimiento_activo = True
            timestamp_consentimiento = ts
            modo = "con_consentimiento"
            return
    consentimiento_activo = False
    timestamp_consentimiento = None
    modo = "sin_consentimiento"


def _guardar_consentimiento(ts: str) -> None:
    """Persiste el timestamp de consentimiento en disco en formato ISO 8601."""
    try:
        securefs.escribir_privado(_CONSENT_FILE, ts)
    except OSError as e:
        log.error(f"No se pudo guardar consentimiento: {e}")


def _eliminar_consentimiento() -> None:
    """Elimina el archivo de consentimiento del disco."""
    try:
        securefs.eliminar_seguro(_CONSENT_FILE)
    except OSError as e:
        log.error(f"No se pudo eliminar archivo de consentimiento: {e}")


def _es_primera_ejecucion() -> bool:
    """Retorna True si el IDS nunca ha sido ejecutado en este equipo."""
    return not securefs.existe_sin_seguir(_INIT_FILE)


def _marcar_inicializado() -> None:
    """Crea el marcador de primera ejecución con la fecha actual."""
    try:
        securefs.escribir_privado(
            _INIT_FILE,
            datetime.now().isoformat(sep=" ", timespec="seconds"),
        )
    except OSError as e:
        log.error(f"No se pudo crear marcador de inicialización: {e}")


def _leer_politica() -> str:
    """Lee docs/aviso_privacidad.txt o retorna un placeholder informativo."""
    try:
        if _PRIVACY_FILE.exists():
            return _PRIVACY_FILE.read_text(encoding="utf-8")
    except OSError:
        pass
    return (
        "AVISO DE PRIVACIDAD\n\n"
        "El archivo de política de privacidad no fue encontrado.\n\n"
        "El administrador del sistema debe colocar el aviso de privacidad en:\n"
        f"  {_PRIVACY_FILE}\n\n"
        "Contacte al administrador del IDS para obtener el documento completo."
    )


def _crear_icono_circulo(color: str, size: int = 22, visible: bool = True) -> QIcon:
    """REF: GUI-020"""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    if visible:
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(color)))
        p.setPen(Qt.PenStyle.NoPen)
        margen = 2
        p.drawEllipse(margen, margen, size - margen * 2, size - margen * 2)
        p.end()
    return QIcon(px)


# ── monitoreo ──


class MonitoreoThread(QThread):
    """Hilo de monitoreo del log en tiempo real. REF: GUI-007"""

    nueva_alerta = pyqtSignal(dict)

    def __init__(self, parent=None):
        """Inicializa el hilo con el flag de control en False."""
        super().__init__(parent)
        self._running = False

    def run(self) -> None:
        """Bucle principal del hilo. Espera a que exista el archivo de log,"""
        self._running = True
        ruta = config.LOG_FILE

        # Esperar a que el archivo exista (el IDS puede no haber iniciado aún)
        while self._running and not Path(ruta).exists():
            time.sleep(2)

        if not self._running:
            return

        try:
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)  # Posicionarse al final del archivo
                while self._running:
                    linea = f.readline()
                    if linea:
                        self._procesar_linea(linea.strip())
                    else:
                        time.sleep(1)
        except OSError as e:
            log.error(f"MonitoreoThread: error leyendo log: {e}")

    def _procesar_linea(self, linea: str) -> None:
        """Evalúa una línea del log y emite una alerta si contiene keywords"""
        if not linea:
            return
        es_critica = "[CRITICAL" in linea
        es_warning = "[WARNING" in linea and "no autorizado" in linea.lower()
        if not (es_critica or es_warning):
            return
        alerta = self._parsear_linea(linea)
        if alerta:
            self.nueva_alerta.emit(alerta)

    def _parsear_linea(self, linea: str) -> dict | None:
        """Extrae los campos relevantes de una línea de log del IDS."""
        # Estructura idéntica a los registros de Supabase
        alerta: dict = {
            "timestamp": "",
            "tipo": "",
            "categoria": None,
            "fuente": None,
            "ip_origen": None,
            "ip_destino": None,
            "dominio": None,
            "mac": None,
            "detalles": "{}",
            "dispositivo_id": _IDS_DISPOSITIVO_ID,
            "linea_completa": linea,
        }

        partes = linea.split("  ", 1)
        if partes:
            alerta["timestamp"] = partes[0].strip()

        if "IP MALICIOSA DETECTADA" in linea or "COMUNICACION CON C2" in linea:
            alerta["tipo"] = "threat_intel"
            alerta["categoria"] = "Botnet/C2"
            m = re.search(r"Interno:\s*(\d+\.\d+\.\d+\.\d+)", linea)
            if m:
                alerta["ip_origen"] = m.group(1)
            m = re.search(r"Externo:\s*(\d+\.\d+\.\d+\.\d+)", linea)
            if not m:
                m = re.search(r"C2:\s*(\d+\.\d+\.\d+\.\d+)", linea)
            if m:
                alerta["ip_destino"] = m.group(1)
            m2 = re.search(r"Tipo:\s*([^|]+)", linea)
            if m2:
                alerta["categoria"] = m2.group(1).strip()
            m3 = re.search(r"Fuente:\s*([^|]+)", linea)
            if m3:
                alerta["fuente"] = m3.group(1).strip()

        elif "DOMINIO MALICIOSO DETECTADO" in linea:
            alerta["tipo"] = "sitios"
            alerta["categoria"] = "Dominio malicioso"
            m = re.search(r"Cliente:\s*(\d+\.\d+\.\d+\.\d+)", linea)
            if m:
                alerta["ip_origen"] = m.group(1)
            m = re.search(r"Dominio:\s*([^\s|]+)", linea)
            if m:
                alerta["dominio"] = m.group(1)
            m2 = re.search(r"Tipo:\s*([^|]+)", linea)
            if m2:
                alerta["categoria"] = m2.group(1).strip()
            m3 = re.search(r"Fuente:\s*([^|]+)", linea)
            if m3:
                alerta["fuente"] = m3.group(1).strip()

        elif "no autorizado" in linea.lower():
            alerta["tipo"] = "whitelist"
            alerta["categoria"] = "Dispositivo no autorizado"
            # fuente queda None — igual que en Supabase
            m = re.search(r"IP '(\d+\.\d+\.\d+\.\d+)'", linea)
            if not m:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", linea)
            if m:
                alerta["ip_origen"] = m.group(1)
            m = re.search(r"MAC '([0-9A-Fa-f:]{17})'", linea)
            if m:
                alerta["mac"] = m.group(1).upper()
        else:
            return None

        return alerta

    def detener(self) -> None:
        """Señaliza al bucle interno que debe detenerse limpiamente."""
        self._running = False


# ── notificación ──


class AlertaEmergente(QWidget):
    """Notificación emergente sin bordes con auto-cierre. REF: GUI-009"""

    def __init__(self, alerta: dict, ventana_principal, parent=None):
        """REF: GUI-009"""
        super().__init__(
            parent,
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint,
        )
        self.alerta = alerta
        self.ventana_principal = ventana_principal
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._setup_ui()
        self._posicionar_y_animar()
        self._iniciar_timer_cierre()

    def _setup_ui(self) -> None:
        """Construye el contenido visual de la notificación emergente."""
        tipo = self.alerta.get("tipo", "")
        color_borde = (
            C["danger"] if tipo in ("threat_intel", "dominio") else C["warning"]
        )

        self.setFixedSize(360, 140)
        self.setStyleSheet(
            f"background-color: {C['bg2']};"
            f"border: 2px solid {color_borde};"
            f"border-radius: 6px;"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 8)
        layout.setSpacing(4)

        # Encabezado
        lbl_tipo = QLabel(f"⚠  {self.alerta.get('tipo', '').upper().replace('_', ' ')}")
        lbl_tipo.setTextFormat(
            Qt.TextFormat.PlainText
        )  # Evitar renderizado HTML con datos de red
        lbl_tipo.setStyleSheet(
            f"color: {color_borde}; font-weight: bold; font-size: 9pt;"
        )
        layout.addWidget(lbl_tipo)

        # Categoría y fuente
        lbl_cat = QLabel(
            f"{self.alerta.get('categoria', '')}  ·  {self.alerta.get('fuente', '')}"
        )
        lbl_cat.setTextFormat(
            Qt.TextFormat.PlainText
        )  # Evitar renderizado HTML con datos de red
        lbl_cat.setStyleSheet(f"color: {C['text2']}; font-size: 9pt;")
        layout.addWidget(lbl_cat)

        # Indicador principal según el tipo de alerta
        # NOTA DE SEGURIDAD: este valor proviene directamente de paquetes de red.
        # setTextFormat(PlainText) previene que Qt interprete HTML inyectado en
        # un dominio DNS o IP malformada (ej: <img src="file:///etc/passwd">).
        tipo_alerta = self.alerta.get("tipo", "")
        if tipo_alerta == "threat_intel":
            indicador = self.alerta.get("ip_destino") or self.alerta.get(
                "ip_origen", ""
            )
        elif tipo_alerta == "sitios":
            indicador = self.alerta.get("dominio") or self.alerta.get("ip_origen", "")
        else:
            indicador = self.alerta.get("ip_origen") or self.alerta.get("mac", "")
        lbl_ip = QLabel(indicador)
        lbl_ip.setTextFormat(
            Qt.TextFormat.PlainText
        )  # Crítico: datos de paquetes de red
        lbl_ip.setStyleSheet(f"color: {C['text']}; font-weight: bold;")
        layout.addWidget(lbl_ip)

        # Nota según consentimiento
        nota = (
            "Esta alerta ha sido registrada y enviada al administrador."
            if consentimiento_activo
            else "⚠ Muestre esta alerta a su administrador."
        )
        lbl_nota = QLabel(nota)
        lbl_nota.setTextFormat(Qt.TextFormat.PlainText)
        lbl_nota.setStyleSheet(f"color: {C['text2']}; font-size: 8pt;")
        lbl_nota.setWordWrap(True)
        layout.addWidget(lbl_nota)

        # Barra de progreso para el cierre automático
        self._barra = QProgressBar()
        self._barra.setRange(0, 150)
        self._barra.setValue(150)
        self._barra.setTextVisible(False)
        self._barra.setFixedHeight(4)
        self._barra.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color_borde}; }}"
        )
        layout.addWidget(self._barra)

        # Botones
        btn_layout = QHBoxLayout()
        btn_detalle = QPushButton("Ver detalle")
        btn_detalle.clicked.connect(self._ver_detalle)
        btn_cerrar = QPushButton("Cerrar")
        btn_cerrar.clicked.connect(self.close)
        btn_layout.addWidget(btn_detalle)
        btn_layout.addWidget(btn_cerrar)
        layout.addLayout(btn_layout)

    def _posicionar_y_animar(self) -> None:
        """Posiciona la ventana en la esquina inferior derecha y la desliza desde la derecha."""
        pantalla = QApplication.primaryScreen().geometry()
        w, h = 360, 140
        margen = 12
        final_x = pantalla.width() - w - margen
        final_y = pantalla.height() - h - margen - 48

        self.move(pantalla.width(), final_y)
        self.show()

        self._anim = QPropertyAnimation(self, b"pos")
        self._anim.setDuration(350)
        self._anim.setStartValue(QPoint(pantalla.width(), final_y))
        self._anim.setEndValue(QPoint(final_x, final_y))
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.start()

    def _iniciar_timer_cierre(self) -> None:
        """Inicia el temporizador de auto-cierre (15 s) y la barra de progreso."""
        self._ticks = 0
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        """Actualiza la barra de progreso y cierra la ventana al llegar a 0."""
        self._ticks += 1
        self._barra.setValue(150 - self._ticks)
        if self._ticks >= 150:
            self._timer.stop()
            self.close()

    def _ver_detalle(self) -> None:
        """Abre el diálogo de detalle y cierra la notificación emergente."""
        self.close()
        dlg = DetalleAlertaDialog(self.alerta, self.ventana_principal)
        dlg.exec()


# ── diálogos ──


class PrimerEjecucionDialog(QDialog):
    """Diálogo de primera ejecución con política de privacidad. REF: GUI-011"""

    def __init__(self, ventana_principal, parent=None):
        """REF: GUI-011"""
        super().__init__(parent)
        self._ventana_principal = ventana_principal
        self.setWindowTitle("Bienvenido al IDS Institucional — Política de privacidad")
        self.setFixedSize(620, 560)
        self.setStyleSheet(STYLESHEET)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowCloseButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 16)
        layout.setSpacing(12)

        # Encabezado
        lbl_titulo = QLabel("Bienvenido al IDS Institucional")
        lbl_titulo.setStyleSheet(
            f"font-size: 14pt; font-weight: bold; color: {C['accent']};"
        )
        lbl_titulo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_titulo)

        lbl_instruccion = QLabel(
            "Antes de continuar, lea la política de privacidad completa.\n"
            "Los botones se habilitarán al llegar al final del documento."
        )
        lbl_instruccion.setStyleSheet(f"color: {C['text2']}; font-size: 9pt;")
        lbl_instruccion.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_instruccion.setWordWrap(True)
        layout.addWidget(lbl_instruccion)

        # Área desplazable con el texto de privacidad
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        contenido = QLabel(_leer_politica())
        contenido.setWordWrap(True)
        contenido.setContentsMargins(14, 14, 14, 14)
        contenido.setStyleSheet(f"color: {C['text']}; background: {C['bg2']};")
        self._scroll.setWidget(contenido)
        layout.addWidget(self._scroll)
        self._scroll.verticalScrollBar().valueChanged.connect(self._on_scroll)

        # Indicador de progreso de lectura
        self._lbl_progreso = QLabel(
            "↓  Desplace el texto hasta el final para continuar"
        )
        self._lbl_progreso.setStyleSheet(
            f"color: {C['warning']}; font-size: 8pt; padding: 2px;"
        )
        self._lbl_progreso.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._lbl_progreso)

        # Botones
        btn_layout = QHBoxLayout()
        self._btn_rechazar = QPushButton("No acepto — Continuar en modo local")
        self._btn_rechazar.setProperty("clase", "rojo")
        self._btn_rechazar.setEnabled(False)
        self._btn_rechazar.clicked.connect(self._rechazar)

        self._btn_aceptar = QPushButton("Acepto y otorgo mi consentimiento")
        self._btn_aceptar.setProperty("clase", "verde")
        self._btn_aceptar.setEnabled(False)
        self._btn_aceptar.clicked.connect(self._aceptar)

        btn_layout.addWidget(self._btn_rechazar)
        btn_layout.addWidget(self._btn_aceptar)
        layout.addLayout(btn_layout)

        # Si el texto no requiere scroll, habilitar de inmediato
        QTimer.singleShot(200, self._verificar_scroll_innecesario)

    def _on_scroll(self, valor: int) -> None:
        """Habilita los botones cuando el usuario llega al final del texto."""
        maximo = self._scroll.verticalScrollBar().maximum()
        if maximo == 0 or valor >= maximo - 10:
            self._habilitar_botones()

    def _verificar_scroll_innecesario(self) -> None:
        """Si el texto cabe sin desplazamiento, habilita los botones directamente."""
        if self._scroll.verticalScrollBar().maximum() == 0:
            self._habilitar_botones()

    def _habilitar_botones(self) -> None:
        """Activa ambos botones y actualiza el indicador visual."""
        if self._btn_aceptar.isEnabled():
            return
        self._btn_aceptar.setEnabled(True)
        self._btn_rechazar.setEnabled(True)
        self._lbl_progreso.setText(
            "✓  Ha llegado al final del documento. Elija una opción."
        )
        self._lbl_progreso.setStyleSheet(
            f"color: {C['accent']}; font-size: 8pt; padding: 2px;"
        )

    def _aceptar(self) -> None:
        """Guarda el consentimiento, marca el sistema como inicializado y actualiza la UI."""
        ts = datetime.now().isoformat(sep=" ", timespec="seconds")
        _guardar_consentimiento(ts)
        _marcar_inicializado()
        self._ventana_principal._actualizar_modo("con_consentimiento", ts)
        self.accept()

    def _rechazar(self) -> None:
        """Marca el sistema como inicializado sin otorgar consentimiento (modo local)."""
        _marcar_inicializado()
        self._ventana_principal._actualizar_modo("sin_consentimiento")
        self.accept()


class VisorPoliticaDialog(QDialog):
    """Diálogo de solo lectura que muestra la política de privacidad completa."""

    def __init__(self, parent=None):
        """Inicializa el visor cargando el texto desde disco."""
        super().__init__(parent)
        self.setWindowTitle("Política de privacidad")
        self.setFixedSize(600, 500)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        texto = QTextEdit()
        texto.setPlainText(_leer_politica())
        texto.setReadOnly(True)
        texto.setFont(QFont("Consolas", 9))
        layout.addWidget(texto)

        btn = QPushButton("Cerrar")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignRight)


class FlujoConsentimientoDialog(QDialog):
    """Diálogo para otorgar consentimiento posterior a la primera ejecución. REF: GUI-012"""

    consentimiento_otorgado = pyqtSignal(str)

    def __init__(self, parent=None):
        """Inicializa el diálogo con el botón de aceptar deshabilitado."""
        super().__init__(parent)
        self.setWindowTitle("Política de privacidad y consentimiento")
        self.setFixedSize(600, 500)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        lbl = QLabel("Lea la política de privacidad completa para continuar:")
        lbl.setStyleSheet(f"color: {C['text2']};")
        layout.addWidget(lbl)

        # Área desplazable con el texto de privacidad
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        contenido = QLabel(_leer_politica())
        contenido.setWordWrap(True)
        contenido.setContentsMargins(12, 12, 12, 12)
        contenido.setStyleSheet(f"color: {C['text']}; background: {C['bg2']};")
        self._scroll.setWidget(contenido)
        layout.addWidget(self._scroll)

        # Conectar el scroll al habilitador del botón
        self._scroll.verticalScrollBar().valueChanged.connect(self._on_scroll)

        # Botones
        btn_layout = QHBoxLayout()
        self._btn_aceptar = QPushButton("Acepto y otorgo mi consentimiento")
        self._btn_aceptar.setProperty("clase", "verde")
        self._btn_aceptar.setEnabled(False)
        self._btn_aceptar.clicked.connect(self._aceptar)
        btn_cancelar = QPushButton("Cancelar")
        btn_cancelar.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancelar)
        btn_layout.addWidget(self._btn_aceptar)
        layout.addLayout(btn_layout)

        # Si el contenido no requiere scroll, habilitar de inmediato
        QTimer.singleShot(200, self._verificar_scroll_innecesario)

    def _on_scroll(self, valor: int) -> None:
        """Habilita el botón cuando el usuario llega al final del texto."""
        maximo = self._scroll.verticalScrollBar().maximum()
        if maximo == 0 or valor >= maximo - 10:
            self._btn_aceptar.setEnabled(True)

    def _verificar_scroll_innecesario(self) -> None:
        """Si el texto cabe sin scroll, habilita el botón directamente."""
        if self._scroll.verticalScrollBar().maximum() == 0:
            self._btn_aceptar.setEnabled(True)

    def _aceptar(self) -> None:
        """Guarda el consentimiento y cierra el diálogo emitiendo la señal."""
        ts = datetime.now().isoformat(sep=" ", timespec="seconds")
        _guardar_consentimiento(ts)
        self.consentimiento_otorgado.emit(ts)
        self.accept()


class FlujoRevocacionDialog(QDialog):
    """Diálogo para revocar el consentimiento del usuario. REF: GUI-013"""

    revocacion_confirmada = pyqtSignal()

    def __init__(self, ventana_principal, parent=None):
        """REF: GUI-013"""
        super().__init__(parent)
        self.ventana_principal = ventana_principal
        self.setWindowTitle("Revocar consentimiento")
        self.setFixedSize(480, 340)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Texto explicativo
        texto = QLabel(
            "Al revocar su consentimiento ocurrirá lo siguiente de forma inmediata:\n\n"
            "  • Todos sus registros en la base de datos serán eliminados permanentemente\n"
            "  • Los archivos de log locales del IDS serán destruidos\n"
            "  • El sistema continuará en modo local sin guardar ningún dato\n"
            "  • Puede otorgar su consentimiento nuevamente en cualquier momento"
        )
        texto.setWordWrap(True)
        texto.setStyleSheet(f"color: {C['text']}; line-height: 1.5;")
        layout.addWidget(texto)

        separador = QFrame()
        separador.setFrameShape(QFrame.Shape.HLine)
        separador.setStyleSheet(f"color: {C['border']};")
        layout.addWidget(separador)

        # Checkbox de confirmación
        self._chk = QCheckBox(
            "Entiendo que esta acción eliminará mis datos de forma permanente"
        )
        self._chk.toggled.connect(self._on_checkbox)
        layout.addWidget(self._chk)

        layout.addStretch()

        # Botones
        btn_layout = QHBoxLayout()
        btn_cancelar = QPushButton("Cancelar")
        btn_cancelar.clicked.connect(self.reject)
        self._btn_confirmar = QPushButton("Confirmar revocación")
        self._btn_confirmar.setProperty("clase", "rojo")
        self._btn_confirmar.setEnabled(False)
        self._btn_confirmar.clicked.connect(self._confirmar)
        btn_layout.addWidget(btn_cancelar)
        btn_layout.addWidget(self._btn_confirmar)
        layout.addLayout(btn_layout)

    def _on_checkbox(self, marcado: bool) -> None:
        """Habilita o deshabilita el botón de confirmación según el checkbox."""
        self._btn_confirmar.setEnabled(marcado)

    def _confirmar(self) -> None:
        """Ejecuta la revocación y cierra el diálogo."""
        self._ejecutar_revocacion()
        self.revocacion_confirmada.emit()
        self.accept()

    def _ejecutar_revocacion(self) -> None:
        """Realiza todas las acciones de la revocación: contacta la función Netlify"""
        # 1. Eliminar datos en Supabase via Netlify Function
        from utils.reporter import revocar_datos_dispositivo

        # REF: GUI-024 — el contacto del responsable sale de la configuración,
        # no de un email hardcodeado en el código.
        contacto = f" ({config.ADMIN_EMAIL})" if config.ADMIN_EMAIL else ""

        exito_remoto, eliminados = revocar_datos_dispositivo()

        # 2. Eliminar archivos de log locales
        for ruta in [config.LOG_FILE, config.SITE_LOG_FILE]:
            try:
                if Path(ruta).exists():
                    os.remove(ruta)
                    log.info(f"Log eliminado: {ruta}")
            except OSError as e:
                log.error(f"Error al eliminar log {ruta}: {e}")

        # 3. Eliminar archivo de consentimiento
        _eliminar_consentimiento()

        # 4. Actualizar estado en la ventana principal
        self.ventana_principal._actualizar_modo("sin_consentimiento")

        # 5. Generar comprobante de revocación (refleja el resultado real)
        if exito_remoto:
            resultado_txt = (
                f"Resultado: {eliminados} registros eliminados del panel remoto.\n"
            )
        else:
            resultado_txt = (
                "Resultado: ADVERTENCIA - no se pudo confirmar el borrado remoto.\n"
                "        Los logs locales fueron destruidos. Reintente la revocacion\n"
                f"        remota o contacte al responsable{contacto}.\n"
            )

        ts_comprobante = datetime.now().strftime("%Y%m%d_%H%M%S")
        ruta_comprobante = config.STATE_DIR / f".revocacion_{ts_comprobante}.txt"
        try:
            securefs.escribir_privado(
                ruta_comprobante,
                f"COMPROBANTE DE REVOCACIÓN DE CONSENTIMIENTO\n"
                f"{'=' * 50}\n"
                f"Fecha y hora: {datetime.now().isoformat()}\n"
                f"Acción: El usuario revocó su consentimiento y solicitó la\n"
                f"        eliminación permanente de sus datos personales.\n"
                f"{resultado_txt}",
            )
        except OSError as e:
            log.error(f"Error al generar comprobante: {e}")

        # 6. Notificar al usuario
        if exito_remoto:
            QMessageBox.information(
                self,
                "Revocación completada",
                "Su consentimiento ha sido revocado exitosamente.\n\n"
                f"Se eliminaron {eliminados} registros del panel remoto y los\n"
                "logs locales fueron destruidos.\n"
                "El IDS continúa en modo local sin registrar datos.\n\n"
                f"Comprobante generado en: {ruta_comprobante.name}",
            )
        else:
            QMessageBox.warning(
                self,
                "Revocación parcial",
                "Sus logs locales fueron destruidos y el IDS continúa en modo\n"
                "local, pero NO se pudo confirmar el borrado de sus datos en el\n"
                "panel remoto.\n\n"
                "Reintente la revocación remota cuando haya conexión o contacte\n"
                f"al responsable{contacto}.\n\n"
                f"Comprobante generado en: {ruta_comprobante.name}",
            )


class ConfirmacionBorradoDialog(QDialog):
    """Diálogo de confirmación de borrado permanente por texto. REF: GUI-014"""

    def __init__(self, parent=None):
        """Inicializa el diálogo con el botón de eliminación deshabilitado."""
        super().__init__(parent)
        self.setWindowTitle("Confirmar eliminación permanente")
        self.setFixedSize(460, 260)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        aviso = QLabel(
            "Esta acción eliminará permanentemente todos los archivos de log del IDS.\n"
            "Los registros eliminados no podrán recuperarse.\n"
            "Esta acción es IRREVERSIBLE."
        )
        aviso.setWordWrap(True)
        aviso.setStyleSheet(f"color: {C['danger']};")
        layout.addWidget(aviso)

        lbl_instruccion = QLabel(
            'Escriba "BORRAR" en el campo de abajo para confirmar:'
        )
        lbl_instruccion.setStyleSheet(f"color: {C['text2']};")
        layout.addWidget(lbl_instruccion)

        self._campo = QLineEdit()
        self._campo.setPlaceholderText("Escriba BORRAR aquí")
        self._campo.textChanged.connect(self._on_texto_cambiado)
        layout.addWidget(self._campo)

        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_cancelar = QPushButton("Cancelar")
        btn_cancelar.clicked.connect(self.reject)
        self._btn_eliminar = QPushButton("Eliminar permanentemente")
        self._btn_eliminar.setProperty("clase", "rojo")
        self._btn_eliminar.setEnabled(False)
        self._btn_eliminar.clicked.connect(self.accept)
        btn_layout.addWidget(btn_cancelar)
        btn_layout.addWidget(self._btn_eliminar)
        layout.addLayout(btn_layout)

    def _on_texto_cambiado(self, texto: str) -> None:
        """Habilita el botón solo cuando el campo contiene exactamente 'BORRAR'."""
        self._btn_eliminar.setEnabled(texto == "BORRAR")


class DetalleAlertaDialog(QDialog):
    """Muestra todos los campos de una alerta en formato legible."""

    def __init__(self, alerta: dict, ventana_principal, parent=None):
        """REF: GUI-021"""
        super().__init__(parent)
        self.setWindowTitle("Detalle de alerta")
        self.setFixedSize(500, 400)
        self.setStyleSheet(STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        texto = QTextEdit()
        texto.setReadOnly(True)
        texto.setFont(QFont("Consolas", 9))

        lineas = ["═" * 50, "  DETALLE DE ALERTA DE SEGURIDAD", "═" * 50, ""]
        for clave, valor in alerta.items():
            if clave != "linea_completa":
                lineas.append(f"  {clave.upper().replace('_', ' ')}: {valor}")
        lineas += ["", "─" * 50, "  REGISTRO ORIGINAL:", "─" * 50]
        lineas.append(alerta.get("linea_completa", ""))
        lineas += ["", "─" * 50]

        nota = (
            "  Puede revocar su participación desde la pestaña Estado."
            if consentimiento_activo
            else "  ⚠ Muestre esta alerta a su administrador para que tome acciones."
        )
        lineas.append(nota)
        texto.setPlainText("\n".join(lineas))
        layout.addWidget(texto)

        btn = QPushButton("Cerrar")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignRight)


# ── ventana principal ──


class VentanaPrincipal(QMainWindow):
    """Ventana principal con 5 pestañas de control del IDS. REF: GUI-015"""

    modo_cambiado = pyqtSignal(str)

    def __init__(self):
        """Inicializa la ventana y carga el estado de consentimiento. El IDS arranca
        explícitamente con iniciar_ids() para garantizar que el consentimiento
        haya sido registrado antes de capturar cualquier tráfico."""
        super().__init__()
        _cargar_estado_consentimiento()
        self._alertas: list[dict] = []
        self._proceso_ids: subprocess.Popen | None = None
        self._monitoreo = MonitoreoThread(self)
        self._monitoreo.nueva_alerta.connect(self._on_nueva_alerta)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Construye toda la interfaz gráfica de la ventana principal."""
        self.setWindowTitle("IDS Institucional - Panel de Control")
        self.setMinimumSize(820, 560)
        self.resize(960, 600)
        self.setStyleSheet(STYLESHEET)

        tabs = QTabWidget()
        tabs.addTab(self._crear_pestaña_estado(), "Estado y Consentimiento")
        tabs.addTab(self._crear_pestaña_alertas(), "Alertas")
        tabs.addTab(self._crear_pestaña_whitelist(), "Whitelist")
        tabs.addTab(self._crear_pestaña_logs(), "Logs internos")
        tabs.addTab(self._crear_pestaña_acerca(), "Acerca de")
        self.setCentralWidget(tabs)

    # ── Pestaña 1 ──────────────────────────────────────────────────────────────

    def _crear_pestaña_estado(self) -> QWidget:
        """Construye la pestaña de estado y consentimiento con su indicador visual."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        # Área de indicador: círculo + textos descriptivos
        fila_indicador = QHBoxLayout()
        fila_indicador.setSpacing(20)

        self._indicador = QLabel()
        self._indicador.setFixedSize(90, 90)
        self._indicador.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fila_indicador.addWidget(self._indicador, 0)

        textos = QVBoxLayout()
        textos.setSpacing(6)
        self._lbl_icono_estado = QLabel()
        self._lbl_icono_estado.setStyleSheet("font-size: 22pt;")
        self._lbl_titulo_estado = QLabel()
        self._lbl_titulo_estado.setStyleSheet("font-size: 13pt; font-weight: bold;")
        self._lbl_desc_estado = QLabel()
        self._lbl_desc_estado.setWordWrap(True)
        self._lbl_desc_estado.setStyleSheet(f"color: {C['text2']}; font-size: 9pt;")
        textos.addWidget(self._lbl_icono_estado)
        textos.addWidget(self._lbl_titulo_estado)
        textos.addWidget(self._lbl_desc_estado)
        fila_indicador.addLayout(textos, 1)
        layout.addLayout(fila_indicador)

        # Separador
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C['border']};")
        layout.addWidget(sep)

        # Botón principal de consentimiento
        self._btn_consentimiento = QPushButton()
        self._btn_consentimiento.setFixedHeight(42)
        self._btn_consentimiento.clicked.connect(self._on_btn_consentimiento)
        layout.addWidget(self._btn_consentimiento)

        # Botón secundario de política
        btn_politica = QPushButton("Ver política de privacidad completa")
        btn_politica.setProperty("clase", "secundario")
        btn_politica.clicked.connect(self._ver_politica)
        layout.addWidget(btn_politica, alignment=Qt.AlignmentFlag.AlignLeft)

        # Timestamp de consentimiento
        self._lbl_ts = QLabel()
        self._lbl_ts.setStyleSheet(f"color: {C['text2']}; font-size: 8pt;")
        layout.addWidget(self._lbl_ts)

        layout.addStretch()
        self._actualizar_vista_estado()
        return w

    def _actualizar_vista_estado(self) -> None:
        """Actualiza todos los widgets de la pestaña Estado según el modo actual."""
        if modo == "con_consentimiento":
            color_circ = C["green"]
            icono = "✓"
            titulo = "Monitoreando activamente"
            desc = (
                "El IDS está registrando eventos y enviando alertas al administrador."
            )
            self._btn_consentimiento.setText("Revocar mi participación")
            self._btn_consentimiento.setProperty("clase", "rojo")
            ts_texto = (
                f"Consentimiento otorgado el: {timestamp_consentimiento}"
                if timestamp_consentimiento
                else ""
            )
        elif modo == "local":
            color_circ = C["teal"]
            icono = "◉"
            titulo = "Modo local activo"
            desc = (
                "Detectando amenazas localmente. Sin registro ni transmisión de datos."
            )
            self._btn_consentimiento.setText(
                "Quiero participar - Otorgar consentimiento"
            )
            self._btn_consentimiento.setProperty("clase", "verde")
            ts_texto = ""
        else:
            color_circ = C["red"]
            icono = "✗"
            titulo = "Consentimiento requerido"
            desc = (
                "El IDS opera en modo local. No se almacena ni transmite ningún dato."
            )
            self._btn_consentimiento.setText(
                "Quiero participar - Otorgar consentimiento"
            )
            self._btn_consentimiento.setProperty("clase", "verde")
            ts_texto = ""

        # Redibujar el círculo indicador
        px = QPixmap(80, 80)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor(color_circ)))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(4, 4, 72, 72)
        p.end()
        self._indicador.setPixmap(px)
        self._lbl_icono_estado.setText(icono)
        self._lbl_titulo_estado.setText(titulo)
        self._lbl_titulo_estado.setStyleSheet(
            f"font-size: 13pt; font-weight: bold; color: {color_circ};"
        )
        self._lbl_desc_estado.setText(desc)
        self._lbl_ts.setText(ts_texto)

        # Forzar refresco del estilo del botón (necesario en PyQt6 para propiedades dinámicas)
        self._btn_consentimiento.style().unpolish(self._btn_consentimiento)
        self._btn_consentimiento.style().polish(self._btn_consentimiento)

    def _on_btn_consentimiento(self) -> None:
        """Abre el diálogo apropiado según el modo actual."""
        if modo == "con_consentimiento":
            dlg = FlujoRevocacionDialog(self)
            dlg.exec()
        else:
            dlg = FlujoConsentimientoDialog(self)
            dlg.consentimiento_otorgado.connect(
                lambda ts: self._actualizar_modo("con_consentimiento", ts)
            )
            dlg.exec()

    def _ver_politica(self) -> None:
        """Abre el visor de política de privacidad en modo solo lectura."""
        VisorPoliticaDialog(self).exec()

    # ── Pestaña 2 ──────────────────────────────────────────────────────────────

    def _crear_pestaña_alertas(self) -> QWidget:
        """Construye la pestaña de alertas con tabla dinámica y nota contextual."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self._tabla_alertas = QTableWidget(0, 10)
        self._tabla_alertas.setHorizontalHeaderLabels(
            [
                "Timestamp",
                "Tipo",
                "Categoría",
                "IP Origen",
                "IP Destino",
                "Dominio",
                "MAC",
                "Fuente",
                "Detalles",
                "Dispositivo ID",
            ]
        )
        self._tabla_alertas.setColumnWidth(0, 155)
        self._tabla_alertas.setColumnWidth(1, 80)
        self._tabla_alertas.setColumnWidth(2, 140)
        self._tabla_alertas.setColumnWidth(3, 120)
        self._tabla_alertas.setColumnWidth(4, 120)
        self._tabla_alertas.setColumnWidth(5, 140)
        self._tabla_alertas.setColumnWidth(6, 130)
        self._tabla_alertas.setColumnWidth(7, 90)
        self._tabla_alertas.setColumnWidth(8, 80)
        self._tabla_alertas.setColumnWidth(9, 130)
        self._tabla_alertas.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._tabla_alertas.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._tabla_alertas.verticalHeader().setVisible(False)
        self._tabla_alertas.setAlternatingRowColors(False)
        self._tabla_alertas.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self._tabla_alertas.doubleClicked.connect(self._on_doble_clic_alerta)
        layout.addWidget(self._tabla_alertas)

        # Nota contextual
        self._lbl_nota_alertas = QLabel()
        self._lbl_nota_alertas.setWordWrap(True)
        self._lbl_nota_alertas.setStyleSheet(
            f"color: {C['text2']}; font-size: 8pt; padding: 4px;"
        )
        self._actualizar_nota_alertas()
        layout.addWidget(self._lbl_nota_alertas)

        btn_limpiar = QPushButton("Limpiar alertas de esta sesión")
        btn_limpiar.clicked.connect(self._limpiar_alertas)
        layout.addWidget(btn_limpiar, alignment=Qt.AlignmentFlag.AlignRight)

        return w

    def _actualizar_nota_alertas(self) -> None:
        """Actualiza el texto de la nota según el modo de consentimiento."""
        if not hasattr(self, "_lbl_nota_alertas"):
            return
        if consentimiento_activo:
            self._lbl_nota_alertas.setText(
                "Puede revocar su participación en cualquier momento desde la pestaña Estado."
            )
        else:
            self._lbl_nota_alertas.setText(
                "⚠  Estas alertas no están siendo registradas. "
                "Muestre esta ventana a su administrador para que tome las acciones necesarias."
            )

    def _agregar_fila_alerta(self, alerta: dict) -> None:
        """Inserta una nueva fila en la tabla con el color correspondiente al tipo."""
        tipo = alerta.get("tipo", "")
        fila = self._tabla_alertas.rowCount()
        self._tabla_alertas.insertRow(fila)

        valores = [
            alerta.get("timestamp", ""),
            tipo,
            alerta.get("categoria", ""),
            alerta.get("ip_origen", "") or "",
            alerta.get("ip_destino", "") or "",
            alerta.get("dominio", "") or "",
            alerta.get("mac", "") or "",
            alerta.get("fuente", "") or "",
            alerta.get("detalles", "") or "{}",
            alerta.get("dispositivo_id", "") or "",
        ]
        for col, valor in enumerate(valores):
            item = QTableWidgetItem(str(valor))
            item.setTextAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
            )
            if tipo in ("threat_intel", "sitios"):
                item.setBackground(QColor(C["row_th"]))
            elif tipo == "whitelist":
                item.setBackground(QColor(C["row_wl"]))
            self._tabla_alertas.setItem(fila, col, item)

        self._tabla_alertas.scrollToBottom()

    def _on_doble_clic_alerta(self) -> None:
        """Abre el diálogo de detalle para la alerta seleccionada."""
        fila = self._tabla_alertas.currentRow()
        if 0 <= fila < len(self._alertas):
            DetalleAlertaDialog(self._alertas[fila], self).exec()

    def _limpiar_alertas(self) -> None:
        """Vacía la tabla y la lista interna de alertas de la sesión."""
        self._tabla_alertas.setRowCount(0)
        self._alertas.clear()

    # ── Pestaña 3 — Whitelist ─────────────────────────────────────────────────

    def _crear_pestaña_whitelist(self) -> QWidget:
        """Construye la pestaña de edición de la whitelist de dispositivos."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        btn_agregar = QPushButton("+ Agregar fila")
        btn_agregar.clicked.connect(self._whitelist_agregar_fila)
        btn_eliminar = QPushButton("- Eliminar seleccionada")
        btn_eliminar.setProperty("clase", "rojo")
        btn_eliminar.clicked.connect(self._whitelist_eliminar_fila)
        btn_guardar = QPushButton("Guardar cambios")
        btn_guardar.setProperty("clase", "verde")
        btn_guardar.clicked.connect(self._whitelist_guardar)
        btn_recargar = QPushButton("Recargar archivo")
        btn_recargar.clicked.connect(self._whitelist_cargar)
        toolbar.addWidget(btn_agregar)
        toolbar.addWidget(btn_eliminar)
        toolbar.addStretch()
        toolbar.addWidget(btn_recargar)
        toolbar.addWidget(btn_guardar)
        layout.addLayout(toolbar)

        self._tabla_whitelist = QTableWidget(0, 3)
        self._tabla_whitelist.setHorizontalHeaderLabels(["IP", "MAC", "Descripción"])
        self._tabla_whitelist.setColumnWidth(0, 160)
        self._tabla_whitelist.setColumnWidth(1, 170)
        self._tabla_whitelist.horizontalHeader().setStretchLastSection(True)
        self._tabla_whitelist.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._tabla_whitelist.verticalHeader().setVisible(False)
        self._tabla_whitelist.setAlternatingRowColors(False)
        layout.addWidget(self._tabla_whitelist)

        nota = QLabel(
            "Doble clic en una celda para editarla.  "
            "Los cambios toman efecto después de guardar y reiniciar el IDS."
        )
        nota.setStyleSheet(f"color: {C['text2']}; font-size: 8pt; padding: 4px;")
        nota.setWordWrap(True)
        layout.addWidget(nota)

        self._whitelist_cargar()
        return w

    def _whitelist_cargar(self) -> None:
        """Lee whitelist.txt y llena la tabla, omitiendo comentarios y líneas vacías."""
        self._tabla_whitelist.setRowCount(0)
        try:
            lineas = (
                Path(config.WHITELIST_FILE).read_text(encoding="utf-8").splitlines()
            )
        except OSError:
            return
        for linea in lineas:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(",", 2)
            fila = self._tabla_whitelist.rowCount()
            self._tabla_whitelist.insertRow(fila)
            for col in range(3):
                valor = partes[col].strip() if col < len(partes) else ""
                self._tabla_whitelist.setItem(fila, col, QTableWidgetItem(valor))

    def _whitelist_agregar_fila(self) -> None:
        """Agrega una fila vacía al final y pone el cursor en la primera celda."""
        fila = self._tabla_whitelist.rowCount()
        self._tabla_whitelist.insertRow(fila)
        for col in range(3):
            self._tabla_whitelist.setItem(fila, col, QTableWidgetItem(""))
        self._tabla_whitelist.scrollToBottom()
        self._tabla_whitelist.editItem(self._tabla_whitelist.item(fila, 0))

    def _whitelist_eliminar_fila(self) -> None:
        """Elimina la fila actualmente seleccionada."""
        fila = self._tabla_whitelist.currentRow()
        if fila >= 0:
            self._tabla_whitelist.removeRow(fila)

    def _whitelist_guardar(self) -> None:
        """Valida el formato de cada fila (REF: GUI-023) y serializa la tabla
        de vuelta a whitelist.txt conservando el encabezado."""
        lineas = [
            "# whitelist.txt - Dispositivos autorizados en la red",
            "# Formato: IP,MAC,DESCRIPCION",
            "# Las lineas que comienzan con # son comentarios y se ignoran",
            "",
        ]
        errores = []
        for fila in range(self._tabla_whitelist.rowCount()):

            def _txt(col):
                item = self._tabla_whitelist.item(fila, col)
                return item.text().strip() if item else ""

            ip, mac, desc = _txt(0), _txt(1), _txt(2)
            if not ip and not mac and not desc:
                continue  # fila totalmente vacía: no se escribe ni se valida

            problema = validar_entrada_whitelist(ip, mac)
            if problema:
                errores.append(f"Fila {fila + 1}: {problema}")
                continue
            lineas.append(f"{ip},{mac},{desc}")

        # REF: GUI-023 — no persistir entradas que el módulo no reconocería
        if errores:
            QMessageBox.warning(
                self,
                "Whitelist inválida",
                "Corrige estos errores antes de guardar:\n\n"
                + "\n".join(f"  • {e}" for e in errores[:12]),
            )
            return

        try:
            securefs.escribir_privado(
                config.WHITELIST_FILE, "\n".join(lineas) + "\n"
            )
            QMessageBox.information(
                self,
                "Guardado",
                "Whitelist guardada correctamente.\n"
                "Reinicia el IDS para que los cambios tomen efecto.",
            )
        except OSError as e:
            QMessageBox.warning(
                self, "Error al guardar", f"No se pudo escribir whitelist.txt:\n{e}"
            )

    # ── Pestaña 4 — Logs internos ─────────────────────────────────────────────

    def _crear_pestaña_logs(self) -> QWidget:
        """Construye la pestaña de logs internos con visor y controles."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self._visor_log = QTextEdit()
        self._visor_log.setReadOnly(True)
        self._visor_log.setFont(QFont("Consolas", 9))
        self._visor_log.setStyleSheet(
            f"background-color: {C['bg']}; color: {C['text']};"
        )
        layout.addWidget(self._visor_log)

        btns = QHBoxLayout()
        btn_actualizar = QPushButton("Actualizar")
        btn_actualizar.clicked.connect(self._cargar_log)

        self._btn_exportar = QPushButton("Exportar log...")
        self._btn_exportar.setEnabled(consentimiento_activo)
        self._btn_exportar.setToolTip(
            "" if consentimiento_activo else "Requiere consentimiento activo"
        )
        self._btn_exportar.clicked.connect(self._exportar_log)

        btn_borrar = QPushButton("Borrar logs permanentemente")
        btn_borrar.setProperty("clase", "rojo")
        btn_borrar.clicked.connect(self._borrar_logs)

        btns.addWidget(btn_actualizar)
        btns.addWidget(self._btn_exportar)
        btns.addStretch()
        btns.addWidget(btn_borrar)
        layout.addLayout(btns)

        self._cargar_log()
        return w

    def _cargar_log(self) -> None:
        """Lee el archivo de bitácora y lo muestra en el visor."""
        try:
            if Path(config.LOG_FILE).exists():
                contenido = Path(config.LOG_FILE).read_text(
                    encoding="utf-8", errors="replace"
                )
                self._visor_log.setPlainText(contenido)
                self._visor_log.moveCursor(
                    self._visor_log.textCursor().MoveOperation.End
                )
            else:
                self._visor_log.setPlainText("(El archivo de log aún no existe)")
        except OSError as e:
            self._visor_log.setPlainText(f"Error al leer log: {e}")

    def _exportar_log(self) -> None:
        """Abre un diálogo para guardar una copia del log en una ruta elegida por el usuario."""
        ruta, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar log",
            "bitacora_ids.log",
            "Archivos de log (*.log);;Todos (*)",
        )
        if ruta:
            try:
                contenido = Path(config.LOG_FILE).read_text(
                    encoding="utf-8", errors="replace"
                )
                Path(ruta).write_text(contenido, encoding="utf-8")
                QMessageBox.information(
                    self, "Exportación exitosa", f"Log guardado en:\n{ruta}"
                )
            except OSError as e:
                QMessageBox.warning(self, "Error", f"No se pudo exportar el log:\n{e}")

    def _borrar_logs(self) -> None:
        """Muestra el diálogo de confirmación y elimina los logs si se confirma."""
        dlg = ConfirmacionBorradoDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            errores = []
            for ruta in [config.LOG_FILE, config.SITE_LOG_FILE]:
                try:
                    if Path(ruta).exists():
                        os.remove(ruta)
                except OSError as e:
                    errores.append(str(e))
            self._visor_log.clear()
            # Reiniciar el IDS si está vivo para que el FileHandler suelte el
            # inode del archivo recién borrado y empiece uno nuevo.
            if self._proceso_ids and self._proceso_ids.poll() is None:
                self._reiniciar_ids()
            if errores:
                QMessageBox.warning(self, "Advertencia", "\n".join(errores))
            else:
                QMessageBox.information(
                    self, "Logs eliminados", "Los archivos de log han sido eliminados."
                )

    # ── Pestaña 5 — Acerca de ─────────────────────────────────────────────────

    def _crear_pestaña_acerca(self) -> QWidget:
        """Construye la pestaña informativa con los datos del proyecto y equipo."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)

        area = QScrollArea()
        area.setWidgetResizable(True)
        contenedor = QWidget()
        v = QVBoxLayout(contenedor)
        v.setContentsMargins(40, 30, 40, 30)
        v.setSpacing(4)
        v.addStretch()

        def _lbl(texto: str, estilo: str = "") -> QLabel:
            l = QLabel(texto)
            l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            l.setWordWrap(True)
            if estilo:
                l.setStyleSheet(estilo)
            return l

        v.addWidget(
            _lbl(
                "IDS Institucional v1.0",
                f"font-size: 16pt; font-weight: bold; color: {C['accent']};",
            )
        )
        v.addWidget(
            _lbl(
                "Sistema de Detección de Intrusos",
                f"font-size: 11pt; color: {C['text2']};",
            )
        )
        v.addWidget(_lbl(" "))
        v.addWidget(
            _lbl(
                "Universidad Autónoma de Aguascalientes",
                f"font-size: 11pt; color: {C['info']};",
            )
        )
        v.addWidget(_lbl("Seguridad en Sistemas", f"color: {C['text2']};"))
        v.addWidget(_lbl(" "))

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C['border']};")
        v.addWidget(sep)
        v.addWidget(_lbl(" "))

        v.addWidget(
            _lbl("Equipo de desarrollo:", f"color: {C['text2']}; font-size: 9pt;")
        )
        for nombre in [
            "Oscar Manuel García Rodríguez",
            "Carlos Franco Acosta",
            "Saúl Álvarez Gaspar",
        ]:
            v.addWidget(_lbl(nombre, f"color: {C['text']};"))

        v.addWidget(_lbl(" "))
        v.addWidget(_lbl("Supervisor: Arturo Ocampo Silva", f"color: {C['text2']};"))
        v.addWidget(_lbl(" "))

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet(f"color: {C['border']};")
        v.addWidget(sep2)
        v.addWidget(_lbl(" "))

        v.addWidget(
            _lbl(
                "Licencia: GNU General Public License v3.0",
                f"color: {C['text2']}; font-size: 9pt;",
            )
        )
        v.addWidget(
            _lbl(
                "El código fuente de este sistema se distribuye bajo los términos\n"
                "de la licencia GNU/GPL v3. Puede obtener una copia en:",
                f"color: {C['text2']}; font-size: 8pt;",
            )
        )
        v.addWidget(
            _lbl(
                "https://www.gnu.org/licenses/gpl-3.0.html",
                f"color: {C['info']}; font-size: 8pt;",
            )
        )
        v.addStretch()

        area.setWidget(contenedor)
        layout.addWidget(area)
        return w

    # ── Slots y actualización de estado ───────────────────────────────────────

    def _on_nueva_alerta(self, alerta: dict) -> None:
        """
        Slot conectado a la señal del hilo de monitoreo.
        Agrega la alerta a la tabla y muestra una notificación emergente.
        """
        self._alertas.append(alerta)
        self._agregar_fila_alerta(alerta)
        emergente = AlertaEmergente(alerta, self)
        emergente.show()

    def _actualizar_modo(self, nuevo_modo: str, ts: str = None) -> None:
        """
        Actualiza el estado global y refresca todos los elementos de la UI
        que dependen del modo de consentimiento.
        """
        global consentimiento_activo, timestamp_consentimiento, modo
        modo = nuevo_modo
        consentimiento_activo = nuevo_modo == "con_consentimiento"
        if ts:
            timestamp_consentimiento = ts
        elif nuevo_modo != "con_consentimiento":
            timestamp_consentimiento = None

        self._actualizar_vista_estado()
        self._actualizar_nota_alertas()
        if hasattr(self, "_btn_exportar"):
            self._btn_exportar.setEnabled(consentimiento_activo)
            self._btn_exportar.setToolTip(
                "" if consentimiento_activo else "Requiere consentimiento activo"
            )
        self.modo_cambiado.emit(nuevo_modo)

        # Reiniciar el IDS con el nuevo modo solo si ya estaba en ejecución
        if self._proceso_ids is not None:
            self._reiniciar_ids()

    def closeEvent(self, event) -> None:
        """Oculta la ventana en lugar de cerrarla para que el tray siga activo."""
        event.ignore()
        self.hide()

    # ── Control del proceso IDS ───────────────────────────────────────────────

    def iniciar_ids(self) -> None:
        """
        Arranca el MonitoreoThread y lanza ids.py como subproceso con sudo -n
        (no interactivo: falla de inmediato si sudo requiere contraseña).
        stdout/stderr del subproceso se redirigen a logs/ids_arranque.log para
        diagnóstico. Tras 2 segundos verifica que el proceso sigue vivo.
        """
        # El MonitoreoThread sigue el archivo de log, que solo existe con
        # consentimiento. En modo local las alertas llegan por stdout del
        # subproceso y se leen con _leer_stdout_local().
        if consentimiento_activo and not self._monitoreo.isRunning():
            self._monitoreo.start()

        python_venv = str(config.BASE_DIR / "venv" / "bin" / "python")
        ids_script  = str(config.BASE_DIR / "ids.py")
        log_ids_path = config.ARRANQUE_LOG_FILE
        env = dict(os.environ)
        securefs.crear_directorio_estado(config.STATE_DIR)

        if consentimiento_activo:
            env.pop("IDS_MODO_LOCAL", None)
            modo_txt = "completo"
        else:
            env["IDS_MODO_LOCAL"] = "1"
            modo_txt = "local"

        try:
            log_ids_file = open(log_ids_path, "w", encoding="utf-8")
            # Si ya somos root (GUI lanzada con sudo -E), ejecutar directo.
            # Si no, intentar con sudo -n (requiere regla NOPASSWD en sudoers).
            if os.geteuid() == 0:
                cmd = [python_venv, ids_script]
            else:
                cmd = ["sudo", "-n", python_venv, ids_script]
            if consentimiento_activo:
                self._proceso_ids = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=log_ids_file,
                    stderr=log_ids_file,
                )
            else:
                # Modo local: sin archivo de log; las alertas se leen del stdout.
                self._proceso_ids = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                threading.Thread(
                    target=self._leer_stdout_local, daemon=True
                ).start()
            log.info(
                f"Proceso IDS lanzado (PID {self._proceso_ids.pid}), modo={modo_txt}"
            )
        except Exception as e:
            log.error(f"No se pudo lanzar el proceso del IDS: {e}")
            return

        # Verificar después de 2 s que el proceso sigue vivo
        def _verificar():
            import time as _time

            _time.sleep(2)
            codigo = self._proceso_ids.poll()
            if codigo is not None:
                try:
                    contenido = log_ids_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    contenido = "(sin salida)"
                log.error(
                    f"El proceso IDS terminó prematuramente (código {codigo}). "
                    f"Revisa logs/ids_arranque.log\n{contenido.strip()}"
                )
            else:
                log.info(
                    f"Proceso IDS confirmado en ejecución (PID {self._proceso_ids.pid})"
                )

        threading.Thread(target=_verificar, daemon=True).start()

    def _leer_stdout_local(self) -> None:
        """En modo local las alertas llegan por stdout del subproceso,
        nunca por archivo. Reusa el parser del MonitoreoThread y emite su
        señal (las señales de PyQt son thread-safe; el slot corre en el hilo
        de la GUI)."""
        proc = self._proceso_ids
        if proc is None or proc.stdout is None:
            return
        for linea in proc.stdout:
            linea = linea.strip()
            if "[CRITICAL" in linea or (
                "[WARNING" in linea and "no autorizado" in linea.lower()
            ):
                alerta = self._monitoreo._parsear_linea(linea)
                if alerta:
                    self._monitoreo.nueva_alerta.emit(alerta)

    def _detener_proceso_ids(self) -> None:
        """Pide al subproceso root que termine vía archivo centinela.

        El subproceso ids.py puede correr como root (sudo) y la GUI no puede
        matarlo con señales sin contraseña; en su lugar crea .ids_stop, que el
        bucle de captura revisa cada 5 s.
        """
        stop = config.STOP_FILE
        try:
            securefs.escribir_privado(stop, "")
        except OSError as e:
            log.error(f"No se pudo crear .ids_stop: {e}")
            return
        if self._proceso_ids:
            try:
                self._proceso_ids.wait(timeout=10)
                log.info("Proceso IDS detenido correctamente.")
            except subprocess.TimeoutExpired:
                log.warning("El proceso IDS no respondio al centinela.")

    def _reiniciar_ids(self) -> None:
        """
        Termina el subproceso del IDS en ejecución y lo reinicia con el modo
        de consentimiento actual. Se llama automáticamente cuando el usuario
        otorga o revoca el consentimiento después de la primera ejecución.
        """
        if self._proceso_ids and self._proceso_ids.poll() is None:
            self._detener_proceso_ids()
        self.iniciar_ids()


# ── bandeja ──


class BandejaIDS(QSystemTrayIcon):
    """Ícono en bandeja con parpadeo en estado sin consentimiento. REF: GUI-020"""

    def __init__(self, ventana: VentanaPrincipal, parent=None):
        """
        Parametros:
            ventana (VentanaPrincipal): Ventana principal del panel de control.
        """
        super().__init__(parent)
        self._ventana = ventana
        self._blink_visible = True
        self._blink_timer = QTimer(self)
        self._blink_timer.setInterval(800)
        self._blink_timer.timeout.connect(self._blinkar)

        self._construir_menu()
        self._actualizar_icono(modo)

        ventana.modo_cambiado.connect(self._actualizar_icono)
        self.activated.connect(self._on_activado)

    def _construir_menu(self) -> None:
        """Construye el menú contextual del ícono en la bandeja."""
        menu = QMenu()
        menu.setStyleSheet(STYLESHEET)
        accion_abrir = QAction("Abrir panel", self)
        accion_abrir.triggered.connect(self._abrir_panel)
        menu.addAction(accion_abrir)
        menu.addSeparator()
        accion_salir = QAction("Salir", self)
        accion_salir.triggered.connect(self._salir)
        menu.addAction(accion_salir)
        self.setContextMenu(menu)

    def _actualizar_icono(self, nuevo_modo: str) -> None:
        """Actualiza el ícono y el tooltip según el nuevo modo."""
        self._blink_timer.stop()
        if nuevo_modo == "con_consentimiento":
            self.setIcon(_crear_icono_circulo(C["green"]))
            self.setToolTip("IDS activo - Monitoreando")
        elif nuevo_modo == "local":
            self.setIcon(_crear_icono_circulo(C["teal"]))
            self.setToolTip("IDS local - Sin tratamiento de datos")
        else:
            self.setIcon(_crear_icono_circulo(C["red"]))
            self.setToolTip("IDS - Consentimiento requerido")
            self._blink_timer.start()

    def _blinkar(self) -> None:
        """Alterna entre el ícono rojo y uno apagado para crear el efecto de parpadeo."""
        self._blink_visible = not self._blink_visible
        self.setIcon(_crear_icono_circulo(C["red"], visible=self._blink_visible))

    def _on_activado(self, razon) -> None:
        """Abre el panel al hacer clic izquierdo en el ícono."""
        if razon == QSystemTrayIcon.ActivationReason.Trigger:
            self._abrir_panel()

    def _abrir_panel(self) -> None:
        """Muestra y trae al frente la ventana principal."""
        self._ventana.show()
        self._ventana.raise_()
        self._ventana.activateWindow()

    def _salir(self) -> None:
        """Detiene el hilo de monitoreo, termina el subproceso del IDS y cierra la app."""
        self._ventana._monitoreo.detener()
        self._ventana._monitoreo.wait(2000)
        if self._ventana._proceso_ids and self._ventana._proceso_ids.poll() is None:
            self._ventana._detener_proceso_ids()
        QApplication.quit()


# ── punto de entrada ──


def _preparar_estado() -> None:
    """Garantiza que STATE_DIR exista y migra una whitelist heredada del
    directorio del código la primera vez (instalaciones previas). REF: GUI-022"""
    securefs.crear_directorio_estado(config.STATE_DIR)
    heredada = config.BASE_DIR / "whitelist.txt"
    if not config.WHITELIST_FILE.exists() and heredada.exists():
        try:
            securefs.escribir_privado(
                config.WHITELIST_FILE,
                heredada.read_text(encoding="utf-8"),
            )
            log.info(f"Whitelist migrada a {config.WHITELIST_FILE}")
        except OSError as e:
            log.error(f"No se pudo migrar la whitelist: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # No cerrar al ocultar la ventana principal

    _preparar_estado()

    # Crear ventana y tray ANTES de iniciar cualquier captura de tráfico
    ventana = VentanaPrincipal()

    # En la primera ejecución mostrar la política de privacidad de forma bloqueante.
    # Scapy todavía no ha iniciado en este punto.
    if _es_primera_ejecucion():
        dlg = PrimerEjecucionDialog(ventana)
        dlg.exec()

    # Solo después de que el usuario eligió (aceptar o rechazar), arrancar el IDS
    tray = BandejaIDS(ventana)
    tray.show()
    ventana.iniciar_ids()

    sys.exit(app.exec())
