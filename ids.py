# IDS Institucional — ids — GNU/GPL v3

import fcntl
import os
import sys
from datetime import datetime

_BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE)

# El consentimiento es la fuente de verdad, no el entorno.
# sudo limpia el entorno y la GUI/autostart pueden inyectar valores erróneos;
# por eso ids.py lee .ids_consent él mismo ANTES de importar config.
# REF: IDS-006 — se usa lstat (existe_sin_seguir): un symlink colocado por un
# usuario sin privilegios NO cuenta como consentimiento (fail-safe).
from utils import securefs


def _resolver_state_dir() -> str:
    """Localiza STATE_DIR igual que config.py (entorno → .env.runtime →
    runtime/), sin importar config todavía."""
    env = os.environ.get("IDS_STATE_DIR")
    if env:
        return env
    try:
        with open(
            os.path.join(_BASE, ".env.runtime"), encoding="utf-8"
        ) as _rt:
            for _linea in _rt:
                if _linea.startswith("IDS_STATE_DIR="):
                    return _linea.partition("=")[2].strip()
    except OSError:
        pass
    return os.path.join(_BASE, "runtime")


# El consentimiento es la fuente de verdad, no el entorno: se resuelve ANTES
# de importar config para que config.MODO_LOCAL refleje el archivo real.
_STATE_DIR = _resolver_state_dir()
_CONSENT_FILE = os.path.join(_STATE_DIR, ".ids_consent")
if securefs.existe_sin_seguir(_CONSENT_FILE):
    os.environ.pop("IDS_MODO_LOCAL", None)
else:
    os.environ["IDS_MODO_LOCAL"] = "1"

import config  # config.MODO_LOCAL ahora refleja el consentimiento real
from utils.logger import obtener_logger
from utils.threat_feed import descargar_todos_los_feeds

log = obtener_logger("ids")

_INIT_FILE = config.INIT_FILE
_LOCK_FILE = config.LOCK_FILE
_STOP_FILE = config.STOP_FILE
_lock_fd = None  # REF: IDS-001


def _adquirir_lock() -> None:
    """REF: IDS-001 — O_NOFOLLOW impide que un symlink previamente colocado
    en STATE_DIR haga que root trunque un archivo arbitrario del sistema."""
    global _lock_fd
    securefs.crear_directorio_estado(config.STATE_DIR)
    try:
        fd = os.open(
            _LOCK_FILE,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("ascii"))
        _lock_fd = os.fdopen(fd, "w")
    except OSError:
        print(
            "\n[ERROR] El IDS ya esta en ejecucion o el archivo de lock no es\n"
            "       utilizable. Detena la instancia actual antes de iniciar\n"
            "       una nueva. Usa: ./detener.sh\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _verificar_inicializado() -> None:
    """REF: IDS-002"""
    if not securefs.existe_sin_seguir(_INIT_FILE):
        print(
            "\n[ERROR] El IDS no puede iniciarse sin que el usuario haya revisado\n"
            "        la politica de privacidad. Ejecute gui.py para iniciar el sistema.\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _verificar_root() -> None:
    """REF: IDS-003"""
    if os.geteuid() != 0:
        print(
            "\n[ERROR] El IDS debe ejecutarse con privilegios de root.\n"
            "        Usa: sudo python ids.py\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _mostrar_banner() -> None:
    """Imprime el banner de inicio en consola."""
    fecha_inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = "=" * 60
    print(f"""
{linea}
  IDS INSTITUCIONAL - Sistema de Deteccion de Intrusos
  Organizacion : {config.ORG_NAME}
  Interfaz     : {config.NETWORK_INTERFACE}
  Admin        : {config.ADMIN_EMAIL}
  Inicio       : {fecha_inicio}
{linea}
""")


def main() -> None:
    """REF: IDS-004"""
    # Verificar root ANTES de tocar el estado: el lock y los centinelas solo
    # deben ser creados/manipulados por el proceso privilegiado.
    _verificar_root()

    _adquirir_lock()

    _verificar_inicializado()

    try:
        config.validar_config()
    except EnvironmentError as e:
        print(f"\n[ERROR DE CONFIGURACION]\n{e}\n", file=sys.stderr)
        sys.exit(1)

    _mostrar_banner()

    log.info("Actualizando todos los feeds de inteligencia de amenazas...")
    descargar_todos_los_feeds()

    from modulos.modulo_sitios import ModuloSitios
    from modulos.modulo_threat_intel import ModuloThreatIntel
    from modulos.modulo_whitelist import ModuloWhitelist

    modulo_whitelist = ModuloWhitelist()
    modulo_sitios = ModuloSitios()
    modulo_threat_intel = ModuloThreatIntel()

    log.info(
        f"Modulos cargados. Iniciando captura en interfaz "
        f"'{config.NETWORK_INTERFACE}' (modo promiscuo)..."
        + (" [MODO LOCAL - sin logs ni reportes]" if config.MODO_LOCAL else "")
    )

    def procesa_paquete(pkt) -> None:
        """REF: IDS-005"""
        try:
            modulo_whitelist.procesar(pkt)
        except Exception as e:
            log.error(f"Error en modulo_whitelist: {e}")

        try:
            modulo_sitios.procesar(pkt)
        except Exception as e:
            log.error(f"Error en modulo_sitios: {e}")

        try:
            modulo_threat_intel.procesar(pkt)
        except Exception as e:
            log.error(f"Error en modulo_threat_intel: {e}")

    # Limpiar un centinela residual. unlink nunca sigue symlinks, por lo que
    # aquí no es posible borrar un archivo arbitrario mediante un enlace.
    securefs.eliminar_seguro(_STOP_FILE)

    try:
        from scapy.all import sniff

        log.info("Captura activa. Presiona Ctrl+C para detener.")
        # El timeout garantiza que aunque la red esté en silencio el bucle
        # revise el centinela cada 5 s, permitiendo detener un proceso root
        # sin necesidad de contraseña ni señales.
        while not securefs.existe_sin_seguir(_STOP_FILE):
            sniff(
                iface=config.NETWORK_INTERFACE,
                filter="ip",
                promisc=True,
                store=False,
                prn=procesa_paquete,
                timeout=5,
                stop_filter=lambda p: securefs.existe_sin_seguir(_STOP_FILE),
            )
        log.info("Senal de detencion recibida (.ids_stop). IDS finalizado.")
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n")
        log.info(
            "Captura detenida por el operador (Ctrl+C). IDS finalizado correctamente."
        )
        sys.exit(0)
    except Exception as e:
        log.critical(f"Error fatal durante la captura de paquetes: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
