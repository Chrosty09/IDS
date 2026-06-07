# IDS Institucional — ids — GNU/GPL v3

import fcntl
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from utils.logger import obtener_logger
from utils.threat_feed import descargar_todos_los_feeds

log = obtener_logger("ids")

_INIT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".ids_initialized"
)
_LOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ids.lock")
_lock_fd = None  # REF: IDS-001


def _adquirir_lock() -> None:
    """REF: IDS-001"""
    global _lock_fd
    try:
        _lock_fd = open(_LOCK_FILE, "w")
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
    except OSError:
        print(
            "\n[ERROR] El IDS ya esta en ejecucion. "
            "Detena la instancia actual antes de iniciar una nueva.\n"
            "       Usa: ./detener.sh\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _verificar_inicializado() -> None:
    """REF: IDS-002"""
    if not os.path.exists(_INIT_FILE):
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
    _adquirir_lock()

    _verificar_inicializado()

    _verificar_root()

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

    try:
        from scapy.all import sniff

        log.info("Captura activa. Presiona Ctrl+C para detener.")
        sniff(
            iface=config.NETWORK_INTERFACE,
            filter="ip",
            promisc=True,
            store=False,
            prn=procesa_paquete,
        )
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
