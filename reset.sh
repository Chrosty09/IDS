#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Hardening C1: si existe el despliegue protegido, se resetea SU estado
# (/var/lib/ids), no el del directorio de desarrollo.
INSTALL_DIR="${IDS_INSTALL_DIR:-/opt/ids}"
[ -f "$INSTALL_DIR/reset_prueba.py" ] || INSTALL_DIR="$DIR"

"$DIR/autostart.sh" desactivar
"$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/reset_prueba.py"
