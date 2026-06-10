#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

"$DIR/autostart.sh" desactivar
"$DIR/venv/bin/python" "$DIR/reset_prueba.py"
