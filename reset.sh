#!/bin/bash
cd /home/kali/IDS

# Desactivar inicio automático antes de limpiar el estado
/home/kali/IDS/autostart.sh desactivar

# Limpiar estado de inicialización y consentimiento
/home/kali/IDS/venv/bin/python /home/kali/IDS/reset_prueba.py
