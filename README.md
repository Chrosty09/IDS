<div align="center">

# 🔍 IDS Institucional

**Sistema de Detección de Intrusos para redes locales**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/Licencia-GNU%20GPL%20v3-green?logo=gnu)](LICENSE)
[![Platform](https://img.shields.io/badge/Plataforma-Linux-orange?logo=linux&logoColor=white)](https://kernel.org)
[![Status](https://img.shields.io/badge/Estado-Proyecto%20acad%C3%A9mico-blueviolet)]()

*Proyecto final — Seguridad en Sistemas | Grupo 8B | Enero–Junio 2026*  
*Universidad Autónoma de Aguascalientes*

</div>

---

> [!WARNING]
> **Este es un proyecto universitario con fines exclusivamente académicos.**
> No está diseñado, probado ni respaldado para su uso en entornos de producción,
> infraestructura crítica ni redes corporativas reales. Ver la sección
> [Descargos de responsabilidad](#descargos-de-responsabilidad) al final de este documento.

---

## ¿Qué es?

El IDS Institucional es un sistema de detección de intrusos pasivo desarrollado en Python que analiza el tráfico de una red local en tiempo real. Detecta dispositivos no autorizados, conexiones a servidores maliciosos conocidos y consultas a dominios de phishing o malware, emite alertas por correo electrónico al administrador de red y registra todos los eventos en una bitácora y en un panel web.

El sistema opera de forma **pasiva**: captura y analiza el tráfico, pero no lo interrumpe. Las alertas son informativas para que el administrador tome las acciones que considere necesarias.

---

## Características principales

| Módulo | Capa OSI | Función |
|--------|----------|---------|
| **Lista Blanca** | 2 (Enlace) y 3 (Red) | Detecta dispositivos no registrados por IP y MAC |
| **Threat Intelligence** | 3 (Red) y 4 (Transporte) | Verifica IPs destino contra 38 000+ indicadores maliciosos |
| **Monitoreo de Sitios** | 7 (Aplicación) | Intercepta consultas DNS y tráfico HTTP, cruza contra 1.2M+ dominios maliciosos |
| **Módulo Forense** | — | Consulta RDAP/ipinfo.io automáticamente ante una detección crítica |

**Fuentes de inteligencia de amenazas integradas:**  
Feodo Tracker · CINS Army · Blocklist.de · Emerging Threats · URLhaus · Phishing Army · OpenPhish · Hagezi TIF · NoCoin · Stalkerware Indicators · y más.

**Otras características:**
- Interfaz gráfica PyQt6 con icono en bandeja del sistema
- Panel de administración web en tiempo real (Netlify + Supabase)
- Tres niveles de alerta por correo (resumen periódico, inmediato y crítico)
- Arquitectura de consentimiento conforme a la LFPDPPP (legislación mexicana)
- Modo local sin almacenamiento ni transmisión de datos
- Derecho de cancelación inmediato (ARCO)
- Configuración cifrada con OpenSSL AES-256-CBC
- Instalador interactivo en un solo comando

---

## Requisitos

- **Sistema operativo:** Linux (Kali Linux 2024+, Ubuntu 22.04+, Debian 12+)
- **Python:** 3.11 o superior
- **Privilegios:** El motor de captura requiere `sudo` (configurado automáticamente por el instalador)
- **Cuenta de correo:** Gmail con verificación en dos pasos y App Password

> El sistema **no es compatible con Windows ni macOS**.

---

## Instalación rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/Chrosty09/IDS.git
cd IDS

# 2. Dar permisos de ejecución a los scripts
chmod +x *.sh

# 3. Ejecutar el instalador (como usuario normal, NO como root)
./install.sh

# 4. Iniciar el IDS
./iniciar.sh
```

El instalador guía paso a paso la configuración del servidor SMTP, la interfaz de red y las opciones opcionales de cifrado e inicio automático.

Para instrucciones detalladas con capturas de pantalla, consultar el **Manual de Usuario** incluido en la documentación del proyecto.

---

## Panel de administración web

El panel web está disponible en:

**https://ids-dashboard-uaa.netlify.app/**

El acceso es por invitación. Para solicitar una cuenta, enviar un correo **desde la dirección que se desea registrar** a:

📧 `ids.tactical931@passmail.com`

Se recibirá un correo de invitación con un enlace para establecer la contraseña.

---

## Estructura del repositorio

```
IDS/
├── ids.py                  # Motor de captura y detección
├── gui.py                  # Interfaz gráfica PyQt6
├── config.py               # Configuración centralizada
├── modulos/
│   ├── modulo_whitelist.py
│   ├── modulo_sitios.py
│   ├── modulo_threat_intel.py
│   └── modulo_forense.py
├── utils/
│   ├── mailer.py           # Sistema de alertas por correo
│   ├── reporter.py         # Reporte al panel web
│   ├── threat_feed.py      # Descarga de feeds de inteligencia
│   ├── logger.py
│   └── env_openssl.py      # Descifrado de configuración
├── install.sh              # Instalador interactivo
├── iniciar.sh              # Iniciar el IDS
├── detener.sh              # Detener el IDS
├── setup.sh                # Verificador de dependencias
├── cifrar_env.sh           # Cifrar configuración con OpenSSL
├── autostart.sh            # Gestionar inicio automático
├── reset.sh                # Restaurar estado inicial (pruebas)
├── .env.example            # Plantilla de configuración
├── whitelist.txt           # Dispositivos autorizados
├── docs/
│   └── aviso_privacidad.txt
└── requirements.txt
```

---

## Privacidad y consentimiento

El sistema implementa una arquitectura de privacidad conforme a la **Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP)** y el **Artículo 211 Bis del Código Penal Federal**:

- El usuario otorga consentimiento informado **antes** de que comience cualquier captura de tráfico.
- El usuario puede **revocar su consentimiento en cualquier momento** desde la interfaz gráfica.
- Al revocar, todos los datos son eliminados de forma inmediata e irreversible de la base de datos.
- El **modo local** permite usar el sistema sin almacenar ni transmitir ningún dato.

El aviso de privacidad completo está disponible en `docs/aviso_privacidad.txt`.

---

## Equipo de desarrollo

| Nombre | Rol principal |
|--------|--------------|
| García Rodríguez, Oscar Manuel | Módulos de detección, Threat Intelligence |
| Franco Acosta, Carlos | Interfaz gráfica, integración cloud, análisis jurídico |
| Álvarez Gaspar, Saúl | Monitoreo de sitios, feeds de threat intelligence |

**Supervisor académico:** M.C. Arturo Ocampo Silva  
**Materia:** Seguridad en Sistemas — Grupo 8B  
**Institución:** Universidad Autónoma de Aguascalientes  
**Periodo:** Enero – Junio 2026

---

## Licencia

Distribuido bajo la **Licencia Pública General GNU v3.0**.

Esto significa que puedes usar, estudiar, modificar y distribuir este software bajo los términos de dicha licencia. Ver el archivo [LICENSE](LICENSE) para el texto completo.

---

## Descargos de responsabilidad

**Este proyecto fue desarrollado con fines exclusivamente académicos** como proyecto final de la materia Seguridad en Sistemas en la Universidad Autónoma de Aguascalientes.

**No se recomienda su uso en producción.** El sistema no ha sido sometido a pruebas de seguridad exhaustivas, auditorías de terceros ni certificaciones de ningún tipo. Puede contener errores, vulnerabilidades o comportamientos inesperados.

**No para uso comercial.** El sistema no está diseñado para proteger infraestructura crítica, redes corporativas de producción ni cualquier entorno donde una falla de seguridad pueda tener consecuencias reales.

**Sin garantía.** El software se proporciona "tal cual", sin garantía de ningún tipo, expresa o implícita, incluyendo pero no limitado a garantías de comerciabilidad, idoneidad para un propósito particular o no infracción.

**Responsabilidad del operador.** El despliegue de un sistema de monitoreo de red en cualquier infraestructura real es responsabilidad exclusiva del operador, quien debe asegurarse de contar con las autorizaciones legales correspondientes antes de hacerlo, conforme al Artículo 211 Bis del Código Penal Federal y la LFPDPPP.

Los autores y la Universidad Autónoma de Aguascalientes no asumen ninguna responsabilidad por daños directos, indirectos, incidentales o de cualquier otra naturaleza derivados del uso de este software.

---

<div align="center">

Desarrollado con fines académicos · UAA · 2026  
GNU General Public License v3.0

</div>
