"""mailer: escape HTML de las alertas y manejo de la cola en modo local.

Los valores de las alertas vienen del tráfico (IPs, MACs, dominios), y se
insertan en correos HTML: sin escape, un nombre de dominio o metadato de un
feed comprometido podría inyectar HTML/script en el correo del administrador.
"""

from utils import mailer


def test_construir_html_alerta_escapa_titulo_y_valores():
    html = mailer.construir_html_alerta(
        titulo='<script>alert("x")</script>',
        detalles={
            "IP": '<img src=x onerror="alert(1)">',
            "Dominio": "evil.com&friends",
        },
        nivel="EMERGENCIA",
    )

    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x" in html
    assert "evil.com&amp;friends" in html
    assert "EMERGENCIA" in html


def test_construir_html_resumen_escapa_y_agrupa_por_categoria():
    alertas = [
        {"categoria": "Phishing <script>", "detalles": {"IP": "1.2.3.4"}, "timestamp": "t1"},
        {"categoria": "Phishing <script>", "detalles": {"IP": "5.6.7.8"}, "timestamp": "t2"},
        {"categoria": "Botnet", "detalles": {"IP": '9.9.9.9"><b>'}, "timestamp": "t3"},
    ]

    html = mailer._construir_html_resumen(alertas, es_inmediato=True)

    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "Resumen Inmediato" in html
    assert html.count("<h3") == 2  # agrupado por categoría
    assert "9.9.9.9&quot;&gt;&lt;b&gt;" in html


def test_enviar_alerta_desde_modo_local_no_encola():
    assert mailer.enviar_alerta("asunto", "<html></html>") is True
