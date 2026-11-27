"""threat_feed: parsers de blacklists, caché de 24h y descargas.

Los parsers son la frontera entre fuentes externas no confiables y las
estructuras que los módulos de detección consultan: un feed comprometido o con
formato inesperado no debe contaminar la base de detección.
"""

import os
import time

import pytest

import config
from utils import threat_feed as tf


class _FakeResp:
    def __init__(self, content: bytes, headers=None):
        self._content = content
        self.headers = {"Content-Type": "text/plain", **(headers or {})}
        self.status_code = 200

    def raise_for_status(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i : i + chunk_size]


_FEED_TXT = {
    "nombre": "cins_test",
    "url": "https://test.local/ci-badguys.txt",
    "destino": "blacklist/cins_blacklist.txt",
    "tipo_parser": "txt_ip",
    "categoria": "Amenaza General",
}

_FEED_CSV = {
    "nombre": "feodo_test",
    "url": "https://test.local/ipblocklist.csv",
    "destino": "blacklist/feodo_blacklist.csv",
    "tipo_parser": "csv_ip",
    "columna_ip": "dst_ip",
    "columna_malware": "malware",
    "columna_puerto": "dst_port",
    "categoria": "Botnet/C2",
}


# ── parsers ──


@pytest.mark.parametrize(
    ("linea", "esperado"),
    [
        ("||evil.com^", "evil.com"),
        ("||sub.evil.com", "sub.evil.com"),
        ("||evil.com^$important", "evil.com"),
        ("! comentario", ""),
        ("[Adblock Plus 2.0]", ""),
        ("@@||good.com^", ""),
        ("@||otro.com^", ""),
        ("example.com", ""),
        ("", ""),
        (" \t ", ""),
    ],
)
def test_parsear_adguard(linea, esperado):
    assert tf._parsear_adguard(linea) == esperado


@pytest.mark.parametrize(
    ("linea", "esperado"),
    [
        ("0.0.0.0 evil.com", "evil.com"),
        ("127.0.0.1 EVIL.COM", "evil.com"),
        ("0.0.0.0 localhost", ""),
        ("0.0.0.0 0.0.0.0", ""),
        ("# comentario", ""),
        ("localhost", ""),
        ("", ""),
    ],
)
def test_parsear_hosts(linea, esperado):
    assert tf._parsear_hosts(linea) == esperado


@pytest.mark.parametrize(
    ("linea", "esperado"),
    [
        ("evil.com", "evil.com"),
        ("HTTPS://EVIL.COM/path", "https://evil.com/path"),
        ("# comentario", ""),
        ("! comentario", ""),
        ("[adblock]", ""),
        ("", ""),
    ],
)
def test_parsear_plain(linea, esperado):
    assert tf._parsear_plain(linea) == esperado


# ── caché de 24 h ──


def test_necesita_actualizacion_segun_edad(tmp_path):
    ausente = tmp_path / "ausente.txt"
    assert tf._necesita_actualizacion(ausente) is True

    vacio = tmp_path / "vacio.txt"
    vacio.write_text("")
    assert tf._necesita_actualizacion(vacio) is True

    vigente = tmp_path / "vigente.txt"
    vigente.write_text("x\n")
    assert tf._necesita_actualizacion(vigente) is False

    viejo = tmp_path / "viejo.txt"
    viejo.write_text("x\n")
    antaño = time.time() - 90000
    os.utime(viejo, (antaño, antaño))
    assert tf._necesita_actualizacion(viejo) is True


# ── descargas ──


def test_descargar_feed_rechaza_contenido_html(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    monkeypatch.setattr(
        tf.requests,
        "get",
        lambda url, timeout=None, stream=None: _FakeResp(
            b"<!DOCTYPE html><html><body>error</body></html>"
        ),
    )

    assert tf.descargar_feed(_FEED_TXT) == 0
    assert not (tmp_path / "blacklist" / "cins_blacklist.txt").exists()
    assert "parece HTML" in caplog.text


def test_descargar_feed_rechaza_tamano_excesivo(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    monkeypatch.setattr(tf, "_MAX_FEED_BYTES", 64)
    monkeypatch.setattr(
        tf.requests, "get", lambda url, timeout=None, stream=None: _FakeResp(b"a" * 200)
    )

    assert tf.descargar_feed(_FEED_TXT) == 0
    assert not (tmp_path / "blacklist" / "cins_blacklist.txt").exists()
    assert "supera el límite" in caplog.text


def test_descargar_feed_error_conexion(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)

    def _boom(url, timeout=None, stream=None):
        raise tf.requests.exceptions.ConnectionError("sin red")

    monkeypatch.setattr(tf.requests, "get", _boom)
    assert tf.descargar_feed(_FEED_TXT) == 0
    assert not (tmp_path / "blacklist" / "cins_blacklist.txt").exists()


def test_descargar_feed_csv_cuenta_ip_unicas(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    contenido = (
        b"# comentario\n"
        b"first_seen,dst_ip,dst_port,malware\n"
        b"2026-01-01,1.2.3.4,445,Heodo\n"
        b"2026-01-02,5.6.7.8,80,TrickBot\n"
        b"2026-01-03,1.2.3.4,445,Heodo\n"
    )
    monkeypatch.setattr(
        tf.requests, "get", lambda url, timeout=None, stream=None: _FakeResp(contenido)
    )

    conteo = tf.descargar_feed(_FEED_CSV)

    assert conteo == 2
    destino = tmp_path / "blacklist" / "feodo_blacklist.csv"
    assert destino.read_bytes() == contenido


def test_descargar_feed_txt_ip_guarda_ordenadas(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    contenido = b"# c\n1.1.1.1\n2.2.2.2\n\n1.1.1.1\n3.3.3.3 # nota\n"
    monkeypatch.setattr(
        tf.requests, "get", lambda url, timeout=None, stream=None: _FakeResp(contenido)
    )

    conteo = tf.descargar_feed(_FEED_TXT)

    assert conteo == 3
    assert (
        (tmp_path / "blacklist" / "cins_blacklist.txt").read_text(encoding="utf-8")
        == "1.1.1.1\n2.2.2.2\n3.3.3.3\n"
    )


def _feed_dominio(nombre, destino, tipo_parser, contenido):
    return {
        "nombre": nombre,
        "url": f"https://test.local/{nombre}",
        "destino": f"blacklist/{destino}",
        "tipo_parser": tipo_parser,
        "categoria": "Test",
    }, contenido


@pytest.mark.parametrize(
    ("tipo", "contenido", "esperado"),
    [
        (
            "adguard",
            b"||evil.com^\n! comentario\n[Adblock Plus 2.0]\n||sub.other.com^$important\n",
            {"evil.com", "sub.other.com"},
        ),
        (
            "hosts",
            b"0.0.0.0 evil.com\n127.0.0.1 localhost\n# comentario\n0.0.0.0 scam.com\n",
            {"evil.com", "scam.com"},
        ),
        (
            "plain",
            b"evil.com\n# comentario\n! otro\n[bloque]\nsite.org\n",
            {"evil.com", "site.org"},
        ),
        (
            "txt_url",
            b"https://evil.com/path\nhttps://evil2.com:443/x\n# c\nplain-domain.com\n",
            {"evil.com", "evil2.com", "plain-domain.com"},
        ),
    ],
)
def test_descargar_feed_dominios_filtra_y_guarda(monkeypatch, tmp_path, tipo, contenido, esperado):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    feed, contenido = _feed_dominio(tipo, f"{tipo}.txt", tipo, contenido)
    monkeypatch.setattr(
        tf.requests, "get", lambda url, timeout=None, stream=None: _FakeResp(contenido)
    )

    conteo = tf.descargar_feed(feed)

    assert conteo == len(esperado)
    guardado = set(
        (tmp_path / "blacklist" / f"{tipo}.txt").read_text(encoding="utf-8").splitlines()
    )
    assert guardado == esperado


def test_descargar_feed_tipo_parser_desconocido(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    feed, _ = _feed_dominio("raros", "raros.txt", "xml", b"<rss></rss>")
    monkeypatch.setattr(
        tf.requests, "get", lambda url, timeout=None, stream=None: _FakeResp(b"<rss></rss>")
    )

    assert tf.descargar_feed(feed) == 0
    assert not (tmp_path / "blacklist" / "raros.txt").exists()
    assert "Tipo de parser desconocido" in caplog.text


def test_descargar_todos_omite_feeds_vigentes_sin_red(monkeypatch, tmp_path):
    # Todos los destinos frescos: la descarga completa debe omitirse y jamás
    # tocar la red.
    monkeypatch.setattr(config, "BASE_DIR", tmp_path)
    monkeypatch.setattr(
        tf.requests, "get", lambda *a, **kw: pytest.fail("no debe descargarse nada")
    )

    carpeta = tmp_path / "blacklist"
    carpeta.mkdir()
    todos = tf.FEEDS_IPS + tf.FEEDS_DOMINIOS
    for feed in todos:
        (carpeta / feed["destino"].split("/", 1)[1]).write_text("x\n", encoding="utf-8")

    resumen = tf.descargar_todos_los_feeds()

    assert resumen["descargados"] == 0
    assert resumen["omitidos"] == len(todos)
