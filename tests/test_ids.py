"""ids: resolución del directorio de estado y el gate de consentimiento.

IDS_STATE_DIR resuelve entorno → .env.runtime → runtime/; los centinelas y el
consentimiento leen de ese directorio y deciden el modo local ANTES de cargar
config, por lo que una resolución equivocada cambia el comportamiento real.
"""

from ids import _resolver_state_dir


def test_resolver_estado_entorno_gana(monkeypatch):
    monkeypatch.setenv("IDS_STATE_DIR", "/var/lib/ids")
    assert _resolver_state_dir() == "/var/lib/ids"


def test_resolver_estado_lee_env_runtime(monkeypatch, tmp_path):
    monkeypatch.delenv("IDS_STATE_DIR", raising=False)
    monkeypatch.setattr("ids._BASE", str(tmp_path))
    (tmp_path / ".env.runtime").write_text(
        "OTRA=1\nIDS_STATE_DIR=/var/lib/ids\n", encoding="utf-8"
    )
    assert _resolver_state_dir() == "/var/lib/ids"


def test_resolver_estado_default_runtime(monkeypatch, tmp_path):
    monkeypatch.delenv("IDS_STATE_DIR", raising=False)
    monkeypatch.setattr("ids._BASE", str(tmp_path))
    assert _resolver_state_dir() == str(tmp_path / "runtime")
