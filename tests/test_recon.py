"""Testes do modo pentest (reconhecimento) contra um servidor local.

Nao acessa a internet: sobe um HTTP server em 127.0.0.1 e o avalia.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
import functools
import http.server
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vestigium.offensive import ReconAgent, parse_target  # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def web_server(tmp_path):
    root = tmp_path / "webroot"
    root.mkdir()
    (root / "index.html").write_text("<h1>alvo</h1>")
    (root / "robots.txt").write_text("User-agent: *\nDisallow: /x")
    (root / ".env").write_text("DB_PASSWORD=segredo\nAPI_KEY=abc")
    gitdir = root / ".git"
    gitdir.mkdir()
    (gitdir / "HEAD").write_text("ref: refs/heads/main")

    port = _free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield port
    httpd.shutdown()


def test_parse_target_rejects_mass():
    with pytest.raises(ValueError):
        parse_target("10.0.0.0/24")       # CIDR
    with pytest.raises(ValueError):
        parse_target("a.com, b.com")      # lista
    tgt = parse_target("http://exemplo.com:8080/x")
    assert tgt.host == "exemplo.com"
    assert tgt.explicit_ports == [8080]


def test_requires_authorization(tmp_path):
    agent = ReconAgent(verbose=False)
    with pytest.raises(PermissionError):
        agent.scan("127.0.0.1", tmp_path, authorized=False)


def test_recon_detects_exposures(tmp_path, web_server):
    agent = ReconAgent(verbose=False, timeout=1.0)
    result = agent.scan(f"127.0.0.1:{web_server}", tmp_path, authorized=True)

    titles = " | ".join(f.title.lower() for f in result.findings)
    assert ".env" in titles                      # segredo exposto
    assert "git" in titles                        # repositorio exposto
    assert "cabecalho" in titles                  # headers de seguranca
    assert any(f.category == "portas" for f in result.findings)
    assert result.risk_score > 0
