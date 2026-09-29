"""Testes de fumaca: garantem que o agente roda e cada categoria dispara.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vestigium.agent import Agent          # noqa: E402
from vestigium import patterns as P        # noqa: E402


def test_patterns_decoders():
    assert P.rot("uryyb", 13) == "hello"
    assert P.try_base64("aGVsbG8=") == b"hello"
    assert P.try_hex("68656c6c6f") == b"hello"
    assert P.find_flags("x flag{abc} y") == ["flag{abc}"]
    iocs = P.extract_iocs("visite http://a.com de 1.2.3.4 e me@a.com")
    assert "1.2.3.4" in iocs["ipv4"]
    assert "me@a.com" in iocs["email"]


def test_agent_end_to_end(tmp_path):
    # gera amostras diretamente
    sys.path.insert(0, str(ROOT))
    from examples import generate_samples as gs
    gs.OUT = tmp_path / "samples"
    gs.main()

    out = tmp_path / "report"
    result = Agent(verbose=False).scan(str(gs.OUT), out)

    assert result.stats["evidence_count"] >= 8
    assert result.stats["finding_count"] > 0

    cats = set(result.stats["by_category"])
    for expected in ("warmup", "pcap", "log", "sqlite", "stego",
                     "crypto", "phishing", "dropper", "chain"):
        assert expected in cats, f"categoria ausente: {expected}"

    # ao menos uma bandeira deve ser recuperada
    assert result.stats["flags"], "nenhuma bandeira recuperada"
    assert result.risk_score > 0
