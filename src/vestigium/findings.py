"""Modelo de dados de achados (findings) do Vestigium.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import enum
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    """Severidade de um achado, ordenada para permitir comparacao/ordenacao."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Informativo",
            Severity.LOW: "Baixa",
            Severity.MEDIUM: "Media",
            Severity.HIGH: "Alta",
            Severity.CRITICAL: "Critica",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "#3b82f6",
            Severity.LOW: "#22c55e",
            Severity.MEDIUM: "#eab308",
            Severity.HIGH: "#f97316",
            Severity.CRITICAL: "#ef4444",
        }[self]


# Categorias forenses suportadas pelo agente.
CATEGORIES = [
    "warmup",
    "pcap",
    "log",
    "sqlite",
    "stego",
    "crypto",
    "phishing",
    "dropper",
    "chain",
]

# Categorias do modo pentest (reconhecimento).
RECON_CATEGORIES = [
    "escopo",
    "portas",
    "servicos",
    "http",
    "tls",
    "descoberta",
]


@dataclass
class Finding:
    """Um achado individual produzido por um analisador."""

    analyzer: str
    category: str
    title: str
    severity: Severity
    description: str = ""
    evidence: str = ""                       # trecho/prova textual
    source: str = ""                         # caminho do arquivo de origem
    recommendation: str = ""
    iocs: dict[str, list[str]] = field(default_factory=dict)   # ip, domain, url, hash, email
    flags: list[str] = field(default_factory=list)             # bandeiras de CTF encontradas
    mitre: list[str] = field(default_factory=list)             # tecnicas ATT&CK (ex: T1059)
    tags: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)         # dados estruturados extras
    ts: float = field(default_factory=time.time)

    @property
    def uid(self) -> str:
        h = hashlib.sha1(
            f"{self.analyzer}|{self.title}|{self.source}|{self.evidence}".encode(
                "utf-8", "replace"
            )
        ).hexdigest()
        return h[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        d["uid"] = self.uid
        return d


def merge_iocs(target: dict[str, list[str]], new: dict[str, list[str]]) -> None:
    """Funde dicionarios de IOC eliminando duplicatas, preservando ordem."""
    for k, vals in new.items():
        bucket = target.setdefault(k, [])
        for v in vals:
            if v not in bucket:
                bucket.append(v)
