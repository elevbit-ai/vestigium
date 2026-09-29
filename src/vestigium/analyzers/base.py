"""Contrato base para analisadores do Vestigium.

Cada analisador declara as categorias que trata, decide se aceita uma
evidencia (`can_handle`) e produz uma lista de achados (`analyze`).

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import abc

from ..evidence import Evidence
from ..findings import Finding


class Analyzer(abc.ABC):
    name: str = "base"
    category: str = "warmup"
    #: tipos de evidencia (Evidence.kind) que este analisador aceita; vazio = todos
    handles: tuple[str, ...] = ()

    def can_handle(self, ev: Evidence) -> bool:
        if not self.handles:
            return True
        return ev.kind in self.handles

    @abc.abstractmethod
    def analyze(self, ev: Evidence, ctx: "Context") -> list[Finding]:
        ...


class Context:
    """Estado compartilhado entre analisadores durante uma varredura."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.all_findings: list[Finding] = []   # preenchido pelo agente
        self.evidences = []                      # lista de Evidence
        self.scratch = {}                        # espaco de trabalho livre

    def carve_path(self, name: str):
        """Retorna caminho para gravar um artefato extraido (carving)."""
        d = self.out_dir / "carved"
        d.mkdir(parents=True, exist_ok=True)
        return d / name
