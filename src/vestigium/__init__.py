"""Vestigium - agente autonomo de analise forense e CTF.

Detecta e correlaciona evidencias nas categorias: PCAP, LOG, SQLite, Stego,
Crypto, Warmup, Phishing, Cadeia e Dropper, produzindo um relatorio
profissional (HTML/Markdown/JSON).

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
Licenca: MIT
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Joaquim Pedro de Morais Filho"
__email__ = "j360074@hotmail.com"
__license__ = "MIT"

from .agent import Agent, ScanResult
from .findings import Finding, Severity, CATEGORIES

__all__ = ["Agent", "ScanResult", "Finding", "Severity", "CATEGORIES",
           "__version__", "__author__", "__email__"]
