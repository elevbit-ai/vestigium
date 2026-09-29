"""Registro dos analisadores do Vestigium.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from .base import Analyzer, Context
from .warmup import WarmupAnalyzer
from .pcap import PcapAnalyzer
from .log import LogAnalyzer
from .sqlite import SqliteAnalyzer
from .stego import StegoAnalyzer
from .crypto import CryptoAnalyzer
from .phishing import PhishingAnalyzer
from .dropper import DropperAnalyzer
from .chain import ChainAnalyzer


def default_analyzers() -> list[Analyzer]:
    """Analisadores por-evidencia, na ordem de execucao."""
    return [
        WarmupAnalyzer(),
        PcapAnalyzer(),
        LogAnalyzer(),
        SqliteAnalyzer(),
        StegoAnalyzer(),
        CryptoAnalyzer(),
        PhishingAnalyzer(),
        DropperAnalyzer(),
    ]


__all__ = [
    "Analyzer", "Context", "default_analyzers", "ChainAnalyzer",
    "WarmupAnalyzer", "PcapAnalyzer", "LogAnalyzer", "SqliteAnalyzer",
    "StegoAnalyzer", "CryptoAnalyzer", "PhishingAnalyzer", "DropperAnalyzer",
]
