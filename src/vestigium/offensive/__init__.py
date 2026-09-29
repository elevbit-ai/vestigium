"""Modo ofensivo do Vestigium: reconhecimento de pentest autorizado.

Reune os modulos de reconhecimento nao destrutivo (varredura de portas,
identificacao de servicos, HTTP, TLS, descoberta de conteudo) usados pelo
agente de pentest.

Uso etico e autorizado apenas.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from .recon import ReconAgent, parse_target

__all__ = ["ReconAgent", "parse_target"]
