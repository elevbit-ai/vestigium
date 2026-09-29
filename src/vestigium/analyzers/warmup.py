"""Analisador Warmup: triagem generica de qualquer arquivo.

Extrai strings ASCII/UTF-16, procura bandeiras de CTF e IOCs, detecta
incoerencia entre extensao e magic bytes e sinaliza base64/hex embutidos.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context


class WarmupAnalyzer(Analyzer):
    name = "warmup"
    category = "warmup"
    handles = ()  # aceita tudo

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = ev.read_bytes(limit=8 * 1024 * 1024)
        except OSError:
            return findings

        strings = P.extract_strings(data) + P.extract_strings_utf16(data)
        blob = "\n".join(strings)

        # Bandeiras diretamente visiveis
        flags = P.find_flags(blob)
        if flags:
            findings.append(Finding(
                analyzer=self.name, category="warmup",
                title=f"Bandeira(s) de CTF em texto claro: {len(flags)}",
                severity=Severity.HIGH,
                description="Padrao de bandeira encontrado nas strings do arquivo.",
                evidence="; ".join(flags[:10]),
                source=str(ev.path), flags=flags,
                recommendation="Confirmar a bandeira; verificar exposicao de segredos em claro.",
            ))

        # IOCs em texto
        iocs = P.extract_iocs(blob)
        if iocs:
            n = sum(len(v) for v in iocs.values())
            findings.append(Finding(
                analyzer=self.name, category="warmup",
                title=f"{n} indicador(es) de comprometimento em texto",
                severity=Severity.INFO,
                description="URLs, IPs, e-mails ou hashes encontrados nas strings.",
                evidence=", ".join(f"{k}:{len(v)}" for k, v in iocs.items()),
                source=str(ev.path), iocs=iocs,
            ))

        # Incoerencia extensao x conteudo (arquivo disfarcado)
        mismatch = self._ext_mismatch(ev)
        if mismatch:
            findings.append(Finding(
                analyzer=self.name, category="warmup",
                title="Extensao incompativel com o conteudo real",
                severity=Severity.MEDIUM,
                description=mismatch,
                source=str(ev.path),
                recommendation="Arquivo possivelmente disfarcado; tratar pelo tipo real.",
                tags=["masquerading"], mitre=["T1036"],
            ))

        # Blocos base64/hex longos e decodificaveis
        decoded_hits = self._scan_encodings(strings)
        if decoded_hits:
            findings.append(Finding(
                analyzer=self.name, category="warmup",
                title=f"{len(decoded_hits)} bloco(s) codificado(s) decodificavel(is)",
                severity=Severity.LOW,
                description="Sequencias base64/hex que decodificam para texto legivel.",
                evidence="\n".join(decoded_hits[:5]),
                source=str(ev.path),
                recommendation="Ver detalhes no analisador Crypto.",
            ))
        return findings

    @staticmethod
    def _ext_mismatch(ev: Evidence) -> str | None:
        real = ev.kind
        ext = ev.path.suffix.lower()
        harmless = {".txt", ".dat", ".bin", "", ".log"}
        if ext in harmless:
            return None
        expect = {
            ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif",
            ".zip": "zip", ".pdf": "pdf", ".exe": "pe", ".sqlite": "sqlite",
            ".db": "sqlite", ".pcap": "pcap",
        }.get(ext)
        if expect and real not in (expect, "ooxml"):
            return f"Extensao {ext} sugere '{expect}', mas magic bytes indicam '{real}'."
        return None

    @staticmethod
    def _scan_encodings(strings: list[str]) -> list[str]:
        hits = []
        for s in strings:
            if len(s) < 16:
                continue
            raw = P.try_base64(s) or P.try_hex(s)
            if raw:
                dec = raw.decode("utf-8", "replace")
                if any(c.isalpha() for c in dec):
                    hits.append(f"{s[:40]}... -> {dec[:60]}")
            if len(hits) >= 20:
                break
        return hits
