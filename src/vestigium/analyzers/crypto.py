"""Analisador Crypto: identifica e tenta resolver desafios criptograficos.

Cobre cadeias base64/base32/hex, ROT/Caesar (todos os deslocamentos),
Atbash, XOR de byte unico (forca bruta), Morse, identificacao de hashes
e deteccao de chaves PEM. Procura bandeiras apos cada decodificacao.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import base64
import re

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context


class CryptoAnalyzer(Analyzer):
    name = "crypto"
    category = "crypto"
    handles = ("text", "log", "pem", "html", "binary")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = ev.read_text(limit=2 * 1024 * 1024)
        except OSError:
            return findings

        # Chaves privadas / material criptografico em PEM
        if "-----BEGIN" in text:
            kind = re.search(r"-----BEGIN ([A-Z ]+)-----", text)
            label = kind.group(1) if kind else "BLOCK"
            sev = Severity.CRITICAL if "PRIVATE" in label else Severity.MEDIUM
            findings.append(Finding(
                analyzer=self.name, category="crypto",
                title=f"Material criptografico PEM: {label}",
                severity=sev, source=str(ev.path),
                description="Bloco PEM encontrado (chave/certificado).",
                recommendation="Nunca versionar chaves privadas; rotacionar se exposta.",
                tags=["secret"], mitre=["T1552"],
            ))

        # Hashes reconheciveis
        hashes = self._identify_hashes(text)
        if hashes:
            findings.append(Finding(
                analyzer=self.name, category="crypto",
                title=f"{sum(len(v) for v in hashes.values())} hash(es) identificado(s)",
                severity=Severity.LOW, source=str(ev.path),
                description="Hashes detectados: " + ", ".join(
                    f"{k}({len(v)})" for k, v in hashes.items()),
                evidence="; ".join(next(iter(hashes.values()))[:3]),
                iocs={"hash": [h for v in hashes.values() for h in v][:50]},
                recommendation="Testar contra wordlists (defensivo) ou identificar algoritmo.",
            ))

        # Resolucao de cadeias de codificacao/cifra sobre cada linha/token
        solved = self._solve(text)
        for f in solved:
            findings.append(f)
        return findings

    # ---------------------------------------------------------------
    @staticmethod
    def _identify_hashes(text: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name, rx in (("md5", P.RE_MD5), ("sha1", P.RE_SHA1), ("sha256", P.RE_SHA256)):
            vals = list(dict.fromkeys(rx.findall(text)))
            if vals:
                out[name] = vals
        return out

    def _solve(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._candidates(text)

        for token in candidates:
            for label, decoded in self._decode_variants(token):
                fl = P.find_flags(decoded)
                if fl:
                    findings.append(Finding(
                        analyzer=self.name, category="crypto",
                        title=f"Bandeira recuperada via {label}",
                        severity=Severity.HIGH,
                        description=f"Decodificacao {label} revelou uma bandeira.",
                        evidence=f"{token[:48]}... -> {decoded[:80]}",
                        flags=fl,
                        recommendation="Confirmar a bandeira recuperada.",
                    ))
        # dedup por titulo+flag
        seen, uniq = set(), []
        for f in findings:
            k = (f.title, tuple(f.flags))
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq[:25]

    @staticmethod
    def _candidates(text: str) -> list[str]:
        toks: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if 6 <= len(line) <= 4096:
                toks.append(line)
        # tambem tokens grandes soltos
        toks += re.findall(r"\S{12,4096}", text)
        # limita para nao explodir
        return list(dict.fromkeys(toks))[:400]

    def _decode_variants(self, token: str):
        """Gera (rotulo, texto_decodificado) para varias tecnicas."""
        # base64
        raw = P.try_base64(token)
        if raw:
            yield "base64", raw.decode("utf-8", "replace")
            # base64 aninhado
            inner = P.try_base64(raw.decode("utf-8", "replace"))
            if inner:
                yield "base64 aninhado", inner.decode("utf-8", "replace")
        # base32
        try:
            b32 = base64.b32decode(token + "=" * (-len(token) % 8), casefold=True)
            if b32 and P._mostly_printable(b32):
                yield "base32", b32.decode("utf-8", "replace")
        except Exception:
            pass
        # hex
        h = P.try_hex(token)
        if h:
            yield "hex", h.decode("utf-8", "replace")
        # ROT / Caesar (todos os shifts)
        if re.search(r"[A-Za-z]", token):
            for n in range(1, 26):
                yield f"ROT{n}", P.rot(token, n)
            yield "Atbash", P.atbash(token)
        # Morse
        m = P.try_morse(token)
        if m:
            yield "Morse", m
        # XOR byte unico
        b = token.encode("latin-1", "replace")
        for key in range(1, 256):
            x = P.xor_single(b, key)
            if P._mostly_printable(x, 0.9):
                dec = x.decode("latin-1", "replace")
                if "{" in dec:
                    yield f"XOR 0x{key:02x}", dec
