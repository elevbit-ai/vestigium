"""Analisador Stego: deteccao de esteganografia e dados ocultos em imagens.

Verifica dados apos o fim logico (EOF) de PNG/JPEG/GIF, arquivos embutidos
(zip/rar/pe), analise de LSB, metadados/comentarios e assinaturas de
ferramentas conhecidas (steghide, OpenStego). Extrai artefatos e bandeiras.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context

_EMBEDDED_SIGS = {
    b"PK\x03\x04": "zip",
    b"Rar!\x1a\x07": "rar",
    b"\x1f\x8b\x08": "gzip",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"MZ": "pe",
    b"BZh": "bzip2",
}


class StegoAnalyzer(Analyzer):
    name = "stego"
    category = "stego"
    handles = ("png", "jpeg", "gif", "bmp")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        data = ev.read_bytes()

        trailing = self._trailing_data(ev.kind, data)
        if trailing is not None:
            off, extra = trailing
            findings.append(self._trailing_finding(ev, off, extra, ctx))

        # Arquivos embutidos em qualquer offset (exceto o cabecalho legitimo)
        embedded = self._scan_embedded(data)
        for sig_name, pos in embedded:
            if pos == 0:
                continue
            findings.append(Finding(
                analyzer=self.name, category="stego",
                title=f"Arquivo embutido ({sig_name}) no offset {pos}",
                severity=Severity.HIGH, source=str(ev.path),
                description=f"Assinatura de {sig_name} encontrada dentro da imagem.",
                recommendation="Extrair (ex.: binwalk/foremost) e analisar o conteudo.",
                tags=["polyglot", "embedded"], mitre=["T1027.003"],
                data={"offset": pos, "type": sig_name},
            ))

        # Metadados / comentarios com texto suspeito
        meta_hit = self._metadata_text(data)
        if meta_hit:
            findings.append(Finding(
                analyzer=self.name, category="stego",
                title="Texto oculto em metadados/comentario",
                severity=Severity.MEDIUM, source=str(ev.path),
                description="Comentario/metadado da imagem contem texto relevante.",
                evidence=meta_hit[:120], flags=P.find_flags(meta_hit),
            ))

        # Assinaturas de ferramentas de stego
        tool = self._tool_signature(data)
        if tool:
            findings.append(Finding(
                analyzer=self.name, category="stego",
                title=f"Indicio de ferramenta de esteganografia: {tool}",
                severity=Severity.MEDIUM, source=str(ev.path),
                description=f"Marcadores tipicos de {tool} presentes.",
                recommendation=f"Tentar extracao com {tool} (senha pode ser necessaria).",
            ))

        # Bandeiras em strings brutas do arquivo
        fl = P.find_flags(data.decode("latin-1", "replace"))
        if fl:
            findings.append(Finding(
                analyzer=self.name, category="stego",
                title="Bandeira em strings da imagem",
                severity=Severity.HIGH, source=str(ev.path),
                evidence="; ".join(fl[:5]), flags=fl,
            ))

        # LSB (apenas heuristica textual para PNG/BMP)
        lsb = self._lsb_text(ev.kind, data)
        if lsb:
            findings.append(Finding(
                analyzer=self.name, category="stego",
                title="Texto plausivel em LSB (canal menos significativo)",
                severity=Severity.HIGH, source=str(ev.path),
                evidence=lsb[:120], flags=P.find_flags(lsb),
                recommendation="Confirmar com zsteg/stegsolve.",
                tags=["lsb"],
            ))
        return findings

    # ---------------------------------------------------------------
    @staticmethod
    def _trailing_data(kind: str, data: bytes):
        markers = {"png": b"IEND\xaeB`\x82", "jpeg": b"\xff\xd9", "gif": b"\x00\x3b"}
        m = markers.get(kind)
        if not m:
            return None
        idx = data.rfind(m)
        if idx == -1:
            return None
        end = idx + len(m)
        extra = data[end:]
        # ignora padding minimo
        if len(extra) > 8:
            return end, extra
        return None

    def _trailing_finding(self, ev, off, extra, ctx: Context) -> Finding:
        sig = next((n for s, n in _EMBEDDED_SIGS.items() if extra.startswith(s)), None)
        flags = P.find_flags(extra.decode("latin-1", "replace"))
        # carve
        carved = None
        try:
            carved = ctx.carve_path(f"{ev.name}.trailing.bin")
            carved.write_bytes(extra[: 5 * 1024 * 1024])
        except Exception:
            carved = None
        return Finding(
            analyzer=self.name, category="stego",
            title=f"{len(extra)} bytes apendados apos o EOF da imagem"
                  + (f" (parece {sig})" if sig else ""),
            severity=Severity.HIGH, source=str(ev.path),
            description="Dados adicionais existem depois do fim logico da imagem.",
            evidence=extra[:64].decode("latin-1", "replace"),
            flags=flags,
            recommendation="Extrair os bytes finais e analisar (polyglot/append stego).",
            tags=["append", "eof"], mitre=["T1027.003"],
            data={"offset": off, "size": len(extra),
                  "carved": str(carved) if carved else None},
        )

    @staticmethod
    def _scan_embedded(data: bytes):
        hits = []
        for sig, name in _EMBEDDED_SIGS.items():
            start = 0
            while True:
                pos = data.find(sig, start)
                if pos == -1:
                    break
                hits.append((name, pos))
                start = pos + 1
                if len(hits) > 40:
                    return hits
        return hits

    @staticmethod
    def _metadata_text(data: bytes) -> str | None:
        for tag in (b"tEXt", b"iTXt", b"zTXt", b"Comment", b"Exif", b"COM"):
            i = data.find(tag)
            if i != -1:
                chunk = data[i: i + 256].decode("latin-1", "replace")
                if any(c.isalpha() for c in chunk[len(tag):]):
                    return chunk
        return None

    @staticmethod
    def _tool_signature(data: bytes) -> str | None:
        if data[:4] == b"\x89PNG" and b"steghide" in data.lower():
            return "steghide"
        if b"OpenStego" in data:
            return "OpenStego"
        if b"\x00\x00STEG" in data or b"STEGHIDE" in data.upper():
            return "steghide"
        return None

    @staticmethod
    def _lsb_text(kind: str, data: bytes) -> str | None:
        # Heuristica leve: extrai LSB do fluxo bruto e busca texto imprimivel.
        if kind not in ("png", "bmp"):
            return None
        bits = []
        for b in data[: 200000]:
            bits.append(b & 1)
        # agrupa em bytes
        chars = bytearray()
        for i in range(0, len(bits) - 8, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            chars.append(byte)
        text = P.extract_strings(bytes(chars), min_len=6)
        for s in text:
            if P.RE_FLAG.search(s):
                return s
        return None
