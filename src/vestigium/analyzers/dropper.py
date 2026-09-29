"""Analisador Dropper: deteccao de artefatos que baixam/executam cargas.

Analisa scripts (PowerShell/JS/VBS/BAT/HTA), documentos OLE/OOXML com macros
e binarios PE. Sinaliza ofuscacao, download de estagios, uso de LOLBins,
execucao de codigo em memoria e secoes de alta entropia (empacotamento).
Extrai URLs de C2/estagio como IOCs.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import re
import struct

from ..evidence import Evidence
from ..evidence import shannon_entropy
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context

# Padroes de comportamento de dropper por linguagem.
_SIGS = [
    ("Download de estagio", "T1105", re.compile(
        r"(DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\bwget\b|\bcurl\b|"
        r"URLDownloadToFile|WinHttp|XMLHTTP|BitsTransfer|New-Object\s+Net\.WebClient)", re.I)),
    ("Execucao em memoria", "T1059.001", re.compile(
        r"(IEX\b|Invoke-Expression|\beval\(|\bexecute\(|FromBase64String|"
        r"\[Reflection\.Assembly\]|\.Invoke\(|Add-Type|CreateThread|VirtualAlloc)", re.I)),
    ("Ofuscacao PowerShell", "T1027", re.compile(
        r"(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}|-nop\b|-w\s+hidden|-ep\s+bypass|"
        r"`[a-z]|\bchar\]\s*\d+|-join)", re.I)),
    ("LOLBin", "T1218", re.compile(
        r"\b(mshta|regsvr32|rundll32|certutil|bitsadmin|wmic|cscript|wscript|"
        r"msiexec|installutil|regasm|conhost)\b", re.I)),
    ("Macro auto-executavel", "T1204.002", re.compile(
        r"(Auto_?Open|Document_Open|Workbook_Open|AutoExec|Auto_Close)", re.I)),
    ("Shell via macro", "T1059.005", re.compile(
        r"(\bShell\s*\(|CreateObject\(\s*[\"']?WScript\.Shell|WScript\.Shell|"
        r"Scripting\.FileSystemObject|Environ\()", re.I)),
    ("Persistencia", "T1547.001", re.compile(
        r"(CurrentVersion\\\\Run|schtasks\b|New-ScheduledTask|reg\s+add|"
        r"HKCU\\|HKLM\\|StartupFolder)", re.I)),
]


class DropperAnalyzer(Analyzer):
    name = "dropper"
    category = "dropper"
    handles = ("powershell", "batch", "javascript", "vbscript", "hta",
               "ole", "ooxml", "pe", "text", "html", "zip")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        data = ev.read_bytes(limit=16 * 1024 * 1024)

        if ev.kind == "pe":
            findings += self._analyze_pe(ev, data)

        # Texto script + strings extraidas (cobre OLE/OOXML/binario tambem)
        text = data.decode("utf-8", "replace")
        text += "\n" + "\n".join(P.extract_strings(data) + P.extract_strings_utf16(data))

        findings += self._behavior(ev, text)
        findings += self._deobfuscate(ev, text)
        return findings

    # ---------------------------------------------------------------
    def _behavior(self, ev, text: str) -> list[Finding]:
        out = []
        matched_categories = 0
        for label, tech, rx in _SIGS:
            m = rx.findall(text)
            if not m:
                continue
            matched_categories += 1
            sev = Severity.HIGH if label in (
                "Download de estagio", "Execucao em memoria",
                "Macro auto-executavel", "Shell via macro") else Severity.MEDIUM
            sample = ", ".join(dict.fromkeys(
                (x if isinstance(x, str) else x[0]) for x in m))[:150]
            out.append(Finding(
                analyzer=self.name, category="dropper",
                title=f"Comportamento de dropper: {label}",
                severity=sev, source=str(ev.path),
                description=f"Indicadores de '{label}' presentes no artefato.",
                evidence=sample, mitre=[tech], tags=["dropper"],
                iocs=P.extract_iocs(text),
            ))
        # Correlacao interna: varias categorias juntas = cadeia de dropper completa
        if matched_categories >= 3:
            out.append(Finding(
                analyzer=self.name, category="dropper",
                title="Cadeia de dropper completa (download + execucao + evasao)",
                severity=Severity.CRITICAL, source=str(ev.path),
                description=(f"{matched_categories} classes de comportamento malicioso "
                            "combinadas no mesmo artefato."),
                iocs=P.extract_iocs(text), tags=["dropper", "malware"],
                mitre=["T1105", "T1059", "T1027"],
                recommendation="Isolar host, coletar carga baixada e bloquear IOCs.",
            ))
        return out

    def _deobfuscate(self, ev, text: str) -> list[Finding]:
        out = []
        # PowerShell -EncodedCommand (base64 UTF-16LE)
        for m in re.finditer(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{40,})", text, re.I):
            b64 = m.group(1)
            try:
                import base64
                raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
                dec = raw.decode("utf-16le", "replace")
                if not any(c.isalpha() for c in dec):
                    dec = raw.decode("utf-8", "replace")
                out.append(Finding(
                    analyzer=self.name, category="dropper",
                    title="Comando PowerShell codificado desofuscado",
                    severity=Severity.HIGH, source=str(ev.path),
                    evidence=dec[:200], iocs=P.extract_iocs(dec),
                    mitre=["T1027", "T1059.001"], tags=["deobfuscated"],
                ))
            except Exception:
                pass
        # base64 generico contendo URL/carga
        for tok in re.findall(r"[A-Za-z0-9+/]{60,}={0,2}", text)[:30]:
            raw = P.try_base64(tok)
            if raw:
                dec = raw.decode("utf-8", "replace")
                iocs = P.extract_iocs(dec)
                if iocs.get("url") or "powershell" in dec.lower() or "http" in dec.lower():
                    out.append(Finding(
                        analyzer=self.name, category="dropper",
                        title="Carga base64 embutida decodificada",
                        severity=Severity.HIGH, source=str(ev.path),
                        evidence=dec[:180], iocs=iocs,
                        mitre=["T1140"], tags=["deobfuscated"],
                    ))
        return out

    def _analyze_pe(self, ev, data: bytes) -> list[Finding]:
        out = []
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
                return out
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            sect_off = e_lfanew + 24 + opt_size
            high_entropy = []
            for i in range(min(num_sections, 32)):
                base = sect_off + i * 40
                name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
                raw_size = struct.unpack_from("<I", data, base + 16)[0]
                raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
                sect = data[raw_ptr:raw_ptr + raw_size]
                ent = shannon_entropy(sect)
                if ent > 7.2 and raw_size > 512:
                    high_entropy.append((name, round(ent, 2)))
            if high_entropy:
                out.append(Finding(
                    analyzer=self.name, category="dropper",
                    title="Secoes PE de alta entropia (empacotado/cifrado)",
                    severity=Severity.HIGH, source=str(ev.path),
                    description="Entropia elevada sugere packer ou carga cifrada.",
                    evidence="; ".join(f"{n}={e}" for n, e in high_entropy),
                    mitre=["T1027.002"], tags=["packed"],
                    recommendation="Analisar em sandbox; considerar unpacking.",
                ))
        except Exception:
            pass
        # Imports/strings suspeitas
        low = data.lower()
        apis = [a for a in (b"virtualalloc", b"writeprocessmemory", b"createremotethread",
                            b"loadlibrary", b"getprocaddress", b"wininet", b"urldownloadtofile",
                            b"internetopen", b"shellexecute") if a in low]
        if len(apis) >= 3:
            out.append(Finding(
                analyzer=self.name, category="dropper",
                title="APIs de injecao/download no executavel",
                severity=Severity.HIGH, source=str(ev.path),
                evidence=", ".join(a.decode() for a in apis),
                mitre=["T1055", "T1105"], tags=["injection"],
            ))
        return out
