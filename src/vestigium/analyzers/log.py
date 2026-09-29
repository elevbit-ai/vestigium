"""Analisador LOG: deteccao de ataques e anomalias em arquivos de log.

Reconhece access logs (Apache/Nginx), auth.log/syslog e formatos genericos.
Detecta SQLi, XSS, path traversal, LFI/RFI, injecao de comando, forca bruta
de autenticacao, varredura (excesso de 404) e user-agents de ferramentas.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context

# Assinaturas de ataque em URLs/parametros.
_ATTACK_SIGS = [
    ("SQL Injection", "T1190", re.compile(
        r"(\bunion\b.+\bselect\b|\bor\b\s+1=1|'\s*or\s*'|;--|/\*.*\*/|\bsleep\(|\bbenchmark\(|information_schema|\bwaitfor\s+delay)", re.I)),
    ("Cross-Site Scripting (XSS)", "T1059.007", re.compile(
        r"(<script\b|onerror\s*=|onload\s*=|javascript:|<img[^>]+src\s*=|%3Cscript)", re.I)),
    ("Path Traversal", "T1083", re.compile(
        r"(\.\./|\.\.%2f|%2e%2e/|/etc/passwd|\\windows\\win\.ini|c:\\)", re.I)),
    ("Local/Remote File Inclusion", "T1505.003", re.compile(
        r"(php://|data://|expect://|=https?://|/proc/self/environ)", re.I)),
    ("Command Injection", "T1059", re.compile(
        r"(;\s*(cat|ls|id|whoami|nc|wget|curl|bash)\b|\|\s*(nc|bash|sh)\b|\$\(.*\)|`.*`|%0a)", re.I)),
    ("Log4Shell / JNDI", "T1190", re.compile(r"\$\{jndi:(ldap|rmi|dns)", re.I)),
]

_TOOL_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|acunetix|nessus|zgrab|python-requests|curl|wget)",
    re.I)

_ACCESS_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


class LogAnalyzer(Analyzer):
    name = "log"
    category = "log"
    handles = ("log", "text")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        try:
            text = ev.read_text(limit=32 * 1024 * 1024)
        except OSError:
            return []
        lines = text.splitlines()
        if not lines:
            return []

        findings: list[Finding] = []
        findings += self._attack_signatures(ev, lines)
        findings += self._access_analysis(ev, lines)
        findings += self._auth_bruteforce(ev, lines)
        # bandeiras/IOCs gerais
        fl = P.find_flags(text)
        if fl:
            findings.append(Finding(
                analyzer=self.name, category="log", title="Bandeira em log",
                severity=Severity.HIGH, source=str(ev.path),
                evidence="; ".join(fl[:5]), flags=fl))
        return findings

    def _attack_signatures(self, ev, lines):
        hits: dict[str, list[str]] = defaultdict(list)
        ips: dict[str, set] = defaultdict(set)
        for ln in lines:
            for label, tech, rx in _ATTACK_SIGS:
                if rx.search(ln):
                    hits[label].append(ln.strip()[:200])
                    m = P.RE_IPV4.search(ln)
                    if m:
                        ips[label].add(m.group())
        out = []
        for (label, tech, _rx) in _ATTACK_SIGS:
            if label in hits:
                sample = hits[label]
                sev = Severity.CRITICAL if label in (
                    "SQL Injection", "Command Injection", "Log4Shell / JNDI"
                ) else Severity.HIGH
                out.append(Finding(
                    analyzer=self.name, category="log",
                    title=f"{label}: {len(sample)} tentativa(s)",
                    severity=sev, source=str(ev.path),
                    description=f"Assinaturas de {label} detectadas nas requisicoes.",
                    evidence="\n".join(sample[:5]),
                    iocs={"ipv4": sorted(ips[label])}, mitre=[tech],
                    tags=["web-attack"],
                    recommendation="Bloquear origem, aplicar WAF e revisar exposicao.",
                ))
        return out

    def _access_analysis(self, ev, lines):
        parsed = [m.groupdict() for ln in lines if (m := _ACCESS_RE.match(ln))]
        if not parsed:
            return []
        out = []
        # Varredura: muitos 404 por IP
        by_ip_404 = Counter(r["ip"] for r in parsed if r["status"] == "404")
        scanners = [(ip, c) for ip, c in by_ip_404.items() if c >= 20]
        if scanners:
            out.append(Finding(
                analyzer=self.name, category="log",
                title=f"Varredura de diretorios por {len(scanners)} IP(s)",
                severity=Severity.MEDIUM, source=str(ev.path),
                description="Alto volume de respostas 404 por origem (enumeracao).",
                evidence="; ".join(f"{ip}={c}x404" for ip, c in scanners[:10]),
                iocs={"ipv4": [ip for ip, _ in scanners]},
                mitre=["T1595.003"], tags=["scanning"],
            ))
        # User-agents de ferramenta
        tool_hits = defaultdict(set)
        for r in parsed:
            ua = r.get("ua") or ""
            m = _TOOL_UA.search(ua)
            if m:
                tool_hits[m.group(1).lower()].add(r["ip"])
        if tool_hits:
            out.append(Finding(
                analyzer=self.name, category="log",
                title="Ferramentas de ataque no User-Agent",
                severity=Severity.HIGH, source=str(ev.path),
                evidence="; ".join(f"{t} <- {sorted(ips)[:3]}" for t, ips in tool_hits.items()),
                iocs={"ipv4": sorted({ip for s in tool_hits.values() for ip in s})},
                tags=["tooling"], mitre=["T1595"],
            ))
        return out

    def _auth_bruteforce(self, ev, lines):
        fails = defaultdict(int)
        users = defaultdict(set)
        for ln in lines:
            low = ln.lower()
            if "failed password" in low or "authentication failure" in low or \
               "invalid user" in low or ln.strip().endswith(" 401 0") or " 401 " in ln:
                m = P.RE_IPV4.search(ln)
                if m:
                    fails[m.group()] += 1
                um = re.search(r"(?:invalid user|for)\s+(\w+)", ln)
                if um and m:
                    users[m.group()].add(um.group(1))
        bru = [(ip, c) for ip, c in fails.items() if c >= 10]
        if not bru:
            return []
        return [Finding(
            analyzer=self.name, category="log",
            title=f"Forca bruta de autenticacao por {len(bru)} IP(s)",
            severity=Severity.HIGH, source=str(ev.path),
            description="Multiplas falhas de autenticacao a partir da mesma origem.",
            evidence="; ".join(
                f"{ip}={c} falhas usuarios={sorted(users[ip])[:4]}" for ip, c in bru[:10]),
            iocs={"ipv4": [ip for ip, _ in bru]},
            mitre=["T1110"], tags=["bruteforce"],
            recommendation="Aplicar rate-limit, MFA e bloqueio temporario por IP.",
        )]
