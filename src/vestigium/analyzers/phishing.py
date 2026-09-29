"""Analisador Phishing: analise de e-mails (.eml) e paginas HTML.

Verifica cabecalhos de autenticacao (SPF/DKIM/DMARC), spoofing de remetente,
dominios sosia (homoglifos/typosquatting), links mascarados, encurtadores,
URLs por IP, linguagem de urgencia, formularios de captura de credenciais e
anexos perigosos (macros/executaveis).

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import re
from email import message_from_bytes
from email.utils import parseaddr

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context

_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
               "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"}
_URGENCY = re.compile(
    r"(urgent|imediat|verify your account|suspend|verifique sua conta|"
    r"senha expir|password expir|click here|clique aqui|account locked|"
    r"conta bloqueada|confirme seus dados|update your payment|fatura)", re.I)
_BRANDS = ["paypal", "microsoft", "apple", "google", "amazon", "netflix",
           "banco", "bradesco", "itau", "santander", "caixa", "nubank",
           "correios", "receita", "gov", "outlook", "office365", "instagram"]
_DANGEROUS_ATTACH = re.compile(
    r"\.(exe|scr|js|vbs|hta|jar|bat|cmd|ps1|docm|xlsm|pptm|iso|img|lnk|zip|rar|7z)$", re.I)


class PhishingAnalyzer(Analyzer):
    name = "phishing"
    category = "phishing"
    handles = ("eml", "html", "text")

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        raw = ev.read_bytes()
        if ev.kind == "eml" or raw[:5] in (b"From ", b"Retur", b"Recei", b"Date:", b"Subje"):
            return self._analyze_email(ev, raw)
        return self._analyze_html(ev, raw.decode("utf-8", "replace"))

    # ---------------------------------------------------------------
    def _analyze_email(self, ev, raw: bytes) -> list[Finding]:
        msg = message_from_bytes(raw)
        findings = []
        from_name, from_addr = parseaddr(msg.get("From", ""))
        return_path = parseaddr(msg.get("Return-Path", ""))[1]
        reply_to = parseaddr(msg.get("Reply-To", ""))[1]

        # Autenticacao
        auth = (msg.get("Authentication-Results", "") + " "
                + msg.get("Received-SPF", "")).lower()
        failed = [k for k in ("spf", "dkim", "dmarc")
                  if f"{k}=fail" in auth or f"{k}=softfail" in auth or f"{k}=none" in auth]
        if failed or not auth.strip():
            findings.append(Finding(
                analyzer=self.name, category="phishing",
                title="Falha/ausencia de autenticacao de e-mail (SPF/DKIM/DMARC)",
                severity=Severity.HIGH, source=str(ev.path),
                description=f"Resultados: {failed or 'nenhum cabecalho de autenticacao'}.",
                evidence=auth[:160], mitre=["T1566.001"], tags=["spoofing"],
                recommendation="Rejeitar/quarentenar; exigir DMARC p=reject no dominio.",
            ))
        # Spoofing: From difere de Return-Path/Reply-To
        def dom(a): return a.split("@")[-1].lower() if "@" in a else ""
        if from_addr and return_path and dom(from_addr) != dom(return_path):
            findings.append(Finding(
                analyzer=self.name, category="phishing",
                title="Remetente divergente do Return-Path",
                severity=Severity.HIGH, source=str(ev.path),
                evidence=f"From={from_addr} Return-Path={return_path}",
                iocs={"email": [from_addr, return_path]},
                mitre=["T1566"], tags=["spoofing"],
            ))
        if reply_to and from_addr and dom(reply_to) != dom(from_addr):
            findings.append(Finding(
                analyzer=self.name, category="phishing",
                title="Reply-To aponta para dominio diferente do remetente",
                severity=Severity.MEDIUM, source=str(ev.path),
                evidence=f"From={from_addr} Reply-To={reply_to}",
                iocs={"email": [reply_to]}, tags=["spoofing"],
            ))
        # Nome de exibicao imita marca mas dominio nao corresponde
        low_name = (from_name or "").lower()
        for b in _BRANDS:
            if b in low_name and b not in dom(from_addr):
                findings.append(Finding(
                    analyzer=self.name, category="phishing",
                    title=f"Nome de exibicao imita marca '{b}'",
                    severity=Severity.HIGH, source=str(ev.path),
                    evidence=f'From: "{from_name}" <{from_addr}>',
                    iocs={"email": [from_addr]}, mitre=["T1566"],
                    tags=["brand-impersonation"],
                ))
                break
        # Corpo
        body = self._email_body(msg)
        findings += self._body_checks(ev, body, dom(from_addr))
        # Anexos
        findings += self._attachments(ev, msg)
        return findings

    @staticmethod
    def _email_body(msg) -> str:
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(part.get_payload(decode=True).decode("utf-8", "replace"))
                except Exception:
                    pass
        return "\n".join(parts)

    def _attachments(self, ev, msg) -> list[Finding]:
        out = []
        for part in msg.walk():
            fn = part.get_filename()
            if fn and _DANGEROUS_ATTACH.search(fn):
                out.append(Finding(
                    analyzer=self.name, category="phishing",
                    title=f"Anexo perigoso: {fn}",
                    severity=Severity.CRITICAL, source=str(ev.path),
                    description="Extensao de anexo comumente usada para malware.",
                    evidence=fn, mitre=["T1566.001"], tags=["attachment", "dropper"],
                    recommendation="Nao abrir; detonar em sandbox; ver analisador Dropper.",
                ))
        return out

    # ---------------------------------------------------------------
    def _analyze_html(self, ev, html: str) -> list[Finding]:
        return self._body_checks(ev, html, "")

    def _body_checks(self, ev, body: str, sender_dom: str) -> list[Finding]:
        out = []
        urls = P.RE_URL.findall(body)
        # Links mascarados: texto do link != destino
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                             body, re.I | re.S):
            href, txt = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
            href_dom = self._domain_of(href)
            txt_dom = self._domain_of(txt)
            if txt_dom and href_dom and txt_dom != href_dom:
                out.append(Finding(
                    analyzer=self.name, category="phishing",
                    title="Link mascarado (texto != destino)",
                    severity=Severity.HIGH, source=str(ev.path),
                    evidence=f'texto="{txt[:50]}" -> {href[:80]}',
                    iocs={"url": [href], "domain": [href_dom]},
                    mitre=["T1566.002"], tags=["masked-link"],
                ))
        # Encurtadores / URLs por IP
        for u in urls:
            d = self._domain_of(u)
            if d in _SHORTENERS:
                out.append(Finding(
                    analyzer=self.name, category="phishing",
                    title=f"URL encurtada: {d}",
                    severity=Severity.MEDIUM, source=str(ev.path),
                    evidence=u, iocs={"url": [u]}, tags=["shortener"]))
            if P.RE_IPV4.search(d):
                out.append(Finding(
                    analyzer=self.name, category="phishing",
                    title="Link aponta para endereco IP (sem dominio)",
                    severity=Severity.HIGH, source=str(ev.path),
                    evidence=u, iocs={"url": [u], "ipv4": [d]},
                    tags=["ip-url"], mitre=["T1566.002"]))
        # Typosquatting / homoglifos de marca
        for u in urls:
            d = self._domain_of(u)
            for b in _BRANDS:
                if b in d and not d.endswith(f"{b}.com") and d != b and b not in sender_dom:
                    if self._looks_typosquat(d, b):
                        out.append(Finding(
                            analyzer=self.name, category="phishing",
                            title=f"Dominio sosia de '{b}': {d}",
                            severity=Severity.HIGH, source=str(ev.path),
                            evidence=u, iocs={"domain": [d], "url": [u]},
                            tags=["typosquat"], mitre=["T1583.001"]))
                        break
        # Formulario de captura de credenciais
        if re.search(r'<input[^>]+type=["\']password', body, re.I) and \
           re.search(r"<form", body, re.I):
            action = re.search(r'<form[^>]+action=["\']([^"\']+)', body, re.I)
            out.append(Finding(
                analyzer=self.name, category="phishing",
                title="Formulario de captura de credenciais",
                severity=Severity.HIGH, source=str(ev.path),
                description="Pagina contem campo de senha submetido por formulario.",
                evidence=f"action={action.group(1) if action else '?'}",
                mitre=["T1566.002"], tags=["credential-harvest"],
            ))
        # Linguagem de urgencia
        urg = _URGENCY.findall(body)
        if urg:
            out.append(Finding(
                analyzer=self.name, category="phishing",
                title="Linguagem de urgencia/isca tipica de phishing",
                severity=Severity.LOW, source=str(ev.path),
                evidence=", ".join(dict.fromkeys(u.lower() for u in urg))[:120],
                tags=["social-engineering"],
            ))
        return out

    @staticmethod
    def _domain_of(u: str) -> str:
        m = re.search(r"https?://([^/\s\"'>]+)", u)
        host = m.group(1) if m else u
        host = host.split("@")[-1].split(":")[0].lower()
        return host

    @staticmethod
    def _looks_typosquat(domain: str, brand: str) -> bool:
        # marca aparece como subdominio enganoso ou com caracteres trocados
        core = domain.split(".")[0]
        if brand in domain and not domain.startswith(brand + "."):
            return True
        # distancia simples
        if brand in core and core != brand:
            return True
        return False
