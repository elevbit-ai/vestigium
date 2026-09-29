"""Agente de reconhecimento de pentest (nao destrutivo).

Executa apenas as fases seguras e passivas/ativas-leves de um teste de
intrusao autorizado, contra UM alvo informado explicitamente:

  * varredura de portas TCP (connect scan)
  * coleta de banner e identificacao de servico/versao
  * analise HTTP (cabecalhos de seguranca, divulgacao de versao, cookies)
  * inspecao TLS (certificado, validade, protocolo negociado)
  * descoberta de conteudo sensivel exposto (GET de caminhos conhecidos)

O agente NAO explora vulnerabilidades, NAO faz forca bruta de credenciais,
NAO gera negacao de servico e NAO aceita faixas (CIDR) ou multiplos alvos,
para evitar ataque em massa. Requer autorizacao explicita do operador.

Uso etico e autorizado apenas.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import concurrent.futures as cf
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ..agent import ScanResult
from ..findings import Finding, Severity

UA = "Vestigium-Recon/1.0 (+https://github.com/elevbit-ai/vestigium)"

# Portas comuns -> servico esperado.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-dev", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

# Servicos cuja simples exposicao a internet ja e um risco alto.
RISKY_EXPOSED = {
    23: "Telnet (texto claro)", 3389: "RDP", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    2375: "Docker API", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    445: "SMB", 135: "MSRPC", 21: "FTP",
}

WEB_PORTS = {80, 443, 3000, 8000, 8080, 8443, 8888, 5601, 9200}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}

# Cabecalhos de seguranca esperados numa resposta HTTP.
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS ausente", Severity.MEDIUM),
    "content-security-policy": ("CSP ausente", Severity.MEDIUM),
    "x-frame-options": ("Protecao contra clickjacking ausente", Severity.LOW),
    "x-content-type-options": ("nosniff ausente", Severity.LOW),
    "referrer-policy": ("Referrer-Policy ausente", Severity.LOW),
    "permissions-policy": ("Permissions-Policy ausente", Severity.INFO),
}

# Caminhos sensiveis comumente expostos por engano (GET nao destrutivo).
DISCOVERY_PATHS = [
    ("/.git/HEAD", "Repositorio Git exposto", Severity.HIGH),
    ("/.env", "Arquivo .env exposto (segredos)", Severity.CRITICAL),
    ("/.svn/entries", "Repositorio SVN exposto", Severity.HIGH),
    ("/.DS_Store", "Arquivo .DS_Store exposto", Severity.LOW),
    ("/server-status", "Apache server-status exposto", Severity.MEDIUM),
    ("/phpinfo.php", "phpinfo() exposto", Severity.HIGH),
    ("/.htaccess", ".htaccess acessivel", Severity.MEDIUM),
    ("/backup.zip", "Backup acessivel", Severity.HIGH),
    ("/config.php.bak", "Config de backup acessivel", Severity.HIGH),
    ("/wp-login.php", "Painel WordPress", Severity.INFO),
    ("/admin/", "Painel administrativo", Severity.LOW),
    ("/actuator/health", "Spring Actuator exposto", Severity.MEDIUM),
    ("/robots.txt", "robots.txt", Severity.INFO),
]


class Target:
    def __init__(self, host: str, scheme: str | None, explicit_ports: list[int] | None):
        self.host = host
        self.scheme = scheme
        self.explicit_ports = explicit_ports

    def __str__(self):
        return self.host


def parse_target(raw: str) -> Target:
    """Analisa um alvo unico. Rejeita faixas/CIDR e listas (anti-massa)."""
    import re

    raw = raw.strip()
    if "," in raw or " " in raw:
        raise ValueError("informe apenas UM alvo (sem listas).")
    # CIDR: IP/mascara (anti-massa)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", raw):
        raise ValueError("faixas CIDR nao sao permitidas; informe um unico host.")

    scheme = None
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        raw = raw.split("/")[0]          # descarta o caminho da URL
    else:
        raw = raw.split("/")[0]          # host/caminho -> so o host

    ports = None
    if ":" in raw and raw.count(":") == 1:  # host:port (nao IPv6)
        host, p = raw.rsplit(":", 1)
        if p.isdigit():
            ports = [int(p)]
            raw = host
    if not raw:
        raise ValueError("alvo vazio ou invalido.")
    return Target(raw, scheme, ports)


class ReconAgent:
    """Agente de reconhecimento. Requer `authorized=True` para executar."""

    def __init__(self, verbose: bool = True, timeout: float = 2.0,
                 max_threads: int = 100):
        self.verbose = verbose
        self.timeout = timeout
        self.max_threads = max_threads

    def _log(self, trace: list[str], msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        trace.append(line)
        if self.verbose:
            print(line)

    def scan(self, target: str, out_dir, authorized: bool = False,
             full_ports: bool = False) -> ScanResult:
        if not authorized:
            raise PermissionError(
                "Reconhecimento requer autorizacao explicita. Confirme que voce "
                "tem permissao para testar este alvo (--authorize).")
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        started = time.time()
        trace: list[str] = []
        tgt = parse_target(target)

        self._log(trace, f"Autorizacao confirmada pelo operador para: {tgt.host}")
        self._log(trace, "Escopo restrito a UM alvo; sem exploracao/forca bruta/DoS.")

        # Resolucao
        try:
            ip = socket.gethostbyname(tgt.host)
        except socket.gaierror as exc:
            raise ValueError(f"nao foi possivel resolver o alvo: {exc}")
        self._log(trace, f"Percepcao: {tgt.host} resolve para {ip}")

        scope_iocs = {"ipv4": [ip]}
        if not tgt.host[0].isdigit():
            scope_iocs["domain"] = [tgt.host]
        findings: list[Finding] = []
        findings.append(Finding(
            analyzer="recon", category="escopo",
            title=f"Alvo autorizado: {tgt.host} ({ip})",
            severity=Severity.INFO, source=tgt.host,
            description="Avaliacao nao destrutiva iniciada mediante autorizacao.",
            iocs=scope_iocs,
        ))

        # Portas a varrer
        if tgt.explicit_ports:
            ports = tgt.explicit_ports
        elif full_ports:
            ports = list(range(1, 1025)) + sorted(COMMON_PORTS)
            ports = sorted(set(ports))
        else:
            ports = sorted(COMMON_PORTS)
        self._log(trace, f"Varredura de portas: {len(ports)} porta(s) (connect scan)")

        open_ports = self._port_scan(tgt.host, ports)
        self._log(trace, f"Portas abertas: {open_ports or 'nenhuma'}")
        findings += self._port_findings(tgt.host, open_ports)

        # Portas candidatas a HTTP: web conhecidas + portas explicitas.
        http_ports = set(WEB_PORTS)
        if tgt.explicit_ports:
            http_ports.update(tgt.explicit_ports)

        # Servico/banner por porta aberta
        for port in open_ports:
            svc, banner = self._grab_banner(tgt.host, port, probe_http=port in http_ports)
            findings += self._service_findings(tgt.host, port, svc, banner, trace)
            if "HTTP/" in banner:  # descobre HTTP em porta nao convencional
                http_ports.add(port)

        # HTTP + TLS + descoberta nas portas web
        for port in open_ports:
            if port in http_ports:
                findings += self._http_checks(tgt, port, trace)
                findings += self._discovery(tgt, port, trace)
            if port in TLS_PORTS:
                findings += self._tls_checks(tgt.host, port, trace)

        findings.sort(key=lambda f: (-int(f.severity), f.category))
        finished = time.time()
        result = ScanResult(target=f"{tgt.host} ({ip})", started=started,
                            finished=finished, evidences=[], findings=findings,
                            trace=trace)
        result.stats = self._stats(result)
        self._log(trace, f"Sintese: risco={result.risk_label} "
                        f"({result.risk_score}/100), {len(findings)} achado(s) "
                        f"em {result.duration}s")
        return result

    # ---------------------------------------------------------------
    def _port_scan(self, host: str, ports: list[int]) -> list[int]:
        open_ports: list[int] = []

        def probe(port: int):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                if s.connect_ex((host, port)) == 0:
                    return port
            except OSError:
                return None
            finally:
                s.close()
            return None

        with cf.ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            for res in ex.map(probe, ports):
                if res is not None:
                    open_ports.append(res)
        return sorted(open_ports)

    def _port_findings(self, host, open_ports) -> list[Finding]:
        out = []
        if open_ports:
            svc = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in open_ports)
            out.append(Finding(
                analyzer="recon", category="portas",
                title=f"{len(open_ports)} porta(s) TCP aberta(s)",
                severity=Severity.INFO, source=host,
                description="Superficie de rede exposta.", evidence=svc,
                data={"open_ports": open_ports},
            ))
        for p in open_ports:
            if p in RISKY_EXPOSED:
                out.append(Finding(
                    analyzer="recon", category="portas",
                    title=f"Servico sensivel exposto: {RISKY_EXPOSED[p]} (porta {p})",
                    severity=Severity.HIGH, source=host,
                    description="Servico frequentemente alvo de ataque quando exposto.",
                    recommendation="Restringir por firewall/VPN e exigir autenticacao forte.",
                    tags=["exposure"], mitre=["T1046"],
                ))
        return out

    def _grab_banner(self, host, port, probe_http=False):
        svc = COMMON_PORTS.get(port, "desconhecido")
        banner = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            if s.connect_ex((host, port)) != 0:
                return svc, banner
            if probe_http and port not in TLS_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            try:
                banner = s.recv(1024).decode("latin-1", "replace").strip()
            except socket.timeout:
                banner = ""
        except OSError:
            pass
        finally:
            s.close()
        return svc, banner

    def _service_findings(self, host, port, svc, banner, trace) -> list[Finding]:
        if not banner:
            return []
        self._log(trace, f"  banner {port}/{svc}: {banner[:60]!r}")
        version = banner.splitlines()[0][:120] if banner else ""
        sev = Severity.LOW if any(k in banner.lower() for k in
                                  ("server:", "ssh-", "220 ", "ftp")) else Severity.INFO
        return [Finding(
            analyzer="recon", category="servicos",
            title=f"Servico identificado na porta {port} ({svc})",
            severity=sev, source=f"{host}:{port}",
            description="Banner/versao divulgado pelo servico.",
            evidence=version, tags=["fingerprint"], mitre=["T1046"],
            recommendation="Ocultar versoes; manter o servico atualizado.",
        )]

    def _http_url(self, tgt: Target, port: int) -> str:
        scheme = "https" if port in TLS_PORTS or port in (443, 8443) else "http"
        if tgt.scheme in ("http", "https"):
            scheme = tgt.scheme if port not in (443, 8443) else "https"
        netloc = tgt.host if port in (80, 443) else f"{tgt.host}:{port}"
        return f"{scheme}://{netloc}/"

    def _http_get(self, url: str, method: str = "GET"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
        return urllib.request.urlopen(req, timeout=self.timeout, context=ctx)

    def _http_checks(self, tgt, port, trace) -> list[Finding]:
        url = self._http_url(tgt, port)
        out = []
        try:
            resp = self._http_get(url)
        except urllib.error.HTTPError as e:
            resp = e
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
            self._log(trace, f"  HTTP {url}: falhou ({exc})")
            return out
        headers = {k.lower(): v for k, v in resp.headers.items()}
        setck_all = resp.headers.get_all("Set-Cookie") or []
        self._log(trace, f"  HTTP {url}: {getattr(resp, 'status', '?')}")
        try:
            resp.read()          # drena e permite fechar a conexao
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass

        # Cabecalhos de seguranca ausentes
        missing = []
        for h, (label, sev) in SECURITY_HEADERS.items():
            if h == "strict-transport-security" and not url.startswith("https"):
                continue
            if h not in headers:
                missing.append((label, sev))
        if missing:
            worst = max(sev for _, sev in missing)
            out.append(Finding(
                analyzer="recon", category="http",
                title=f"{len(missing)} cabecalho(s) de seguranca ausente(s)",
                severity=worst, source=url,
                evidence="; ".join(m for m, _ in missing),
                recommendation="Adicionar os cabecalhos de seguranca faltantes.",
                tags=["hardening"], mitre=["T1590"],
            ))
        # Divulgacao de versao
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if h in headers and any(ch.isdigit() for ch in headers[h]):
                out.append(Finding(
                    analyzer="recon", category="http",
                    title=f"Divulgacao de versao em '{h}'",
                    severity=Severity.LOW, source=url,
                    evidence=f"{h}: {headers[h]}",
                    recommendation="Remover/ocultar cabecalhos que revelam versao.",
                    tags=["info-leak"],
                ))
        # Cookies sem flags
        for ck in setck_all:
            low = ck.lower()
            faltas = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                     ("SameSite", "samesite")) if k not in low]
            if faltas:
                out.append(Finding(
                    analyzer="recon", category="http",
                    title=f"Cookie sem flags: {', '.join(faltas)}",
                    severity=Severity.LOW, source=url,
                    evidence=ck.split(";")[0][:80],
                    recommendation="Definir Secure, HttpOnly e SameSite nos cookies.",
                    tags=["cookie"],
                ))
        return out

    def _discovery(self, tgt, port, trace) -> list[Finding]:
        base = self._http_url(tgt, port).rstrip("/")
        out = []
        for path, label, sev in DISCOVERY_PATHS:
            url = base + path
            try:
                resp = self._http_get(url)
                status = getattr(resp, "status", 0)
                body = resp.read(1024).decode("latin-1", "replace")
                resp.close()
            except urllib.error.HTTPError as e:
                status, body = e.code, ""
                try:
                    e.close()
                except Exception:
                    pass
            except (urllib.error.URLError, OSError, ssl.SSLError, ValueError):
                continue
            if status == 200:
                # confirma alguns casos por conteudo
                if path == "/.git/HEAD" and "ref:" not in body:
                    continue
                if path == "/.env" and "=" not in body:
                    continue
                out.append(Finding(
                    analyzer="recon", category="descoberta",
                    title=f"{label}: {path}",
                    severity=sev, source=url,
                    description=f"Resposta 200 em caminho sensivel.",
                    evidence=body[:120].replace("\n", " ") if body else url,
                    recommendation="Remover/bloquear o recurso exposto.",
                    tags=["exposure"], mitre=["T1592"],
                ))
                self._log(trace, f"  descoberta: {path} -> 200")
            # detecta listagem de diretorio
            if status == 200 and "Index of /" in body:
                out.append(Finding(
                    analyzer="recon", category="descoberta",
                    title=f"Listagem de diretorio habilitada em {path}",
                    severity=Severity.MEDIUM, source=url,
                    recommendation="Desabilitar autoindex/directory listing.",
                    tags=["exposure"],
                ))
        return out

    def _tls_checks(self, host, port, trace) -> list[Finding]:
        out = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()
        except (OSError, ssl.SSLError) as exc:
            self._log(trace, f"  TLS {host}:{port}: falhou ({exc})")
            return out
        self._log(trace, f"  TLS {host}:{port}: {proto} {cipher[0] if cipher else ''}")

        # Protocolo fraco
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(Finding(
                analyzer="recon", category="tls",
                title=f"Protocolo TLS obsoleto negociado: {proto}",
                severity=Severity.HIGH, source=f"{host}:{port}",
                recommendation="Desabilitar TLS < 1.2; preferir TLS 1.3.",
                tags=["crypto"], mitre=["T1040"],
            ))
        # Validade do certificado
        cert = cert or self._cert_via_pem(host, port)
        if cert and cert.get("notAfter"):
            try:
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    sev, msg = Severity.HIGH, f"expirado ha {-days} dia(s)"
                elif days < 30:
                    sev, msg = Severity.MEDIUM, f"expira em {days} dia(s)"
                else:
                    sev, msg = Severity.INFO, f"valido por mais {days} dia(s)"
                subj = dict(x[0] for x in cert.get("subject", [])).get("commonName", "?")
                out.append(Finding(
                    analyzer="recon", category="tls",
                    title=f"Certificado TLS ({subj}): {msg}",
                    severity=sev, source=f"{host}:{port}",
                    evidence=f"notAfter={cert['notAfter']}",
                    recommendation="Renovar antes do vencimento; automatizar rotacao.",
                    tags=["tls"],
                ))
            except ValueError:
                pass
        return out

    @staticmethod
    def _cert_via_pem(host, port):
        try:
            pem = ssl.get_server_certificate((host, port), timeout=2)
            # parse minimo: nao ha API stdlib sem cryptography; retorna None
            return None if pem else None
        except Exception:
            return None

    @staticmethod
    def _stats(result: ScanResult) -> dict:
        sev_count = {s.name: 0 for s in Severity}
        cat_count: dict[str, int] = {}
        iocs: dict[str, set] = {}
        for f in result.findings:
            sev_count[f.severity.name] += 1
            cat_count[f.category] = cat_count.get(f.category, 0) + 1
            for k, vals in f.iocs.items():
                iocs.setdefault(k, set()).update(vals)
        return {
            "evidence_count": len({f.source for f in result.findings}),
            "finding_count": len(result.findings),
            "by_severity": sev_count,
            "by_category": cat_count,
            "flags": [],
            "ioc_count": {k: len(v) for k, v in iocs.items()},
            "iocs": {k: sorted(v) for k, v in iocs.items()},
        }
