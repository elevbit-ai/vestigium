"""Base de conhecimento de CVEs (curada, offline) e comparacao de versoes.

Mapeia produto+versao para CVEs conhecidas, permitindo *correlacao de
deteccao* durante o reconhecimento. NAO explora nada: apenas relaciona a
versao observada a vulnerabilidades publicas conhecidas.

IMPORTANTE: esta e uma lista CURADA e ILUSTRATIVA de CVEs de alto perfil,
mantida offline e sem qualquer dependencia externa. NAO e exaustiva nem
substitui uma consulta ao NVD/feeds oficiais. Sempre confirme cada achado
em https://nvd.nist.gov/vuln/detail/<CVE>.

Sintaxe de faixa: restricoes separadas por virgula, cada uma no formato
`<X`, `<=X`, `>X`, `>=X` ou `==X`. A versao casa se satisfizer TODAS.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import re

# produto (chave normalizada) -> lista de CVEs
KB: dict[str, list[dict]] = {
    "apache": [
        {"cve": "CVE-2021-41773", "range": "==2.4.49", "cvss": 7.5,
         "desc": "Path traversal em mod_alias/CGI (pode levar a RCE)."},
        {"cve": "CVE-2021-42013", "range": ">=2.4.49,<=2.4.50", "cvss": 9.8,
         "desc": "Path traversal/RCE (bypass do patch do CVE-2021-41773)."},
        {"cve": "CVE-2019-0211", "range": ">=2.4.17,<=2.4.38", "cvss": 7.8,
         "desc": "Escalada de privilegio local via scoreboard (MPM event/worker)."},
        {"cve": "CVE-2017-15715", "range": ">=2.4.0,<=2.4.29", "cvss": 8.1,
         "desc": "Bypass de FilesMatch por nova linha no nome do arquivo."},
    ],
    "nginx": [
        {"cve": "CVE-2013-2028", "range": ">=1.3.9,<=1.4.0", "cvss": 7.5,
         "desc": "Stack buffer overflow em chunked transfer (DoS/RCE)."},
        {"cve": "CVE-2019-20372", "range": "<1.17.7", "cvss": 5.3,
         "desc": "Request smuggling / injecao via error_page."},
        {"cve": "CVE-2021-23017", "range": "<1.21.0", "cvss": 7.3,
         "desc": "Off-by-one no resolver DNS (corrupcao de memoria)."},
    ],
    "openssh": [
        {"cve": "CVE-2024-6387", "range": ">=8.5,<9.8", "cvss": 8.1,
         "desc": "regreSSHion: RCE nao autenticado via race condition no sshd."},
        {"cve": "CVE-2020-15778", "range": "<=8.3", "cvss": 7.8,
         "desc": "Injecao de comando via scp (nome de arquivo com metacaracteres)."},
        {"cve": "CVE-2018-15473", "range": "<=7.7", "cvss": 5.3,
         "desc": "Enumeracao de usuarios validos por diferenca de resposta."},
    ],
    "php": [
        {"cve": "CVE-2024-4577", "range": "<8.3.8", "cvss": 9.8,
         "desc": "Argument injection no PHP-CGI (Windows), pode levar a RCE."},
        {"cve": "CVE-2019-11043", "range": ">=7.0,<7.3.11", "cvss": 8.7,
         "desc": "Buffer underflow no PHP-FPM/mod_php (RCE em certas configs)."},
    ],
    "openssl": [
        {"cve": "CVE-2014-0160", "range": ">=1.0.1,<1.0.1.7", "cvss": 7.5,
         "desc": "Heartbleed: leitura de memoria via extensao heartbeat do TLS."},
        {"cve": "CVE-2022-3602", "range": ">=3.0.0,<3.0.7", "cvss": 7.5,
         "desc": "Buffer overflow na verificacao de certificado (punycode)."},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "range": "<5.8.3", "cvss": 8.8,
         "desc": "SQL injection via WP_Query (nucleo do WordPress)."},
        {"cve": "CVE-2023-2745", "range": "<6.2.1", "cvss": 5.4,
         "desc": "Directory traversal / vazamento de conteudo em rascunhos."},
    ],
    "jquery": [
        {"cve": "CVE-2019-11358", "range": "<3.4.0", "cvss": 6.1,
         "desc": "Prototype pollution via jQuery.extend(true, ...)."},
        {"cve": "CVE-2020-11022", "range": ">=1.2,<3.5.0", "cvss": 6.1,
         "desc": "XSS via HTML de fonte confiavel passado a metodos de manipulacao."},
        {"cve": "CVE-2020-11023", "range": ">=1.0.3,<3.5.0", "cvss": 6.1,
         "desc": "XSS via elementos <option> em HTML manipulado."},
    ],
}


def parse_version(v: str) -> tuple[int, ...]:
    """Extrai a versao como tupla de inteiros (ignora sufixos como 'p1')."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _satisfies(ver: tuple[int, ...], constraint: str) -> bool:
    m = re.match(r"(<=|>=|==|<|>)\s*(.+)", constraint.strip())
    if not m:
        return False
    op, target = m.group(1), parse_version(m.group(2))
    c = _cmp(ver, target)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0}[op]


def match_cves(product: str, version: str) -> list[dict]:
    """Retorna as CVEs conhecidas cuja faixa contem a versao informada."""
    entries = KB.get(product.lower())
    if not entries:
        return []
    ver = parse_version(version)
    hits = []
    for e in entries:
        constraints = [c.strip() for c in e["range"].split(",") if c.strip()]
        if constraints and all(_satisfies(ver, c) for c in constraints):
            hits.append(e)
    return hits


def cvss_severity(score: float) -> str:
    """Converte CVSS base em rotulo de severidade (nomes de Severity)."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"
