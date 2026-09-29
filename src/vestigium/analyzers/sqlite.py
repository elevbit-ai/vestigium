"""Analisador SQLite: forense de bancos de dados SQLite.

Enumera tabelas e colunas, sinaliza tabelas de credenciais/sessoes/PII,
identifica hashes de senha, procura bandeiras e faz carving simples de
registros apagados varrendo a freelist e areas nao alocadas das paginas.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import re
import sqlite3
import struct
import tempfile
from pathlib import Path

from ..evidence import Evidence
from ..findings import Finding, Severity
from .. import patterns as P
from .base import Analyzer, Context

_SENSITIVE_COLS = re.compile(
    r"(pass|senha|pwd|secret|token|hash|api[_-]?key|credit|card|cvv|ssn|cpf|salt)", re.I)
_SENSITIVE_TABLES = re.compile(r"(user|users|admin|login|account|conta|session|cred)", re.I)


class SqliteAnalyzer(Analyzer):
    name = "sqlite"
    category = "sqlite"
    handles = ("sqlite",)

    def analyze(self, ev: Evidence, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        # Copia para tempfile (evita lock e permite ro).
        tmp = Path(tempfile.gettempdir()) / f"vestigium_{ev.sha256[:10]}.db"
        try:
            tmp.write_bytes(ev.read_bytes())
        except OSError:
            return findings

        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
            con.text_factory = lambda b: b.decode("utf-8", "replace")
            findings += self._schema(ev, con)
            findings += self._scan_rows(ev, con)
            con.close()
        except sqlite3.DatabaseError as exc:
            findings.append(Finding(
                analyzer=self.name, category="sqlite",
                title="Banco SQLite corrompido ou parcial",
                severity=Severity.LOW, source=str(ev.path),
                description=f"Leitura via SQL falhou ({exc}); tentando carving bruto.",
            ))
        # Carving de registros apagados (independe do SQL funcionar)
        findings += self._carve_deleted(ev)
        try:
            tmp.unlink()
        except OSError:
            pass
        return findings

    # ---------------------------------------------------------------
    def _schema(self, ev, con) -> list[Finding]:
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        out = [Finding(
            analyzer=self.name, category="sqlite",
            title=f"Banco SQLite com {len(tables)} tabela(s)",
            severity=Severity.INFO, source=str(ev.path),
            evidence=", ".join(tables[:30]),
            data={"tables": tables},
        )]
        for t in tables:
            try:
                cols = [c[1] for c in cur.execute(f'PRAGMA table_info("{t}")').fetchall()]
            except sqlite3.DatabaseError:
                continue
            sens = [c for c in cols if _SENSITIVE_COLS.search(c)]
            if sens or _SENSITIVE_TABLES.search(t):
                try:
                    n = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                except sqlite3.DatabaseError:
                    n = "?"
                out.append(Finding(
                    analyzer=self.name, category="sqlite",
                    title=f"Tabela sensivel '{t}' ({n} registros)",
                    severity=Severity.HIGH, source=str(ev.path),
                    description=f"Colunas sensiveis: {sens or '(nome da tabela)'}.",
                    tags=["pii", "credentials"], mitre=["T1005"],
                    recommendation="Verificar cifragem em repouso e minimizacao de dados.",
                    data={"table": t, "columns": cols},
                ))
        return out

    def _scan_rows(self, ev, con) -> list[Finding]:
        out = []
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        flags, hashes = [], []
        for t in tables:
            try:
                rows = cur.execute(f'SELECT * FROM "{t}" LIMIT 5000').fetchall()
            except sqlite3.DatabaseError:
                continue
            for row in rows:
                cell = " ".join(str(c) for c in row)
                flags += P.find_flags(cell)
                hashes += P.RE_MD5.findall(cell) + P.RE_SHA1.findall(cell) + P.RE_SHA256.findall(cell)
        if flags:
            out.append(Finding(
                analyzer=self.name, category="sqlite",
                title="Bandeira em registro do banco",
                severity=Severity.HIGH, source=str(ev.path),
                evidence="; ".join(dict.fromkeys(flags))[:200],
                flags=list(dict.fromkeys(flags))))
        if hashes:
            uniq = list(dict.fromkeys(hashes))
            out.append(Finding(
                analyzer=self.name, category="sqlite",
                title=f"{len(uniq)} hash(es) de credencial armazenado(s)",
                severity=Severity.MEDIUM, source=str(ev.path),
                evidence="; ".join(uniq[:5]),
                iocs={"hash": uniq[:100]}, tags=["credentials"],
                recommendation="Usar algoritmos lentos com salt (bcrypt/argon2).",
            ))
        return out

    def _carve_deleted(self, ev) -> list[Finding]:
        """Carving simples: le paginas, coleta ASCII de areas nao alocadas."""
        try:
            data = ev.read_bytes()
        except OSError:
            return []
        if data[:16] != b"SQLite format 3\x00":
            return []
        page_size = struct.unpack_from(">H", data, 16)[0] or 4096
        if page_size == 1:
            page_size = 65536
        recovered = []
        n_pages = len(data) // page_size
        for i in range(n_pages):
            page = data[i * page_size:(i + 1) * page_size]
            # heuristica: strings imprimiveis longas nao referenciadas
            for s in P.extract_strings(page, min_len=8):
                if P.RE_FLAG.search(s) or P.RE_EMAIL.search(s):
                    recovered.append(s)
        recovered = list(dict.fromkeys(recovered))
        if not recovered:
            return []
        return [Finding(
            analyzer=self.name, category="sqlite",
            title=f"{len(recovered)} artefato(s) recuperado(s) de area nao alocada",
            severity=Severity.HIGH, source=str(ev.path),
            description="Strings sensiveis em paginas/freelist (possiveis registros apagados).",
            evidence="\n".join(recovered[:8]),
            flags=P.find_flags("\n".join(recovered)),
            iocs={"email": [e for s in recovered for e in P.RE_EMAIL.findall(s)][:50]},
            tags=["carving", "deleted"], mitre=["T1005"],
            recommendation="Registros apagados permanecem recuperaveis; usar VACUUM/secure delete.",
        )]
