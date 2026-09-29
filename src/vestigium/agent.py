"""Agente autonomo de analise forense do Vestigium.

O agente executa um ciclo deterministico:
  1. Percepcao  - coleta e identifica evidencias.
  2. Roteamento - decide quais analisadores se aplicam a cada evidencia.
  3. Analise    - executa os analisadores e coleta achados.
  4. Correlacao - o analisador Cadeia liga achados entre evidencias.
  5. Sintese    - pontua o risco e produz o relatorio.

Cada decisao e registrada em `trace` para tornar o comportamento auditavel.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import evidence as ev_mod
from .analyzers import default_analyzers, ChainAnalyzer, Context
from .findings import Finding, Severity


@dataclass
class ScanResult:
    target: str
    started: float
    finished: float
    evidences: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return round(self.finished - self.started, 2)

    @property
    def risk_score(self) -> int:
        """0-100 a partir da severidade dos achados (saturacao suave)."""
        weight = {Severity.INFO: 0, Severity.LOW: 3, Severity.MEDIUM: 8,
                  Severity.HIGH: 18, Severity.CRITICAL: 35}
        total = sum(weight[f.severity] for f in self.findings)
        return min(100, total)

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s >= 75:
            return "Critico"
        if s >= 45:
            return "Alto"
        if s >= 20:
            return "Medio"
        if s > 0:
            return "Baixo"
        return "Limpo"


class Agent:
    """Orquestrador. Use `Agent().scan(path, out_dir)`."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.analyzers = default_analyzers()
        self.chain = ChainAnalyzer()

    def _log(self, trace: list[str], msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        trace.append(line)
        if self.verbose:
            print(line)

    def scan(self, target: str, out_dir: str | Path) -> ScanResult:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        started = time.time()
        trace: list[str] = []
        ctx = Context(out_dir)

        # 1. Percepcao
        self._log(trace, f"Percepcao: coletando evidencias de '{target}'")
        evidences = ev_mod.collect(target)
        ctx.evidences = evidences
        self._log(trace, f"Percepcao: {len(evidences)} arquivo(s) identificado(s)")
        by_kind: dict[str, int] = {}
        for e in evidences:
            by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
        self._log(trace, f"Percepcao: tipos = {by_kind}")

        # 2-3. Roteamento + Analise
        findings: list[Finding] = []
        for e in evidences:
            routed = [a for a in self.analyzers if a.can_handle(e)]
            self._log(trace,
                      f"Roteamento: {e.name} ({e.kind}) -> "
                      f"{', '.join(a.name for a in routed) or 'nenhum'}")
            for a in routed:
                try:
                    res = a.analyze(e, ctx)
                except Exception as exc:  # analisador nunca derruba a varredura
                    self._log(trace, f"  ! {a.name} falhou em {e.name}: {exc}")
                    continue
                if res:
                    findings.extend(res)
                    ctx.all_findings = findings  # visivel para correlacao futura
                    self._log(trace, f"  + {a.name}: {len(res)} achado(s)")

        # 4. Correlacao (Cadeia)
        ctx.all_findings = findings
        self._log(trace, "Correlacao: reconstruindo cadeia de ataque")
        chain_findings = self.chain.correlate(ctx)
        findings.extend(chain_findings)
        self._log(trace, f"Correlacao: {len(chain_findings)} achado(s) de cadeia")

        # 5. Sintese
        findings.sort(key=lambda f: (-int(f.severity), f.category, f.analyzer))
        finished = time.time()
        result = ScanResult(
            target=str(target), started=started, finished=finished,
            evidences=evidences, findings=findings, trace=trace,
        )
        result.stats = self._compute_stats(result)
        self._log(trace,
                  f"Sintese: risco={result.risk_label} ({result.risk_score}/100), "
                  f"{len(findings)} achado(s) em {result.duration}s")
        return result

    @staticmethod
    def _compute_stats(result: ScanResult) -> dict:
        sev_count = {s.name: 0 for s in Severity}
        cat_count: dict[str, int] = {}
        flags: list[str] = []
        iocs: dict[str, set] = {}
        for f in result.findings:
            sev_count[f.severity.name] += 1
            cat_count[f.category] = cat_count.get(f.category, 0) + 1
            flags.extend(f.flags)
            for k, vals in f.iocs.items():
                iocs.setdefault(k, set()).update(vals)
        return {
            "evidence_count": len(result.evidences),
            "finding_count": len(result.findings),
            "by_severity": sev_count,
            "by_category": cat_count,
            "flags": list(dict.fromkeys(flags)),
            "ioc_count": {k: len(v) for k, v in iocs.items()},
            "iocs": {k: sorted(v) for k, v in iocs.items()},
        }
