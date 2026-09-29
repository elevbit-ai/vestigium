"""Analisador Cadeia (Chain): correlaciona achados e reconstroi o ataque.

Diferente dos demais, roda ao final sobre TODOS os achados. Correlaciona
IOCs compartilhados entre evidencias, monta uma linha do tempo e mapeia o
que foi observado nas fases da cyber kill chain / MITRE ATT&CK.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

from collections import defaultdict

from ..findings import Finding, Severity
from .base import Context

# Ordem das fases da kill chain e as categorias/tecnicas que as alimentam.
KILL_CHAIN = [
    ("Reconhecimento", ["scanning", "web-attack"], ["T1595", "T1595.003", "T1190"]),
    ("Entrega", ["phishing", "shortener", "masked-link", "attachment"],
     ["T1566", "T1566.001", "T1566.002"]),
    ("Exploracao", ["web-attack", "dropper"], ["T1190", "T1204.002", "T1203"]),
    ("Instalacao", ["dropper", "packed", "persistence"],
     ["T1105", "T1547.001", "T1027"]),
    ("Comando e Controle", ["c2", "beacon", "dns-tunnel"],
     ["T1071", "T1071.001", "T1071.004", "T1105"]),
    ("Acoes sobre o objetivo", ["exfil", "credentials", "pii", "carving"],
     ["T1048", "T1040", "T1005", "T1552"]),
]


class ChainAnalyzer:
    name = "chain"
    category = "chain"

    def correlate(self, ctx: Context) -> list[Finding]:
        findings = ctx.all_findings
        if not findings:
            return []
        out: list[Finding] = []
        out += self._shared_iocs(findings)
        out += self._kill_chain(findings)
        out += self._timeline(findings)
        return out

    # ---------------------------------------------------------------
    def _shared_iocs(self, findings) -> list[Finding]:
        """IOCs que aparecem em mais de uma evidencia = pivot da cadeia."""
        index: dict[tuple[str, str], set] = defaultdict(set)
        for f in findings:
            for kind, vals in f.iocs.items():
                for v in vals:
                    index[(kind, v)].add(f.source)
        pivots = {k: srcs for k, srcs in index.items() if len(srcs) >= 2}
        if not pivots:
            return []
        lines = [f"{kind}={val} -> {len(srcs)} evidencias"
                 for (kind, val), srcs in sorted(pivots.items(), key=lambda x: -len(x[1]))[:20]]
        merged: dict[str, list[str]] = defaultdict(list)
        for (kind, val) in pivots:
            merged[kind].append(val)
        return [Finding(
            analyzer=self.name, category="chain",
            title=f"{len(pivots)} IOC(s) correlacionado(s) entre multiplas evidencias",
            severity=Severity.HIGH, source="(correlacao)",
            description="Indicadores compartilhados ligam artefatos diferentes do incidente.",
            evidence="\n".join(lines),
            iocs=dict(merged), tags=["correlation", "pivot"],
            recommendation="Tratar como um unico incidente; bloquear IOCs em conjunto.",
        )]

    def _kill_chain(self, findings) -> list[Finding]:
        tag_set = set()
        tech_set = set()
        cat_set = set()
        for f in findings:
            tag_set.update(f.tags)
            tech_set.update(f.mitre)
            cat_set.add(f.category)

        observed = []
        phase_hits = {}
        for phase, tags, techs in KILL_CHAIN:
            hit = (set(tags) & tag_set) or (set(techs) & tech_set) or (set(tags) & cat_set)
            if hit:
                observed.append(phase)
                phase_hits[phase] = sorted(set(map(str, hit)))
        if len(observed) < 2:
            return []
        sev = Severity.CRITICAL if len(observed) >= 4 else Severity.HIGH
        desc = " -> ".join(observed)
        detail = "\n".join(f"[{p}] {', '.join(phase_hits[p])}" for p in observed)
        return [Finding(
            analyzer=self.name, category="chain",
            title=f"Cadeia de ataque reconstruida: {len(observed)} fase(s)",
            severity=sev, source="(correlacao)",
            description=f"Fases observadas: {desc}.",
            evidence=detail,
            mitre=sorted(tech_set)[:20], tags=["kill-chain"],
            recommendation="Conter na fase mais avancada e erradicar de tras para frente.",
            data={"phases": observed},
        )]

    def _timeline(self, findings) -> list[Finding]:
        stamped = [f for f in findings if f.data.get("interval_s") or f.ts]
        if not stamped:
            return []
        by_sev = sorted(findings, key=lambda f: (-int(f.severity), f.category))
        top = by_sev[:12]
        lines = [f"[{f.severity.label}] {f.category}: {f.title}" for f in top]
        return [Finding(
            analyzer=self.name, category="chain",
            title="Resumo priorizado do incidente",
            severity=Severity.INFO, source="(correlacao)",
            description="Principais achados ordenados por severidade.",
            evidence="\n".join(lines), tags=["summary"],
        )]
