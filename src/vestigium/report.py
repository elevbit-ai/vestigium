"""Geracao de relatorio profissional (HTML, Markdown, JSON).

Produz um relatorio autocontido e imprimivel a partir de um ScanResult.

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import html
import json
import time
from pathlib import Path

from .agent import ScanResult
from .findings import Severity

AUTHOR = "Joaquim Pedro de Morais Filho"
EMAIL = "j360074@hotmail.com"
TOOL = "Vestigium"


# ---------------------------------------------------------------- JSON
def write_json(result: ScanResult, path: Path) -> None:
    payload = {
        "tool": TOOL,
        "author": AUTHOR,
        "email": EMAIL,
        "target": result.target,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duration_s": result.duration,
        "risk_score": result.risk_score,
        "risk_label": result.risk_label,
        "stats": result.stats,
        "evidences": [
            {"path": str(e.path), "kind": e.kind, "size": e.size,
             "sha256": e.sha256, "md5": e.md5, "entropy": e.entropy}
            for e in result.evidences
        ],
        "findings": [f.to_dict() for f in result.findings],
        "trace": result.trace,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------- Markdown
def write_markdown(result: ScanResult, path: Path) -> None:
    s = result.stats
    L = []
    L.append(f"# Relatorio de Analise Forense - {TOOL}\n")
    L.append(f"- **Alvo:** `{result.target}`")
    L.append(f"- **Gerado em:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- **Autor:** {AUTHOR} <{EMAIL}>")
    L.append(f"- **Duracao:** {result.duration}s")
    L.append(f"- **Risco:** {result.risk_label} ({result.risk_score}/100)\n")

    L.append("## Sumario Executivo\n")
    L.append(f"Foram analisadas **{s['evidence_count']}** evidencias, gerando "
             f"**{s['finding_count']}** achados. "
             f"Severidades: " +
             ", ".join(f"{k}={v}" for k, v in s['by_severity'].items() if v) + ".\n")
    if s["flags"]:
        L.append("### Bandeiras recuperadas\n")
        for fl in s["flags"]:
            L.append(f"- `{fl}`")
        L.append("")

    L.append("## Achados\n")
    for f in result.findings:
        L.append(f"### [{f.severity.label}] {f.title}")
        L.append(f"- **Categoria:** {f.category} | **Analisador:** {f.analyzer} "
                 f"| **ID:** {f.uid}")
        if f.source:
            L.append(f"- **Origem:** `{f.source}`")
        if f.description:
            L.append(f"- {f.description}")
        if f.evidence:
            L.append(f"- **Evidencia:**\n\n```\n{f.evidence[:1500]}\n```")
        if f.mitre:
            L.append(f"- **MITRE ATT&CK:** {', '.join(f.mitre)}")
        if f.iocs:
            L.append("- **IOCs:** " + "; ".join(
                f"{k}: {', '.join(v[:8])}" for k, v in f.iocs.items()))
        if f.recommendation:
            L.append(f"- **Recomendacao:** {f.recommendation}")
        L.append("")

    L.append("## Cadeia de Custodia\n")
    L.append("| Arquivo | Tipo | Tamanho | SHA-256 |")
    L.append("|---|---|---|---|")
    for e in result.evidences:
        L.append(f"| `{e.name}` | {e.kind} | {e.size} B | `{e.sha256}` |")
    L.append("")
    L.append(f"---\n_{TOOL} - agente autonomo de analise forense. "
             f"(c) {AUTHOR}._")
    path.write_text("\n".join(L), encoding="utf-8")


# ---------------------------------------------------------------- HTML
def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def write_html(result: ScanResult, path: Path) -> None:
    s = result.stats
    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]

    # cartoes de severidade
    sev_cards = "".join(
        f'<div class="stat" style="border-color:{sv.color}">'
        f'<div class="num" style="color:{sv.color}">{s["by_severity"][sv.name]}</div>'
        f'<div class="lbl">{sv.label}</div></div>'
        for sv in sev_order
    )

    # barra de risco
    risk_color = {"Critico": "#ef4444", "Alto": "#f97316", "Medio": "#eab308",
                  "Baixo": "#22c55e", "Limpo": "#3b82f6"}[result.risk_label]

    # bandeiras
    flags_html = ""
    if s["flags"]:
        items = "".join(f"<code>{_esc(fl)}</code>" for fl in s["flags"])
        flags_html = f'<div class="flags"><h3>Bandeiras recuperadas</h3>{items}</div>'

    # categorias
    cat_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(s["by_category"].items(), key=lambda x: -x[1])
    )

    # achados
    findings_html = []
    for f in result.findings:
        iocs = ""
        if f.iocs:
            iocs = "<div class='iocs'>" + "".join(
                f"<span class='k'>{_esc(k)}</span>: " +
                ", ".join(f"<code>{_esc(v)}</code>" for v in vals[:12])
                + "<br>" for k, vals in f.iocs.items()) + "</div>"
        mitre = ("<span class='mitre'>" +
                 " ".join(f"<a href='https://attack.mitre.org/techniques/{t.replace('.', '/')}/' "
                          f"target='_blank' rel='noopener'>{_esc(t)}</a>"
                          for t in f.mitre) + "</span>") if f.mitre else ""
        ev = (f"<pre>{_esc(f.evidence[:2000])}</pre>") if f.evidence else ""
        rec = (f"<div class='rec'><b>Recomendacao:</b> {_esc(f.recommendation)}</div>"
               if f.recommendation else "")
        findings_html.append(f"""
        <details class="finding sev-{f.severity.name.lower()}" open>
          <summary>
            <span class="badge" style="background:{f.severity.color}">{f.severity.label}</span>
            <span class="ftitle">{_esc(f.title)}</span>
            <span class="fmeta">{_esc(f.category)} &middot; {_esc(f.analyzer)} &middot; #{f.uid}</span>
          </summary>
          <div class="fbody">
            {f"<p class='desc'>{_esc(f.description)}</p>" if f.description else ""}
            {f"<p class='src'>Origem: <code>{_esc(f.source)}</code></p>" if f.source else ""}
            {ev}
            {mitre}
            {iocs}
            {rec}
          </div>
        </details>""")

    # cadeia de custodia
    coc_rows = "".join(
        f"<tr><td><code>{_esc(e.name)}</code></td><td>{_esc(e.kind)}</td>"
        f"<td>{e.size:,}</td><td>{e.entropy}</td><td class='hash'>{e.sha256}</td></tr>"
        for e in result.evidences
    )

    trace_html = "".join(f"<div>{_esc(t)}</div>" for t in result.trace)

    doc = f"""<!doctype html>
<html lang="pt-br"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatorio {TOOL} - {_esc(Path(result.target).name)}</title>
<style>
:root {{ --bg:#0b1020; --panel:#141b33; --panel2:#1c2545; --txt:#e8ecf7;
        --muted:#93a0c4; --line:#2a3357; --accent:#6ea8fe; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        background:var(--bg); color:var(--txt); }}
.wrap {{ max-width:1100px; margin:0 auto; padding:32px 20px 80px; }}
header.hero {{ background:linear-gradient(135deg,#182042,#0b1020);
        border:1px solid var(--line); border-radius:16px; padding:28px 30px; }}
.hero h1 {{ margin:0 0 4px; font-size:26px; letter-spacing:.5px; }}
.hero .sub {{ color:var(--muted); font-size:14px; }}
.meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
        gap:12px; margin-top:20px; }}
.meta-grid div {{ background:var(--panel2); border:1px solid var(--line);
        border-radius:10px; padding:10px 14px; font-size:13px; }}
.meta-grid b {{ display:block; color:var(--muted); font-weight:600; font-size:11px;
        text-transform:uppercase; letter-spacing:.6px; margin-bottom:2px; }}
.riskbar {{ margin:22px 0; }}
.riskbar .track {{ height:14px; background:var(--panel2); border-radius:8px;
        overflow:hidden; border:1px solid var(--line); }}
.riskbar .fill {{ height:100%; width:{result.risk_score}%; background:{risk_color}; }}
.riskbar .label {{ display:flex; justify-content:space-between; font-size:13px;
        margin-bottom:6px; color:var(--muted); }}
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:24px 0; }}
.stat {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid;
        border-radius:10px; padding:14px; text-align:center; }}
.stat .num {{ font-size:28px; font-weight:700; }}
.stat .lbl {{ font-size:12px; color:var(--muted); }}
h2 {{ font-size:19px; margin:34px 0 14px; padding-bottom:8px;
        border-bottom:1px solid var(--line); }}
.flags {{ background:#132a1e; border:1px solid #1f7a4d; border-radius:12px;
        padding:16px 18px; margin:18px 0; }}
.flags h3 {{ margin:0 0 10px; color:#4ade80; }}
.flags code {{ display:inline-block; background:#0c1f16; color:#86efac;
        padding:4px 10px; margin:4px; border-radius:6px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
th {{ color:var(--muted); font-weight:600; }}
td.hash {{ font-family:monospace; font-size:11px; color:var(--muted);
        word-break:break-all; }}
.finding {{ background:var(--panel); border:1px solid var(--line);
        border-radius:12px; margin:12px 0; overflow:hidden; }}
.finding summary {{ cursor:pointer; padding:14px 16px; list-style:none;
        display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
.finding summary::-webkit-details-marker {{ display:none; }}
.badge {{ color:#0b1020; font-weight:700; font-size:11px; padding:3px 9px;
        border-radius:20px; text-transform:uppercase; letter-spacing:.4px; }}
.ftitle {{ font-weight:600; flex:1; min-width:200px; }}
.fmeta {{ color:var(--muted); font-size:12px; }}
.fbody {{ padding:0 16px 16px; border-top:1px solid var(--line); }}
.fbody .desc {{ color:#cfd8f2; }}
.fbody pre {{ background:#070b18; border:1px solid var(--line); border-radius:8px;
        padding:12px; overflow-x:auto; font-size:12px; color:#cbd5f5; }}
.rec {{ background:#1a2036; border-left:3px solid var(--accent); padding:8px 12px;
        border-radius:6px; margin-top:10px; font-size:13px; }}
.iocs {{ font-size:12px; margin-top:8px; color:var(--muted); }}
.iocs .k {{ color:var(--accent); font-weight:600; }}
.iocs code, .src code, td code {{ background:#0c1226; padding:1px 6px;
        border-radius:4px; color:#a9c1ff; }}
.mitre a {{ display:inline-block; background:#3a1f2e; color:#ffb4c4; text-decoration:none;
        padding:2px 8px; margin:4px 4px 0 0; border-radius:5px; font-size:11px; }}
.sev-critical {{ border-left:4px solid #ef4444; }}
.sev-high {{ border-left:4px solid #f97316; }}
.sev-medium {{ border-left:4px solid #eab308; }}
.sev-low {{ border-left:4px solid #22c55e; }}
.sev-info {{ border-left:4px solid #3b82f6; }}
details.trace {{ background:var(--panel); border:1px solid var(--line);
        border-radius:10px; padding:12px 16px; font-family:monospace; font-size:12px;
        color:var(--muted); }}
footer {{ margin-top:40px; padding-top:20px; border-top:1px solid var(--line);
        color:var(--muted); font-size:13px; text-align:center; }}
@media print {{ body {{ background:#fff; color:#111; }} .finding{{break-inside:avoid;}} }}
</style></head>
<body><div class="wrap">
<header class="hero">
  <h1>&#128270; {TOOL} &mdash; Relatorio de Analise Forense</h1>
  <div class="sub">Agente autonomo de deteccao &middot; PCAP &middot; LOG &middot; SQLite
     &middot; Stego &middot; Crypto &middot; Warmup &middot; Phishing &middot; Cadeia &middot; Dropper</div>
  <div class="meta-grid">
    <div><b>Alvo</b>{_esc(result.target)}</div>
    <div><b>Gerado em</b>{time.strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div><b>Evidencias</b>{s['evidence_count']}</div>
    <div><b>Achados</b>{s['finding_count']}</div>
    <div><b>Duracao</b>{result.duration}s</div>
    <div><b>Analista</b>{AUTHOR}</div>
  </div>
</header>

<div class="riskbar">
  <div class="label"><span>Indice de risco</span>
     <span>{result.risk_label} &mdash; {result.risk_score}/100</span></div>
  <div class="track"><div class="fill"></div></div>
</div>

<div class="stats">{sev_cards}</div>

{flags_html}

<h2>Achados por categoria</h2>
<table><thead><tr><th>Categoria</th><th>Achados</th></tr></thead>
<tbody>{cat_rows}</tbody></table>

<h2>Detalhamento dos achados</h2>
{''.join(findings_html) or '<p>Nenhum achado registrado.</p>'}

<h2>Cadeia de custodia</h2>
<table><thead><tr><th>Arquivo</th><th>Tipo</th><th>Bytes</th><th>Entropia</th>
<th>SHA-256</th></tr></thead><tbody>{coc_rows}</tbody></table>

<h2>Trilha de decisao do agente</h2>
<details class="trace"><summary>Ver {len(result.trace)} passos</summary>{trace_html}</details>

<footer>
  Gerado por <b>{TOOL}</b> &mdash; agente autonomo de analise forense.<br>
  &copy; {time.strftime('%Y')} {AUTHOR} &lt;{EMAIL}&gt;. Uso etico e autorizado apenas.
</footer>
</div></body></html>"""
    path.write_text(doc, encoding="utf-8")


def write_all(result: ScanResult, out_dir: Path, base: str = "relatorio") -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "html": out_dir / f"{base}.html",
        "md": out_dir / f"{base}.md",
        "json": out_dir / f"{base}.json",
    }
    write_html(result, paths["html"])
    write_markdown(result, paths["md"])
    write_json(result, paths["json"])
    return paths
