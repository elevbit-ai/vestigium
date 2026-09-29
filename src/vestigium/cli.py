"""Interface de linha de comando do Vestigium.

Uso:
    vestigium scan <caminho> [-o SAIDA] [--formats html,md,json] [--quiet]
    vestigium version

Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agent import Agent
from .findings import Severity
from . import report as report_mod

BANNER = r"""
 __     __        _   _       _
 \ \   / /__  ___| |_(_) __ _(_)_   _ _ __ ___
  \ \ / / _ \/ __| __| |/ _` | | | | | '_ ` _ \
   \ V /  __/\__ \ |_| | (_| | | |_| | | | | | |
    \_/ \___||___/\__|_|\__, |_|\__,_|_| |_| |_|
                        |___/  agente forense autonomo
"""


def _print_summary(result) -> None:
    print("\n" + "=" * 60)
    print(f"  RISCO: {result.risk_label} ({result.risk_score}/100)")
    print(f"  Evidencias: {result.stats['evidence_count']} | "
          f"Achados: {result.stats['finding_count']} | "
          f"Tempo: {result.duration}s")
    sev = result.stats["by_severity"]
    print("  Severidade: " + " | ".join(
        f"{Severity[k].label}={v}" for k, v in sev.items() if v))
    if result.stats["flags"]:
        print("  Bandeiras: " + ", ".join(result.stats["flags"][:10]))
    print("=" * 60)


def cmd_scan(args) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"erro: caminho nao encontrado: {target}", file=sys.stderr)
        return 2
    if not args.quiet:
        print(BANNER)
    out_dir = Path(args.output)
    agent = Agent(verbose=not args.quiet)
    result = agent.scan(str(target), out_dir)

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    paths = {}
    if "html" in formats:
        p = out_dir / "relatorio.html"
        report_mod.write_html(result, p)
        paths["html"] = p
    if "md" in formats:
        p = out_dir / "relatorio.md"
        report_mod.write_markdown(result, p)
        paths["md"] = p
    if "json" in formats:
        p = out_dir / "relatorio.json"
        report_mod.write_json(result, p)
        paths["json"] = p

    _print_summary(result)
    print("\nRelatorios gerados:")
    for fmt, p in paths.items():
        print(f"  - {fmt.upper():4} {p}")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def cmd_recon(args) -> int:
    from .offensive import ReconAgent
    from . import report as rp

    if not args.quiet:
        print(BANNER)
        print("  MODO PENTEST - reconhecimento nao destrutivo (autorizado)\n")

    if not args.authorize:
        print("erro: reconhecimento requer autorizacao explicita.\n"
              "      Use --authorize para confirmar que voce tem permissao\n"
              "      para testar este alvo. Uso etico e autorizado apenas.",
              file=sys.stderr)
        return 2

    out_dir = Path(args.output)
    agent = ReconAgent(verbose=not args.quiet, timeout=args.timeout,
                       max_threads=args.threads)
    try:
        result = agent.scan(args.target, out_dir, authorized=True,
                            full_ports=args.full_ports)
    except (ValueError, PermissionError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    paths = {}
    if "html" in formats:
        p = out_dir / "pentest.html"
        rp.write_html(result, p, rp.PENTEST)
        paths["html"] = p
    if "md" in formats:
        p = out_dir / "pentest.md"
        rp.write_markdown(result, p, rp.PENTEST)
        paths["md"] = p
    if "json" in formats:
        p = out_dir / "pentest.json"
        rp.write_json(result, p, rp.PENTEST)
        paths["json"] = p

    _print_summary(result)
    print("\nRelatorios gerados:")
    for fmt, p in paths.items():
        print(f"  - {fmt.upper():4} {p}")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vestigium",
        description="Agente autonomo de analise forense e CTF "
                    "(PCAP, LOG, SQLite, Stego, Crypto, Warmup, Phishing, Cadeia, Dropper).",
        epilog="Autor: Joaquim Pedro de Morais Filho <j360074@hotmail.com>",
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"vestigium {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="analisar um arquivo ou diretorio de evidencias")
    sc.add_argument("target", help="arquivo ou pasta com as evidencias")
    sc.add_argument("-o", "--output", default="vestigium-report",
                    help="diretorio de saida (padrao: vestigium-report)")
    sc.add_argument("--formats", default="html,md,json",
                    help="formatos separados por virgula (html,md,json)")
    sc.add_argument("--fail-on", metavar="SEV",
                    choices=[s.name.lower() for s in Severity],
                    help="retorna codigo 1 se houver achado >= severidade (para CI)")
    sc.add_argument("-q", "--quiet", action="store_true", help="silencia a trilha")
    sc.set_defaults(func=cmd_scan)

    rc = sub.add_parser(
        "recon",
        help="pentest: reconhecimento nao destrutivo de UM alvo autorizado",
        description="Reconhecimento de pentest (portas, servicos, HTTP, TLS, "
                    "descoberta). Sem exploracao, forca bruta ou DoS. "
                    "Requer autorizacao explicita (--authorize).",
    )
    rc.add_argument("target", help="um unico host/IP/URL autorizado (sem CIDR/listas)")
    rc.add_argument("--authorize", action="store_true",
                    help="confirma que voce tem permissao para testar o alvo")
    rc.add_argument("-o", "--output", default="vestigium-pentest",
                    help="diretorio de saida (padrao: vestigium-pentest)")
    rc.add_argument("--formats", default="html,md,json",
                    help="formatos separados por virgula (html,md,json)")
    rc.add_argument("--full-ports", action="store_true",
                    help="varre 1-1024 alem das portas comuns (mais lento)")
    rc.add_argument("--timeout", type=float, default=2.0,
                    help="timeout por conexao em segundos (padrao: 2.0)")
    rc.add_argument("--threads", type=int, default=100,
                    help="conexoes simultaneas na varredura (padrao: 100)")
    rc.add_argument("--fail-on", metavar="SEV",
                    choices=[s.name.lower() for s in Severity],
                    help="retorna codigo 1 se houver achado >= severidade (para CI)")
    rc.add_argument("-q", "--quiet", action="store_true", help="silencia a trilha")
    rc.set_defaults(func=cmd_recon)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
