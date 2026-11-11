"""Point d'entrée : lance tout le pipeline sur les fichiers de logs donnés.

Exemple :
    python main.py data/app_logs_1.log data/app_logs_2.log \
        --blacklist data/blacklist.txt --audit
"""

import argparse
import logging
import sys
import tracemalloc
from collections import defaultdict
from pathlib import Path
from typing import Any

from log_engine.aggregation import (
    aggregate,
    compare_ips,
    detect_brute_force,
    load_blacklist,
)
from log_engine.audit import audit_scope, save_audit
from log_engine.config import ALLOWED_PORTS, MAX_FAILURES, NIGHT_END_HOUR
from log_engine.pipeline import build_pipeline
from log_engine.report import build_report, print_report, save_report
from log_engine.rules import RULES, apply_security_rules


def positive_int(text: str) -> int:
    """Convertit une option en entier, en refusant tout ce qui est sous 1."""
    value = int(text)
    # Au seuil 0, une IP sans aucun échec serait déclarée suspecte
    if value < 1:
        raise argparse.ArgumentTypeError("le seuil doit valoir au moins 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Décrit les options de la ligne de commande."""
    parser = argparse.ArgumentParser(description="Analyse de logs de sécurité")
    parser.add_argument("files", nargs="+", help="fichiers de logs à analyser")
    parser.add_argument("--blacklist", required=True, help="fichier des IP interdites")
    parser.add_argument("--max-failures", type=positive_int, default=MAX_FAILURES)
    parser.add_argument(
        "--rules", nargs="+", choices=sorted(RULES), default=sorted(RULES)
    )
    parser.add_argument("--output", default="output", help="dossier des rapports")
    parser.add_argument("--audit", action="store_true", help="exporte audit.json")
    return parser


def keep_existing(paths: list[str]) -> list[str]:
    """Garde les fichiers présents et avertit une seule fois pour les autres."""
    existing = []
    for path in paths:
        if Path(path).is_file():
            existing.append(path)
        else:
            logging.warning("Fichier introuvable : %s", path)
    return existing


def analyze(
    files: list[str], blacklist: frozenset[str], args: argparse.Namespace
) -> dict[str, Any]:
    """Les 4 modules dans l'ordre : pipeline, agrégation, règles, audit."""
    # 1er passage sur les logs : tous les compteurs
    stats: defaultdict[str, int] = defaultdict(int)
    agg = aggregate(build_pipeline(files, stats))
    ip_sets = compare_ips(agg["active_ips"], blacklist)
    brute_force = detect_brute_force(agg["login_events"], args.max_failures)

    # 2e passage : un pipeline neuf, car un générateur ne se lit qu'une fois
    audit: dict[str, Any] = {}
    alerts = apply_security_rules(
        *[RULES[name] for name in args.rules],  # *args : les règles choisies
        records=build_pipeline(files),  # **kwargs : le flux et les réglages
        audit_sink=audit,
        blacklist=blacklist,
        allowed_ports=ALLOWED_PORTS,
        night_end_hour=NIGHT_END_HOUR,
    )

    if args.audit:
        audit["main"] = audit_scope(globals(), "globals")
        save_audit(audit, Path(args.output) / "audit.json")

    _, peak = tracemalloc.get_traced_memory()
    return build_report(
        files,
        stats["read"],
        agg,
        ip_sets,
        brute_force,
        alerts,
        args.max_failures,
        peak,
    )


def main() -> int:
    """Lit les options, vérifie les fichiers et lance l'analyse (0 = succès)."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = keep_existing(args.files)
    if not files:
        logging.error("Aucun fichier de logs à analyser")
        return 1
    try:
        blacklist = load_blacklist(args.blacklist)
    except FileNotFoundError:
        logging.error("Liste noire introuvable : %s", args.blacklist)
        return 1

    tracemalloc.start()  # mesure la mémoire réellement utilisée par l'analyse
    report = analyze(files, blacklist, args)
    report_path = output_dir / "rapport.json"
    save_report(report, report_path)
    print_report(report, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
