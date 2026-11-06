"""Point d'entrée : lance tout le pipeline log_engine."""

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
    existing: list[str] = []
    for path in paths:
        if Path(path).is_file():
            existing.append(path)
        else:
            logging.warning("Fichier introuvable : %s", path)
    return existing


def run_rules(
    files: list[str],
    rule_names: list[str],
    blacklist: frozenset[str],
    audit: dict[str, Any],
) -> dict[str, Any]:
    """Lance le moteur de règles sur un pipeline neuf."""
    # Pipeline neuf : le premier générateur a déjà été vidé par aggregate
    return apply_security_rules(
        *[RULES[name] for name in rule_names],
        records=build_pipeline(files),
        audit_sink=audit,
        blacklist=blacklist,
        allowed_ports=ALLOWED_PORTS,
        night_end_hour=NIGHT_END_HOUR,
    )


def analyze(
    files: list[str],
    blacklist: frozenset[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Enchaîne l'agrégation, la détection, les règles et l'audit."""
    stats: defaultdict[str, int] = defaultdict(int)
    agg = aggregate(build_pipeline(files, stats))
    ip_sets = compare_ips(agg["active_ips"], blacklist)
    brute_force = detect_brute_force(agg["login_events"], args.max_failures)
    audit: dict[str, Any] = {}
    alerts = run_rules(files, args.rules, blacklist, audit)
    if args.audit:
        audit["main"] = audit_scope(globals(), "globals")
        save_audit(audit, Path(args.output) / "audit.json")
    _, peak = tracemalloc.get_traced_memory()
    return build_report(
        files, stats, agg, ip_sets, brute_force, alerts, args.max_failures, peak
    )


def publish(report: dict[str, Any], report_path: Path) -> None:
    """Enregistre le rapport, puis l'affiche."""
    save_report(report, report_path)
    print_report(report, report_path)


def main() -> int:
    """Lance tout le pipeline et rend le code de sortie."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args()
    # Dossier créé tout de suite : audit.json s'écrit avant le rapport
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    files = keep_existing(args.files)
    if not files:
        logging.error("Aucun fichier de logs à analyser")
        return 1
    tracemalloc.start()
    try:
        blacklist = load_blacklist(args.blacklist)
    except FileNotFoundError:
        logging.error("Liste noire introuvable : %s", args.blacklist)
        return 1
    publish(analyze(files, blacklist, args), output_dir / "rapport.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
