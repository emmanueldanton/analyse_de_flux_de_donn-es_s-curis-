"""Construire, afficher et enregistrer le rapport final."""

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from log_engine.config import LEVEL_ORDER

WIDTH: int = 53  # largeur du cadre dans le terminal


def ranking(counts: Mapping[str, int], limit: int | None = None) -> list[list[Any]]:
    """Trie un compteur du plus grand au plus petit (à égalité : par nom)."""
    pairs = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    return [[name, count] for name, count in pairs[:limit]]


def build_report(
    files: list[str],
    lines_read: int,
    agg: dict[str, Any],
    ip_sets: dict[str, set[str]],
    brute_force: dict[str, list[str]],
    alerts: dict[str, Any],
    max_failures: int,
    peak_bytes: int,
) -> dict[str, Any]:
    """Rassemble tous les résultats dans un dictionnaire prêt pour le JSON."""
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "files": files,
        "lines": {
            "read": lines_read,
            "valid": agg["total"],
            "rejected": lines_read - agg["total"],
        },
        "by_level": {level: agg["by_level"][level] for level in LEVEL_ORDER},
        "by_category": dict(ranking(agg["by_category"])),
        "top_users": ranking(agg["by_user"], 10),
        "error_ips": sorted(agg["error_ips"]),
        "top_error_ips": ranking(agg["error_counts"], 10),
        # Le JSON ne connaît pas les set : on les écrit en listes triées
        "ip_sets": {name: sorted(ips) for name, ips in ip_sets.items()},
        "brute_force": {
            "max_failures": max_failures,
            "suspects": brute_force["suspects"],
            "clean_count": len(brute_force["clean"]),
        },
        "alerts": {
            "counts": dict(sorted(alerts["counts"].items())),
            "samples": dict(sorted(alerts["samples"].items())),
        },
        "performance": {"peak_memory_kb": round(peak_bytes / 1024)},
    }


def one_line(counts: Mapping[str, int]) -> str:
    """Écrit un compteur sur une ligne : INFO 12 | ERROR 3."""
    return " | ".join(f"{name} {count}" for name, count in counts.items())


def print_report(report: dict[str, Any], report_path: str | Path) -> None:
    """Affiche le rapport dans le terminal."""
    lines = report["lines"]
    active = report["ip_sets"]["blacklisted_active"]
    brute_force = report["brute_force"]

    print(" RAPPORT DE SÉCURITÉ ".center(WIDTH, "="))
    print(f"Fichiers analysés : {len(report['files'])}")
    print(
        f"Lignes lues : {lines['read']} | valides : {lines['valid']} "
        f"| rejetées : {lines['rejected']}"
    )
    print()
    print(f"{'Par niveau':<15}{one_line(report['by_level'])}")
    print(f"{'Par catégorie':<15}{one_line(report['by_category'])}")
    print()
    print(f"IP blacklistées encore actives ({len(active)}) : {', '.join(active)}")
    print(
        f"Force brute (seuil {brute_force['max_failures']}) : "
        f"{len(brute_force['suspects'])} IP suspectes"
    )
    for ip in brute_force["suspects"]:
        print(f"  - {ip}")
    print()
    print("Alertes par règle")
    for name, count in report["alerts"]["counts"].items():
        print(f"  {name:<22}{count:>4}")
    print()
    print(f"Pic mémoire : {report['performance']['peak_memory_kb']} Ko")
    print(f"Rapport complet : {report_path}")
    print("=" * WIDTH)


def save_report(report: dict[str, Any], path: str | Path) -> None:
    """Écrit le rapport dans un fichier JSON lisible."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
