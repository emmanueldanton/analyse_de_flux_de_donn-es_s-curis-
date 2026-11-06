"""Affichage et export du rapport."""

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from log_engine.config import LEVEL_ORDER

TOP_LIMIT: int = 10
BAR_WIDTH: int = 53


def sort_counts(counts: Mapping[str, int]) -> list[tuple[str, int]]:
    """Trie un compteur du plus grand au plus petit, puis par nom."""
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))


def top_pairs(counts: Mapping[str, int]) -> list[list[Any]]:
    """Rend les premières paires d'un compteur, sous forme de listes pour le JSON."""
    return [[name, count] for name, count in sort_counts(counts)[:TOP_LIMIT]]


def build_report(
    files: list[str],
    stats: Mapping[str, int],
    agg: dict[str, Any],
    ip_sets: dict[str, set[str]],
    brute_force: dict[str, list[str]],
    alerts: dict[str, Any],
    max_failures: int,
    peak_bytes: int,
) -> dict[str, Any]:
    """Rassemble tous les résultats dans un dictionnaire prêt pour le JSON."""
    read = stats["read"]
    valid = agg["total"]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "files": files,
        "lines": {"read": read, "valid": valid, "rejected": read - valid},
        "by_level": {level: agg["by_level"][level] for level in LEVEL_ORDER},
        "by_category": dict(sort_counts(agg["by_category"])),
        "top_users": top_pairs(agg["by_user"]),
        "error_ips": sorted(agg["error_ips"]),
        "top_error_ips": top_pairs(agg["error_counts"]),
        # Le JSON ne connaît pas les set : on les convertit en listes triées
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


def join_counts(counts: Mapping[str, int]) -> str:
    """Écrit un compteur sur une ligne : INFO 12 | ERROR 3."""
    return " | ".join([f"{name} {count}" for name, count in counts.items()])


def print_summary(report: dict[str, Any]) -> None:
    """Affiche les fichiers, les lignes et les compteurs."""
    lines = report["lines"]
    print(f"Fichiers analysés : {len(report['files'])}")
    print(
        f"Lignes lues : {lines['read']} | valides : {lines['valid']} "
        f"| rejetées : {lines['rejected']}"
    )
    print()
    print(f"{'Par niveau':<15}{join_counts(report['by_level'])}")
    print(f"{'Par catégorie':<15}{join_counts(report['by_category'])}")


def print_threats(report: dict[str, Any]) -> None:
    """Affiche les IP blacklistées actives et la force brute."""
    active = report["ip_sets"]["blacklisted_active"]
    brute_force = report["brute_force"]
    suspects = brute_force["suspects"]
    print(f"IP blacklistées encore actives ({len(active)}) : {', '.join(active)}")
    print(
        f"Force brute (seuil {brute_force['max_failures']}) : "
        f"{len(suspects)} IP suspectes"
    )
    for ip in suspects:
        print(f"  - {ip}")


def print_alerts(report: dict[str, Any]) -> None:
    """Affiche le nombre d'alertes de chaque règle."""
    print("Alertes par règle")
    for name, count in report["alerts"]["counts"].items():
        print(f"  {name:<22}{count:>4}")


def print_report(report: dict[str, Any], report_path: str | Path) -> None:
    """Affiche le rapport dans le terminal."""
    print(" RAPPORT DE SÉCURITÉ ".center(BAR_WIDTH, "="))
    print_summary(report)
    print()
    print_threats(report)
    print()
    print_alerts(report)
    print()
    print(f"Pic mémoire : {report['performance']['peak_memory_kb']} Ko")
    print(f"Rapport complet : {report_path}")
    print("=" * BAR_WIDTH)


def save_report(report: dict[str, Any], path: str | Path) -> None:
    """Écrit le rapport en JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
