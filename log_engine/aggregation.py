"""Module 3 : ensembles, compteurs et force brute."""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from log_engine.config import ERROR_LEVELS, LOGIN_EVENTS
from log_engine.models import LogRecord


def load_blacklist(path: str | Path) -> frozenset[str]:
    """Lit la liste noire : une IP par ligne."""
    with open(path, encoding="utf-8") as f:
        ips: Iterator[str] = map(str.strip, f)  # enlève espaces et retours à la ligne
        ips = filter(None, ips)  # enlève les lignes vides
        return frozenset(ips)  # liste figée, impossible à modifier


def note_login(
    login_events: defaultdict[str, list[bool]], ip: str, payload: object
) -> None:
    """Ajoute la tentative à l'historique de l'IP si le log est une connexion."""
    if not isinstance(payload, dict):
        return
    event = payload.get("event")
    if event in LOGIN_EVENTS:
        # Un bool et non le texte : 3 Mo au lieu de 23 Mo sur 1 million de lignes
        login_events[ip].append(event == "login_failed")


def aggregate(records: Iterable[LogRecord]) -> dict[str, Any]:
    """Remplit tous les compteurs en un seul passage sur le flux."""
    by_level: defaultdict[str, int] = defaultdict(int)
    by_category: defaultdict[str, int] = defaultdict(int)
    by_user: defaultdict[str, int] = defaultdict(int)
    error_counts: defaultdict[str, int] = defaultdict(int)
    login_events: defaultdict[str, list[bool]] = defaultdict(list)
    error_ips: set[str] = set()
    active_ips: set[str] = set()
    total = 0

    # Un générateur ne se lit qu'une fois : tout se remplit dans cette boucle
    for record in records:
        ip = record["connection"].ip
        total += 1
        by_level[record["level"]] += 1
        by_category[record["category"]] += 1
        by_user[record["user"]] += 1
        active_ips.add(ip)
        if record["level"] in ERROR_LEVELS:
            error_ips.add(ip)
            error_counts[ip] += 1
        note_login(login_events, ip, record["payload"])

    return {
        "total": total,
        "by_level": by_level,
        "by_category": by_category,
        "by_user": by_user,
        "error_ips": error_ips,
        "error_counts": error_counts,
        "active_ips": active_ips,
        "login_events": login_events,
    }


def compare_ips(active_ips: set[str], blacklist: frozenset[str]) -> dict[str, set[str]]:
    """Compare les IP actives et la liste noire avec les 4 opérations d'ensembles."""
    return {
        "union": active_ips | blacklist,
        "blacklisted_active": active_ips & blacklist,
        "active_not_blacklisted": active_ips - blacklist,
        "one_side_only": active_ips ^ blacklist,
    }


def detect_brute_force(
    login_events: dict[str, list[bool]], max_failures: int
) -> dict[str, list[str]]:
    """Trouve les IP qui ont raté trop de connexions de suite."""
    suspects: list[str] = []
    clean: list[str] = []

    for ip, failures in login_events.items():
        # Moins de tentatives que le seuil : impossible d'avoir une attaque
        if len(failures) < max_failures:
            clean.append(ip)
            continue

        # On parcourt les tentatives une par une
        i = 0
        streak = 0  # nombre d'échecs de suite
        while i < len(failures):
            if failures[i]:
                streak = streak + 1  # encore un échec
            else:
                streak = 0  # une réussite remet à zéro
            i = i + 1

            if streak >= max_failures:
                suspects.append(ip)
                break  # attaque trouvée, on arrête pour cette IP
        else:
            # La boucle est allée au bout sans break : aucune attaque
            clean.append(ip)

    return {"suspects": sorted(suspects), "clean": sorted(clean)}
