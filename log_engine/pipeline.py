"""Module 2 : enchaîner filter(), map() et lambda, router avec match-case."""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

from log_engine.config import VALID_LEVELS, LogRecord
from log_engine.ingestion import parse_stream, read_many_files


def route(item: object) -> str:
    """Dit quel est le format d'un payload ou d'une connexion."""
    # Les cas sont testés de haut en bas. "error" passe avant "event" :
    # un échec de connexion contient à la fois "level" et "event".
    match item:
        case str():
            return "raw"
        case {"level": "ERROR" | "CRITICAL", "code": int()}:
            return "error"
        case {"event": str()}:
            return "event"
        case (str(), int(), "TCP" | "UDP" | "SSH"):
            return "connection"
        case _:
            return "unknown"


def normalize(record: LogRecord) -> LogRecord:
    """Met le niveau en majuscules, l'utilisateur en minuscules, ajoute un résumé."""
    record["level"] = record["level"].strip().upper()
    record["user"] = record["user"].strip().lower()
    if isinstance(record["payload"], str):
        record["payload"] = record["payload"].strip()
    ip, port, protocol = record["connection"]  # on déballe le tuple
    record["summary"] = f"[{record['level']}] {ip}:{port}/{protocol} {record['user']}"
    return record


def categorize(record: LogRecord) -> LogRecord:
    """Ajoute au log la catégorie de son payload (raw, error ou event)."""
    record["category"] = route(record["payload"])
    return record


def count_lines(lines: Iterable[str], stats: defaultdict[str, int]) -> Iterator[str]:
    """Compte les lignes au passage, sans les stocker."""
    for line in lines:
        stats["read"] += 1
        yield line


def build_pipeline(
    paths: Iterable[str | Path], stats: defaultdict[str, int] | None = None
) -> Iterator[LogRecord]:
    """Enchaîne lecture, parsing, filtres et transformations, sans aucune liste.

    Rien n'est calculé ici : chaque log ne traverse la chaîne que lorsque
    quelqu'un le demande (boucle for), comme sur un tapis roulant.
    """
    lines = read_many_files(paths)
    if stats is not None:
        lines = count_lines(lines, stats)
    records: Iterator[LogRecord] = filter(None, parse_stream(lines))  # enlève None
    # normalize passe avant le filtre, sinon un niveau "error" serait rejeté
    records = map(normalize, records)
    records = filter(lambda r: r["level"] in VALID_LEVELS, records)  # enlève DEBUG
    records = filter(lambda r: route(r["connection"]) == "connection", records)
    records = map(categorize, records)
    return records
