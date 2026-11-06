"""Module 2 : filter, map et match-case."""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from pathlib import Path

from log_engine.config import VALID_LEVELS
from log_engine.ingestion import parse_stream, read_many_files
from log_engine.models import LogRecord


def route(item: object) -> str:
    """Rend le format d'un payload ou d'une connexion."""
    # L'ordre compte : un échec de connexion a les clés de "error" et de "event"
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


def has_valid_connection(record: LogRecord) -> bool:
    """Dit si la connexion du log utilise un protocole connu."""
    return route(record["connection"]) == "connection"


def normalize(record: LogRecord) -> LogRecord:
    """Nettoie le niveau, l'utilisateur et le texte, puis ajoute le résumé."""
    level = record["level"].strip().upper()
    user = record["user"].strip().lower()
    ip, port, protocol = record["connection"]
    record["level"] = level
    record["user"] = user
    if route(record["payload"]) == "raw":
        record["payload"] = record["payload"].strip()
    record["summary"] = f"[{level}] {ip}:{port}/{protocol} {user}"
    return record


def categorize(record: LogRecord) -> LogRecord:
    """Ajoute au log la catégorie de son payload."""
    record["category"] = route(record["payload"])
    return record


def count_lines(lines: Iterable[str], stats: defaultdict[str, int]) -> Iterator[str]:
    """Compte les lignes qui passent, sans les stocker."""
    for line in lines:
        stats["read"] += 1
        yield line


def build_pipeline(
    paths: Iterable[str | Path], stats: defaultdict[str, int] | None = None
) -> Iterator[LogRecord]:
    """Enchaîne lecture, parsing, filtres et transformations, sans aucune liste."""
    lines = read_many_files(paths)
    if stats is not None:
        lines = count_lines(lines, stats)
    records: Iterator[LogRecord] = filter(None, parse_stream(lines))
    # normalize passe avant le filtre, sinon un niveau "error" serait rejeté
    records = map(normalize, records)
    records = filter(lambda r: r["level"] in VALID_LEVELS, records)
    records = filter(has_valid_connection, records)
    records = map(categorize, records)
    return records
