"""Module 1 : générateurs et parsing."""

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from log_engine.config import LINE_PATTERN
from log_engine.models import ConnectionMeta, LogRecord


def read_log_file(path: str | Path) -> Iterator[str]:
    """Rend les lignes d'un fichier une par une, sans le charger en mémoire."""
    # errors="replace" : un octet corrompu ne doit pas arrêter toute la lecture
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def read_many_files(paths: Iterable[str | Path]) -> Iterator[str]:
    """Enchaîne les lignes de plusieurs fichiers, en sautant ceux qui manquent."""
    for path in paths:
        try:
            yield from read_log_file(path)
        except FileNotFoundError:
            logging.warning("Fichier introuvable : %s", path)


def parse_payload(text: str) -> dict[str, Any] | str | None:
    """Rend le payload en dictionnaire s'il est en JSON, None s'il est cassé."""
    if not text.startswith("{"):
        return text
    try:
        return json.loads(text)
    # RecursionError : un JSON imbriqué à l'extrême ne doit pas tout faire planter
    except (json.JSONDecodeError, RecursionError):
        return None


def parse_line(line: str) -> LogRecord | None:
    """Transforme une ligne en dictionnaire, ou rend None si elle est invalide."""
    m = LINE_PATTERN.match(line.strip())
    if m is None:
        return None
    payload = parse_payload(m["payload"])
    if payload is None:
        return None
    try:
        timestamp = datetime.fromisoformat(m["timestamp"])
        port = int(m["port"])
    except ValueError:
        return None
    return {
        "timestamp": timestamp,
        "level": m["level"],
        "connection": ConnectionMeta(m["ip"], port, m["protocol"]),
        "user": m["user"],
        "payload": payload,
    }


def parse_stream(lines: Iterable[str]) -> Iterator[LogRecord | None]:
    """Parse un flux de lignes, en gardant les None pour le Module 2."""
    for line in lines:
        yield parse_line(line)
