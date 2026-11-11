"""Module 1 : lire les fichiers ligne par ligne (yield) et parser chaque ligne."""

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from log_engine.config import LINE_PATTERN, ConnectionMeta, LogRecord


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
            yield from read_log_file(path)  # délègue tout le fichier au générateur
        except FileNotFoundError:
            logging.warning("Fichier introuvable : %s", path)


def parse_payload(text: str) -> dict[str, Any] | str | None:
    """Rend le payload en dictionnaire s'il est en JSON, None s'il est cassé."""
    if not text.startswith("{"):
        return text  # texte brut
    try:
        return json.loads(text)
    # RecursionError : un JSON imbriqué à l'extrême ne doit pas tout faire planter
    except (json.JSONDecodeError, RecursionError):
        return None


def parse_line(line: str) -> LogRecord | None:
    """Transforme une ligne en dictionnaire, ou rend None si elle est invalide."""
    match = LINE_PATTERN.match(line.strip())
    if match is None:
        return None
    payload = parse_payload(match["payload"])
    if payload is None:
        return None
    try:
        timestamp = datetime.fromisoformat(match["timestamp"])
        port = int(match["port"])
    except ValueError:  # date impossible, par exemple 2026-13-45
        return None
    return {
        "timestamp": timestamp,
        "level": match["level"],
        "connection": ConnectionMeta(match["ip"], port, match["protocol"]),
        "user": match["user"],
        "payload": payload,
    }


def parse_stream(lines: Iterable[str]) -> Iterator[LogRecord | None]:
    """Parse un flux de lignes. Les None restent : le Module 2 les filtre."""
    for line in lines:
        yield parse_line(line)
