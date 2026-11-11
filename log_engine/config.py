"""Réglages et types partagés par tous les modules."""

import re
from typing import Any, NamedTuple

# Niveaux, protocoles et ports connus : des frozenset, car ils ne changent jamais
VALID_LEVELS: frozenset[str] = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})
ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})
VALID_PROTOCOLS: frozenset[str] = frozenset({"TCP", "UDP", "SSH"})
ALLOWED_PORTS: frozenset[int] = frozenset({22, 80, 443})
LOGIN_EVENTS: frozenset[str] = frozenset({"login_failed", "login_success"})

# Un tuple et non un frozenset : le rapport affiche les niveaux dans cet ordre
LEVEL_ORDER: tuple[str, ...] = ("INFO", "WARNING", "ERROR", "CRITICAL")

MAX_FAILURES: int = 5  # échecs de suite pour parler de force brute
NIGHT_END_HOUR: int = 6  # avant 6 h, une activité est « de nuit »

# Une ligne de log : 5 champs séparés par " | "
# 2026-11-04T05:50:03 | ERROR | 192.168.1.18:22/SSH | user=u008 | {...}
LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\S+) \| (?P<level>\w+) \| "
    r"(?P<ip>[\d.]+):(?P<port>\d+)/(?P<protocol>\w+) \| "
    r"user=(?P<user>\w+) \| (?P<payload>.+)$"
)


class ConnectionMeta(NamedTuple):
    """La connexion (IP, port, protocole) : un tuple, donc impossible à modifier."""

    ip: str
    port: int
    protocol: str


# Un log parsé est un simple dictionnaire
LogRecord = dict[str, Any]
