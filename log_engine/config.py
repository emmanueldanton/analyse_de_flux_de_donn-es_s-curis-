"""Constantes partagées par tous les modules."""

import re

VALID_LEVELS: frozenset[str] = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})
ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})
# Un tuple et non un frozenset : le rapport affiche les niveaux dans cet ordre
LEVEL_ORDER: tuple[str, ...] = ("INFO", "WARNING", "ERROR", "CRITICAL")
VALID_PROTOCOLS: frozenset[str] = frozenset({"TCP", "UDP", "SSH"})
ALLOWED_PORTS: frozenset[int] = frozenset({22, 80, 443})
LOGIN_EVENTS: frozenset[str] = frozenset({"login_failed", "login_success"})
MAX_FAILURES: int = 5
NIGHT_END_HOUR: int = 6

# Une ligne de log : 5 champs séparés par " | "
LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\S+) \| (?P<level>\w+) \| "
    r"(?P<ip>[\d.]+):(?P<port>\d+)/(?P<protocol>\w+) \| "
    r"user=(?P<user>\w+) \| (?P<payload>.+)$"
)
