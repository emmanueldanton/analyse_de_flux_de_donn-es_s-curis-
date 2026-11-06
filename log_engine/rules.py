"""Module 4 : règles de sécurité et moteur."""

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from log_engine.audit import audit_scope
from log_engine.models import LogRecord

MAX_SAMPLES: int = 5


def rule_blacklisted_ip(record: LogRecord, **config: Any) -> str | None:
    """Signale une IP présente dans la liste noire."""
    if record["connection"].ip in config.get("blacklist", frozenset()):
        return f"IP blacklistée : {record['summary']}"
    return None


def rule_critical_level(record: LogRecord, **config: Any) -> str | None:
    """Signale un log de niveau CRITICAL."""
    # **config reste là même sans usage : le moteur le passe à toutes les règles
    if record["level"] == "CRITICAL":
        return f"Niveau critique : {record['summary']}"
    return None


def rule_suspicious_port(record: LogRecord, **config: Any) -> str | None:
    """Signale un port absent de la liste autorisée."""
    port = record["connection"].port
    if port not in config.get("allowed_ports", frozenset()):
        return f"Port non autorisé {port} : {record['summary']}"
    return None


def rule_night_activity(record: LogRecord, **config: Any) -> str | None:
    """Signale une activité avant l'heure de fin de nuit."""
    if record["timestamp"].hour < config.get("night_end_hour", 6):
        return f"Activité de nuit : {record['summary']}"
    return None


# Un dictionnaire de fonctions : ajouter une règle ne touche pas au moteur
RULES: dict[str, Callable[..., str | None]] = {
    "blacklist": rule_blacklisted_ip,
    "critical": rule_critical_level,
    "port": rule_suspicious_port,
    "night": rule_night_activity,
}


def apply_security_rules(
    *args: Callable[..., str | None], **kwargs: Any
) -> dict[str, Any]:
    """Applique les règles à chaque log et compte les alertes."""
    # On sort ces deux clés, sinon chaque règle recevrait tout le flux de logs
    records = kwargs.pop("records")
    audit_sink = kwargs.pop("audit_sink", None)
    counts: defaultdict[str, int] = defaultdict(int)
    samples: defaultdict[str, list[str]] = defaultdict(list)

    for record in records:
        for rule in args:
            try:
                message = rule(record, **kwargs)
            # Seul except large du projet : une règle peut avoir n'importe quel bug
            except Exception as exc:
                counts["rule_errors"] += 1
                logging.error("%s a échoué : %s", rule.__name__, exc)
                continue
            if message:
                counts[rule.__name__] += 1
                # 5 exemples seulement : tout garder coûtait 59 Mo sur 1 million
                if len(samples[rule.__name__]) < MAX_SAMPLES:
                    samples[rule.__name__].append(message)

    if audit_sink is not None:
        audit_sink["apply_security_rules"] = audit_scope(locals(), "locals")
    return {"counts": counts, "samples": samples}
