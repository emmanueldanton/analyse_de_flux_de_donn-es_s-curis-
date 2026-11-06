"""Module 4 : audit avec globals() et locals()."""

import json
import sys
import types
from pathlib import Path
from typing import Any


def audit_scope(scope: dict[str, Any], name: str) -> dict[str, Any]:
    """Décrit les variables d'une portée : nom, type et taille."""
    variables: list[dict[str, Any]] = []
    for key, value in sorted(scope.items()):
        # Les noms internes et les modules ne disent rien de l'exécution
        if key.startswith("_"):
            continue
        if isinstance(value, types.ModuleType):
            continue
        variables.append(
            {
                "name": key,
                "type": type(value).__name__,
                "size_bytes": sys.getsizeof(value),
            }
        )
    return {"scope": name, "count": len(variables), "variables": variables}


def save_audit(audit: dict[str, Any], path: str | Path) -> None:
    """Écrit le rapport d'audit en JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2, ensure_ascii=False)
