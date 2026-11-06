"""Types partagés : la connexion et l'enregistrement de log."""

from typing import Any, NamedTuple


class ConnectionMeta(NamedTuple):
    """Métadonnées fixes d'une connexion, immuables car c'est un tuple."""

    ip: str
    port: int
    protocol: str


# dict et non TypedDict : NotRequired n'existe qu'à partir de Python 3.11
LogRecord = dict[str, Any]
