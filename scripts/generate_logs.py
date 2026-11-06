"""Crée les fichiers de logs de test, avec des attaques cachées à position fixe."""

import argparse
import random
from collections import defaultdict
from datetime import datetime, timedelta
from typing import TextIO

BROKEN_RATE = 0.05
ODD_PORT_RATE = 0.02
ODD_PROTOCOL_RATE = 0.01
ODD_CASE_RATE = 0.01
MAX_NOISE_FAILURES = 2

KINDS = ["fail", "success", "server", "disk", "slow", "debug", "normal"]
WEIGHTS = [25, 15, 10, 3, 10, 2, 35]
NORMAL_TEXTS = ["Page consultée", "Fichier téléchargé", "Session ouverte"]

LOGIN_FAILED = '{"event": "login_failed", "level": "ERROR", "code": 401}'
LOGIN_SUCCESS = '{"event": "login_success", "level": "INFO"}'
SERVER_ERROR = '{"event": "server_error", "level": "ERROR", "code": 500}'
DISK_FULL = '{"event": "disk_full", "level": "CRITICAL", "code": 507}'

SERVICE_LINES = {
    "server": ("ERROR", SERVER_ERROR),
    "disk": ("CRITICAL", DISK_FULL),
    "slow": ("WARNING", "Temps de réponse élevé"),
    "debug": ("DEBUG", "Trace interne"),
}

# Position de l'attaque : IP, utilisateur, tentatives (True = échec)
FILE1_ATTACKS = {
    200: ("203.0.113.10", "u099", [True] * 8),
    600: ("198.51.100.8", "u098", [True] * 4 + [False]),
}
FILE2_ATTACKS = {
    300: ("203.0.113.20", "u097", [True] * 6),
    700: ("198.51.100.7", "u096", [True] * 5),
}
PROFILES = {"file1": FILE1_ATTACKS, "file2": FILE2_ATTACKS, "big": FILE1_ATTACKS}


def format_line(
    clock: datetime, level: str, connection: str, user: str, payload: str
) -> str:
    """Écrit une ligne de log au format du contrat."""
    stamp = clock.isoformat(timespec="seconds")
    return f"{stamp} | {level} | {connection} | user={user} | {payload}\n"


def login_line(clock: datetime, ip: str, user: str, failed: bool) -> str:
    """Écrit une tentative de connexion, toujours en 22/SSH."""
    # Toujours SSH : le filtre FTP effacerait une réussite, d'où une fausse attaque
    connection = f"{ip}:22/SSH"
    if failed:
        return format_line(clock, "ERROR", connection, user, LOGIN_FAILED)
    return format_line(clock, "INFO", connection, user, LOGIN_SUCCESS)


def broken_line(rng: random.Random, clock: datetime) -> str:
    """Écrit une ligne que le parseur doit rejeter."""
    cut_line = f"{clock.isoformat(timespec='seconds')} | INFO | 192.168.1.1"
    choices = ["", "     ", "### ligne corrompue ###", cut_line]
    return rng.choice(choices) + "\n"


def service_connection(rng: random.Random, ip: str) -> str:
    """Tire un port et un protocole, avec de rares valeurs anormales."""
    port = rng.choice([22, 80, 443])
    if rng.random() < ODD_PORT_RATE:
        port = 3389
    protocol = rng.choice(["TCP", "UDP", "SSH"])
    if rng.random() < ODD_PROTOCOL_RATE:
        protocol = "FTP"
    return f"{ip}:{port}/{protocol}"


def service_line(
    rng: random.Random, clock: datetime, ip: str, user: str, kind: str
) -> str:
    """Écrit une ligne de bruit qui n'est pas une connexion."""
    connection = service_connection(rng, ip)
    if kind == "normal":
        level = "INFO"
        payload = rng.choice(NORMAL_TEXTS)
    else:
        level, payload = SERVICE_LINES[kind]
    # Quelques lignes mal écrites, pour que la normalisation serve vraiment
    if rng.random() < ODD_CASE_RATE:
        level = level.lower()
        user = user.upper()
    return format_line(clock, level, connection, user, payload)


def noise_line(
    rng: random.Random, clock: datetime, failures: defaultdict[str, int]
) -> str:
    """Écrit une ligne de bruit, sans jamais créer de fausse attaque."""
    ip = f"192.168.1.{rng.randint(1, 40)}"
    user = f"u{rng.randint(1, 30):03d}"
    kind = rng.choices(KINDS, WEIGHTS)[0]
    # Après 2 échecs, la connexion suivante de cette IP réussit forcément
    if kind == "fail" and failures[ip] >= MAX_NOISE_FAILURES:
        kind = "success"
    if kind == "fail":
        failures[ip] += 1
        return login_line(clock, ip, user, True)
    if kind == "success":
        failures[ip] = 0
        return login_line(clock, ip, user, False)
    return service_line(rng, clock, ip, user, kind)


def tick(rng: random.Random, clock: datetime) -> datetime:
    """Avance l'horloge de 1 à 3 secondes."""
    return clock + timedelta(seconds=rng.randint(1, 3))


def write_attack(
    f: TextIO,
    rng: random.Random,
    clock: datetime,
    attack: tuple[str, str, list[bool]],
) -> datetime:
    """Écrit une séquence d'attaque et rend l'horloge avancée."""
    ip, user, attempts = attack
    for failed in attempts:
        clock = tick(rng, clock)
        f.write(login_line(clock, ip, user, failed))
    return clock


def write_logs(args: argparse.Namespace) -> None:
    """Écrit le fichier ligne par ligne, sans liste en mémoire."""
    rng = random.Random(args.seed)
    clock = datetime.fromisoformat(args.start)
    attacks = PROFILES[args.profile]
    failures: defaultdict[str, int] = defaultdict(int)
    # newline="\n" : même fichier sous Windows et sous Linux
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        for number in range(1, args.lines + 1):
            if number in attacks:
                clock = write_attack(f, rng, clock, attacks[number])
            clock = tick(rng, clock)
            # Tirée avant le type de ligne : ne remplace jamais une réussite forcée
            if rng.random() < BROKEN_RATE:
                f.write(broken_line(rng, clock))
            else:
                f.write(noise_line(rng, clock, failures))


def main() -> None:
    """Lit les options et écrit le fichier de logs."""
    parser = argparse.ArgumentParser(description="Génère des logs de test")
    parser.add_argument("output", help="chemin du fichier à créer")
    parser.add_argument("--lines", type=int, default=1000, help="lignes de bruit")
    parser.add_argument("--start", default="2026-11-04T08:00:00", help="date ISO")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="file1")
    write_logs(parser.parse_args())


if __name__ == "__main__":
    main()
