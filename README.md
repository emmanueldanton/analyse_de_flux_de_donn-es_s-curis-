# log_engine

Outil Python en ligne de commande qui lit de gros fichiers de logs sans les charger en mémoire, les nettoie, les analyse et sort un rapport de sécurité : compteurs, IP blacklistées encore actives, attaques par force brute, alertes par règle.

Auteur : Emmanuel Danton (ECE, ING3).

Python 3.10 ou plus. Le cœur du projet n'utilise que la bibliothèque standard.

## Installation

Windows :

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Linux et macOS :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Lancement

Les logs de test sont déjà dans `data/`.

```bash
python main.py data/app_logs_1.log data/app_logs_2.log --blacklist data/blacklist.txt --audit
```

| Option | Rôle | Défaut |
| --- | --- | --- |
| `files` | fichiers de logs, lus dans l'ordre donné | obligatoire |
| `--blacklist` | fichier des IP interdites, une par ligne | obligatoire |
| `--max-failures` | échecs de suite pour déclarer une attaque | 5 |
| `--rules` | règles à appliquer : `blacklist`, `critical`, `night`, `port` | toutes |
| `--output` | dossier des rapports | `output` |
| `--audit` | exporte aussi `audit.json` | non |

Le programme crée `rapport.json`, et `audit.json` avec `--audit`, dans le dossier de sortie.

Exemple de sortie :

```text
================ RAPPORT DE SÉCURITÉ ================
Fichiers analysés : 2
Lignes lues : 2024 | valides : 1888 | rejetées : 136

Par niveau     INFO 1049 | WARNING 176 | ERROR 607 | CRITICAL 56
Par catégorie  raw 851 | error 663 | event 374

IP blacklistées encore actives (3) : 192.168.1.17, 192.168.1.5, 203.0.113.10
Force brute (seuil 5) : 3 IP suspectes
  - 198.51.100.7
  - 203.0.113.10
  - 203.0.113.20

Alertes par règle
  rule_blacklisted_ip     98
  rule_critical_level     56
  rule_night_activity    285
  rule_suspicious_port    16

Pic mémoire : 87 Ko
Rapport complet : output\rapport.json
=====================================================
```

## Générer d'autres logs

```bash
python scripts/generate_logs.py data/app_logs_1.log --profile file1 --start 2026-11-04T05:50:00 --seed 42
python scripts/generate_logs.py data/app_logs_2.log --profile file2 --start 2026-11-04T14:00:00 --seed 43
python scripts/generate_logs.py output/big.log --profile big --lines 1000000
```

## Vérifications

```bash
black --check .
flake8 log_engine/ main.py scripts/ tests/
mypy log_engine/ main.py scripts/
pytest -q
```

## Rapport

`notebooks/rapport.ipynb` montre chaque module en action, avec les mesures mémoire et les graphiques.
