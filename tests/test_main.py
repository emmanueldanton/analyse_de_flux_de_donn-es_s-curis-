"""Tests d'intégration : lancent le vrai main.py sur le jeu de test."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILE1 = "data/app_logs_1.log"
FILE2 = "data/app_logs_2.log"
BLACKLIST = "data/blacklist.txt"
ATTACKERS = ["198.51.100.7", "203.0.113.10", "203.0.113.20"]


def run_main(*options):
    command = [sys.executable, "main.py", *options]
    # UTF-8 forcé : sinon les accents dépendent de l'encodage du terminal
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        command, cwd=ROOT, env=env, capture_output=True, encoding="utf-8"
    )


def analyze(output_dir, *options):
    result = run_main(
        FILE1, FILE2, "--blacklist", BLACKLIST, "--output", str(output_dir), *options
    )
    assert result.returncode == 0, result.stderr
    report_path = output_dir / "rapport.json"
    return json.loads(report_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    # Un dossier absent : le lancement doit le créer, audit compris
    output_dir = tmp_path_factory.mktemp("sortie") / "neuf" / "output"
    data = analyze(output_dir, "--audit")
    data["output_dir"] = output_dir
    return data


def test_suspects_at_default_threshold(report):
    assert report["brute_force"]["suspects"] == ATTACKERS
    assert report["brute_force"]["max_failures"] == 5


def test_trap_ip_is_not_suspect(report):
    assert "198.51.100.8" not in report["brute_force"]["suspects"]
    assert "198.51.100.8" in report["ip_sets"]["active_not_blacklisted"]


def test_no_suspect_at_threshold_nine(tmp_path):
    assert analyze(tmp_path, "--max-failures", "9")["brute_force"]["suspects"] == []


def test_threshold_four_adds_the_trap(tmp_path):
    suspects = analyze(tmp_path, "--max-failures", "4")["brute_force"]["suspects"]
    assert set(ATTACKERS + ["198.51.100.8"]) <= set(suspects)


def test_blacklisted_active(report):
    expected = ["192.168.1.17", "192.168.1.5", "203.0.113.10"]
    assert report["ip_sets"]["blacklisted_active"] == expected


def test_categories_and_levels(report):
    assert set(report["by_category"]) == {"raw", "error", "event"}
    assert set(report["by_level"]) == {"INFO", "WARNING", "ERROR", "CRITICAL"}


def test_line_counts_add_up(report):
    lines = report["lines"]
    assert lines["read"] == 2024
    assert lines["valid"] + lines["rejected"] == lines["read"]
    assert sum(report["by_level"].values()) == lines["valid"]
    assert sum(report["by_category"].values()) == lines["valid"]


def test_critical_alerts_match_critical_level(report):
    critical = report["by_level"]["CRITICAL"]
    assert report["alerts"]["counts"]["rule_critical_level"] == critical


def test_night_rule_only_fires_on_first_file(tmp_path):
    result = run_main(FILE2, "--blacklist", BLACKLIST, "--output", str(tmp_path))
    assert result.returncode == 0
    report_path = tmp_path / "rapport.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "rule_night_activity" not in data["alerts"]["counts"]


def test_two_rules_give_two_counters(tmp_path):
    data = analyze(tmp_path, "--rules", "blacklist", "critical")
    expected = ["rule_blacklisted_ip", "rule_critical_level"]
    assert sorted(data["alerts"]["counts"]) == expected


def test_error_ips_and_top_are_in_report(report):
    assert "203.0.113.10" in report["error_ips"]
    assert len(report["top_error_ips"]) == 10
    counts = [count for _, count in report["top_error_ips"]]
    assert counts == sorted(counts, reverse=True)


def test_audit_export(report):
    audit_path = report["output_dir"] / "audit.json"
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["apply_security_rules"]["scope"] == "locals"
    assert audit["main"]["scope"] == "globals"
    names = [variable["name"] for variable in audit["main"]["variables"]]
    assert "build_pipeline" in names


def test_missing_file_gives_one_warning(tmp_path):
    result = run_main(
        FILE1, "absent.log", "--blacklist", BLACKLIST, "--output", str(tmp_path)
    )
    assert result.returncode == 0
    assert result.stderr.count("Fichier introuvable") == 1


def test_no_file_left_returns_one(tmp_path):
    result = run_main("absent.log", "--blacklist", BLACKLIST, "--output", str(tmp_path))
    assert result.returncode == 1


def test_missing_blacklist_returns_one(tmp_path):
    result = run_main(FILE1, "--blacklist", "absent.txt", "--output", str(tmp_path))
    assert result.returncode == 1
    assert "Liste noire introuvable" in result.stderr


def test_threshold_zero_is_refused(tmp_path):
    result = run_main(
        FILE1,
        "--blacklist",
        BLACKLIST,
        "--max-failures",
        "0",
        "--output",
        str(tmp_path),
    )
    assert result.returncode == 2


def test_terminal_report_is_printed(tmp_path):
    result = run_main(FILE1, "--blacklist", BLACKLIST, "--output", str(tmp_path))
    assert "RAPPORT DE SÉCURITÉ" in result.stdout
    assert "Pic mémoire" in result.stdout
