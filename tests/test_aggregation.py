"""Tests de aggregation."""

import pytest

from log_engine.aggregation import (
    aggregate,
    compare_ips,
    detect_brute_force,
    load_blacklist,
)
from log_engine.models import ConnectionMeta


def make_record(ip, level, payload, category, user="u001"):
    return {
        "level": level,
        "connection": ConnectionMeta(ip, 22, "SSH"),
        "user": user,
        "payload": payload,
        "category": category,
    }


FAILED = {"event": "login_failed", "level": "ERROR", "code": 401}
SUCCESS = {"event": "login_success", "level": "INFO"}


def test_load_blacklist_removes_blanks_and_is_frozen(tmp_path):
    path = tmp_path / "blacklist.txt"
    path.write_text("1.1.1.1\n\n  2.2.2.2  \n", encoding="utf-8")
    blacklist = load_blacklist(path)
    assert blacklist == frozenset({"1.1.1.1", "2.2.2.2"})
    assert isinstance(blacklist, frozenset)


def test_load_blacklist_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_blacklist(tmp_path / "absent.txt")


def test_aggregate_fills_all_counters():
    result = aggregate(
        [
            make_record("1.1.1.1", "ERROR", FAILED, "error"),
            make_record("1.1.1.1", "INFO", SUCCESS, "event"),
            make_record("2.2.2.2", "CRITICAL", {"event": "x"}, "event", "u002"),
            make_record("3.3.3.3", "INFO", "Texte", "raw"),
        ]
    )
    assert result["total"] == 4
    assert result["by_level"] == {"ERROR": 1, "INFO": 2, "CRITICAL": 1}
    assert result["by_category"] == {"error": 1, "event": 2, "raw": 1}
    assert result["by_user"] == {"u001": 3, "u002": 1}
    assert result["active_ips"] == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert result["error_ips"] == {"1.1.1.1", "2.2.2.2"}
    assert result["error_counts"] == {"1.1.1.1": 1, "2.2.2.2": 1}
    assert result["login_events"] == {"1.1.1.1": [True, False]}


def test_aggregate_empty_stream():
    result = aggregate([])
    assert result["total"] == 0
    assert result["active_ips"] == set()


def test_compare_ips_four_operations():
    result = compare_ips({"a", "b"}, frozenset({"b", "c"}))
    assert result["union"] == {"a", "b", "c"}
    assert result["blacklisted_active"] == {"b"}
    assert result["active_not_blacklisted"] == {"a"}
    assert result["one_side_only"] == {"a", "c"}


def test_detect_brute_force_exact_threshold_is_suspect():
    result = detect_brute_force({"1.1.1.1": [True] * 5}, 5)
    assert result == {"suspects": ["1.1.1.1"], "clean": []}


def test_detect_brute_force_loop_else_marks_clean():
    # Assez de tentatives pour entrer dans le while, mais jamais de break
    result = detect_brute_force({"1.1.1.1": [True] * 4 + [False, True]}, 5)
    assert result == {"suspects": [], "clean": ["1.1.1.1"]}


def test_detect_brute_force_success_resets_streak():
    attempts = [True, True, True, False, True, True, True]
    assert detect_brute_force({"1.1.1.1": attempts}, 4)["suspects"] == []


def test_detect_brute_force_continue_skips_few_attempts():
    assert detect_brute_force({"1.1.1.1": [True]}, 5)["clean"] == ["1.1.1.1"]


def test_detect_brute_force_results_are_sorted():
    events = {"9.9.9.9": [True] * 5, "1.1.1.1": [True] * 5}
    assert detect_brute_force(events, 5)["suspects"] == ["1.1.1.1", "9.9.9.9"]
