"""Tests de pipeline."""

from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime

import pytest

from log_engine.config import ConnectionMeta
from log_engine.pipeline import (
    build_pipeline,
    categorize,
    count_lines,
    normalize,
    route,
)

SSH = ConnectionMeta("1.2.3.4", 22, "SSH")
FTP = ConnectionMeta("1.2.3.4", 21, "FTP")


def make_record(**changes):
    record = {
        "timestamp": datetime(2026, 11, 4, 10, 0, 0),
        "level": "INFO",
        "connection": SSH,
        "user": "u001",
        "payload": "Texte",
    }
    record.update(changes)
    return record


@pytest.mark.parametrize(
    "item, expected",
    [
        ("Session ouverte", "raw"),
        ({"event": "login_failed", "level": "ERROR", "code": 401}, "error"),
        ({"event": "disk_full", "level": "CRITICAL", "code": 507}, "error"),
        ({"event": "login_success", "level": "INFO"}, "event"),
        (SSH, "connection"),
        (FTP, "unknown"),
        ({"a": 1}, "unknown"),
    ],
)
def test_route(item, expected):
    assert route(item) == expected


def test_normalize_cleans_fields_and_adds_summary():
    record = normalize(make_record(level="error", user="U017", payload=" Texte "))
    assert record["level"] == "ERROR"
    assert record["user"] == "u017"
    assert record["payload"] == "Texte"
    assert record["summary"] == "[ERROR] 1.2.3.4:22/SSH u017"


def test_normalize_leaves_json_payload_untouched():
    payload = {"event": "login_success", "level": "INFO"}
    assert normalize(make_record(payload=payload))["payload"] == payload


def test_categorize_adds_category():
    assert categorize(make_record())["category"] == "raw"


def test_count_lines_counts_without_storing():
    stats = defaultdict(int)
    lines = count_lines(["a", "b"], stats)
    assert stats["read"] == 0
    assert list(lines) == ["a", "b"]
    assert stats["read"] == 2


def write_log(tmp_path, *lines):
    path = tmp_path / "a.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_build_pipeline_is_an_empty_iterator_once_read(tmp_path):
    line = "2026-11-04T05:53:44 | INFO | 1.2.3.4:22/SSH | user=u001 | Texte"
    records = build_pipeline([write_log(tmp_path, line)])
    assert isinstance(records, Iterator)
    assert len(list(records)) == 1
    assert list(records) == []


def test_build_pipeline_removes_invalid_records(tmp_path):
    path = write_log(
        tmp_path,
        "### ligne corrompue ###",
        "2026-11-04T05:53:44 | DEBUG | 1.2.3.4:22/SSH | user=u001 | Trace",
        "2026-11-04T05:53:44 | INFO | 1.2.3.4:21/FTP | user=u001 | Texte",
        "2026-11-04T05:53:44 | INFO | 1.2.3.4:22/SSH | user=u001 | Texte",
    )
    stats = defaultdict(int)
    records = list(build_pipeline([path], stats))
    assert stats["read"] == 4
    assert len(records) == 1
    assert records[0]["category"] == "raw"


def test_build_pipeline_keeps_lowercase_level(tmp_path):
    line = "2026-11-04T05:53:44 | error | 1.2.3.4:22/SSH | user=U001 | Texte"
    records = list(build_pipeline([write_log(tmp_path, line)]))
    assert records[0]["level"] == "ERROR"
    assert records[0]["user"] == "u001"
