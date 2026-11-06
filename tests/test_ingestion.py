"""Tests de ingestion."""

import logging
import types
from datetime import datetime

from log_engine.ingestion import (
    parse_line,
    parse_stream,
    read_log_file,
    read_many_files,
)
from log_engine.models import ConnectionMeta

JSON_LINE = (
    "2026-11-04T05:53:44 | ERROR | 192.168.1.31:22/SSH | user=u017 | "
    '{"event": "login_failed", "level": "ERROR", "code": 401}'
)
TEXT_LINE = (
    "2026-11-04T05:53:50 | WARNING | 192.168.1.8:443/TCP | user=u004 | "
    "Temps de réponse élevé"
)
PREFIX = "2026-11-04T05:53:44 | INFO | 1.2.3.4:22/SSH | user=u001 | "


def test_read_log_file_is_a_generator(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("un\ndeux\n", encoding="utf-8")
    lines = read_log_file(path)
    assert isinstance(lines, types.GeneratorType)
    assert list(lines) == ["un", "deux"]


def test_read_log_file_survives_invalid_utf8(tmp_path):
    path = tmp_path / "a.log"
    path.write_bytes(b"avant\n\xff\xfe casse\napres\n")
    lines = list(read_log_file(path))
    assert len(lines) == 3
    assert lines[2] == "apres"


def test_read_many_files_chains_in_order(tmp_path):
    first = tmp_path / "a.log"
    second = tmp_path / "b.log"
    first.write_text("a\n", encoding="utf-8")
    second.write_text("b\n", encoding="utf-8")
    lines = read_many_files([first, second])
    assert isinstance(lines, types.GeneratorType)
    assert list(lines) == ["a", "b"]


def test_read_many_files_skips_missing_file(tmp_path, caplog):
    present = tmp_path / "a.log"
    present.write_text("a\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        lines = list(read_many_files([tmp_path / "absent.log", present]))
    assert lines == ["a"]
    assert "Fichier introuvable" in caplog.text


def test_parse_line_json_payload():
    record = parse_line(JSON_LINE)
    assert record["timestamp"] == datetime(2026, 11, 4, 5, 53, 44)
    assert record["level"] == "ERROR"
    assert record["connection"] == ConnectionMeta("192.168.1.31", 22, "SSH")
    assert record["user"] == "u017"
    assert record["payload"]["code"] == 401


def test_parse_line_text_payload():
    record = parse_line(TEXT_LINE)
    assert record["payload"] == "Temps de réponse élevé"
    assert record["connection"].port == 443


def test_parse_line_keeps_unknown_level():
    # Le Module 2 retire DEBUG : chaque module a un seul rôle
    line = "2026-11-04T05:53:44 | DEBUG | 1.2.3.4:22/SSH | user=u001 | Trace"
    assert parse_line(line)["level"] == "DEBUG"


def test_parse_line_rejects_broken_lines():
    assert parse_line("") is None
    assert parse_line("     ") is None
    assert parse_line("### ligne corrompue ###") is None
    assert parse_line("2026-11-04T05:53:44 | INFO | 192.168.1.1") is None


def test_parse_line_rejects_bad_date():
    line = "2026-13-45T05:53:44 | INFO | 1.2.3.4:22/SSH | user=u001 | Texte"
    assert parse_line(line) is None


def test_parse_line_rejects_bad_json():
    assert parse_line(PREFIX + '{"event": ') is None


def test_parse_line_rejects_giant_port():
    line = "2026-11-04T05:53:44 | INFO | 1.2.3.4:" + "9" * 5000
    assert parse_line(line + "/SSH | user=u001 | Texte") is None


def test_parse_line_rejects_extreme_json_nesting():
    assert parse_line(PREFIX + '{"a":' * 200000) is None


def test_parse_stream_keeps_none():
    records = parse_stream([TEXT_LINE, "cassée"])
    assert isinstance(records, types.GeneratorType)
    results = list(records)
    assert results[0]["user"] == "u004"
    assert results[1] is None
