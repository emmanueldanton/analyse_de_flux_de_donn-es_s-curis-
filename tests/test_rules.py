"""Tests de rules et audit."""

import json
import sys
from datetime import datetime

from log_engine.audit import audit_scope, save_audit
from log_engine.models import ConnectionMeta
from log_engine.rules import (
    RULES,
    apply_security_rules,
    rule_blacklisted_ip,
    rule_critical_level,
    rule_night_activity,
    rule_suspicious_port,
)


def make_record(ip="1.1.1.1", port=22, level="INFO", hour=10):
    return {
        "timestamp": datetime(2026, 11, 4, hour, 0, 0),
        "level": level,
        "connection": ConnectionMeta(ip, port, "SSH"),
        "user": "u001",
        "payload": "Texte",
        "summary": f"[{level}] {ip}:{port}/SSH u001",
        "category": "raw",
    }


def broken_rule(record, **config):
    raise ValueError("règle cassée")


def test_rule_blacklisted_ip():
    blacklist = frozenset({"1.1.1.1"})
    assert "blacklistée" in rule_blacklisted_ip(make_record(), blacklist=blacklist)
    other = make_record(ip="2.2.2.2")
    assert rule_blacklisted_ip(other, blacklist=blacklist) is None


def test_rule_critical_level_accepts_unused_options():
    assert rule_critical_level(make_record(level="CRITICAL"), blacklist=frozenset())
    assert rule_critical_level(make_record()) is None


def test_rule_suspicious_port():
    allowed = frozenset({22})
    message = rule_suspicious_port(make_record(port=3389), allowed_ports=allowed)
    assert "3389" in message
    assert rule_suspicious_port(make_record(), allowed_ports=allowed) is None


def test_rule_night_activity():
    assert rule_night_activity(make_record(hour=5), night_end_hour=6)
    assert rule_night_activity(make_record(hour=6), night_end_hour=6) is None


def test_engine_runs_with_two_then_four_rules():
    records = [make_record(level="CRITICAL", hour=5, port=3389)]
    options = {"blacklist": frozenset({"1.1.1.1"}), "allowed_ports": frozenset({22})}
    two = apply_security_rules(
        rule_blacklisted_ip, rule_critical_level, records=iter(records), **options
    )
    four = apply_security_rules(*RULES.values(), records=iter(records), **options)
    assert len(two["counts"]) == 2
    assert len(four["counts"]) == 4


def test_engine_accepts_a_new_rule_without_change():
    def rule_always(record, **config):
        return "alerte"

    result = apply_security_rules(rule_always, records=[make_record()])
    assert result["counts"]["rule_always"] == 1


def test_engine_keeps_five_samples_but_counts_everything():
    records = [make_record(level="CRITICAL") for _ in range(8)]
    result = apply_security_rules(rule_critical_level, records=records)
    assert result["counts"]["rule_critical_level"] == 8
    assert len(result["samples"]["rule_critical_level"]) == 5


def test_broken_rule_does_not_stop_the_others():
    records = [make_record(level="CRITICAL"), make_record(level="CRITICAL")]
    result = apply_security_rules(broken_rule, rule_critical_level, records=records)
    assert result["counts"]["rule_errors"] == 2
    assert result["counts"]["rule_critical_level"] == 2


def test_rules_do_not_receive_records_or_audit_sink():
    received = {}

    def rule_spy(record, **config):
        received.update(config)

    apply_security_rules(rule_spy, records=[make_record()], audit_sink={}, seuil=3)
    assert received == {"seuil": 3}


def test_engine_fills_audit_sink_with_locals():
    sink = {}
    apply_security_rules(rule_critical_level, records=[make_record()], audit_sink=sink)
    audit = sink["apply_security_rules"]
    names = [variable["name"] for variable in audit["variables"]]
    assert audit["scope"] == "locals"
    assert {"args", "records", "counts", "samples"} <= set(names)


def test_audit_scope_skips_private_names_and_modules():
    scope = {"_private": 1, "sys": sys, "value": "texte"}
    audit = audit_scope(scope, "test")
    assert audit["count"] == 1
    assert audit["variables"][0]["name"] == "value"
    assert audit["variables"][0]["type"] == "str"
    assert audit["variables"][0]["size_bytes"] == sys.getsizeof("texte")


def test_audit_scope_on_globals():
    audit = audit_scope(globals(), "globals")
    names = [variable["name"] for variable in audit["variables"]]
    assert "make_record" in names
    assert "sys" not in names


def test_save_audit_writes_json(tmp_path):
    path = tmp_path / "audit.json"
    save_audit({"portée": 1}, path)
    assert json.loads(path.read_text(encoding="utf-8")) == {"portée": 1}
