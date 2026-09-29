from __future__ import annotations

from datetime import UTC, datetime

from lg_sotf.ingestion.fingerprint import compute_fingerprint, fingerprint_parts
from lg_sotf.models.alert import CanonicalAlert, Entities


def _alert(**overrides: object) -> CanonicalAlert:
    values: dict = {
        "source_id": "s1",
        "source_type": "splunk",
        "source_alert_id": "a1",
        "title": "Brute force on db-01",
        "rule_name": "Access - Brute Force",
        "severity": "high",
        "occurred_at": datetime(2024, 1, 1, tzinfo=UTC),
        "entities": Entities(hosts=["db-01"], users=["root"], ips=["203.0.113.5"]),
    }
    values.update(overrides)
    return CanonicalAlert(**values)


def test_stable_and_hex() -> None:
    fp = compute_fingerprint(_alert())
    assert fp == compute_fingerprint(_alert())
    assert len(fp) == 64 and int(fp, 16) >= 0


def test_ignores_ids_times_severity_description_and_entity_order() -> None:
    base = compute_fingerprint(_alert())
    varied = _alert(
        source_alert_id="other",
        source_id="s2",
        occurred_at=datetime(2025, 6, 1, tzinfo=UTC),
        severity="low",
        description="different text",
        title="Brute force on db-01 (re-fired)",
        entities=Entities(hosts=["DB-01"], users=["root"], ips=["203.0.113.5"], urls=["https://x.example.com"]),
    )
    assert compute_fingerprint(varied) == base
    reordered = _alert(entities=Entities(ips=["203.0.113.5"], users=["root"], hosts=["db-01"]))
    assert compute_fingerprint(reordered) == base


def test_changes_with_rule_entities_or_source_type() -> None:
    base = compute_fingerprint(_alert())
    assert compute_fingerprint(_alert(rule_name="Other rule")) != base
    assert compute_fingerprint(_alert(entities=Entities(hosts=["db-02"], users=["root"], ips=["203.0.113.5"]))) != base
    assert compute_fingerprint(_alert(source_type="wazuh")) != base


def test_falls_back_to_title_without_rule_name() -> None:
    a = _alert(rule_name=None, title="Same  Title")
    b = _alert(rule_name=None, title="same title")
    assert compute_fingerprint(a) == compute_fingerprint(b)
    assert fingerprint_parts(a)["rule"] == "same title"
