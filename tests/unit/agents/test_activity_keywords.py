"""AI-E6.4: rule-name words that name the detected activity are benign evidence only with a trusted qualifier.

``scheduled``, ``update``, ``backup``, ``scan`` and ``monitoring`` describe what
a rule detects, and attackers do those things (``scheduled-task-created`` is
T1053, ``real time monitoring was disabled`` is T1562.001). They count only
with an intent word in the same rule name (``test``, ``selftest``,
``maintenance``, ``health_check``), a test-environment source id or, for
``scan``, one of the tenant's known scanners among the entities.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping

import pytest

from lg_sotf.agents.triage.base import (
    SCANNER_SIGNAL,
    injection_suspected,
    rule_confidence,
    rule_indicators,
    rules_alone_close,
)
from lg_sotf.domain.benign_evidence import ACTIVITY_KEYWORDS, RULE_NAME_KEYWORDS, KnownScanners, rule_name_keywords
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.ingestion.normalizers import get_normalizer, resolve_format
from lg_sotf.ingestion.normalizers.base import NormalizeContext

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
ACTIVITY_SIGNALS = {f"{k}_detected" for k in ACTIVITY_KEYWORDS}
KEYWORD_SIGNALS = {f"{k}_detected" for k in RULE_NAME_KEYWORDS}
CORPUS_SCANNERS = KnownScanners.from_settings({"triage": {"known_scanners": ["scanner-01", "10.0.5.10"]}})


def _alert(rule_name: str, **extra: Any) -> Dict[str, Any]:
    return {"title": "x", "rule_name": rule_name, "severity": "low", "source_id": "edr-prod", **extra}


@pytest.mark.parametrize(
    "rule_name",
    [
        # ATT&CK-relevant rule names whose words name the activity (shipped sets and common vendor rules).
        "scheduled-task-created",  # T1053.005, synthetic_v1 and adversarial_v2
        "scheduled-task-programdata",  # T1053.005, adversarial_v2
        "92008: Windows Defender real time monitoring was disabled by Powershell command",  # T1562.001, corpus_v1
        "100210: Windows Defender: real time monitoring was disabled",  # T1562.001, adversarial_v2
        "scheduled-backup-deleted",  # T1490
        "Backup catalog deleted with wbadmin",  # T1490
        "cron-job-scheduled-by-web-user",  # T1053.003
        "internal-port-scan",  # T1046
        "update-agent-spawned-shell",  # T1195.002
        "Scheduled task update",  # T1053.005
        "Windows Update service disabled",  # T1562.001
    ],
)
def test_activity_words_alone_are_not_benign_evidence(rule_name: str) -> None:
    fp, tp = rule_indicators(_alert(rule_name), scanners=CORPUS_SCANNERS)
    assert fp == [], fp
    # The score no longer drops for "scheduled" either.
    assert rule_confidence(_alert(rule_name)) == rule_confidence(_alert("detection"))
    assert not rules_alone_close("info", rule_confidence({**_alert(rule_name), "severity": "info"}), fp, tp,
                                 RoutingThresholds())


@pytest.mark.parametrize(
    ("alert", "expected"),
    [
        # An intent word in the same rule name qualifies every activity word (a maintenance-window rule).
        (_alert("2932: Scheduled maintenance: package update installed"),
         ["scheduled_detected", "maintenance_detected", "update_detected"]),
        (_alert("backup-selftest"), ["selftest_detected", "backup_detected"]),
        (_alert("uptime health-check monitoring"), ["health_check_detected", "monitoring_detected"]),
        # A test-like source id qualifies them too.
        (_alert("scheduled-task-created", source_id="splunk-staging"), ["scheduled_detected", "test_environment"]),
        # A configured scanner among the entities qualifies "scan", and only "scan".
        (_alert("vuln-scan-started", entities={"ips": ["10.0.5.10"]}), ["scan_detected", SCANNER_SIGNAL]),
        (_alert("scheduled-scan-update", entities={"hosts": ["scanner-01"]}), ["scan_detected", SCANNER_SIGNAL]),
        (_alert("vuln-scan-started", entities={"ips": ["10.0.6.10"]}), []),
        # Intent words need no qualifier.
        (_alert("ups-test"), ["test_detected"]),
        (_alert("pipeline-selftest"), ["selftest_detected"]),
    ],
)
def test_qualified_activity_words_still_count(alert: Mapping[str, Any], expected: List[str]) -> None:
    assert rule_indicators(alert, scanners=CORPUS_SCANNERS)[0] == expected


@pytest.mark.parametrize(
    "alert",
    [
        # The qualifier must be detector text too: quoted or attacker-named spans are masked first.
        _alert("Scheduled task 'Maintenance Test' created"),
        _alert("Scheduled task Maintenance Test created", raw={"TaskName": "Maintenance Test"}),
        _alert("Service Backup Selftest installed", entities={"processes": ["Backup Selftest"]}),
        # Neither a scanner named in the title nor a test-like word outside the source id qualifies.
        _alert("internal-port-scan", title="scan from scanner-01"),
        _alert("scheduled-task-created", raw={"environment": "test"}),
    ],
)
def test_qualifiers_come_only_from_trusted_fields(alert: Mapping[str, Any]) -> None:
    assert not set(rule_indicators(alert, scanners=CORPUS_SCANNERS)[0]) & KEYWORD_SIGNALS


def test_rule_name_keywords_keeps_the_reporting_order() -> None:
    words = frozenset({"monitoring", "scan", "backup", "update", "maintenance", "scheduled", "test"})
    assert rule_name_keywords(words) == ["test", "scheduled", "maintenance", "update", "backup", "scan", "monitoring"]
    assert rule_name_keywords(frozenset({"scan", "update"}), known_scanner=True) == ["scan"]
    assert rule_name_keywords(frozenset({"scan", "update"}), test_environment=True) == ["update", "scan"]
    assert rule_name_keywords(frozenset()) == []


def _normalised(path: Path) -> List[tuple[str, str, Dict[str, Any]]]:
    out = []
    for item in load_dataset(path).items:
        if item.source_type == "email":
            continue
        fmt = "canonical" if item.source_type == "canonical" else resolve_format(item.source_type, item.source_config)
        ctx = NormalizeContext(source_id="eval-src", source_type=item.source_type, config=item.source_config or {})
        alert = get_normalizer(fmt).normalize(item.alert, ctx).model_dump(mode="json")
        out.append((item.id, item.expected.disposition, alert))
    return out


@pytest.mark.parametrize("name", ["synthetic_v1.jsonl", "adversarial_v2.jsonl", "corpus_v1.jsonl.gz"])
def test_no_malicious_item_of_the_shipped_sets_gets_activity_evidence(name: str) -> None:
    offenders = [
        (item_id, alert.get("rule_name"), fp)
        for item_id, disposition, alert in _normalised(FIXTURES / name)
        if disposition == "malicious"
        for fp in [rule_indicators(alert, scanners=CORPUS_SCANNERS)[0]]
        if set(fp) & ACTIVITY_SIGNALS
    ]
    assert offenders == []


def test_the_activity_camouflage_items_reach_the_keyword_rules() -> None:
    """The new adversarial items test the keyword path, not the injection detector (which voids text evidence)."""
    items = {i: a for i, _, a in _normalised(FIXTURES / "adversarial_v2.jsonl") if i.startswith("adv2-ac-")}
    assert len(items) == 6
    for item_id, alert in items.items():
        assert not injection_suspected(alert), item_id
        fp, tp = rule_indicators(alert, scanners=CORPUS_SCANNERS)
        assert fp == [], (item_id, fp)
        assert not rules_alone_close(str(alert["severity"]), rule_confidence(alert), fp, tp, RoutingThresholds())
    raw = [json.loads(line) for line in (FIXTURES / "adversarial_v2.jsonl").read_text().splitlines()[1:]]
    assert {r["id"] for r in raw if r.get("family") == "activity-camouflage"} == set(items)
