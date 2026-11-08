"""AI-E6.3: triage never takes benign evidence from text the attacker names (title camouflage).

False-positive signals come only from the detection rule's name (attacker-named
values masked out), EICAR hashes, the tenant's configured scanners and the
source id. Titles, entity names, command lines, user agents and email
subjects never produce them, so an attacker who names a scheduled task
"Windows Update Test" no longer closes the alert on rules alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

import pytest

from lg_sotf.agents.triage.base import (
    EICAR_SIGNAL,
    SCANNER_SIGNAL,
    TriageAgent,
    rule_confidence,
    rule_indicators,
    rules_alone_close,
    trusted_words,
)
from lg_sotf.domain.benign_evidence import (
    EICAR_MD5,
    EICAR_SHA1,
    EICAR_SHA256,
    KnownScanners,
    detector_words,
    eicar_only,
    validate_triage_settings,
)
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.onboarding.samples import sample_events
from lg_sotf.settings import Settings
from tests.unit.agents._support import ctx, factory, fake_repos, scripted

pytestmark = pytest.mark.unit

DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "eval" / "adversarial_v2.jsonl"
BENIGN_WORDS = {"test_detected", "update_detected", "maintenance_detected", "scheduled_detected", "backup_detected",
                "health_check_detected", "monitoring_detected", "scan_detected"}


def camouflaged() -> Dict[str, Dict[str, Any]]:
    """The title-camouflage items as triage sees them (the webhook item after its field map)."""
    items = {}
    for line in DATASET.read_text().splitlines():
        item = json.loads(line)
        if item.get("family") == "title-camouflage":
            items[item["id"]] = item
    tc03 = items["adv2-tc-03"]["alert"]
    alerts = {k: {**v["alert"], "source_id": "edr-prod"} for k, v in items.items() if v["source_type"] == "canonical"}
    alerts["adv2-tc-03"] = {
        "title": tc03["alert"]["name"], "severity": "info", "category": tc03["alert"]["kind"],
        "rule_name": tc03["alert"]["rule"]["name"], "description": tc03["alert"]["details"]["summary"],
        "source_id": "webhook-prod", "entities": {"hosts": [tc03["asset"]["hostname"]], "ips": list(tc03["network"].values())},
    }
    return alerts


@pytest.mark.parametrize("item_id", ["adv2-tc-01", "adv2-tc-02", "adv2-tc-03"])
def test_the_title_camouflage_items_get_no_benign_evidence_and_never_close_on_rules(item_id: str) -> None:
    alert = camouflaged()[item_id]
    fp, tp = rule_indicators(alert)
    assert not set(fp) & {"test_detected", "update_detected", "maintenance_detected", "backup_detected"}, fp
    assert not set(fp) & {"health_check_detected"}, fp
    severity = str(alert["severity"])
    assert not rules_alone_close(severity, rule_confidence(alert), fp, tp, RoutingThresholds())


@pytest.mark.parametrize(
    "alert",
    [
        # Attacker-named objects copied into the title by the detector or an integration.
        {"title": "Scheduled task created: Windows Update Test", "rule_name": "task-created"},
        {"title": "New service installed: Scheduled Backup Maintenance", "rule_name": "service-installed"},
        {"title": "Process maintenance_test.exe started", "rule_name": "proc-start"},
        {"title": "Email reported: Monitoring test - scheduled maintenance", "rule_name": "user-report"},
        # The same names in the fields they come from.
        {"title": "Task created", "rule_name": "task-created", "raw": {"TaskName": "Windows Update Test"}},
        {"title": "Process", "rule_name": "proc", "entities": {"processes": ["test.exe"], "files": ["backup test.ps1"],
                                                               "command_lines": ["schtasks /tn 'maintenance test'"]}},
        {"title": "Web request", "rule_name": "waf", "raw": {"user_agent": "HealthCheck test monitoring scanner"}},
        {"title": "Mail", "rule_name": "mail-gw", "raw": {"subject": "Scheduled maintenance test update"}},
    ],
)
def test_attacker_named_text_is_never_benign_evidence(alert: Mapping[str, Any]) -> None:
    fp, _ = rule_indicators({"severity": "low", "source_id": "edr-prod", **alert})
    assert not set(fp) & BENIGN_WORDS, fp


@pytest.mark.parametrize(
    ("rule_name", "extra", "kept", "dropped"),
    [
        # Products that render values into rule names: quoted spans and named values are masked out.
        ("Service 'Windows Update Test' installed", {}, {"service", "installed"}, {"update", "test", "windows"}),
        ("Service \u201cScheduled Backup\u201d installed", {}, {"service"}, {"scheduled", "backup"}),
        ("Service Windows Update Test installed", {"raw": {"ServiceName": "Windows Update Test"}},
         {"service", "installed"}, {"update", "test"}),
        ("Task Maintenance Job created on host", {"entities": {"processes": ["Maintenance Job"]}},
         {"task", "created"}, {"maintenance"}),
        # A zero-width joiner cannot hide a value from masking.
        ("Process test\u200b.exe ran", {"entities": {"processes": ["test.exe"]}}, {"process", "ran"}, {"test"}),
        # Detector words: separators split, file names stay whole, adjacent words join for multi-word keywords.
        ("ups-test", {}, {"ups", "test"}, set()),
        ("CERT_ROTATION_TEST", {}, {"test", "cert_rotation"}, set()),
        ("uptime health-check", {}, {"health_check"}, set()),
        ("C:\\test\\maintenance.exe dropped", {}, {"dropped"}, {"test", "maintenance"}),
    ],
)
def test_detector_words_mask_attacker_spans(rule_name: str, extra: Dict[str, Any], kept: set, dropped: set) -> None:
    words = trusted_words({"rule_name": rule_name, **extra})
    assert kept <= words and not dropped & words, words


def test_rule_name_words_are_trusted_and_untrusted_titles_stay_untrusted() -> None:
    fp, _ = rule_indicators({"title": "x", "rule_name": "pipeline-selftest", "severity": "info", "source_id": "siem"})
    assert fp == ["selftest_detected"]
    fp, _ = rule_indicators({"title": "x", "rule_name": "2932: Scheduled maintenance: package update installed",
                             "severity": "low", "source_id": "wazuh"})
    assert fp == ["scheduled_detected", "maintenance_detected", "update_detected"]
    # A rule name a model wrote, or an email's, is no evidence either.
    assert trusted_words({"rule_name": "maintenance-test", "flags": ["llm_normalized"]}) == frozenset()
    assert trusted_words({"rule_name": "maintenance-test", "flags": ["title_from_message"]}) == frozenset()
    assert detector_words(None) == frozenset() and detector_words("") == frozenset()


def test_eicar_hashes_are_benign_evidence_only_when_every_hash_is_eicar() -> None:
    for digest in (EICAR_MD5, EICAR_SHA1, EICAR_SHA256.upper()):
        alert = {"title": "AV detection", "rule_name": "av-detection", "severity": "low", "source_id": "edr",
                 "entities": {"hashes": [digest]}}
        assert eicar_only(alert) and EICAR_SIGNAL in rule_indicators(alert)[0]
    mixed = {"entities": {"hashes": [EICAR_MD5]}, "raw": {"file_hash": "d41d8cd98f00b204e9800998ecf8427e"}}
    assert not eicar_only(mixed) and not eicar_only({"title": "EICAR test file"})
    base = {"title": "AV detection", "rule_name": "av-detection", "severity": "low", "source_id": "edr"}
    assert rule_confidence({**base, "entities": {"hashes": [EICAR_SHA256]}}) == rule_confidence(base) - 25


def test_known_scanners_come_from_tenant_configuration() -> None:
    settings = {"triage": {"known_scanners": ["Scanner-01.corp.example.", "10.0.5.0/28", 7, "not a host!"]}}
    scanners = KnownScanners.from_settings(settings)
    assert scanners.hosts == {"scanner-01.corp.example"} and len(scanners.networks) == 1
    assert scanners.matches({"entities": {"hosts": ["SCANNER-01.corp.example"]}})
    assert scanners.matches({"entities": {"ips": ["10.0.5.10"]}})
    assert not scanners.matches({"entities": {"ips": ["10.0.6.10"], "hosts": ["scanner-02"]}})
    # Only structured entities count: a scanner's name in the title or a raw field is attacker-writable.
    assert not scanners.matches({"title": "scan from scanner-01.corp.example", "raw": {"src": "10.0.5.10"}})
    assert not KnownScanners.from_settings({}) and not KnownScanners.from_settings({"triage": ["x"]})
    alert = {"title": "Port scan", "rule_name": "ids-portscan", "severity": "low", "source_id": "ids",
             "entities": {"ips": ["10.0.5.3"]}}
    assert rule_indicators(alert, scanners=scanners)[0] == [SCANNER_SIGNAL]
    assert rule_indicators(alert)[0] == []


def test_triage_settings_validation() -> None:
    assert validate_triage_settings({"known_scanners": [" Scanner-01. ", "10.0.5.10", "10.0.5.0/24", "scanner-01"]}) == {
        "known_scanners": ["scanner-01", "10.0.5.10/32", "10.0.5.0/24"]
    }
    for bad in ({"known_scanners": ["not a host!"]}, {"scanners": []}, ["x"], {"known_scanners": ["x"] * 257}):
        with pytest.raises(ValueError, match="triage"):
            validate_triage_settings(bad)


def test_the_onboarding_samples_are_still_recognised_through_trusted_signals() -> None:
    samples = {e["source_alert_id"]: {**e, "source_id": "sample"} for e in sample_events()}
    fp, _ = rule_indicators(samples["sample-002-eicar"])
    assert {EICAR_SIGNAL, "test_detected"} <= set(fp)
    scan = samples["sample-005-scan"]
    scanners = KnownScanners.from_settings({"triage": {"known_scanners": ["scanner-01.corp.example"]}})
    assert {SCANNER_SIGNAL, "scan_detected"} <= set(rule_indicators(scan, scanners=scanners)[0])
    assert SCANNER_SIGNAL not in rule_indicators(scan)[0]


async def test_triage_reads_the_tenant_scanners(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos(tenant_settings={"t1": {"triage": {"known_scanners": ["10.0.9.9"]}}})
    alert = {"title": "Vulnerability scan", "rule_name": "ids-portscan", "severity": "low", "source_id": "ids",
             "entities": {"ips": ["10.0.9.9"]}}
    agent = TriageAgent(settings=settings, model_factory=factory(scripted()))
    result = await agent.run(ctx(settings, repos=repos), alert)
    assert SCANNER_SIGNAL in result.rule_fp and repos.tenants.reads == 1
    # An alert with no host, address or email section does not read the tenant settings.
    await agent.run(ctx(settings, repos=repos), {"title": "Login", "severity": "low", "source_id": "x"})
    assert repos.tenants.reads == 1
