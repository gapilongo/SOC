"""The campaign split (FIX-2, decision policy v2.1): one detection rule repeating is noise; different detections on
the same entities are a possible kill chain.

The correlation agent counts, over every related alert, the quiet repeats of
this alert's own vendor rule (``related_rule_repeats``) and whether the
related set is complete (``related_complete``); the real routing policy then
decides on the digest it produced.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

import pytest

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.correlation.base import CorrelationAgent, CorrelationResult
from lg_sotf.domain import routing
from lg_sotf.domain.closure import MODEL_CLOSED, model_close_blockers
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.settings import Settings
from tests.unit.agents._support import NOW, FakeBlindAudit, Related, StoredAlert, fake_repos

T = RoutingThresholds()
AUTO = "auto_full_audit"
HOST = "web-01"
BENIGN_TRIAGE: Dict[str, Any] = {"threat_assessment": "benign", "threat_likelihood": 3, "llm_used": True,
                                 "rule_fp": [], "rule_tp": []}
BENIGN_ANALYSIS: Dict[str, Any] = {"verdict": "benign", "certainty": 90, "threat_score": 8, "llm_used": True,
                                   "rule_evidence": [], "rule_corroborated": False}
#: A sibling's own correlation digest when it had no related alert.
ALONE: Dict[str, Any] = {"related_count": 0, "related_complete": True, "related_rule_repeats": 0, "related_threats": 0,
                         "related_other_rules": 0, "related_dispositions": {}}
#: What a sibling the models could close themselves has stored: both tiers benign within the thresholds, alone.
BENIGN_SUMMARY: Dict[str, Any] = {"triage": BENIGN_TRIAGE, "analysis": BENIGN_ANALYSIS, "correlation": ALONE}
RULES = {
    "2902": "New dpkg (Debian Package) installed.",
    "5402": "Successful sudo to ROOT executed.",
    "80792": "Audit: Command: /usr/bin/curl.",
    "60612": "Application installed Product: Helper -- Installation completed successfully.",
}


def wazuh(rule_id: str, *, mitre: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    """A Wazuh alert on ``HOST`` as the correlation agent sees it: canonical fields and the raw event."""
    description = RULES[rule_id]
    return {
        "title": description, "severity": "medium", "rule_name": f"{rule_id}: {description}", "normalizer": "wazuh",
        "entities": {"hosts": [HOST]}, "mitre": mitre or {"tactics": [], "techniques": []},
        "raw": {"rule": {"id": rule_id, "level": 7, "description": description}, "agent": {"name": HOST}},
    }


def stored(alert_id: str, rule_id: str, *, status: str = "waiting_human", summary: Optional[Dict[str, Any]] = None,
           severity: str = "medium",
           disposition: Optional[str] = None, mitre: Optional[Dict[str, List[str]]] = None) -> StoredAlert:
    document = wazuh(rule_id, mitre=mitre)
    raw = document.pop("raw")
    return StoredAlert(id=alert_id, title=document["title"], severity=severity, status=status, disposition=disposition,
                       normalized=document, raw=raw, summary=BENIGN_SUMMARY if summary is None else summary)


async def correlate(settings: Settings, others: List[StoredAlert], *, rule_id: str = "2902",
                    pending: tuple = (), max_correlations: int = 10) -> CorrelationResult:  # type: ignore[type-arg]
    related = [Related(a.id, 1, NOW - timedelta(minutes=2)) for a in others]
    repos = fake_repos(alerts=others, related=related)
    repos.blind_audit = FakeBlindAudit(pending)
    agent = CorrelationAgent(settings=settings, config={"enable_llm_correlation": False,
                                                        "max_correlations": max_correlations})
    return await agent.run(AgentContext("t1", "a1", settings, repos=repos), wazuh(rule_id), base_confidence=25, now=NOW)


def decide(result: CorrelationResult, rule_id: str = "2902") -> routing.Decision:
    """The real routing decision for an alert both model tiers call benign, with the digest the agent produced."""
    state = {
        "severity": "medium", "confidence": 25, "alert": wazuh(rule_id),
        "triage": {"rule_fp": [], "rule_tp": [], "llm_used": True, "threat_assessment": "benign",
                   "threat_likelihood": 3},
        "correlation": dict(result.digest()),
        "analysis": {"threat_score": 8, "certainty": 92, "verdict": "benign", "rule_evidence": [],
                     "rule_corroborated": False, "llm_used": True},
    }
    return routing.decide(state, T, AUTO)


async def test_the_same_rule_repeating_as_benign_noise_is_not_a_campaign(make_settings: Callable[..., Settings]) -> None:
    """A burst of one rule (dpkg installs during patching), every repeat judged benign and still open for review:
    before FIX-2 the burst and the open reviews blocked every close, so the check blocked itself."""
    others = [stored(f"r{i}", "2902") for i in range(7)]
    others.append(stored("r7", "2902", status="closed", disposition="benign",
                         summary={**BENIGN_SUMMARY, "close_reason": "ai_closed:audit_required"}))
    result = await correlate(make_settings(), others)
    assert result.burst and result.related_count == 8 and result.related_open_reviews == 7
    assert (result.related_rule_repeats, result.related_complete, result.related_threats) == (8, True, 0)
    assert decide(result).code == MODEL_CLOSED


async def test_a_different_detection_on_the_same_host_is_a_possible_kill_chain(
    make_settings: Callable[..., Settings],
) -> None:
    """Mixed rules on one host (package installs, then sudo to root, then curl): even when every one of them was
    judged benign and closed, the other rules count against closing; one alert alone is enough."""
    for intruder in (stored("x", "5402"), stored("x", "80792", status="closed", disposition="benign"),
                     stored("x", "5402", status="closed", disposition="benign",
                            summary={**BENIGN_SUMMARY, "close_reason": "analyst:false_positive"})):
        result = await correlate(make_settings(), [stored(f"r{i}", "2902") for i in range(4)] + [intruder])
        assert (result.related_count, result.related_rule_repeats, result.related_complete) == (5, 4, True)
        decision = decide(result)
        assert decision.route == "escalate", intruder
    # Seen from the other side: the sudo alert next to the dpkg repeats is not a repeat of its own rule either.
    result = await correlate(make_settings(), [stored(f"r{i}", "2902") for i in range(4)], rule_id="5402")
    assert result.related_rule_repeats == 0 and decide(result, "5402").route == "escalate"


@pytest.mark.parametrize(
    ("why", "repeat"),
    [
        ("a model judged it malicious",
         {"summary": {**BENIGN_SUMMARY, "analysis": {**BENIGN_ANALYSIS, "verdict": "malicious"}}}),
        ("the fast tier judged it suspicious",
         {"summary": {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "threat_assessment": "suspicious"}}}),
        ("the fast tier judged it a likely threat",
         {"summary": {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "threat_assessment": "likely_threat"}}}),
        ("the deep tier could not tell",
         {"summary": {**BENIGN_SUMMARY, "analysis": {**BENIGN_ANALYSIS, "verdict": "inconclusive"}}}),
        ("no model judged it yet (still in flight)", {"status": "processing", "summary": {}}),
        ("only the rules judged it", {"summary": {"triage": {**BENIGN_TRIAGE, "llm_used": False}}}),
        ("it is a response plan awaiting approval", {"status": "waiting_approval"}),
        ("it is in a never-close class", {"mitre": {"tactics": ["Credential Access"], "techniques": ["T1110"]}}),
        ("it is high severity", {"severity": "high"}),
        # Review of #345 (M1): what FIX-1 blocked on in the sibling itself blocks it as a repeat.
        ("(a) it carries steering text",
         {"summary": {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "rule_tp": ["prompt_injection_suspected"]}}}),
        ("(b) rule evidence corroborates a threat",
         {"summary": {**BENIGN_SUMMARY, "analysis": {**BENIGN_ANALYSIS, "rule_corroborated": True}}}),
        ("(b) its entities have analyst-confirmed malicious history",
         {"summary": {**BENIGN_SUMMARY,
                      "analysis": {**BENIGN_ANALYSIS, "rule_evidence": ["prior_malicious_history"]}}}),
        ("(b) one of its own related alerts closed as malicious",
         {"summary": {**BENIGN_SUMMARY, "correlation": {**ALONE, "related_dispositions": {"malicious": 1}}}}),
        ("(c) the fast tier said benign at likelihood 40",
         {"summary": {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "threat_likelihood": 40}}}),
        ("(c) the deep tier said benign at certainty 60",
         {"summary": {**BENIGN_SUMMARY, "analysis": {**BENIGN_ANALYSIS, "certainty": 60}}}),
        ("(d) it is still in flight without a deep verdict",
         {"status": "processing", "summary": {"triage": BENIGN_TRIAGE}}),
    ],
)
async def test_a_same_rule_alert_still_counts_against_closing_when(
    why: str, repeat: Dict[str, Any], make_settings: Callable[..., Settings]
) -> None:
    others = [stored(f"r{i}", "2902") for i in range(3)] + [stored("odd", "2902", **repeat)]
    result = await correlate(make_settings(), others)
    assert (result.related_count, result.related_rule_repeats) == (4, 3), why
    assert decide(result).route == "escalate", why


async def test_an_incomplete_related_set_fails_closed(make_settings: Callable[..., Settings]) -> None:
    """The query hit its limit (more related alerts may exist, a kill chain among them), or a related alert is
    hidden while it waits for a blind-audit label: the counts cover only part of the set, so a close is blocked."""
    settings = make_settings()
    full = await correlate(settings, [stored(f"r{i}", "2902") for i in range(5)], max_correlations=5)
    assert (full.related_count, full.related_rule_repeats, full.related_complete) == (5, 5, False)
    assert decide(full).route == "escalate"
    hidden = await correlate(settings, [stored("r0", "2902"), stored("audit", "5402")], pending=("audit",))
    assert (hidden.related_count, hidden.related_rule_repeats, hidden.related_complete) == (1, 1, False)
    assert decide(hidden).route == "escalate"
    only_hidden = await correlate(settings, [stored("audit", "2902")], pending=("audit",))
    assert (only_hidden.related_count, only_hidden.related_complete) == (0, False)
    assert decide(only_hidden).route == "escalate"
    alone = await correlate(settings, [])
    assert (alone.related_count, alone.related_complete) == (0, True) and decide(alone).code == MODEL_CLOSED


async def test_an_unknown_rule_on_either_side_is_never_a_repeat(make_settings: Callable[..., Settings]) -> None:
    """No vendor rule id (another vendor, a canonical alert, a raw event the state cap dropped): fail closed."""
    settings = make_settings()
    no_raw = stored("r0", "2902")
    no_raw.raw = {}
    renamed = stored("r1", "2902")
    renamed.normalized = {**renamed.normalized, "rule_name": "New dpkg (Debian Package) installed."}
    pushed = stored("r2", "2902")  # a canonical push that copies a Wazuh document: not the Wazuh normalizer
    pushed.normalized = {**pushed.normalized, "normalizer": "canonical"}
    legacy = stored("r3", "2902")  # stored before the format was recorded
    legacy.normalized = {k: v for k, v in legacy.normalized.items() if k != "normalizer"}
    result = await correlate(settings, [no_raw, renamed, pushed, legacy])
    assert (result.related_count, result.related_rule_repeats) == (4, 0) and decide(result).route == "escalate"

    agent = CorrelationAgent(settings=settings, config={"enable_llm_correlation": False})
    others = [stored("r0", "2902")]
    repos = fake_repos(alerts=others, related=[Related("r0", 1, NOW)])
    this = {**wazuh("2902"), "raw": {"_omitted": "raw event too large for workflow state"}}
    unknown = await agent.run(AgentContext("t1", "a1", settings, repos=repos), this, base_confidence=25, now=NOW)
    assert unknown.related_rule_repeats == 0
    state = {"severity": "medium", "alert": this, "correlation": dict(unknown.digest())}
    assert "campaign_in_progress" in model_close_blockers(state, tier=AUTO, max_likelihood=8, min_certainty=85)


async def test_the_new_counts_are_in_the_digest_but_never_in_the_correlation_prompt(
    make_settings: Callable[..., Settings],
) -> None:
    result = await correlate(make_settings(), [stored("r0", "2902")])
    digest = result.digest()
    assert digest["related_rule_repeats"] == 1 and digest["related_complete"] is True
    view = CorrelationAgent.alert_view(wazuh("2902"))
    assert "raw" not in view and "related_rule_repeats" not in str(view)


async def test_a_sibling_closed_as_benign_is_a_quiet_repeat(make_settings: Callable[..., Settings]) -> None:
    """An analyst (or approved evidence) who closed a sibling as benign looked at it: it counts as a repeat even when
    its own model judgement would not have closed it. Closed as malicious, it is a recent true positive instead."""
    steering = {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "rule_tp": ["prompt_injection_suspected"]}}
    looked_at = stored("r0", "2902", status="closed", disposition="benign", summary=steering)
    result = await correlate(make_settings(), [looked_at, stored("r1", "2902")])
    assert (result.related_count, result.related_rule_repeats) == (2, 2) and decide(result).code == MODEL_CLOSED
    bad = stored("r0", "2902", status="closed", disposition="malicious")
    result = await correlate(make_settings(), [bad])
    assert result.related_rule_repeats == 1 and decide(result).route == "escalate"  # recent true positive


async def test_review_m1_a_steering_msi_does_not_vouch_for_the_next(make_settings: Callable[..., Settings]) -> None:
    """Review of #345 (M1a): MSI install #1 carries steering text and waits for an analyst; a clean MSI #2 on the same
    host is not closed on the strength of #1 being the same rule."""
    steering = {**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "rule_tp": ["prompt_injection_suspected"]}}
    result = await correlate(make_settings(), [stored("msi1", "60612", summary=steering)], rule_id="60612")
    assert (result.related_count, result.related_rule_repeats) == (1, 0)
    assert decide(result, "60612").route == "escalate"



# --------------------------------------------------------------------------- re-check of #345: campaign-block laundering


async def sibling_with_own_digest(settings: Settings, its_related: List[StoredAlert], **correlate_kwargs: Any) -> StoredAlert:
    """S (rule 2902, both tiers benign) as stored after its own correlation over ``its_related``: the digest is the
    one the real agent produced for it."""
    own = await correlate(settings, its_related, **correlate_kwargs)
    return stored("S", "2902", summary={**BENIGN_SUMMARY, "correlation": dict(own.digest())})


async def test_recheck_a_campaign_block_is_not_laundered_through_a_sibling(
    make_settings: Callable[..., Settings],
) -> None:
    """X (another rule, a possible kill-chain step) on host H at t0; S (2902) at t50 is blocked by X and waits for an
    analyst; A (2902) at t70 sees S but no longer X (outside its 60-minute window). S's campaign block is not exempt:
    its digest shows a related alert of another rule, so S is no quiet repeat and A goes to an analyst."""
    settings = make_settings()
    s = await sibling_with_own_digest(settings, [stored("X", "5402")])
    assert s.summary["correlation"]["related_other_rules"] == 1
    a = await correlate(settings, [s])
    assert (a.related_count, a.related_rule_repeats, a.related_other_rules) == (1, 0, 0)
    assert decide(a).route == "escalate"


@pytest.mark.parametrize(
    ("why", "its_related", "kwargs"),
    [
        ("a related alert a model judged suspicious",
         [stored("T", "2902", summary={**BENIGN_SUMMARY, "triage": {**BENIGN_TRIAGE, "threat_assessment": "suspicious"}})],
         {}),
        ("an incomplete related set (query at its limit)", [stored(f"r{i}", "2902") for i in range(2)],
         {"max_correlations": 2}),
        ("a related alert hidden for a blind audit", [stored("r0", "2902"), stored("audit", "2902")],
         {"pending": ("audit",)}),
    ],
)
async def test_recheck_threat_and_incomplete_set_blocks_are_not_laundered_either(
    why: str, its_related: List[StoredAlert], kwargs: Dict[str, Any], make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings()
    s = await sibling_with_own_digest(settings, its_related, **kwargs)
    a = await correlate(settings, [s])
    assert a.related_rule_repeats == 0, why
    assert decide(a).route == "escalate", why


async def test_recheck_a_sibling_digest_without_the_new_count_is_not_quiet(make_settings: Callable[..., Settings]) -> None:
    """Fail closed: a sibling blocked by its own campaign check, whose digest predates ``related_other_rules``."""
    old = {"related_count": 1, "related_rule_repeats": 0, "related_complete": True, "related_threats": 0,
           "related_dispositions": {}}
    a = await correlate(make_settings(), [stored("S", "2902", summary={**BENIGN_SUMMARY, "correlation": old})])
    assert a.related_rule_repeats == 0 and decide(a).route == "escalate"


async def test_recheck_a_burst_does_not_block_itself(make_settings: Callable[..., Settings]) -> None:
    """Control: S was blocked only by a same-rule sibling no model had judged yet (in flight). Its digest shows no
    threat, a complete set and no other rule, so its block clears and A, which sees only S, closes."""
    settings = make_settings()
    s = await sibling_with_own_digest(settings, [stored("P", "2902", status="processing", summary={})])
    own = s.summary["correlation"]
    assert (own["related_count"], own["related_rule_repeats"], own["related_other_rules"]) == (1, 0, 0)
    a = await correlate(settings, [s])
    assert a.related_rule_repeats == 1 and decide(a).code == MODEL_CLOSED
