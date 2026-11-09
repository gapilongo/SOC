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
BENIGN_SUMMARY: Dict[str, Any] = {"triage": {"threat_assessment": "benign", "threat_likelihood": 3},
                                  "analysis": {"verdict": "benign", "certainty": 90}}
RULES = {
    "2902": "New dpkg (Debian Package) installed.",
    "5402": "Successful sudo to ROOT executed.",
    "80792": "Audit: Command: /usr/bin/curl.",
}


def wazuh(rule_id: str, *, mitre: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    """A Wazuh alert on ``HOST`` as the correlation agent sees it: canonical fields and the raw event."""
    description = RULES[rule_id]
    return {
        "title": description, "severity": "medium", "rule_name": f"{rule_id}: {description}",
        "entities": {"hosts": [HOST]}, "mitre": mitre or {"tactics": [], "techniques": []},
        "raw": {"rule": {"id": rule_id, "level": 7, "description": description}, "agent": {"name": HOST}},
    }


def stored(alert_id: str, rule_id: str, *, status: str = "waiting_human", summary: Optional[Dict[str, Any]] = None,
           disposition: Optional[str] = None, mitre: Optional[Dict[str, List[str]]] = None) -> StoredAlert:
    document = wazuh(rule_id, mitre=mitre)
    raw = document.pop("raw")
    return StoredAlert(id=alert_id, title=document["title"], status=status, disposition=disposition,
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
        ("a model judged it malicious", {"summary": {**BENIGN_SUMMARY, "analysis": {"verdict": "malicious"}}}),
        ("the fast tier judged it suspicious",
         {"summary": {**BENIGN_SUMMARY, "triage": {"threat_assessment": "suspicious"}}}),
        ("the fast tier judged it a likely threat",
         {"summary": {**BENIGN_SUMMARY, "triage": {"threat_assessment": "likely_threat"}}}),
        ("the deep tier could not tell", {"summary": {**BENIGN_SUMMARY, "analysis": {"verdict": "inconclusive"}}}),
        ("no model judged it yet (still in flight)", {"status": "processing", "summary": {}}),
        ("only the rules judged it", {"summary": {"triage": {"llm_used": False}}}),
        ("it is a response plan awaiting approval", {"status": "waiting_approval"}),
        ("it is in a never-close class", {"mitre": {"tactics": ["Credential Access"], "techniques": ["T1110"]}}),
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
    result = await correlate(settings, [no_raw, renamed])
    assert (result.related_count, result.related_rule_repeats) == (2, 0) and decide(result).route == "escalate"

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
