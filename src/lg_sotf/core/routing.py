"""Routing policy: pure functions of workflow state and thresholds.

Safety rules enforced here (contract section 8):

* Automation never closes a high/critical alert: only an analyst decision,
  a suppression rule or an analyst-confirmed verdict (not for critical) does.
  Lower severities close only with rule-based corroboration of the LLM.
* A response the policy (not an analyst) chose goes to an analyst unless an
  action really succeeded or is waiting for approval: dry-run or blocked
  actions alone never close a malicious alert silently.
* Containment is only ever proposed through ``plan_response``, where tenant
  autonomy and guardrails apply.
* ``needs_more_info`` sends the case back to analysis at most
  ``max_more_info_loops`` times; afterwards it goes back to an analyst.
* Once an analyst has asked for more information, automation never closes
  or responds on its own: the case returns to the analyst.
* A model refusal (``llm_refusal`` in the triage, correlation or analysis
  digest) always ends with an analyst: triage never closes such an alert and
  ``decide`` escalates it with code ``model_refused``, whatever the scores
  the rules produced without the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional

from pydantic import BaseModel, ConfigDict

HIGH_SEVERITIES = frozenset({"high", "critical"})
BENIGN_DECISIONS = frozenset({"false_positive", "benign_positive"})

GateRoute = Literal["triage", "close"]
TriageRoute = Literal["correlation", "close"]
CorrelationRoute = Literal["analysis", "decide"]
DecideRoute = Literal["escalate", "plan_response", "close"]
AnalystRoute = Literal["plan_response", "close", "analysis", "escalate"]
PlanRoute = Literal["execute_actions", "await_approval", "close", "escalate"]
ExecuteRoute = Literal["await_approval", "close", "escalate"]


class RoutingThresholds(BaseModel):
    """Numeric policy knobs, read from ``settings.routing`` (unknown keys ignored)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    triage_close_max_confidence: int = 10
    triage_close_min_fp: int = 2
    triage_fp_majority_min: int = 3
    triage_fp_majority_max_confidence: int = 20
    correlation_strong_score: int = 85
    correlation_strong_min_related: int = 5
    correlation_grey_zone_min: int = 30
    correlation_grey_zone_max: int = 70
    human_review_min: int = 20
    human_review_max: int = 60
    analysis_threshold: int = 40
    response_threshold: int = 80
    response_combo_threat: int = 60
    response_combo_confidence: int = 80
    close_max_threat: int = 30
    max_more_info_loops: int = 1
    max_alert_age_hours: int = 72

    @classmethod
    def from_settings(cls, routing: Optional[Mapping[str, Any]]) -> RoutingThresholds:
        return cls.model_validate(dict(routing or {}))


@dataclass(frozen=True)
class Decision:
    route: DecideRoute
    reason: str
    disposition: Optional[str]
    code: str

    def as_dict(self) -> dict[str, Any]:
        return {"route": self.route, "reason": self.reason, "disposition": self.disposition, "code": self.code}


def _is_high(state: Mapping[str, Any]) -> bool:
    return state.get("severity") in HIGH_SEVERITIES


REFUSAL_DIGESTS = ("triage", "correlation", "analysis")


def refused_by(state: Mapping[str, Any]) -> Optional[str]:
    """The first agent (triage, correlation, analysis) whose model refused this alert, if any."""
    for agent in REFUSAL_DIGESTS:
        digest = state.get(agent)
        if isinstance(digest, Mapping) and isinstance(digest.get("llm_refusal"), Mapping):
            return agent
    return None


def route_after_gate(state: Mapping[str, Any]) -> GateRoute:
    gate = state.get("gate") or {}
    return "close" if gate.get("suppressed") else "triage"


def _obvious_fp(confidence: float, fp: int, tp: int, t: RoutingThresholds) -> bool:
    if confidence <= t.triage_close_max_confidence and fp >= t.triage_close_min_fp:
        return True
    return fp > tp and fp >= t.triage_fp_majority_min and confidence <= t.triage_fp_majority_max_confidence


def route_after_triage(state: Mapping[str, Any], t: RoutingThresholds) -> TriageRoute:
    """Close only obvious false positives of low/medium/info severity.

    High and critical alerts always continue to correlation and analysis:
    triage evidence (keyword rules over alert text an attacker can shape,
    or the fast LLM) is never enough to close them. For the rest, closing
    needs at least one rule-based false-positive signal besides the LLM's.
    """
    if _is_high(state):
        return "correlation"
    triage = state.get("triage") or {}
    if isinstance(triage.get("llm_refusal"), Mapping):
        return "correlation"
    rule_fp = len(triage.get("rule_fp") or [])
    rule_tp = len(triage.get("rule_tp") or [])
    fp = rule_fp + len(triage.get("llm_fp") or [])
    tp = rule_tp + len(triage.get("llm_tp") or [])
    confidence = float(triage.get("confidence", 50))
    if rule_fp == 0 or not _obvious_fp(confidence, fp, tp, t):
        return "correlation"
    return "close"


def route_after_correlation(state: Mapping[str, Any], t: RoutingThresholds) -> CorrelationRoute:
    corr = state.get("correlation") or {}
    score = float(corr.get("score", 0))
    related = int(corr.get("related_count", 0))
    confidence = float(state.get("confidence", 50))
    if score > t.correlation_strong_score and related >= t.correlation_strong_min_related:
        return "decide"
    if (
        not _is_high(state)
        and confidence < t.human_review_min
        and score < t.human_review_min
        and not corr.get("burst")
    ):
        return "decide"
    return "analysis"


def decide(state: Mapping[str, Any], t: RoutingThresholds) -> Decision:
    if int(state.get("more_info_loops", 0)) > 0:
        return Decision("escalate", "analyst requested more information", None, "analyst_request")
    refused = refused_by(state)
    if refused is not None:
        return Decision("escalate", f"the model declined to assess the alert ({refused})", None, "model_refused")

    triage = state.get("triage") or {}
    analysis = state.get("analysis") or {}
    confidence = float(state.get("confidence", triage.get("confidence", 50)))
    if analysis:
        threat = float(analysis.get("threat_score", confidence))
        rule_threat = float(analysis.get("rule_threat_score", threat))
        verdict = analysis.get("verdict")
    else:
        threat = confidence
        rule_threat = float(triage.get("rule_confidence", confidence))
        verdict = None

    if threat >= t.response_threshold or (
        threat >= t.response_combo_threat and confidence >= t.response_combo_confidence
    ):
        return Decision(
            "plan_response", f"threat score {threat:.0f} meets the response policy", "malicious", "high_risk"
        )

    if verdict == "inconclusive" or t.correlation_grey_zone_min <= confidence <= t.correlation_grey_zone_max:
        return Decision("escalate", "confidence in the grey zone", None, "grey_zone")

    if threat < t.close_max_threat:
        if _is_high(state):
            return Decision("escalate", "high severity alerts are closed only by an analyst", None, "false_positive_review")
        if rule_threat < t.close_max_threat:
            return Decision("close", "low threat corroborated by rules", "benign", "rule_corroborated_benign")
        return Decision("escalate", "low threat verdict lacks rule corroboration", None, "false_positive_review")

    return Decision("escalate", "no automatic policy applies", None, "inconclusive")


def route_after_decide(state: Mapping[str, Any]) -> DecideRoute:
    decision = state.get("decision") or {}
    route = decision.get("route")
    if route not in ("escalate", "plan_response", "close"):
        raise ValueError(f"decide produced no valid route: {route!r}")
    return route


def route_after_analyst(state: Mapping[str, Any], t: RoutingThresholds) -> AnalystRoute:
    analyst = state.get("analyst") or {}
    decision = analyst.get("decision")
    if decision == "true_positive":
        return "plan_response"
    if decision in BENIGN_DECISIONS:
        return "close"
    if decision == "needs_more_info":
        if int(state.get("more_info_loops", 0)) < t.max_more_info_loops:
            return "analysis"
        return "escalate"
    raise ValueError(f"unknown analyst decision: {decision!r}")


def _analyst_confirmed(state: Mapping[str, Any]) -> bool:
    return (state.get("analyst") or {}).get("decision") == "true_positive"


def route_after_plan(state: Mapping[str, Any]) -> PlanRoute:
    plan = state.get("plan") or {}
    if plan.get("auto"):
        return "execute_actions"
    if state.get("awaiting_actions", plan.get("awaiting")):
        return "await_approval"
    return "close" if _analyst_confirmed(state) else "escalate"


def route_after_execute(state: Mapping[str, Any]) -> ExecuteRoute:
    """Back to approval while actions still wait; otherwise close, or escalate a policy-only response.

    A response the policy chose closes only when an action really succeeded
    through a connector; dry-run, blocked or rejected actions alone mean no
    human and no external system has handled the threat yet.
    """
    if state.get("awaiting_actions"):
        return "await_approval"
    if _analyst_confirmed(state):
        return "close"
    executed = state.get("executed") or {}
    if any(status == "succeeded" for status in executed.values()):
        return "close"
    return "escalate"
