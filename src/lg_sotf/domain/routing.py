"""Routing policy: pure functions of workflow state and thresholds.

Safety rules enforced here (contract section 8):

* Automation never closes a high/critical alert: only an analyst decision,
  a suppression rule or an analyst-confirmed verdict (not for critical) does.
  Lower severities close only with rule-based corroboration of the LLM, or
  (AI-E1.9) a benign deep-model verdict corroborated by context the tenant
  declared (``tenant_context``: a configured scanner, no steering text).
* A response the policy (not an analyst) chose goes to an analyst when an
  action failed or none completed; it closes (disposition ``malicious``)
  once its actions succeeded or ran in the tenant's dry-run mode. Blocked
  or rejected actions alone never close a malicious alert silently.
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
from typing import TYPE_CHECKING, Any, Literal, Mapping, Optional, Tuple, cast

from pydantic import BaseModel, ConfigDict

from lg_sotf.domain.benign_evidence import INJECTION_SIGNAL, TENANT_CONTEXT_SIGNALS
from lg_sotf.models.vocabulary import BENIGN_DECISIONS, COMPLETED_ACTION_STATUSES, HIGH_SEVERITIES, ROUTES
from lg_sotf.models.vocabulary import Route as DecideRoute

if TYPE_CHECKING:
    from lg_sotf.core.state import (
        AnalysisDigest,
        AnalystInput,
        CorrelationDigest,
        DecisionDigest,
        GateDigest,
        PlanDigest,
        RoutingDigest,
        TriageDigest,
    )

GateRoute = Literal["triage", "close"]
TriageRoute = Literal["correlation", "close"]
CorrelationRoute = Literal["analysis", "decide"]
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
    # AI-E1.9 (docs/scorecards/v2/deepseek-v4/CALIBRATION.md): false restores the 1.2 policy. The correlation
    # cap was measured and is not on by default.
    benign_verdict_precedence: bool = True
    context_corroboration: bool = True
    cap_correlated_confidence: bool = False

    @classmethod
    def from_settings(cls, routing: Optional[Mapping[str, Any]]) -> RoutingThresholds:
        return cls.model_validate(dict(routing or {}))


@dataclass(frozen=True)
class Decision:
    route: DecideRoute
    reason: str
    disposition: Optional[str]
    code: str

    def as_dict(self) -> DecisionDigest:
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


LLM_NORMALIZED_FLAG = "llm_normalized"


def llm_normalized(state: Mapping[str, Any]) -> bool:
    """The alert was mapped by the LLM-fallback normalizer: its title, rule name and severity
    were chosen by a model from untrusted text, so nothing automatic may close it."""
    alert = state.get("alert")
    flags = alert.get("flags") if isinstance(alert, Mapping) else None
    return isinstance(flags, list) and LLM_NORMALIZED_FLAG in flags


def route_after_gate(state: Mapping[str, Any]) -> GateRoute:
    gate = cast("GateDigest", state.get("gate") or {})
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
    if _is_high(state) or llm_normalized(state):
        return "correlation"
    triage = cast("TriageDigest", state.get("triage") or {})
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
    corr = cast("CorrelationDigest", state.get("correlation") or {})
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

    triage = cast("TriageDigest", state.get("triage") or {})
    analysis = cast("AnalysisDigest", state.get("analysis") or {})
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

    benign_verdict = verdict == "benign" and threat < t.close_max_threat
    in_band = t.correlation_grey_zone_min <= confidence <= t.correlation_grey_zone_max
    if verdict == "inconclusive" or (in_band and not (benign_verdict and t.benign_verdict_precedence)):
        return Decision("escalate", "confidence in the grey zone", None, "grey_zone")

    if threat < t.close_max_threat:
        if _is_high(state):
            return Decision("escalate", "high severity alerts are closed only by an analyst", None, "false_positive_review")
        if llm_normalized(state):
            return Decision(
                "escalate", "the alert was normalised by a model; an analyst confirms benign closes", None, "llm_normalized"
            )
        if rule_threat < t.close_max_threat:
            return Decision("close", "low threat corroborated by rules", "benign", "rule_corroborated_benign")
        if benign_verdict and t.context_corroboration and tenant_context(triage):
            return Decision("close", "benign verdict corroborated by the tenant's context", "benign", "context_corroborated_benign")
        return Decision("escalate", "low threat verdict lacks rule corroboration", None, "false_positive_review")

    return Decision("escalate", "no automatic policy applies", None, "inconclusive")


def tenant_context(triage: Mapping[str, Any]) -> bool:
    """Triage found rule evidence the tenant declared (a configured scanner), and no text written to steer a model."""
    fp, tp = triage.get("rule_fp"), triage.get("rule_tp")
    if not isinstance(fp, list) or (isinstance(tp, list) and INJECTION_SIGNAL in tp):
        return False
    return any(s in TENANT_CONTEXT_SIGNALS for s in fp if isinstance(s, str))


def correlated_confidence(base: float, adjusted: int, t: RoutingThresholds) -> int:
    """Correlation's adjusted confidence; with ``cap_correlated_confidence`` related alerts never lift it to the
    response policy's ``response_combo_confidence`` (triage alone decides that, with trusted rule evidence)."""
    if not t.cap_correlated_confidence or base >= t.response_combo_confidence:
        return adjusted
    return min(adjusted, t.response_combo_confidence - 1)


def review_band(code: str, confidence: float, t: RoutingThresholds) -> Optional[Tuple[int, int]]:
    """The confidence band that sent the alert to an analyst, when one did.

    Only ``grey_zone`` escalations are decided by a band: the confidence lies
    in ``[correlation_grey_zone_min, correlation_grey_zone_max]``. A
    ``grey_zone`` escalation caused by an ``inconclusive`` verdict outside the
    band, and every other code, has none.
    """
    if code == "grey_zone" and t.correlation_grey_zone_min <= confidence <= t.correlation_grey_zone_max:
        return t.correlation_grey_zone_min, t.correlation_grey_zone_max
    return None


def routing_digest(code: str, confidence: float, t: RoutingThresholds) -> RoutingDigest:
    """What an escalation records about the routing that created it: the code, the confidence and the band."""
    band = review_band(code, confidence, t)
    return {
        "code": code,
        "confidence": confidence,
        "band": {"min": band[0], "max": band[1]} if band is not None else None,
    }


def route_after_decide(state: Mapping[str, Any]) -> DecideRoute:
    decision = cast("DecisionDigest", state.get("decision") or {})
    route = decision.get("route")
    if route not in ROUTES:
        raise ValueError(f"decide produced no valid route: {route!r}")
    return route


def route_after_analyst(state: Mapping[str, Any], t: RoutingThresholds) -> AnalystRoute:
    analyst = cast("AnalystInput", state.get("analyst") or {})
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
    analyst = cast("AnalystInput", state.get("analyst") or {})
    return analyst.get("decision") == "true_positive"


def route_after_plan(state: Mapping[str, Any]) -> PlanRoute:
    plan = cast("PlanDigest", state.get("plan") or {})
    if plan.get("auto"):
        return "execute_actions"
    if state.get("awaiting_actions", plan.get("awaiting")):
        return "await_approval"
    return "close" if _analyst_confirmed(state) else "escalate"


def route_after_execute(state: Mapping[str, Any]) -> ExecuteRoute:
    """Back to approval while actions still wait; otherwise close, or escalate a policy-only response.

    A response the policy chose closes when its actions completed: through
    a connector (``succeeded``) or in the dry-run mode the tenant chose
    (``dry_run``). It escalates when an action failed or is still
    ``executing`` (a stateful connector deferred it to the scheduler, so the
    outcome is not known yet), or when no action completed at all
    (everything blocked or rejected): then neither a human nor a connector
    has handled the threat.
    """
    if state.get("awaiting_actions"):
        return "await_approval"
    if _analyst_confirmed(state):
        return "close"
    statuses = set((state.get("executed") or {}).values())
    if "failed" in statuses or "executing" in statuses:
        return "escalate"
    if statuses & COMPLETED_ACTION_STATUSES:
        return "close"
    return "escalate"
