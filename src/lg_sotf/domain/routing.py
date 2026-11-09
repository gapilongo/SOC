"""Routing policy: pure functions of workflow state and thresholds.

Safety rules enforced here (contract section 8):

* Automation never closes a high/critical alert: only an analyst decision,
  a suppression rule or an analyst-confirmed verdict (not for critical) does.
* Decision policy v2 (FIX-1). Every low/medium alert is analysed: correlation
  never skips analysis for it, and correlation is evidence for the model, not
  a confidence boost. The grey zone and the response policy read the
  post-analysis assessment (the analysis threat score; the triage confidence
  only when no analysis ran). A low-threat benign verdict closes a lower
  severity alert only with approved benign evidence (:func:`benign_evidence`:
  triage's rule false-positive signals, which come only from the detection
  rule's name, the EICAR hash, a test source or the tenant's declared
  context; a cached analyst verdict closes earlier, at the gate; never past
  steering text, a recent true positive or, for a declared scanner or a test
  source, a never-close class: :func:`closure.evidence_close_blockers`) or, when the
  tenant's autonomy tier is ``auto_full_audit``, through a model-led close
  (:mod:`lg_sotf.domain.closure`, code ``model_closed``) that every condition
  of that module allows. With the tier ``off`` a model never closes alone.
  Policy v2.1 (FIX-2) lets a catalogued noise rule (vendor and rule id,
  :mod:`lg_sotf.domain.noise_families`) lift only the ``unmapped`` class,
  and tells one rule repeating apart from a campaign.
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

from lg_sotf.domain import closure, noise_families
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
    # Model-led close (lg_sotf.domain.closure): the fast tier's likelihood at most this, the deep tier's
    # certainty at least this. Install-wide on purpose: a tenant chooses the tier, never looser numbers.
    model_close_max_likelihood: int = 8
    model_close_min_certainty: int = 85

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
    """Every alert automation may close (below high) is analysed; strong correlation skips it only for high/critical.

    High and critical alerts never close automatically, so a strong
    correlation may send them straight to ``decide``, which escalates them
    (or plans a response only on trusted triage evidence).
    """
    if not _is_high(state):
        return "analysis"
    corr = cast("CorrelationDigest", state.get("correlation") or {})
    score = float(corr.get("score", 0))
    related = int(corr.get("related_count", 0))
    if score > t.correlation_strong_score and related >= t.correlation_strong_min_related:
        return "decide"
    return "analysis"


def benign_evidence(triage: Mapping[str, Any]) -> bool:
    """Approved benign evidence for a close: a rule false-positive signal of triage.

    Triage takes those only from what an attacker does not write
    (:mod:`lg_sotf.domain.benign_evidence`): the detection rule's name with
    attacker-named values masked, an EICAR-only hash, a test-environment
    source id, a scanner the tenant declared (``triage.known_scanners``) and,
    for email, an authenticated sender of the tenant's internal domains.
    """
    fp = triage.get("rule_fp")
    return isinstance(fp, list) and any(isinstance(signal, str) and signal for signal in fp)


def assessed_threat(state: Mapping[str, Any]) -> float:
    """The post-analysis assessment routing tests: the analysis threat score, else the confidence."""
    triage = cast("TriageDigest", state.get("triage") or {})
    analysis = cast("AnalysisDigest", state.get("analysis") or {})
    confidence = float(state.get("confidence", triage.get("confidence", 50)))
    return float(analysis.get("threat_score", confidence)) if analysis else confidence


def decide(state: Mapping[str, Any], t: RoutingThresholds, tier: str = "off") -> Decision:
    """The routing decision after analysis; ``tier`` is the tenant's autonomy tier for model-led closure."""
    if int(state.get("more_info_loops", 0)) > 0:
        return Decision("escalate", "analyst requested more information", None, "analyst_request")
    refused = refused_by(state)
    if refused is not None:
        return Decision("escalate", f"the model declined to assess the alert ({refused})", None, "model_refused")

    triage = cast("TriageDigest", state.get("triage") or {})
    analysis = cast("AnalysisDigest", state.get("analysis") or {})
    confidence = float(state.get("confidence", triage.get("confidence", 50)))
    threat = assessed_threat(state)
    verdict = analysis.get("verdict") if analysis else None

    if threat >= t.response_threshold or (
        threat >= t.response_combo_threat and confidence >= t.response_combo_confidence
    ):
        return Decision(
            "plan_response", f"threat score {threat:.0f} meets the response policy", "malicious", "high_risk"
        )

    if verdict == "inconclusive" or t.correlation_grey_zone_min <= threat <= t.correlation_grey_zone_max:
        return Decision("escalate", "assessment in the grey zone", None, "grey_zone")

    if threat < t.close_max_threat:
        return _low_threat(state, triage, verdict, t, tier)

    return Decision("escalate", "no automatic policy applies", None, "inconclusive")


def _low_threat(
    state: Mapping[str, Any], triage: Mapping[str, Any], verdict: Optional[str], t: RoutingThresholds, tier: str
) -> Decision:
    """A low threat: close on approved benign evidence or a model-led close the tier allows, else an analyst."""
    if _is_high(state):
        return Decision("escalate", "high severity alerts are closed only by an analyst", None, "false_positive_review")
    if llm_normalized(state):
        return Decision(
            "escalate", "the alert was normalised by a model; an analyst confirms benign closes", None, "llm_normalized"
        )
    if verdict not in (None, "benign"):
        return Decision("escalate", "low threat score without a benign verdict", None, "false_positive_review")
    if benign_evidence(triage):
        overruled = closure.evidence_close_blockers(state)
        if overruled:
            reason = f"approved benign evidence overruled by {', '.join(overruled)}"
            return Decision("escalate", reason, None, "false_positive_review")
        return Decision("close", "low threat corroborated by approved benign evidence", "benign", "rule_corroborated_benign")
    blockers = closure.model_close_blockers(
        state, tier=tier, max_likelihood=t.model_close_max_likelihood, min_certainty=t.model_close_min_certainty
    )
    if not blockers:
        reason = "AI-closed, audit required: both model tiers judged it benign"
        family = closure.catalogued_noise(state.get("alert"))
        if family is not None:
            reason += f" (catalogued noise {family.family}, catalogue {noise_families.CATALOGUE_VERSION})"
        return Decision("close", reason, "benign", closure.MODEL_CLOSED)
    return Decision("escalate", "low threat verdict lacks approved benign evidence", None, "false_positive_review")


def review_band(code: str, confidence: float, t: RoutingThresholds) -> Optional[Tuple[int, int]]:
    """The band that sent the alert to an analyst, when one did.

    Only ``grey_zone`` escalations are decided by a band: the assessed threat
    (:func:`assessed_threat`, passed as ``confidence``) lies in
    ``[correlation_grey_zone_min, correlation_grey_zone_max]``. A
    ``grey_zone`` escalation caused by an ``inconclusive`` verdict outside the
    band, and every other code, has none.
    """
    if code == "grey_zone" and t.correlation_grey_zone_min <= confidence <= t.correlation_grey_zone_max:
        return t.correlation_grey_zone_min, t.correlation_grey_zone_max
    return None


def routing_digest(code: str, confidence: float, t: RoutingThresholds) -> RoutingDigest:
    """What an escalation records about the routing that created it: the code, the score routing tested against
    the grey zone (``confidence``: :func:`assessed_threat` for ``decide``'s escalations) and the band."""
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
