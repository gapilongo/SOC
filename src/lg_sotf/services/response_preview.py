"""Dry-run response plan for an escalation: what a ``true_positive`` decision would propose, without writing.

The plan is computed the way the workflow computes it after an analyst's
``true_positive`` (evidence ``analyst``; :mod:`lg_sotf.services.plan_context`
builds the planner's input from the stored alert and its analysis), then each
candidate action is checked like the planner checks it: the guardrails
against the tenant's current policy, the autonomy mode of its risk, and the
connector that would execute it (:mod:`lg_sotf.services.connectors.routing`).
Nothing is written to the ledger and no connector is called.

Per action:

* ``without_preapproval``: what the plan does with it when the analyst
  pre-approves nothing: ``blocked`` (a guardrail), ``automatic`` (the
  tenant's autonomy for its risk is ``auto``; the hourly caps still apply
  when it runs, and turn it into an approval when reached) or
  ``awaiting_approval``;
* ``can_preapprove``: whether the caller's role may pre-approve it with the
  decision (``approved_actions``); ``role_lock`` says why not: ``admin``
  (high and critical risk need an admin) or ``disabled`` (the tenant's
  autonomy disables its risk: nobody may approve it). A blocked action
  cannot be pre-approved either;
* ``approval_entry``: the ``approved_actions`` entry naming exactly this
  action (``action_type:target``).

The final plan is computed when the decision is recorded, from the alert as
it is then; this preview can differ if the alert, the tenant's policy or the
integrations change in between.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import List, Literal, Optional

from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.domain.actions import ACTION_CATALOG
from lg_sotf.services.plan_context import canonical_alert, plan_context
from lg_sotf.services.response import (
    ANALYST_APPROVAL_RISKS,
    ResponseService,
    approval_allowed,
    build_candidates,
    check_guardrails,
)

Outcome = Literal["automatic", "awaiting_approval", "blocked"]
RoleLock = Literal["admin", "disabled"]


@dataclass(frozen=True)
class PreviewAction:
    action_type: str
    target: str
    description: str
    risk: str
    reversible: bool
    inverse_action: Optional[str]
    irreversible_note: Optional[str]
    connector: str
    connector_source: str
    connector_live: Optional[bool]
    connector_ready: bool
    guardrail_verdict: Literal["passed", "blocked"]
    guardrail_code: Optional[str]
    guardrail_reason: Optional[str]
    autonomy: str
    without_preapproval: Outcome
    can_preapprove: bool
    role_lock: Optional[RoleLock]
    approval_entry: str


@dataclass(frozen=True)
class ResponsePreview:
    escalation_id: str
    alert_id: str
    generated_at: datetime
    threat_type: str
    evidence: str
    dry_run_forced: bool
    actions: List[PreviewAction] = field(default_factory=list)


def _outcome(blocked: bool, autonomy: str) -> Outcome:
    if blocked:
        return "blocked"
    return "automatic" if autonomy == "auto" else "awaiting_approval"


def _role_lock(risk: str, autonomy: str) -> Optional[RoleLock]:
    if autonomy == "disabled":
        return "disabled"
    return None if risk in ANALYST_APPROVAL_RISKS else "admin"


async def response_preview(
    repos: Repositories, responses: ResponseService, tenant_id: str, escalation_id: str, *, role: Optional[str]
) -> ResponsePreview:
    """The plan a ``true_positive`` decision on the escalation would produce, for a caller with ``role``."""
    escalation = await repos.escalations.get(tenant_id, escalation_id)
    alert = await repos.alerts.get(tenant_id, escalation.alert_id)
    tenant = await repos.tenants.get(tenant_id)
    policy = responses.policy(tenant.settings)
    snapshot = await responses.routing(tenant_id, tenant.settings)
    canonical = canonical_alert(alert)
    summary = alert.summary or {}
    ctx = plan_context(
        canonical,
        severity=alert.severity,
        evidence="analyst",
        analysis=summary.get("analysis") or {},
        triage=summary.get("triage") or {},
    )
    threat_type, candidates = build_candidates(ctx, alert.id)
    sample = alert.source_id == SAMPLE_SOURCE_ID
    actions: List[PreviewAction] = []
    for cand in candidates:
        spec = ACTION_CATALOG[cand.action_type]
        block = check_guardrails(cand.action_type, cand.target, policy)
        autonomy = policy.autonomy[spec.risk]
        route = snapshot.route(cand.action_type, sample=sample)
        actions.append(
            PreviewAction(
                action_type=cand.action_type,
                target=cand.target,
                description=spec.description,
                risk=spec.risk,
                reversible=spec.inverse is not None,
                inverse_action=spec.inverse,
                irreversible_note=spec.irreversible_note or None,
                connector=route.connector,
                connector_source=route.source,
                connector_live=route.live,
                connector_ready=route.problem is None,
                guardrail_verdict="blocked" if block else "passed",
                guardrail_code=block.code if block else None,
                guardrail_reason=block.explanation[:500] if block else None,
                autonomy=autonomy,
                without_preapproval=_outcome(block is not None, autonomy),
                can_preapprove=block is None and approval_allowed(spec.risk, role, autonomy),
                role_lock=_role_lock(spec.risk, autonomy),
                approval_entry=f"{cand.action_type}:{cand.target}",
            )
        )
    return ResponsePreview(
        escalation_id=escalation.id,
        alert_id=alert.id,
        generated_at=datetime.now(UTC),
        threat_type=threat_type,
        evidence=ctx.evidence,
        dry_run_forced=snapshot.dry_run_forced,
        actions=actions,
    )
