"""What the console shows next to a response action: its guardrail verdict, blast radius and reversibility.

Computed from the ledger row, the action catalog and the tenant's current
response policy; nothing here writes.

Guardrail verdict (``guardrail``):

* an action **awaiting approval** is checked now against the tenant's
  current policy with the same guardrails execution applies
  (:func:`~lg_sotf.services.response.check_guardrails`; rules 0-6 of that
  module). ``passed`` means approving it would not be refused by a
  guardrail today (the hourly caps are checked again at execution; see
  ``blast_radius``); ``blocked`` gives the guardrail code and why.
  ``approval_reason`` is the planner's code for why a human must approve
  (``admin_approval_required``, ``llm_only_evidence``,
  ``target_not_corroborated``, ``hourly_cap_reached``,
  ``blast_radius_exceeded``; absent when the tenant's autonomy policy asks
  for approval) and ``reason`` the planner's explanation;
* a **blocked** action reports the guardrail recorded on the ledger
  (``evaluated: "recorded"``);
* other statuses have no verdict (``None``).

Blast radius (``blast_radius``): the kind of target the action changes and,
for host-local actions, the hosts it is scoped to. For an action awaiting
approval it also gives the hourly limits it will be checked against when it
executes: the per-type limit (the platform's "blast radius" limit) and the
tenant-wide cap, with how many actions started executing in the last hour.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence, Tuple
from uuid import UUID

from lg_sotf.db.repos import Repositories, ResponseAction
from lg_sotf.domain.actions import ACTION_CATALOG, GUARDRAIL_REASONS
from lg_sotf.services.response import ResponsePolicy, check_guardrails
from lg_sotf.settings import Settings

MAX_REASON_CHARS = 500


@dataclass(frozen=True)
class GuardrailView:
    verdict: Literal["passed", "blocked"]
    evaluated: Literal["now", "recorded"]
    code: Optional[str] = None
    reason: Optional[str] = None
    approval_reason: Optional[str] = None


@dataclass(frozen=True)
class BlastRadiusView:
    target_kind: Optional[str]
    scope_hosts: List[str] = field(default_factory=list)
    hourly_limit: Optional[int] = None
    executed_last_hour: Optional[int] = None
    tenant_hourly_cap: Optional[int] = None
    tenant_executed_last_hour: Optional[int] = None


@dataclass(frozen=True)
class ActionView:
    guardrail: Optional[GuardrailView]
    blast_radius: BlastRadiusView
    reversible: Optional[bool]
    irreversible_note: Optional[str]


@dataclass(frozen=True)
class LiveLimits:
    """The tenant's current policy and last-hour execution counts (only read when an action is pending)."""

    policy: ResponsePolicy
    used_total: int
    used_by_type: Mapping[str, int]


def _text(value: Any) -> Optional[str]:
    return value[:MAX_REASON_CHARS] if isinstance(value, str) and value else None


def _scope_hosts(params: Mapping[str, Any]) -> List[str]:
    scope = params.get("scope")
    hosts = scope.get("hosts") if isinstance(scope, Mapping) else None
    return [str(h) for h in hosts if isinstance(h, str)] if isinstance(hosts, list) else []


def _recorded_block(action: ResponseAction) -> GuardrailView:
    code = action.blocked_reason
    result = action.result or {}
    reason = _text(result.get("explanation")) if result.get("guardrail") else None
    if reason is None:
        explanation = _text(action.params.get("explanation"))
        reason = explanation if explanation and explanation.startswith("blocked") else None
    if reason is None and code:
        reason = GUARDRAIL_REASONS.get(code, code)
    return GuardrailView("blocked", "recorded", code=code, reason=reason)


def _current(action: ResponseAction, live: LiveLimits) -> GuardrailView:
    spec = ACTION_CATALOG.get(action.action_type)
    restorative = bool(spec is not None and spec.restorative and action.rollback_of is not None)
    block = check_guardrails(action.action_type, action.target, live.policy, restorative=restorative)
    if block is not None:
        return GuardrailView("blocked", "now", code=block.code, reason=_text(block.explanation))
    return GuardrailView(
        "passed",
        "now",
        reason=_text(action.params.get("explanation")),
        approval_reason=_text(action.params.get("approval_reason")),
    )


def action_view(action: ResponseAction, live: Optional[LiveLimits]) -> ActionView:
    """The view of one action; ``live`` is required for an action awaiting approval to get a verdict."""
    spec = ACTION_CATALOG.get(action.action_type)
    pending = action.status == "awaiting_approval" and live is not None
    guardrail: Optional[GuardrailView] = None
    if action.status == "blocked":
        guardrail = _recorded_block(action)
    elif pending and live is not None:
        guardrail = _current(action, live)
    radius = BlastRadiusView(target_kind=spec.target_kind if spec else None, scope_hosts=_scope_hosts(action.params))
    if pending and live is not None:
        radius = BlastRadiusView(
            target_kind=radius.target_kind,
            scope_hosts=radius.scope_hosts,
            hourly_limit=live.policy.blast_radius.get(action.action_type),
            executed_last_hour=int(live.used_by_type.get(action.action_type, 0)),
            tenant_hourly_cap=live.policy.max_actions_per_hour,
            tenant_executed_last_hour=live.used_total,
        )
    return ActionView(
        guardrail=guardrail,
        blast_radius=radius,
        reversible=(spec.inverse is not None) if spec else None,
        irreversible_note=(spec.irreversible_note or None) if spec else None,
    )


async def action_views(
    repos: Repositories, settings: Settings, tenant_id: str, actions: Sequence[ResponseAction]
) -> Dict[UUID, ActionView]:
    """:func:`action_view` of every action; the policy and hourly counts are read once, when one is pending."""
    live: Optional[LiveLimits] = None
    if any(a.status == "awaiting_approval" for a in actions):
        async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            tenant = await repos.tenants.get(tenant_id, conn=conn)
            counts: Tuple[int, Dict[str, int]] = await repos.actions.executed_counts(tenant_id, conn=conn)
        live = LiveLimits(ResponsePolicy.resolve(tenant.settings, settings), counts[0], counts[1])
    return {a.id: action_view(a, live) for a in actions}
