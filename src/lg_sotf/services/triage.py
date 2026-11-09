"""Bulk triage of escalations: claim N, close N as benign with one note, propose one suppression from N.

Claim and close report per-item results
----------------------------------------
Each escalation goes through exactly the call the single-item endpoint makes
(:meth:`ReviewService.claim <lg_sotf.services.review.ReviewService.claim>`,
:meth:`ReviewService.decide <lg_sotf.services.review.ReviewService.decide>`):
the same role checks, optimistic lock (the item's ``version``), tenant
transaction, audit entry, events and outbound notifications, one transaction
per escalation, in request order. An item that fails for a reason the single
endpoint answers with a client error (not found in the tenant, stale
version, already decided, claimed by another analyst, a role that may not)
is reported with that error and the other items still go through; items
already processed stay committed. Anything else (the database going away)
ends the request: the items before it are committed, and retrying is safe
because every item is guarded by its version. A batch holds at most
:data:`MAX_BULK` escalations, each at most once.

Proposing a suppression is all-or-nothing
-----------------------------------------
One *disabled* suppression rule is proposed from all the escalations, or
nothing is written. Every escalation must exist in the tenant and carry an
analyst's ``false_positive`` or ``benign_positive`` decision: a proposal
needs that evidence, as for the detection report's proposals. The rule
matches the escalations' alerts' verdict keys (the same detection on the
same entities with the same process, command line, service, user and
parent: :mod:`lg_sotf.domain.verdict_key`) and sources, bounded to the most severe of their severities
(``{"severity": {"in": [...]}}``), so it never covers a more severe alert.
It is created through :meth:`ReviewService.propose_suppression
<lg_sotf.services.review.ReviewService.propose_suppression>` (audited as
``suppression.suggested``, expires after 90 days, an admin enables it) and
an unexpired rule with the same match is returned instead of a new one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union
from uuid import UUID

from lg_sotf.db.errors import AlreadyInState, Conflict, InvalidTransition, InvalidValue, NotFound
from lg_sotf.db.repos import Escalation, Repositories, SuppressionRule
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.models.vocabulary import BENIGN_DECISIONS, SEVERITIES
from lg_sotf.services.review import DecisionResult, ReviewDenied, ReviewError, ReviewService

MAX_BULK = 50
MAX_RULE_NAME_CHARS = 200
# The errors a single-item claim or decision answers with a client error (4xx).
ITEM_ERRORS: Tuple[Type[Exception], ...] = (
    NotFound,
    Conflict,
    InvalidTransition,
    AlreadyInState,
    InvalidValue,
    ReviewError,
    ReviewDenied,
)


@dataclass
class ItemOutcome:
    """One escalation of a bulk request: what it became, or the error that stopped it."""

    escalation_id: str
    escalation: Optional[Escalation] = None
    decision: Optional[DecisionResult] = None
    error: Optional[Exception] = None


@dataclass
class SuppressionProposal:
    """``rule`` is ``None`` (and nothing was written) when ``unconfirmed`` lists escalations without a benign
    analyst decision."""

    rule: Optional[SuppressionRule] = None
    created: bool = False
    escalation_ids: List[str] = field(default_factory=list)
    unconfirmed: List[str] = field(default_factory=list)


def _check_batch(ids: Sequence[str]) -> None:
    if not 1 <= len(ids) <= MAX_BULK:
        raise ReviewError(f"a batch holds 1 to {MAX_BULK} escalations")
    if len(set(ids)) != len(ids):
        raise ReviewError("each escalation may appear only once")


async def bulk_claim(
    review: ReviewService,
    tenant_id: str,
    items: Sequence[Tuple[str, int]],
    *,
    user: Union[UUID, str],
    role: str,
) -> List[ItemOutcome]:
    """Claim each ``(escalation_id, version)`` for ``user``, as ``POST /escalations/{id}/claim`` does."""
    _check_batch([escalation_id for escalation_id, _ in items])
    out: List[ItemOutcome] = []
    for escalation_id, version in items:
        try:
            claimed = await review.claim(tenant_id, escalation_id, user, version, role=role)
        except ITEM_ERRORS as exc:
            out.append(ItemOutcome(escalation_id, error=exc))
            continue
        out.append(ItemOutcome(escalation_id, escalation=claimed))
    return out


async def bulk_close(
    review: ReviewService,
    tenant_id: str,
    items: Sequence[Tuple[str, int]],
    *,
    user: Union[UUID, str],
    role: str,
    decision: str,
    notes: str,
    suggest_suppression: Optional[bool] = None,
    delegated: bool = False,
) -> List[ItemOutcome]:
    """Decide each ``(escalation_id, version)`` as ``decision`` (benign only) with ``notes``, as
    ``POST /escalations/{id}/decision`` does. The caller enqueues each outcome's resume messages."""
    if decision not in BENIGN_DECISIONS:
        raise ReviewError("a bulk close records false_positive or benign_positive")
    _check_batch([escalation_id for escalation_id, _ in items])
    out: List[ItemOutcome] = []
    for escalation_id, version in items:
        try:
            result = await review.decide(
                tenant_id, escalation_id, user, role, decision, notes, [], version,
                suggest_suppression=suggest_suppression, delegated=delegated,
            )
        except ITEM_ERRORS as exc:
            out.append(ItemOutcome(escalation_id, error=exc))
            continue
        out.append(ItemOutcome(escalation_id, escalation=result.escalation, decision=result))
    return out


def _rule_name(rules: Sequence[str], count: int) -> str:
    distinct = sorted(set(rules))
    if len(distinct) == 1:
        name = f"Proposed from {count} benign escalation(s): {distinct[0]}"
    else:
        name = f"Proposed from {count} benign escalations of {len(distinct)} detections"
    return name[:MAX_RULE_NAME_CHARS]


async def propose_suppression(
    repos: Repositories,
    review: ReviewService,
    tenant_id: str,
    escalation_ids: Sequence[str],
    *,
    actor_type: str,
    actor_id: str,
    created_by: Optional[UUID],
    name: Optional[str] = None,
) -> SuppressionProposal:
    """One disabled rule from escalations an analyst decided benign (all-or-nothing; module docstring).

    :class:`~lg_sotf.db.errors.NotFound` when one is not in the tenant; ``unconfirmed`` (nothing written)
    when one has no benign decision.
    """
    ids = list(escalation_ids)
    _check_batch(ids)
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        escalations = [await repos.escalations.get(tenant_id, i, conn=conn) for i in ids]
        alerts = await repos.views.alert_digests(tenant_id, [e.alert_id for e in escalations], conn=conn)
        keys = {verdict_key_of(await repos.alerts.get(tenant_id, e.alert_id, conn=conn)) for e in escalations}
    unconfirmed = [e.id for e in escalations if e.status != "decided" or e.decision not in BENIGN_DECISIONS]
    if unconfirmed:
        return SuppressionProposal(unconfirmed=unconfirmed)
    if None in keys:
        raise ReviewError("an alert's event could not be read completely; no rule can match its behaviour")
    digests = [alerts[e.alert_id] for e in escalations if e.alert_id in alerts]
    rank = max(SEVERITIES.index(d.severity) for d in digests if d.severity in SEVERITIES) if digests else 0
    match: Dict[str, Any] = {
        "verdict_key": {"in": sorted(str(k) for k in keys)},
        "source_id": {"in": sorted({d.source_id for d in digests})},
        "severity": {"in": list(SEVERITIES[: rank + 1])},
    }
    rule, created = await review.propose_suppression(
        tenant_id,
        name=name or _rule_name([d.rule for d in digests], len(ids)),
        match=match,
        actor_type=actor_type,
        actor_id=actor_id,
        created_by=created_by,
        details={
            "source": "escalations",
            "escalation_ids": ids,
            "decisions": sorted({str(e.decision) for e in escalations}),
        },
        reuse_existing=True,
    )
    return SuppressionProposal(rule=rule, created=created, escalation_ids=ids)
