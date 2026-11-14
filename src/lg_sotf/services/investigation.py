"""The investigation view of one alert (PRD-2.8a): reads the stored rows, the domain assembles them.

Read-only. Everything is read in one tenant transaction (RLS) except the
proposed response, which reuses the response preview and the action views
(their own read-only transactions). No model is called and nothing is
written; the shape and the plain sentences are
:mod:`lg_sotf.domain.investigation`.

The trace store keeps hashes, not inputs, so a lookup recorded in the
alert's summary is matched to its trace step by hash: the input hash when
the stored target is the one that was sent, else the output hash, keeping
the order the lookups ran in and preferring the newest analysis.

An alert that waits for its blind-audit label shows nothing of the AI's
side, as on every other read.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from lg_sotf.db import Connection
from lg_sotf.db.repos import Alert, AlertEvent, Escalation, Repositories, ResponseAction, TraceStep
from lg_sotf.domain import closure
from lg_sotf.domain.actions import ACTION_CATALOG
from lg_sotf.domain.blind_audit import MIN_ESTIMATE_SAMPLES
from lg_sotf.domain.investigation import (
    AlertFacts,
    EscalationFacts,
    EventFacts,
    Investigation,
    InvestigationFacts,
    Lookup,
    TraceRef,
    TrackCounts,
    assemble,
    outcome_category,
)
from lg_sotf.domain.investigation.evidence import lookups_of
from lg_sotf.domain.investigation.facts import MAX_ACTION_TARGET_CHARS, MAX_STEPS, bounded
from lg_sotf.domain.investigation.model import (
    OutcomeCategory,
    ProposedAction,
    ProposedActionGuardrail,
    ProposedResponse,
)
from lg_sotf.domain.investigation.outcome import AUDIT_CLOSE_REASONS, EVIDENCE_CLOSE_REASONS, LIKELY_MALICIOUS_CODES
from lg_sotf.llm.trace import content_hash, tool_input_hash
from lg_sotf.services.action_views import ActionView, action_views
from lg_sotf.services.plan_context import canonical_alert
from lg_sotf.services.response import ResponseService
from lg_sotf.services.response_preview import PreviewAction, response_preview
from lg_sotf.settings import Settings

#: The track record counts people's verdicts of the last 90 days and gives a rate from 30 of them on.
TRACK_WINDOW_DAYS = 90
MIN_TRACK_SAMPLES = MIN_ESTIMATE_SAMPLES
MAX_TRACE_STEPS = 1_000
MAX_ACTIONS = 50
MAX_REASON_CHARS = 500


def alert_view(alert: Alert) -> Dict[str, Any]:
    """The workflow's view of the stored alert, with the safety net's ``reopened`` marker taken from the
    summary (never from the event), as a run's initial state has it."""
    view = canonical_alert(alert)
    view.pop(closure.REOPENED, None)
    if alert.summary.get(closure.REOPENED):
        view[closure.REOPENED] = {"reason": "reopened"}
    return view


def _alert(alert: Alert) -> AlertFacts:
    return AlertFacts(
        id=alert.id, tenant_id=alert.tenant_id, status=alert.status, severity=alert.severity,
        summary=alert.summary or {}, view=alert_view(alert), ingested_at=alert.ingested_at, closed_at=alert.closed_at,
    )


def _escalation(escalation: Optional[Escalation]) -> Optional[EscalationFacts]:
    if escalation is None:
        return None
    return EscalationFacts(
        id=escalation.id, alert_id=escalation.alert_id, status=escalation.status, summary=escalation.summary or {},
        decision=escalation.decision,
    )


def _events(events: Sequence[AlertEvent]) -> List[EventFacts]:
    return [EventFacts(ts=e.ts, event_type=e.event_type, node=e.node, data=e.data or {}) for e in events]


def _ref(step: TraceStep) -> TraceRef:
    return TraceRef(
        tool=step.tool or "", input_hash=step.input_hash, started_at=step.started_at, outcome=step.outcome,
        output_hash=step.output_hash, error_type=step.error_type,
    )


def _input_hash(lookup: Lookup) -> str:
    """The input hash the analysis recorded for this lookup, when the stored target is the value it sent."""
    request: Dict[str, Any] = {"kind": lookup.kind, "value": lookup.target}
    if lookup.tool != "history":
        request["providers"] = sorted(str(r.get("provider")) for r in lookup.results)
    return tool_input_hash(lookup.tool, request)


def _newest(
    free: Mapping[int, TraceStep], tool: str, attribute: str, wanted: str, after: int = -1, before: Optional[int] = None
) -> Optional[int]:
    """The position of the newest unmatched step of ``tool`` whose hash ``attribute`` is ``wanted``, between two
    positions (exclusive)."""
    for position in sorted(free, reverse=True):
        inside = position > after and (before is None or position < before)
        if inside and free[position].tool == tool and getattr(free[position], attribute) == wanted:
            return position
    return None


def match_traces(lookups: Sequence[Lookup], steps: Sequence[TraceStep]) -> Tuple[List[Lookup], List[TraceRef]]:
    """Each lookup with its trace step (where the store has it), and the tool calls of the same analysis that
    raised.

    First by input hash, the newest step winning (an alert analysed twice keeps the steps of both runs). Then,
    for a lookup whose stored target is not the value that was sent (redacted or cut), by output hash, between
    the steps of the lookups that ran before and after it, so equal outputs keep the order they came in.
    """
    tools = {i: s for i, s in enumerate(steps) if s.kind == "tool" and s.tool}
    free = dict(tools)
    hits: Dict[int, int] = {}
    for index in reversed(range(len(lookups))):
        hit = _newest(free, lookups[index].tool, "input_hash", _input_hash(lookups[index]))
        if hit is not None:
            hits[index] = hit
            del free[hit]
    for index in reversed(range(len(lookups))):
        if index in hits:
            continue
        after = max((step for at, step in hits.items() if at < index), default=-1)
        before = min((step for at, step in hits.items() if at > index), default=None)
        hit = _newest(free, lookups[index].tool, "output_hash", content_hash(lookups[index].output), after, before)
        if hit is not None:
            hits[index] = hit
            del free[hit]
    with_trace = [
        Lookup(x.tool, x.kind, x.target, x.results, x.output, x.checked_at, _ref(tools[hits[i]]) if i in hits else None)
        for i, x in enumerate(lookups)
    ]
    if hits:
        start = min(hits.values())
    else:  # no lookup returned: the calls that raised after the last one that did
        start = max((i for i, s in tools.items() if s.outcome != "error"), default=-1) + 1
    failed = [_ref(s) for i, s in tools.items() if i >= start and i in free and s.outcome == "error"]
    return with_trace, failed


def decided_tier(events: Sequence[AlertEvent], tenant_settings: Optional[Mapping[str, Any]]) -> str:
    """The tenant's model-led closure tier as the last ``decide`` step recorded it, else as it is now."""
    for event in reversed(events):
        if event.event_type == "node.completed" and event.node == "decide":
            tier = (event.data or {}).get("autonomy_tier")
            if tier in closure.AUTONOMY_TIERS:
                return str(tier)
    return closure.autonomy_tier(tenant_settings)


async def _track(
    repos: Repositories, tenant_id: str, category: Optional[OutcomeCategory], now: datetime, conn: Connection
) -> Optional[TrackCounts]:
    if category is None:
        return None
    start = now - timedelta(days=TRACK_WINDOW_DAYS)
    if category in ("ai_closed_audit", "ai_closed_evidence"):
        reasons = AUDIT_CLOSE_REASONS if category == "ai_closed_audit" else EVIDENCE_CLOSE_REASONS
        total, confirmed = await repos.reports.audited_closes(tenant_id, start, now, close_reasons=reasons, conn=conn)
    else:
        total, confirmed = await repos.reports.decided_outcomes(
            tenant_id, start, now, likely_malicious=category == "needs_decision",
            malicious_codes=LIKELY_MALICIOUS_CODES, conn=conn,
        )
    return TrackCounts(total=total, confirmed=confirmed, window_days=TRACK_WINDOW_DAYS, min_samples=MIN_TRACK_SAMPLES)


def _planned(action: ResponseAction, view: Optional[ActionView]) -> ProposedAction:
    spec = ACTION_CATALOG.get(action.action_type)
    guardrail = view.guardrail if view is not None else None
    return ProposedAction(
        action_id=action.id,
        action_type=action.action_type,
        target=bounded(action.target, MAX_ACTION_TARGET_CHARS),
        description=spec.description if spec else None,
        risk=action.risk_level,
        reversible=view.reversible if view is not None else None,
        inverse_action=spec.inverse if spec else None,
        irreversible_note=view.irreversible_note if view is not None else None,
        status=action.status,
        guardrail=(
            ProposedActionGuardrail(verdict=guardrail.verdict, code=guardrail.code, reason=guardrail.reason)
            if guardrail is not None
            else None
        ),
    )


def _previewed(action: PreviewAction) -> ProposedAction:
    reason = action.guardrail_reason
    return ProposedAction(
        action_type=action.action_type,
        target=bounded(action.target, MAX_ACTION_TARGET_CHARS),
        description=action.description,
        risk=action.risk,
        reversible=action.reversible,
        inverse_action=action.inverse_action,
        irreversible_note=action.irreversible_note,
        guardrail=ProposedActionGuardrail(
            verdict=action.guardrail_verdict, code=action.guardrail_code,
            reason=bounded(reason, MAX_REASON_CHARS) if reason else None,
        ),
        without_preapproval=action.without_preapproval,
        can_preapprove=action.can_preapprove,
        role_lock=action.role_lock,
        approval_entry=bounded(action.approval_entry, MAX_ACTION_TARGET_CHARS + 64),
    )


async def proposed_response(
    repos: Repositories, responses: ResponseService, settings: Settings, alert: Alert,
    escalation: Optional[Escalation], actions: Sequence[ResponseAction], *, role: Optional[str],
) -> ProposedResponse:
    """The actions on the ledger when the workflow planned a response (oldest first); else, while the alert's
    own escalation waits for a decision, the preview of what a ``true_positive`` would propose; else nothing."""
    if actions:
        views = await action_views(repos, settings, alert.tenant_id, actions)
        ordered = sorted(actions, key=lambda a: (a.created_at, str(a.id)))
        return ProposedResponse(source="plan", actions=[_planned(a, views.get(a.id)) for a in ordered])
    if escalation is not None and escalation.alert_id == alert.id and escalation.is_active:
        preview = await response_preview(repos, responses, alert.tenant_id, escalation.id, role=role)
        return ProposedResponse(source="preview", actions=[_previewed(a) for a in preview.actions[:MAX_ACTIONS]])
    return ProposedResponse(source="none")


async def investigation(
    repos: Repositories, responses: ResponseService, settings: Settings, tenant_id: str, alert_id: str, *,
    role: Optional[str], now: Optional[datetime] = None,
) -> Investigation:
    """The investigation view of the tenant's alert (``NotFound`` when it is not the tenant's).

    ``role`` is the caller's: the response preview says what that role may pre-approve.
    """
    now = now or datetime.now(UTC)
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        events = (await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=MAX_STEPS, conn=conn)).items
        if await repos.blind_audit.pending_alert_ids(tenant_id, [alert_id], conn=conn):
            return assemble(InvestigationFacts(alert=_alert(alert), now=now, events=_events(events), hidden=True))
        newest = await repos.escalations.list(tenant_id, alert_id=alert_id, include_attached=True, limit=1, conn=conn)
        escalation = newest.items[0] if newest.items else None
        trace = await repos.investigation_steps.list_for_alert(tenant_id, alert_id, limit=MAX_TRACE_STEPS, conn=conn)
        tenant = await repos.tenants.get(tenant_id, conn=conn)
        actions = (await repos.actions.list(tenant_id, alert_id=alert_id, limit=MAX_ACTIONS, conn=conn)).items
        facts, escalated = _alert(alert), _escalation(escalation)
        event_facts = _events(events)
        track = await _track(repos, tenant_id, outcome_category(facts, escalated, event_facts), now, conn)
    lookups, failed = match_traces(lookups_of(facts.summary), trace)
    return assemble(
        InvestigationFacts(
            alert=facts,
            now=now,
            escalation=escalated,
            events=event_facts,
            lookups=lookups,
            failed_tools=failed,
            tier=decided_tier(events, tenant.settings),
            response=await proposed_response(repos, responses, settings, alert, escalation, actions, role=role),
            track=track,
        )
    )
