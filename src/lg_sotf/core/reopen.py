"""A person reopens an alert the AI closed, or flags the close as wrong (PRD-2.9a).

Both apply to an alert the models closed alone (close reason ``ai_closed:*``),
the same alerts the safety net reopens, and through the same function
(:func:`lg_sotf.core.retro_reopen.reopen_one`), so a reopened alert is one
thing whoever reopened it:

* its case is still open: the alert is **folded** into it and waits for a
  person there (``waiting_human``). No run starts; the decision on the case
  settles it (:mod:`lg_sotf.services.folded`);
* no open case holds it: it is **requeued** for a new run. The marker
  ``reopened`` on its summary is the closing policy's ``reopened`` blocker
  (:func:`lg_sotf.domain.closure.model_close_blockers`): the models never
  close it on their word again, and the same marker holds every other close
  without a person (#461, :func:`lg_sotf.domain.closure.reopened_code`): no
  suppression rule or cached verdict at the gate, not the first assessment,
  not approved evidence. That run sends the alert to an analyst.

**Reopen** is "a person wants to look at it". **Flag** is "the AI was wrong
to close it": the alert also keeps ``flagged`` (who, when) on its summary and
gets an ``alert.flagged`` event and audit entry, which the blind-audit and
accuracy reports count as a disagreement with the AI's close. When no open
case holds the flagged alert, the caller also treats the flag as a person's
confirmation of that alert for the safety net (``api.routers.alerts``): the
other alerts the models closed on its host or user are reopened, except a
sample that waits for its blind-audit label. Inside an open case a flag
confirms nothing: nobody has judged the case's threat.

The person's reason is data. It is stored on the timeline event and in the
audit entry, cut to :data:`MAX_REASON_CHARS`, and never on the alert's
summary: the workflow reads the summary, and of the marker only the fixed
code (:data:`ANALYST_REOPEN`, :data:`ANALYST_FLAG`). No model is shown it.

Everything is written in one tenant transaction with its audit entries.
Enqueueing the new run and publishing the change happen after the commit, in
the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.retro_reopen import PERSON_TEXT, reopen_one
from lg_sotf.db import Connection
from lg_sotf.db.repos import Alert, Escalation, Repositories
from lg_sotf.domain.case.alerts import FLAGGED_EVENT
from lg_sotf.domain.case.facts import MAX_REASON_CHARS
from lg_sotf.domain.closure import ANALYST_FLAG, ANALYST_REOPEN
from lg_sotf.services.folded import FOLDED, closed_by_models

#: The audit action and the timeline event of a flag. The alert's summary keeps ``flagged``: ``{"by": user id,
#: "at": ISO time}``.
FLAG_ACTION = FLAGGED_EVENT

__all__ = ["FLAG_ACTION", "MAX_REASON_CHARS", "NotReopenable", "Reopened", "reopen"]


class NotReopenable(ValueError):
    """The alert cannot be reopened or flagged as it stands; ``code`` says why."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Reopened:
    alert_id: str
    #: ``folded`` (it waits in ``case_id``) or ``requeued`` (a new run reviews it).
    mode: str
    #: The open case the alert waits in; ``None`` when it was requeued.
    case_id: Optional[str]


async def _case(
    repos: Repositories, tenant_id: str, alert_id: str, case_id: Optional[str], conn: Connection
) -> Optional[Escalation]:
    """The case the alert returns to: the one named, which must hold it (``NotFound`` when it is not the
    tenant's), else the oldest open case it is attached to, if any."""
    if case_id is None:
        return await repos.escalations.find_attached_to(tenant_id, alert_id, conn=conn)
    case = await repos.escalations.get(tenant_id, case_id, conn=conn)
    if alert_id not in case.related_alert_ids:
        raise NotReopenable("not_in_case", "the alert is not one of this case's alerts")
    return case


async def _flag(
    repos: Repositories, conn: Connection, alert: Alert, actor: Actor, reason: str, case: Optional[Escalation], now: datetime
) -> None:
    """Record the disagreement with the AI's close, before the close reason changes."""
    details = {
        "note": reason, "close_reason": alert.summary.get("close_reason"), "disposition": alert.disposition,
        "escalation_id": case.id if case is not None else None,
    }
    await repos.alerts.update(
        alert.tenant_id, alert.id, summary={"flagged": {"by": actor.id, "at": now.isoformat()}}, conn=conn
    )
    await repos.alert_events.append(
        alert.tenant_id, alert.id, FLAG_ACTION, actor_type=actor.type, actor_id=actor.id, data=dict(details), conn=conn
    )
    await AuditLogger(repos).record(
        alert.tenant_id, FLAG_ACTION, "alert", alert.id, actor_type=actor.type, actor_id=actor.id,
        details=dict(details), unlogged=PERSON_TEXT, conn=conn,
    )


async def reopen(
    repos: Repositories,
    tenant_id: str,
    alert_id: str,
    *,
    actor: Actor,
    reason: str,
    flag: bool = False,
    case_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Reopened:
    """Reopen the alert for a person (``flag``: and record that the AI was wrong to close it).

    ``NotFound`` when the alert, or the case named, is not the tenant's. :class:`NotReopenable` when the alert
    waits for its blind-audit label (reopening it would say what the AI did), when the models' close does not
    stand (it is open, a person or a rule closed it, or it already waits for a decision), or when the case
    named does not hold it. Audited ``alert.reopened`` (and ``alert.flagged``) with the person and the reason.
    """
    now = now or datetime.now(UTC)
    reason = reason[:MAX_REASON_CHARS]
    async with repos.db.tenant_tx(tenant_id) as conn:
        alert = await repos.alerts.get_locked(tenant_id, alert_id, conn=conn)
        if await repos.blind_audit.pending_alert_ids(tenant_id, [alert_id], conn=conn):
            raise NotReopenable("hidden_for_blind_audit", "the alert waits for its blind-audit label; label it first")
        if not closed_by_models(alert):
            raise NotReopenable("not_ai_closed", "only an alert the AI closed on the model's word can be reopened")
        if await repos.escalations.get_active_for_alert(tenant_id, alert_id, conn=conn) is not None:
            raise NotReopenable("already_with_a_person", "the alert already waits for a decision in a case of its own")
        case = await _case(repos, tenant_id, alert_id, case_id, conn)
        if flag:
            await _flag(repos, conn, alert, actor, reason, case, now)
        mode = await reopen_one(
            repos, tenant_id, alert_id, actor=actor, escalation_id=case.id if case is not None else None,
            threat_id=case.alert_id if case is not None else None,
            reason=ANALYST_FLAG if flag else ANALYST_REOPEN, recorded={"note": reason}, conn=conn,
        )
    assert mode is not None  # the row is locked and the models' close stood above
    return Reopened(alert_id, mode, case.id if case is not None and mode == FOLDED else None)
