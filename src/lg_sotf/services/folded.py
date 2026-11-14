"""Alerts decision policy v3 folded into a related threat's case (lg_sotf.core.retro_reopen): the case decision
settles them.

A folded alert was closed by the models, then reopened and attached to the
threat's open escalation as a related alert, with ``waiting_human`` status
and **no run waiting** (its run had completed). The analyst's decision on the
case therefore cannot reach it through a workflow resume: the review service
applies it in the decision's own transaction (:func:`settle_folded`), and the
worker applies it again, idempotently, if a resume message for it arrives.
``true_positive`` closes it ``malicious``, a benign decision ``benign``;
``needs_more_info`` leaves it waiting, and the threat's next case takes it
over (:func:`lg_sotf.core.retro_reopen.refold`).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Set

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db import Connection
from lg_sotf.db.repos import Repositories
from lg_sotf.models.vocabulary import BENIGN_DECISIONS

#: How a reopened alert came back: folded into the threat's open case, or queued for its own review run.
FOLDED, REQUEUED = "folded", "requeued"
SETTLED_ACTION = "alert.folded_settled"


def folded_into(alert: Any) -> Optional[str]:
    """The escalation a folded, still waiting alert belongs to, else ``None``."""
    summary = alert.summary if isinstance(alert.summary, Mapping) else {}
    marker = summary.get("reopened")
    if alert.status != "waiting_human" or not isinstance(marker, Mapping) or marker.get("mode") != FOLDED:
        return None
    case = summary.get("escalation_id")
    return case if isinstance(case, str) else None


async def settle_folded(
    repos: Repositories, tenant_id: str, alert_id: str, *, escalation_id: str, decision: str, decided_by: str,
    conn: Optional[Connection] = None,
) -> bool:
    """Apply the decision on ``escalation_id`` to a folded alert; whether the alert is a folded one (into any case).

    Only a decision on the alert's own case changes it. Idempotent: a settled alert is no longer folded.
    """
    if conn is None:
        async with repos.db.tenant_tx(tenant_id) as tx:
            return await settle_folded(repos, tenant_id, alert_id, escalation_id=escalation_id, decision=decision,
                                       decided_by=decided_by, conn=tx)
    alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
    case = folded_into(alert)
    if case is None:
        return False
    if case != escalation_id:
        return True  # folded into another case: that case's decision settles it
    if decision == "true_positive":
        disposition = "malicious"
    elif decision in BENIGN_DECISIONS:
        disposition = "benign"
    else:
        return True  # needs_more_info: it stays with the threat, whose next case takes it over
    await repos.alerts.update_status(tenant_id, alert_id, "processing", conn=conn)
    await repos.alerts.update(
        tenant_id, alert_id, disposition=disposition,
        summary={"close_reason": f"analyst:{decision}", "analyst_decision": decision}, conn=conn,
    )
    await repos.alerts.update_status(tenant_id, alert_id, "closed", conn=conn)
    details = {"decision": decision, "escalation_id": escalation_id, "disposition": disposition}
    await repos.alert_events.append(
        tenant_id, alert_id, "analyst.decision", node="await_analyst", actor_type="user", actor_id=decided_by,
        data={**details, "folded": True}, conn=conn,
    )
    await AuditLogger(repos).record(
        tenant_id, SETTLED_ACTION, "alert", alert_id, actor_type="user", actor_id=decided_by, details=details,
        conn=conn,
    )
    return True


async def settle_case(
    repos: Repositories, tenant_id: str, escalation: Any, decision: str, decided_by: Any, conn: Connection
) -> Set[str]:
    """In the decision's transaction: settle every alert folded into the decided case; their ids (they have no run
    waiting, so the review service sends them no resume message)."""
    return {
        alert_id for alert_id in escalation.related_alert_ids
        if await settle_folded(repos, tenant_id, alert_id, escalation_id=escalation.id, decision=decision,
                               decided_by=str(decided_by), conn=conn)
    }
