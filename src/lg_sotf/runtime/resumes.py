"""Re-deriving lost resume messages from PostgreSQL (contract section 1).

An analyst decision or approval commits first and its ``resume`` message is
enqueued afterwards. If that ``XADD`` fails, or Redis loses the entry
(``FLUSHALL``, failover to a replica without AOF, a purged dead letter), the
run would wait forever: the escalation already shows ``decided`` and nothing
else drives the run. The database has everything needed to rebuild the
message:

* a run ``waiting_human`` whose alert belongs to a **decided** escalation
  (its own alert or an attached one) gets the ``analyst_decision`` payload
  rebuilt from the escalation row;
* a run ``waiting_approval`` whose alert has actions ``approved`` (they run on
  the next pass of ``execute_actions``) or none ``awaiting_approval`` any more
  gets an empty ``approval`` payload, which lets the run execute what is
  approved and wait again for the rest. Only the run's own (workflow-owned)
  actions count: rollbacks and actions handed to the scheduler never keep a
  run waiting or resume it.

The scheduler's ``orphaned_runs`` job calls :func:`recover_lost_resumes` for
runs that have waited like that longer than a threshold, and ``lg-sotf
enqueue --resume`` does it for one alert. A duplicate of a message that was
only delayed is harmless: the worker refuses a resume for a run that is no
longer waiting. Suspended tenants are skipped (the worker would drop their
messages); their decisions are recovered after reactivation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.models.vocabulary import REVIEWER_ROLES
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.producer import WorkQueue

log = get_logger(__name__)

RECOVERY_ACTOR = "system:resume-recovery"

_STRANDED_WAITING_SQL = """
SELECT r.tenant_id, r.alert_id, r.status
FROM workflow_runs r
WHERE r.updated_at < now() - make_interval(secs => $1)
  AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id AND t.status = 'active')
  AND (
    (r.status = 'waiting_human' AND EXISTS (
        SELECT 1 FROM escalations e
        WHERE e.tenant_id = r.tenant_id AND e.status = 'decided'
          AND e.decided_at < now() - make_interval(secs => $1)
          AND (e.alert_id = r.alert_id OR r.alert_id = ANY(e.related_alert_ids))
          AND NOT EXISTS (
              SELECT 1 FROM escalations o
              WHERE o.tenant_id = r.tenant_id AND o.status IN ('open', 'claimed', 'expired')
                AND (o.alert_id = r.alert_id OR r.alert_id = ANY(o.related_alert_ids))
          )
    ))
    OR (r.status = 'waiting_approval' AND (
        EXISTS (SELECT 1 FROM response_actions a
                WHERE a.tenant_id = r.tenant_id AND a.alert_id = r.alert_id AND a.status = 'approved'
                  AND a.execution_owner = 'workflow'
                  AND COALESCE(a.approved_at, a.updated_at) < now() - make_interval(secs => $1))
        OR NOT EXISTS (SELECT 1 FROM response_actions a
                       WHERE a.tenant_id = r.tenant_id AND a.alert_id = r.alert_id
                         AND a.status = 'awaiting_approval' AND a.execution_owner = 'workflow')
    ))
  )
ORDER BY r.updated_at
LIMIT $2
"""


@dataclass(frozen=True)
class StrandedRun:
    tenant_id: str
    alert_id: str
    status: str


async def find_stranded_waiting_runs(db: Database, *, older_than_s: float, limit: int) -> List[StrandedRun]:
    """Waiting runs whose resume should already have happened (cross-tenant; owner role, ``system_tx``)."""
    async with db.system_tx(readonly=True) as conn:
        rows = await conn.fetch(_STRANDED_WAITING_SQL, float(older_than_s), limit)
    return [StrandedRun(r["tenant_id"], r["alert_id"], r["status"]) for r in rows]


async def rebuild_resume_payload(repos: Repositories, tenant_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
    """The resume payload a waiting run should have received, or ``None`` when it should keep waiting."""
    try:
        run = await repos.runs.get(tenant_id, alert_id)
    except NotFound:
        return None
    if run.status == "waiting_human":
        return await _decision_payload(repos, tenant_id, alert_id)
    if run.status == "waiting_approval":
        return await _approval_payload(repos, tenant_id, alert_id)
    return None


async def _decision_payload(repos: Repositories, tenant_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        row = await conn.fetchrow(
            """
            SELECT id FROM escalations
            WHERE tenant_id = $1 AND (alert_id = $2 OR $2 = ANY(related_alert_ids))
            ORDER BY created_at DESC LIMIT 1
            """,
            tenant_id,
            alert_id,
        )
    if row is None:
        return None
    escalation = await repos.escalations.get(tenant_id, row["id"])
    if escalation.status != "decided" or not escalation.decision or escalation.decided_by is None:
        return None
    role: Optional[str] = None
    try:
        user = await repos.users.get(tenant_id, escalation.decided_by)
        # The approver's authority as it is now: never more than when the decision was made
        # (decide() refused pre-approvals above the role), possibly less.
        role = user.role if user.is_active and user.role in REVIEWER_ROLES else None
    except NotFound:
        role = None
    own = alert_id == escalation.alert_id
    return {
        "type": "analyst_decision",
        "escalation_id": escalation.id,
        "decision": escalation.decision,
        "approved_actions": list(escalation.approved_actions) if own and role else [],
        "decided_by": str(escalation.decided_by),
        "notes": escalation.decision_notes or "",
        "approver_role": role,
    }


async def _approval_payload(repos: Repositories, tenant_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        counts = await conn.fetchrow(
            """
            SELECT count(*) FILTER (WHERE status = 'approved') AS approved,
                   count(*) FILTER (WHERE status = 'awaiting_approval') AS awaiting,
                   (array_agg(approved_by ORDER BY approved_at DESC NULLS LAST)
                        FILTER (WHERE approved_by IS NOT NULL))[1] AS approver
            FROM response_actions WHERE tenant_id = $1 AND alert_id = $2 AND execution_owner = 'workflow'
            """,
            tenant_id,
            alert_id,
        )
    if counts is None or (counts["approved"] == 0 and counts["awaiting"] > 0):
        return None
    # Named actions were already decided in the ledger; an empty payload makes execute_actions
    # run every approved action and wait again for anything still awaiting approval.
    return {
        "type": "approval",
        "approved_action_ids": [],
        "rejected_action_ids": [],
        "decided_by": str(counts["approver"] or RECOVERY_ACTOR)[:128],
        "reject_remaining": False,
    }


async def recover_lost_resumes(
    db: Database, repos: Repositories, queue: WorkQueue, *, older_than_s: float, limit: int = 100
) -> Tuple[int, int]:
    """Rebuild and enqueue resumes for stranded waiting runs; returns ``(enqueued, examined)``."""
    stranded = await find_stranded_waiting_runs(db, older_than_s=older_than_s, limit=limit)
    enqueued = 0
    for run in stranded:
        payload = await rebuild_resume_payload(repos, run.tenant_id, run.alert_id)
        if payload is None:
            continue
        await queue.enqueue_resume(run.tenant_id, run.alert_id, payload)
        # Touch the run so it is examined again only after another full threshold.
        async with db.tenant_tx(run.tenant_id) as conn:
            await conn.execute(
                "UPDATE workflow_runs SET updated_at = now() WHERE tenant_id = $1 AND alert_id = $2 AND status = $3",
                run.tenant_id,
                run.alert_id,
                run.status,
            )
        enqueued += 1
        log.warning("resume.recovered", tenant_id=run.tenant_id, alert_id=run.alert_id, kind=payload["type"])
    return enqueued, len(stranded)


__all__ = [
    "RECOVERY_ACTOR",
    "StrandedRun",
    "find_stranded_waiting_runs",
    "rebuild_resume_payload",
    "recover_lost_resumes",
]
