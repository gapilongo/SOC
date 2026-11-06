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
from lg_sotf.db.repos.runs import RunsRepo
from lg_sotf.models.vocabulary import REVIEWER_ROLES
from lg_sotf.observability.logging import get_logger
from lg_sotf.queue.producer import WorkQueue

log = get_logger(__name__)

RECOVERY_ACTOR = "system:resume-recovery"



@dataclass(frozen=True)
class StrandedRun:
    tenant_id: str
    alert_id: str
    status: str


async def find_stranded_waiting_runs(db: Database, *, older_than_s: float, limit: int) -> List[StrandedRun]:
    """Waiting runs whose resume should already have happened (cross-tenant; owner role, ``system_tx``)."""
    rows = await RunsRepo(db).find_stranded_waiting_all_tenants(older_than_s=older_than_s, limit=limit)
    return [StrandedRun(r.tenant_id, r.alert_id, r.status) for r in rows]


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
        escalation_id = await repos.escalations.latest_id_for_alert(tenant_id, alert_id, conn=conn)
    if escalation_id is None:
        return None
    escalation = await repos.escalations.get(tenant_id, escalation_id)
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
        counts = await repos.actions.workflow_approvals(tenant_id, alert_id, conn=conn)
    if counts.approved == 0 and counts.awaiting > 0:
        return None
    # Named actions were already decided in the ledger; an empty payload makes execute_actions
    # run every approved action and wait again for anything still awaiting approval.
    return {
        "type": "approval",
        "approved_action_ids": [],
        "rejected_action_ids": [],
        "decided_by": str(counts.approver or RECOVERY_ACTOR)[:128],
        "reject_remaining": False,
    }


async def recover_lost_resumes(
    db: Database, repos: Repositories, queue: WorkQueue, *, older_than_s: float, limit: int = 100
) -> Tuple[int, int]:
    """Rebuild and enqueue resumes for stranded waiting runs; returns ``(enqueued, examined)``."""
    stranded = await find_stranded_waiting_runs(db, older_than_s=older_than_s, limit=limit)
    runs = RunsRepo(db)
    enqueued = 0
    for run in stranded:
        payload = await rebuild_resume_payload(repos, run.tenant_id, run.alert_id)
        if payload is None:
            continue
        await queue.enqueue_resume(run.tenant_id, run.alert_id, payload)
        # Touch the run so it is examined again only after another full threshold.
        await runs.touch(run.tenant_id, run.alert_id, status=run.status)
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
