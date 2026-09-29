"""An escalation the scheduler expired (SLA breached at L3) can still be decided, and the waiting run resumes.

The scheduler leaves the alert ``waiting_human`` when it expires an L3
escalation; the run waits on that escalation's interrupt. A decision the
review service refused at this point would strand the alert for good.
"""

from __future__ import annotations

from typing import Any, Callable, Dict
from uuid import uuid4

import pytest

from lg_sotf.db.errors import Conflict
from lg_sotf.db.repos import Repositories
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.services.review import ReviewService
from tests.integration.db._support import TENANT_A
from tests.integration.e2e.conftest import Stack, eventually, running

pytestmark = pytest.mark.integration

CRITICAL: Dict[str, Any] = {
    "source_alert_id": "sla-001",
    "title": "Credential dumping on domain controller",
    "severity": "critical",
    "occurred_at": "2026-09-29T07:00:00Z",
    "entities": {"hosts": ["dc-01"], "processes": ["procdump.exe"]},
}


async def _expire(stack: Stack, scheduler: Scheduler, escalation_id: str) -> None:
    """Breach the SLA until the scheduler has walked the escalation up to L3 and expired it."""
    for _ in range(4):
        esc = await stack.repos.escalations.get(TENANT_A, escalation_id)
        if esc.status == "expired":
            return
        async with stack.db.system_tx() as conn:
            await conn.execute("UPDATE escalations SET sla_deadline = now() - interval '1 minute' WHERE id = $1", escalation_id)
        await scheduler.sweep_sla()
    raise AssertionError("the scheduler did not expire the escalation")


async def test_a_late_decision_on_an_expired_escalation_resumes_the_run(
    stack_factory: Callable[..., Stack], repos: Repositories
) -> None:
    stack = stack_factory()
    analyst = (await repos.users.create(TENANT_A, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")).id
    review = ReviewService(repos, stack.settings, stack.events)
    scheduler = Scheduler(stack.settings, stack.db, stack.redis, lambda: stack.ingestion, stack.queue, stack.events)
    result = await stack.ingest(TENANT_A, "api", [CRITICAL])
    alert_id = result.inserted[0].alert_id
    await stack.dispatch(TENANT_A, result)

    async with running(stack.worker(await stack.engine())):
        await eventually(lambda: _run_is(stack, alert_id, "waiting_human"))
        esc = await repos.escalations.get_active_for_alert(TENANT_A, alert_id)
        assert esc is not None
        await _expire(stack, scheduler, esc.id)
        expired = await repos.escalations.get(TENANT_A, esc.id)
        assert (expired.status, expired.level) == ("expired", "L3")
        assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"

        # A stale version is still a conflict; the current one records the late decision.
        with pytest.raises(Conflict):
            await review.decide(TENANT_A, esc.id, analyst, "analyst", "false_positive", None, [], expired.version - 1)
        decided = await review.decide(
            TENANT_A, esc.id, analyst, "analyst", "false_positive", "authorised admin tool", [], expired.version
        )
        assert decided.escalation.status == "decided" and decided.escalation.decision == "false_positive"
        assert [r.alert_id for r in decided] == [alert_id]
        for rid, payload in decided:
            await stack.queue.enqueue_resume(TENANT_A, rid, payload)
        await eventually(lambda: _run_is(stack, alert_id, "completed"))

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition, alert.summary["close_reason"]) == ("closed", "benign", "analyst:false_positive")
    audit = [e for e in (await repos.audit.list(TENANT_A, resource_id=esc.id)).items if e.action == "escalation.decided"]
    assert len(audit) == 1 and audit[0].details["after_sla_expiry"] is True
    assert (await repos.audit.verify_chain(TENANT_A)).ok


async def _run_is(stack: Stack, alert_id: str, status: str) -> bool:
    return await stack.run_status(TENANT_A, alert_id) == status
