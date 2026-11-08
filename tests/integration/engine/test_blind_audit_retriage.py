"""PRD-10.2 review F5: an analyst's decision on a blind-audit escalation reaches the alert (re-triage).

An auto-closed alert is labelled malicious in a blind audit, which opens an escalation. Deciding it on
the closed alert re-queues the alert through the reprocess path; the new run starts at the analyst's
decision (it waits on that escalation), so it sets the disposition and ``analyst_decision`` and plans a
response like any other analyst-confirmed run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core.state import AlertSummary
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.services.blind_audit import BlindAuditService
from lg_sotf.services.escalation import EscalationService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.engine._support import analyst, undeclared_keys

pytestmark = pytest.mark.integration


async def _closed_and_labelled(
    engine: WorkflowEngine, repos: Repositories, settings: Settings, label_actor: str
) -> tuple[str, str]:
    alert_id = await make_alert(
        repos, TENANT_A, title="Scheduled backup maintenance test job", severity="low",
        normalized={"rule_name": "scheduled-backup-maintenance-test", "entities": {"hosts": ["backup-01"]}},
    )
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    first = await engine.run(TENANT_A, alert_id)
    assert (first.status, first.alert_status) == ("completed", "closed")
    async with repos.db.system_tx() as conn:  # what the worker records after a completed run
        await conn.execute(
            "UPDATE workflow_runs SET status = 'completed' WHERE tenant_id = $1 AND alert_id = $2", TENANT_A, alert_id
        )
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition == "benign" and alert.closed_at is not None
    await repos.blind_audit.create_run(
        TENANT_A, since=alert.closed_at - timedelta(minutes=1), until=datetime.now(UTC), seed=1, sample_rate=None,
        min_sample=0, fixed_size=1, frame_size=1, items=[(alert_id, 1, "benign")], trigger="api", created_by="t",
    )
    [item] = (await repos.blind_audit.list_items(TENANT_A)).items
    service = BlindAuditService(repos, EscalationService(repos, None, settings))
    result = await service.label(
        TENANT_A, item.id, "malicious", notes="beacon", actor=Actor("user", label_actor), user_id=UUID(label_actor)
    )
    assert result.escalation is not None and result.escalation_created
    return alert_id, result.escalation.id


async def test_a_decided_blind_audit_escalation_re_triages_the_closed_alert(
    engine: WorkflowEngine, repos: Repositories, engine_settings: Settings
) -> None:
    user_id = await analyst(repos)
    alert_id, escalation_id = await _closed_and_labelled(engine, repos, engine_settings, user_id)
    esc = await repos.escalations.get(TENANT_A, escalation_id)
    decided = await repos.escalations.decide(
        TENANT_A, escalation_id, decision="true_positive", decided_by=UUID(user_id), expected_version=esc.version
    )

    severity = await BlindAuditService(repos).requeue_after_decision(TENANT_A, decided, Actor("user", user_id))

    assert severity == "low"
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "queued"
    # The worker's process message: the fresh run starts at the escalation and waits for its decision ...
    waiting = await engine.run(TENANT_A, alert_id)
    assert waiting.status == "waiting_human" and waiting.interrupt["escalation_id"] == escalation_id
    # ... which the decision's resume message delivers.
    payload = {"type": "analyst_decision", "escalation_id": escalation_id, "decision": "true_positive",
               "approved_actions": [], "decided_by": user_id, "notes": "beacon"}
    planned = await engine.resume(TENANT_A, alert_id, payload)
    # The analyst confirmed a threat: a response is planned and waits for approval under the default policy.
    assert planned.status == "waiting_approval" and planned.interrupt["action_ids"]
    final = await engine.resume(
        TENANT_A, alert_id,
        {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": user_id,
         "reject_remaining": True},
    )
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (final.status, alert.status, alert.disposition) == ("completed", "closed", "malicious")
    assert alert.summary["analyst_decision"] == "true_positive"
    assert alert.summary.get("blind_audit_review") is None  # consumed by the run that started at it
    assert undeclared_keys(alert.summary, AlertSummary) == []
    # Nothing to re-queue for another escalation or a run that has not ended.
    assert await BlindAuditService(repos).requeue_after_decision(TENANT_A, decided, Actor("user", user_id)) is None
