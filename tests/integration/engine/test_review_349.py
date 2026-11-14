"""Adversarial review of PR #349 (FIX-3): folded alerts in production conditions.

Since AI-E3.15 the engine's model-judged escalation only links the related model close to the case; a person's
confirmation while the case is open (:func:`confirm`) folds it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, List

import pytest
import redis.asyncio as aioredis

from lg_sotf.audit.logger import Actor
from lg_sotf.core.retro_reopen import reopen_related_model_closes
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain import closure
from lg_sotf.queue.consumer import StreamConsumer
from lg_sotf.queue.streams import Message
from lg_sotf.runtime.worker import Worker
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.engine._support import RecordingEvents, analyst, decide, threat_alert

pytestmark = pytest.mark.integration


async def model_closed_with_run(repos: Repositories, entities: Dict[str, List[str]]) -> str:
    """A model-closed alert as production leaves it: its workflow run is ``completed``."""
    alert_id = await make_alert(repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    await repos.runs.start(TENANT_A, alert_id, "w0", lease_s=30, kind="process")
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(TENANT_A, alert_id, status)
    await repos.alerts.update(TENANT_A, alert_id, disposition="benign",
                              summary={"close_reason": closure.MODEL_CLOSE_REASON})
    await repos.runs.complete(TENANT_A, alert_id, worker_id="w0")
    return alert_id


async def confirm(repos: Repositories, threat: str, case: str) -> None:
    """A person confirms the threat while its case is open (a blind-audit label, an approved response action)."""
    await reopen_related_model_closes(repos, TENANT_A, await repos.alerts.get(TENANT_A, threat),
                                      actor=Actor("user", "test"), escalation_id=case)


async def test_worker_delivers_the_case_decision_to_a_folded_alert(
    engine: WorkflowEngine, repos: Repositories, db: Database, redis_client: aioredis.Redis,
    engine_settings: Settings,
) -> None:
    folded = await model_closed_with_run(repos, {"hosts": ["ws-042"]})
    threat = await threat_alert(repos)
    outcome = await engine.run(TENANT_A, threat)
    case = outcome.interrupt["escalation_id"]
    user_id = await analyst(repos)

    worker = Worker(engine_settings, db, redis_client, engine, StreamConsumer(redis_client, engine_settings, "w1"),
                    RecordingEvents())
    payload = {"type": "analyst_decision", "escalation_id": case, "decision": "false_positive",
               "approved_actions": [], "decided_by": user_id, "notes": ""}
    # What the API enqueues for every alert of the case (EscalationService.alerts_to_resume), as the worker gets it.
    msg = Message(stream="s", entry_id="0-1", tenant_id=TENANT_A, alert_id=folded, kind="resume",
                  payload=payload, enqueued_at=datetime.now(UTC), deliveries=1)
    # AI-E3.15: only linked so far (a model judged the threat). The decision does not reach a linked alert.
    await worker.process(msg)
    alert = await repos.alerts.get(TENANT_A, folded)
    assert (alert.status, alert.summary["close_reason"]) == ("closed", closure.MODEL_CLOSE_REASON)
    assert alert.summary.get("analyst_decision") is None

    await confirm(repos, threat, case)
    assert (await repos.alerts.get(TENANT_A, folded)).status == "waiting_human"
    await worker.process(msg)
    alert = await repos.alerts.get(TENANT_A, folded)
    assert alert.status == "closed", f"folded alert left {alert.status}: the worker never calls engine.resume"
    assert alert.summary["close_reason"] == "analyst:false_positive"


async def test_needs_more_info_strands_a_folded_alert(engine: WorkflowEngine, repos: Repositories) -> None:
    folded = await model_closed_with_run(repos, {"hosts": ["ws-042"]})
    threat = await threat_alert(repos)
    first = await engine.run(TENANT_A, threat)
    case1 = first.interrupt["escalation_id"]
    await confirm(repos, threat, case1)
    assert (await repos.alerts.get(TENANT_A, folded)).summary["escalation_id"] == case1
    user_id = await analyst(repos)

    second = await decide(engine, repos, threat, case1, "needs_more_info", user_id)
    assert second.status == "waiting_human"
    case2 = second.interrupt["escalation_id"]
    assert case2 != case1
    # Even with the needs_more_info resume delivered to the folded alert, it stays waiting on case1 (decided).
    await engine.resume(TENANT_A, folded, {"type": "analyst_decision", "escalation_id": case1,
                                           "decision": "needs_more_info", "approved_actions": [],
                                           "decided_by": user_id, "notes": ""})
    escalation2 = await repos.escalations.get(TENANT_A, case2)
    await decide(engine, repos, threat, case2, "false_positive", user_id)
    # The API resumes alerts_to_resume(case2) only: the folded alert is not among them.
    assert folded in [escalation2.alert_id, *escalation2.related_alert_ids], (
        f"folded alert is attached only to decided case {case1}; case2 holds {escalation2.related_alert_ids}; "
        f"status {(await repos.alerts.get(TENANT_A, folded)).status}"
    )
