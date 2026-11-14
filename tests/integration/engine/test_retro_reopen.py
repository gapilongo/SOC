"""Decision policy v3 safety net (FIX-3): a related threat reopens the alerts the models closed alone.

Through the real workflow and database: each threat path of the engine
(an escalation a model judged a threat, a response plan, a malicious close)
reopens the tenant's model-closed alerts that share a host, user or IP and
closed in the previous 24 hours; the reopen is idempotent, tenant-scoped,
audited ``alert.reopened`` and counted when it fails. A reopened alert never
closes on the models' word again.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import pytest

from lg_sotf.audit.logger import Actor
from lg_sotf.core import retro_reopen
from lg_sotf.core.graph import initial_state
from lg_sotf.core.retro_reopen import REOPEN_ACTION, reopen_counted, reopen_related_model_closes
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.domain import closure
from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import analyst, decide, suspicious_alert, threat_alert

pytestmark = pytest.mark.integration

ACTOR = Actor("system", "test")


async def model_closed(repos: Repositories, entities: Dict[str, List[str]], tenant_id: str = TENANT_A,
                       closed_at: datetime | None = None) -> str:
    """An alert the models closed alone (``model_closed``, close reason ``ai_closed:audit_required``)."""
    alert_id = await make_alert(repos, tenant_id, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(tenant_id, alert_id, status, now=closed_at)
    await repos.alerts.update(tenant_id, alert_id, disposition="benign",
                              summary={"close_reason": closure.MODEL_CLOSE_REASON})
    return alert_id


async def reopened(repos: Repositories, alert_id: str, mode: str, tenant_id: str = TENANT_A) -> bool:
    """Folded into an open case (``waiting_human``, no new run) or, without one, queued for its own review run."""
    alert = await repos.alerts.get(tenant_id, alert_id)
    marker = alert.summary.get("reopened") or {}
    status = "waiting_human" if mode == "folded" else "queued"
    return (alert.status, marker.get("reason"), marker.get("mode"), alert.disposition) == (
        status, "related_threat", mode, None)


async def test_an_escalation_the_models_only_found_suspicious_reopens_nothing(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """FIX-4: the fast tier's ``suspicious`` with an inconclusive deep verdict is a doubt, not a threat. It does
    not block a model close (policy v3), so it does not undo one either: the alert goes to an analyst, and only
    the analyst's ``true_positive`` (or a model that judges it a threat) reopens the related closes."""
    same_host = await model_closed(repos, {"hosts": ["ws-042"]})
    doubt = await suspicious_alert(repos)
    outcome = await engine.run(TENANT_A, doubt)
    assert outcome.status == "waiting_human"
    summary = (await repos.alerts.get(TENANT_A, doubt)).summary
    assert summary["triage"]["threat_assessment"] == "suspicious"
    assert (summary.get("analysis") or {}).get("verdict") != "malicious"
    assert not retro_reopen.judged_threat(summary["triage"], summary.get("analysis") or {})
    closed = await repos.alerts.get(TENANT_A, same_host)
    assert (closed.status, closed.summary.get("reopened")) == ("closed", None)


async def test_an_escalation_a_model_judged_a_threat_reopens_related_model_closes(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    same_host = await model_closed(repos, {"hosts": ["ws-042"]})
    same_user = await model_closed(repos, {"users": ["jdoe"]})
    same_ip = await model_closed(repos, {"ips": ["185.220.101.44"]})
    unrelated = await model_closed(repos, {"hosts": ["db-01"]})
    stale = await model_closed(repos, {"hosts": ["ws-042"]}, closed_at=datetime.now(UTC) - timedelta(hours=25))
    other_tenant = await model_closed(repos, {"hosts": ["ws-042"]}, tenant_id=TENANT_B)

    threat = await threat_alert(repos)
    outcome = await engine.run(TENANT_A, threat)
    assert outcome.status == "waiting_human"
    triage = (await repos.alerts.get(TENANT_A, threat)).summary["triage"]
    analysis = (await repos.alerts.get(TENANT_A, threat)).summary.get("analysis") or {}
    assert retro_reopen.judged_threat(triage, analysis), (triage, analysis)

    case = outcome.interrupt["escalation_id"]
    for alert_id in (same_host, same_user, same_ip):
        assert await reopened(repos, alert_id, "folded"), alert_id
        folded = await repos.alerts.get(TENANT_A, alert_id)
        assert folded.summary["reopened"] == {"reason": "related_threat", "threat_alert_id": threat,
                                              "escalation_id": case, "mode": "folded"}
        assert folded.summary["escalation_id"] == case
        assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is None  # no case of its own
        with pytest.raises(NotFound):  # and no new run (these alerts were closed without one in this test)
            await repos.runs.get(TENANT_A, alert_id)
    for alert_id, tenant in ((unrelated, TENANT_A), (stale, TENANT_A), (other_tenant, TENANT_B)):
        alert = await repos.alerts.get(tenant, alert_id)
        assert (alert.status, alert.disposition) == ("closed", "benign"), alert_id
    escalation = await repos.escalations.get(TENANT_A, outcome.interrupt["escalation_id"])
    assert {same_host, same_user, same_ip} <= set(escalation.related_alert_ids)
    audited = {e.resource_id for e in (await repos.audit.list(TENANT_A, action=REOPEN_ACTION)).items}
    assert audited == {same_host, same_user, same_ip}
    events = (await repos.alert_events.list_for_alert(TENANT_A, same_host)).items
    assert [e.event_type for e in events if e.event_type == REOPEN_ACTION] == [REOPEN_ACTION]

    # Idempotent: a second threat on the same host finds nothing left to reopen.
    again = await reopen_related_model_closes(repos, TENANT_A, await repos.alerts.get(TENANT_A, threat), actor=ACTOR)
    assert again == []

    # Should a reopened alert run again, it never closes on the models' word.
    state = initial_state(TENANT_A, await repos.alerts.get(TENANT_A, same_host))
    assert state["alert"]["reopened"] == {"reason": "related_threat"}
    assert "reopened" in closure.model_close_blockers(state, tier=closure.MODEL_CLOSE_TIER)


async def test_a_response_plan_and_the_malicious_close_each_reopen_related_model_closes(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    """The plan_response path and the malicious-close path each reopen what closed since the previous one."""
    threat = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, threat)
    assert first.status == "waiting_human"

    before_plan = await model_closed(repos, {"hosts": ["ws-042"]})
    second = await decide(engine, repos, threat, first.interrupt["escalation_id"], "true_positive", user_id)
    assert second.status == "waiting_approval"
    assert await reopened(repos, before_plan, "requeued")  # plan_response: the case is decided, nothing to fold into

    before_close = await model_closed(repos, {"users": ["jdoe"]})
    done = await engine.resume(
        TENANT_A, threat,
        {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": user_id,
         "reject_remaining": True},
    )
    assert done.status == "completed"
    assert (await repos.alerts.get(TENANT_A, threat)).disposition == "malicious"
    assert await reopened(repos, before_close, "requeued")  # the malicious close


async def test_a_benign_escalation_reopens_nothing(engine: WorkflowEngine, repos: Repositories) -> None:
    closed_alert = await model_closed(repos, {"hosts": ["build-7"]})
    quiet = await make_alert(repos, TENANT_A, title="Authorized approved expected patch healthcheck",
                             severity="low", normalized={"entities": {"hosts": ["build-7"]}})
    await engine.run(TENANT_A, quiet)
    alert = await repos.alerts.get(TENANT_A, closed_alert)
    assert (alert.status, alert.disposition) == ("closed", "benign")


async def test_a_reopen_failure_is_counted_not_swallowed(
    repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    await model_closed(repos, {"hosts": ["ws-042"]})
    threat = await repos.alerts.get(TENANT_A, await suspicious_alert(repos))

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("database went away")

    monkeypatch.setattr(repos.alerts, "model_closed_sharing_entities", broken)
    before = RETRO_REOPEN_FAILURES.labels(path="workflow")._value.get()
    assert await reopen_counted(repos, TENANT_A, threat, actor=ACTOR, path="workflow") == []
    assert RETRO_REOPEN_FAILURES.labels(path="workflow")._value.get() == before + 1
