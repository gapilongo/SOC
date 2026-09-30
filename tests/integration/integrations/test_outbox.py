"""Events are queued in the transaction of the change they announce, once, and only for the tenant's integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List
from uuid import uuid4

import pytest

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.integrations.outbox import enqueue_event
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.dispatch import dispatch_new_alerts
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.response import PlanContext, ResponseService
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.integrations.conftest import add_integration, slack_url
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration

ALL_EVENTS = (
    "escalation.created", "escalation.sla_breached", "escalation.decided", "action.awaiting_approval",
    "action.executed", "action.failed", "alert.critical_received",
)


async def outbox(repos: Repositories, tenant_id: str = TENANT_A) -> List[Any]:
    async with repos.db.tenant_tx(tenant_id) as conn:
        return list(await conn.fetch("SELECT * FROM notification_outbox ORDER BY created_at, event_type"))


async def slack(repos: Repositories, box: SecretBox, tenant_id: str = TENANT_A, **kwargs: Any) -> Any:
    return await add_integration(repos, box, tenant_id, "slack", secret={"webhook_url": slack_url()}, **kwargs)


async def escalate(repos: Repositories, settings: Settings, severity: str = "high") -> tuple[str, str]:
    alert_id = await add_alert(repos, TENANT_A, severity=severity, entities={"hosts": ["ws-042"]})
    ticket = await EscalationService(repos, None, settings).open_or_attach(
        TENANT_A, alert_id, severity=severity, confidence=40, threat_score=60, reason="grey zone"
    )
    return alert_id, ticket.id


async def test_escalation_created_is_queued_once_with_a_summary(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings()
    hook = await slack(repos, box)
    muted = await slack(repos, box, min_severity="critical")
    alert_id, esc_id = await escalate(repos, settings)
    # The node runs again on resume: no second message.
    await EscalationService(repos, None, settings).open_or_attach(
        TENANT_A, alert_id, severity="high", confidence=40, threat_score=60, reason="grey zone"
    )
    rows = await outbox(repos)
    assert [(r["integration_id"], r["event_type"], r["operation"], r["status"]) for r in rows] == [
        (hook.id, "escalation.created", "notify", "pending")
    ]
    payload = rows[0]["payload"]
    assert rows[0]["escalation_id"] == esc_id and rows[0]["alert_id"] == alert_id
    assert payload["schema"] == "lg-sotf.event.v1" and payload["escalation"]["id"] == esc_id
    assert payload["alert"]["confidence"] == 40.0 and payload["alert"]["entities"] == {"hosts": ["ws-042"]}
    assert "raw" not in payload["alert"]
    assert muted.id not in {r["integration_id"] for r in rows}


async def test_outbox_row_rolls_back_with_the_change(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    await slack(repos, box)
    alert_id = await add_alert(repos, TENANT_A)
    with pytest.raises(RuntimeError):
        async with repos.db.tenant_tx(TENANT_A) as conn:
            esc, _ = await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r", conn=conn)
            assert await enqueue_event(
                conn, TENANT_A, "escalation.created", alert_id=alert_id, dedupe_key=f"x:{esc.id}", escalation=esc
            ) == 1
            raise RuntimeError("the state change fails after the event was written")
    assert await outbox(repos) == []
    assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is None


async def test_decisions_actions_and_critical_alerts_are_queued(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    await slack(repos, box, events=ALL_EVENTS)
    jira = await add_integration(
        repos, box, TENANT_A, "jira", events=("escalation.created", "escalation.decided"),
        config={"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SOC"},
        secret={"api_token": "t" * 20},
    )
    alert_id, esc_id = await escalate(repos, settings)
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:6]}@example.com", "analyst")).id
    esc = await repos.escalations.get(TENANT_A, esc_id)
    await ReviewService(repos, settings).decide(
        TENANT_A, esc_id, analyst, "analyst", "true_positive", "confirmed", [], esc.version
    )
    responses = ResponseService(repos, settings)
    plan = await responses.plan(
        TENANT_A, alert_id,
        PlanContext(severity="high", title="t", evidence="analyst", recommended_actions=["isolate_host"],
                    hosts=["ws-042"], entities={"hosts": ["ws-042"]}),
    )
    assert plan.awaiting
    critical = await add_alert(repos, TENANT_A, severity="critical")

    @dataclass(frozen=True)
    class Ingested:
        alert_id: str
        severity: str

    queue = WorkQueue(redis_client, settings)
    for _ in range(2):  # a repeated dispatch never repeats the notification
        await dispatch_new_alerts(repos, queue, TENANT_A, [Ingested(critical, "critical")])

    rows = await outbox(repos)
    kinds = sorted((r["event_type"], r["operation"]) for r in rows)
    assert ("escalation.decided", "notify") in kinds and ("escalation.decided", "ticket_update") in kinds
    assert ("escalation.created", "ticket_create") in kinds
    assert ("action.awaiting_approval", "notify") in kinds
    assert [r["alert_id"] for r in rows if r["event_type"] == "alert.critical_received"] == [critical]
    decided = next(r for r in rows if r["event_type"] == "escalation.decided" and r["integration_id"] == jira.id)
    assert decided["payload"]["escalation"]["decision"] == "true_positive"


async def test_executed_actions_are_queued_with_their_outcome(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings()
    await slack(repos, box, events=("action.executed", "action.failed"))
    alert_id = await add_alert(repos, TENANT_A)
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    responses = ResponseService(repos, settings)
    plan = await responses.plan(
        TENANT_A, alert_id,
        PlanContext(severity="high", title="t", evidence="rules", recommended_actions=["create_ticket"]),
    )
    assert plan.auto
    statuses = await responses.execute(TENANT_A, alert_id, plan.auto)
    assert set(statuses.values()) == {"dry_run"}
    rows = await outbox(repos)
    assert len(rows) == len(plan.auto)
    assert {(r["event_type"], r["payload"]["action"]["dry_run"]) for r in rows} == {("action.executed", True)}
    assert {r["payload"]["action"]["id"] for r in rows} == set(plan.auto)


async def test_integrations_are_isolated_per_tenant(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings()
    other = await slack(repos, box, TENANT_B)
    await escalate(repos, settings)
    assert await outbox(repos, TENANT_B) == []
    assert await outbox(repos, TENANT_A) == []
    with pytest.raises(NotFound):
        await repos.integrations.get(TENANT_A, other.id)
    assert await repos.integrations.list(TENANT_A) == []
    async with repos.db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval("SELECT count(*) FROM integrations") == 0
        updated = await conn.execute("UPDATE integrations SET enabled = false")
    assert updated == "UPDATE 0"
    assert (await repos.integrations.get(TENANT_B, other.id)).enabled
