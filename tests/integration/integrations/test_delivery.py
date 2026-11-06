"""The scheduler's delivery loop and ticket sync against stub receivers (httpx.MockTransport)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List
from uuid import uuid4

import httpx
import pytest

from lg_sotf.db.repos import NewAlert, Repositories
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.integrations.delivery import DELIVERIES, sync_tickets
from lg_sotf.integrations.outbox import enqueue_critical_alerts
from lg_sotf.integrations.ticketing import TicketService
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.scheduler import Scheduler
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.connectors.webhook import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify_signature
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.response import PlanContext, ResponseService
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.integrations.conftest import Receiver, add_integration, fake_secret, slack_url
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration

JIRA_CONFIG = {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SOC",
               "resolve_transition": "Done"}
SNOW_CONFIG = {"instance_url": "https://acme.service-now.com", "username": "lgsotf", "resolve_on_decision": True}


async def rows(repos: Repositories, tenant_id: str = TENANT_A) -> List[Any]:
    async with repos.db.tenant_tx(tenant_id) as conn:
        return list(await conn.fetch("SELECT * FROM notification_outbox ORDER BY created_at"))


async def make_due(repos: Repositories) -> None:
    async with repos.db.system_tx() as conn:
        await conn.execute("UPDATE notification_outbox SET next_attempt_at = now() WHERE status IN ('pending', 'failed')")


async def age_tickets(repos: Repositories) -> None:
    async with repos.db.system_tx() as conn:
        await conn.execute("UPDATE external_tickets SET last_synced_at = now() - interval '1 day'")


async def escalate(repos: Repositories, settings: Settings, tenant_id: str = TENANT_A) -> tuple[str, str]:
    alert_id = await add_alert(repos, tenant_id, severity="high", entities={"ips": ["185.220.101.44"]})
    ticket = await EscalationService(repos, None, settings).open_or_attach(
        tenant_id, alert_id, severity="high", confidence=35, threat_score=70, reason="grey zone"
    )
    return alert_id, ticket.id


def scheduler(settings: Settings, repos: Repositories, redis_client: Any, delivery: Any) -> Scheduler:
    return Scheduler(settings, repos.db, redis_client, lambda: None, WorkQueue(redis_client, settings), None,  # type: ignore[arg-type, return-value]
                     delivery=delivery)


async def test_scheduler_delivers_retries_with_backoff_and_dead_letters(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    slack = await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()})
    hook_secret = fake_secret("hmac")
    hook = await add_integration(
        repos, box, TENANT_A, "webhook", config={"url": "https://soar.example.com/lgsotf"},
        secret={"signing_secret": hook_secret},
    )
    receiver = Receiver({"POST /services/T11111111/B11111111/" + "y" * 24: httpx.Response(500)})
    sched = scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box))
    alert_id, _ = await escalate(repos, settings)

    await sched.deliver_notifications()
    by_integration = {r["integration_id"]: r for r in await rows(repos)}
    sent, failed = by_integration[hook.id], by_integration[slack.id]
    assert sent["status"] == "sent" and sent["attempts"] == 1 and sent["sent_at"] is not None
    assert failed["status"] == "failed" and failed["attempts"] == 1 and "HTTP 500" in failed["last_error"]
    assert failed["next_attempt_at"] > datetime.now(UTC) + timedelta(seconds=3)  # backoff, not immediate
    assert "hooks.slack.com" not in failed["last_error"]

    webhook_request = next(r for r in receiver.requests if r.url.host == "soar.example.com")
    assert verify_signature(hook_secret, webhook_request.headers[TIMESTAMP_HEADER], webhook_request.content,
                            webhook_request.headers[SIGNATURE_HEADER])
    assert json.loads(webhook_request.content)["alert"]["id"] == alert_id

    for _ in range(2):  # max_attempts = 3
        await make_due(repos)
        await sched.deliver_notifications()
    dead = {r["integration_id"]: r for r in await rows(repos)}[slack.id]
    assert dead["status"] == "dead" and dead["attempts"] == 3
    await make_due(repos)
    await sched.deliver_notifications()
    assert len([r for r in receiver.requests if r.url.host == "hooks.slack.com"]) == 3  # dead rows are left alone


async def test_claims_skip_locked_rows_and_leases_them(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings()
    for _ in range(3):
        await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()})
    await add_integration(repos, box, TENANT_B, "slack", secret={"webhook_url": slack_url()})
    await escalate(repos, settings)
    await escalate(repos, settings, TENANT_B)
    first, second = await asyncio.gather(
        repos.outbox.claim_due_all_tenants(limit=2, lease_s=60),
        repos.outbox.claim_due_all_tenants(limit=2, lease_s=60),
    )
    claimed = [e.id for e in first + second]
    assert len(claimed) == 4 and len(set(claimed)) == 4
    assert await repos.outbox.claim_due_all_tenants(limit=10, lease_s=60) == []  # leased
    stale = first[0]
    assert await repos.outbox.record_outcome(stale.tenant_id, stale.id, claimed_attempts=stale.attempts, status="sent")
    assert not await repos.outbox.record_outcome(stale.tenant_id, stale.id, claimed_attempts=stale.attempts,
                                                       status="failed")  # finished rows are not rewritten


async def test_jira_ticket_lifecycle(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    jira = await add_integration(repos, box, TENANT_A, "jira", config=JIRA_CONFIG, secret={"api_token": "t" * 24},
                                 events=("escalation.created", "escalation.decided"))
    issue_state: Dict[str, Any] = {"status": "To Do", "category": "new"}
    receiver = Receiver({
        "GET /rest/api/3/search/jql": httpx.Response(200, json={"issues": []}),
        "POST /rest/api/3/issue": httpx.Response(201, json={"id": "10001", "key": "SOC-7"}),
        "POST /rest/api/3/issue/SOC-7/comment": httpx.Response(201, json={}),
        "GET /rest/api/3/issue/SOC-7/transitions": httpx.Response(200, json={"transitions": [
            {"id": "31", "name": "Done", "to": {"name": "Done"}}]}),
        "POST /rest/api/3/issue/SOC-7/transitions": httpx.Response(204),
        "GET /rest/api/3/issue/SOC-7": lambda r: httpx.Response(200, json={
            "key": "SOC-7",
            "fields": {"status": {"name": issue_state["status"], "statusCategory": {"key": issue_state["category"]}}},
            "changelog": {"histories": [{"author": {"displayName": "Jo Analyst"}, "items": [{"field": "status"}]}]},
        }),
    })
    delivery = receiver.delivery(repos, settings, box)
    sched = scheduler(settings, repos, redis_client, delivery)
    alert_id, esc_id = await escalate(repos, settings)

    await sched.deliver_notifications()
    tickets = await repos.tickets.list(TENANT_A, alert_id=alert_id)
    assert [(t.external_key, t.escalation_id, t.system) for t in tickets] == [("SOC-7", esc_id, "jira")]
    assert tickets[0].external_url == "https://acme.atlassian.net/browse/SOC-7"
    created = json.loads(next(r for r in receiver.requests if r.url.path == "/rest/api/3/issue").content)
    assert created["fields"]["summary"].startswith("[LG-SOTF] [HIGH]")
    timeline = (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items
    assert any(e.event_type == "ticket.created" and e.data["ticket"] == "SOC-7" for e in timeline)

    # External resolution while the escalation is open: a timeline note, never a decision.
    issue_state.update(status="Done", category="done")
    assert await sync_tickets(repos, settings, delivery.tickets) == 0  # synced when it was opened
    await age_tickets(repos)
    assert await sync_tickets(repos, settings, delivery.tickets) == 1
    esc = await repos.escalations.get(TENANT_A, esc_id)
    assert esc.status == "open" and esc.decision is None
    notes = [e for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items
             if e.event_type == "ticket.resolved_externally"]
    assert len(notes) == 1 and notes[0].data["note"].startswith("Ticket SOC-7 done by Jo Analyst")
    synced = (await repos.tickets.list(TENANT_A, alert_id=alert_id))[0]
    assert synced.resolved and synced.external_status == "Done" and synced.resolved_by == "Jo Analyst"
    await age_tickets(repos)
    assert await sync_tickets(repos, settings, delivery.tickets) == 0  # resolved tickets are not polled again

    # The analyst decides in LG-SOTF: comment and transition on the same ticket (no second ticket).
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:6]}@example.com", "analyst")).id
    await ReviewService(repos, settings).decide(TENANT_A, esc_id, analyst, "analyst", "false_positive", None, [], esc.version)
    await sched.deliver_notifications()
    paths = receiver.paths()
    assert paths.count("POST /rest/api/3/issue") == 1 and "POST /rest/api/3/issue/SOC-7/comment" in paths
    assert "POST /rest/api/3/issue/SOC-7/transitions" not in paths  # already resolved outside
    assert {r["status"] for r in await rows(repos)} == {"sent"}
    assert jira.id in {r["integration_id"] for r in await rows(repos)}


async def test_ticket_create_is_idempotent_and_updates_wait_for_it(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    await add_integration(repos, box, TENANT_A, "servicenow", config=SNOW_CONFIG, secret={"password": "p" * 20},
                          events=("escalation.created", "escalation.decided"))
    existing = {"sys_id": "abc123", "number": "INC0010001", "state": "2"}
    receiver = Receiver({
        # A ticket opened by an earlier attempt that crashed before recording it is found, not duplicated.
        "GET /api/now/table/incident": httpx.Response(200, json={"result": [existing]}),
        "PATCH /api/now/table/incident/abc123": httpx.Response(200, json={"result": existing}),
    })
    sched = scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box))
    alert_id, esc_id = await escalate(repos, settings)
    analyst = (await repos.users.create(TENANT_A, f"a-{uuid4().hex[:6]}@example.com", "analyst")).id
    esc = await repos.escalations.get(TENANT_A, esc_id)
    await ReviewService(repos, settings).decide(TENANT_A, esc_id, analyst, "analyst", "benign_positive", None, [], esc.version)

    # The decision is delivered first: it waits (no attempt used) until the ticket exists.
    async with repos.db.system_tx() as conn:
        await conn.execute("UPDATE notification_outbox SET next_attempt_at = now() + interval '1 hour' "
                           "WHERE operation = 'ticket_create'")
    await sched.deliver_notifications()
    update = next(r for r in await rows(repos) if r["operation"] == "ticket_update")
    assert update["status"] == "pending" and update["attempts"] == 0

    await make_due(repos)
    await sched.deliver_notifications()
    await make_due(repos)
    await sched.deliver_notifications()
    assert {r["operation"]: r["status"] for r in await rows(repos)} == {"ticket_create": "sent", "ticket_update": "sent"}
    assert "POST /api/now/table/incident" not in receiver.paths()
    patches = [json.loads(r.content) for r in receiver.requests if r.method == "PATCH"]
    assert patches[0] == {"work_notes": patches[0]["work_notes"]} and "benign positive" in patches[0]["work_notes"]
    assert patches[1]["state"] == "6" and patches[1]["close_code"] == "Solution provided"
    tickets = await repos.tickets.list(TENANT_A, escalation_ids=[esc_id])
    assert [t.external_key for t in tickets] == ["INC0010001"] and tickets[0].external_status == "Resolved"


async def test_create_ticket_action_uses_the_ticketing_integration(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings(response={"dry_run": False})
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}, "response": {"dry_run": False}})
    await add_integration(repos, box, TENANT_A, "servicenow", config=SNOW_CONFIG, secret={"password": "p" * 20},
                          events=())
    created = {"sys_id": "def456", "number": "INC0010002", "state": "1"}
    receiver = Receiver({
        "GET /api/now/table/incident": httpx.Response(200, json={"result": []}),
        "POST /api/now/table/incident": httpx.Response(201, json={"result": created}),
    })
    tickets = TicketService(repos, settings, http=receiver.http(settings), secret_box=box)
    responses = ResponseService(repos, settings, ticketing=tickets)
    alert_id = await add_alert(repos, TENANT_A)
    plan = await responses.plan(
        TENANT_A, alert_id, PlanContext(severity="high", title="t", evidence="rules", recommended_actions=["create_ticket"])
    )
    statuses = await responses.execute(TENANT_A, alert_id, plan.auto)
    ledger = {a.action_type: a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id)).items}
    ticket_action = ledger["create_ticket"]
    assert statuses[str(ticket_action.id)] == "succeeded" and ticket_action.connector == "ticketing"
    assert ticket_action.result["ticket"] == "INC0010002" and ticket_action.result["created"] is True
    assert ledger["send_alert"].connector != "ticketing"  # other actions keep the tenant's connector
    linked = await repos.tickets.list(TENANT_A, alert_id=alert_id)
    assert [(t.external_key, t.escalation_id, t.action_id) for t in linked] == [("INC0010002", None, ticket_action.id)]

    # The alert escalates later: its escalation reuses the ticket instead of opening a second one.
    settings_with_events = settings
    integ = (await repos.integrations.list(TENANT_A))[0]
    await repos.integrations.update(TENANT_A, integ.id, events=["escalation.created"])
    esc = await EscalationService(repos, None, settings_with_events).open_or_attach(
        TENANT_A, alert_id, severity="high", confidence=30, threat_score=60, reason="review"
    )
    delivery = receiver.delivery(repos, settings, box)
    assert await delivery.run_once() == 1
    linked = await repos.tickets.list(TENANT_A, alert_id=alert_id)
    assert [(t.external_key, t.escalation_id) for t in linked] == [("INC0010002", esc.id)]
    assert receiver.paths().count("POST /api/now/table/incident") == 1


async def test_sla_breach_is_announced(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()},
                          events=("escalation.sla_breached",))
    alert_id = await add_alert(repos, TENANT_A)
    await repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r", sla_deadline=datetime.now(UTC) - timedelta(seconds=1))
    receiver = Receiver()
    sched = scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box))
    await sched.sweep_sla()
    queued = await rows(repos)
    assert [(r["event_type"], r["payload"]["escalation"]["level"], r["payload"]["escalation"]["from_level"])
            for r in queued] == [("escalation.sla_breached", "L2", "L1")]
    await sched.deliver_notifications()
    assert json.loads(receiver.requests[0].content)["blocks"][0]["text"]["text"].startswith("Escalation SLA breached")


async def test_suspended_tenants_get_no_deliveries(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()})
    await escalate(repos, settings)
    await repos.tenants.set_status(TENANT_A, "suspended")
    receiver = Receiver()
    sched = scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box))
    deferred = DELIVERIES.labels(kind="slack", outcome="deferred")
    before = deferred._value.get()
    await sched.deliver_notifications()
    assert receiver.requests == []
    # Deferred, not dead: status kept, no attempt used, looked at again in about five minutes.
    [row] = await rows(repos)
    assert (row["status"], row["attempts"], row["last_error"]) == ("pending", 0, None)
    assert timedelta(minutes=4) < row["next_attempt_at"] - datetime.now(UTC) <= timedelta(minutes=5, seconds=5)
    assert deferred._value.get() == before + 1

    # Reactivated: the held row is delivered.
    await repos.tenants.set_status(TENANT_A, "active")
    async with repos.db.tenant_tx(TENANT_A) as conn:
        await conn.execute("UPDATE notification_outbox SET next_attempt_at = now()")
    await sched.deliver_notifications()
    assert len(receiver.requests) == 1 and [r["status"] for r in await rows(repos)] == ["sent"]


async def test_held_rows_of_a_suspended_tenant_still_expire(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()})
    await escalate(repos, settings)
    await repos.tenants.set_status(TENANT_A, "suspended")
    async with repos.db.tenant_tx(TENANT_A) as conn:
        await conn.execute("UPDATE notification_outbox SET created_at = now() - interval '2 days'")
    receiver = Receiver()
    await scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box)).deliver_notifications()
    assert receiver.requests == []
    assert [(r["status"], r["last_error"]) for r in await rows(repos)] == [
        ("dead", "expired: not delivered within integrations.max_age_hours")
    ]


async def test_rows_of_a_disabled_integration_are_dead(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox, redis_client: Any
) -> None:
    settings = integ_settings()
    integration = await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()})
    await escalate(repos, settings)
    await repos.tenants.set_status(TENANT_A, "suspended")
    await repos.integrations.update(TENANT_A, integration.id, enabled=False)
    receiver = Receiver()
    await scheduler(settings, repos, redis_client, receiver.delivery(repos, settings, box)).deliver_notifications()
    assert receiver.requests == []
    assert [(r["status"], r["last_error"]) for r in await rows(repos)] == [("dead", "integration disabled or deleted")]


async def test_onboarding_sample_alerts_never_reach_integrations(
    repos: Repositories, integ_settings: Callable[..., Settings], box: SecretBox
) -> None:
    settings = integ_settings(response={"dry_run": False})
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}, "response": {"dry_run": False}})
    await add_integration(repos, box, TENANT_A, "servicenow", config=SNOW_CONFIG, secret={"password": "p" * 20},
                          events=("escalation.created",))
    await add_integration(repos, box, TENANT_A, "slack", secret={"webhook_url": slack_url()},
                          events=("alert.critical_received", "escalation.created", "action.executed"))
    sample = NewAlert(
        source_id=SAMPLE_SOURCE_ID, source_alert_id=uuid4().hex, fingerprint=f"fp-{uuid4().hex}", title="Sample",
        severity="critical", occurred_at=datetime.now(UTC), raw={"vendor": "demo"},
        normalized={"title": "Sample", "severity": "critical", "entities": {}},
    )
    [sample_id] = await repos.alerts.insert_many_if_absent(TENANT_A, [sample])
    real_id = await add_alert(repos, TENANT_A, severity="critical")

    async with repos.db.tenant_tx(TENANT_A) as conn:
        assert await enqueue_critical_alerts(conn, TENANT_A, [sample_id]) == 0
        assert await enqueue_critical_alerts(conn, TENANT_A, [real_id]) == 1  # control: real alerts still notify
    await EscalationService(repos, None, settings).open_or_attach(
        TENANT_A, sample_id, severity="critical", confidence=30, threat_score=60, reason="review"
    )
    assert [r["alert_id"] for r in await rows(repos)] == [real_id]

    # create_ticket on a sample runs as a dry run, never through the ticketing integration.
    receiver = Receiver()
    responses = ResponseService(
        repos, settings, ticketing=TicketService(repos, settings, http=receiver.http(settings), secret_box=box)
    )
    plan = await responses.plan(
        TENANT_A, sample_id, PlanContext(severity="high", title="t", evidence="rules", recommended_actions=["create_ticket"])
    )
    statuses = await responses.execute(TENANT_A, sample_id, plan.auto)
    ledger = {a.action_type: a for a in (await repos.actions.list(TENANT_A, alert_id=sample_id)).items}
    ticket_action = ledger["create_ticket"]
    assert statuses[str(ticket_action.id)] == "dry_run" and ticket_action.connector == "dry_run"
    assert receiver.requests == [] and await repos.tickets.list(TENANT_A, alert_id=sample_id) == []
    assert [r["alert_id"] for r in await rows(repos)] == [real_id]
