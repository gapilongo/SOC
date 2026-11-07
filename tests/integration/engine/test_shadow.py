"""Shadow mode (AI-E1.5a) against real Postgres and Redis: a shadow run changes nothing outside the system.

The alert is critical, the tenant lets low-risk containment run on its own,
the response threshold is 0 and a Slack integration subscribes to every
event: a live run of the same alert plans and executes actions and queues
notifications (the control at the end of the test). The shadow run of it
must do none of that, and must record what it would have done.
"""

from __future__ import annotations

import smtplib
from typing import Any, Dict, List

import httpx
import pytest
import redis.asyncio as aioredis
from asyncpg.exceptions import ReadOnlySQLTransactionError

from lg_sotf.core.shadow import ShadowRunner
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.shadow import ShadowRun, shadow_scope
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.settings import Settings
from tests.integration.db._support import ALL_TABLES, TENANT_A, make_alert
from tests.integration.engine._support import SUSPICIOUS_ENTITIES, RecordingEvents
from tests.integration.integrations._support import add_integration, slack_url

pytestmark = pytest.mark.integration

ALL_EVENTS = (
    "escalation.created", "escalation.sla_breached", "escalation.decided", "action.awaiting_approval",
    "action.executed", "action.failed", "alert.critical_received",
)


async def snapshot(db: Database, alert_id: str) -> Dict[str, Any]:
    """Every table's row count, the alert row and the stored trace."""
    async with db.system_tx(readonly=True) as conn:
        counts = {t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in ALL_TABLES}  # noqa: S608
        alert = dict(await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_id))
    return {"counts": counts, "alert": alert}


def forbid_network(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    attempts: List[str] = []

    async def async_send(self: Any, request: httpx.Request) -> httpx.Response:
        attempts.append(f"http {request.url.host}")
        raise AssertionError("no HTTP request in this test")

    def sync_send(self: Any, request: httpx.Request) -> httpx.Response:
        attempts.append(f"http {request.url.host}")
        raise AssertionError("no HTTP request in this test")

    def smtp(self: Any, *args: Any, **kwargs: Any) -> None:
        attempts.append("smtp")
        raise AssertionError("no SMTP connection in this test")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_send)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", sync_send)
    monkeypatch.setattr(smtplib.SMTP, "__init__", smtp)
    return attempts


def record_connector_calls(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    calls: List[str] = []
    original = DryRunConnector.execute

    async def execute(self: DryRunConnector, action: Any) -> Any:
        calls.append(action.action_type)
        return await original(self, action)

    monkeypatch.setattr(DryRunConnector, "execute", execute)
    return calls


async def test_shadow_no_side_effects(
    engine_factory: Any, engine_settings: Settings, repos: Repositories, db: Database, events: RecordingEvents,
    redis_client: aioredis.Redis, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = engine_settings.model_copy(
        update={"routing": {**dict(engine_settings.routing or {}), "response_threshold": 0}}
    )
    engine: WorkflowEngine = await engine_factory(settings=settings)
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    await add_integration(
        repos, SecretBox.from_settings(settings), TENANT_A, "slack", secret={"webhook_url": slack_url()},
        events=ALL_EVENTS,
    )
    alert_id = await make_alert(
        repos, TENANT_A, title="Possible C2 beacon from workstation", severity="critical",
        normalized={"entities": SUSPICIOUS_ENTITIES}, raw={"vendor": "edr"},
    )
    alert = await repos.alerts.get(TENANT_A, alert_id)
    verdicts = engine.node_deps.verdicts
    await verdicts.put_analyst_benign(
        TENANT_A, alert.fingerprint, decision="false_positive", alert_id="earlier", escalation_id=None
    )
    network = forbid_network(monkeypatch)
    connector_calls = record_connector_calls(monkeypatch)
    pubsub = redis_client.pubsub()
    await pubsub.psubscribe("*")
    redis_keys = sorted(await redis_client.keys("*"))
    before = await snapshot(db, alert_id)

    outcome = await ShadowRunner(engine.node_deps).run(TENANT_A, alert_id)

    # It ran the real pipeline: a confident malicious verdict and a response plan, then it stopped.
    assert outcome.run_id.startswith("shadow/")
    assert outcome.state["decision"]["route"] == "plan_response"
    assert outcome.interrupt == {"type": "analyst_decision", "escalation_id": "shadow"}
    # Nothing left the system: no connector call, HTTP request, mail, WebSocket event or Redis write...
    assert connector_calls == [] and network == [] and events.events == []
    assert await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2) is None
    assert sorted(await redis_client.keys("*")) == redis_keys
    assert await verdicts.get(TENANT_A, alert.fingerprint) is not None
    # ...and no database row changed: alert, events, escalation, actions, outbox, audit, trace.
    after = await snapshot(db, alert_id)
    assert after["alert"] == before["alert"]
    assert after["counts"] == {**before["counts"], "shadow_effects": len(outcome.effects)}
    # The sink holds what the run would have done, in order, and only that is stored.
    effects = [(e.boundary, e.operation, e.outcome) for e in outcome.effects]
    assert ("alert", "AlertsRepo.update", "sunk") in effects
    assert ("alert_event", "AlertEventsRepo.append", "sunk") in effects
    assert ("ws_event", "publish_event", "sunk") in effects
    assert ("verdict_cache", "VerdictCache.invalidate", "sunk") in effects
    assert ("escalation", "EscalationService.open_or_attach", "sunk") in effects
    plan = next(e for e in outcome.effects if e.boundary == "response_plan")
    assert "block_ip:185.220.101.44" in plan.detail["actions"]
    assert all(e.outcome == "sunk" for e in outcome.effects)
    stored = await repos.shadow_effects.list_for_run(TENANT_A, alert_id, outcome.run_id)
    assert [(s.seq, s.boundary, s.operation, s.detail) for s in stored] == [
        (e.seq, e.boundary, e.operation, e.detail) for e in outcome.effects
    ]

    # Control: live, the same alert executes actions, queues notifications and publishes events.
    await pubsub.aclose()
    await engine.run(TENANT_A, alert_id)
    assert connector_calls and events.events
    async with db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval("SELECT count(*) FROM notification_outbox") > 0
    assert network == []


async def test_a_write_no_boundary_diverts_fails_in_shadow_mode(db: Database, repos: Repositories) -> None:
    """The database backstop: every transaction of a shadow run is read only."""
    with shadow_scope(ShadowRun("shadow/backstop")):
        with pytest.raises(ReadOnlySQLTransactionError):
            await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
        async with db.connection() as conn:
            with pytest.raises(ReadOnlySQLTransactionError):
                await conn.execute("UPDATE tenants SET name = 'changed' WHERE id = $1", TENANT_A)
        with pytest.raises(ReadOnlySQLTransactionError):
            async with db.system_tx() as conn:
                await conn.execute("UPDATE tenants SET name = 'changed' WHERE id = $1", TENANT_A)
    tenant = await repos.tenants.get(TENANT_A)
    assert tenant.name == "Tenant A" and not tenant.settings
