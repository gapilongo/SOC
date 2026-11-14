"""Shadow mode (AI-E1.5a) against real Postgres and Redis: a shadow run changes nothing outside the system.

The alert is critical, the tenant lets low-risk containment run on its own,
the response threshold is 0 and a Slack integration subscribes to every
event: a live run of the same alert plans and executes actions and queues
notifications (the control at the end of the test). The shadow run of it
must do none of that, and must record what it would have done.
"""

from __future__ import annotations

import dataclasses
import smtplib
from datetime import UTC, datetime
from typing import Any, Dict, List
from uuid import uuid4

import httpx
import pytest
import redis.asyncio as aioredis
from asyncpg.exceptions import InvalidCachedStatementError, ReadOnlySQLTransactionError

from lg_sotf.core.retro_reopen import enqueue_requeued, judged_threat
from lg_sotf.core.shadow import ShadowRunner
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import ShadowRoleRequired, SystemScopeDenied
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.outbox import NewOutboxEntry, enqueue_on
from lg_sotf.domain import closure
from lg_sotf.domain.events import publish_event
from lg_sotf.domain.verdict_key import verdict_key_of
from lg_sotf.integrations.ticketing import JiraClient, TicketDraft
from lg_sotf.models.trace import NewTraceStep
from lg_sotf.net.egress import egress_policy
from lg_sotf.net.http import guarded_client
from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES, RETRO_REOPENED
from lg_sotf.queue.events import EventBus
from lg_sotf.queue.redis import ShadowSafeRedis
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.shadow import ShadowEgressRefused, ShadowRun, shadow_scope
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.services.folded import settle_folded
from lg_sotf.settings import Settings
from tests.integration.db._support import ALL_TABLES, TENANT_A, db_settings, make_alert
from tests.integration.engine._support import SUSPICIOUS_ENTITIES, RecordingEvents
from tests.integration.integrations._support import Receiver, add_integration, fake_secret, public_resolver, slack_url

pytestmark = pytest.mark.integration

JIRA_CONFIG = {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SOC",
               "issue_type": "Task", "labels": ["lg-sotf"], "resolve_transition": "Done", "priority_map": {}}
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


async def redis_state(client: aioredis.Redis) -> Dict[bytes, Any]:
    """Every key's value (``DUMP``); for a stream its length, last id, groups and pending entries."""
    state: Dict[bytes, Any] = {}
    for key in sorted(await client.keys("*")):
        if await client.type(key) != b"stream":
            state[key] = await client.dump(key)
            continue
        info = await client.xinfo_stream(key)
        groups = await client.xinfo_groups(key)
        state[key] = (
            info["length"], info["last-generated-id"],
            [(g["name"], g["pending"], g["last-delivered-id"], await client.xpending(key, g["name"])) for g in groups],
        )
    return state


async def seed_stream(client: aioredis.Redis, prefix: str) -> None:
    """A work stream with a consumer group and one pending entry, as a running worker leaves it."""
    stream = f"{prefix}:probe:stream"
    await client.xadd(stream, {"alert_id": "a1"})
    await client.xgroup_create(stream, "workers", id="0")
    await client.xreadgroup("workers", "worker-1", {stream: ">"}, count=1)


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
        TENANT_A, verdict_key_of(alert), decision="false_positive", alert_id="earlier", escalation_id=None
    )
    network = forbid_network(monkeypatch)
    connector_calls = record_connector_calls(monkeypatch)
    await seed_stream(redis_client, settings.redis.key_prefix)
    pubsub = redis_client.pubsub()
    await pubsub.psubscribe("*")
    redis_before = await redis_state(redis_client)
    before = await snapshot(db, alert_id)

    outcome = await ShadowRunner(engine.node_deps).run(TENANT_A, alert_id)

    # It ran the real pipeline: a confident malicious verdict and a response plan, then it stopped.
    assert outcome.run_id.startswith("shadow/")
    assert outcome.state["decision"]["route"] == "plan_response"
    assert outcome.interrupt == {"type": "analyst_decision", "escalation_id": "shadow"}
    # Nothing left the system: no connector call, HTTP request, mail, WebSocket event or Redis write...
    assert connector_calls == [] and network == [] and events.events == []
    assert await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2) is None
    assert await redis_state(redis_client) == redis_before
    assert await verdicts.get(TENANT_A, verdict_key_of(alert)) is not None
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
        with pytest.raises(SystemScopeDenied):  # the shadow role cannot bypass isolation (AI-E1.5c)
            async with db.system_tx() as conn:
                await conn.execute("UPDATE tenants SET name = 'changed' WHERE id = $1", TENANT_A)
        # A transaction retried after a stale cached statement is a new transaction: read only too.
        attempts: List[str] = []

        async def stale_then_write(conn: Any) -> None:
            attempts.append("attempt")
            if len(attempts) == 1:
                raise InvalidCachedStatementError("cached statement plan is invalid")
            await conn.execute("UPDATE tenants SET name = 'changed' WHERE id = $1", TENANT_A)

        with pytest.raises(ReadOnlySQLTransactionError):
            await db.run_tenant_tx(TENANT_A, stale_then_write)
        assert attempts == ["attempt", "attempt"]
    tenant = await repos.tenants.get(TENANT_A)
    assert tenant.name == "Tenant A" and not tenant.settings


async def test_every_boundary_diverts_when_called_directly(
    engine_factory: Any, engine_settings: Settings, repos: Repositories, db: Database, redis_client: aioredis.Redis,
) -> None:
    """Each boundary, called in a shadow run with real collaborators built live beforehand, does nothing.

    The collaborators are the production ones: the alert, suppression, sighting, trace and outbox repositories,
    the verdict cache and the event bus on a plain Redis client, a guarded HTTP client built before the run (the
    per-request check, not the construction check, must stop it), Slack and Jira over the integrations HTTP
    stack. Every call must leave the database and Redis as they were, reach no receiver, and be in the sink.
    """
    engine: WorkflowEngine = await engine_factory()
    settings, prefix = engine_settings, engine_settings.redis.key_prefix
    alert_id = await make_alert(repos, TENANT_A, title="Beacon", severity="high", normalized={"entities": {}})
    rule = await repos.suppressions.create(TENANT_A, "noisy", {"title": "Beacon"})
    integration = await add_integration(repos, SecretBox.from_settings(settings), TENANT_A, "slack",
                                        secret={"webhook_url": slack_url()})
    verdicts = VerdictCache(redis_client, prefix)
    await verdicts.put_analyst_benign(TENANT_A, "fp-old", decision="false_positive", alert_id="a0", escalation_id=None)
    await seed_stream(redis_client, prefix)
    bus = EventBus(redis_client, settings)
    receiver = Receiver()
    prebuilt = guarded_client(
        policy=egress_policy(settings), verify=True, user_agent="test", timeout=httpx.Timeout(5.0),
        transport=httpx.MockTransport(receiver), resolver=public_resolver, pin=False,
    )
    slack = receiver.http(settings)
    jira = JiraClient(receiver.http(settings), JIRA_CONFIG, {"api_token": fake_secret()})
    entry = NewOutboxEntry(integration_id=integration.id, event_id=uuid4(), event_type="escalation.created",
                           operation="notify", dedupe_key="probe", alert_id=alert_id)
    step = NewTraceStep(agent="analysis", kind="tool", tool="history", input_hash="0" * 64, outcome="success",
                        started_at=datetime.now(UTC))
    pubsub = redis_client.pubsub()
    await pubsub.psubscribe("*")
    redis_before, before = await redis_state(redis_client), await snapshot(db, alert_id)

    with shadow_scope(ShadowRun("shadow/direct")) as run:
        assert await repos.alerts.update(TENANT_A, alert_id, confidence=99.0) is None
        assert await repos.alerts.update_status(TENANT_A, alert_id, "processing") is None
        assert await repos.alert_events.append(TENANT_A, alert_id, "probe", data={"x": 1}) is None
        assert await repos.suppressions.record_hit(TENANT_A, rule.id) is None
        assert await repos.indicators.add_sightings(
            TENANT_A, alert_id, [("ip", "0" * 64, "203.0.113.x", datetime.now(UTC))]
        ) == 0
        assert await repos.investigation_steps.append(TENANT_A, alert_id, "shadow/direct", [step]) == 1
        async with db.tenant_tx(TENANT_A) as conn:
            assert await enqueue_on(conn, TENANT_A, [entry]) == 0
        with pytest.raises(ShadowEgressRefused):
            await repos.outbox.record_test(TENANT_A, entry, ok=True, error=None, result=None)
        assert await verdicts.put_analyst_benign(
            TENANT_A, "fp-new", decision="false_positive", alert_id=alert_id, escalation_id=None
        ) is False
        assert await verdicts.invalidate(TENANT_A, "fp-old") is False
        with pytest.raises(ShadowEgressRefused):
            await verdicts.clear_tenant(TENANT_A)
        await bus.publish(TENANT_A, {"type": "alert.updated", "alert_id": alert_id, "data": {}})
        await publish_event(bus, "alert.updated", TENANT_A, alert_id, {"node": "probe"})
        with pytest.raises(ShadowEgressRefused):
            await prebuilt.get("https://hooks.slack.com/services/T1/B1/x")
        with pytest.raises(ShadowEgressRefused):
            await slack.request("POST", slack_url(), json_body={"text": "probe"})
        with pytest.raises(ShadowEgressRefused):
            await jira.create(TicketDraft(summary="probe", lines=[], severity="high", correlation="lgsotf-probe"))
        assert await engine.node_deps.responses.execute(TENANT_A, alert_id, [str(uuid4())]) == {}
        safe = ShadowSafeRedis(connection_pool=redis_client.connection_pool)
        assert await safe.hgetall(verdicts.key(TENANT_A, "fp-old"))
        with pytest.raises(ShadowEgressRefused):
            await safe.set(f"{prefix}:probe", b"x")
        with pytest.raises(ShadowEgressRefused):
            safe.pipeline()

    await prebuilt.aclose()
    assert receiver.requests == []
    assert await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2) is None
    await pubsub.aclose()
    assert await redis_state(redis_client) == redis_before
    assert await snapshot(db, alert_id) == before
    assert (await repos.suppressions.get(TENANT_A, rule.id)).hit_count == rule.hit_count
    assert run.trace == [step]
    done = {(e.operation, e.outcome) for e in run.sink.effects}
    assert done >= {
        ("AlertsRepo.update", "sunk"), ("AlertsRepo.update_status", "sunk"), ("AlertEventsRepo.append", "sunk"),
        ("SuppressionsRepo.record_hit", "sunk"), ("IndicatorsRepo.add_sightings", "sunk"),
        ("InvestigationStepsRepo.append", "sunk"), ("enqueue_on", "sunk"), ("OutboxRepo.record_test", "refused"),
        ("VerdictCache.put_analyst_benign", "sunk"), ("VerdictCache.invalidate", "sunk"),
        ("VerdictCache.clear_tenant", "refused"), ("EventBus.publish", "sunk"), ("publish_event", "sunk"),
        ("GuardedTransport.handle_async_request", "refused"), ("guarded_client", "refused"),
        ("ResponseService.execute", "sunk"), ("Redis SET", "refused"), ("Redis pipeline", "refused"),
    }, done


async def test_the_shadow_runner_reads_redis_through_a_write_refusing_client(
    engine_factory: Any, redis_client: aioredis.Redis
) -> None:
    """Whatever client production injected (here a plain one), the shadow graph's Redis refuses writes."""
    engine: WorkflowEngine = await engine_factory()
    runner = ShadowRunner(engine.node_deps)
    assert runner.deps.budget is None
    shadow_redis = runner.deps.verdicts.redis
    key = f"{engine.settings.redis.key_prefix}:probe"
    await redis_client.set(key, b"live")
    with shadow_scope(ShadowRun("shadow/redis")):
        assert await shadow_redis.get(key) == b"live"
        with pytest.raises(ShadowEgressRefused):
            await shadow_redis.set(key, b"shadow")
        with pytest.raises(ShadowEgressRefused):
            await shadow_redis.delete(key)
    assert await redis_client.get(key) == b"live"


async def test_a_shadow_run_refuses_to_start_without_the_shadow_role(
    engine_factory: Any, repos: Repositories, db: Database, migrated_database_url: str
) -> None:
    """AI-E1.5c: no ``database.shadow_url``, no shadow run; it never runs on the runtime role instead."""
    engine: WorkflowEngine = await engine_factory()
    alert_id = await make_alert(repos, TENANT_A, title="x", severity="low")
    runtime_only = Database(db_settings(migrated_database_url, pool_min=0, pool_max=2), application_name="no-shadow")
    await runtime_only.open()
    try:
        deps = dataclasses.replace(engine.node_deps, repos=Repositories.create(runtime_only))
        with pytest.raises(ShadowRoleRequired, match="database.shadow_url"):
            await ShadowRunner(deps).run(TENANT_A, alert_id)
    finally:
        await runtime_only.close()
    async with db.tenant_tx(TENANT_A) as conn:
        assert await conn.fetchval("SELECT count(*) FROM shadow_effects") == 0


async def model_closed(repos: Repositories, entities: Dict[str, List[str]]) -> str:
    """An alert the models closed alone, as decision policy v3 leaves it (close reason ``ai_closed:audit_required``)."""
    alert_id = await make_alert(repos, TENANT_A, title="Package installed", severity="low",
                                normalized={"entities": entities})
    for status in ("queued", "processing", "closed"):
        await repos.alerts.update_status(TENANT_A, alert_id, status)
    await repos.alerts.update(TENANT_A, alert_id, disposition="benign",
                              summary={"close_reason": closure.MODEL_CLOSE_REASON})
    return alert_id


def reopen_counters() -> List[float]:
    return [counter.labels(path=path)._value.get()
            for counter in (RETRO_REOPEN_FAILURES, RETRO_REOPENED) for path in ("workflow", "escalation")]


async def test_a_shadow_run_of_a_threat_reopens_nothing_and_enqueues_nothing(
    engine_factory: Any, engine_settings: Settings, repos: Repositories, db: Database, redis_client: aioredis.Redis,
) -> None:
    """Decision policy v3 (FIX-3) in a shadow run: the safety net is recorded, never run.

    Live, the alert below (a model judges it a threat: a response plan, then an escalation) reopens the related
    alert the models closed alone and queues a run for it (the control at the end). The shadow run of it reopens
    nothing, enqueues nothing, counts no reopen and no reopen failure, and only ``shadow_effects`` grows. The two
    writes of the policy a shadow graph does not reach, the run message of a requeued alert and the settling of a
    folded one, are refused when called in a shadow run.
    """
    settings = engine_settings.model_copy(
        update={"routing": {**dict(engine_settings.routing or {}), "response_threshold": 0}}
    )
    engine: WorkflowEngine = await engine_factory(settings=settings)
    related = await model_closed(repos, {"hosts": ["ws-042"]})
    queued = await make_alert(repos, TENANT_A, title="Requeued for review", severity="low")
    await repos.alerts.update_status(TENANT_A, queued, "queued")
    folded, case = await model_closed(repos, {"hosts": ["db-01"]}), str(uuid4())
    await repos.alerts.update_status(TENANT_A, folded, "waiting_human")
    await repos.alerts.update(TENANT_A, folded, summary={"reopened": {"mode": "folded"}, "escalation_id": case})
    threat = await make_alert(
        repos, TENANT_A, title="Possible C2 beacon from workstation", severity="critical",
        normalized={"entities": SUSPICIOUS_ENTITIES}, raw={"vendor": "edr"},
    )
    await seed_stream(redis_client, settings.redis.key_prefix)
    redis_before, counters = await redis_state(redis_client), reopen_counters()
    before, folded_before = await snapshot(db, related), await snapshot(db, folded)

    outcome = await ShadowRunner(engine.node_deps).run(TENANT_A, threat)

    # A model judged it a threat, on both workflow paths of the safety net: the response plan and the escalation.
    assert outcome.state["decision"]["route"] == "plan_response"
    assert judged_threat(outcome.state.get("triage") or {}, outcome.state.get("analysis") or {})
    assert outcome.interrupt == {"type": "analyst_decision", "escalation_id": "shadow"}
    reopens = [(e.operation, e.outcome, e.detail) for e in outcome.effects if e.boundary == "retro_reopen"]
    assert reopens == [("reopen_counted", "sunk", {"path": "workflow"}), ("reopen_counted", "sunk", {"path": "escalation"})]
    assert all(e.outcome == "sunk" for e in outcome.effects)
    # Nothing reopened: no alert change, run, event or audit entry, no run message, no counter moved.
    after = await snapshot(db, related)
    assert after["alert"] == before["alert"] and after["alert"]["status"] == "closed"
    assert after["counts"] == {**before["counts"], "shadow_effects": len(outcome.effects)}
    assert await redis_state(redis_client) == redis_before
    assert reopen_counters() == counters

    # Called in a shadow run all the same: the queue refuses the run message, the database the settle.
    with shadow_scope(ShadowRun("shadow/direct")) as direct:
        assert await enqueue_requeued(repos, engine.node_deps.queue, TENANT_A, [queued]) == 0
        with pytest.raises(ReadOnlySQLTransactionError):
            await settle_folded(repos, TENANT_A, folded, escalation_id=case, decision="true_positive",
                                decided_by="analyst-1")
    assert ("queue", "WorkQueue._add", "refused") in [(e.boundary, e.operation, e.outcome) for e in direct.sink.effects]
    assert await redis_state(redis_client) == redis_before
    assert await snapshot(db, folded) == {**folded_before, "counts": after["counts"]}

    # Control: live, the same alert reopens the related alert and queues a run for it.
    await engine.run(TENANT_A, threat)
    reopened = await repos.alerts.get(TENANT_A, related)
    assert (reopened.status, reopened.summary["reopened"]["mode"]) == ("queued", "requeued")
    assert await redis_state(redis_client) != redis_before
    assert reopen_counters()[2] == counters[2] + 1
