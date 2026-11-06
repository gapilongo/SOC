"""WorkflowEngine against real Postgres (checkpoints included), real Redis and the fake LLM."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import NewAlert, Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.errors import InvalidResumePayload
from lg_sotf.services.connectors.dry_run import DryRunConnector
from lg_sotf.services.response import ResponseService
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine.conftest import RecordingEvents

pytestmark = pytest.mark.integration

SUSPICIOUS_ENTITIES = {
    "ips": ["185.220.101.44", "10.0.0.5"],
    "hosts": ["ws-042"],
    "users": ["jdoe"],
    "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
    "processes": ["powershell.exe"],
}


async def benign_alert(repos: Repositories, tenant_id: str = TENANT_A, **kwargs: Any) -> str:
    return await make_alert(
        repos,
        tenant_id,
        title="Scheduled backup maintenance test job",
        severity="low",
        normalized={"entities": {"hosts": ["backup-01"]}},
        **kwargs,
    )


async def suspicious_alert(repos: Repositories, tenant_id: str = TENANT_A, **kwargs: Any) -> str:
    return await make_alert(
        repos,
        tenant_id,
        title="Possible C2 beacon from workstation",
        severity="medium",
        normalized={"entities": SUSPICIOUS_ENTITIES},
        raw={"vendor": "edr"},
        **kwargs,
    )


def count_calls(monkeypatch: pytest.MonkeyPatch, obj: Any, name: str) -> List[int]:
    calls: List[int] = []
    original = getattr(obj, name)

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return await original(*args, **kwargs)

    monkeypatch.setattr(obj, name, spy)
    return calls


async def analyst(repos: Repositories, tenant_id: str = TENANT_A) -> str:
    user = await repos.users.create(tenant_id, f"analyst-{uuid4().hex[:8]}@example.com", "analyst")
    return str(user.id)


async def decide(
    engine: WorkflowEngine, repos: Repositories, alert_id: str, escalation_id: str, decision: str, user_id: str,
    tenant_id: str = TENANT_A, **extra: Any,
):
    """What the API does: record the decision with the analyst's version, then resume."""
    esc = await repos.escalations.get(tenant_id, escalation_id)
    await repos.escalations.decide(
        tenant_id, escalation_id, decision=decision, decided_by=UUID(user_id),
        expected_version=esc.version,
    )
    payload: Dict[str, Any] = {
        "type": "analyst_decision",
        "escalation_id": escalation_id,
        "decision": decision,
        "approved_actions": [],
        "decided_by": user_id,
        "notes": "",
    }
    payload.update(extra)
    return await engine.resume(tenant_id, alert_id, payload)


async def test_benign_alert_is_closed(engine: WorkflowEngine, repos: Repositories, events: RecordingEvents) -> None:
    alert_id = await benign_alert(repos)

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "completed" and outcome.alert_status == "closed" and outcome.interrupt is None
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "benign")
    assert alert.closed_at is not None
    assert alert.summary["verdict"] == "benign" and alert.summary["close_reason"] == "triage:false_positive"
    nodes = [e.node for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items]
    assert nodes == ["gate", "triage", "close"]
    assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is None
    statuses = [e["data"].get("status") for e in events.of_type("alert.updated")]
    assert "processing" in statuses and "closed" in statuses


async def test_suspicious_alert_full_lifecycle(
    engine: WorkflowEngine, repos: Repositories, events: RecordingEvents
) -> None:
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)

    first = await engine.run(TENANT_A, alert_id)
    assert first.status == "waiting_human"
    escalation_id = first.interrupt["escalation_id"]
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"
    assert events.of_type("escalation.created")

    second = await decide(engine, repos, alert_id, escalation_id, "true_positive", user_id)
    assert second.status == "waiting_approval" and second.alert_status == "waiting_approval"
    pending = second.interrupt["action_ids"]
    actions = {str(a.id): a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    by_type = {(a.action_type, a.target): a for a in actions.values()}
    assert by_type[("block_ip", "10.0.0.5")].status == "blocked"
    assert by_type[("block_ip", "10.0.0.5")].blocked_reason == "non_public_ip"
    assert by_type[("block_ip", "185.220.101.44")].status == "awaiting_approval"
    assert set(pending) == {i for i, a in actions.items() if a.status == "awaiting_approval"}

    approve = [str(by_type[("block_ip", "185.220.101.44")].id), str(by_type[("create_ticket", f"alert:{alert_id}")].id)]
    reject = [str(by_type[("isolate_host", "ws-042")].id)]
    third = await engine.resume(
        TENANT_A,
        alert_id,
        {"type": "approval", "approved_action_ids": approve, "rejected_action_ids": reject, "decided_by": user_id},
    )
    leftover_ids = [i for i in pending if i not in approve + reject]
    assert third.status == "waiting_approval" and set(third.interrupt["action_ids"]) == set(leftover_ids)

    fourth = await engine.resume(
        TENANT_A,
        alert_id,
        {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": user_id,
         "reject_remaining": True},
    )
    assert fourth.status == "completed" and fourth.alert_status == "closed"

    final = {str(a.id): a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    for action_id in approve:
        assert final[action_id].status == "dry_run"
        assert final[action_id].connector == "dry_run"
        assert final[action_id].approved_by == user_id
        assert final[action_id].result["would_execute"] == final[action_id].action_type
    assert final[reject[0]].status == "rejected"
    leftovers = [final[i] for i in leftover_ids]
    assert leftovers and all(a.status == "rejected" for a in leftovers)

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "malicious")
    assert alert.summary["analyst_decision"] == "true_positive"
    tools = alert.summary["analysis"]["tools"]
    assert alert.summary["analysis"]["simulated_evidence"] is bool(tools)
    assert all(t["simulated"] for t in tools)
    esc = await repos.escalations.get(TENANT_A, escalation_id)
    assert esc.status == "decided"
    audit = (await repos.audit.list(TENANT_A, resource_type="response_action", limit=200)).items
    audited = {e.action for e in audit}
    assert {"response_action.proposed", "response_action.executing", "response_action.dry_run"} <= audited
    assert {"response_action.approved", "response_action.rejected"} <= audited
    decisions = [e for e in audit if e.action in ("response_action.approved", "response_action.rejected")]
    assert decisions and all((e.actor_type, e.actor_id) == ("user", user_id) for e in decisions)
    assert (await repos.audit.verify_chain(TENANT_A)).ok
    assert events.of_type("action.updated")


async def test_tenant_autonomy_auto_executes_low_risk_before_approval(
    engine: WorkflowEngine, repos: Repositories
) -> None:
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)

    second = await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "true_positive", user_id)

    assert second.status == "waiting_approval"
    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    low = [a for a in actions if a.risk_level == "low" and a.status != "blocked"]
    assert low and all(a.status == "dry_run" for a in low)
    assert all(a.status in ("awaiting_approval", "blocked") for a in actions if a.risk_level != "low")


async def test_crash_resumes_from_checkpoint_without_rerunning_triage(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await suspicious_alert(repos)
    triage_calls = count_calls(monkeypatch, engine.agents.triage, "run")
    original = engine.agents.correlation.run
    correlation_calls: List[int] = []

    async def flaky(*args: Any, **kwargs: Any) -> Any:
        correlation_calls.append(1)
        if len(correlation_calls) == 1:
            raise RuntimeError("correlation crashed")
        return await original(*args, **kwargs)

    monkeypatch.setattr(engine.agents.correlation, "run", flaky)

    with pytest.raises(RuntimeError, match="correlation crashed"):
        await engine.run(TENANT_A, alert_id)
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "failed"
    snapshot = await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_A, alert_id)}})
    assert snapshot.next == ("correlation",)

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "waiting_human"
    assert len(triage_calls) == 1
    assert len(correlation_calls) == 2


async def test_transient_error_is_retried_inside_the_node(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await benign_alert(repos)
    original = engine.agents.triage.run
    calls: List[int] = []

    async def flaky(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionResetError("network blip")
        return await original(*args, **kwargs)

    monkeypatch.setattr(engine.agents.triage, "run", flaky)

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.alert_status == "closed" and len(calls) == 2


async def test_needs_more_info_returns_to_analysis_at_most_once(
    engine: WorkflowEngine, repos: Repositories, redis_client: Any, engine_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    analysis_calls = count_calls(monkeypatch, engine.agents.analysis, "run")

    first = await engine.run(TENANT_A, alert_id)
    assert len(analysis_calls) == 1
    second = await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "needs_more_info", user_id)
    assert second.status == "waiting_human" and len(analysis_calls) == 2
    assert second.interrupt["escalation_id"] != first.interrupt["escalation_id"]
    third = await decide(engine, repos, alert_id, second.interrupt["escalation_id"], "needs_more_info", user_id)
    assert third.status == "waiting_human" and len(analysis_calls) == 2
    final = await decide(engine, repos, alert_id, third.interrupt["escalation_id"], "false_positive", user_id)

    assert final.alert_status == "closed"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition == "benign" and alert.summary["close_reason"] == "analyst:false_positive"
    key = f"{engine_settings.redis.key_prefix}:t:{TENANT_A}:verdict:{alert.fingerprint}"
    assert await redis_client.exists(key) == 1
    assert 0 < await redis_client.ttl(key) <= 7 * 24 * 3600


async def test_verdict_cache_closes_repeats_but_never_critical(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)
    await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "benign_positive", user_id)
    fingerprint = (await repos.alerts.get(TENANT_A, alert_id)).fingerprint
    triage_calls = count_calls(monkeypatch, engine.agents.triage, "run")

    async def repeat(severity: str) -> str:
        row = NewAlert(
            source_id="splunk-prod", source_alert_id=uuid4().hex, fingerprint=fingerprint, title="Possible C2 beacon",
            severity=severity, occurred_at=datetime.now(UTC), normalized={"entities": SUSPICIOUS_ENTITIES},
        )
        return (await repos.alerts.insert_many_if_absent(TENANT_A, [row]))[0]

    medium = await repeat("medium")
    assert (await engine.run(TENANT_A, medium)).alert_status == "closed"
    closed = await repos.alerts.get(TENANT_A, medium)
    assert closed.summary["suppressed_by"]["type"] == "verdict_cache" and not triage_calls

    critical = await repeat("critical")
    await engine.run(TENANT_A, critical)
    assert triage_calls, "critical alerts must never be closed from the verdict cache"


async def test_suppression_rule_closes_before_triage(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = await repos.suppressions.create(
        TENANT_A, "known scanner", {"title": {"regex": "Known scanner .{0,40}"}, "entities.ips": {"cidr": "10.0.0.0/8"}}
    )
    triage_calls = count_calls(monkeypatch, engine.agents.triage, "run")
    alert_id = await make_alert(
        repos, TENANT_A, title="Known scanner sweep", severity="high", normalized={"entities": {"ips": ["10.1.2.3"]}}
    )

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.alert_status == "closed" and not triage_calls
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition == "benign"
    assert alert.summary["suppressed_by"] == {"type": "suppression_rule", "rule_id": rule.id, "name": "known scanner"}
    assert (await repos.suppressions.get(TENANT_A, rule.id)).hit_count == 1


async def test_escalate_is_idempotent_when_the_node_reruns(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await suspicious_alert(repos)
    original = engine.repos.alert_events.append
    failed: List[int] = []

    async def fail_after_escalate(tenant_id: str, a_id: str, event_type: str, **kwargs: Any) -> Any:
        if kwargs.get("node") == "escalate" and not failed:
            failed.append(1)
            raise RuntimeError("crash after the escalation was written")
        return await original(tenant_id, a_id, event_type, **kwargs)

    monkeypatch.setattr(engine.repos.alert_events, "append", fail_after_escalate)

    with pytest.raises(RuntimeError):
        await engine.run(TENANT_A, alert_id)
    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "waiting_human"
    escalations = (await repos.escalations.list(TENANT_A, alert_id=alert_id)).items
    assert len(escalations) == 1 and escalations[0].id == outcome.interrupt["escalation_id"]


async def test_same_alert_id_in_two_tenants_is_isolated(
    engine: WorkflowEngine, repos: Repositories, events: RecordingEvents
) -> None:
    shared_id = "shared-alert-1"
    await benign_alert(repos, TENANT_A, id=shared_id)
    await suspicious_alert(repos, TENANT_B, id=shared_id)

    a = await engine.run(TENANT_A, shared_id)
    b = await engine.run(TENANT_B, shared_id)

    assert a.alert_status == "closed" and b.status == "waiting_human"
    assert (await repos.alerts.get(TENANT_A, shared_id)).status == "closed"
    assert (await repos.alerts.get(TENANT_B, shared_id)).status == "waiting_human"
    assert await repos.escalations.get_active_for_alert(TENANT_A, shared_id) is None
    assert await repos.escalations.get_active_for_alert(TENANT_B, shared_id) is not None
    state_a = await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_A, shared_id)}})
    state_b = await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_B, shared_id)}})
    assert state_a.values["tenant_id"] == TENANT_A and state_b.values["tenant_id"] == TENANT_B
    assert not await repos.indicators.sightings_for_alert(TENANT_A, shared_id)
    assert await repos.indicators.sightings_for_alert(TENANT_B, shared_id)
    assert all(e["tenant_id"] in (TENANT_A, TENANT_B) for e in events.events)


async def test_resume_rejects_mismatched_payloads(engine: WorkflowEngine, repos: Repositories) -> None:
    alert_id = await suspicious_alert(repos)
    first = await engine.run(TENANT_A, alert_id)

    with pytest.raises(InvalidResumePayload):
        await engine.resume(
            TENANT_A, alert_id, {"type": "approval", "approved_action_ids": [], "rejected_action_ids": [], "decided_by": "x"}
        )
    with pytest.raises(InvalidResumePayload):
        await engine.resume(
            TENANT_A,
            alert_id,
            {"type": "analyst_decision", "escalation_id": "other", "decision": "true_positive",
             "approved_actions": [], "decided_by": "x", "notes": ""},
        )
    with pytest.raises(InvalidResumePayload):
        await engine.resume(TENANT_A, alert_id, {"type": "analyst_decision", "decision": "maybe"})
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"
    assert (await engine.run(TENANT_A, alert_id)).interrupt == first.interrupt


async def test_redelivered_run_of_a_finished_alert_is_a_no_op(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await benign_alert(repos)
    await engine.run(TENANT_A, alert_id)
    triage_calls = count_calls(monkeypatch, engine.agents.triage, "run")

    again = await engine.run(TENANT_A, alert_id)

    assert again.status == "completed" and again.alert_status == "closed" and not triage_calls


async def test_reprocess_starts_a_fresh_run(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await benign_alert(repos)
    await engine.run(TENANT_A, alert_id)
    await repos.alerts.update_status(TENANT_A, alert_id, "queued")
    triage_calls = count_calls(monkeypatch, engine.agents.triage, "run")

    again = await engine.run(TENANT_A, alert_id)

    assert again.alert_status == "closed" and len(triage_calls) == 1


@pytest.mark.parametrize("decided_by_kind", ["user_id", "external"])
async def test_resume_closes_an_escalation_the_api_left_open(
    engine: WorkflowEngine, repos: Repositories, decided_by_kind: str
) -> None:
    alert_id = await suspicious_alert(repos)
    decided_by = await analyst(repos) if decided_by_kind == "user_id" else "soar-integration"
    first = await engine.run(TENANT_A, alert_id)
    escalation_id = first.interrupt["escalation_id"]

    outcome = await engine.resume(
        TENANT_A,
        alert_id,
        {"type": "analyst_decision", "escalation_id": escalation_id, "decision": "false_positive",
         "approved_actions": [], "decided_by": decided_by, "notes": "known admin tooling"},
    )

    assert outcome.alert_status == "closed"
    esc = await repos.escalations.get(TENANT_A, escalation_id)
    assert esc.status == ("decided" if decided_by_kind == "user_id" else "cancelled")
    audit = (await repos.audit.list(TENANT_A, resource_type="escalation", resource_id=escalation_id)).items
    assert {e.action for e in audit} >= {"escalation.created"}
    assert len(audit) == 2


async def _approve(engine: WorkflowEngine, alert_id: str, user_id: str, approved: List[str], rejected: Optional[List[str]] = None) -> Any:
    return await engine.resume(
        TENANT_A,
        alert_id,
        {"type": "approval", "approved_action_ids": list(approved), "rejected_action_ids": list(rejected or []),
         "decided_by": user_id},
    )


async def test_actions_can_be_approved_one_at_a_time(engine: WorkflowEngine, repos: Repositories) -> None:
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)
    second = await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "true_positive", user_id)
    pending = list(second.interrupt["action_ids"])
    assert len(pending) >= 3

    outcome = second
    for index, action_id in enumerate(pending):
        if index % 2:
            outcome = await _approve(engine, alert_id, user_id, [], [action_id])
        else:
            outcome = await _approve(engine, alert_id, user_id, [action_id])
        remaining = pending[index + 1:]
        if remaining:
            assert outcome.status == "waiting_approval" and outcome.interrupt["action_ids"] == remaining
            assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_approval"

    assert outcome.status == "completed" and outcome.alert_status == "closed"
    final = {str(a.id): a.status for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    assert [final[i] for i in pending] == ["dry_run" if i % 2 == 0 else "rejected" for i in range(len(pending))]
    stale = await _approve(engine, alert_id, user_id, [pending[1]])
    assert stale.status == "completed" and final[pending[1]] == "rejected"


async def test_approvals_committed_while_the_run_executes_are_all_executed(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Approvals land between execute() and the awaiting() re-read, on two passes: every one still runs once."""
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)
    second = await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "true_positive", user_id)
    pending = list(second.interrupt["action_ids"])
    assert len(pending) >= 3
    # The worker's run row (the engine alone keeps none): the run is live, so approvals stay the run's work
    # (an approval for an ended or missing run goes to the scheduler instead).
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    review = ReviewService(repos, engine_settings)
    late = [[pending[1]], pending[2:]]
    original = ResponseService.awaiting

    async def approve_meanwhile(self: ResponseService, *args: Any, **kwargs: Any) -> Any:
        if late:
            await review.approve_actions(TENANT_A, late.pop(0), user_id, "admin")
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(ResponseService, "awaiting", approve_meanwhile)
    outcome = await _approve(engine, alert_id, user_id, [pending[0]])

    assert not late
    assert outcome.status == "completed" and outcome.alert_status == "closed"
    final = {str(a.id): a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items}
    assert all(final[i].status == "dry_run" for i in pending)
    audited = [
        e.resource_id
        for e in (await repos.audit.list(TENANT_A, resource_type="response_action", limit=200)).items
        if e.action == "response_action.executing"
    ]
    assert sorted(i for i in audited if i in pending) == sorted(pending)
    stale = await _approve(engine, alert_id, user_id, pending[1:])
    assert stale.status == "completed"


async def test_alert_at_ingestion_size_limits_runs_to_completion(engine: WorkflowEngine, repos: Repositories) -> None:
    entities = {
        "urls": [f"https://cdn{i}.example.com/" + "u" * 700 for i in range(50)],
        "command_lines": [f"powershell -nop -enc {i} " + "c" * 4_000 for i in range(9)],
        "ips": ["185.220.101.44"],
        "hosts": ["ws-042"],
    }
    alert_id = await make_alert(
        repos, TENANT_A, title="Encoded PowerShell with many downloads", severity="medium",
        normalized={"entities": entities, "description": "d" * 8_000},
    )

    outcome = await asyncio.wait_for(engine.run(TENANT_A, alert_id), timeout=60)

    assert outcome.status in ("waiting_human", "completed")
    snapshot = await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_A, alert_id)}})
    state_alert = snapshot.values["alert"]
    assert state_alert["_entities_truncated"] is True
    assert state_alert["entities"]["ips"] == ["185.220.101.44"] and state_alert["entities"]["hosts"] == ["ws-042"]


async def test_crash_after_close_committed_is_finished_on_redelivery(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch, events: RecordingEvents,
    redis_client: Any, engine_settings: Any,
) -> None:
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)
    original = engine.repos.alert_events.append
    failed: List[int] = []

    async def fail_close_once(tenant_id: str, a_id: str, event_type: str, **kwargs: Any) -> Any:
        if kwargs.get("node") == "close" and not failed:
            failed.append(1)
            raise RuntimeError("crash after close committed")
        return await original(tenant_id, a_id, event_type, **kwargs)

    monkeypatch.setattr(engine.repos.alert_events, "append", fail_close_once)

    with pytest.raises(RuntimeError, match="close committed"):
        await decide(engine, repos, alert_id, first.interrupt["escalation_id"], "benign_positive", user_id)
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "closed"

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "completed" and outcome.alert_status == "closed"
    nodes = [e.node for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id, limit=100)).items]
    assert nodes.count("close") == 1
    assert any(e["data"].get("status") == "closed" and e["data"].get("node") == "close" for e in events.of_type("alert.updated"))
    fingerprint = (await repos.alerts.get(TENANT_A, alert_id)).fingerprint
    assert await redis_client.exists(f"{engine_settings.redis.key_prefix}:t:{TENANT_A}:verdict:{fingerprint}") == 1
    snapshot = await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_A, alert_id)}})
    assert snapshot.next == ()


async def test_action_left_executing_by_a_crash_is_finished(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    alert_id = await suspicious_alert(repos)
    user_id = await analyst(repos)
    first = await engine.run(TENANT_A, alert_id)
    original = engine.repos.actions.transition
    failed: List[int] = []

    async def crash_once(tenant_id: str, action_id: UUID, to_status: str, **kwargs: Any) -> Any:
        if to_status == "dry_run" and not failed:
            failed.append(1)
            raise RuntimeError("worker died mid-execution")
        return await original(tenant_id, action_id, to_status, **kwargs)

    monkeypatch.setattr(engine.repos.actions, "transition", crash_once)
    payload = {"type": "analyst_decision", "escalation_id": first.interrupt["escalation_id"], "decision": "true_positive",
               "approved_actions": [], "decided_by": user_id, "notes": ""}

    with pytest.raises(RuntimeError, match="mid-execution"):
        await engine.resume(TENANT_A, alert_id, payload)
    stuck = [a for a in (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items if a.status == "executing"]
    assert len(stuck) == 1

    outcome = await engine.resume(TENANT_A, alert_id, payload)

    assert outcome.status == "waiting_approval"
    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    assert not [a for a in actions if a.status == "executing"]
    assert next(a for a in actions if a.id == stuck[0].id).status == "dry_run"


async def _policy_response_alert(engine_factory: Any, engine_settings: Settings, repos: Repositories) -> tuple[WorkflowEngine, str]:
    settings = engine_settings.model_copy(update={"routing": {**dict(engine_settings.routing or {}), "response_threshold": 0}})
    engine = await engine_factory(settings=settings)
    await repos.tenants.update_settings(TENANT_A, {"autonomy": {"low": "auto"}})
    alert_id = await make_alert(repos, TENANT_A, title="Unusual outbound traffic volume", severity="medium",
                                normalized={"entities": {}})
    return engine, alert_id


async def test_policy_response_with_only_dry_run_actions_closes_malicious(
    engine_factory: Any, engine_settings: Settings, repos: Repositories
) -> None:
    """The tenant runs in dry-run mode: the dry-run actions are the completed response."""
    engine, alert_id = await _policy_response_alert(engine_factory, engine_settings, repos)

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "completed" and outcome.alert_status == "closed"
    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    assert actions and {a.status for a in actions} == {"dry_run"}
    assert await repos.escalations.get_active_for_alert(TENANT_A, alert_id) is None
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.disposition == "malicious"
    assert alert.summary["close_reason"] == "policy:response"
    assert alert.summary["dry_run"] is True and alert.summary["actions"] == {"dry_run": len(actions)}


async def test_policy_response_with_a_failed_action_goes_to_an_analyst(
    engine_factory: Any, engine_settings: Settings, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, alert_id = await _policy_response_alert(engine_factory, engine_settings, repos)

    async def fail(self: DryRunConnector, action: Any) -> ConnectorResult:
        return ConnectorResult("failed", {"error": "connector_exception"})

    monkeypatch.setattr(DryRunConnector, "execute", fail)

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "waiting_human" and outcome.alert_status == "waiting_human"
    actions = (await repos.actions.list(TENANT_A, alert_id=alert_id, limit=50)).items
    assert actions and {a.status for a in actions} == {"failed"}
    esc = await repos.escalations.get(TENANT_A, outcome.interrupt["escalation_id"])
    assert esc.reason == "an automatic response action failed"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status == "waiting_human" and alert.disposition is None


@pytest.mark.parametrize("severity", ["high", "critical"])
async def test_spoofed_fp_keywords_never_close_high_severity(
    engine: WorkflowEngine, repos: Repositories, severity: str
) -> None:
    alert_id = await make_alert(
        repos, TENANT_A, title="Scheduled task persistence: maintenance.exe dropped by mimikatz", severity=severity,
        normalized={"entities": {"processes": ["mimikatz.exe"]}},
        raw={"command_line": "schtasks /create /tn update /tr C:\\test\\maintenance.exe"},
    )

    outcome = await engine.run(TENANT_A, alert_id)

    assert outcome.status == "waiting_human"
    nodes = [e.node for e in (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items]
    assert nodes[:4] == ["gate", "triage", "correlation", "analysis"]
