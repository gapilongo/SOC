"""Background execution against Postgres: deferral, late and superseded approvals, TTL, orphans, leases, retry."""

from __future__ import annotations

from typing import Iterator, List
from uuid import UUID

import httpx
import pytest

from lg_sotf.db.errors import ReferenceNotFound
from lg_sotf.db.repos import Repositories, ResponseAction
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.response import ActionRequestError
from lg_sotf.services.review import ReviewService
from lg_sotf.services.rollback import RollbackService
from tests.fixtures.microsoft import defender_error
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.integrations.microsoft.conftest import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft._support import FAKE_SPECS, MACHINE_ID, script_isolation

pytestmark = pytest.mark.integration

ISO = {"defender.fake_isolation": {}}


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


async def audits(repos: Repositories, action: ResponseAction) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(action.id), limit=100)
    return [e.action for e in reversed(page.items)]


async def set_run(env: MicrosoftEnv, status: str, completed_offset_s: float = 0.0) -> None:
    alert = await env.alert()
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE workflow_runs SET status = $3, completed_at = now() + make_interval(secs => $4) "
            "WHERE tenant_id = $1 AND alert_id = $2",
            env.tenant_id, alert, status, completed_offset_s,
        )


async def user(repos: Repositories, role: str) -> UUID:
    return (await repos.users.create(TENANT_A, f"{role}-{UUID(int=len(role)).hex[:6]}@example.com", role)).id


def isolate_posts(env: MicrosoftEnv) -> List[httpx.Request]:
    return [r for r in env.fake.writes() if r.url.path.endswith("/isolate")]


async def test_deferred_execution_is_handed_to_the_scheduler(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    env.fake.route("GET", "defender", "/api/machines",
                   defender_error(429, "TooManyRequests", headers={"Retry-After": "600"}), times=1)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "executing"
    row = await env.get(action)
    assert row.execution_owner == "scheduler" and row.status == "executing" and row.attempts == 1
    assert row.result is not None and row.result["deferred"] == "throttled" and row.lease_until is not None
    assert "response_action.deferred" in await audits(env.repos, action)
    assert await env.run_background() == 0  # leased until the Retry-After ends
    await env.expire_leases()
    assert await env.run_background() == 1
    done = await env.get(action)
    assert done.status == "succeeded" and done.attempts == 2 and done.verification == "pending"
    assert len(isolate_posts(env)) == 1 and done.external_ref and done.external_ref["capability"] == "defender.fake_isolation"


async def test_late_approval_executes_exactly_once_even_during_a_reprocess(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042", status="awaiting_approval")
    await set_run(env, "completed")
    review = ReviewService(env.repos, env.settings, responses=env.service)
    admin = await user(env.repos, "admin")
    assert await review.approve_actions(TENANT_A, [action.id], admin, "admin") == []  # no run to resume
    handed = await env.get(action)
    assert handed.status == "approved" and handed.execution_owner == "scheduler"
    assert (await audits(env.repos, action))[-2:] == ["response_action.approved", "response_action.handed_off"]
    # A reprocess restarts the run: its workflow never executes the scheduler's row.
    await env.repos.runs.upsert_queued(TENANT_A, action.alert_id, requeue_terminal=True)
    assert await env.service.execute(TENANT_A, action.alert_id, [str(action.id)]) == {}
    assert await env.service.awaiting(TENANT_A, action.alert_id, [str(action.id)]) == []
    assert await env.run_background() == 1
    assert (await env.get(action)).status == "succeeded"
    assert await env.run_background() == 0
    assert await env.service.execute(TENANT_A, action.alert_id, [str(action.id)]) == {}
    assert len(isolate_posts(env)) == 1


async def test_stranded_approvals_are_handed_off_or_superseded(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    superseded = await env.propose("isolate_host", "ws-042")
    await set_run(env, "completed", completed_offset_s=60)  # the run ended after this approval, without it
    await env.run_background()
    row = await env.get(superseded)
    assert row.status == "blocked" and row.blocked_reason == "approval_superseded" and env.fake.writes() == []

    late = await env.propose("isolate_host", "ws-043")
    async with env.repos.db.system_tx() as conn:  # approved after the run ended (workflow owner kept)
        await conn.execute("UPDATE workflow_runs SET completed_at = now() - interval '1 hour' WHERE tenant_id = $1",
                           TENANT_A)
    env.fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": [{"id": MACHINE_ID}]}))
    await env.run_background()
    handed = await env.get(late)
    assert handed.execution_owner == "scheduler"
    assert "response_action.handed_off" in await audits(env.repos, late)


async def test_an_old_stranded_approval_expires_instead_of_executing(microsoft_env: MicrosoftEnvFactory) -> None:
    # A row approved weeks ago after its run had ended (1.0 never executed such rows): found after an upgrade.
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    old = await env.propose("isolate_host", "ws-042")
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET approved_at = now() - interval '21 days' WHERE id = $1", old.id)
        await conn.execute("UPDATE workflow_runs SET status = 'completed', completed_at = now() - interval '30 days' "
                           "WHERE tenant_id = $1", TENANT_A)
    await env.run_background()
    row = await env.get(old)
    assert row.status == "blocked" and row.blocked_reason == "approval_expired" and row.execution_owner == "workflow"
    assert env.fake.requests == [] and "response_action.handed_off" not in await audits(env.repos, old)
    # A recent late approval of the same kind is still handed off and executed.
    recent = await env.propose("isolate_host", "ws-043")
    env.fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": [{"id": MACHINE_ID}]}))
    await env.run_background()
    assert (await env.get(recent)).execution_owner == "scheduler"


async def test_approval_ttl_blocks_old_scheduler_approvals(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await env.propose("isolate_host", "ws-042", execution_owner="scheduler")
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET approved_at = now() - interval '2 days' WHERE id = $1", action.id)
    await env.run_background()
    row = await env.get(action)
    assert row.status == "blocked" and row.blocked_reason == "approval_expired" and env.fake.requests == []
    assert row.result is not None and row.result["guardrail"] == "approval_expired"


async def test_orphans_are_handed_off_after_the_grace_period(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    stateful = await env.propose("isolate_host", "ws-042")
    webhook = await env.propose("block_ip", "185.220.101.44")
    recent = await env.propose("isolate_host", "ws-044")
    for action, connector, minutes in ((stateful, "microsoft", 10), (webhook, "webhook", 10), (recent, "microsoft", 0)):
        async with env.repos.db.system_tx() as conn:
            await conn.execute(
                "UPDATE response_actions SET status = 'executing', connector = $2, integration_id = $3, "
                "executed_at = now() - make_interval(mins => $4) WHERE id = $1",
                action.id, connector, env.integration.id if connector == "microsoft" else None, minutes,
            )
    await set_run(env, "dead_lettered")
    assert await env.service.fail_orphaned_executing() == 2
    assert (await env.get(stateful)).execution_owner == "scheduler"
    failed = await env.get(webhook)
    assert failed.status == "failed" and failed.result is not None and failed.result["error"] == "orphaned_execution"
    assert (await env.get(recent)).execution_owner == "workflow"  # still within the grace period
    assert await env.run_background() == 1
    assert (await env.get(stateful)).status == "succeeded"


async def test_lease_recovery_and_attempts_exhausted(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    rerun = await env.propose("isolate_host", "ws-042", execution_owner="scheduler")
    exhausted = await env.propose("isolate_host", "ws-043", execution_owner="scheduler")
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'executing', connector = 'microsoft', integration_id = $2, "
            "attempts = CASE WHEN id = $3 THEN 5 ELSE 1 END, lease_until = now() - interval '1 minute' "
            "WHERE tenant_id = $1",
            TENANT_A, env.integration.id, exhausted.id,
        )
    assert await env.run_background() == 2
    assert (await env.get(rerun)).status == "succeeded"
    gave_up = await env.get(exhausted)
    assert gave_up.status == "failed" and gave_up.result is not None and gave_up.result["error"] == "attempts_exhausted"
    assert len(isolate_posts(env)) == 1


async def test_retry(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'failed', connector = 'microsoft', integration_id = $2, "
            "attempts = 5, result = $3 WHERE id = $1",
            action.id, env.integration.id, {"error": "throttled", "retryable": True},
        )
    analyst, admin = await user(env.repos, "analyst"), await user(env.repos, "admin")
    with pytest.raises(ActionRequestError) as denied:
        await env.service.retry(TENANT_A, action.id, user=analyst, role="analyst", reason="again")
    assert denied.value.status == 403
    await env.repos.tenants.update_settings(TENANT_A, {"protected_assets": {"hosts": ["ws-042"]}})
    with pytest.raises(ActionRequestError) as blocked:
        await env.service.retry(TENANT_A, action.id, user=admin, role="admin", reason="again")
    assert blocked.value.code == "guardrail_blocked" and (await env.get(action)).status == "failed"
    await env.repos.tenants.update_settings(TENANT_A, {"protected_assets": None})
    retried = await env.service.retry(TENANT_A, action.id, user=admin, role="admin", reason="again")
    assert retried.status == "executing" and retried.execution_owner == "scheduler" and retried.attempts == 0
    assert "response_action.retry_requested" in await audits(env.repos, action)
    assert await env.run_background() == 1
    assert (await env.get(action)).status == "succeeded"
    with pytest.raises(ActionRequestError) as again:
        await env.service.retry(TENANT_A, action.id, user=admin, role="admin", reason="again")
    assert again.value.code == "retry_unavailable"


async def test_retry_is_refused_while_a_rollback_of_the_action_exists(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'failed', connector = 'microsoft', integration_id = $2, "
            "result = $3, external_ref = $4 WHERE id = $1",
            action.id, env.integration.id, {"error": "partial", "retryable": True, "changed": True},
            {"machine_id": MACHINE_ID, "capability": "defender.fake_isolation", "partial": True, "reversible": True},
        )
    admin = await user(env.repos, "admin")
    rollback, _, created = await RollbackService(env.service).request(
        TENANT_A, action.id, user=admin, role="admin", reason="false positive", approve=False,
    )
    assert created and rollback.status == "awaiting_approval"
    with pytest.raises(ActionRequestError) as refused:
        await env.service.retry(TENANT_A, action.id, user=admin, role="admin", reason="again")
    assert refused.value.status == 409 and refused.value.code == "retry_unavailable"
    assert refused.value.reason == "rollback_exists"
    row = await env.get(action)
    assert row.status == "failed" and row.execution_owner == "workflow"
    assert "response_action.retry_requested" not in await audits(env.repos, action)


async def test_kill_switch_wins_in_the_background(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await env.propose("isolate_host", "ws-042", execution_owner="scheduler")
    await env.repos.tenants.update_settings(TENANT_A, {"response": {"dry_run": True}})
    await env.run_background()
    row = await env.get(action)
    assert row.status == "dry_run" and env.fake.requests == []


async def test_a_tenants_rows_cannot_pin_another_tenants_integration(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    from tests.integration.db._support import make_alert

    alert = await make_alert(env.repos, TENANT_B)
    with pytest.raises(ReferenceNotFound) as exc:
        await env.repos.actions.propose(TENANT_B, alert, "isolate_host", "ws-1", "high", status="approved",
                                        connector="microsoft", integration_id=env.integration.id)
    assert exc.value.resource == "integration"


async def test_rehearsal_through_the_workflow_records_dry_run(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO, live=False)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    assert await env.execute(action) == "dry_run"
    row = await env.get(action)
    assert row.connector == "microsoft" and row.integration_id == env.integration.id
    assert row.result is not None and row.result["rehearsal"] is True and env.fake.writes() == []
    assert row.verification is None

