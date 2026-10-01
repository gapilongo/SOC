"""A started Microsoft execution is never recorded as "nothing ran", never abandoned, never lost to a ledger error.

A row whose checkpoints show a write (``requested``, a step done) may have
changed Microsoft. Re-running it under a kill switch, with its integration
disabled, past the call's deadline or with the database failing mid-call
must keep it executing (deferred), or fail it retryably with what was done
(``partial``, reversible) so Retry and Roll back stay available.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Dict, Iterator

import pytest

from lg_sotf.db.repos import ResponseAction
from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.connectors.base import ConnectorResult, LedgerUnavailable
from lg_sotf.services.rollback import RollbackService
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft.conftest import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft._support import FAKE_SPECS, MACHINE_ID, OPERATION_ID, script_isolation

pytestmark = pytest.mark.integration

ISO = {"defender.fake_isolation": {}}
STARTED: Dict[str, Any] = {
    "machine_id": MACHINE_ID, "step": "isolating", "requested": True, "operation_id": OPERATION_ID,
    "capability": "defender.fake_isolation",
}


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


async def started_row(env: MicrosoftEnv, *, attempts: int = 1, owner: str = "scheduler") -> ResponseAction:
    """An isolate_host row an earlier attempt left executing after it requested the isolation."""
    action = await env.propose("isolate_host", "ws-042", execution_owner=owner)
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'executing', connector = 'microsoft', integration_id = $2, "
            "attempts = $3, external_ref = $4, executed_at = now(), lease_until = now() - interval '1 second' "
            "WHERE id = $1",
            action.id, env.integration.id, attempts, STARTED,
        )
    return await env.get(action)


def eligible(row: ResponseAction) -> bool:
    service = RollbackService.__new__(RollbackService)
    return service.eligibility(row, None, now=datetime.now(UTC)).available


async def test_a_kill_switch_holds_a_started_row_instead_of_recording_a_dry_run(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env(ISO)
    row = await started_row(env)
    await env.repos.tenants.update_settings(TENANT_A, {"response": {"dry_run": True}})
    assert await env.run_background() == 1
    held = await env.get(row)
    assert held.status == "executing" and held.execution_owner == "scheduler"
    assert held.result is not None and held.result["deferred"] == "halted" and env.fake.requests == []
    assert held.external_ref == STARTED
    # Still held when its attempts run out: then it fails retryably and keeps what was done.
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET attempts = 5 WHERE id = $1", row.id)
    await env.expire_leases()
    assert await env.run_background() == 1
    failed = await env.get(row)
    assert failed.status == "failed" and failed.result is not None and failed.result["error"] == "halted"
    assert failed.result["retryable"] is True and failed.result["changed"] is True
    assert failed.external_ref is not None and failed.external_ref["partial"] is True
    assert failed.external_ref["reversible"] is True and eligible(failed)


async def test_a_workflow_rerun_under_a_kill_switch_is_handed_to_the_scheduler(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    row = await started_row(env, owner="workflow")
    await env.repos.tenants.update_settings(TENANT_A, {"response": {"dry_run": True}})
    assert await env.execute(row) == "executing"
    held = await env.get(row)
    assert held.execution_owner == "scheduler" and held.result is not None and held.result["deferred"] == "halted"


async def test_a_nothing_started_row_still_records_the_dry_run(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    action = await env.propose("isolate_host", "ws-042", execution_owner="scheduler")
    async with env.repos.db.system_tx() as conn:
        await conn.execute(
            "UPDATE response_actions SET status = 'executing', connector = 'microsoft', integration_id = $2, "
            "attempts = 1, lease_until = now() - interval '1 second' WHERE id = $1",
            action.id, env.integration.id,
        )
    await env.repos.tenants.update_settings(TENANT_A, {"response": {"dry_run": True}})
    await env.run_background()
    assert (await env.get(action)).status == "dry_run"


@pytest.mark.parametrize("attempts", [1, 5])
async def test_a_disabled_integration_fails_a_started_row_retryably_with_its_progress(
    microsoft_env: MicrosoftEnvFactory, attempts: int
) -> None:
    env = await microsoft_env(ISO)
    row = await started_row(env, attempts=attempts)
    await env.repos.integrations.update(TENANT_A, env.integration.id, enabled=False)
    assert await env.run_background() == 1
    failed = await env.get(row)
    assert failed.status == "failed" and failed.result is not None
    assert failed.result["error"] == "connector_misconfigured" and failed.result["retryable"] is True
    assert failed.external_ref is not None and failed.external_ref["partial"] is True and eligible(failed)


async def test_live_off_fails_a_started_row_retryably_instead_of_rehearsing(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO, live=False)
    row = await started_row(env)
    assert await env.run_background() == 1
    failed = await env.get(row)
    assert failed.status == "failed" and failed.result is not None
    assert failed.result["error"] == "capability_not_live" and failed.result["retryable"] is True
    assert failed.external_ref is not None and failed.external_ref["partial"] is True and eligible(failed)
    assert env.fake.requests == []


class SlowMicrosoft:
    """A stateful connector whose call outlives the caller's deadline (a write in flight)."""

    def __init__(self, name: str = "microsoft") -> None:
        self.name = name

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        await asyncio.sleep(5)
        return ConnectorResult("succeeded", {"summary": "too late"})


async def test_the_outer_deadline_defers_a_stateful_call_instead_of_failing_it(
    microsoft_env: MicrosoftEnvFactory,
) -> None:
    env = await microsoft_env(ISO)
    row = await started_row(env, owner="workflow")
    status = await env.service._run_connector(TENANT_A, row, SlowMicrosoft(), timeout_s=0.05)
    assert status == "executing"
    deferred = await env.get(row)
    assert deferred.execution_owner == "scheduler" and deferred.result is not None
    assert deferred.result["deferred"] == "deadline"
    webhook = await env.propose("block_ip", "185.220.101.44")
    async with env.repos.db.system_tx() as conn:
        await conn.execute("UPDATE response_actions SET status = 'executing', connector = 'webhook' WHERE id = $1",
                           webhook.id)
    assert await env.service._run_connector(TENANT_A, await env.get(webhook), SlowMicrosoft("webhook"),
                                            timeout_s=0.05) == "failed"


async def test_too_little_budget_defers_a_microsoft_action_unsent(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    statuses = await env.service.execute(TENANT_A, action.alert_id, [str(action.id)], budget_s=2.0)
    assert statuses[str(action.id)] == "executing"
    row = await env.get(action)
    assert row.execution_owner == "scheduler" and row.result is not None
    assert row.result["deferred"] == "execution_budget" and env.fake.writes() == []
    await env.expire_leases()
    assert await env.run_background() == 1
    assert (await env.get(action)).status == "succeeded"


async def test_a_database_error_mid_call_leaves_the_row_executing(
    microsoft_env: MicrosoftEnvFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = await microsoft_env(ISO)
    script_isolation(env.fake)
    action = await env.propose("isolate_host", "ws-042")
    real = env.repos.actions.checkpoint
    calls = {"n": 0}

    async def flaky(*args: Any, **kwargs: Any) -> bool:
        calls["n"] += 1
        if calls["n"] == 2:  # the checkpoint right after the isolate POST
            raise OSError("connection reset by peer")
        return await real(*args, **kwargs)

    monkeypatch.setattr(env.repos.actions, "checkpoint", flaky)
    with pytest.raises(LedgerUnavailable):
        await env.execute(action)
    row = await env.get(action)
    assert row.status == "executing" and row.result is None  # never failed{connector_exception, changed: false}
    assert len([r for r in env.fake.writes() if r.url.path.endswith("/isolate")]) == 1
