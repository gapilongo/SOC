"""``/pov/runs`` (PRD-11.1): a proof of value is created through the API alone and only reads.

The acceptance test creates a run with ``POST /pov/runs``, lets the scheduler's
``pov_backtests`` job run its backtest (no CLI step anywhere) and compares a
digest of every row of every other table, and the Redis keys, before and
after: no alert changes status, no response action, escalation, event or
notification is created.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Set
from uuid import uuid4

import pytest

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.pov import MAX_RUNS_PER_DAY
from lg_sotf.eval import pov as pov_backtests
from lg_sotf.queue.producer import WorkQueue
from lg_sotf.runtime.scheduler import Scheduler
from tests.integration.api._support import API, TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import ALL_TABLES, make_alert

pytestmark = pytest.mark.integration

RUNS = f"{API}/pov/runs"
BODY = {"name": "Acme proof of value", "backtest_days": 30, "shadow_days": 14}
DECISIONS = ("true_positive", "false_positive", "benign_positive", "false_positive")


async def snapshot(db: Database) -> Dict[str, str]:
    """A digest of every row of every table but ``pov_runs``: equal before and after means nothing else was written."""
    out: Dict[str, str] = {}
    async with db.system_tx() as conn:
        for table in ALL_TABLES:
            if table != "pov_runs":
                out[table] = await conn.fetchval(
                    f"SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) FROM {table} t"  # noqa: S608
                )
    return out


def changed(before: Dict[str, str], after: Dict[str, str]) -> Set[str]:
    return {table for table in before if before[table] != after[table]}


async def decide(db: Database, repos: Repositories, tenant_id: str, alert_id: str, decision: str, at: datetime) -> None:
    """An escalation and the analyst's decision on ``alert_id``, recorded at ``at``."""
    escalation, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="review")
    await repos.feedback.create(tenant_id, escalation.id, alert_id, decision)
    async with db.system_tx() as conn:
        await conn.execute(
            "UPDATE escalations SET status = 'decided', decision = $2, decided_at = $3 WHERE id = $1",
            escalation.id, decision, at,
        )
        await conn.execute("UPDATE analyst_feedback SET created_at = $2 WHERE escalation_id = $1", escalation.id, at)


async def seed_history(db: Database, repos: Repositories) -> List[str]:
    """Tenant A: four alerts analysts decided ten days ago, one decided long ago, one still waiting for an
    approval, and a notification channel. Tenant B: one decided alert. Returns tenant A's four."""
    now = datetime.now(UTC)
    decided: List[str] = []
    for n, decision in enumerate(DECISIONS):
        alert_id = await make_alert(repos, TENANT_A, title=f"Suspicious sign-in {n}", ingested_at=now - timedelta(days=11))
        await decide(db, repos, TENANT_A, alert_id, decision, now - timedelta(days=10))
        decided.append(alert_id)
    old = await make_alert(repos, TENANT_A, title="Decided before the window", ingested_at=now - timedelta(days=90))
    await decide(db, repos, TENANT_A, old, "true_positive", now - timedelta(days=80))
    waiting = await make_alert(repos, TENANT_A, title="Waiting for an approval")
    await repos.actions.propose(TENANT_A, waiting, "block_ip", "203.0.113.7", "low", status="awaiting_approval")
    await repos.integrations.create(TENANT_A, "email", "SOC mailbox", config={"recipients": ["soc@example.com"]})
    other = await make_alert(repos, TENANT_B, title="Tenant B's alert", ingested_at=now - timedelta(days=11))
    await decide(db, repos, TENANT_B, other, "true_positive", now - timedelta(days=10))
    return decided


def scheduler_with_pov_job(api: ApiHarness, db: Database, redis_client: Any) -> Scheduler:
    """The scheduler as ``lg-sotf scheduler`` builds it: the CLI hands it the backtest job."""
    settings = api.ctx.settings

    def no_ingestion() -> Any:
        raise AssertionError("the proof-of-value job polls no source")

    return Scheduler(
        settings, db, redis_client, no_ingestion, WorkQueue(redis_client, settings), None,
        pov_backtests=pov_backtests.pov_backtest_job(settings, db, None),
    )


async def test_pov_created_through_the_api_only_and_its_backtest_cause_no_side_effects(
    api: ApiHarness, db: Database, redis_client: Any
) -> None:
    decided = await seed_history(db, api.repos)
    admin = await api.login_headers(TENANT_A, "admin")
    viewer = await api.login_headers(TENANT_A, "viewer")
    before = await snapshot(db)

    created = await api.client.post(RUNS, json=BODY, headers=admin)

    assert created.status_code == 201, created.text
    run = created.json()
    assert (run["name"], run["status"]) == ("Acme proof of value", "backtest")
    assert (run["backtest"]["status"], run["backtest"]["result"], run["shadow"]["status"]) == ("pending", None, "running")
    backtest_end = datetime.fromisoformat(run["backtest"]["window_end"])
    assert datetime.fromisoformat(run["backtest"]["window_start"]) == backtest_end - timedelta(days=30)
    assert datetime.fromisoformat(run["shadow"]["window_start"]) == backtest_end
    assert datetime.fromisoformat(run["shadow"]["window_end"]) == backtest_end + timedelta(days=14)
    # Creating the run wrote the run and its audit entry: no alert, action, escalation, event or notification.
    after_create = await snapshot(db)
    assert changed(before, after_create) == {"audit_log"}
    entries = (await api.repos.audit.list(TENANT_A, resource_type="pov_run")).items
    assert [(e.action, e.resource_id) for e in entries] == [("pov_run.created", run["id"])]
    assert all(b":rl:" in key for key in await redis_client.keys("*"))  # the rate limiter's counters only

    # The scheduler runs the backtest: no CLI step. It replays the four decided alerts and writes only the run.
    keys = set(await redis_client.keys("*"))
    scheduler = scheduler_with_pov_job(api, db, redis_client)
    await scheduler.jobs["pov_backtests"].fn()

    assert changed(after_create, await snapshot(db)) == set(), "the backtest wrote outside pov_runs"
    assert set(await redis_client.keys("*")) == keys
    detail = (await api.client.get(f"{RUNS}/{run['id']}", headers=viewer)).json()
    assert (detail["status"], detail["backtest"]["status"], detail["backtest"]["error"]) == ("shadow", "completed", None)
    result = detail["backtest"]["result"]
    assert "items" not in result  # aggregates only: no per-alert row
    assert (result["metrics"]["items"], result["metrics"]["errors"]) == (len(decided), 0)
    assert (result["metrics"]["malicious_items"], result["metrics"]["benign_items"]) == (1, 3)
    assert result["run"]["side_effects"] == "none: read-only replay up to the routing decision"
    assert result["run"]["mode"] == "history" and result["dataset"]["items"] == len(decided)
    # Nothing is left to run, and the list carries the status without the result.
    await scheduler.jobs["pov_backtests"].fn()
    [listed] = (await api.client.get(RUNS, headers=viewer)).json()["items"]
    assert (listed["id"], listed["backtest"]["status"], listed["backtest"]["result"]) == (run["id"], "completed", None)

    # The shadow period's results are the tenant's reports over its window.
    start = backtest_end.date().isoformat()
    end = (backtest_end + timedelta(days=14) - timedelta(microseconds=1)).date().isoformat()
    assert detail["shadow"]["reports"] == {
        name: f"/reports/{name}?from={start}&to={end}" for name in ("value", "accuracy", "detections")
    }
    for path in detail["shadow"]["reports"].values():
        assert (await api.client.get(f"{API}{path}", headers=viewer)).status_code == 200, path


async def test_a_backtest_without_history_or_that_fails_is_recorded_on_the_run(
    api: ApiHarness, db: Database, redis_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    other = await api.login_headers(TENANT_B, "admin")
    alert_id = await make_alert(api.repos, TENANT_B, ingested_at=datetime.now(UTC) - timedelta(days=3))
    await decide(db, api.repos, TENANT_B, alert_id, "true_positive", datetime.now(UTC) - timedelta(days=2))
    empty = (await api.client.post(RUNS, json=BODY, headers=admin)).json()
    failing = (await api.client.post(RUNS, json={**BODY, "name": "Tenant B"}, headers=other)).json()
    scheduler = scheduler_with_pov_job(api, db, redis_client)

    # Tenant A has no analyst-decided alert: nothing to replay, and the run moves on to its shadow period.
    await scheduler.jobs["pov_backtests"].fn()
    detail = (await api.client.get(f"{RUNS}/{empty['id']}", headers=admin)).json()
    assert (detail["status"], detail["backtest"]["status"], detail["backtest"]["result"]) == ("shadow", "no_data", None)

    async def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("model endpoint unreachable")

    monkeypatch.setattr(pov_backtests, "run_history_backtest", broken)
    before = await snapshot(db)
    await scheduler.jobs["pov_backtests"].fn()
    assert await snapshot(db) == before
    detail = (await api.client.get(f"{RUNS}/{failing['id']}", headers=other)).json()
    assert (detail["status"], detail["backtest"]["status"]) == ("shadow", "failed")
    assert "model endpoint unreachable" in detail["backtest"]["error"] and detail["backtest"]["result"] is None


async def test_run_rules_roles_and_tenant_isolation(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    analyst = await api.login_headers(TENANT_A, "analyst")
    viewer = await api.login_headers(TENANT_A, "viewer")
    outsider = await api.login_headers(TENANT_B, "admin")
    read_key = await api.key_headers(TENANT_A, ["read"])

    # Admins create and cancel; an API key cannot.
    for headers in (analyst, viewer, read_key):
        assert (await api.client.post(RUNS, json=BODY, headers=headers)).status_code == 403
    for invalid in (
        {**BODY, "name": "   "}, {**BODY, "name": "n" * 121}, {**BODY, "backtest_days": 0}, {**BODY, "backtest_days": 367},
        {**BODY, "shadow_days": 0}, {**BODY, "shadow_days": 91}, {**BODY, "backtest_status": "completed"}, {},
    ):
        assert (await api.client.post(RUNS, json=invalid, headers=admin)).status_code == 422, invalid
    defaults = await api.client.post(RUNS, json={"name": "  Defaults  "}, headers=admin)
    assert defaults.status_code == 201, defaults.text
    first = defaults.json()
    assert first["name"] == "Defaults"
    start, end = (datetime.fromisoformat(first["backtest"][k]) for k in ("window_start", "window_end"))
    assert end - start == timedelta(days=90)
    assert datetime.fromisoformat(first["shadow"]["window_end"]) - end == timedelta(days=14)

    # One run in progress per tenant; tenant B is not concerned.
    again = await api.client.post(RUNS, json=BODY, headers=admin)
    assert again.status_code == 409 and again.json()["error"]["code"] == "pov_run_in_progress"
    assert (await api.client.post(RUNS, json=BODY, headers=outsider)).status_code == 201

    # Reads: viewers and read keys of the tenant; another tenant sees nothing.
    for headers in (viewer, read_key):
        assert (await api.client.get(f"{RUNS}/{first['id']}", headers=headers)).json()["id"] == first["id"]
    assert (await api.client.get(f"{RUNS}/{first['id']}", headers=outsider)).status_code == 404
    assert (await api.client.get(f"{RUNS}/{uuid4()}", headers=admin)).status_code == 404
    assert (await api.client.get(f"{RUNS}/not-a-uuid", headers=admin)).status_code == 422
    assert first["id"] not in [r["id"] for r in (await api.client.get(RUNS, headers=outsider)).json()["items"]]

    # Cancel: admins of the tenant, once.
    cancel = f"{RUNS}/{first['id']}/cancel"
    assert (await api.client.post(cancel, headers=analyst)).status_code == 403
    assert (await api.client.post(cancel, headers=outsider)).status_code == 404
    cancelled = await api.client.post(cancel, headers=admin)
    assert cancelled.status_code == 200, cancelled.text
    assert (cancelled.json()["status"], cancelled.json()["shadow"]["status"]) == ("cancelled", "completed")
    assert cancelled.json()["cancelled_at"] is not None
    twice = await api.client.post(cancel, headers=admin)
    assert twice.status_code == 409 and twice.json()["error"]["code"] == "pov_run_not_in_progress"
    assert [e.action for e in (await api.repos.audit.list(TENANT_A, resource_type="pov_run")).items] == [
        "pov_run.cancelled", "pov_run.created",
    ]

    # A cancelled run frees the tenant for the next one, up to the daily cap (each run starts a backtest).
    ids = [first["id"]]
    for _ in range(MAX_RUNS_PER_DAY - 1):
        made = await api.client.post(RUNS, json=BODY, headers=admin)
        assert made.status_code == 201, made.text
        ids.append(made.json()["id"])
        assert (await api.client.post(f"{RUNS}/{ids[-1]}/cancel", headers=admin)).status_code == 200
    capped = await api.client.post(RUNS, json=BODY, headers=admin)
    assert capped.status_code == 429 and capped.json()["error"]["code"] == "too_many_pov_runs"
    listed = (await api.client.get(RUNS, params={"limit": 2}, headers=viewer)).json()
    assert [r["id"] for r in listed["items"]] == ids[:0:-1][:2] and listed["next_cursor"]
    rest = (await api.client.get(RUNS, params={"cursor": listed["next_cursor"]}, headers=viewer)).json()
    assert [r["id"] for r in rest["items"]] == ids[::-1][2:] and rest["next_cursor"] is None


async def test_a_cancelled_run_is_not_backtested_and_an_ended_one_is_completed(
    api: ApiHarness, db: Database, redis_client: Any
) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    await seed_history(db, api.repos)
    run = (await api.client.post(RUNS, json=BODY, headers=admin)).json()
    assert (await api.client.post(f"{RUNS}/{run['id']}/cancel", headers=admin)).status_code == 200
    scheduler = scheduler_with_pov_job(api, db, redis_client)

    await scheduler.jobs["pov_backtests"].fn()

    detail = (await api.client.get(f"{RUNS}/{run['id']}", headers=admin)).json()
    assert (detail["status"], detail["backtest"]["status"], detail["backtest"]["started_at"]) == ("cancelled", "pending", None)

    # A run whose shadow period has ended, backtest settled: completed, and the tenant can start another.
    ended = (await api.client.post(RUNS, json=BODY, headers=admin)).json()
    await scheduler.jobs["pov_backtests"].fn()
    async with db.system_tx() as conn:
        await conn.execute(
            "UPDATE pov_runs SET backtest_start = backtest_start - interval '30 days', "
            "backtest_end = backtest_end - interval '30 days', shadow_start = shadow_start - interval '30 days', "
            "shadow_end = shadow_end - interval '30 days' WHERE id = $1",
            ended["id"],
        )
    detail = (await api.client.get(f"{RUNS}/{ended['id']}", headers=admin)).json()
    assert (detail["status"], detail["backtest"]["status"], detail["shadow"]["status"]) == ("completed", "completed", "completed")
    over = await api.client.post(f"{RUNS}/{ended['id']}/cancel", headers=admin)
    assert over.status_code == 409 and over.json()["error"]["code"] == "pov_run_not_in_progress"
    assert (await api.client.post(RUNS, json=BODY, headers=admin)).status_code == 201
