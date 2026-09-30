"""``lg-sotf eval --from-history``: analyst-decided alerts replayed through the current pipeline, with no side effects."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import asyncpg
import pytest

from lg_sotf.agents.correlation.indicators import extract_indicators
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.command import EXIT_OK, EvalOptions, execute
from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.history import (
    HistoryBacktestError,
    ReplayWriteBlocked,
    replay_repositories,
    run_history_backtest,
)
from lg_sotf.eval.report import HISTORY_NOTE
from lg_sotf.ingestion.service import API_SOURCE_ID, IngestionService
from lg_sotf.security.hashing import hmac_indicator
from lg_sotf.settings import Settings
from tests.integration.conftest import ALL_TABLES
from tests.integration.db._support import TENANT_A, TENANT_B

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
DATASET = ROOT / "tests" / "fixtures" / "eval" / "synthetic_v1.jsonl"
DECISION = {"malicious": "true_positive", "benign": "false_positive"}
AGE = timedelta(days=10)


async def snapshot(db: Database) -> Dict[str, str]:
    """A digest of every row of every tenant table: equal before and after means nothing was written."""
    out: Dict[str, str] = {}
    async with db.system_tx() as conn:
        for table in ALL_TABLES:
            out[table] = await conn.fetchval(
                f"SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) FROM {table} t"  # noqa: S608
            )
    return out


async def seed_history(db: Database, repos: Repositories, settings: Settings) -> Dict[str, Any]:
    """Canonical synthetic alerts in tenant A, ingested 10 days ago and decided by an analyst.

    Also: one alert whose only decision is needs_more_info, one decided long ago, one alert in
    tenant B, and indicator sightings (before and after the first alert's ingestion) so correlation
    runs against the point-in-time view.
    """
    items = [i for i in load_dataset(DATASET).items if i.source_type == "canonical" and i.expected.disposition in DECISION]
    items = items[:8]
    ingestion = IngestionService(db, settings)
    try:
        result = await ingestion.ingest(TENANT_A, API_SOURCE_ID, [dict(i.alert) for i in items])
        extra = await ingestion.ingest(
            TENANT_A,
            API_SOURCE_ID,
            [
                {"source_alert_id": "hist-nmi", "title": "Only needs more info", "severity": "low"},
                {"source_alert_id": "hist-old", "title": "Decided long ago", "severity": "low"},
            ],
        )
        other = await ingestion.ingest(TENANT_B, API_SOURCE_ID, [dict(items[0].alert)])
    finally:
        await ingestion.close()
    alert_ids = [r.alert_id for r in result.items]
    assert all(alert_ids) and len(alert_ids) == len(items)
    now = datetime.now(UTC)
    base = now - AGE
    decided: Dict[str, str] = {}
    async with db.system_tx() as conn:
        for n, alert_id in enumerate(alert_ids):
            await conn.execute(
                "UPDATE alerts SET ingested_at = $2 WHERE id = $1", alert_id, base + timedelta(minutes=n)
            )
    for item, alert_id in zip(items, alert_ids, strict=True):
        decision = DECISION[item.expected.disposition]
        await decide(db, repos, TENANT_A, alert_id, decision, base + timedelta(hours=2))
        decided[alert_id] = item.expected.disposition
    nmi, old = (r.alert_id for r in extra.items)
    await decide(db, repos, TENANT_A, nmi, "needs_more_info", base + timedelta(hours=2))
    await decide(db, repos, TENANT_A, old, "true_positive", now - timedelta(days=90))
    await decide(db, repos, TENANT_B, other.items[0].alert_id, "true_positive", base + timedelta(hours=2))

    # Sightings of the first alert's indicators by another alert: one 30 min before its ingestion
    # (in the correlation window), one after it (must not be visible to the replay).
    first = await repos.alerts.get(TENANT_A, alert_ids[0])
    indicators = extract_indicators(first.normalized)
    assert indicators
    hashed = [(i.type, hmac_indicator(i.type, i.value, settings=settings), i.display) for i in indicators]
    before, after = alert_ids[1], alert_ids[2]
    await repos.indicators.add_sightings(
        TENANT_A, before, [(t, h, d, first.ingested_at - timedelta(minutes=30)) for t, h, d in hashed]
    )
    await repos.indicators.add_sightings(
        TENANT_A, after, [(t, h, d, first.ingested_at + timedelta(minutes=30)) for t, h, d in hashed]
    )
    return {"decided": decided, "first": alert_ids[0], "before": before, "after": after, "hashed": hashed}


async def decide(db: Database, repos: Repositories, tenant_id: str, alert_id: str, decision: str, at: datetime) -> None:
    """An escalation and the analyst's feedback row for ``alert_id``, recorded at ``at``."""
    esc, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="review")
    await repos.feedback.create(tenant_id, esc.id, alert_id, decision)
    status = "decided"
    async with db.system_tx() as conn:
        await conn.execute(
            "UPDATE escalations SET status = $2, decision = $3, decided_at = $4 WHERE id = $1",
            esc.id,
            status,
            decision,
            at,
        )
        await conn.execute("UPDATE analyst_feedback SET created_at = $2 WHERE escalation_id = $1", esc.id, at)


async def test_backtest_replays_decided_alerts_without_side_effects(
    eval_settings: Settings, db: Database, repos: Repositories, redis_client: Any
) -> None:
    seeded = await seed_history(db, repos, eval_settings)
    before = await snapshot(db)
    redis_keys = await redis_client.dbsize()

    run = await run_history_backtest(eval_settings, tenant_id=TENANT_A, days=30, db=db)

    assert await snapshot(db) == before, "the backtest wrote to the database"
    assert await redis_client.dbsize() == redis_keys
    decided: Dict[str, str] = seeded["decided"]
    results = {r.alert_id: r for r in run.results}
    assert set(results) == set(decided)  # not the needs_more_info-only, the 90-day-old or tenant B's alert
    for alert_id, result in results.items():
        assert result.expected == decided[alert_id]
        assert result.error is None, result.error
        assert result.status in ("closed", "waiting_human", "waiting_approval")
        assert result.predicted in ("malicious", "benign", "inconclusive")
        assert result.route in ("close", "escalate", "plan_response")
        assert result.labels == {"analyst": decided[alert_id]}
    assert any(r.llm_calls > 0 for r in run.results)
    assert run.info["mode"] == "history" and run.info["tenant_id"] == TENANT_A and run.info["llm_provider"] == "fake"
    assert len(run.dataset.items) == len(decided) and run.dataset.synthetic is False
    assert run.dataset.path == f"history:{TENANT_A}:30d"
    again = await run_history_backtest(eval_settings, tenant_id=TENANT_A, days=30, db=db)
    assert again.dataset.sha256 == run.dataset.sha256  # same decisions: comparable baselines
    assert [r.predicted for r in again.results] == [r.predicted for r in run.results]  # deterministic fake model

    limited = await run_history_backtest(eval_settings, tenant_id=TENANT_A, days=30, db=db, limit=2)
    assert len(limited.results) == 2
    with pytest.raises(HistoryBacktestError, match="no analyst-decided alerts"):
        await run_history_backtest(eval_settings, tenant_id=TENANT_A, days=1, db=db)
    with pytest.raises(HistoryBacktestError, match="does not exist"):
        await run_history_backtest(eval_settings, tenant_id="no-such-tenant", days=30, db=db)


async def test_replay_repositories_are_read_only_and_point_in_time(
    eval_settings: Settings, db: Database, repos: Repositories
) -> None:
    seeded = await seed_history(db, repos, eval_settings)
    first = await repos.alerts.get(TENANT_A, seeded["first"])
    offset = datetime.now(UTC) - first.ingested_at
    view = replay_repositories(db, cutoff=first.ingested_at, offset=offset)

    with pytest.raises(asyncpg.exceptions.ReadOnlySQLTransactionError):
        await view.alerts.update(TENANT_A, first.id, summary={"x": 1})
    with pytest.raises(ReplayWriteBlocked):
        async with view.db.system_tx():
            pass
    assert await view.indicators.add_sightings(TENANT_A, first.id, [("ip", "h", "d", datetime.now(UTC))]) == 0

    # "The last hour" (wall clock) means the hour before the alert was ingested: only the earlier sighting.
    related = await view.indicators.related_alerts(
        TENANT_A,
        [(t, h) for t, h, _ in seeded["hashed"]],
        since=datetime.now(UTC) - timedelta(hours=1),
        exclude_alert_id=first.id,
    )
    assert [r.alert_id for r in related] == [seeded["before"]]
    assert abs((related[0].last_seen - (datetime.now(UTC) - timedelta(minutes=30))).total_seconds()) < 60
    # The related alert was decided (closed) after the cutoff: its outcome is hidden.
    async with db.system_tx() as conn:
        await conn.execute(
            "UPDATE alerts SET status = 'closed', disposition = 'benign', closed_at = $2, "
            "summary = '{\"analyst_decision\": \"false_positive\"}' WHERE id = $1",
            seeded["before"],
            first.ingested_at + timedelta(hours=1),
        )
    hidden = await view.alerts.get(TENANT_A, seeded["before"])
    assert hidden.disposition is None and hidden.summary == {} and hidden.status == "processing"
    earlier = replay_repositories(db, cutoff=first.ingested_at + timedelta(hours=2), offset=offset)
    shown = await earlier.alerts.get(TENANT_A, seeded["before"])
    assert shown.disposition == "benign" and shown.summary == {"analyst_decision": "false_positive"}


async def test_eval_command_from_history_writes_a_report(
    eval_settings: Settings, db: Database, repos: Repositories, tmp_path: Path
) -> None:
    seeded = await seed_history(db, repos, eval_settings)
    before = await snapshot(db)
    report_path = tmp_path / "history.json"
    lines: List[str] = []
    options = EvalOptions(
        dataset="", report=str(report_path), tenant_id=TENANT_A, from_history=True, days=30, limit=50
    )
    code = await asyncio.to_thread(execute, eval_settings, options, lines.append, lines.append)
    assert code == EXIT_OK, lines
    assert await snapshot(db) == before
    report = json.loads(report_path.read_text())
    assert report["run"]["mode"] == "history" and report["run"]["selection"]["days"] == 30
    assert HISTORY_NOTE in report["notes"] and report["dataset"]["synthetic"] is False
    metrics = report["metrics"]
    assert metrics["items"] == len(seeded["decided"]) and metrics["errors"] == 0
    expected = {"malicious": 0, "benign": 0}
    for disposition in seeded["decided"].values():
        expected[disposition] += 1
    assert (metrics["malicious_items"], metrics["benign_items"]) == (expected["malicious"], expected["benign"])
    assert sum(sum(row.values()) for row in metrics["confusion_matrix"].values()) == metrics["scored"]
    assert (tmp_path / "history.md").read_text().startswith("# LG-SOTF evaluation report")
    assert any("analyst malicious" in line or "analyst benign" in line for line in lines)


async def test_pipeline_records_provider_and_model_on_the_alert(eval_runner: Any, repos: Repositories) -> None:
    """Going forward every alert carries the provider/model per agent (the accuracy report's model key)."""
    from tests.integration.eval.conftest import EVAL_TENANT

    item = next(i for i in load_dataset(DATASET).items if i.source_type == "canonical")
    result = (await eval_runner.run([item]))[0]
    assert result.alert_id and result.llm_calls > 0, result
    alert = await repos.alerts.get(EVAL_TENANT, result.alert_id)
    by_agent = alert.summary["llm_usage"]["by_agent"]
    called = {name: entry for name, entry in by_agent.items() if entry["calls"] > 0}
    assert called and all(e["provider"] == "fake" and e["model"].startswith("fake") for e in called.values())
    assert by_agent["analysis"]["model"] == "fake-deep"
