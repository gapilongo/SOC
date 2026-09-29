"""docs/tools/export_feedback.sql: one item per alert, labelled with the analyst's final decision, replayable."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import load_dataset, parse_dataset
from lg_sotf.eval.runner import EvalRunner
from tests.integration.eval.conftest import EVAL_TENANT

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
EXPORT_SQL = ROOT / "docs" / "tools" / "export_feedback.sql"
DATASET = ROOT / "tests" / "fixtures" / "eval" / "synthetic_v1.jsonl"


def export_query() -> str:
    text = EXPORT_SQL.read_text(encoding="utf-8")
    body = text.split("-- export-query-begin", 1)[1].split("-- export-query-end", 1)[0]
    return body.replace(":'tenant'", "$1").replace(":days", "$2::int").strip().rstrip(";")


async def decide(db: Database, escalation_id: str, decision: str, age: timedelta) -> None:
    """Mark an escalation decided and record the analyst_feedback row, ``age`` ago."""
    async with db.system_tx() as conn:
        row = await conn.fetchrow(
            "UPDATE escalations SET status = 'decided', decision = $2, decided_at = now() - $3::interval "
            "WHERE id = $1 RETURNING tenant_id, alert_id",
            escalation_id,
            decision,
            age,
        )
        await conn.execute(
            "INSERT INTO analyst_feedback (tenant_id, escalation_id, alert_id, decision, created_at) "
            "VALUES ($1, $2, $3, $4, now() - $5::interval)",
            row["tenant_id"],
            escalation_id,
            row["alert_id"],
            decision,
            age,
        )


async def reescalate(db: Database, escalation_id: str) -> str:
    """A second escalation of the same alert (what a needs_more_info decision leads to)."""
    async with db.system_tx() as conn:
        return await conn.fetchval(
            "INSERT INTO escalations (tenant_id, alert_id, thread_id, reason) "
            "SELECT tenant_id, alert_id, thread_id, 're-escalated' FROM escalations WHERE id = $1 RETURNING id",
            escalation_id,
        )


async def labelled_alerts(eval_runner: EvalRunner, db: Database, repos: Repositories) -> Dict[str, str]:
    items = [i for i in load_dataset(DATASET).items if i.id in ("syn-001", "syn-002")]
    results = {r.item_id: r for r in await eval_runner.run(items)}
    assert all(r.status == "waiting_human" for r in results.values()), results
    first = await repos.escalations.get_active_for_alert(EVAL_TENANT, results["syn-001"].alert_id)
    second = await repos.escalations.get_active_for_alert(EVAL_TENANT, results["syn-002"].alert_id)
    # syn-001: needs_more_info first, re-escalated, then confirmed as a true positive.
    await decide(db, first.id, "needs_more_info", timedelta(hours=2))
    again = await reescalate(db, first.id)
    await decide(db, again, "true_positive", timedelta(hours=1))
    # syn-002: only a needs_more_info decision so far.
    await decide(db, second.id, "needs_more_info", timedelta(minutes=30))
    return {"syn-001": results["syn-001"].alert_id, "syn-002": results["syn-002"].alert_id}


def lines_by_alert(lines: List[Dict[str, Any]], alerts: Dict[str, str], raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for line in lines:
        for item_id, alert_id in alerts.items():
            if line["alert"] == raw[alert_id]:
                assert item_id not in out, f"{item_id} exported twice"
                out[item_id] = line
    return out


async def test_export_keeps_one_item_per_alert_with_the_final_decision(
    eval_runner: EvalRunner, db: Database, repos: Repositories
) -> None:
    alerts = await labelled_alerts(eval_runner, db, repos)
    async with db.tenant_tx(EVAL_TENANT, readonly=True) as conn:
        rows = await conn.fetch(export_query(), EVAL_TENANT, 90)
    lines = [r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in rows]
    assert len(lines) == 2
    raw = {a: (await repos.alerts.get(EVAL_TENANT, a)).raw for a in alerts.values()}
    got = lines_by_alert(lines, alerts, raw)
    assert got["syn-001"]["expected"] == {"disposition": "malicious"}
    assert "decision:true_positive" in got["syn-001"]["tags"]
    assert got["syn-002"]["expected"] == {"disposition": "inconclusive"}
    assert [line["id"] for line in lines] == [got["syn-001"]["id"], got["syn-002"]["id"]]  # by decision time

    # The export is a valid dataset that replays in a fresh tenant without duplicates.
    dataset = parse_dataset("\n".join(json.dumps(line) for line in lines))
    await repos.tenants.create("eval-fb-replay", "Replay")
    replay = EvalRunner(
        tenant_id="eval-fb-replay", repos=repos, ingestion=eval_runner.ingestion, engine=eval_runner.engine
    )
    results = await replay.run(dataset.items)
    assert [r.status for r in results if r.status == "error"] == [], [r.error for r in results]


def run_psql_export(psql: str, dsn: str, workdir: Path) -> List[Dict[str, Any]]:
    """Run the script as documented (blocking: called in a thread). Checks the usage guard and the output path."""
    base = [psql, "-X", "-q", dsn, "-v", f"tenant={EVAL_TENANT}", "-v", "days=90"]
    usage = subprocess.run([*base, "-f", str(EXPORT_SQL)], capture_output=True, text=True, timeout=60, cwd=workdir)
    assert "usage:" in usage.stdout and list(workdir.iterdir()) == []

    out = workdir / "private" / "feedback.jsonl"
    out.parent.mkdir()
    done = subprocess.run(
        [*base, "-v", f"out={out}", "-v", "ON_ERROR_STOP=1", "-f", str(EXPORT_SQL)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workdir,
    )
    assert done.returncode == 0, done.stderr
    assert sorted(p.name for p in workdir.iterdir()) == ["private"]  # nothing written to the working directory
    return [json.loads(line) for line in out.read_text().splitlines() if line.strip()]


async def test_export_script_runs_under_psql_and_requires_an_output_path(
    eval_runner: EvalRunner, db: Database, repos: Repositories, eval_database_url: str, tmp_path: Path
) -> None:
    psql = shutil.which("psql")
    if psql is None:
        pytest.skip("psql is not installed")
    await labelled_alerts(eval_runner, db, repos)
    lines = await asyncio.to_thread(run_psql_export, psql, eval_database_url, tmp_path)
    assert sorted(line["expected"]["disposition"] for line in lines) == ["inconclusive", "malicious"]
