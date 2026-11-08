"""``lg-sotf shadow-run`` end to end (AI-E1.5b): real shadow runs of decided alerts, compared and reported.

The candidate profile is the production pipeline itself (same fake model), so
it must agree with production on every alert; and the replay must change
nothing but the shadow tables.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.errors import OperationError
from lg_sotf.runtime.shadow_replay import ShadowRunOptions, run_shadow_replay
from lg_sotf.settings import Settings
from tests.integration.db._support import ALL_TABLES, TENANT_A, TENANT_B, make_alert
from tests.integration.engine._support import RecordingEvents, suspicious_alert

pytestmark = pytest.mark.integration


async def counts(db: Database) -> Dict[str, int]:
    async with db.system_tx(readonly=True) as conn:
        return {t: await conn.fetchval(f"SELECT count(*) FROM {t}") for t in ALL_TABLES}  # noqa: S608


def profile(tmp_path: Path) -> Path:
    path = tmp_path / "same-pipeline.yaml"
    path.write_text("name: same pipeline\nllm:\n  provider: fake\n  allow_fake: true\n")
    return path


async def test_shadow_run_replays_decided_alerts_and_agrees_with_itself(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, db: Database, events: RecordingEvents,
    tmp_path: Path,
) -> None:
    benign = await make_alert(
        repos, TENANT_A, title="Scheduled backup maintenance test job", severity="low",
        normalized={"rule_name": "scheduled-backup-maintenance-test", "entities": {"hosts": ["backup-01"]}},
    )
    suspicious = await suspicious_alert(repos)
    undecided = await suspicious_alert(repos)  # never run: production has no verdict, so it is not replayed
    await make_alert(repos, TENANT_B)  # another tenant's alert is never read
    assert (await engine.run(TENANT_A, benign)).alert_status == "closed"
    assert (await engine.run(TENANT_A, suspicious)).status == "waiting_human"
    events.events.clear()
    before = await counts(db)

    seen: list[Any] = []
    report = await run_shadow_replay(
        engine_settings,
        ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(days=1),
                         no_shadow_role_acknowledged=True),
        progress=lambda done, total, row: seen.append((done, total, row.alert_id)),
    )

    assert {alert_id for _, _, alert_id in seen} == {benign, suspicious} and undecided not in str(seen)
    assert report.candidate == "same pipeline" and report.tenant_id == TENANT_A
    assert (report.alerts, report.compared, report.candidate_failed) == (2, 2, 0)
    assert report.agreement.rate == 1.0 and report.agreement.n == 2
    assert report.agreement.ci_low is not None and report.agreement.ci_low < 1.0 == report.agreement.ci_high
    assert report.confusion["close"]["close"] == 1 and report.confusion["escalate"]["escalate"] == 1
    assert report.potential_misses.count == report.new_escalations.count == 0
    # Only the shadow tables changed: one verdict row per alert, the runs' would-be effects; no event went out.
    after = await counts(db)
    assert after["shadow_verdicts"] == before["shadow_verdicts"] + 2
    assert after["shadow_effects"] > before["shadow_effects"]
    assert {t: n for t, n in after.items() if t not in ("shadow_verdicts", "shadow_effects")} == {
        t: n for t, n in before.items() if t not in ("shadow_verdicts", "shadow_effects")
    }
    assert events.events == []
    stored = await repos.shadow_verdicts.list_for_report(TENANT_A, report.report_id)
    assert {r.alert_id for r in stored} == {benign, suspicious}
    assert all(r.run_id and r.run_id.startswith("shadow/") for r in stored)


async def test_shadow_run_needs_decided_alerts_and_the_gate(
    engine_settings: Settings, repos: Repositories, tmp_path: Path
) -> None:
    options = ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(hours=1),
                               no_shadow_role_acknowledged=True)
    with pytest.raises(OperationError, match="no decided alerts"):
        await run_shadow_replay(engine_settings, options)
    ungated = ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(hours=1))
    with pytest.raises(OperationError, match="AI-E1.5c"):
        await run_shadow_replay(engine_settings, ungated)
