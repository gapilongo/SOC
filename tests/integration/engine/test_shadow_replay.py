"""``lg-sotf shadow-run`` end to end (AI-E1.5b): real shadow runs of decided alerts, compared and reported.

The candidate profile is the production pipeline itself (same fake model), so
it must agree with production on every alert; and the replay must change
nothing but the shadow tables.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.errors import ShadowRoleRequired
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.db.repos.shadow_effects import ShadowEffectsRepo
from lg_sotf.db.repos.shadow_verdicts import ShadowVerdictsRepo
from lg_sotf.errors import OperationError
from lg_sotf.runtime.shadow_replay import ShadowRunOptions, run_shadow_replay
from lg_sotf.security.shadow import in_shadow
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


@pytest.fixture
def role_spies(monkeypatch: pytest.MonkeyPatch) -> Dict[str, List[bool]]:
    """Every shadow read must come from the SELECT-only pool, every replay write must happen outside shadow mode."""
    seen: Dict[str, List[bool]] = {"shadow_reads": [], "verdict_writes": [], "effect_writes": []}
    require_pool, shadow_pool = Database._require_pool, Database._shadow_or_refuse

    def runtime_pool(self: Database) -> Any:
        assert not in_shadow(), "a shadow-scope connection came from the runtime pool"
        return require_pool(self)

    def select_only_pool(self: Database) -> Any:
        seen["shadow_reads"].append(in_shadow())
        return shadow_pool(self)

    def spy_append(key: str, append: Any) -> Any:
        async def spied(*args: Any, **kwargs: Any) -> Any:
            seen[key].append(in_shadow())
            return await append(*args, **kwargs)

        return spied

    monkeypatch.setattr(Database, "_require_pool", runtime_pool)
    monkeypatch.setattr(Database, "_shadow_or_refuse", select_only_pool)
    monkeypatch.setattr(ShadowVerdictsRepo, "append", spy_append("verdict_writes", ShadowVerdictsRepo.append))
    monkeypatch.setattr(ShadowEffectsRepo, "append", spy_append("effect_writes", ShadowEffectsRepo.append))
    return seen


async def test_shadow_run_replays_decided_alerts_and_agrees_with_itself(
    engine: WorkflowEngine, engine_settings: Settings, repos: Repositories, db: Database, events: RecordingEvents,
    tmp_path: Path, role_spies: Dict[str, List[bool]],
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
    platform = engine_settings.model_copy(
        update={"auth": engine_settings.auth.model_copy(update={"bootstrap_tenant_id": TENANT_B})}
    )

    seen: list[Any] = []
    report = await run_shadow_replay(
        platform,
        ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(days=1)),
        progress=lambda done, total, row: seen.append((done, total, row.alert_id)),
    )

    assert {alert_id for _, _, alert_id in seen} == {benign, suspicious} and undecided not in str(seen)
    assert report.candidate == "same pipeline" and report.tenant_id == TENANT_A
    assert report.candidate_host == ""  # the fake model: no network
    assert (report.alerts, report.compared, report.candidate_failed) == (2, 2, 0)
    assert report.agreement.rate == 1.0 and report.agreement.n == 2
    assert report.agreement.ci_low is not None and report.agreement.ci_low < 1.0 == report.agreement.ci_high
    assert report.confusion["close"]["close"] == 1 and report.confusion["escalate"]["escalate"] == 1
    assert report.potential_misses.count == report.new_escalations.count == 0
    # AI-E1.5c: the shadow runs read only through the SELECT-only pool; the rows were written outside shadow mode.
    assert role_spies["shadow_reads"] and all(role_spies["shadow_reads"])
    assert role_spies["verdict_writes"] == [False, False]
    assert role_spies["effect_writes"] and not any(role_spies["effect_writes"])
    # Only the shadow tables and the two audit entries changed: one verdict row per alert, the runs' would-be
    # effects; no event went out.
    after = await counts(db)
    assert after["shadow_verdicts"] == before["shadow_verdicts"] + 2
    assert after["shadow_effects"] > before["shadow_effects"]
    assert after["audit_log"] == before["audit_log"] + 2
    changed = ("shadow_verdicts", "shadow_effects", "audit_log")
    assert {t: n for t, n in after.items() if t not in changed} == {
        t: n for t, n in before.items() if t not in changed
    }
    assert events.events == []
    stored = await repos.shadow_verdicts.list_for_report(TENANT_A, report.report_id)
    assert {r.alert_id for r in stored} == {benign, suspicious}
    assert all(r.run_id and r.run_id.startswith("shadow/") for r in stored)
    assert {r.candidate_host for r in stored} == {""}
    # Audited in the tenant and in the platform tenant, with what was replayed and where it went.
    [entry] = (await repos.audit.list(TENANT_A, action="tenant.shadow_replayed")).items
    [platform_entry] = (await repos.audit.list(TENANT_B, action="platform.tenant_shadow_replayed")).items
    for e in (entry, platform_entry):
        assert e.resource_id == TENANT_A and e.actor_id == "cli"
        assert e.details == {
            "report_id": report.report_id, "candidate": "same pipeline", "candidate_host": "",
            "window_hours": 24, "alerts": 2,
        }


async def test_shadow_run_needs_the_shadow_role_an_allowed_host_and_decided_alerts(
    engine_settings: Settings, repos: Repositories, db: Database, tmp_path: Path
) -> None:
    options = ShadowRunOptions(tenant_id=TENANT_A, candidate=profile(tmp_path), window=timedelta(hours=1))
    with pytest.raises(OperationError, match="no decided alerts"):
        await run_shadow_replay(engine_settings, options)
    no_role = engine_settings.model_copy(
        update={"database": engine_settings.database.model_copy(update={"shadow_url": None})}
    )
    with pytest.raises(ShadowRoleRequired, match="database.shadow_url"):
        await run_shadow_replay(no_role, options)
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text(
        "name: elsewhere\nllm:\n  provider: openai_compatible\n  base_url: https://llm.example.net/v1\n"
        "  api_key: x\n"
    )
    before = await counts(db)
    with pytest.raises(OperationError, match="shadow_candidate_llm_hosts"):
        await run_shadow_replay(engine_settings, ShadowRunOptions(TENANT_A, elsewhere, timedelta(days=1)))
    assert await counts(db) == before  # refused before any alert was read or any audit entry written
