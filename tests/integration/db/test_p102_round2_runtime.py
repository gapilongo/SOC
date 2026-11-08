"""Round 2 of the review of PR #308, as the runtime role: forging a whole run (defence in depth, N4).

The runtime role can insert a run row of its own (any window and frame) and items for alerts outside
that window and frame, or with a wrong ``ai_class``. Database-level run integrity (trigger checks on the
window, the frame and the AI class) is the follow-up story PRD-10.3 (issue #313): this test asserts the
safe behaviour and is expected to fail until then (strict, so it flags the fix).
"""

from __future__ import annotations

from typing import Dict

import pytest

from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A, attempt_as, closed_alert_as

pytestmark = pytest.mark.asyncio


@pytest.mark.xfail(strict=True, reason="N4: DB-level run integrity is PRD-10.3 (gapilongo/SOC#313)")
async def test_runtime_role_cannot_forge_a_whole_run(app: Repositories, repos: Repositories) -> None:
    good = await closed_alert_as(app, repos, TENANT_A)
    hit = await closed_alert_as(app, repos, TENANT_A)
    async with repos.db.system_tx() as conn:  # an alert the AI called malicious, never closed: outside any frame
        await conn.execute("UPDATE alerts SET status='processing', disposition='malicious', closed_at=NULL WHERE id=$1", hit)
    results: Dict[str, str] = {}
    forged = (
        "INSERT INTO blind_audit_runs (tenant_id, window_start, window_end, seed, sample_rate, frame_size, sample_size,"
        " trigger, created_by) VALUES ($1, '2020-01-01', '2020-01-02', 1, 1, 100000, 2, 'api', 'x')"
    )
    results["forged run (non-contiguous 2020 window, frame 100000)"] = await attempt_as(app, forged, TENANT_A)
    async with repos.db.system_tx() as conn:
        run_id = await conn.fetchval("SELECT id FROM blind_audit_runs WHERE window_start = '2020-01-01'")
    if run_id is not None:
        results["item: an alert outside the window and the frame, ai_class=benign"] = await attempt_as(
            app, "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class) "
            "VALUES ($1, $2, $3, 1, 'benign')", TENANT_A, run_id, hit)
        results["item: wrong ai_class for a benign-closed alert"] = await attempt_as(
            app, "INSERT INTO blind_audit_items (tenant_id, run_id, alert_id, sample_rank, ai_class) "
            "VALUES ($1, $2, $3, 2, 'malicious')", TENANT_A, run_id, good)
    assert "ALLOWED" not in results.values(), results
