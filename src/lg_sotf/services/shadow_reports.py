"""Shadow agreement reports from the stored comparisons (AI-E1.5b).

The CLI (after a replay) and ``GET /platform/shadow/reports/{id}`` both build
the report here, from the ``shadow_verdicts`` rows, so they always agree.
"""

from __future__ import annotations

from typing import Optional

from lg_sotf.db.repos import Repositories
from lg_sotf.domain.shadow_agreement import ShadowAgreementReport, build_report


async def stored_report(repos: Repositories, tenant_id: str, report_id: str) -> Optional[ShadowAgreementReport]:
    """The report ``report_id`` of ``tenant_id``, or ``None`` when the tenant has no such report."""
    rows = await repos.shadow_verdicts.list_for_report(tenant_id, report_id)
    if not rows:
        return None
    return build_report(
        [r.comparison() for r in rows], report_id=report_id, tenant_id=tenant_id, candidate=rows[0].candidate,
        candidate_host=rows[0].candidate_host,
    )
