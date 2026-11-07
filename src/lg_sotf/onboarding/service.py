"""First-run checklist of a tenant, computed from its own data on every request.

Steps (ids are stable; the UI owns the wording and links):

* ``source_connected``: a source is registered or a real (non-sample) alert
  has arrived;
* ``notifications_configured``: a notification integration exists. The
  ``integrations`` table is optional (a separate feature); while it is
  missing, or unreadable for this role, the step is reported as not
  ``available`` and does not count towards completion;
* ``teammate_invited``: the tenant has more than one user account;
* ``autonomy_reviewed``: an admin saved the tenant settings or marked the
  autonomy policy reviewed (``tenants.onboarding.autonomy_reviewed_at``);
* ``first_alert_triaged``: an alert (sample alerts included) has a
  disposition or is closed.

Everything runs in one read-only transaction scoped to the tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lg_sotf.db import Connection
from lg_sotf.db.errors import STATEMENT_ERRORS
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Tenant
from lg_sotf.db.repos._base import fetch_one
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.integrations.config import NOTIFY_KINDS
from lg_sotf.observability.logging import get_logger, log_failure

log = get_logger(__name__)

STEP_IDS = (
    "source_connected",
    "notifications_configured",
    "teammate_invited",
    "autonomy_reviewed",
    "first_alert_triaged",
)

_FACTS_SQL = """
SELECT
    EXISTS (SELECT 1 FROM sources WHERE tenant_id = $1) AS has_source,
    EXISTS (SELECT 1 FROM alerts WHERE tenant_id = $1 AND source_id <> $2) AS has_alerts,
    EXISTS (SELECT 1 FROM alerts WHERE tenant_id = $1 AND source_id = $2) AS has_samples,
    (SELECT count(*) FROM users WHERE tenant_id = $1) AS users,
    EXISTS (
        SELECT 1 FROM alerts WHERE tenant_id = $1 AND (disposition IS NOT NULL OR status = 'closed')
    ) AS triaged
"""


@dataclass(frozen=True)
class Step:
    id: str
    done: bool
    available: bool = True


@dataclass(frozen=True)
class OnboardingStatus:
    tenant_id: str
    steps: List[Step]
    dismissed_at: Optional[str]
    samples_sent: bool
    marks: Dict[str, Any] = field(default_factory=dict)

    @property
    def dismissed(self) -> bool:
        return self.dismissed_at is not None

    @property
    def counted(self) -> List[Step]:
        return [s for s in self.steps if s.available]

    @property
    def completed(self) -> int:
        return sum(1 for s in self.counted if s.done)

    @property
    def complete(self) -> bool:
        return self.completed == len(self.counted)


async def _notifications_configured(conn: Connection, tenant_id: str) -> Optional[bool]:
    """Whether the tenant has an enabled notification integration (Slack, Teams, email, webhook).

    Ticketing integrations and disabled rows do not count: they notify nobody.
    ``None`` when the table does not exist or cannot be read.
    """
    if await conn.fetchval("SELECT to_regclass('public.integrations') IS NOT NULL") is not True:
        return None
    try:
        async with conn.transaction():  # a savepoint: a refused read must not abort the whole check
            return bool(
                await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM integrations"
                    " WHERE tenant_id = $1 AND enabled AND kind = ANY($2::text[]))",
                    tenant_id,
                    list(NOTIFY_KINDS),
                )
            )
    except STATEMENT_ERRORS as exc:
        log_failure(log, "onboarding.integrations_unreadable", exc, level="info", error_type=type(exc).__name__)
        return None


async def onboarding_status(db: Database, tenant: Tenant) -> OnboardingStatus:
    async with db.tenant_tx(tenant.id, readonly=True) as conn:
        facts = await fetch_one(conn, _FACTS_SQL, tenant.id, SAMPLE_SOURCE_ID)
        notifications = await _notifications_configured(conn, tenant.id)
    marks = dict(tenant.onboarding or {})
    steps = [
        Step("source_connected", bool(facts["has_source"] or facts["has_alerts"])),
        Step("notifications_configured", bool(notifications), available=notifications is not None),
        Step("teammate_invited", int(facts["users"]) > 1),
        Step("autonomy_reviewed", bool(marks.get("autonomy_reviewed_at"))),
        Step("first_alert_triaged", bool(facts["triaged"])),
    ]
    dismissed = marks.get("dismissed_at")
    return OnboardingStatus(
        tenant_id=tenant.id,
        steps=steps,
        dismissed_at=str(dismissed) if dismissed else None,
        samples_sent=bool(facts["has_samples"]),
        marks=marks,
    )


__all__ = ["STEP_IDS", "OnboardingStatus", "Step", "onboarding_status"]
