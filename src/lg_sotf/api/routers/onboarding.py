# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/onboarding`` (admin): the tenant's getting-started checklist.

* ``GET /onboarding/status``: checklist state, computed server-side from the
  tenant's data (:mod:`lg_sotf.onboarding.service`).
* ``POST /onboarding/sample-alerts``: ingest the built-in synthetic alerts
  (:mod:`lg_sotf.onboarding.samples`) through the normal ingestion service
  under the reserved source ``demo:samples`` and queue them for triage.
  Idempotent: the set has fixed ids, so a repeat stores nothing new. Sample
  alerts are flagged ``sample`` and not metered or subject to the daily quota.
* ``POST /onboarding/autonomy-reviewed``: mark the autonomy policy reviewed
  without changing it (saving the tenant settings marks it as well).
* ``POST /onboarding/dismiss``: hide the dashboard banner for the tenant.

Changes are audited in the tenant.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from lg_sotf.api.auth.deps import ADMIN, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.onboarding import SAMPLE_SOURCE_ID, OnboardingStatus, onboarding_status, sample_events
from lg_sotf.services.dispatch import dispatch_new_alerts

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


class OnboardingStepOut(BaseModel):
    id: str
    done: bool
    available: bool


class OnboardingStatusOut(BaseModel):
    tenant_id: str
    steps: List[OnboardingStepOut]
    completed: int
    total: int
    complete: bool
    dismissed: bool
    dismissed_at: Optional[str] = None
    samples_sent: bool


class SampleAlertsOut(BaseModel):
    source_id: str
    received: int
    inserted: int
    duplicates: int
    enqueued: int
    alert_ids: List[str]


def _out(status: OnboardingStatus) -> OnboardingStatusOut:
    return OnboardingStatusOut(
        tenant_id=status.tenant_id,
        steps=[OnboardingStepOut(id=s.id, done=s.done, available=s.available) for s in status.steps],
        completed=status.completed,
        total=len(status.counted),
        complete=status.complete,
        dismissed=status.dismissed,
        dismissed_at=status.dismissed_at,
        samples_sent=status.samples_sent,
    )


async def _status(ctx: ApiContext, tenant_id: str) -> OnboardingStatusOut:
    return _out(await onboarding_status(ctx.db, await ctx.repos.tenants.get(tenant_id)))


async def _audit(ctx: ApiContext, principal: Principal, action: str, **details: object) -> None:
    await AuditLogger(ctx.repos).record(
        principal.tenant_id,
        action,
        "tenant",
        principal.tenant_id,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        details=details,
    )


@router.get("/status", response_model=OnboardingStatusOut, summary="Getting-started checklist")
async def get_status(request: Request, principal: Principal = Depends(require(ADMIN))) -> OnboardingStatusOut:
    return await _status(get_ctx(request), principal.tenant_id)


@router.post(
    "/sample-alerts", response_model=SampleAlertsOut, summary="Send the built-in sample alerts (idempotent)"
)
async def send_sample_alerts(request: Request, principal: Principal = Depends(require(ADMIN))) -> SampleAlertsOut:
    ctx = get_ctx(request)
    tenant_id = principal.tenant_id
    events = sample_events()
    result = await ctx.ingestion.ingest(tenant_id, SAMPLE_SOURCE_ID, events)
    enqueued = await dispatch_new_alerts(ctx.repos, ctx.queue, tenant_id, list(result.inserted), events=ctx.events)
    if result.inserted:
        await ctx.repos.tenants.mark_onboarding(tenant_id, "samples_sent_at")
    await _audit(
        ctx,
        principal,
        "onboarding.sample_alerts_sent",
        inserted=len(result.inserted),
        duplicates=result.duplicates,
        rejected=len(result.rejected),
    )
    return SampleAlertsOut(
        source_id=SAMPLE_SOURCE_ID,
        received=len(events),
        inserted=len(result.inserted),
        duplicates=result.duplicates,
        enqueued=enqueued,
        alert_ids=[i.alert_id for i in result.items if i.alert_id],
    )


@router.post("/autonomy-reviewed", response_model=OnboardingStatusOut, summary="Mark the autonomy policy reviewed")
async def mark_autonomy_reviewed(request: Request, principal: Principal = Depends(require(ADMIN))) -> OnboardingStatusOut:
    ctx = get_ctx(request)
    await ctx.repos.tenants.mark_onboarding(principal.tenant_id, "autonomy_reviewed_at")
    await _audit(ctx, principal, "onboarding.autonomy_reviewed")
    return await _status(ctx, principal.tenant_id)


@router.post("/dismiss", response_model=OnboardingStatusOut, summary="Hide the getting-started banner")
async def dismiss(request: Request, principal: Principal = Depends(require(ADMIN))) -> OnboardingStatusOut:
    ctx = get_ctx(request)
    await ctx.repos.tenants.mark_onboarding(principal.tenant_id, "dismissed_at")
    await _audit(ctx, principal, "onboarding.dismissed")
    return await _status(ctx, principal.tenant_id)
