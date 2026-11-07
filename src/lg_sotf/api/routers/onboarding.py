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

First-run setup wizard (the install's platform admin, in their home tenant;
:mod:`lg_sotf.onboarding.setup`):

* ``GET /onboarding/setup``: whether setup is done, the organisation and
  tenant names, the picked model profile, the model configured now (provider,
  models, where it is hosted) and the profiles on offer, EU or local first;
* ``PUT /onboarding/setup``: save the organisation name, the tenant name and
  the picked profile. The running model is install configuration and is not
  changed; ``POST /tenant/llm/test`` tests it;
* ``POST /onboarding/setup/complete``: mark setup done (also when skipped).

Changes are audited in the tenant.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator

from lg_sotf.api.auth.deps import ADMIN, Access, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import ApiContext, get_ctx
from lg_sotf.api.schemas import In
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.onboarding import SAMPLE_SOURCE_ID, OnboardingStatus, onboarding_status, sample_events
from lg_sotf.onboarding.llm_profiles import DEFAULT_PROFILE, PROFILES, configured_model
from lg_sotf.onboarding.progress import record_step
from lg_sotf.onboarding.setup import SetupState, complete_setup, save_setup, setup_state
from lg_sotf.services.dispatch import dispatch_new_alerts

router = APIRouter(prefix="/onboarding", tags=["onboarding"])

# The install's first-run setup: a platform admin's own account, in their home tenant.
SETUP = Access(role="admin", platform_admin=True, user_account=True, home_tenant_only=True)


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
    first_verdict: bool = Field(
        default=False, description="An alert (samples included) is closed or waits for an analyst or an approval."
    )


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
        first_verdict=status.first_verdict,
    )


async def _status(ctx: ApiContext, tenant_id: str) -> OnboardingStatusOut:
    return _out(await onboarding_status(ctx.db, await ctx.repos.tenants.get(tenant_id)))


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
    await record_step(
        ctx.repos,
        AuditLogger(ctx.repos),
        tenant_id,
        principal.actor,
        "onboarding.sample_alerts_sent",
        mark="samples_sent_at" if result.inserted else None,
        details={"inserted": len(result.inserted), "duplicates": result.duplicates, "rejected": len(result.rejected)},
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
    await record_step(
        ctx.repos,
        AuditLogger(ctx.repos),
        principal.tenant_id,
        principal.actor,
        "onboarding.autonomy_reviewed",
        mark="autonomy_reviewed_at",
    )
    return await _status(ctx, principal.tenant_id)


@router.post("/dismiss", response_model=OnboardingStatusOut, summary="Hide the getting-started banner")
async def dismiss(request: Request, principal: Principal = Depends(require(ADMIN))) -> OnboardingStatusOut:
    ctx = get_ctx(request)
    await record_step(
        ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, "onboarding.dismissed", mark="dismissed_at"
    )
    return await _status(ctx, principal.tenant_id)


# ------------------------------------------------------------------ first-run setup wizard

ProfileId = Literal["mistral_eu", "ollama_local", "self_hosted", "anthropic"]
Residency = Literal["eu", "local", "us", "cn", "offline", "unknown"]


class EnvVarOut(BaseModel):
    name: str
    value: str


class LlmProfileOut(BaseModel):
    id: str
    label: str
    residency: Residency
    description: str
    provider: str
    fast_model: str
    deep_model: str
    env: List[EnvVarOut]


class ConfiguredModelOut(BaseModel):
    provider: str
    enabled: bool
    fast_model: str
    deep_model: str
    residency: Residency = Field(description="Where the configured model runs; cn is flagged in the UI.")
    profile: Optional[str] = Field(default=None, description="The offered profile the configuration matches.")


class SetupOut(BaseModel):
    completed: bool
    completed_at: Optional[str] = None
    tenant_id: str
    tenant_name: str
    organisation: Optional[str] = None
    llm_profile: Optional[str] = Field(default=None, description="The profile picked in the wizard.")
    default_llm_profile: str
    configured_llm: ConfiguredModelOut
    llm_profiles: List[LlmProfileOut]


class SetupIn(In):
    organisation: str = Field(min_length=1, max_length=200)
    tenant_name: str = Field(min_length=1, max_length=200)
    llm_profile: Optional[ProfileId] = None

    @field_validator("organisation", "tenant_name")
    @classmethod
    def _one_line(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("must not be blank")
        return value


class SetupCompleteIn(In):
    skipped: bool = False


def _setup_out(ctx: ApiContext, state: SetupState) -> SetupOut:
    model = configured_model(ctx.settings)
    return SetupOut(
        completed=state.completed,
        completed_at=state.completed_at,
        tenant_id=state.tenant_id,
        tenant_name=state.tenant_name,
        organisation=state.organisation,
        llm_profile=state.llm_profile,
        default_llm_profile=DEFAULT_PROFILE,
        configured_llm=ConfiguredModelOut(
            provider=model.provider,
            enabled=model.enabled,
            fast_model=model.fast_model,
            deep_model=model.deep_model,
            residency=model.residency,
            profile=model.profile,
        ),
        llm_profiles=[
            LlmProfileOut(
                id=p.id,
                label=p.label,
                residency=p.residency,
                description=p.description,
                provider=p.provider,
                fast_model=p.fast_model,
                deep_model=p.deep_model,
                env=[EnvVarOut(name=n, value=v) for n, v in p.env()],
            )
            for p in PROFILES
        ],
    )


@router.get("/setup", response_model=SetupOut, summary="First-run setup state (platform admin)")
async def get_setup(request: Request, principal: Principal = Depends(require(SETUP))) -> SetupOut:
    ctx = get_ctx(request)
    return _setup_out(ctx, setup_state(await ctx.repos.tenants.get(principal.tenant_id)))


@router.put("/setup", response_model=SetupOut, summary="Save the organisation, tenant name and model profile")
async def put_setup(body: SetupIn, request: Request, principal: Principal = Depends(require(SETUP))) -> SetupOut:
    ctx = get_ctx(request)
    state = await save_setup(
        ctx.repos,
        AuditLogger(ctx.repos),
        principal.tenant_id,
        principal.actor,
        organisation=body.organisation,
        tenant_name=body.tenant_name,
        llm_profile=body.llm_profile,
    )
    ctx.tenants.invalidate(principal.tenant_id)
    return _setup_out(ctx, state)


@router.post("/setup/complete", response_model=SetupOut, summary="Mark the first-run setup done")
async def post_setup_complete(
    request: Request, body: Optional[SetupCompleteIn] = None, principal: Principal = Depends(require(SETUP))
) -> SetupOut:
    ctx = get_ctx(request)
    skipped = body.skipped if body is not None else False
    state = await complete_setup(ctx.repos, AuditLogger(ctx.repos), principal.tenant_id, principal.actor, skipped=skipped)
    return _setup_out(ctx, state)
