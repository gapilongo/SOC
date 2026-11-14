# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/pov/runs``: proof-of-value runs (PRD-11.1).

* ``POST /pov/runs`` (admins, also an MSSP's under a grant): record a run
  with a history window of ``backtest_days`` ending now and a shadow period
  of ``shadow_days`` starting now. Nothing else is written: no alert,
  action or notification. The scheduler then runs the backtest, read-only.
* ``GET /pov/runs`` and ``GET /pov/runs/{pov_run_id}`` (viewers): the runs, each
  with its status, its backtest (status, and on the run's own read the
  stored result) and its shadow period with the report links over it.
* ``POST /pov/runs/{pov_run_id}/cancel`` (admins): end a run in progress.

All beta (:func:`lg_sotf.api.app.api_routers`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field, StringConstraints

from lg_sotf.api.auth.deps import ADMIN, VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.errors import ApiError
from lg_sotf.api.schemas import In, PageOut
from lg_sotf.db.pagination import API_MAX_LIMIT
from lg_sotf.db.repos.pov_runs import PovRun
from lg_sotf.domain.pov import (
    DEFAULT_BACKTEST_DAYS,
    DEFAULT_SHADOW_DAYS,
    MAX_BACKTEST_DAYS,
    MAX_NAME_CHARS,
    MAX_SHADOW_DAYS,
    PovBacktestStatus,
    PovShadowStatus,
    PovStatus,
    pov_status,
    shadow_status,
)
from lg_sotf.services.pov import PovError, PovService

router = APIRouter(prefix="/pov", tags=["pov"])

SHADOW_REPORTS = ("value", "accuracy", "detections")
_ERROR_STATUS = {"too_many_pov_runs": 429}


class PovRunIn(In):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_NAME_CHARS)]
    backtest_days: int = Field(
        default=DEFAULT_BACKTEST_DAYS, ge=1, le=MAX_BACKTEST_DAYS,
        description="History to replay: the alerts analysts decided in this many days before now.",
    )
    shadow_days: int = Field(
        default=DEFAULT_SHADOW_DAYS, ge=1, le=MAX_SHADOW_DAYS,
        description="The shadow period: this many days of live alerts from now.",
    )


class PovBacktestOut(BaseModel):
    """The backtest: analyst-decided alerts of the history window replayed read-only through the pipeline."""

    window_start: datetime
    window_end: datetime
    status: PovBacktestStatus = Field(
        description="no_data: no analyst-decided alert in the window, nothing was replayed."
    )
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = Field(
        default=None,
        description="A completed backtest's evaluation report without its per-alert items "
        "(docs/evaluation.md). On the run's own read only.",
    )


class PovShadowOut(BaseModel):
    """The shadow period: the run observes the live alerts of this window and changes none of them."""

    window_start: datetime
    window_end: datetime
    status: PovShadowStatus
    reports: Dict[str, str] = Field(
        description="The tenant's reports over the shadow period: API paths, relative to the API prefix."
    )


class PovRunOut(BaseModel):
    id: UUID
    name: str
    status: PovStatus = Field(description="The phase the run is in.")
    backtest: PovBacktestOut
    shadow: PovShadowOut
    created_at: datetime
    created_by: Optional[str] = None
    cancelled_at: Optional[datetime] = None
    cancelled_by: Optional[str] = None


def shadow_reports(run: PovRun) -> Dict[str, str]:
    """The report endpoints over the run's shadow period (their windows are whole UTC days, ``to`` included)."""
    start = run.shadow_start.astimezone(UTC).date()
    end = max(start, (run.shadow_end - timedelta(microseconds=1)).astimezone(UTC).date())
    return {name: f"/reports/{name}?from={start.isoformat()}&to={end.isoformat()}" for name in SHADOW_REPORTS}


def run_out(run: PovRun, *, now: Optional[datetime] = None, detail: bool = False) -> PovRunOut:
    now = now or datetime.now(UTC)
    return PovRunOut(
        id=run.id,
        name=run.name,
        status=pov_status(
            backtest_status=run.backtest_status, shadow_end=run.shadow_end, cancelled_at=run.cancelled_at, now=now
        ),
        backtest=PovBacktestOut(
            window_start=run.backtest_start,
            window_end=run.backtest_end,
            status=run.backtest_status,
            started_at=run.backtest_started_at,
            finished_at=run.backtest_finished_at,
            error=run.backtest_error,
            result=run.backtest_result if detail else None,
        ),
        shadow=PovShadowOut(
            window_start=run.shadow_start,
            window_end=run.shadow_end,
            status=shadow_status(run.shadow_start, run.cancelled_at or run.shadow_end, now),
            reports=shadow_reports(run),
        ),
        created_at=run.created_at,
        created_by=run.created_by,
        cancelled_at=run.cancelled_at,
        cancelled_by=run.cancelled_by,
    )


def _api_error(exc: PovError) -> ApiError:
    return ApiError(_ERROR_STATUS.get(exc.code, 409), exc.code, str(exc))


@router.get("/runs", response_model=PageOut[PovRunOut], summary="Proof-of-value runs, newest first")
async def list_runs(
    request: Request,
    cursor: Optional[str] = Query(default=None, max_length=512),
    limit: int = Query(default=50, ge=1, le=API_MAX_LIMIT),
    principal: Principal = Depends(require(VIEWER)),
) -> PageOut[PovRunOut]:
    page = await PovService(get_ctx(request).repos).runs(principal.tenant_id, limit=limit, cursor=cursor)
    now = datetime.now(UTC)
    return PageOut[PovRunOut](items=[run_out(r, now=now) for r in page.items], next_cursor=page.next_cursor)


@router.post(
    "/runs",
    response_model=PovRunOut,
    status_code=201,
    summary="Start a proof of value: a read-only backtest over history, then a shadow period",
)
async def create_run(
    body: PovRunIn, request: Request, principal: Principal = Depends(require(ADMIN))
) -> PovRunOut:
    try:
        run = await PovService(get_ctx(request).repos).create(
            principal.tenant_id, name=body.name, backtest_days=body.backtest_days, shadow_days=body.shadow_days,
            actor=principal.actor,
        )
    except PovError as exc:
        raise _api_error(exc) from exc
    return run_out(run, detail=True)


@router.get("/runs/{pov_run_id}", response_model=PovRunOut, summary="One proof-of-value run with its backtest result")
async def get_run(pov_run_id: UUID, request: Request, principal: Principal = Depends(require(VIEWER))) -> PovRunOut:
    return run_out(await PovService(get_ctx(request).repos).get(principal.tenant_id, pov_run_id), detail=True)


@router.post("/runs/{pov_run_id}/cancel", response_model=PovRunOut, summary="Cancel a proof-of-value run in progress")
async def cancel_run(pov_run_id: UUID, request: Request, principal: Principal = Depends(require(ADMIN))) -> PovRunOut:
    try:
        run = await PovService(get_ctx(request).repos).cancel(principal.tenant_id, pov_run_id, actor=principal.actor)
    except PovError as exc:
        raise _api_error(exc) from exc
    return run_out(run, detail=True)
