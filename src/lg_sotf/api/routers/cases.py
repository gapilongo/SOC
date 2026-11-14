# ruff: noqa: B008 - FastAPI declares dependencies and parameters as call defaults
"""``/cases``: the case view. A case is today's escalation with its alerts, and its key is the escalation's id."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from lg_sotf.api.auth.deps import VIEWER, require
from lg_sotf.api.auth.principal import Principal
from lg_sotf.api.context import get_ctx
from lg_sotf.api.stability import route_contract
from lg_sotf.domain.case import Case
from lg_sotf.services.case import case

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get(
    "/{case_id}",
    response_model=Case,
    summary="One case: its alerts, who or what closed each and why (the case view)",
    **route_contract(stability="beta"),
)
async def get_case(case_id: str, request: Request, principal: Principal = Depends(require(VIEWER))) -> Case:
    """One read model for the case page: the case (the escalation ``case_id``), every alert in it with its state
    and who or what closed it and why, the alerts the safety net linked or reopened, the response actions with
    their status and guardrail result, what the alerts share, and one merged timeline. Built from stored data:
    no model is called, nothing is written.

    ``not_available`` names what the stored data cannot say yet. An alert that waits for its blind-audit label
    shows what its source sent and nothing of the AI's side (``hidden_for_blind_audit``).
    """
    ctx = get_ctx(request)
    return await case(ctx.repos, ctx.settings, principal.tenant_id, case_id)
