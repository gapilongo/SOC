"""Approval disposition (S1): every branch of the pure planner decision, table-driven."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

import pytest

from lg_sotf.domain.actions import guardrail_result
from lg_sotf.services.response import (
    ACTION_CATALOG,
    AutoBudget,
    Candidate,
    Disposition,
    GuardrailBlock,
    PlanContext,
    ProtectedAssets,
    ResponsePolicy,
    ResponseService,
    dispose,
)
from lg_sotf.services.rollback import dispose_rollback
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeRepos, FakeTenants

pytestmark = pytest.mark.unit

AUTO = {"low": "auto", "medium": "auto", "high": "auto", "critical": "auto"}
APPROVAL = {"low": "approval", "medium": "approval", "high": "approval", "critical": "approval"}


def policy(autonomy: Optional[Dict[str, Any]] = None, *, cap: int = 50, blast: Optional[Dict[str, int]] = None) -> ResponsePolicy:
    return ResponsePolicy(
        autonomy=dict(autonomy or AUTO), protected=ProtectedAssets(), max_actions_per_hour=cap,
        blast_radius=dict(blast if blast is not None else {"isolate_host": 5}),
    )


def ctx(**kw: Any) -> PlanContext:
    base: Dict[str, Any] = {"severity": "high", "evidence": "rules", "title": "beacon"}
    base.update(kw)
    return PlanContext(**base)


ISOLATE = Candidate("isolate_host", "ws-042")
BLOCK_IP = Candidate("block_ip", "203.0.113.5")
TICKET = Candidate("create_ticket", "alert:a1")
GUARD = GuardrailBlock("protected_asset", "matches a protected host entry")

CASES = [
    pytest.param(
        ISOLATE, ctx(), policy(), GUARD,
        Disposition("blocked", "blocked: the target is on the tenant's protected assets list: matches a protected host entry"),
        id="guardrail-block",
    ),
    pytest.param(
        BLOCK_IP, ctx(approved_actions=["block_ip"], approved_by="u1", approver_role="analyst"), policy(APPROVAL), None,
        Disposition("approved", "approved: pre-approved by the analyst decision (medium risk)", "u1"),
        id="preapproval-within-authority",
    ),
    pytest.param(
        ISOLATE, ctx(approved_actions=["isolate_host:ws-042"], approved_by="u1", approver_role="analyst"), policy(),
        None,
        Disposition("awaiting_approval", "awaiting approval: high risk needs an admin approval",
                    approval_reason="admin_approval_required"),
        id="preapproval-above-authority",
    ),
    pytest.param(
        ISOLATE, ctx(approved_actions=["isolate_host"], approved_by="u2", approver_role="admin"), policy(APPROVAL),
        None,
        Disposition("approved", "approved: pre-approved by the analyst decision (high risk)", "u2"),
        id="preapproval-by-admin",
    ),
    pytest.param(
        ISOLATE, ctx(approved_actions=["isolate_host"]), policy(APPROVAL), None,
        Disposition("awaiting_approval", "awaiting approval: tenant autonomy for high risk is 'approval'"),
        id="preapproval-without-approver-is-ignored",
    ),
    pytest.param(
        ISOLATE, ctx(evidence="llm_only"), policy(), None,
        Disposition("awaiting_approval", "awaiting approval: containment on LLM-only evidence is never automatic",
                    approval_reason="llm_only_evidence"),
        id="llm-only-containment",
    ),
    pytest.param(
        ISOLATE, ctx(corroborated_targets=frozenset({("host", "ws-099")})), policy(), None,
        Disposition(
            "awaiting_approval",
            "awaiting approval: the rule evidence does not concern this target, so containing it is not automatic",
            approval_reason="target_not_corroborated",
        ),
        id="uncorroborated-target",
    ),
    pytest.param(
        ISOLATE, ctx(corroborated_targets=frozenset({("host", "WS-042.corp.local")})), policy(), None,
        Disposition("approved", "approved: tenant autonomy for high risk is 'auto'", "policy:auto"),
        id="corroborated-target-in-another-spelling",
    ),
    pytest.param(
        ISOLATE, ctx(), policy(cap=0), None,
        Disposition("awaiting_approval", "awaiting approval: hourly cap of 0 reached",
                    approval_reason="hourly_cap_reached"),
        id="hourly-cap",
    ),
    pytest.param(
        ISOLATE, ctx(), policy(blast={"isolate_host": 0}), None,
        Disposition("awaiting_approval", "awaiting approval: at most 0 isolate_host per hour",
                    approval_reason="blast_radius_exceeded"),
        id="blast-radius",
    ),
    pytest.param(
        TICKET, ctx(evidence="llm_only"), policy(), None,
        Disposition("approved", "approved: tenant autonomy for low risk is 'auto'", "policy:auto"),
        id="auto-non-containment-on-llm-evidence",
    ),
    pytest.param(
        BLOCK_IP, ctx(), policy(), None,
        Disposition("approved", "approved: tenant autonomy for medium risk is 'auto'", "policy:auto"),
        id="auto",
    ),
    pytest.param(
        BLOCK_IP, ctx(), policy(APPROVAL), None,
        Disposition("awaiting_approval", "awaiting approval: tenant autonomy for medium risk is 'approval'"),
        id="approval",
    ),
]


@pytest.mark.parametrize(("cand", "context", "pol", "block", "expected"), CASES)
def test_dispose(
    cand: Candidate, context: PlanContext, pol: ResponsePolicy, block: Optional[GuardrailBlock], expected: Disposition
) -> None:
    budget = AutoBudget.remaining(pol, 0, {})
    before = (budget.total, dict(budget.per_type))
    assert dispose(cand, ACTION_CATALOG[cand.action_type], context, pol, block, budget) == expected
    if expected.approved_by == "policy:auto":
        per_type = dict(before[1])
        if cand.action_type in per_type:
            per_type[cand.action_type] -= 1
        assert (budget.total, budget.per_type) == (before[0] - 1, per_type)
    else:
        assert (budget.total, budget.per_type) == before


def test_auto_budget_counts_the_window_and_is_consumed_per_type() -> None:
    budget = AutoBudget.remaining(policy(cap=3, blast={"isolate_host": 2}), 1, {"isolate_host": 1, "block_ip": 9})
    assert (budget.total, budget.per_type) == (2, {"isolate_host": 1})
    assert budget.can_auto("isolate_host") and budget.can_auto("block_ip")
    budget.consume("isolate_host")
    assert not budget.can_auto("isolate_host") and budget.can_auto("block_ip")
    budget.consume("block_ip")
    assert (budget.total, budget.per_type) == (0, {"isolate_host": 0})
    assert not budget.can_auto("block_ip")
    over = AutoBudget.remaining(policy(cap=1, blast={"isolate_host": 1}), 5, {"isolate_host": 4})
    assert (over.total, over.per_type) == (0, {"isolate_host": 0})


def test_the_hourly_cap_is_reported_before_the_blast_radius() -> None:
    pol = policy(cap=1, blast={"isolate_host": 0})
    out = dispose(ISOLATE, ACTION_CATALOG["isolate_host"], ctx(), pol, None, AutoBudget(0, {"isolate_host": 0}))
    assert out.approval_reason == "hourly_cap_reached"


async def test_plan_consumes_the_budget_for_existing_rows_too(make_settings: Callable[..., Settings]) -> None:
    """An automatic approval uses the budget even when ``propose`` returns an existing row (as before S1)."""
    tenant = {"autonomy": AUTO, "response": {"blast_radius": {"block_ip": 1}}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    existing, _ = await repos.actions.propose("t1", "a1", "block_ip", "185.220.101.44", "medium",
                                              status="awaiting_approval")
    entities = {"ip": ["185.220.101.44", "45.33.32.156"]}
    context = PlanContext(severity="high", evidence="analyst", title="port scan", entities=entities)
    result = await service.plan("t1", "a1", context)
    rows = {r.target: r for r in repos.actions.rows.values() if r.action_type == "block_ip"}
    assert rows["185.220.101.44"] is existing and existing.status == "awaiting_approval"
    assert str(existing.id) in result.awaiting
    second = rows["45.33.32.156"]
    assert second.status == "awaiting_approval" and second.params["approval_reason"] == "blast_radius_exceeded"


@pytest.mark.parametrize(
    ("guard", "role", "approve", "expected"),
    [
        (GUARD, "admin", True, Disposition("blocked", "blocked: the target is on the tenant's protected assets list: matches a protected host entry")),
        (None, "admin", True, Disposition(
            "approved", "approved: rollback requested and approved by user:u1 (high risk)", "user:u1")),
        (None, "analyst", True, Disposition(
            "awaiting_approval", "awaiting approval: rolling back needs an approval for high risk",
            approval_reason="admin_approval_required")),
        (None, "admin", False, Disposition(
            "awaiting_approval", "awaiting approval: rolling back needs an approval for high risk",
            approval_reason="rollback_review")),
    ],
    ids=["blocked", "approved", "admin-required", "review"],
)
def test_dispose_rollback(guard: Optional[GuardrailBlock], role: str, approve: bool, expected: Disposition) -> None:
    assert dispose_rollback(guard, risk="high", role=role, autonomy="approval", approve=approve,
                            requester="user:u1") == expected


def test_dispose_rollback_respects_disabled_autonomy() -> None:
    out = dispose_rollback(None, risk="low", role="admin", autonomy="disabled", approve=True, requester="user:u1")
    assert out.status == "awaiting_approval" and out.approval_reason == "admin_approval_required"


def test_guardrail_result_matches_the_historical_dict() -> None:
    assert guardrail_result("hourly_cap_reached", cap=5, used=5) == {
        "guardrail": "hourly_cap_reached", "explanation": "the tenant's hourly action cap was reached", "cap": 5, "used": 5,
    }
    assert list(guardrail_result("unknown_code", detail="x", stage="rollback")) == [
        "guardrail", "explanation", "detail", "stage",
    ]
    assert guardrail_result("unknown_code")["explanation"] == "unknown_code"
    assert guardrail_result("protected_asset", code="kept")["code"] == "kept"
