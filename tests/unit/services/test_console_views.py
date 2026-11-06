"""Console views: escalation row context, action guardrail and blast radius, approvable counts."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Callable, Dict, Optional

import pytest

from lg_sotf.db.repos import AlertDigest, Escalation
from lg_sotf.services.action_views import LiveLimits, action_view
from lg_sotf.services.dashboard import approvable, llm_model
from lg_sotf.services.escalation_views import escalation_view, routing_of
from lg_sotf.services.response import ResponsePolicy
from lg_sotf.settings import Settings
from tests.unit.services._support import make_action

pytestmark = pytest.mark.unit


def make_escalation(**kw: Any) -> Escalation:
    now = datetime.now(UTC)
    base: Dict[str, Any] = dict(
        id="e1", tenant_id="t1", alert_id="a1", thread_id="t1:a1", level="L1", status="open", reason="grey zone",
        priority=5, summary={}, related_alert_ids=[], assigned_to=None, sla_deadline=now, decision=None,
        decision_notes=None, approved_actions=[], decided_by=None, decided_at=None, claimed_at=None, version=0,
        created_at=now, updated_at=now,
    )
    base.update(kw)
    return Escalation(**base)


def digest(**kw: Any) -> AlertDigest:
    base: Dict[str, Any] = dict(
        id="a1", severity="high", title="Unusual sign-in", fingerprint="fp", source_id="entra", source_name="Entra ID",
        rule_name=None, entities={"users": ["j.doe@example.com"], "ips": ["203.0.113.4"]},
    )
    base.update(kw)
    return AlertDigest(**base)


def test_escalation_view_joins_owner_alert_and_summary() -> None:
    owner, decider = uuid.uuid4(), uuid.uuid4()
    escalation = make_escalation(
        assigned_to=owner,
        decided_by=decider,
        summary={
            "conclusion": "TOR sign-in nine minutes after a normal one. MFA fatigue is likely.",
            "llm_used": True,
            "routing": {"code": "grey_zone", "confidence": 42, "band": {"min": 30, "max": 70}},
        },
    )
    view = escalation_view(escalation, {owner: "owner@example.com"}, digest(rule_name="Unusual sign-in pattern"))
    assert view.assigned_to_email == "owner@example.com"
    assert view.decided_by_email is None  # a user who no longer exists
    assert (view.rule, view.source_id, view.source_name, view.alert_severity) == (
        "Unusual sign-in pattern", "entra", "Entra ID", "high"
    )
    assert view.entities_preview == {
        "items": [{"kind": "user", "value": "j.doe@example.com"}, {"kind": "ip", "value": "203.0.113.4"}],
        "counts": {"user": 1, "ip": 1},
    }
    assert view.ai_reason == "TOR sign-in nine minutes after a normal one."
    assert view.ai_reason_source == "model"
    assert view.routing == {"code": "grey_zone", "confidence": 42.0, "band": {"min": 30, "max": 70}}


def test_escalation_view_of_an_older_escalation_leaves_unknowns_empty() -> None:
    view = escalation_view(make_escalation(summary={"conclusion": "Rules only."}), {}, None)
    assert view.rule is None and view.entities_preview is None and view.routing is None
    assert view.ai_reason == "Rules only." and view.ai_reason_source is None
    assert escalation_view(make_escalation(summary={"llm_used": False}), {}, digest()).ai_reason_source is None
    assert digest(rule_name="  ").rule == "Unusual sign-in"


@pytest.mark.parametrize(
    ("routing", "expected"),
    [
        (None, None),
        ({"confidence": 3}, None),
        ({"code": "inconclusive", "confidence": True, "band": {"min": "a", "max": 3}}, {"code": "inconclusive", "confidence": None, "band": None}),
        ({"code": "high_risk"}, {"code": "high_risk", "confidence": None, "band": None}),
    ],
)
def test_routing_of_ignores_malformed_values(routing: Optional[Dict[str, Any]], expected: object) -> None:
    assert routing_of({"routing": routing} if routing is not None else {}) == expected


def live(make_settings: Callable[..., Settings], tenant: Optional[Dict[str, Any]] = None, used: int = 0) -> LiveLimits:
    return LiveLimits(ResponsePolicy.resolve(tenant or {}, make_settings()), used, {"isolate_host": used})


def test_a_pending_action_is_checked_against_the_current_policy(make_settings: Callable[..., Settings]) -> None:
    action = make_action(
        status="awaiting_approval",
        action_type="isolate_host",
        target="ws-042",
        risk_level="high",
        params={"explanation": "awaiting approval: high risk needs an admin approval", "approval_reason": "admin_approval_required"},
    )
    passed = action_view(action, live(make_settings, used=2))
    assert passed.guardrail is not None
    assert (passed.guardrail.verdict, passed.guardrail.evaluated, passed.guardrail.code) == ("passed", "now", None)
    assert passed.guardrail.approval_reason == "admin_approval_required"
    assert passed.blast_radius.target_kind == "host"
    assert (passed.blast_radius.hourly_limit, passed.blast_radius.executed_last_hour) == (5, 2)
    assert passed.blast_radius.tenant_executed_last_hour == 2 and passed.blast_radius.tenant_hourly_cap is not None
    assert passed.reversible is True and passed.irreversible_note is None

    protected = action_view(action, live(make_settings, {"protected_assets": {"hosts": ["ws-*"]}}))
    assert protected.guardrail is not None
    assert (protected.guardrail.verdict, protected.guardrail.code) == ("blocked", "protected_asset")
    assert protected.guardrail.reason and "protected" in protected.guardrail.reason


def test_a_blocked_action_reports_the_recorded_guardrail() -> None:
    planned = make_action(status="blocked", blocked_reason="non_public_ip", params={"explanation": "blocked: internal"})
    view = action_view(planned, None)
    assert view.guardrail is not None and (view.guardrail.verdict, view.guardrail.evaluated) == ("blocked", "recorded")
    assert (view.guardrail.code, view.guardrail.reason) == ("non_public_ip", "blocked: internal")
    at_execution = make_action(
        status="blocked", blocked_reason="protected_asset",
        params={"explanation": "awaiting approval: tenant autonomy"},
        result={"guardrail": "protected_asset", "explanation": "the target is protected", "stage": "execution"},
    )
    assert action_view(at_execution, None).guardrail.reason == "the target is protected"  # type: ignore[union-attr]
    bare = make_action(status="blocked", blocked_reason="autonomy_disabled", params={})
    assert action_view(bare, None).guardrail.reason.startswith("the tenant's autonomy")  # type: ignore[union-attr]


def test_other_actions_have_no_verdict_or_hourly_figures(make_settings: Callable[..., Settings]) -> None:
    done = action_view(
        make_action(status="succeeded", action_type="terminate_process", target="evil.exe",
                    params={"scope": {"hosts": ["ws-1", 7]}}),
        live(make_settings),
    )
    assert done.guardrail is None and done.blast_radius.hourly_limit is None
    assert done.blast_radius.scope_hosts == ["ws-1"]
    assert done.reversible is False and done.irreversible_note
    unknown = action_view(make_action(status="succeeded", action_type="retired_type"), None)
    assert unknown.reversible is None and unknown.blast_radius.target_kind is None


def test_approvable_counts_what_the_role_may_approve(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    pending = {"low": 2, "medium": 1, "high": 3, "critical": 4, "bogus": 9}
    assert approvable(pending, "analyst", {}, settings) == 3
    assert approvable(pending, "viewer", {}, settings) == 0
    admin_all = approvable(pending, "admin", {"autonomy": {"critical": "approval"}}, settings)
    assert admin_all == 10
    assert approvable(pending, "admin", {"autonomy": {"critical": "disabled", "high": "disabled"}}, settings) == 3


def test_llm_model_is_the_deep_tier_when_enabled(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    assert llm_model(settings) == settings.llm.deep.model
    assert llm_model(make_settings(llm={"enabled": False})) is None
