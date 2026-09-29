"""ResponseService: typed actions, autonomy, guardrails, approval and dry-run execution."""

from __future__ import annotations

from typing import Any, Callable, Dict
from uuid import UUID

import pytest

from lg_sotf.services.response import (
    ConnectorResult,
    DryRunConnector,
    PlanContext,
    ResponseService,
    actions_from_recommendations,
    build_candidates,
    detect_threat_type,
    resolve_autonomy,
    validate_target,
)
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeEvents, FakeRepos, FakeTenants

ENTITIES = {"ip": ["185.220.101.44", "10.0.0.5", "127.0.0.1"], "host": ["ws-042"], "user": ["jdoe"],
            "hash": ["44d88612fea8a8f36de82e1278abb02f"], "process": ["powershell.exe"]}


def plan_ctx(**kw: Any) -> PlanContext:
    base: Dict[str, Any] = {"severity": "high", "evidence": "analyst", "title": "Cobalt Strike beacon", "entities": ENTITIES}
    base.update(kw)
    return PlanContext(**base)


@pytest.mark.parametrize(
    ("kind", "target", "reason"),
    [
        ("ip", "8.8.8.8", None),
        ("ip", "10.0.0.5", "non_public_ip"),
        ("ip", "127.0.0.1", "non_public_ip"),
        ("ip", "169.254.1.1", "non_public_ip"),
        ("ip", "fe80::1", "non_public_ip"),
        ("ip", "nope", "invalid_ip"),
        ("domain", "evil.example.com", None),
        ("domain", "bad domain", "invalid_domain"),
        ("url", "https://evil.example.com/x", None),
        ("url", "javascript:alert(1)", "invalid_url"),
        ("hash", "44d88612fea8a8f36de82e1278abb02f", None),
        ("hash", "xyz", "invalid_hash"),
        ("host", "ws-042", None),
        ("host", "ws 042; rm -rf", "invalid_host"),
        ("user", "jdoe\x00", "invalid_user"),
        ("alert", "alert:1", None),
    ],
)
def test_validate_target(kind: str, target: str, reason: Any) -> None:
    assert validate_target(kind, target) == reason


def test_threat_type_and_recommendations() -> None:
    assert detect_threat_type(["Mimikatz run on DC"])[0] == "credential_access"
    assert detect_threat_type(["cobalt strike beacon"])[0] == "malware"
    assert detect_threat_type(["nothing specific"])[0] == "generic"
    assert actions_from_recommendations(["Block suspicious indicators", "Isolate the host", "Open a ticket"]) == [
        "block_ip", "isolate_host", "create_ticket"
    ]


def test_candidates_are_bounded_and_typed() -> None:
    threat, cands = build_candidates(plan_ctx(), "a1")
    assert threat == "malware"
    assert ("create_ticket", "alert:a1") in {(c.action_type, c.target) for c in cands}
    assert len(cands) <= 15 and all(c.params["playbook"] == "malware" for c in cands)


def test_autonomy_resolution(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    assert resolve_autonomy("critical", {}, settings) == "disabled"
    assert resolve_autonomy("low", {"autonomy": {"low": "auto"}}, settings) == "auto"
    assert resolve_autonomy("low", {"autonomy": {"low": "yolo"}}, settings) == "approval"


async def test_plan_applies_guardrails_and_is_idempotent(make_settings: Callable[..., Settings]) -> None:
    repos, events = FakeRepos(), FakeEvents()
    service = ResponseService(repos, make_settings(), events)  # type: ignore[arg-type]
    first = await service.plan("t1", "a1", plan_ctx())
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    assert rows[("block_ip", "10.0.0.5")].status == "blocked"
    assert rows[("block_ip", "127.0.0.1")].blocked_reason == "non_public_ip"
    assert rows[("isolate_host", "ws-042")].status == "awaiting_approval"
    assert first.auto == [] and first.awaiting and first.blocked

    audit_before = len(repos.audit.entries)
    second = await service.plan("t1", "a1", plan_ctx())
    assert (second.awaiting, second.blocked) == (first.awaiting, first.blocked)
    assert len(repos.audit.entries) == audit_before
    assert all(e["type"] == "action.updated" for e in events.events)


async def test_disabled_autonomy_blocks(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", plan_ctx(title="lateral movement via psexec"))
    disable = [r for r in repos.actions.rows.values() if r.action_type == "disable_user"]
    assert disable and disable[0].status == "blocked" and disable[0].blocked_reason == "autonomy_disabled"


async def test_protected_assets_are_blocked(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos(tenants=FakeTenants({"protected_assets": ["WS-042"], "protected_cidrs": ["185.220.0.0/16"]}))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", plan_ctx())
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    assert rows[("isolate_host", "ws-042")].blocked_reason == "protected_asset"
    assert rows[("block_ip", "185.220.101.44")].blocked_reason == "protected_asset"


async def test_llm_only_evidence_never_auto_contains(make_settings: Callable[..., Settings]) -> None:
    auto_all = {"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}
    repos = FakeRepos(tenants=FakeTenants(auto_all))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    result = await service.plan("t1", "a1", plan_ctx(evidence="llm_only"))
    rows = list(repos.actions.rows.values())
    contained = [r for r in rows if r.action_type in ("isolate_host", "block_ip", "quarantine_file") and r.status != "blocked"]
    assert contained and all(r.status == "awaiting_approval" for r in contained)
    assert all(r.params.get("approval_reason") == "llm_only_evidence" for r in contained)
    tickets = [r for r in rows if r.action_type == "create_ticket"]
    assert tickets[0].status == "approved" and str(tickets[0].id) in result.auto


async def test_hourly_cap_turns_auto_into_approval(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}))
    repos.actions.executed_last_hour = 50
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    result = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    assert result.auto == []
    assert any(r.params.get("approval_reason") == "hourly_cap_reached" for r in repos.actions.rows.values())


async def test_analyst_preapproval_of_a_single_target(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    result = await service.plan("t1", "a1", plan_ctx(approved_actions=["block_ip:185.220.101.44"], approved_by="u1"))
    approved = [r for r in repos.actions.rows.values() if r.status == "approved"]
    assert [(r.action_type, r.target) for r in approved] == [("block_ip", "185.220.101.44")]
    assert result.auto == [str(approved[0].id)]


async def test_analyst_preapproval_is_limited_to_low_and_medium_risk(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    ctx = plan_ctx(approved_actions=["isolate_host", "block_ip:185.220.101.44"], approved_by="u1", approver_role="analyst")
    result = await service.plan("t1", "a1", ctx)
    rows = {(r.action_type, r.target): r for r in repos.actions.rows.values()}
    isolate = rows[("isolate_host", "ws-042")]
    assert isolate.risk_level == "high" and isolate.status == "awaiting_approval"
    assert isolate.params["approval_reason"] == "admin_approval_required"
    block = rows[("block_ip", "185.220.101.44")]
    assert block.status == "approved" and block.approved_by == "u1" and str(block.id) in result.auto
    approved_audit = [e for e in repos.audit.entries if e[2] == "response_action.approved"]
    assert [(e[1], e[5]["approved_by"]) for e in approved_audit] == [("user", "u1")]

    admin_repos = FakeRepos()
    admin = ResponseService(admin_repos, make_settings(), None)  # type: ignore[arg-type]
    await admin.plan("t1", "a1", plan_ctx(approved_actions=["isolate_host"], approved_by="u2", approver_role="admin"))
    isolate = next(r for r in admin_repos.actions.rows.values() if r.action_type == "isolate_host")
    assert isolate.status == "approved" and isolate.approved_by == "u2"


async def test_policy_auto_approval_records_the_policy_as_approver(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto"}}))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    result = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    auto = [repos.actions.rows[UUID(i)] for i in result.auto]
    assert auto and all(r.approved_by == "policy:auto" and r.risk_level == "low" for r in auto)
    again = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    assert again.auto == result.auto


async def test_approval_applies_only_to_named_actions(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx())
    first, second, *rest = plan.awaiting
    blocked = plan.blocked[0]
    outcome = await service.apply_approval(
        "t1", "a1", pending_ids=plan.awaiting, approved_ids=[first, blocked, "not-ours"], rejected_ids=[second],
        decided_by="u1",
    )
    assert outcome == {first: "approved", second: "rejected"}
    assert repos.actions.rows[UUID(blocked)].status == "blocked"
    assert await service.awaiting("t1", "a1", plan.awaiting) == rest
    decisions = [e for e in repos.audit.entries if e[2] in ("response_action.approved", "response_action.rejected")]
    assert decisions and all(e[1] == "user" for e in decisions)

    executed = await service.execute("t1", "a1", plan.awaiting + plan.blocked)
    assert executed[first] == "dry_run"
    row = repos.actions.rows[UUID(first)]
    assert row.connector == "dry_run" and row.result["would_execute"] == row.action_type
    assert all(executed[r] == "awaiting_approval" for r in rest)
    again = await service.execute("t1", "a1", [first])
    assert again[first] == "dry_run"
    audited = [e[2] for e in repos.audit.entries]
    assert audited.count("response_action.executing") == 1 and "response_action.dry_run" in audited

    final = await service.apply_approval(
        "t1", "a1", pending_ids=rest, approved_ids=[], rejected_ids=[], decided_by="u1", reject_remaining=True
    )
    assert set(final) == set(rest) and set(final.values()) == {"rejected"}
    assert await service.awaiting("t1", "a1", plan.awaiting) == []


async def test_interrupted_executing_action_is_run_again(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto"}}))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    stuck = plan.auto[0]
    await repos.actions.transition("t1", UUID(stuck), "executing", connector="dry_run")

    result = await service.execute("t1", "a1", plan.auto)

    assert result[stuck] == "dry_run" and set(result.values()) == {"dry_run"}
    assert repos.actions.rows[UUID(stuck)].result["would_execute"]


async def test_hourly_cap_blocks_approved_actions_for_real_connectors(make_settings: Callable[..., Settings]) -> None:
    class Recording:
        name = "webhook"

        def __init__(self) -> None:
            self.calls: list[str] = []

        async def execute(self, action: Any) -> ConnectorResult:
            self.calls.append(action.action_type)
            return ConnectorResult("succeeded", {"ok": True})

    connector = Recording()
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto"}, "connector": "webhook"}))
    settings = make_settings(response={"dry_run": False, "max_actions_per_hour_per_tenant": 2})
    service = ResponseService(repos, settings, None, connectors={"webhook": connector})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx(evidence="rules", title="malware"))
    assert len(plan.auto) == 2

    extra, _ = await repos.actions.propose("t1", "a1", "send_alert", "alert:a1", "low", status="approved")
    result = await service.execute("t1", "a1", [*plan.auto, str(extra.id)])

    assert sorted(result.values()) == ["blocked", "succeeded", "succeeded"]
    assert repos.actions.rows[extra.id].blocked_reason == "hourly_cap_reached"
    assert len(connector.calls) == 2
    locks = [args for sql, args in repos.db.conn.statements if "pg_advisory_xact_lock" in sql]
    assert len(locks) == 3 and all(args[1] == "t1" for args in locks)


async def test_connector_failure_is_recorded(make_settings: Callable[..., Settings]) -> None:
    class Exploding:
        name = "webhook"

        async def execute(self, action: Any) -> ConnectorResult:
            raise ConnectionError("soar down")

    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto"}, "connector": "webhook"}))
    service = ResponseService(repos, make_settings(response={"dry_run": False}), None, connectors={"webhook": Exploding()})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    result = await service.execute("t1", "a1", plan.auto)
    assert result and all(status == "failed" for status in result.values())


def test_dry_run_forced_globally(make_settings: Callable[..., Settings]) -> None:
    service = ResponseService(FakeRepos(), make_settings(), None, connectors={"webhook": object()})  # type: ignore[arg-type,dict-item]
    assert isinstance(service.connector_for({"connector": "webhook"}), DryRunConnector)
