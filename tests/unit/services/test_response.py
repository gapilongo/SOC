"""ResponseService: typed actions, autonomy, guardrails, approval, rate limits and execution."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, List, Tuple
from uuid import UUID

import pytest

from lg_sotf.services.connectors import ConnectorResult, DryRunConnector, MisconfiguredConnector
from lg_sotf.services.response import (
    EXECUTION_CONCURRENCY,
    PlanContext,
    ResponseService,
    actions_from_recommendations,
    build_candidates,
    detect_threat_type,
    resolve_autonomy,
)
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeEvents, FakeRepos, FakeTenants

ENTITIES = {"ip": ["185.220.101.44", "10.0.0.5", "127.0.0.1"], "host": ["ws-042"], "user": ["jdoe"],
            "hash": ["44d88612fea8a8f36de82e1278abb02f"], "process": ["powershell.exe"]}


def plan_ctx(**kw: Any) -> PlanContext:
    base: Dict[str, Any] = {"severity": "high", "evidence": "analyst", "title": "Cobalt Strike beacon", "entities": ENTITIES}
    base.update(kw)
    return PlanContext(**base)


class Recording:
    """A connector that records calls and succeeds."""

    name = "webhook"

    def __init__(self) -> None:
        self.calls: List[str] = []

    async def execute(self, action: Any) -> ConnectorResult:
        self.calls.append(str(action.id))
        return ConnectorResult("succeeded", {"ok": True})


def rows_by_key(repos: FakeRepos) -> Dict[Any, Any]:
    return {(r.action_type, r.target): r for r in repos.actions.rows.values()}


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
    assert resolve_autonomy("low", {"response": {"autonomy": {"low": "auto"}}}, settings) == "auto"
    assert resolve_autonomy("low", {"autonomy": {"low": "yolo"}}, settings) == "disabled"  # a typo never loosens


async def test_plan_applies_guardrails_explains_and_is_idempotent(make_settings: Callable[..., Settings]) -> None:
    repos, events = FakeRepos(), FakeEvents()
    service = ResponseService(repos, make_settings(), events)  # type: ignore[arg-type]
    first = await service.plan("t1", "a1", plan_ctx())
    rows = rows_by_key(repos)
    assert rows[("block_ip", "10.0.0.5")].blocked_reason == "non_public_ip"
    assert rows[("block_ip", "127.0.0.1")].blocked_reason == "unroutable_ip"
    assert rows[("block_ip", "127.0.0.1")].params["explanation"].startswith("blocked: loopback")
    isolate = rows[("isolate_host", "ws-042")]
    assert isolate.status == "awaiting_approval" and "autonomy for high risk is 'approval'" in isolate.params["explanation"]
    assert isolate.params["alert"] == {"severity": "high", "title": "Cobalt Strike beacon"}
    assert all(r.params.get("explanation") for r in repos.actions.rows.values())
    assert first.auto == [] and first.awaiting and first.blocked

    audit_before = len(repos.audit.entries)
    second = await service.plan("t1", "a1", plan_ctx())
    assert (second.awaiting, second.blocked) == (first.awaiting, first.blocked)
    assert len(repos.audit.entries) == audit_before
    assert events.events and all(e["type"] == "action.updated" for e in events.events)


async def test_disabled_autonomy_blocks(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", plan_ctx(title="lateral movement via psexec"))
    disable = [r for r in repos.actions.rows.values() if r.action_type == "disable_user"]
    assert disable and disable[0].status == "blocked" and disable[0].blocked_reason == "autonomy_disabled"


async def test_protected_assets_are_blocked(make_settings: Callable[..., Settings]) -> None:
    tenant = {"protected_assets": {"hosts": ["WS-042"], "cidrs": ["185.220.0.0/16"]}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", plan_ctx())
    rows = rows_by_key(repos)
    assert rows[("isolate_host", "ws-042")].blocked_reason == "protected_asset"
    assert rows[("collect_forensics", "ws-042")].blocked_reason == "protected_asset"
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


async def test_blast_radius_turns_auto_into_approval(make_settings: Callable[..., Settings]) -> None:
    tenant = {"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}, "response": {"blast_radius": {"isolate_host": 2}}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    repos.actions.executed_earlier = {"isolate_host": 2}
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    rows = rows_by_key(repos)
    isolate = rows[("isolate_host", "ws-042")]
    assert isolate.status == "awaiting_approval" and isolate.params["approval_reason"] == "blast_radius_exceeded"
    assert "at most 2 isolate_host per hour" in isolate.params["explanation"]
    assert rows[("block_ip", "185.220.101.44")].status == "approved"


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
    rows = rows_by_key(repos)
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
    assert all(r.params["explanation"] == "approved: tenant autonomy for low risk is 'auto'" for r in auto)
    again = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    assert again.auto == result.auto


async def test_partial_approval_leaves_other_actions_pending(make_settings: Callable[..., Settings]) -> None:
    """Regression (Wave 2): approving some actions must not reject the others unless reject_remaining is set."""
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
    assert repos.actions.rows[UUID(second)].blocked_reason == "rejected_by_reviewer"
    assert repos.actions.rows[UUID(blocked)].status == "blocked"
    assert rest and await service.awaiting("t1", "a1", plan.awaiting) == [first, *rest]
    decisions = [e for e in repos.audit.entries if e[2] in ("response_action.approved", "response_action.rejected")]
    assert decisions and all(e[1] == "user" for e in decisions)

    executed = await service.execute("t1", "a1", plan.awaiting + plan.blocked)
    assert executed[first] == "dry_run"
    row = repos.actions.rows[UUID(first)]
    assert row.connector == "dry_run" and row.result["would_execute"] == row.action_type
    assert all(executed[r] == "awaiting_approval" for r in rest)
    assert await service.awaiting("t1", "a1", plan.awaiting) == rest
    again = await service.execute("t1", "a1", [first])
    assert again[first] == "dry_run"
    audited = repos.audit.actions()
    assert audited.count("response_action.executing") == 1 and "response_action.dry_run" in audited

    final = await service.apply_approval(
        "t1", "a1", pending_ids=rest, approved_ids=[], rejected_ids=[], decided_by="u1", reject_remaining=True
    )
    assert set(final) == set(rest) and set(final.values()) == {"rejected"}
    assert {repos.actions.rows[UUID(r)].blocked_reason for r in rest} == {"rejected_with_remaining"}
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


async def test_interrupted_action_resumes_on_its_recorded_connector(make_settings: Callable[..., Settings]) -> None:
    connector = Recording()
    tenant = {"autonomy": {"low": "auto"}, "response": {"connector": "webhook"}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(response={"dry_run": False}), None, connectors={"webhook": connector})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx(evidence="rules"))
    stuck = plan.auto[0]
    await repos.actions.transition("t1", UUID(stuck), "executing", connector="webhook")
    result = await service.execute("t1", "a1", [stuck])
    assert result == {stuck: "succeeded"} and connector.calls == [stuck]
    # Terminal actions are never executed again.
    assert await service.execute("t1", "a1", [stuck]) == {stuck: "succeeded"} and connector.calls == [stuck]


async def test_hourly_cap_blocks_approved_actions_for_real_connectors(make_settings: Callable[..., Settings]) -> None:
    connector = Recording()
    repos = FakeRepos(tenants=FakeTenants({"autonomy": {"low": "auto"}, "connector": "webhook"}))
    settings = make_settings(response={"dry_run": False, "max_actions_per_hour_per_tenant": 2})
    service = ResponseService(repos, settings, None, connectors={"webhook": connector})  # type: ignore[arg-type]
    plan = await service.plan("t1", "a1", plan_ctx(evidence="rules", title="malware"))
    assert len(plan.auto) == 2

    extra, _ = await repos.actions.propose("t1", "a1", "send_alert", "alert:a1", "low", status="approved")
    result = await service.execute("t1", "a1", [*plan.auto, str(extra.id)])

    assert sorted(result.values()) == ["blocked", "succeeded", "succeeded"]
    blocked = repos.actions.rows[extra.id]
    assert blocked.blocked_reason == "hourly_cap_reached" and blocked.result == {
        "guardrail": "hourly_cap_reached", "explanation": "the tenant's hourly action cap was reached", "cap": 2, "used": 2
    }
    assert len(connector.calls) == 2
    locks = [args for sql, args in repos.db.conn.statements if "pg_advisory_xact_lock" in sql]
    assert len(locks) == 3 and all(args[1] == "t1" for args in locks)


async def test_blast_radius_blocks_at_execution(make_settings: Callable[..., Settings]) -> None:
    connector = Recording()
    tenant = {"response": {"connector": "webhook", "blast_radius": {"isolate_host": 1}}}
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(response={"dry_run": False}), None, connectors={"webhook": connector})  # type: ignore[arg-type]
    one, _ = await repos.actions.propose("t1", "a1", "isolate_host", "ws-1", "high", status="approved")
    two, _ = await repos.actions.propose("t1", "a1", "isolate_host", "ws-2", "high", status="approved")
    ticket, _ = await repos.actions.propose("t1", "a1", "create_ticket", "alert:a1", "low", status="approved")
    result = await service.execute("t1", "a1", [str(one.id), str(two.id), str(ticket.id)])
    assert result == {str(one.id): "succeeded", str(two.id): "blocked", str(ticket.id): "succeeded"}
    row = repos.actions.rows[two.id]
    assert row.blocked_reason == "blast_radius_exceeded" and row.result["limit"] == 1 and row.result["used"] == 1


async def test_guardrails_are_rechecked_before_execution(make_settings: Callable[..., Settings]) -> None:
    repos = FakeRepos()
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    action, _ = await repos.actions.propose("t1", "a1", "isolate_host", "dc-01", "high", status="approved")
    repos.tenants.tenant.settings = {"protected_assets": {"hosts": ["dc-*"]}}
    result = await service.execute("t1", "a1", [str(action.id)])
    assert result == {str(action.id): "blocked"}
    row = repos.actions.rows[action.id]
    assert row.blocked_reason == "protected_asset" and row.result["stage"] == "execution"
    assert "response_action.blocked" in repos.audit.actions()


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
    assert repos.actions.rows[UUID(plan.auto[0])].result == {"error": "connector_exception", "error_type": "ConnectionError"}


def test_dry_run_forced_globally_and_per_tenant(make_settings: Callable[..., Settings]) -> None:
    webhook = Recording()
    forced = ResponseService(FakeRepos(), make_settings(), None, connectors={"webhook": webhook})  # type: ignore[arg-type]
    assert isinstance(forced.connector_for("t1", {"connector": "webhook"}), DryRunConnector)
    live = ResponseService(FakeRepos(), make_settings(response={"dry_run": False}), None, connectors={"webhook": webhook})  # type: ignore[arg-type]
    assert live.connector_for("t1", {"response": {"connector": "webhook"}}) is webhook
    assert isinstance(live.connector_for("t1", {"response": {"connector": "webhook", "dry_run": True}}), DryRunConnector)
    assert isinstance(live.connector_for("t1", {}), DryRunConnector)
    assert isinstance(live.connector_for("t1", {"response": {"connector": "edr-magic"}}), MisconfiguredConnector)


def test_malformed_tenant_dry_run_flag_fails_safe(make_settings: Callable[..., Settings]) -> None:
    webhook = Recording()
    live = ResponseService(FakeRepos(), make_settings(response={"dry_run": False}), None, connectors={"webhook": webhook})  # type: ignore[arg-type]
    for flag in ("false", "yes", 0, 1, [], {}):
        tenant = {"response": {"connector": "webhook", "dry_run": flag}}
        assert isinstance(live.connector_for("t1", tenant), DryRunConnector), flag
    assert live.connector_for("t1", {"response": {"connector": "webhook", "dry_run": False}}) is webhook


class Slow:
    """A connector that takes ``delay`` seconds per action and records how many run at once."""

    name = "webhook"

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.running = 0
        self.peak = 0
        self.calls: List[str] = []

    async def execute(self, action: Any) -> ConnectorResult:
        self.calls.append(str(action.id))
        self.running += 1
        self.peak = max(self.peak, self.running)
        try:
            await asyncio.sleep(self.delay)
        finally:
            self.running -= 1
        return ConnectorResult("succeeded", {"ok": True})


async def _approved(repos: FakeRepos, count: int) -> List[str]:
    ids = []
    for n in range(count):
        action, _ = await repos.actions.propose("t1", "a1", "block_ip", f"185.220.101.{n + 1}", "medium", status="approved")
        ids.append(str(action.id))
    return ids


def _live(make_settings: Callable[..., Settings], connector: Any, **worker: Any) -> Tuple[FakeRepos, ResponseService]:
    repos = FakeRepos(tenants=FakeTenants({"response": {"connector": "webhook"}}))
    settings = make_settings(response={"dry_run": False}, **({"worker": worker} if worker else {}))
    return repos, ResponseService(repos, settings, None, connectors={"webhook": connector})  # type: ignore[arg-type]


async def test_execution_runs_actions_concurrently_within_the_budget(make_settings: Callable[..., Settings]) -> None:
    connector = Slow(0.05)
    repos, service = _live(make_settings, connector, node_timeout_s=40.0)
    assert service.execution_budget_s == pytest.approx(30.0)  # EXECUTION_BUDGET_FRACTION of the node timeout
    ids = await _approved(repos, 10)
    result = await service.execute("t1", "a1", ids)
    assert result == {i: "succeeded" for i in ids} and sorted(connector.calls) == sorted(ids)
    assert connector.peak == EXECUTION_CONCURRENCY


async def test_connector_call_past_the_budget_is_abandoned_and_recorded(make_settings: Callable[..., Settings]) -> None:
    """RR-4: a slow receiver can no longer run the node into its timeout; the ledger explains what happened."""
    connector = Slow(10.0)
    repos, service = _live(make_settings, connector)
    ids = await _approved(repos, 6)
    started = asyncio.get_running_loop().time()
    result = await service.execute("t1", "a1", ids, budget_s=1.2)
    assert asyncio.get_running_loop().time() - started < 3.0
    assert set(result.values()) == {"failed"}
    errors = sorted(repos.actions.rows[UUID(i)].result["error"] for i in ids)
    # The first four ran into the deadline; the other two never had time to start and were not sent.
    assert errors == ["deadline"] * 4 + ["execution_budget_exhausted"] * 2
    assert len(connector.calls) == 4
    assert repos.audit.actions().count("response_action.failed") == 6


async def test_connector_raising_timeout_itself_is_a_connector_error(make_settings: Callable[..., Settings]) -> None:
    class TimesOut:
        name = "webhook"

        async def execute(self, action: Any) -> ConnectorResult:
            raise TimeoutError("receiver socket timeout")

    repos, service = _live(make_settings, TimesOut())
    ids = await _approved(repos, 1)
    assert await service.execute("t1", "a1", ids) == {ids[0]: "failed"}
    assert repos.actions.rows[UUID(ids[0])].result == {"error": "connector_exception", "error_type": "TimeoutError"}


async def test_rules_evidence_contains_only_the_targets_it_concerns(make_settings: Callable[..., Settings]) -> None:
    """LLM-W6-01 (c): port/temp-path observations authorise containment of *their* targets only."""
    auto_all = {"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}
    repos = FakeRepos(tenants=FakeTenants(auto_all))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    corroborated = frozenset({("ip", "185.220.101.44"), ("host", "WS-042.corp.example")})
    await service.plan("t1", "a1", plan_ctx(evidence="rules", corroborated_targets=corroborated, hosts=["ws-042"]))
    rows = rows_by_key(repos)
    assert rows[("block_ip", "185.220.101.44")].status == "approved"
    assert rows[("isolate_host", "ws-042")].status == "approved"  # short and FQDN forms compare equal
    other = rows[("quarantine_file", "44d88612fea8a8f36de82e1278abb02f")]
    assert other.status == "awaiting_approval" and other.params["approval_reason"] == "target_not_corroborated"
    assert other.params["scope"] == {"hosts": ["ws-042"]}
    assert rows[("create_ticket", "alert:a1")].status == "approved"  # non-containment is unaffected


async def test_critical_and_tenant_protected_processes_and_hashes_are_blocked(
    make_settings: Callable[..., Settings],
) -> None:
    tenant = {
        "autonomy": {"low": "auto", "medium": "auto", "high": "auto"},
        "protected_assets": {"processes": ["corp-agent*"], "hashes": ["44D88612FEA8A8F36DE82E1278ABB02F"]},
    }
    repos = FakeRepos(tenants=FakeTenants(tenant))
    service = ResponseService(repos, make_settings(), None)  # type: ignore[arg-type]
    entities = {**ENTITIES, "process": ["C:\\Windows\\System32\\LSASS.EXE", "ｅｘｐｌｏｒｅｒ.exe", "corp-agent.exe", "evil.exe"]}
    await service.plan("t1", "a1", plan_ctx(entities=entities, recommended_actions=["kill the process"]))
    rows = rows_by_key(repos)
    for target in ("C:\\Windows\\System32\\LSASS.EXE", "ｅｘｐｌｏｒｅｒ.exe", "corp-agent.exe"):
        assert rows[("terminate_process", target)].blocked_reason == "protected_asset", target
    assert rows[("quarantine_file", "44d88612fea8a8f36de82e1278abb02f")].blocked_reason == "protected_asset"


def test_parent_process_fields_are_never_targets() -> None:
    from lg_sotf.services.response import plan_entities

    alert = {
        "entities": {
            "processes": ["lsass.exe", "explorer.exe", "cmd.exe"],
            "hashes": ["a" * 64, "b" * 64],
        },
        "raw": {
            "process_name": "lsass.exe",
            "parent_process_name": "C:\\Windows\\explorer.exe",
            "ParentImage": "cmd.exe",
            "process_hash": "a" * 64,
            "parent_process_hash": "B" * 64,
        },
    }
    entities = plan_entities(alert)
    assert entities["process"] == ["lsass.exe"]
    assert entities["hash"] == ["a" * 64]
    # A value that is both the subject and its parent (cmd spawning cmd) stays a target.
    alert["raw"]["process_name"] = "cmd.exe"
    assert "cmd.exe" in plan_entities(alert)["process"]
