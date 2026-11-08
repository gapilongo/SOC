"""INV-02: no response action runs without an approval or an autonomy rule, and the kill switch wins."""

from __future__ import annotations

from typing import Any, Callable, List
from uuid import UUID

import pytest

from lg_sotf.services.connectors import ConnectorResult
from lg_sotf.services.response import PlanContext, ResponseService
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeRepos, FakeTenants

pytestmark = pytest.mark.unit

CONTEXT = PlanContext(
    severity="high",
    evidence="analyst",
    title="Cobalt Strike beacon",
    entities={"ip": ["185.220.101.44"], "host": ["ws-042"], "user": ["jdoe"]},
)


class Recording:
    """A live connector that records every action it is asked to run."""

    name = "webhook"

    def __init__(self) -> None:
        self.calls: List[str] = []

    async def execute(self, action: Any) -> ConnectorResult:
        self.calls.append(str(action.id))
        return ConnectorResult("succeeded", {"ok": True})


def _service(make_settings: Callable[..., Settings], tenant: dict, connector: Recording) -> tuple:
    repos = FakeRepos(tenants=FakeTenants({"response": {"connector": "webhook"}, **tenant}))
    settings = make_settings(response={"dry_run": False})
    return repos, ResponseService(repos, settings, None, connectors={"webhook": connector})  # type: ignore[arg-type]


async def test_actions_awaiting_approval_are_never_executed(make_settings: Callable[..., Settings]) -> None:
    connector = Recording()
    repos, service = _service(make_settings, {"protected_assets": {"hosts": ["ws-042"]}}, connector)
    plan = await service.plan("t1", "a1", CONTEXT)
    assert plan.awaiting and plan.blocked and plan.auto == []

    executed = await service.execute("t1", "a1", plan.awaiting + plan.blocked)
    assert connector.calls == []
    assert {executed[i] for i in plan.awaiting} == {"awaiting_approval"}
    assert {repos.actions.rows[UUID(i)].status for i in plan.blocked} == {"blocked"}

    first = plan.awaiting[0]
    await service.apply_approval("t1", "a1", pending_ids=plan.awaiting, approved_ids=[first], rejected_ids=[],
                                 decided_by="u1")
    executed = await service.execute("t1", "a1", plan.awaiting)
    assert connector.calls == [first] and executed[first] == "succeeded"


async def test_a_dry_run_tenant_rehearses_even_auto_approved_actions(make_settings: Callable[..., Settings]) -> None:
    connector = Recording()
    autonomy = {"autonomy": {"low": "auto", "medium": "auto", "high": "auto"}}
    repos, service = _service(make_settings, {**autonomy, "response": {"connector": "webhook", "dry_run": True}},
                              connector)
    plan = await service.plan("t1", "a1", CONTEXT)
    assert plan.auto

    executed = await service.execute("t1", "a1", plan.auto)
    assert connector.calls == []
    assert set(executed.values()) == {"dry_run"}
