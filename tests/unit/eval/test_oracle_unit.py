"""The analyst oracle's decision loop with stand-ins (the real path runs in tests/integration/eval/test_oracle.py)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from lg_sotf.core.workflow import RunOutcome
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.oracle import MAX_ORACLE_STEPS, AnalystOracle, oracle_info
from lg_sotf.eval.results import ItemResult
from lg_sotf.services.review import ResumeRequest

pytestmark = pytest.mark.unit


def _item(disposition: str) -> Any:
    row = {"id": "i-1", "source_type": "canonical", "alert": {"title": "t"}, "expected": {"disposition": disposition}}
    return parse_dataset(json.dumps(row)).items[0]


def _result() -> ItemResult:
    return ItemResult(item_id="i-1", split="standard", tags=[], source_type="canonical", expected="benign",
                      status="waiting_approval", alert_id="a-1")


class _Repos:
    def __init__(self) -> None:
        self.users = SimpleNamespace(get_by_email=self._none, create=self._create)
        self.alerts = SimpleNamespace(get=self._alert)
        self.created: List[str] = []

    async def _none(self, *args: Any) -> None:
        return None

    async def _create(self, tenant_id: str, email: str, role: str) -> Any:
        self.created.append(role)
        return SimpleNamespace(id="u-1")

    async def _alert(self, tenant_id: str, alert_id: str) -> Any:
        return SimpleNamespace(status="waiting_approval")


class _Review:
    def __init__(self) -> None:
        self.rejected: List[List[str]] = []

    async def reject_actions(self, tenant_id: str, ids: List[str], user: Any, role: str, **kw: Any) -> List[Any]:
        self.rejected.append(ids)
        return [ResumeRequest("a-1", {"type": "approval"})]


class _Engine:
    """Every resume comes back waiting for approval again: the oracle must stop after MAX_ORACLE_STEPS."""

    async def resume(self, tenant_id: str, alert_id: str, payload: Dict[str, Any]) -> RunOutcome:
        return RunOutcome("waiting_approval", "waiting_approval", {"type": "approval", "action_ids": ["x"]})


def _oracle() -> AnalystOracle:
    return AnalystOracle(_Repos(), _Engine(), _Review())  # type: ignore[arg-type]


def test_items_without_ground_truth_or_still_running_are_left_alone() -> None:
    oracle = _oracle()
    waiting = RunOutcome("waiting_human", "waiting_human", {"type": "analyst_decision", "escalation_id": "e"})
    result = _result()
    asyncio.run(oracle.settle("t", _item("inconclusive"), result, waiting))
    asyncio.run(oracle.settle("t", _item("benign"), result, RunOutcome("completed", "closed", None)))
    assert result.review is None and result.oracle_decisions == [] and result.final_status is None


def test_the_loop_is_bounded_and_records_what_it_did() -> None:
    oracle = _oracle()
    result = _result()
    waiting = RunOutcome("waiting_approval", "waiting_approval", {"type": "approval", "action_ids": ["x"]})
    asyncio.run(oracle.settle("t", _item("benign"), result, waiting))
    assert result.oracle_decisions == ["reject_actions"] * MAX_ORACLE_STEPS
    assert result.review == "oracle" and result.final_status == "waiting_approval"
    assert oracle.repos.created == ["admin"]  # type: ignore[attr-defined]
    stuck = _result()
    asyncio.run(oracle.settle("t", _item("benign"), stuck, RunOutcome("waiting_human", "waiting_human", {})))
    assert stuck.oracle_decisions == [] and stuck.final_status == "waiting_approval"
    assert oracle.repos.created == ["admin"]  # type: ignore[attr-defined]  # one account per tenant


def test_run_info_names_the_mode() -> None:
    assert oracle_info(None) == {}
    assert oracle_info(_oracle())["oracle"]["decisions"] == {"benign": "false_positive", "malicious": "true_positive"}


def test_an_oracle_failure_keeps_what_automation_did() -> None:
    from lg_sotf.eval.runner import ORACLE_FAILED, EvalRunner

    class Broken:
        async def settle(self, *args: Any) -> None:
            raise RuntimeError("resume failed")

    runner = EvalRunner(tenant_id="t", repos=None, ingestion=None, engine=None, oracle=Broken())  # type: ignore[arg-type]
    result = _result()
    asyncio.run(runner._settle(_item("benign"), result, RunOutcome("waiting_human", "waiting_human", None)))
    assert result.status == "waiting_approval" and result.final_status == ORACLE_FAILED and result.error is None
