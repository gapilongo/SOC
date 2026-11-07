"""Roadmap T4: the engine and the backtest start a run from the same initial workflow state.

``eval/history.py`` used to hand-copy how ``WorkflowEngine`` builds it, and had
drifted (the gate, the keys of the later steps, a bool token budget). Both now
call :func:`lg_sotf.core.graph.initial_state`.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping

import pytest

from lg_sotf.core import graph
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Alert
from lg_sotf.eval import history

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
TENANT = "t-char"


def alert(**overrides: Any) -> Alert:
    base: Dict[str, Any] = dict(
        tenant_id=TENANT, id="a-1", source_id="src-1", source_alert_id="ext-1", fingerprint="fp-1",
        title="Possible C2 beacon", severity="medium", category="malware", status="queued", disposition=None,
        confidence=None, threat_score=None, priority=None, assigned_to=None, occurred_at=T0, ingested_at=T0,
        updated_at=T0, closed_at=None, summary={}, case_key=None,
        raw={"vendor": "edr", "process_name": "powershell.exe"},
        normalized={"entities": {"ips": ["203.0.113.9"], "hosts": ["ws-042"]}, "description": "beacon"},
    )
    base.update(overrides)
    return Alert(**base)


FIXTURES: List[Alert] = [
    alert(),
    # The normalized form carries its own raw and category; the row's category is unset.
    alert(id="a-2", category=None, normalized={"category": "phishing", "raw": {"from": "normalized"}, "email": {}}),
    # Over the size caps: cap_alert drops and truncates.
    alert(id="a-3", severity="critical", normalized={"description": "x" * 50_000, "entities": {"ips": ["198.51.100.1"]}}),
]


def engine_state(item: Alert, tenant_settings: Mapping[str, Any]) -> Dict[str, Any]:
    engine = WorkflowEngine.__new__(WorkflowEngine)

    async def get(tenant_id: str) -> Any:
        assert tenant_id == TENANT
        return SimpleNamespace(settings=dict(tenant_settings))

    engine.repos = SimpleNamespace(tenants=SimpleNamespace(get=get))  # type: ignore[assignment]
    return dict(asyncio.run(engine._initial_state(TENANT, item)))


def backtest_state(item: Alert, tenant_settings: Mapping[str, Any]) -> Dict[str, Any]:
    """What ``HistoryReplayer.replay`` starts from."""
    return dict(history.initial_state(TENANT, item, llm_budget_limit=tenant_settings.get("llm_daily_token_budget")))


def test_the_backtest_uses_the_engine_factory() -> None:
    assert history.initial_state is graph.initial_state


@pytest.mark.parametrize("item", FIXTURES, ids=lambda a: a.id)
@pytest.mark.parametrize("budget", [None, 0, 250_000, "250000", 2.5])
def test_backtest_initial_state_equals_the_engine(item: Alert, budget: Any) -> None:
    settings = {"llm_daily_token_budget": budget}
    engine = engine_state(item, settings)
    assert engine == backtest_state(item, settings)
    assert engine["gate"] == {} and engine["notes"] == [] and engine["alert"]["id"] == item.id
    assert engine["llm_budget_limit"] == (budget if isinstance(budget, int) else None)


@pytest.mark.parametrize("budget", [True, False])
def test_a_bool_token_budget_is_rejected_by_the_engine_and_the_backtest(budget: bool) -> None:
    """Behaviour change (backtest only): the backtest used to keep a bool budget."""
    settings = {"llm_daily_token_budget": budget}
    assert engine_state(FIXTURES[0], settings)["llm_budget_limit"] is None
    assert backtest_state(FIXTURES[0], settings)["llm_budget_limit"] is None
