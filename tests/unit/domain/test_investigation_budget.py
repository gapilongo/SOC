"""An investigation's budgets (AI-E3.3): the install's defaults, the tenant's override within the install's bounds."""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest

from lg_sotf.domain.investigation_budget import (
    BUDGET_KINDS,
    Budget,
    BudgetLimits,
    tenant_limits,
    validate_investigation_settings,
)
from lg_sotf.settings import InvestigationBudget, InvestigationSettings

pytestmark = pytest.mark.unit

DEFAULT = BudgetLimits(steps=8, wall_s=60.0, tokens=20_000, usd=0.25)
MAXIMUM = BudgetLimits(steps=16, wall_s=120.0, tokens=100_000, usd=1.0)


def limits(budget: Optional[Dict[str, Any]], **kwargs: Any) -> BudgetLimits:
    return tenant_limits(DEFAULT, MAXIMUM, None if budget is None else {"investigation": {"budget": budget}}, **kwargs)


def test_the_defaults_are_the_adrs() -> None:
    """ADR 0014 section 3.2: at most 8 queries an investigation; section 2.3: under $0.25 on a frontier model."""
    install = InvestigationSettings()
    assert (install.budget.steps, install.budget.wall_s, install.budget.tokens, install.budget.usd) == (8, 60.0, 20_000, 0.25)
    assert install.evidence_backend == "indexer" and install.breaker_failures == 2
    assert set(InvestigationBudget.model_fields) == set(BUDGET_KINDS)
    assert limits(None) == DEFAULT == limits({})


def test_a_tenant_lowers_freely_and_raises_only_to_the_installs_maximum() -> None:
    assert limits({"steps": 2, "usd": 0}) == BudgetLimits(2, 60.0, 20_000, 0.0)
    assert limits({"steps": 12, "wall_s": 90, "tokens": 50_000, "usd": 0.5}) == BudgetLimits(12, 90.0, 50_000, 0.5)
    assert limits({"steps": 10_000, "wall_s": 1e9, "tokens": 10**12, "usd": 1e6}) == MAXIMUM
    # The wall clock is also never more than the share of the analysis node's time it is given.
    assert limits({"wall_s": 90}, wall_cap_s=30.0).wall_s == 30.0 and limits(None, wall_cap_s=5.0).wall_s == 5.0


@pytest.mark.parametrize("bad", [{"steps": -1}, {"steps": "9"}, {"steps": True}, {"usd": float("nan")}, {"steps": None}, {"steps": [9]}])
def test_an_unreadable_override_is_ignored(bad: Dict[str, Any]) -> None:
    assert limits(bad) == DEFAULT
    for doc in ({"investigation": bad}, {"investigation": {"budget": "all of it"}}, {"investigation": None}, [], "x"):
        assert tenant_limits(DEFAULT, MAXIMUM, doc) == DEFAULT  # type: ignore[arg-type]


def test_the_install_refuses_a_default_above_its_own_maximum_and_a_store_without_files() -> None:
    with pytest.raises(ValueError, match="must not exceed investigation.tenant_max"):
        InvestigationSettings(budget={"steps": 20})
    with pytest.raises(ValueError, match="needs investigation.event_store_files"):
        InvestigationSettings(evidence_backend="event_store")
    with pytest.raises(ValueError):
        InvestigationSettings(evidence_backend="whatever is there")
    assert InvestigationSettings(evidence_backend="event_store", event_store_files=["a.jsonl"]).event_store_files == ["a.jsonl"]


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("spend", "reason"),
    [({"steps": 8}, "budget_steps"), ({"tokens": 20_001}, "budget_tokens"), ({"usd": 0.26}, "budget_usd"), ({}, None),
     ({"steps": 7, "tokens": 20_000, "usd": 0.25}, None)],
)
def test_each_budget_stops_the_next_call(spend: Dict[str, Any], reason: Optional[str]) -> None:
    budget = Budget(DEFAULT, Clock())
    budget.charge(**spend)
    assert budget.spent() == reason


def test_the_wall_clock_and_the_next_calls_price_count() -> None:
    clock = Clock()
    budget = Budget(DEFAULT, clock)
    assert budget.spent() is None and budget.remaining_s == 60.0
    clock.now += 59.0
    assert budget.spent() is None and budget.remaining_s == pytest.approx(1.0)
    clock.now += 1.0
    assert budget.spent() == "budget_wall" and budget.remaining_s == 0.0
    priced = Budget(DEFAULT, Clock())
    priced.charge(usd=0.2)
    assert priced.spent(next_usd=0.05) is None and priced.spent(next_usd=0.06) == "budget_usd"
    assert Budget(BudgetLimits(8, 60.0, 0, 0.0), Clock()).spent() is None  # nothing spent: zero budgets stop nothing free
    assert priced.used() == {
        "steps": {"used": 0, "limit": 8}, "wall_s": {"used": 0.0, "limit": 60.0},
        "tokens": {"used": 0, "limit": 20_000}, "usd": {"used": 0.2, "limit": 0.25},
    }


def test_the_tenant_setting_is_strict() -> None:
    assert validate_investigation_settings({"budget": {"steps": 4, "usd": 0.1}}) == {"budget": {"steps": 4, "usd": 0.1}}
    assert validate_investigation_settings({}) == {"budget": {}}
    for bad in ({"budget": {"steps": 0}}, {"budget": {"steps": 33}}, {"budget": {"queries": 3}}, {"budget": {"usd": -1}},
                {"budget": {"steps": "4"}}, {"enabled": True}, {"budget": {"wall_s": 301}}, {"budget": {"tokens": 1.5}}):
        with pytest.raises(ValueError, match="investigation"):
            validate_investigation_settings(bad)
    with pytest.raises(ValueError, match="must be an object"):
        validate_investigation_settings(["budget"])
