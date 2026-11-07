"""The tenant settings document (roadmap T5): one key list, one token budget rule."""

from __future__ import annotations

from typing import Any, Optional

import pytest

from lg_sotf.models.tenant_settings import (
    COPIED_KEYS,
    EDITABLE_KEYS,
    LLM_BUDGET_SETTING,
    MAX_TOKEN_BUDGET,
    TenantSettingsDoc,
    as_token_budget,
    token_budget,
    token_budget_problem,
)
from lg_sotf.services import tenancy

pytestmark = pytest.mark.unit

SYSTEM_KEYS = {"erased_at"}


def test_the_document_declares_every_editable_key() -> None:
    assert set(TenantSettingsDoc.__annotations__) == EDITABLE_KEYS | SYSTEM_KEYS
    assert set(COPIED_KEYS) <= EDITABLE_KEYS and "phishing" not in COPIED_KEYS
    assert LLM_BUDGET_SETTING in EDITABLE_KEYS


def test_profiles_seed_only_editable_keys() -> None:
    for profile in tenancy.PROFILES:
        assert set(tenancy.profile_settings(profile)) <= EDITABLE_KEYS


@pytest.mark.parametrize(
    ("stored", "expected"),
    [(None, None), (0, 0), (250_000, 250_000), (-5, -5), (True, None), (False, None), ("1000", None), (2.5, None)],
)
def test_token_budget_reads_an_int_that_is_not_a_bool(stored: Any, expected: Optional[int]) -> None:
    assert as_token_budget(stored) == expected
    assert token_budget({LLM_BUDGET_SETTING: stored}) == expected


def test_token_budget_of_a_missing_or_malformed_document_is_the_default() -> None:
    assert token_budget({}) is None
    assert token_budget(None) is None
    assert token_budget(["not", "a", "mapping"]) is None  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [None, 0, 1, MAX_TOKEN_BUDGET])
def test_storable_token_budgets(value: Any) -> None:
    assert token_budget_problem(value) is None


@pytest.mark.parametrize("value", [-1, MAX_TOKEN_BUDGET + 1, True, False, "1000", 2.5, {}])
def test_unstorable_token_budgets(value: Any) -> None:
    assert token_budget_problem(value) == f"llm_daily_token_budget: must be an integer 0..{MAX_TOKEN_BUDGET} or null"
