"""Agents record the provider, model and prompt version they called in ``summary.llm_models``."""

from __future__ import annotations

from typing import Callable

from lg_sotf.agents.triage.base import PROMPT, TriageAgent
from lg_sotf.settings import Settings
from tests.unit.agents._support import AMBIGUOUS, ASSESSMENT, BENIGN, ctx, factory, fake_repos, scripted


async def test_llm_call_records_provider_model_and_tier(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()
    repos.alerts.rows[("t1", "a1")].summary = {"llm_models": {"analysis": {"provider": "openai", "model": "gpt-x"}}}
    model = scripted(TriageAssessment=[ASSESSMENT])

    await TriageAgent(settings=settings, model_factory=factory(model)).run(ctx(settings, repos=repos), AMBIGUOUS)

    assert repos.alerts.rows[("t1", "a1")].summary["llm_models"] == {
        "analysis": {"provider": "openai", "model": "gpt-x"},
        "triage": {
            "provider": "fake",
            "model": "fake-scripted",
            "tier": "fast",
            "prompt_name": "triage.assess",
            "prompt_hash": PROMPT.hash,
        },
    }


async def test_rules_only_run_records_no_model(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings()
    repos = fake_repos()

    await TriageAgent(settings=settings, model_factory=factory(scripted())).run(ctx(settings, repos=repos), BENIGN)

    assert "llm_models" not in repos.alerts.rows[("t1", "a1")].summary
