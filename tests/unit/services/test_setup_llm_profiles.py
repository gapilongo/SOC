"""First-run setup wizard: the language-model profiles on offer and where the configured model runs."""

from __future__ import annotations

from typing import Any, Callable, Optional, get_args

import pytest

from lg_sotf.api.routers.onboarding import ProfileId, Residency
from lg_sotf.onboarding.llm_profiles import (
    DEFAULT_PROFILE,
    PROFILE_IDS,
    PROFILES,
    configured_model,
)
from lg_sotf.onboarding.llm_profiles import (
    Residency as ProfileResidency,
)
from lg_sotf.onboarding.setup import setup_state
from lg_sotf.settings import Settings

pytestmark = pytest.mark.unit


def test_the_default_profile_is_eu_or_local_and_offers_lead_with_them() -> None:
    by_id = {p.id: p for p in PROFILES}
    assert by_id[DEFAULT_PROFILE].residency in ("eu", "local")
    assert PROFILES[0].id == DEFAULT_PROFILE
    residencies = [p.residency for p in PROFILES]
    assert residencies == sorted(residencies, key=lambda r: r not in ("eu", "local")), "EU and local offers come first"


def test_no_profile_is_hosted_in_china_or_names_such_a_provider() -> None:
    for profile in PROFILES:
        assert profile.residency != "cn"
        text = " ".join([profile.label, profile.description, *(f"{n}={v}" for n, v in profile.env())]).lower()
        assert "deepseek" not in text


def test_profile_ids_and_residencies_match_the_api_schema() -> None:
    assert set(get_args(ProfileId)) == PROFILE_IDS
    assert set(get_args(Residency)) == set(get_args(ProfileResidency))


def test_env_lines_select_the_profile_and_never_hold_a_key() -> None:
    mistral = dict(next(p for p in PROFILES if p.id == "mistral_eu").env())
    assert mistral["LG_SOTF_LLM__PROVIDER"] == "openai"
    assert mistral["LG_SOTF_LLM__BASE_URL"] == "https://api.mistral.ai/v1"
    assert mistral["LG_SOTF_LLM__API_KEY"].startswith("<")
    ollama = dict(next(p for p in PROFILES if p.id == "ollama_local").env())
    assert ollama["LG_SOTF_LLM__PROVIDER"] == "ollama" and "LG_SOTF_LLM__API_KEY" not in ollama


@pytest.mark.parametrize(
    ("llm", "residency", "profile"),
    [
        ({"provider": "fake", "allow_fake": True}, "offline", None),
        ({"provider": "openai", "base_url": "https://api.mistral.ai/v1"}, "eu", "mistral_eu"),
        ({"provider": "openai_compatible", "base_url": "https://api.mistral.ai/v1"}, "eu", None),
        ({"provider": "ollama"}, "local", "ollama_local"),
        ({"provider": "ollama", "base_url": "http://10.0.0.5:11434/v1"}, "local", "ollama_local"),
        ({"provider": "openai_compatible", "base_url": "http://vllm:8000/v1"}, "local", "self_hosted"),
        ({"provider": "openai_compatible", "base_url": "https://llm.example.com/v1"}, "unknown", None),
        ({"provider": "anthropic"}, "us", "anthropic"),
        ({"provider": "openai"}, "us", None),
        ({"provider": "gemini"}, "us", None),
        ({"provider": "openai", "base_url": "https://gateway.example.com/v1"}, "unknown", None),
        ({"provider": "openai", "base_url": "https://api.deepseek.com"}, "cn", None),
    ],
)
def test_the_configured_model_is_placed(
    make_settings: Callable[..., Settings], llm: dict[str, Any], residency: str, profile: Optional[str]
) -> None:
    model = configured_model(make_settings(llm=llm))
    assert (model.residency, model.profile, model.provider) == (residency, profile, llm["provider"])


def test_the_offline_model_reports_its_own_names(make_settings: Callable[..., Settings]) -> None:
    model = configured_model(make_settings())
    assert (model.fast_model, model.deep_model) == ("fake-fast", "fake-deep")
    real = configured_model(make_settings(llm={"provider": "ollama", "fast": {"model": "qwen3:8b"}}))
    assert real.fast_model == "qwen3:8b"


def test_setup_state_reads_the_onboarding_marks() -> None:
    class _Tenant:
        id = "acme"
        name = "Acme"
        onboarding = {"organisation": "Acme Group", "llm_profile": "mistral_eu", "setup_completed_at": "2026-11-07"}

    state = setup_state(_Tenant())  # type: ignore[arg-type]
    assert state.completed and (state.organisation, state.llm_profile) == ("Acme Group", "mistral_eu")
    _Tenant.onboarding = {}
    assert not setup_state(_Tenant()).completed  # type: ignore[arg-type]
