"""Chat model factory and per-tier concurrency."""

from __future__ import annotations

import asyncio
from typing import Callable

import pytest

from lg_sotf.llm.client import (
    ANTHROPIC_API_URL,
    SERVER_FALLBACK_BETA,
    get_chat_model,
    llm_slot,
    model_capabilities,
    model_name_of,
    provider_of,
)
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.settings import Settings


def test_disabled(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(LLMUnavailable):
        get_chat_model("fast", make_settings(llm={"enabled": False}))


def test_unknown_tier(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValueError):
        get_chat_model("medium", make_settings())  # type: ignore[arg-type]


def test_missing_api_key(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(LLMUnavailable, match="api_key"):
        get_chat_model("fast", make_settings(llm={"provider": "anthropic", "api_key": None}))
    with pytest.raises(LLMUnavailable):
        get_chat_model("fast", make_settings(llm={"provider": "anthropic", "api_key": ""}))


def test_fake_provider(make_settings: Callable[..., Settings]) -> None:
    model = get_chat_model("deep", make_settings(llm={"deep": {"model": "ignored", "max_tokens": 777}}))
    assert isinstance(model, FakeChatModel)
    assert model.model_name == "fake-deep" and model.max_tokens == 777
    assert provider_of(model) == "fake"


def test_fake_refused_in_production(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(LLMUnavailable):
        get_chat_model("fast", make_settings(environment="production", llm={"allow_fake": False}))
    assert isinstance(get_chat_model("fast", make_settings(environment="production")), FakeChatModel)


def test_anthropic_opus_tier(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(
        llm={
            "provider": "anthropic",
            "api_key": "sk-ant-test",
            "deep": {"model": "claude-opus-5-5", "max_tokens": 16000, "timeout_s": 300, "max_retries": 4, "temperature": 0.2},
        }
    )
    model = get_chat_model("deep", s)
    assert provider_of(model) == "anthropic"
    assert model_name_of(model) == "claude-opus-5-5"
    assert model.max_tokens == 16000  # type: ignore[attr-defined]
    assert model.default_request_timeout == 300  # type: ignore[attr-defined]
    assert model.max_retries == 4  # type: ignore[attr-defined]
    assert model.temperature is None  # type: ignore[attr-defined]
    assert model.anthropic_api_url == ANTHROPIC_API_URL  # type: ignore[attr-defined]
    assert model.anthropic_api_key.get_secret_value() == "sk-ant-test"  # type: ignore[attr-defined]
    assert model.betas == [SERVER_FALLBACK_BETA]  # type: ignore[attr-defined]
    assert model.model_kwargs == {"fallbacks": "default"}  # type: ignore[attr-defined]


def test_anthropic_haiku_tier(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"provider": "anthropic", "api_key": "k", "fast": {"model": "claude-haiku-4-5", "temperature": 0.0}})
    model = get_chat_model("fast", s)
    assert model.temperature == 0.0  # type: ignore[attr-defined]
    assert not model.betas  # type: ignore[attr-defined]
    assert model.model_kwargs == {}  # type: ignore[attr-defined]


def test_custom_gateway_disables_server_fallback(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(
        llm={"provider": "anthropic", "api_key": "k", "base_url": "https://llm-gw.internal", "deep": {"model": "claude-opus-5-5"}}
    )
    model = get_chat_model("deep", s)
    assert model.anthropic_api_url == "https://llm-gw.internal"  # type: ignore[attr-defined]
    assert not model.betas  # type: ignore[attr-defined]


def test_request_payload_shape(make_settings: Callable[..., Settings]) -> None:
    from langchain_core.messages import HumanMessage

    s = make_settings(llm={"provider": "anthropic", "api_key": "k", "deep": {"model": "claude-opus-5-5", "max_tokens": 2048}})
    payload = get_chat_model("deep", s)._get_request_payload([HumanMessage("hi")])  # type: ignore[attr-defined]
    assert payload["model"] == "claude-opus-5-5"
    assert payload["max_tokens"] == 2048
    assert payload["fallbacks"] == "default"
    assert payload["betas"] == [SERVER_FALLBACK_BETA]
    assert "temperature" not in payload and "temperature" not in payload.get("extra_body", {})


def test_openai_and_gemini(make_settings: Callable[..., Settings]) -> None:
    openai = get_chat_model("fast", make_settings(llm={"provider": "openai", "api_key": "k", "fast": {"model": "gpt-4.1-mini"}}))
    assert provider_of(openai) == "openai" and model_name_of(openai) == "gpt-4.1-mini"
    assert openai.temperature == 0.0  # type: ignore[attr-defined]
    reasoning = get_chat_model("fast", make_settings(llm={"provider": "openai", "api_key": "k", "fast": {"model": "o4-mini"}}))
    assert reasoning.temperature is None  # type: ignore[attr-defined]
    gemini = get_chat_model("fast", make_settings(llm={"provider": "gemini", "api_key": "k", "fast": {"model": "gemini-2.5-flash"}}))
    assert provider_of(gemini) == "gemini"


def test_models_are_cached_and_rebuilt_on_change(make_settings: Callable[..., Settings]) -> None:
    s1 = make_settings(llm={"provider": "anthropic", "api_key": "k", "fast": {"model": "claude-haiku-4-5"}})
    a = get_chat_model("fast", s1)
    assert get_chat_model("fast", s1) is a
    assert get_chat_model("fast", make_settings(llm={"provider": "anthropic", "api_key": "k", "fast": {"model": "claude-haiku-4-5"}})) is a
    b = get_chat_model("fast", make_settings(llm={"provider": "anthropic", "api_key": "k", "fast": {"model": "claude-haiku-4-5", "max_tokens": 99}}))
    assert b is not a and b.max_tokens == 99  # type: ignore[attr-defined]
    c = get_chat_model("fast", make_settings(llm={"provider": "anthropic", "api_key": "other", "fast": {"model": "claude-haiku-4-5", "max_tokens": 99}}))
    assert c is not b


@pytest.mark.parametrize(
    ("provider", "model", "temperature", "json_schema", "fallback"),
    [
        ("anthropic", "claude-opus-5-5", False, True, True),
        ("anthropic", "claude-sonnet-5-5", False, True, True),
        ("anthropic", "claude-sonnet-5", False, True, False),
        ("anthropic", "claude-haiku-4-5", True, True, False),
        ("anthropic", "claude-haiku-4-5-20251001", True, True, False),
        ("anthropic", "claude-sonnet-4-6", True, True, False),
        ("anthropic", "claude-opus-4-6", True, True, False),
        ("anthropic", "claude-opus-4-7", False, True, False),
        ("anthropic", "claude-opus-4-8", False, True, False),
        ("anthropic", "claude-sonnet-4-5", True, False, False),
        ("anthropic", "claude-sonnet-4-5-20250929", True, False, False),
        ("anthropic", "claude-opus-4-5", True, True, False),
        ("anthropic", "claude-opus-4-1", True, True, False),
        ("anthropic", "claude-opus-4-0", True, False, False),
        ("anthropic", "claude-opus-4-20250514", True, False, False),
        ("anthropic", "claude-3-5-haiku-20241022", True, False, False),
        # A model released after this code: current API surface (no sampling params, structured outputs).
        ("anthropic", "claude-sonnet-6", False, True, False),
        ("anthropic", "claude-fable-5-1", False, True, True),
        ("openai", "gpt-4.1", True, False, False),
        ("fake", "fake-fast", True, True, False),
    ],
)
def test_capabilities(provider: str, model: str, temperature: bool, json_schema: bool, fallback: bool) -> None:
    caps = model_capabilities(provider, model)
    assert (caps.accepts_temperature, caps.json_schema, caps.server_fallback) == (temperature, json_schema, fallback)


async def test_llm_slot_bounds_concurrency(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"fast": {"model": "f", "max_concurrency": 2}})
    active = peak = 0

    async def call() -> None:
        nonlocal active, peak
        async with llm_slot("fast", s):
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1

    await asyncio.gather(*(call() for _ in range(8)))
    assert peak == 2


async def test_llm_slot_tiers_are_independent(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"fast": {"model": "f", "max_concurrency": 1}, "deep": {"model": "d", "max_concurrency": 1}})
    async with llm_slot("fast", s):
        await asyncio.wait_for(_enter("deep", s), timeout=1)


async def _enter(tier: str, s: Settings) -> None:
    async with llm_slot(tier, s):  # type: ignore[arg-type]
        pass


def test_llm_slot_works_across_event_loops(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"fast": {"model": "f", "max_concurrency": 1}})

    async def contended() -> None:
        await asyncio.gather(_enter("fast", s), _enter("fast", s))

    asyncio.run(contended())
    asyncio.run(contended())


async def test_llm_slot_rejects_bad_config(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(LLMUnavailable):
        await _enter("fast", make_settings(llm={"fast": {"model": "f", "max_concurrency": 0}}))
    with pytest.raises(ValueError):
        await _enter("huge", make_settings())
