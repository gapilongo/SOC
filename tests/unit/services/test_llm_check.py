"""The model connectivity check behind ``POST /tenant/llm/test``."""

from __future__ import annotations

import asyncio
from typing import Any, Callable

import httpx
import openai
import pytest
from langchain_core.language_models.chat_models import BaseChatModel

from lg_sotf.llm.errors import LLMOutputError, LLMRefusal, LLMUnavailable
from lg_sotf.llm.fake import FakeChatModel, Invalid, Refuse, ScriptedChatModel
from lg_sotf.llm.usage import get_usage_recorder
from lg_sotf.services.llm_check import AGENT, check_llm, describe_error
from lg_sotf.settings import Settings

LEAKY_BODY = "Incorrect API key provided: sk-proj-" + "a" * 8 + "*** at https://gw.internal.example/v1"


async def test_fake_model_passes_both_tiers(make_settings: Callable[..., Settings]) -> None:
    s = make_settings()
    report = await check_llm(s, "t1")
    assert report.ok and report.provider == "fake" and report.enabled
    assert [t.tier for t in report.tiers] == ["fast", "deep"]
    assert {t.model for t in report.tiers} == {"fake-fast", "fake-deep"}
    assert all(t.ok and t.latency_ms >= 0 and t.method == "json_schema" and t.error is None for t in report.tiers)
    rows = [r for r in get_usage_recorder(s).pending_rows() if r["agent"] == AGENT]
    assert {r["model"] for r in rows} == {"fake-fast", "fake-deep"} and all(r["tenant_id"] == "t1" for r in rows)


async def test_disabled_llm_reports_without_calling(make_settings: Callable[..., Settings]) -> None:
    def factory(tier: Any, settings: Settings) -> BaseChatModel:
        raise AssertionError("no model may be built")

    report = await check_llm(make_settings(llm={"enabled": False}), "t1", factory=factory)
    assert not report.ok and not report.enabled
    assert {t.error_code for t in report.tiers} == {"disabled"}


async def test_one_failing_tier_is_reported_per_tier(make_settings: Callable[..., Settings]) -> None:
    def factory(tier: Any, settings: Settings) -> BaseChatModel:
        if tier == "deep":
            return ScriptedChatModel(model_name="deep-x", script={"*": [Refuse("cyber")]})
        return FakeChatModel(model_name="fast-x")

    report = await check_llm(make_settings(), "t1", factory=factory)
    fast, deep = report.tiers
    assert fast.ok and not deep.ok and not report.ok
    assert (deep.model, deep.error_code, deep.error) == ("deep-x", "refusal", "the model declined the probe")


async def test_slow_model_times_out(make_settings: Callable[..., Settings]) -> None:
    class Slow(FakeChatModel):
        def with_structured_output(self, schema: Any, **kwargs: Any) -> Any:
            inner = super().with_structured_output(schema, **kwargs)

            async def slow(value: Any, config: Any = None, **kw: Any) -> Any:
                await asyncio.sleep(5)
                return await inner.ainvoke(value)

            from langchain_core.runnables import RunnableLambda

            return RunnableLambda(lambda _: None, afunc=slow)

    report = await check_llm(make_settings(), "t1", timeout_s=0.05, factory=lambda tier, s: Slow())
    assert {t.error_code for t in report.tiers} == {"timeout"}
    assert all(t.latency_ms < 2_000 for t in report.tiers)


async def test_misconfiguration_is_reported_not_raised(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"provider": "openai_compatible", "base_url": "http://llm.example.com/v1"})
    report = await check_llm(s, "t1")
    assert not report.ok
    assert {t.error_code for t in report.tiers} == {"unavailable"}
    assert all("https" in (t.error or "") and "llm.example.com" not in (t.error or "") for t in report.tiers)


def _status_error(status: int) -> openai.APIStatusError:
    request = httpx.Request("POST", "https://gw.internal.example/v1/chat/completions")
    response = httpx.Response(status, request=request, json={"error": {"message": LEAKY_BODY}})
    return openai.APIStatusError(LEAKY_BODY, response=response, body={"message": LEAKY_BODY})


@pytest.mark.parametrize(
    ("exc", "code", "fragment"),
    [
        (_status_error(401), "http_error", "HTTP 401"),
        (_status_error(404), "http_error", "pull the model"),
        (_status_error(503), "http_error", "server error"),
        (openai.APIConnectionError(message=LEAKY_BODY, request=httpx.Request("POST", "http://ollama:11434")), "connection", "could not connect"),
        (httpx.ConnectTimeout(LEAKY_BODY), "timeout", "did not answer"),
        (TimeoutError(), "timeout", "within 60 s"),
        (LLMUnavailable("llm.api_key is not configured"), "unavailable", "llm.api_key"),
        (LLMRefusal("x", category="cyber"), "refusal", "declined"),
        (LLMOutputError("x", validation_errors=["status: literal_error"]), "invalid_output", "status: literal_error"),
        (LLMOutputError("x", stop_reason="length"), "invalid_output", "raise max_tokens"),
        (RuntimeError(LEAKY_BODY), "error", "RuntimeError"),
    ],
)
def test_errors_are_sanitized(exc: BaseException, code: str, fragment: str) -> None:
    got_code, message = describe_error(exc, 60.0)
    assert got_code == code and fragment in message
    assert "sk-proj" not in message and "gw.internal" not in message and "ollama:11434" not in message


async def test_invalid_output_is_explained(make_settings: Callable[..., Settings]) -> None:
    report = await check_llm(
        make_settings(), "t1", factory=lambda tier, s: ScriptedChatModel(script={"*": [Invalid("hello there")]})
    )
    assert {t.error_code for t in report.tiers} == {"invalid_output"}
    assert all("hello there" not in (t.error or "") for t in report.tiers)
