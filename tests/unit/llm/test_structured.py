"""Structured output: happy path, refusals, invalid output, usage and budget."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Literal, Optional

import fakeredis
import pytest
from anthropic.types.beta import BetaMessage
from langchain_core.exceptions import OutputParserException
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel, Field

from lg_sotf.llm.budget import USE_DEFAULT, TokenBudget
from lg_sotf.llm.client import SERVER_FALLBACK_BETA, get_chat_model
from lg_sotf.llm.errors import LLMBudgetExceeded, LLMOutputError, LLMRefusal
from lg_sotf.llm.fake import FakeChatModel
from lg_sotf.llm.prompting import build_messages
from lg_sotf.llm.structured import ainvoke_structured, estimate_input_tokens, structured_method
from lg_sotf.llm.usage import get_usage_recorder
from lg_sotf.settings import Settings


class Verdict(BaseModel):
    disposition: Literal["malicious", "benign", "inconclusive"]
    confidence: int = Field(ge=0, le=100)
    reasoning: str


class StubModel(BaseChatModel):
    """Returns a canned ``with_structured_output(include_raw=True)`` result."""

    result: Dict[str, Any] = {}
    error: Optional[BaseException] = None
    calls: int = 0
    model: str = "claude-opus-5-5"

    @property
    def _llm_type(self) -> str:
        return "stub"

    def _generate(self, messages: List[BaseMessage], stop: Optional[List[str]] = None, run_manager: Any = None, **kwargs: Any) -> ChatResult:
        raise AssertionError("not used")

    def with_structured_output(self, schema: Any, *, include_raw: bool = False, **kwargs: Any) -> Runnable:  # type: ignore[override]
        async def run(_: Any) -> Dict[str, Any]:
            self.calls += 1
            if self.error is not None:
                raise self.error
            return self.result

        return RunnableLambda(lambda _: None, afunc=run)


def _raw(content: Any, *, stop_reason: str = "end_turn", **meta: Any) -> AIMessage:
    return AIMessage(
        content=content,
        usage_metadata={"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
        response_metadata={"model_name": "claude-opus-5-5", "stop_reason": stop_reason, **meta},
    )


def _msgs(settings: Settings, title: str = "Mimikatz and C2 beacon observed") -> List[BaseMessage]:
    return build_messages("You are a SOC analyst.", "Return a verdict.", {"title": title}, settings=settings)


def _rows() -> Dict[str, Any]:
    return {r["agent"]: r for r in get_usage_recorder().pending_rows()}


async def test_happy_path_with_fake_model(make_settings: Callable[..., Settings]) -> None:
    s = make_settings()
    model = get_chat_model("fast", s)
    verdict = await ainvoke_structured(model, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s)
    assert isinstance(verdict, Verdict)
    assert verdict.disposition == "malicious"
    row = _rows()["triage"]
    assert row["calls"] == 1 and row["tenant_id"] == "t1" and row["model"] == "fake-fast"
    assert row["input_tokens"] > 0 and row["output_tokens"] > 0
    assert row["cost_usd"] == 0


async def test_refusal(make_settings: Callable[..., Settings]) -> None:
    stub = StubModel(
        result={
            "raw": _raw([], stop_reason="refusal", stop_details={"type": "refusal", "category": "cyber", "explanation": "x"}),
            "parsed": None,
            "parsing_error": OutputParserException("Failed to parse"),
        }
    )
    with pytest.raises(LLMRefusal) as exc:
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="analysis", tier="deep", tenant_id="t1", settings=make_settings())
    assert exc.value.category == "cyber"
    assert exc.value.model == "claude-opus-5-5"
    row = _rows()["analysis"]
    assert row["refusals"] == 1 and row["errors"] == 0 and row["calls"] == 1


async def test_openai_style_refusal(make_settings: Callable[..., Settings]) -> None:
    raw = AIMessage(content="", additional_kwargs={"refusal": "I can't help with that."}, response_metadata={"finish_reason": "stop"})
    stub = StubModel(result={"raw": raw, "parsed": None, "parsing_error": None}, model="gpt-4.1")
    with pytest.raises(LLMRefusal):
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", settings=make_settings())


async def test_safety_finish_reason_is_a_refusal(make_settings: Callable[..., Settings]) -> None:
    raw = AIMessage(content="", response_metadata={"finish_reason": "SAFETY"})
    stub = StubModel(result={"raw": raw, "parsed": None, "parsing_error": None}, model="gemini-2.5-flash")
    with pytest.raises(LLMRefusal) as exc:
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", settings=make_settings())
    assert exc.value.category == "safety"


async def test_unparseable_output(make_settings: Callable[..., Settings]) -> None:
    secret_output = "not json at all: attacker text"
    stub = StubModel(result={"raw": _raw(secret_output), "parsed": None, "parsing_error": OutputParserException(secret_output)})
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", tenant_id="t1", settings=make_settings())
    assert secret_output not in str(exc.value)
    assert exc.value.__cause__ is None
    assert _rows()["triage"]["errors"] == 1


async def test_truncated_output(make_settings: Callable[..., Settings]) -> None:
    stub = StubModel(result={"raw": _raw('{"disposition": "mal', stop_reason="max_tokens"), "parsed": None, "parsing_error": OutputParserException("x")})
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", settings=make_settings())
    assert exc.value.stop_reason == "max_tokens"


async def test_out_of_range_values_are_not_clamped(make_settings: Callable[..., Settings]) -> None:
    stub = StubModel(result={"raw": _raw("{}"), "parsed": {"disposition": "benign", "confidence": 150, "reasoning": "SECRET-REASON"}, "parsing_error": None})
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", settings=make_settings())
    assert exc.value.validation_errors == ["confidence: less_than_equal"]
    assert "150" not in str(exc.value)


async def test_dict_output_is_validated(make_settings: Callable[..., Settings]) -> None:
    stub = StubModel(result={"raw": _raw("{}"), "parsed": {"disposition": "benign", "confidence": 90, "reasoning": "ok"}, "parsing_error": None})
    verdict = await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", settings=make_settings())
    assert verdict == Verdict(disposition="benign", confidence=90, reasoning="ok")


async def test_transport_errors_propagate_unchanged(make_settings: Callable[..., Settings]) -> None:
    stub = StubModel(error=TimeoutError("upstream timeout"))
    with pytest.raises(TimeoutError):
        await ainvoke_structured(stub, Verdict, _msgs(make_settings()), agent="triage", tier="fast", tenant_id="t1", settings=make_settings())
    row = _rows()["triage"]
    assert row["errors"] == 1 and row["input_tokens"] == 0


async def test_budget_exceeded_skips_the_call(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"daily_token_budget_per_tenant": 10})
    budget = TokenBudget(fakeredis.FakeAsyncRedis(), s)
    stub = StubModel(result={"raw": _raw("{}"), "parsed": Verdict(disposition="benign", confidence=1, reasoning="r"), "parsing_error": None})
    with pytest.raises(LLMBudgetExceeded):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget)
    assert stub.calls == 0
    assert "triage" not in _rows()


async def test_budget_is_settled_with_actual_usage(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"daily_token_budget_per_tenant": 1_000_000})
    budget = TokenBudget(fakeredis.FakeAsyncRedis(), s)
    stub = StubModel(result={"raw": _raw("{}"), "parsed": Verdict(disposition="benign", confidence=1, reasoning="r"), "parsing_error": None})
    await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget)
    assert await budget.used("t1") == 150

    stub.error = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget)
    assert await budget.used("t1") == 150

    with pytest.raises(LLMBudgetExceeded):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget, budget_limit=200)


async def test_budget_limit_none_means_unlimited(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(llm={"daily_token_budget_per_tenant": 10})
    budget = TokenBudget(fakeredis.FakeAsyncRedis(), s)
    stub = StubModel(result={"raw": _raw("{}"), "parsed": Verdict(disposition="benign", confidence=1, reasoning="r"), "parsing_error": None})
    await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget, budget_limit=None)
    assert stub.calls == 1
    assert await budget.used("t1") == 150

    with pytest.raises(LLMBudgetExceeded):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget)
    with pytest.raises(LLMBudgetExceeded):
        await ainvoke_structured(
            stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget, budget_limit=USE_DEFAULT
        )
    assert stub.calls == 1


def test_structured_method_selection(make_settings: Callable[..., Settings]) -> None:
    assert structured_method(FakeChatModel()) == "json_schema"
    for model, expected in [
        ("claude-haiku-4-5", "json_schema"),
        ("claude-opus-5-5", "json_schema"),
        ("claude-sonnet-4-6", "json_schema"),
        ("claude-opus-4-6", "json_schema"),
        ("claude-opus-4-7", "json_schema"),
        ("claude-sonnet-6", "json_schema"),
        ("claude-sonnet-4-5", "function_calling"),
        ("claude-3-5-haiku-20241022", "function_calling"),
    ]:
        s = make_settings(llm={"provider": "anthropic", "api_key": "k", "fast": {"model": model}})
        assert structured_method(get_chat_model("fast", s)) == expected
    openai = get_chat_model("fast", make_settings(llm={"provider": "openai", "api_key": "k", "fast": {"model": "gpt-4.1"}}))
    assert structured_method(openai) == "function_calling"


def test_estimate_input_tokens(make_settings: Callable[..., Settings]) -> None:
    msgs = build_messages("s" * 300, "t", {"x": "y" * 300}, settings=make_settings(llm={"provider": "anthropic"}))
    assert estimate_input_tokens(msgs) >= 200


# --------------------------------------------------------------------------
# Real ChatAnthropic (langchain-anthropic 1.7.4) against recorded API responses.
# --------------------------------------------------------------------------


class _RawResponse:
    def __init__(self, message: BetaMessage):
        self._message = message

    def parse(self) -> BetaMessage:
        return self._message


def _beta_message(content: List[Dict[str, Any]], stop_reason: str, *, model: str = "claude-opus-5-5", **extra: Any) -> BetaMessage:
    usage = extra.pop(
        "usage",
        {
            "input_tokens": 900,
            "output_tokens": 60,
            "cache_read_input_tokens": 2000,
            "cache_creation_input_tokens": 0,
            "cache_creation": {"ephemeral_5m_input_tokens": 300, "ephemeral_1h_input_tokens": 0},
        },
    )
    return BetaMessage.model_validate(
        {"id": "msg_test", "type": "message", "role": "assistant", "model": model, "content": content,
         "stop_reason": stop_reason, "stop_sequence": None, "usage": usage, **extra}
    )


@pytest.fixture
def anthropic_deep(make_settings: Callable[..., Settings]) -> tuple[Any, Settings, List[Dict[str, Any]]]:
    s = make_settings(llm={"provider": "anthropic", "api_key": "sk-ant-test", "prompt_caching": True,
                           "deep": {"model": "claude-opus-5-5", "max_tokens": 4000}})
    model = get_chat_model("deep", s)
    payloads: List[Dict[str, Any]] = []
    return model, s, payloads


def _respond(model: Any, payloads: List[Dict[str, Any]], message: BetaMessage) -> None:
    async def fake_acreate(payload: Dict[str, Any]) -> _RawResponse:
        payloads.append(payload)
        return _RawResponse(message)

    object.__setattr__(model, "_acreate", fake_acreate)


async def test_anthropic_request_and_usage(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    body = json.dumps({"disposition": "malicious", "confidence": 88, "reasoning": "credential theft"})
    _respond(model, payloads, _beta_message([{"type": "thinking", "thinking": "", "signature": "sig"}, {"type": "text", "text": body}], "end_turn"))

    verdict = await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", tenant_id="t1", settings=s)
    assert verdict.disposition == "malicious" and verdict.confidence == 88

    payload = payloads[0]
    assert payload["output_config"]["format"]["type"] == "json_schema"
    assert payload["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert payload["fallbacks"] == "default" and payload["betas"] == [SERVER_FALLBACK_BETA]
    assert "temperature" not in payload
    assert "<alert_data>" in payload["messages"][0]["content"]

    row = _rows()["analysis"]
    assert (row["input_tokens"], row["cache_read_tokens"], row["cache_write_tokens"], row["output_tokens"]) == (900, 2000, 300, 60)
    expected = (900 * 4 + 2000 * 0.20 + 300 * 5 + 60 * 20) / 1_000_000
    assert float(row["cost_usd"]) == pytest.approx(expected)


async def test_anthropic_refusal(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    _respond(model, payloads, _beta_message([], "refusal", stop_details={"type": "refusal", "category": "cyber", "explanation": "declined"}))
    with pytest.raises(LLMRefusal) as exc:
        await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", tenant_id="t1", settings=s)
    assert exc.value.category == "cyber"
    assert _rows()["analysis"]["refusals"] == 1


async def test_anthropic_invalid_json(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    body = json.dumps({"disposition": "benign", "confidence": 150, "reasoning": "SECRET-REASON"})
    _respond(model, payloads, _beta_message([{"type": "text", "text": body}], "end_turn"))
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", settings=s)
    # LangChain wraps the pydantic error in OutputParserException; the locations must still surface.
    assert exc.value.validation_errors == ["confidence: less_than_equal"]
    assert "SECRET-REASON" not in str(exc.value) and "150" not in str(exc.value)


async def test_anthropic_unparseable_json_has_no_validation_errors(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    _respond(model, payloads, _beta_message([{"type": "text", "text": "not json"}], "end_turn"))
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", settings=s)
    assert exc.value.validation_errors == []


def test_validation_error_is_found_through_the_exception_chain() -> None:
    from pydantic import ValidationError

    from lg_sotf.llm.structured import _find_validation_error

    try:
        Verdict.model_validate({"disposition": "x", "confidence": 1, "reasoning": "r"})
    except ValidationError as exc:
        validation = exc
    wrapped = OutputParserException("failed")
    wrapped.__cause__ = validation
    outer = RuntimeError("outer")
    outer.__context__ = wrapped
    assert _find_validation_error(validation) is validation
    assert _find_validation_error(wrapped) is validation
    assert _find_validation_error(outer) is validation
    assert _find_validation_error(OutputParserException("no cause")) is None
    assert _find_validation_error(None) is None
    looped = OutputParserException("loop")
    looped.__context__ = looped
    assert _find_validation_error(looped) is None


async def test_anthropic_max_tokens(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    _respond(model, payloads, _beta_message([{"type": "text", "text": '{"disposition": "ben'}], "max_tokens"))
    with pytest.raises(LLMOutputError) as exc:
        await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", settings=s)
    assert exc.value.stop_reason == "max_tokens"


async def test_anthropic_server_fallback_is_metered_per_model(anthropic_deep: Any) -> None:
    model, s, payloads = anthropic_deep
    body = json.dumps({"disposition": "inconclusive", "confidence": 50, "reasoning": "r"})
    message = _beta_message(
        [
            {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"}, "trigger": {"type": "refusal", "category": "cyber"}},
            {"type": "text", "text": body},
        ],
        "end_turn",
        model="claude-opus-4-8",
        usage={
            "input_tokens": 1000,
            "output_tokens": 40,
            "iterations": [
                {"type": "message", "model": "claude-opus-5-5", "input_tokens": 1000, "output_tokens": 0,
                 "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                {"type": "fallback_message", "model": "claude-opus-4-8", "input_tokens": 1000, "output_tokens": 40,
                 "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
            ],
        },
    )
    _respond(model, payloads, message)
    verdict = await ainvoke_structured(model, Verdict, _msgs(s), agent="analysis", tier="deep", tenant_id="t1", settings=s)
    assert verdict.disposition == "inconclusive"
    rows = {r["model"]: r for r in get_usage_recorder().pending_rows()}
    assert rows["claude-opus-5-5"]["refusals"] == 1
    assert rows["claude-opus-4-8"]["output_tokens"] == 40 and rows["claude-opus-4-8"]["refusals"] == 0


async def test_cancellation_releases_reservation(make_settings: Callable[..., Settings]) -> None:
    import asyncio

    s = make_settings(llm={"daily_token_budget_per_tenant": 1_000_000})
    budget = TokenBudget(fakeredis.FakeAsyncRedis(), s)
    stub = StubModel(error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", tenant_id="t1", settings=s, budget=budget)
    assert await budget.used("t1") == 0
    assert "triage" not in _rows()


async def test_non_mapping_result_is_invalid_output(make_settings: Callable[..., Settings]) -> None:
    class Weird(StubModel):
        def with_structured_output(self, schema: Any, *, include_raw: bool = False, **kwargs: Any) -> Runnable:  # type: ignore[override]
            async def run(_: Any) -> str:
                return "oops"

            return RunnableLambda(lambda _: None, afunc=run)

    with pytest.raises(LLMOutputError):
        await ainvoke_structured(Weird(), Verdict, _msgs(make_settings()), agent="triage", tier="fast", tenant_id="t1", settings=make_settings())
    assert _rows()["triage"]["errors"] == 1


# ------------------------------------------------------------------ per-alert tally


async def test_tally_accumulates_calls_tokens_and_outcomes(make_settings: Callable[..., Settings]) -> None:
    from lg_sotf.llm.fake import Refuse, ScriptedChatModel
    from lg_sotf.llm.usage import UsageTally

    settings = make_settings()
    tally = UsageTally()
    model = ScriptedChatModel(script={"Verdict": [{"disposition": "benign", "confidence": 5, "reasoning": "r"}, Refuse("cyber")]})
    messages = build_messages("s", "t", {"title": "mimikatz"}, settings=settings)
    await ainvoke_structured(model, Verdict, messages, agent="triage", tier="fast", tally=tally, settings=settings)
    with pytest.raises(LLMRefusal) as info:
        await ainvoke_structured(model, Verdict, messages, agent="analysis", tier="deep", tally=tally, settings=settings)
    assert info.value.category == "cyber"
    assert tally.calls == 2
    assert tally.by_agent["triage"].input_tokens > 0 and tally.by_agent["triage"].refusals == 0
    assert tally.by_agent["analysis"].refusals == 1


async def test_tally_counts_transport_errors_and_budget_rejections(make_settings: Callable[..., Settings]) -> None:
    from lg_sotf.llm.usage import UsageTally

    settings = make_settings()
    tally = UsageTally()
    stub = StubModel(error=RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        await ainvoke_structured(stub, Verdict, build_messages("s", "t", {}, settings=settings), agent="triage",
                                 tier="fast", tally=tally, settings=settings)
    budget = TokenBudget(fakeredis.FakeAsyncRedis(), settings, key_prefix="tally")
    with pytest.raises(LLMBudgetExceeded):
        await ainvoke_structured(FakeChatModel(), Verdict, build_messages("s", "t", {}, settings=settings),
                                 agent="triage", tier="fast", tally=tally, settings=settings, budget=budget,
                                 tenant_id="t1", budget_limit=1)
    assert tally.by_agent["triage"].errors == 1 and tally.by_agent["triage"].calls == 1
    assert tally.by_agent["triage"].budget_exceeded == 1


class _StatusError(Exception):
    """A provider error carrying an HTTP status, like google-genai's ServerError (``code``)."""

    def __init__(self, code: int) -> None:
        super().__init__(f"{code} provider error")
        self.code = code


class FlakyStub(StubModel):
    """Fails with ``error`` for the first ``failures`` calls, then returns ``result``."""

    failures: int = 0

    def with_structured_output(self, schema: Any, *, include_raw: bool = False, **kwargs: Any) -> Runnable:  # type: ignore[override]
        async def run(_: Any) -> Dict[str, Any]:
            self.calls += 1
            if self.calls <= self.failures and self.error is not None:
                raise self.error
            return self.result

        return RunnableLambda(lambda _: None, afunc=run)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> List[float]:
    waits: List[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr("lg_sotf.llm.structured.asyncio.sleep", fake_sleep)
    return waits


def _ok_result() -> Dict[str, Any]:
    return {"raw": _raw("{}"), "parsed": Verdict(disposition="malicious", confidence=90, reasoning="r"), "parsing_error": None}


async def test_transient_provider_error_is_retried_within_the_call(
    make_settings: Callable[..., Settings], no_sleep: List[float]
) -> None:
    s = make_settings()
    stub = FlakyStub(result=_ok_result(), error=_StatusError(503), failures=2)
    verdict = await ainvoke_structured(stub, Verdict, _msgs(s), agent="analysis", tier="deep", tenant_id="t1", settings=s)
    assert verdict.disposition == "malicious"
    assert stub.calls == 3 and len(no_sleep) == 2 and no_sleep[0] < no_sleep[1]
    row = _rows()["analysis"]
    assert row["errors"] == 2  # each failed call is still metered


async def test_transient_errors_give_up_after_the_retries(
    make_settings: Callable[..., Settings], no_sleep: List[float]
) -> None:
    s = make_settings()
    stub = FlakyStub(result=_ok_result(), error=_StatusError(429), failures=10)
    with pytest.raises(_StatusError):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", settings=s)
    assert stub.calls == 3 and len(no_sleep) == 2


async def test_permanent_provider_error_is_not_retried(
    make_settings: Callable[..., Settings], no_sleep: List[float]
) -> None:
    s = make_settings()
    stub = FlakyStub(result=_ok_result(), error=_StatusError(400), failures=10)
    with pytest.raises(_StatusError):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", settings=s)
    assert stub.calls == 1 and no_sleep == []


async def test_timeouts_are_left_to_the_node_policy(make_settings: Callable[..., Settings], no_sleep: List[float]) -> None:
    s = make_settings()
    stub = FlakyStub(result=_ok_result(), error=TimeoutError("upstream timeout"), failures=10)
    with pytest.raises(TimeoutError):
        await ainvoke_structured(stub, Verdict, _msgs(s), agent="triage", tier="fast", settings=s)
    assert stub.calls == 1 and no_sleep == []


async def test_a_wrapped_gemini_503_is_retried(make_settings: Callable[..., Settings], no_sleep: List[float]) -> None:
    """langchain-google-genai raises its own error ``from`` google-genai's ServerError(code=503)."""
    s = make_settings()

    class WrappedError(Exception):
        pass

    try:
        try:
            raise _StatusError(503)
        except _StatusError as inner:
            raise WrappedError("Error calling model (UNAVAILABLE)") from inner
    except WrappedError as wrapped:
        error = wrapped
    stub = FlakyStub(result=_ok_result(), error=error, failures=1)
    verdict = await ainvoke_structured(stub, Verdict, _msgs(s), agent="analysis", tier="deep", settings=s)
    assert verdict.disposition == "malicious" and stub.calls == 2 and len(no_sleep) == 1
