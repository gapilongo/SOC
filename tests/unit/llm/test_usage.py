"""Usage metering: cost math, aggregation, flushing and metrics."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from typing import List

import pytest
from langchain_core.messages import AIMessage

from lg_sotf.llm.pricing import DEFAULT_PRICES, ModelPrice, compute_cost, lookup_price, price_table
from lg_sotf.llm.usage import LLMUsageRow, UsageRecorder, UsageSample, extract_usage, get_usage_recorder
from lg_sotf.observability.metrics import REGISTRY

DAY = date(2026, 9, 1)


def _metric(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_cost_math_per_million_tokens() -> None:
    haiku = DEFAULT_PRICES["claude-haiku-4-5"]
    assert compute_cost(haiku, input_tokens=1_000_000, output_tokens=0) == Decimal("1")
    assert compute_cost(haiku, input_tokens=0, output_tokens=1_000_000) == Decimal("5")
    opus = DEFAULT_PRICES["claude-opus-5-5"]
    cost = compute_cost(
        opus,
        input_tokens=10_000,
        output_tokens=2_000,
        cache_read_tokens=100_000,
        cache_write_tokens=8_000,
        cache_write_1h_tokens=3_000,
    )
    expected = (
        Decimal("4") * 10_000 + Decimal("20") * 2_000 + Decimal("0.20") * 100_000 + Decimal("5") * 5_000 + Decimal("8") * 3_000
    ) / 1_000_000
    assert cost == expected
    assert cost == Decimal("0.149")


def test_price_lookup() -> None:
    assert lookup_price("claude-haiku-4-5-20251001", DEFAULT_PRICES) is DEFAULT_PRICES["claude-haiku-4-5"]
    assert lookup_price("claude-opus-5-5", DEFAULT_PRICES) is DEFAULT_PRICES["claude-opus-5-5"]
    assert lookup_price("claude-opus-5-9", DEFAULT_PRICES) is None
    assert lookup_price("gpt-4.1", DEFAULT_PRICES) is None
    zero = lookup_price("fake-fast", DEFAULT_PRICES)
    assert zero is not None and zero.input == 0


def test_price_overrides() -> None:
    settings = SimpleNamespace(llm=SimpleNamespace(prices={"gpt-4.1": {"input": 2, "output": 8}, "claude-haiku-4-5": ModelPrice.of("9", "9", "9", "9")}))
    table = price_table(settings)  # type: ignore[arg-type]
    assert table["gpt-4.1"] == ModelPrice.of("2", "8", "2.50", "0.2")
    assert table["claude-haiku-4-5"].input == Decimal("9")
    assert price_table(None) == DEFAULT_PRICES


def test_aggregation_and_counters() -> None:
    rec = UsageRecorder()
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id="t1", input_tokens=1000, output_tokens=100, day=DAY)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="refusal", tenant_id="t1", input_tokens=500, day=DAY)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="invalid_output", tenant_id="t1", output_tokens=10, day=DAY)
    rec.record(model="claude-haiku-4-5", agent="correlation", outcome="error", tenant_id="t1", day=DAY)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id="t2", input_tokens=1, day=DAY)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id=None, input_tokens=99)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="budget_exceeded", tenant_id="t1", day=DAY)

    rows = {(r["tenant_id"], r["agent"]): r for r in rec.pending_rows()}
    assert set(rows) == {("t1", "triage"), ("t1", "correlation"), ("t2", "triage")}
    t1 = rows[("t1", "triage")]
    assert t1["calls"] == 3
    assert t1["input_tokens"] == 1500 and t1["output_tokens"] == 110
    assert t1["refusals"] == 1 and t1["errors"] == 1
    assert t1["cost_usd"] == Decimal("0.002050")
    assert t1["day"] == DAY and t1["model"] == "claude-haiku-4-5"
    assert rows[("t1", "correlation")]["errors"] == 1


def test_metrics_are_updated() -> None:
    before_calls = _metric("lgsotf_llm_calls_total", model="claude-sonnet-5-5", agent="analysis", outcome="success")
    before_tokens = _metric("lgsotf_llm_tokens_total", model="claude-sonnet-5-5", kind="cache_read")
    before_cost = _metric("lgsotf_llm_cost_usd_total", model="claude-sonnet-5-5")
    UsageRecorder().record(
        model="claude-sonnet-5-5", agent="analysis", outcome="success", input_tokens=1_000_000, cache_read_tokens=10
    )
    assert _metric("lgsotf_llm_calls_total", model="claude-sonnet-5-5", agent="analysis", outcome="success") == before_calls + 1
    assert _metric("lgsotf_llm_tokens_total", model="claude-sonnet-5-5", kind="cache_read") == before_tokens + 10
    assert _metric("lgsotf_llm_cost_usd_total", model="claude-sonnet-5-5") == pytest.approx(before_cost + 2.000002)


def test_unknown_model_costs_zero_and_is_reported() -> None:
    rec = UsageRecorder()
    assert rec.record(model="mystery-model", agent="a", outcome="success", tenant_id="t", input_tokens=10**6) == 0
    assert rec.cost_of(UsageSample(model="mystery-model", input_tokens=5)) == 0


async def test_flush_hands_rows_to_sink_and_clears() -> None:
    rec = UsageRecorder()
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id="t1", input_tokens=10, day=DAY)
    received: List[List[LLMUsageRow]] = []

    async def sink(rows: List[LLMUsageRow]) -> None:
        received.append(rows)

    assert await rec.flush(sink) == 1
    assert len(received) == 1 and received[0][0]["input_tokens"] == 10
    assert rec.pending_rows() == []
    assert await rec.flush(sink) == 0
    assert len(received) == 1


async def test_failed_flush_keeps_rows() -> None:
    rec = UsageRecorder()
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id="t1", input_tokens=10, day=DAY)

    async def broken(rows: List[LLMUsageRow]) -> None:
        raise ConnectionError("db down")

    with pytest.raises(ConnectionError):
        await rec.flush(broken)
    rec.record(model="claude-haiku-4-5", agent="triage", outcome="success", tenant_id="t1", input_tokens=5, day=DAY)
    rows = rec.pending_rows()
    assert len(rows) == 1 and rows[0]["input_tokens"] == 15 and rows[0]["calls"] == 2


def test_extract_usage_with_cache_tokens() -> None:
    msg = AIMessage(
        content="{}",
        usage_metadata={
            "input_tokens": 160,
            "output_tokens": 20,
            "total_tokens": 180,
            "input_token_details": {"cache_read": 50, "cache_creation": 0, "ephemeral_5m_input_tokens": 6, "ephemeral_1h_input_tokens": 4},
        },
        response_metadata={"model_name": "claude-opus-5-5", "stop_reason": "end_turn"},
    )
    [sample] = extract_usage(msg, default_model="configured")
    assert sample == UsageSample(
        model="claude-opus-5-5", input_tokens=100, output_tokens=20, cache_read_tokens=50, cache_write_tokens=10, cache_write_1h_tokens=4
    )
    assert sample.total_tokens == 180


def test_extract_usage_attributes_fallback_attempts() -> None:
    msg = AIMessage(
        content="{}",
        usage_metadata={"input_tokens": 30, "output_tokens": 5, "total_tokens": 35},
        response_metadata={
            "model_name": "claude-opus-4-8",
            "usage": {
                "input_tokens": 30,
                "output_tokens": 5,
                "iterations": [
                    {"type": "message", "model": "claude-opus-5-5", "input_tokens": 30, "output_tokens": 0,
                     "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    {"type": "fallback_message", "model": "claude-opus-4-8", "input_tokens": 30, "output_tokens": 5,
                     "cache_read_input_tokens": 2, "cache_creation_input_tokens": None,
                     "cache_creation": {"ephemeral_5m_input_tokens": 3, "ephemeral_1h_input_tokens": 0}},
                ],
            },
        },
    )
    first, second = extract_usage(msg, default_model="claude-opus-5-5")
    assert (first.model, first.input_tokens, first.output_tokens) == ("claude-opus-5-5", 30, 0)
    assert (second.model, second.output_tokens, second.cache_read_tokens, second.cache_write_tokens) == ("claude-opus-4-8", 5, 2, 3)

    rec = UsageRecorder()
    rec.record_samples([first, second], agent="analysis", outcome="success", tenant_id="t")
    rows = {r["model"]: r for r in rec.pending_rows()}
    assert rows["claude-opus-5-5"]["refusals"] == 1
    assert rows["claude-opus-4-8"]["refusals"] == 0 and rows["claude-opus-4-8"]["calls"] == 1


def test_extract_usage_without_metadata() -> None:
    assert extract_usage(None, default_model="m") == []
    [sample] = extract_usage(AIMessage(content="x"), default_model="m")
    assert sample == UsageSample(model="m")


def test_singleton() -> None:
    assert get_usage_recorder() is get_usage_recorder()
