"""Usage metering: cost math, aggregation, flushing and metrics."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Callable, List

import pytest
from langchain_core.messages import AIMessage

from lg_sotf.llm.pricing import DEFAULT_PRICES, ModelPrice, compute_cost, lookup_price, price_table
from lg_sotf.llm.usage import LLMUsageRow, UsageRecorder, UsageSample, extract_usage, get_usage_recorder
from lg_sotf.observability.metrics import REGISTRY
from lg_sotf.settings import Settings

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


def test_singleton(make_settings: Callable[..., Settings]) -> None:
    first = get_usage_recorder(make_settings(llm={"prices": {"house-model": {"input": 1, "output": 2}}}))
    assert get_usage_recorder(make_settings()) is first
    assert "house-model" in first._prices  # priced by the first caller's settings


# ------------------------------------------------------------------ per-alert totals


def test_merge_usage_summary_adds_to_stored_totals() -> None:
    from decimal import Decimal as D

    from lg_sotf.llm.usage import UsageSample, UsageTally, merge_usage_summary

    tally = UsageTally()
    tally.add_call("triage", [UsageSample("claude-haiku-4-5", 100, 20, 0, 0)], "success", D("0.0002"))
    tally.add_call("analysis", [UsageSample("claude-opus-5-5", 50, 10, 900, 100)], "success", D("0.01"))
    tally.add_call("analysis", [], "refusal", D(0))
    tally.add_budget_exceeded("correlation")
    first = merge_usage_summary(None, tally)
    assert first["calls"] == 3 and first["refusals"] == 1 and first["budget_exceeded"] == 1
    assert first["input_tokens"] == 150 and first["cache_read_tokens"] == 900 and first["cache_write_tokens"] == 100
    assert first["total_tokens"] == 150 + 30 + 900 + 100
    assert first["cost_usd"] == 0.0102
    assert set(first["by_agent"]) == {"analysis", "correlation", "triage"}

    again = merge_usage_summary(first, tally)
    assert again["calls"] == 6 and again["cost_usd"] == 0.0204
    assert again["by_agent"]["triage"] == {**first["by_agent"]["triage"], "calls": 2, "input_tokens": 200,
                                           "output_tokens": 40, "cost_usd": 0.0004}


def test_merge_usage_summary_tolerates_malformed_stored_values() -> None:
    from decimal import Decimal as D

    from lg_sotf.llm.usage import UsageSample, UsageTally, merge_usage_summary

    tally = UsageTally()
    tally.add_call("triage", [UsageSample("m", 1, 1)], "success", D("0.5"))
    stored = {"by_agent": {"triage": {"calls": "x", "cost_usd": "nan"}, 5: {}, "bad": "not a mapping"}, "calls": -3}
    merged = merge_usage_summary(stored, tally)
    assert merged["calls"] == 1 and merged["cost_usd"] == 0.5 and list(merged["by_agent"]) == ["triage"]
    assert UsageTally().is_empty() and not tally.is_empty()


def test_merge_usage_summary_records_provider_and_model_per_agent() -> None:
    from decimal import Decimal as D

    from lg_sotf.llm.usage import UsageSample, UsageTally, merge_usage_summary

    tally = UsageTally()
    tally.add_call(
        "triage", [UsageSample("claude-haiku-4-5-20251001", 1, 1)], "success", D(0),
        model="claude-haiku-4-5", provider="anthropic",
    )
    tally.add_call("analysis", [], "error", D(0), model="gpt-5", provider="openai")
    tally.add_call("correlation", [], "error", D(0))
    first = merge_usage_summary(None, tally)
    # The served model (response metadata) wins over the requested one.
    assert first["by_agent"]["triage"]["model"] == "claude-haiku-4-5-20251001"
    assert first["by_agent"]["triage"]["provider"] == "anthropic"
    assert first["by_agent"]["analysis"]["model"] == "gpt-5" and first["by_agent"]["analysis"]["provider"] == "openai"
    assert "model" not in first["by_agent"]["correlation"]
    # Stored values survive a merge without calls from that agent; a new call replaces them.
    later = UsageTally()
    later.add_call("analysis", [], "success", D(0), model="gemini-2.5-pro", provider="gemini")
    merged = merge_usage_summary(first, later)
    assert merged["by_agent"]["triage"]["model"] == "claude-haiku-4-5-20251001"
    assert (merged["by_agent"]["analysis"]["model"], merged["by_agent"]["analysis"]["provider"]) == (
        "gemini-2.5-pro",
        "gemini",
    )
    stored = {"by_agent": {"triage": {"calls": 1, "model": 7, "provider": "x" * 100}}}
    again = merge_usage_summary(stored, UsageTally())["by_agent"]["triage"]
    assert "model" not in again and len(again["provider"]) == 32


# --- DeepSeek: official prices (api-docs.deepseek.com/quick_start/pricing, 2026-11-06) ---------
# Off-peak USD per 1M tokens: flash 0.003 cache hit / 0.15 miss / 0.60 output;
# v4-pro 0.022 / 0.66 / 1.98. Peak (01-04 and 06-10 UTC, Monday to Friday) is twice that.
OFF_PEAK = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)  # Wednesday 12:00 UTC
PEAK = datetime(2026, 11, 4, 2, 30, tzinfo=UTC)  # Wednesday 02:30 UTC
WEEKEND_PEAK_HOUR = datetime(2026, 11, 7, 2, 30, tzinfo=UTC)  # Saturday 02:30 UTC


@pytest.mark.parametrize(
    ("model", "hit", "miss", "out"),
    [
        ("deepseek-flash", "0.003", "0.15", "0.60"),
        ("deepseek-v4-flash", "0.003", "0.15", "0.60"),
        ("deepseek-v4-pro", "0.022", "0.66", "1.98"),
    ],
)
def test_deepseek_off_peak_prices_match_the_published_table(model: str, hit: str, miss: str, out: str) -> None:
    price = DEFAULT_PRICES[model]
    m = 1_000_000
    assert compute_cost(price, input_tokens=m, output_tokens=0, at=OFF_PEAK) == Decimal(miss)
    assert compute_cost(price, input_tokens=0, output_tokens=0, cache_read_tokens=m, at=OFF_PEAK) == Decimal(hit)
    assert compute_cost(price, input_tokens=0, output_tokens=m, at=OFF_PEAK) == Decimal(out)


def test_deepseek_peak_hours_double_every_rate_on_weekdays_only() -> None:
    pro = DEFAULT_PRICES["deepseek-v4-pro"]
    calls = {"input_tokens": 1_000_000, "output_tokens": 1_000_000, "cache_read_tokens": 1_000_000}
    off = compute_cost(pro, **calls, at=OFF_PEAK)
    assert off == Decimal("0.66") + Decimal("1.98") + Decimal("0.022")
    assert compute_cost(pro, **calls, at=PEAK) == off * 2
    assert compute_cost(pro, **calls, at=WEEKEND_PEAK_HOUR) == off
    # Window edges: 01:00 and 06:00 are peak, 04:00 and 10:00 are not.
    for hour, mult in ((0, 1), (1, 2), (3, 2), (4, 1), (5, 1), (6, 2), (9, 2), (10, 1)):
        at = datetime(2026, 11, 4, hour, 0, tzinfo=UTC)
        assert pro.multiplier_at(at) == mult, hour
    # Without a time the base (off-peak) rate applies; prices with no windows never change.
    assert compute_cost(pro, **calls) == off
    assert DEFAULT_PRICES["claude-haiku-4-5"].multiplier_at(PEAK) == 1


def test_recorder_prices_deepseek_at_the_time_of_the_call() -> None:
    recorder = UsageRecorder()
    sample = UsageSample(model="deepseek-flash", input_tokens=1_000_000, cache_read_tokens=1_000_000)
    assert recorder.cost_of(sample, at=OFF_PEAK) == Decimal("0.153")
    assert recorder.cost_of(sample, at=PEAK) == Decimal("0.306")
    assert recorder.cost_of(sample) in (Decimal("0.153"), Decimal("0.306"))
