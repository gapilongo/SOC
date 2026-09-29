"""LLM usage metering.

Every call is reported to Prometheus immediately and aggregated in memory per
``(tenant_id, day, model, agent)``. A background task periodically calls
:meth:`UsageRecorder.flush` with a sink that UPSERTs the rows into
``llm_usage_daily`` (additively: ``calls = calls + EXCLUDED.calls`` ...).
If the sink fails the rows are merged back and retried on the next flush.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Awaitable, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Set, Tuple, TypedDict

from langchain_core.messages import BaseMessage

from lg_sotf.llm.pricing import ModelPrice, compute_cost, lookup_price, price_table
from lg_sotf.observability import metrics
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings

Outcome = Literal["success", "refusal", "invalid_output", "error", "budget_exceeded"]

_COST_QUANTUM = Decimal("0.000001")
logger = get_logger(__name__)


class LLMUsageRow(TypedDict):
    """One ``llm_usage_daily`` delta. ``input_tokens`` excludes cache reads/writes."""

    tenant_id: str
    day: date
    model: str
    agent: str
    calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: Decimal
    refusals: int
    errors: int


UsageSink = Callable[[List[LLMUsageRow]], Awaitable[None]]


@dataclass(frozen=True)
class UsageSample:
    """Token counts for one model attempt, in provider billing semantics."""

    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cache_write_1h_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_read_tokens + self.cache_write_tokens


@dataclass
class _Aggregate:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: Decimal = field(default_factory=Decimal)
    refusals: int = 0
    errors: int = 0

    def merge(self, other: _Aggregate) -> None:
        self.calls += other.calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.cost_usd += other.cost_usd
        self.refusals += other.refusals
        self.errors += other.errors


_Key = Tuple[str, date, str, str]


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) and value > 0 else 0


def extract_usage(message: Optional[BaseMessage], *, default_model: str) -> List[UsageSample]:
    """Token usage from a provider response.

    Anthropic server-side refusal fallbacks report one entry per attempt in
    ``usage.iterations`` (the top-level usage covers only the final attempt),
    so each attempt is attributed to the model that ran it.
    """
    if message is None:
        return []
    meta = getattr(message, "response_metadata", None) or {}
    served_model = str(meta.get("model_name") or meta.get("model") or default_model)
    raw_usage = meta.get("usage")
    iterations = raw_usage.get("iterations") if isinstance(raw_usage, Mapping) else None
    if isinstance(iterations, list) and any(
        isinstance(it, Mapping) and it.get("type") == "fallback_message" for it in iterations
    ):
        samples = []
        for it in iterations:
            if not isinstance(it, Mapping) or "model" not in it:
                continue
            raw_creation = it.get("cache_creation")
            creation: Mapping[str, Any] = raw_creation if isinstance(raw_creation, Mapping) else {}
            write_1h = _int(creation.get("ephemeral_1h_input_tokens"))
            write_total = _int(it.get("cache_creation_input_tokens")) or (
                _int(creation.get("ephemeral_5m_input_tokens")) + write_1h
            )
            samples.append(
                UsageSample(
                    model=str(it["model"]),
                    input_tokens=_int(it.get("input_tokens")),
                    output_tokens=_int(it.get("output_tokens")),
                    cache_read_tokens=_int(it.get("cache_read_input_tokens")),
                    cache_write_tokens=write_total,
                    cache_write_1h_tokens=write_1h,
                )
            )
        if samples:
            return samples

    usage = getattr(message, "usage_metadata", None)
    if not usage:
        return [UsageSample(model=served_model)]
    details = usage.get("input_token_details") or {}
    cache_read = _int(details.get("cache_read"))
    write_1h = _int(details.get("ephemeral_1h_input_tokens"))
    cache_write = _int(details.get("cache_creation")) + _int(details.get("ephemeral_5m_input_tokens")) + write_1h
    # LangChain's input_tokens includes cached tokens for every provider.
    uncached = max(_int(usage.get("input_tokens")) - cache_read - cache_write, 0)
    return [
        UsageSample(
            model=served_model,
            input_tokens=uncached,
            output_tokens=_int(usage.get("output_tokens")),
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            cache_write_1h_tokens=write_1h,
        )
    ]


class UsageRecorder:
    def __init__(self, settings: Optional[Settings] = None):
        self._lock = threading.Lock()
        self._pending: Dict[_Key, _Aggregate] = {}
        self._prices: Dict[str, ModelPrice] = price_table(settings)
        self._unpriced: Set[str] = set()

    def configure(self, settings: Settings) -> None:
        """Reload prices (e.g. after ``llm.prices`` changes)."""
        with self._lock:
            self._prices = price_table(settings)
            self._unpriced.clear()

    def cost_of(self, sample: UsageSample) -> Decimal:
        price = lookup_price(sample.model, self._prices)
        if price is None:
            if sample.model not in self._unpriced:
                self._unpriced.add(sample.model)
                logger.warning("llm.price_unknown", model=sample.model)
            return Decimal(0)
        return compute_cost(
            price,
            input_tokens=sample.input_tokens,
            output_tokens=sample.output_tokens,
            cache_read_tokens=sample.cache_read_tokens,
            cache_write_tokens=sample.cache_write_tokens,
            cache_write_1h_tokens=sample.cache_write_1h_tokens,
        )

    def record(
        self,
        *,
        model: str,
        agent: str,
        outcome: Outcome,
        tenant_id: Optional[str] = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        cache_write_1h_tokens: int = 0,
        day: Optional[date] = None,
    ) -> Decimal:
        """Record one model attempt and return its cost in USD."""
        sample = UsageSample(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
            cache_write_1h_tokens=cache_write_1h_tokens,
        )
        return self.record_sample(sample, agent=agent, outcome=outcome, tenant_id=tenant_id, day=day)

    def record_sample(
        self,
        sample: UsageSample,
        *,
        agent: str,
        outcome: Outcome,
        tenant_id: Optional[str] = None,
        day: Optional[date] = None,
    ) -> Decimal:
        cost = self.cost_of(sample)
        metrics.record_llm_call(sample.model, agent, outcome)
        metrics.record_llm_tokens(sample.model, "input", sample.input_tokens)
        metrics.record_llm_tokens(sample.model, "output", sample.output_tokens)
        metrics.record_llm_tokens(sample.model, "cache_read", sample.cache_read_tokens)
        metrics.record_llm_tokens(sample.model, "cache_write", sample.cache_write_tokens)
        metrics.record_llm_cost(sample.model, float(cost))

        # Rows are billing records: no tenant (evals, tooling) or no call made means nothing to bill.
        if tenant_id is None or outcome == "budget_exceeded":
            return cost
        key: _Key = (tenant_id, day or datetime.now(UTC).date(), sample.model, agent)
        with self._lock:
            agg = self._pending.setdefault(key, _Aggregate())
            agg.calls += 1
            agg.input_tokens += sample.input_tokens
            agg.output_tokens += sample.output_tokens
            agg.cache_read_tokens += sample.cache_read_tokens
            agg.cache_write_tokens += sample.cache_write_tokens
            agg.cost_usd += cost
            if outcome == "refusal":
                agg.refusals += 1
            elif outcome in ("error", "invalid_output"):
                agg.errors += 1
        return cost

    def record_samples(
        self,
        samples: Sequence[UsageSample],
        *,
        agent: str,
        outcome: Outcome,
        tenant_id: Optional[str] = None,
    ) -> Decimal:
        """Record a call; every attempt but the last was a refusal that triggered a fallback."""
        total = Decimal(0)
        for idx, sample in enumerate(samples):
            attempt_outcome: Outcome = outcome if idx == len(samples) - 1 else "refusal"
            total += self.record_sample(sample, agent=agent, outcome=attempt_outcome, tenant_id=tenant_id)
        return total

    def pending_rows(self) -> List[LLMUsageRow]:
        with self._lock:
            return [_row(k, v) for k, v in self._pending.items()]

    async def flush(self, sink: UsageSink) -> int:
        """Hand pending aggregates to ``sink``; on failure they are kept for the next flush."""
        with self._lock:
            pending, self._pending = self._pending, {}
        if not pending:
            return 0
        rows = [_row(k, v) for k, v in pending.items()]
        try:
            await sink(rows)
        except BaseException:
            with self._lock:
                for key, agg in pending.items():
                    self._pending.setdefault(key, _Aggregate()).merge(agg)
            raise
        return len(rows)

    def reset(self) -> None:
        with self._lock:
            self._pending.clear()


_TALLY_COUNTERS = (
    "calls",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "refusals",
    "errors",
    "budget_exceeded",
)
MAX_TALLY_AGENTS = 16


@dataclass
class _AgentTally:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    refusals: int = 0
    errors: int = 0
    budget_exceeded: int = 0
    cost_usd: Decimal = field(default_factory=Decimal)


@dataclass
class UsageTally:
    """Token and cost totals for one unit of work (an alert run, one agent invocation).

    :func:`~lg_sotf.llm.structured.ainvoke_structured` adds every call it
    makes when given a tally; agents persist the totals to
    ``alerts.summary.llm_usage`` with :func:`merge_usage_summary`.
    """

    by_agent: Dict[str, _AgentTally] = field(default_factory=dict)

    def _agent(self, agent: str) -> _AgentTally:
        key = agent[:64]
        tally = self.by_agent.get(key)
        if tally is None:
            if len(self.by_agent) >= MAX_TALLY_AGENTS:
                key = "other"
                tally = self.by_agent.setdefault(key, _AgentTally())
            else:
                tally = self.by_agent[key] = _AgentTally()
        return tally

    def add_call(self, agent: str, samples: Sequence[UsageSample], outcome: Outcome, cost: Decimal) -> None:
        t = self._agent(agent)
        t.calls += 1
        for s in samples:
            t.input_tokens += s.input_tokens
            t.output_tokens += s.output_tokens
            t.cache_read_tokens += s.cache_read_tokens
            t.cache_write_tokens += s.cache_write_tokens
        t.cost_usd += cost
        if outcome == "refusal":
            t.refusals += 1
        elif outcome in ("error", "invalid_output"):
            t.errors += 1

    def add_budget_exceeded(self, agent: str) -> None:
        self._agent(agent).budget_exceeded += 1

    @property
    def calls(self) -> int:
        return sum(t.calls for t in self.by_agent.values())

    @property
    def cost_usd(self) -> Decimal:
        return sum((t.cost_usd for t in self.by_agent.values()), Decimal(0))

    def is_empty(self) -> bool:
        return not any(t.calls or t.budget_exceeded for t in self.by_agent.values())

    def as_summary(self) -> Dict[str, Any]:
        """JSON-ready totals: ``{calls, ..., cost_usd, total_tokens, by_agent: {agent: {...}}}``."""
        return merge_usage_summary({}, self)


def _as_int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0 else 0


def _as_decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        return Decimal(0)
    try:
        amount = Decimal(str(value))
    except ArithmeticError:
        return Decimal(0)
    return amount if amount.is_finite() and amount > 0 else Decimal(0)


def merge_usage_summary(existing: Optional[Mapping[str, Any]], tally: UsageTally) -> Dict[str, Any]:
    """Add ``tally`` to a stored ``summary.llm_usage`` object and return the new object.

    Unknown or malformed stored values are treated as zero, so a hand-edited
    summary can never break processing.
    """
    stored: Mapping[str, Any] = existing if isinstance(existing, Mapping) else {}
    raw_agents = stored.get("by_agent")
    stored_agents: Mapping[str, Any] = raw_agents if isinstance(raw_agents, Mapping) else {}
    agents: Dict[str, Dict[str, Any]] = {}
    for name, value in list(stored_agents.items())[:MAX_TALLY_AGENTS]:
        if isinstance(name, str) and isinstance(value, Mapping):
            entry: Dict[str, Any] = {c: _as_int(value.get(c)) for c in _TALLY_COUNTERS}
            entry["cost_usd"] = _as_decimal(value.get("cost_usd"))
            agents[name[:64]] = entry
    for name, t in tally.by_agent.items():
        fresh: Dict[str, Any] = {**{c: 0 for c in _TALLY_COUNTERS}, "cost_usd": Decimal(0)}
        entry = agents.setdefault(name, fresh)
        for c in _TALLY_COUNTERS:
            entry[c] += getattr(t, c)
        entry["cost_usd"] += t.cost_usd
    totals: Dict[str, Any] = {c: sum(a[c] for a in agents.values()) for c in _TALLY_COUNTERS}
    cost = sum((a["cost_usd"] for a in agents.values()), Decimal(0))
    totals["total_tokens"] = (
        totals["input_tokens"] + totals["output_tokens"] + totals["cache_read_tokens"] + totals["cache_write_tokens"]
    )
    totals["cost_usd"] = float(cost.quantize(_COST_QUANTUM))
    totals["by_agent"] = {
        name: {**{c: a[c] for c in _TALLY_COUNTERS}, "cost_usd": float(a["cost_usd"].quantize(_COST_QUANTUM))}
        for name, a in sorted(agents.items())
    }
    return totals


def _row(key: _Key, agg: _Aggregate) -> LLMUsageRow:
    tenant_id, day, model, agent = key
    return LLMUsageRow(
        tenant_id=tenant_id,
        day=day,
        model=model,
        agent=agent,
        calls=agg.calls,
        input_tokens=agg.input_tokens,
        output_tokens=agg.output_tokens,
        cache_read_tokens=agg.cache_read_tokens,
        cache_write_tokens=agg.cache_write_tokens,
        cost_usd=agg.cost_usd.quantize(_COST_QUANTUM),
        refusals=agg.refusals,
        errors=agg.errors,
    )


_recorder: Optional[UsageRecorder] = None
_recorder_lock = threading.Lock()


def get_usage_recorder() -> UsageRecorder:
    global _recorder
    with _recorder_lock:
        if _recorder is None:
            from lg_sotf.settings import get_settings

            _recorder = UsageRecorder(get_settings())
        return _recorder


def reset_usage_recorder() -> None:
    global _recorder
    with _recorder_lock:
        _recorder = None
