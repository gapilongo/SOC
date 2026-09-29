"""Validated structured output from chat models.

``ainvoke_structured`` uses Anthropic structured outputs
(``output_config.format``, via ``with_structured_output(method="json_schema")``)
where the model supports them and tool calling elsewhere. It distinguishes a
refusal (:class:`LLMRefusal`) from truncated or invalid output
(:class:`LLMOutputError`), never repairs or clamps values, meters usage, and
honours the per-tier concurrency slot and the tenant token budget.
"""

from __future__ import annotations

import asyncio
import math
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Type, TypeVar

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from pydantic import BaseModel, ValidationError
from redis.exceptions import RedisError

from lg_sotf.llm.budget import USE_DEFAULT, BudgetLimit, Reservation, TokenBudget
from lg_sotf.llm.client import Tier, llm_slot, model_capabilities, model_name_of, provider_of
from lg_sotf.llm.errors import LLMBudgetExceeded, LLMOutputError, LLMRefusal
from lg_sotf.llm.usage import Outcome, UsageSample, extract_usage, get_usage_recorder
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings, get_settings

T = TypeVar("T", bound=BaseModel)

logger = get_logger(__name__)

_TRUNCATION_REASONS = frozenset({"max_tokens", "length", "MAX_TOKENS", "model_context_window_exceeded"})
_SAFETY_FINISH_REASONS = frozenset(
    {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "IMAGE_SAFETY", "content_filter"}
)


def structured_method(model: BaseChatModel) -> str:
    provider = provider_of(model)
    if provider == "fake":
        return "json_schema"
    if provider == "anthropic" and model_capabilities("anthropic", model_name_of(model)).json_schema:
        return "json_schema"
    return "function_calling"


def estimate_input_tokens(messages: Sequence[BaseMessage]) -> int:
    """Conservative token estimate (~3 characters per token for JSON-heavy prompts)."""
    chars = 0
    for m in messages:
        if isinstance(m.content, str):
            chars += len(m.content)
        else:
            for block in m.content:
                if isinstance(block, str):
                    chars += len(block)
                elif isinstance(block, Mapping) and isinstance(block.get("text"), str):
                    chars += len(block["text"])
    return math.ceil(chars / 3)


def _stop_reason(raw: Optional[BaseMessage]) -> Optional[str]:
    if raw is None:
        return None
    meta = raw.response_metadata or {}
    reason = meta.get("stop_reason") or meta.get("finish_reason")
    return str(reason) if reason is not None else None


def _refusal(raw: Optional[BaseMessage], model: str) -> Optional[LLMRefusal]:
    if raw is None:
        return None
    meta = raw.response_metadata or {}
    reason = _stop_reason(raw)
    if reason == "refusal":
        details = meta.get("stop_details")
        category = details.get("category") if isinstance(details, Mapping) else None
        return LLMRefusal(f"model declined the request (category={category})", category=category, model=model)
    if isinstance(raw, AIMessage) and raw.additional_kwargs.get("refusal"):
        return LLMRefusal("model declined the request", category=None, model=model)
    if reason in _SAFETY_FINISH_REASONS:
        return LLMRefusal(f"provider safety filter stopped generation ({reason})", category=reason.lower(), model=model)
    return None


def _validation_summary(exc: ValidationError) -> List[str]:
    # Locations and error types only: messages and inputs may echo alert content.
    return [f"{'.'.join(str(p) for p in err['loc'])}: {err['type']}" for err in exc.errors()]


def _find_validation_error(exc: Optional[BaseException], max_depth: int = 4) -> Optional[ValidationError]:
    """The pydantic error behind a parser failure (LangChain wraps it in OutputParserException)."""
    seen: set[int] = set()
    current = exc
    for _ in range(max_depth + 1):
        if current is None or id(current) in seen:
            return None
        if isinstance(current, ValidationError):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def _classify(
    result: Mapping[str, Any], schema: Type[T], model: str, agent: str
) -> tuple[Outcome, Optional[T], Optional[Exception]]:
    raw = result.get("raw")
    parsed = result.get("parsed")
    parsing_error = result.get("parsing_error")

    refusal = _refusal(raw, model)
    if refusal is not None:
        return "refusal", None, refusal

    reason = _stop_reason(raw)
    if reason in _TRUNCATION_REASONS:
        return "invalid_output", None, LLMOutputError(
            f"{agent}: output truncated before {schema.__name__} was complete (stop_reason={reason})",
            model=model,
            stop_reason=reason,
        )
    if parsing_error is not None or parsed is None:
        kind = type(parsing_error).__name__ if parsing_error is not None else "no structured output"
        validation = _find_validation_error(parsing_error)
        return "invalid_output", None, LLMOutputError(
            f"{agent}: model output could not be parsed as {schema.__name__} ({kind})",
            model=model,
            stop_reason=reason,
            validation_errors=_validation_summary(validation) if validation is not None else None,
        )
    if isinstance(parsed, schema):
        return "success", parsed, None
    try:
        payload = parsed.model_dump() if isinstance(parsed, BaseModel) else parsed
        return "success", schema.model_validate(payload), None
    except ValidationError as exc:
        return "invalid_output", None, LLMOutputError(
            f"{agent}: model output failed {schema.__name__} validation ({exc.error_count()} errors)",
            model=model,
            stop_reason=reason,
            validation_errors=_validation_summary(exc),
        )


async def ainvoke_structured(
    model: BaseChatModel,
    schema: Type[T],
    messages: Sequence[BaseMessage],
    *,
    agent: str,
    tier: Tier,
    tenant_id: Optional[str] = None,
    settings: Optional[Settings] = None,
    budget: Optional[TokenBudget] = None,
    budget_limit: BudgetLimit = USE_DEFAULT,
) -> T:
    """Invoke ``model`` and return a validated ``schema`` instance.

    Raises :class:`LLMRefusal`, :class:`LLMOutputError` or
    :class:`LLMBudgetExceeded`; provider transport errors propagate unchanged.
    With ``budget`` and ``tenant_id`` an estimate is reserved first and settled
    with the real token count afterwards. ``budget_limit`` is the tenant's
    daily limit: an int, ``None`` for unlimited, or ``USE_DEFAULT`` (the
    default) for ``llm.daily_token_budget_per_tenant``.
    """
    s = settings or get_settings()
    model_id = model_name_of(model)
    recorder = get_usage_recorder()
    log = logger.bind(agent=agent, tier=tier, model=model_id)

    reservation: Optional[Reservation] = None
    if budget is not None and tenant_id is not None:
        estimate = estimate_input_tokens(messages) + getattr(s.llm, tier).max_tokens
        try:
            reservation = await budget.check_and_reserve(tenant_id, estimate, limit=budget_limit)
        except LLMBudgetExceeded:
            recorder.record(model=model_id, agent=agent, outcome="budget_exceeded", tenant_id=tenant_id)
            log.warning("llm.budget_exceeded")
            raise

    runnable = model.with_structured_output(schema, method=structured_method(model), include_raw=True)
    start = time.perf_counter()
    try:
        async with llm_slot(tier, s):
            result = await runnable.ainvoke(list(messages))
    except BaseException as exc:
        # Cancellation (node timeouts) must also hand the reservation back.
        if not isinstance(exc, asyncio.CancelledError):
            recorder.record(model=model_id, agent=agent, outcome="error", tenant_id=tenant_id)
            log.warning(
                "llm.call_failed", error_type=type(exc).__name__, latency_ms=round((time.perf_counter() - start) * 1000)
            )
        if reservation is not None and budget is not None:
            await _settle(budget, reservation, 0)
        raise
    latency_ms = round((time.perf_counter() - start) * 1000)

    if not isinstance(result, Mapping):
        recorder.record(model=model_id, agent=agent, outcome="invalid_output", tenant_id=tenant_id)
        if reservation is not None and budget is not None:
            await _settle(budget, reservation, 0)
        raise LLMOutputError(
            f"{agent}: structured runnable returned {type(result).__name__}, expected a mapping", model=model_id
        )
    outcome, value, error = _classify(result, schema, model_id, agent)
    samples: List[UsageSample] = extract_usage(result.get("raw"), default_model=model_id)
    cost = recorder.record_samples(samples, agent=agent, outcome=outcome, tenant_id=tenant_id)
    if reservation is not None and budget is not None:
        await _settle(budget, reservation, sum(sample.total_tokens for sample in samples))

    event: Dict[str, Any] = {
        "outcome": outcome,
        "latency_ms": latency_ms,
        "input_tokens": sum(x.input_tokens for x in samples),
        "output_tokens": sum(x.output_tokens for x in samples),
        "cache_read_tokens": sum(x.cache_read_tokens for x in samples),
        "cache_write_tokens": sum(x.cache_write_tokens for x in samples),
        "cost_usd": float(cost),
        "served_by": samples[-1].model if samples else model_id,
    }
    if error is not None or value is None:
        if isinstance(error, LLMRefusal):
            event["refusal_category"] = error.category
        log.warning("llm.call", **event)
        raise error or LLMOutputError(f"{agent}: no structured output", model=model_id)
    log.info("llm.call", **event)
    return value


async def _settle(budget: TokenBudget, reservation: Reservation, actual: int) -> None:
    try:
        await budget.settle(reservation, actual)
    except RedisError as exc:
        # The call already happened; failing it now would discard a paid-for result.
        logger.error("llm.budget_settle_failed", error_type=type(exc).__name__, tenant_id=reservation.tenant_id)
