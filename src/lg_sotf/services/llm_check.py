"""Model connectivity check: one tiny structured call per tier (``POST /tenant/llm/test``).

The probe goes through the same path as triage (``get_chat_model`` and
:func:`~lg_sotf.llm.ainvoke_structured`: the configured structured-output
method, the concurrency slots, usage metering under agent ``llm_test``), so
a green result means the model can actually answer the platform's schemas,
not only that the endpoint accepts connections. The prompt carries no alert
data; the probe value still goes through the untrusted-data boundary.

Errors are reported as a fixed code and a message built here: provider
error bodies (which can echo a partial API key or an internal URL) are never
passed through.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, List, Literal, Optional, Tuple

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import BaseModel

from lg_sotf.llm import LLMError, LLMOutputError, LLMRefusal, LLMUnavailable, ainvoke_structured, build_messages
from lg_sotf.llm.client import TIERS, Tier, get_chat_model
from lg_sotf.llm.schema import clipped_str
from lg_sotf.llm.structured import structured_method, usage_model_id
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.settings import Settings

log = get_logger(__name__)

AGENT = "llm_test"
DEFAULT_TIMEOUT_S = 60.0
SYSTEM = "You are the connectivity check of a security alert triage platform."
TASK = 'Confirm that you can answer in the required format: set status to "ok" and echo the probe value.'
ModelFactory = Callable[[Tier, Settings], BaseChatModel]


class LLMProbe(BaseModel):
    status: Literal["ok"]
    echo: clipped_str(64)  # type: ignore[valid-type]


@dataclass(frozen=True)
class TierCheck:
    tier: Tier
    model: str
    ok: bool
    latency_ms: int
    method: Optional[str] = None
    error_code: Optional[str] = None
    error: Optional[str] = None


@dataclass
class LLMCheckReport:
    provider: str
    enabled: bool
    tiers: List[TierCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.tiers) and all(t.ok for t in self.tiers)


_HTTP_HINTS = {
    401: "the endpoint rejected the API key (check llm.api_key)",
    403: "the API key is not allowed to use this model",
    404: "the model or endpoint path was not found (for Ollama: pull the model; check llm.base_url ends in /v1)",
    408: "the endpoint timed out",
    413: "the request was too large for the endpoint",
    429: "rate limited or out of quota at the provider",
}


def _status_code(exc: BaseException) -> Optional[int]:
    for candidate in (exc, getattr(exc, "response", None)):
        code = getattr(candidate, "status_code", None) or getattr(candidate, "code", None)
        if isinstance(code, int) and 100 <= code <= 599:
            return code
    return None


def describe_error(exc: BaseException, timeout_s: float) -> Tuple[str, str]:
    """``(code, message)`` safe to show a tenant admin: no provider response text, URL or key."""
    if isinstance(exc, TimeoutError):
        return "timeout", f"no answer within {timeout_s:.0f} s"
    if isinstance(exc, LLMUnavailable):
        # Our own configuration messages; they never contain the key or the URL.
        return "unavailable", str(exc)[:300]
    if isinstance(exc, LLMRefusal):
        return "refusal", "the model declined the probe"
    if isinstance(exc, LLMOutputError):
        detail = "; ".join(exc.validation_errors[:5])
        truncated = " (output truncated: raise max_tokens)" if exc.stop_reason in ("length", "max_tokens") else ""
        return "invalid_output", (
            "the model answered but not in the required JSON format" + (f": {detail}" if detail else "") + truncated
        )
    if isinstance(exc, LLMError):
        return "error", type(exc).__name__
    name = type(exc).__name__
    status = _status_code(exc)
    if status is not None:
        hint = _HTTP_HINTS.get(status, "the provider reported a server error" if status >= 500 else "request refused")
        return "http_error", f"HTTP {status}: {hint}"
    if "timeout" in name.lower():
        return "timeout", "the endpoint did not answer in time"
    if "connect" in name.lower():
        return "connection", "could not connect to the model endpoint (is it running and reachable from the API?)"
    return "error", name


async def _check_tier(
    tier: Tier, settings: Settings, tenant_id: str, timeout_s: float, factory: ModelFactory
) -> TierCheck:
    configured = getattr(settings.llm, tier).model
    started = time.perf_counter()
    model_id, method = configured, None
    try:
        model = factory(tier, settings)
        model_id, method = usage_model_id(model), structured_method(model)
        messages = build_messages(SYSTEM, TASK, {"probe": "ping"}, settings=settings)
        await asyncio.wait_for(
            ainvoke_structured(model, LLMProbe, messages, agent=AGENT, tier=tier, tenant_id=tenant_id, settings=settings),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001 - every failure becomes a sanitized report line
        code, message = describe_error(exc, timeout_s)
        latency = round((time.perf_counter() - started) * 1000)
        log_failure(
            log, "llm.check_failed", exc, level="warning", tier=tier, model=model_id, error_code=code,
            error_type=type(exc).__name__,
        )
        return TierCheck(tier, model_id, False, latency, method, code, message)
    latency = round((time.perf_counter() - started) * 1000)
    log.info("llm.check_ok", tier=tier, model=model_id, latency_ms=latency)
    return TierCheck(tier, model_id, True, latency, method)


async def check_llm(
    settings: Settings,
    tenant_id: str,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    factory: Optional[ModelFactory] = None,
) -> LLMCheckReport:
    """Probe the fast and deep tiers concurrently, each bounded by ``timeout_s``."""
    report = LLMCheckReport(provider=settings.llm.provider, enabled=settings.llm.enabled)
    make: ModelFactory = factory or (lambda tier, s: get_chat_model(tier, s))
    if not settings.llm.enabled:
        report.tiers = [
            TierCheck(t, getattr(settings.llm, t).model, False, 0, None, "disabled", "LLM use is disabled (llm.enabled=false)")
            for t in TIERS
        ]
        return report
    report.tiers = list(await asyncio.gather(*(_check_tier(t, settings, tenant_id, timeout_s, make) for t in TIERS)))
    return report
