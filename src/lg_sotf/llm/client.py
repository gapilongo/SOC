"""Chat model factory and per-tier concurrency limits.

``get_chat_model("fast" | "deep")`` returns a configured LangChain chat model
for ``llm.provider``. Models are cached per (provider, tier) and rebuilt when
the tier configuration changes. ``llm_slot(tier)`` bounds in-flight calls per
tier and event loop.

Every model built here carries its provider and structured-output method in
``model.metadata`` (:data:`PROVIDER_KEY`, :data:`STRUCTURED_KEY`), so the
structured-output layer and the usage meter know how to treat it without
guessing from the client class: the self-hosted providers (``ollama``,
``openai_compatible``) use the same OpenAI client class as ``openai``.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading
import time
import weakref
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Literal, Optional, Tuple

from langchain_core.language_models.chat_models import BaseChatModel

from lg_sotf.llm.endpoint import is_self_hosted, resolve_base_url
from lg_sotf.llm.errors import LLMUnavailable
from lg_sotf.observability.metrics import record_llm_slot_wait
from lg_sotf.settings import LLMTierSettings, Settings

Tier = Literal["fast", "deep"]
TIERS: Tuple[Tier, ...] = ("fast", "deep")

# Both lists name the older models that differ from the current API surface, so a newly
# released model works without a code change: Opus 4.7+, Sonnet 5+ and the Fable/Mythos
# line reject non-default sampling parameters, and the newest ones reject the forced
# tool_choice that function calling relies on.
# Models that still accept temperature/top_p/top_k.
_SAMPLING_PREFIXES = (
    "claude-haiku-4-5",
    "claude-sonnet-4-6",
    "claude-opus-4-6",
    "claude-sonnet-4-5",
    "claude-opus-4-5",
    "claude-opus-4-1",
    "claude-opus-4-0",
    "claude-sonnet-4-0",
    "claude-opus-4-2025",
    "claude-sonnet-4-2025",
    "claude-3",
    "claude-2",
    "claude-instant",
)
# Models without structured outputs (output_config.format); they use tool calling instead.
_NO_JSON_SCHEMA_PREFIXES = (
    "claude-sonnet-4-5",
    "claude-sonnet-4-0",
    "claude-sonnet-4-2025",
    "claude-opus-4-0",
    "claude-opus-4-2025",
    "claude-3",
    "claude-2",
    "claude-instant",
)
# Models whose safety classifiers can decline (stop_reason="refusal") and that accept the
# server-side ``fallbacks: "default"`` form, which re-runs a declined request on the model
# Anthropic recommends for the refusal category.
_SERVER_FALLBACK_MODELS = frozenset(
    {"claude-fable-5-1", "claude-mythos-5-1", "claude-fable-5", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
)
SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01"
ANTHROPIC_API_URL = "https://api.anthropic.com"
PROVIDER_KEY = "lg_sotf_provider"
STRUCTURED_KEY = "lg_sotf_structured"
# Sent as the bearer token to a self-hosted server that needs no key: the OpenAI client
# insists on one, and without an explicit value it would read OPENAI_API_KEY from the
# process environment and hand a real cloud key to the local server.
NO_API_KEY = "no-key"


@dataclass(frozen=True)
class ModelCapabilities:
    accepts_temperature: bool
    json_schema: bool
    server_fallback: bool


def model_capabilities(provider: str, model: str) -> ModelCapabilities:
    if provider == "anthropic":
        return ModelCapabilities(
            accepts_temperature=model.startswith(_SAMPLING_PREFIXES),
            json_schema=not model.startswith(_NO_JSON_SCHEMA_PREFIXES),
            server_fallback=model in _SERVER_FALLBACK_MODELS,
        )
    if provider == "fake" or is_self_hosted(provider):
        return ModelCapabilities(accepts_temperature=True, json_schema=True, server_fallback=False)
    reasoning_openai = provider == "openai" and model.startswith(("o1", "o3", "o4", "gpt-5"))
    return ModelCapabilities(accepts_temperature=not reasoning_openai, json_schema=False, server_fallback=False)


def _llm_option(settings: Settings, name: str, default: Any) -> Any:
    """Optional ``llm.*`` fields not (yet) declared on ``LLMSettings``."""
    return getattr(settings.llm, name, default)


def _fingerprint(settings: Settings, tier: Tier) -> Tuple[Any, ...]:
    llm = settings.llm
    key = llm.api_key.get_secret_value() if llm.api_key else ""
    return (
        llm.provider,
        getattr(llm, tier).model_dump_json(),
        llm.base_url,
        llm.structured_output,
        hashlib.sha256(key.encode()).hexdigest(),
        _llm_option(settings, "refusal_fallback", True),
        settings.is_production,
        llm.allow_fake,
    )


_model_cache: Dict[Tuple[str, str], Tuple[Tuple[Any, ...], BaseChatModel]] = {}
_model_cache_lock = threading.Lock()


def get_chat_model(tier: Tier, settings: Settings) -> BaseChatModel:
    """Configured chat model for ``tier``. Raises :class:`LLMUnavailable` when disabled or misconfigured."""
    if tier not in TIERS:
        raise ValueError(f"unknown LLM tier {tier!r}")
    if not settings.llm.enabled:
        raise LLMUnavailable("LLM use is disabled (llm.enabled=false)")
    fingerprint = _fingerprint(settings, tier)
    cache_key = (settings.llm.provider, tier)
    with _model_cache_lock:
        cached = _model_cache.get(cache_key)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
    model = _build_model(settings, tier)
    with _model_cache_lock:
        _model_cache[cache_key] = (fingerprint, model)
    return model


def clear_model_cache() -> None:
    with _model_cache_lock:
        _model_cache.clear()


def _require_api_key(settings: Settings) -> str:
    if settings.llm.api_key is None or not settings.llm.api_key.get_secret_value():
        raise LLMUnavailable(
            f"llm.api_key is not configured for provider {settings.llm.provider!r} "
            "(set LG_SOTF_LLM__API_KEY or the provider's standard API key variable)"
        )
    return settings.llm.api_key.get_secret_value()


def self_hosted_method(settings: Settings) -> str:
    """Structured-output method of the self-hosted providers (``llm.structured_output``, auto = json_schema)."""
    method = settings.llm.structured_output
    return "json_schema" if method == "auto" else method


def _build_model(settings: Settings, tier: Tier) -> BaseChatModel:
    llm = settings.llm
    cfg: LLMTierSettings = getattr(llm, tier)
    provider = llm.provider
    caps = model_capabilities(provider, cfg.model)
    temperature = cfg.temperature if caps.accepts_temperature else None

    if provider == "fake":
        if settings.is_production and not llm.allow_fake:
            raise LLMUnavailable("llm.provider=fake is not allowed in staging/production")
        from lg_sotf.llm.fake import FakeChatModel

        return FakeChatModel(model_name=f"fake-{tier}", max_tokens=cfg.max_tokens)

    base_url = resolve_base_url(settings)
    metadata: Dict[str, Any] = {PROVIDER_KEY: provider}

    if is_self_hosted(provider):
        return _build_self_hosted(settings, cfg, base_url, temperature, metadata)

    api_key = _require_api_key(settings)

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        kwargs: Dict[str, Any] = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            "timeout": cfg.timeout_s,
            "max_retries": cfg.max_retries,
            "api_key": api_key,
        }
        # Always explicit so the SDK never falls back to ANTHROPIC_BASE_URL from the process environment.
        kwargs["base_url"] = base_url or ANTHROPIC_API_URL
        if temperature is not None:
            kwargs["temperature"] = temperature
        effort = getattr(cfg, "effort", None)
        if effort:
            kwargs["effort"] = effort
        # Server-side fallbacks are a Claude API feature; custom gateways may not accept them.
        if caps.server_fallback and not llm.base_url and _llm_option(settings, "refusal_fallback", True):
            kwargs["betas"] = [SERVER_FALLBACK_BETA]
            kwargs["model_kwargs"] = {"fallbacks": "default"}
        return ChatAnthropic(metadata=metadata, **kwargs)

    if provider == "openai":
        return _build_openai(settings, cfg, api_key, base_url, temperature, metadata)

    if provider == "gemini":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError as exc:
            raise LLMUnavailable("provider 'gemini' requires the optional extra: pip install 'lg-sotf[gemini]'") from exc
        kwargs = {
            "model": cfg.model,
            "max_output_tokens": cfg.max_tokens,
            "timeout": cfg.timeout_s,
            "max_retries": cfg.max_retries,
            "api_key": api_key,
        }
        if base_url:
            kwargs["base_url"] = base_url
        if temperature is not None:
            kwargs["temperature"] = temperature
        return ChatGoogleGenerativeAI(metadata=metadata, **kwargs)

    raise LLMUnavailable(f"unsupported LLM provider {provider!r}")


def _build_openai(
    settings: Settings,
    cfg: LLMTierSettings,
    api_key: str,
    base_url: Optional[str],
    temperature: Optional[float],
    metadata: Dict[str, Any],
) -> BaseChatModel:
    """OpenAI, or another OpenAI-compatible cloud API at ``llm.base_url``."""
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise LLMUnavailable("provider 'openai' requires the optional extra: pip install 'lg-sotf[openai]'") from exc
    kwargs: Dict[str, Any] = {
        "model": cfg.model,
        "max_completion_tokens": cfg.max_tokens,
        "timeout": cfg.timeout_s,
        "max_retries": cfg.max_retries,
        "api_key": api_key,
    }
    if base_url:
        kwargs["base_url"] = base_url
    if temperature is not None:
        kwargs["temperature"] = temperature
    method = settings.llm.structured_output
    if base_url and method != "auto":
        # Another OpenAI-compatible cloud API may refuse OpenAI's native method: DeepSeek's
        # thinking models reject a forced tool_choice, so they answer in JSON mode.
        # OpenAI itself (no base_url) always keeps tool calling.
        metadata = {**metadata, STRUCTURED_KEY: method}
    return ChatOpenAI(metadata=metadata, **kwargs)


def _build_self_hosted(
    settings: Settings,
    cfg: LLMTierSettings,
    base_url: Optional[str],
    temperature: Optional[float],
    metadata: Dict[str, Any],
) -> BaseChatModel:
    """An OpenAI chat-completions client for Ollama, vLLM or another compatible server.

    ``BaseChatOpenAI`` rather than ``ChatOpenAI``: it sends ``max_tokens``, which every
    compatible server understands, where ``ChatOpenAI`` renames it to
    ``max_completion_tokens`` (unknown to Ollama). The Responses API is never used.
    """
    try:
        from langchain_openai.chat_models.base import BaseChatOpenAI
    except ImportError as exc:
        raise LLMUnavailable(
            f"provider {settings.llm.provider!r} requires the optional extra: pip install 'lg-sotf[openai]'"
        ) from exc
    if base_url is None:  # resolve_base_url guarantees one; keep the SDK off OPENAI_BASE_URL regardless
        raise LLMUnavailable(f"llm.base_url is required for provider {settings.llm.provider!r}")
    key = settings.llm.api_key.get_secret_value() if settings.llm.api_key else ""
    kwargs: Dict[str, Any] = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "timeout": cfg.timeout_s,
        "max_retries": cfg.max_retries,
        "api_key": key or NO_API_KEY,
        "base_url": base_url,
        "use_responses_api": False,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    return BaseChatOpenAI(metadata={**metadata, STRUCTURED_KEY: self_hosted_method(settings)}, **kwargs)


def _metadata(model: BaseChatModel, key: str) -> Optional[str]:
    meta = getattr(model, "metadata", None)
    value = meta.get(key) if isinstance(meta, dict) else None
    return value if isinstance(value, str) and value else None


def model_structured_method(model: BaseChatModel) -> Optional[str]:
    """The structured-output method the factory chose for ``model`` (None: decide from the provider)."""
    return _metadata(model, STRUCTURED_KEY)


def model_is_self_hosted(model: BaseChatModel) -> bool:
    return is_self_hosted(provider_of(model))


def provider_of(model: BaseChatModel) -> str:
    """Provider name for a chat model instance (``anthropic``, ``openai``, ``gemini``, ``ollama``, ...)."""
    tagged = _metadata(model, PROVIDER_KEY)
    if tagged is not None:
        return tagged
    llm_type = getattr(model, "_llm_type", "")
    if llm_type == "anthropic-chat":
        return "anthropic"
    if llm_type == "lg-sotf-fake":
        return "fake"
    if "openai" in llm_type:
        return "openai"
    if "google" in llm_type or "gemini" in llm_type:
        return "gemini"
    return llm_type or type(model).__name__


def model_name_of(model: BaseChatModel) -> str:
    for attr in ("model", "model_name"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value:
            return value
    return type(model).__name__


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------

_slot_lock = threading.Lock()
_semaphores: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Dict[str, Tuple[int, asyncio.Semaphore]]] = (
    weakref.WeakKeyDictionary()
)


def _semaphore(tier: Tier, size: int) -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    with _slot_lock:
        per_loop = _semaphores.get(loop)
        if per_loop is None:
            per_loop = {}
            _semaphores[loop] = per_loop
        entry = per_loop.get(tier)
        if entry is None or entry[0] != size:
            entry = (size, asyncio.Semaphore(size))
            per_loop[tier] = entry
        return entry[1]


@asynccontextmanager
async def llm_slot(tier: Tier, settings: Settings) -> AsyncIterator[None]:
    """Hold one of ``llm.<tier>.max_concurrency`` slots for the duration of a call.

    Unset, the tier gets ``worker.concurrency`` slots (one per run in flight), so
    the slots never cap throughput below the worker's own concurrency. The wait
    is exported as ``lgsotf_llm_slot_wait_seconds{tier}``: it counts against the
    node timeout, so a sustained wait means the slots are too few.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown LLM tier {tier!r}")
    configured = getattr(settings.llm, tier).max_concurrency
    size = settings.worker.concurrency if configured is None else configured
    if size < 1:
        raise LLMUnavailable(f"llm.{tier}.max_concurrency must be >= 1")
    started = time.monotonic()
    async with _semaphore(tier, size):
        record_llm_slot_wait(tier, time.monotonic() - started)
        yield


def reset_llm_state() -> None:
    """Drop cached models and semaphores (tests, settings reload)."""
    clear_model_cache()
    with _slot_lock:
        _semaphores.clear()
