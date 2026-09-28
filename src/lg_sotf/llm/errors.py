"""LLM layer errors.

Agents catch :class:`LLMError` subclasses to fall back to rule-based
behaviour; transport errors from the provider SDK (rate limits, timeouts,
5xx) are deliberately *not* wrapped so LangGraph retry policies can see them.
"""

from __future__ import annotations

from typing import List, Optional


class LLMError(Exception):
    """Base class for LLM layer failures."""


class LLMUnavailable(LLMError):
    """LLM use is disabled or the provider is misconfigured."""


class LLMRefusal(LLMError):
    """The model declined to answer (``stop_reason == "refusal"`` or provider equivalent)."""

    def __init__(self, message: str, *, category: Optional[str] = None, model: Optional[str] = None):
        super().__init__(message)
        self.category = category
        self.model = model


class LLMOutputError(LLMError):
    """The model answered but the output was truncated, unparseable or failed validation."""

    def __init__(
        self,
        message: str,
        *,
        model: Optional[str] = None,
        stop_reason: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
    ):
        super().__init__(message)
        self.model = model
        self.stop_reason = stop_reason
        self.validation_errors: List[str] = validation_errors or []


class LLMBudgetExceeded(LLMError):
    """The tenant's daily token budget would be exceeded by this call."""

    def __init__(self, tenant_id: str, *, limit: int, used: int, requested: int):
        super().__init__(f"daily LLM token budget exceeded for tenant (limit={limit}, used={used}, requested={requested})")
        self.tenant_id = tenant_id
        self.limit = limit
        self.used = used
        self.requested = requested
