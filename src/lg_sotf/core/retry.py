"""Which node failures are transient, and the LangGraph retry policy built on that.

Only infrastructure hiccups are retried inside a run: lost database or Redis
connections, LLM transport errors, rate limits and 5xx responses, and
timeouts of individual calls. The node's own time budget
(:class:`~lg_sotf.core.exceptions.NodeTimeout`) is never retried, and nodes
whose budget would not fit the worker's run timeout more than once get a
single attempt (:func:`attempts_within_budget`). Everything else (bad data,
validation, programming errors, LLM refusals or invalid output) raises
immediately so the worker records the failure and the queue's delivery
limit applies.
"""

from __future__ import annotations

import asyncio
from typing import Optional, Tuple, Type

import asyncpg
import httpx
import psycopg
from langgraph.types import RetryPolicy
from redis import exceptions as redis_exceptions

from lg_sotf.core.exceptions import NodeTimeout
from lg_sotf.db.errors import DatabaseUnavailable
from lg_sotf.llm.errors import LLMError

_TRANSIENT_TYPES: Tuple[Type[BaseException], ...] = (
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    DatabaseUnavailable,
    asyncpg.PostgresConnectionError,
    asyncpg.ConnectionDoesNotExistError,
    asyncpg.TooManyConnectionsError,
    asyncpg.CannotConnectNowError,
    asyncpg.SerializationError,
    asyncpg.DeadlockDetectedError,
    psycopg.OperationalError,
    redis_exceptions.ConnectionError,
    redis_exceptions.TimeoutError,
    redis_exceptions.BusyLoadingError,
    httpx.TransportError,
)

try:
    import anthropic

    _TRANSIENT_TYPES += (
        anthropic.APIConnectionError,
        anthropic.APITimeoutError,
        anthropic.RateLimitError,
        anthropic.InternalServerError,
    )
except ImportError:  # pragma: no cover - anthropic is a core dependency, guard kept for slim installs
    pass

_RETRYABLE_STATUS = frozenset({408, 409, 425, 429})
_MAX_CAUSE_DEPTH = 4


def _status_code(exc: BaseException) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    if status is None:
        # google-genai (Gemini) errors carry the HTTP status as ``code``. Other libraries use ``code`` for
        # non-HTTP values (SQLSTATE strings, errno), so only an integer in the HTTP range counts.
        code = getattr(exc, "code", None)
        if isinstance(code, int) and not isinstance(code, bool) and 100 <= code <= 599:
            status = code
    return status if isinstance(status, int) else None


def _is_transient_single(exc: BaseException) -> bool:
    if isinstance(exc, (LLMError, NodeTimeout)):
        return False
    if isinstance(exc, _TRANSIENT_TYPES):
        return True
    status = _status_code(exc)
    return status is not None and (status in _RETRYABLE_STATUS or 500 <= status <= 599)


def is_transient(exc: BaseException) -> bool:
    """True when ``exc`` (or an exception it was raised from) is worth retrying."""
    current: Optional[BaseException] = exc
    for _ in range(_MAX_CAUSE_DEPTH):
        if current is None:
            return False
        if isinstance(current, (LLMError, NodeTimeout)):
            return False
        if _is_transient_single(current):
            return True
        current = current.__cause__
    return False


DEFAULT_MAX_ATTEMPTS = 3
RUN_BUDGET_FRACTION = 0.8


def attempts_within_budget(
    node_timeout_s: float, run_timeout_s: float, max_attempts: int = DEFAULT_MAX_ATTEMPTS
) -> int:
    """How many attempts of a node fit in the worker's run timeout (at least one).

    Retrying a node whose attempts cannot all finish before the worker
    cancels the run only burns LLM calls until the message is dead-lettered.
    """
    if node_timeout_s <= 0:
        raise ValueError("node timeout must be positive")
    fits = int((run_timeout_s * RUN_BUDGET_FRACTION) // node_timeout_s)
    return max(1, min(max_attempts, fits))


def build_retry_policy(max_attempts: int = DEFAULT_MAX_ATTEMPTS, initial_interval: float = 0.5) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=max_attempts,
        initial_interval=initial_interval,
        backoff_factor=2.0,
        max_interval=30.0,
        jitter=True,
        retry_on=is_transient,
    )
