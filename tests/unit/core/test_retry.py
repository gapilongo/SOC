"""Only transient infrastructure failures are retried."""

from __future__ import annotations

import httpx
import pytest
from redis import exceptions as redis_exceptions

from lg_sotf.core.retry import attempts_within_budget, build_retry_policy, is_transient
from lg_sotf.db.errors import DatabaseUnavailable, InvalidValue, PoolExhausted
from lg_sotf.errors import NodeTimeout
from lg_sotf.llm.errors import LLMOutputError, LLMRefusal, LLMUnavailable


class CodeError(Exception):
    """Like google-genai's APIError (Gemini): the HTTP status is in ``code``."""

    def __init__(self, code: object) -> None:
        super().__init__(f"code {code}")
        self.code = code


class StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError(),
        TimeoutError(),
        ConnectionResetError(),
        DatabaseUnavailable("down"),
        PoolExhausted("busy"),
        redis_exceptions.ConnectionError(),
        redis_exceptions.TimeoutError(),
        httpx.ConnectError("refused"),
        StatusError(429),
        StatusError(503),
        StatusError(529),
        CodeError(503),
        CodeError(429),
    ],
)
def test_transient(exc: BaseException) -> None:
    assert is_transient(exc)


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("bug"),
        ValueError("bad data"),
        KeyError("x"),
        InvalidValue("constraint"),
        LLMRefusal("no"),
        LLMOutputError("bad json"),
        LLMUnavailable("disabled"),
        StatusError(400),
        StatusError(401),
        CodeError(400),
        CodeError("40001"),
        CodeError(5),
        NodeTimeout("analysis", 420),
    ],
)
def test_not_transient(exc: BaseException) -> None:
    assert not is_transient(exc)


def test_cause_chain_is_inspected() -> None:
    wrapper = RuntimeError("wrapped")
    wrapper.__cause__ = ConnectionResetError()
    assert is_transient(wrapper)


def test_anthropic_transport_errors_are_transient() -> None:
    anthropic = pytest.importorskip("anthropic")
    request = httpx.Request("POST", "https://example.invalid")
    assert is_transient(anthropic.APIConnectionError(request=request))
    response = httpx.Response(429, request=request)
    assert is_transient(anthropic.RateLimitError("slow down", response=response, body=None))
    bad = httpx.Response(400, request=request)
    assert not is_transient(anthropic.BadRequestError("bad", response=bad, body=None))


def test_policy_uses_the_classifier() -> None:
    policy = build_retry_policy(max_attempts=4)
    assert policy.max_attempts == 4 and policy.retry_on is is_transient


def test_node_timeout_is_not_retried_even_though_caused_by_a_timeout() -> None:
    exc = NodeTimeout("analysis", 420)
    exc.__cause__ = TimeoutError()
    assert not is_transient(exc)
    assert not isinstance(exc, TimeoutError)


@pytest.mark.parametrize(
    ("node_timeout", "run_timeout", "expected"),
    [(420, 900, 1), (180, 900, 3), (300, 900, 2), (1_000, 900, 1), (60, 900, 3)],
)
def test_attempts_fit_the_worker_run_timeout(node_timeout: float, run_timeout: float, expected: int) -> None:
    assert attempts_within_budget(node_timeout, run_timeout) == expected


def test_gemini_server_errors_are_transient() -> None:
    errors = pytest.importorskip("google.genai.errors")
    overloaded = errors.ServerError(503, {"error": {"code": 503, "message": "high demand", "status": "UNAVAILABLE"}})
    assert is_transient(overloaded)
    throttled = errors.ClientError(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}})
    assert is_transient(throttled)
    assert not is_transient(errors.ClientError(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}))
