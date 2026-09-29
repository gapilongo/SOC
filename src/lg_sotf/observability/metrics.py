"""Prometheus metrics (architecture section 13).

All metrics live on a module registry so importing this module twice, or
running tests in the same process, never collides with the global default
registry. Labels are low-cardinality only: never tenant, alert or user ids.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Tuple

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

REGISTRY = CollectorRegistry(auto_describe=True)

_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_NODE_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0)

HTTP_REQUESTS = Counter(
    "lgsotf_http_requests_total",
    "HTTP requests handled, by route template, method and status code.",
    ["route", "method", "status"],
    registry=REGISTRY,
)
HTTP_REQUEST_SECONDS = Histogram(
    "lgsotf_http_request_seconds",
    "HTTP request latency in seconds, by route template and method.",
    ["route", "method"],
    buckets=_LATENCY_BUCKETS,
    registry=REGISTRY,
)
QUEUE_DEPTH = Gauge(
    "lgsotf_queue_depth",
    "Entries in a work queue stream.",
    ["stream"],
    registry=REGISTRY,
)
QUEUE_PENDING = Gauge(
    "lgsotf_queue_pending",
    "Delivered but unacknowledged entries in a work queue stream.",
    ["stream"],
    registry=REGISTRY,
)
RUNS = Counter(
    "lgsotf_runs_total",
    "Workflow runs finished, by outcome.",
    ["outcome"],
    registry=REGISTRY,
)
NODE_SECONDS = Histogram(
    "lgsotf_node_seconds",
    "Workflow node execution time in seconds.",
    ["node"],
    buckets=_NODE_BUCKETS,
    registry=REGISTRY,
)
LLM_CALLS = Counter(
    "lgsotf_llm_calls_total",
    "LLM calls, by model, calling agent and outcome.",
    ["model", "agent", "outcome"],
    registry=REGISTRY,
)
LLM_TOKENS = Counter(
    "lgsotf_llm_tokens_total",
    "LLM tokens, by model and kind (input, output, cache_read, cache_write).",
    ["model", "kind"],
    registry=REGISTRY,
)
LLM_COST_USD = Counter(
    "lgsotf_llm_cost_usd_total",
    "Estimated LLM spend in US dollars, by model.",
    ["model"],
    registry=REGISTRY,
)
ESCALATIONS_OPEN = Gauge(
    "lgsotf_escalations_open",
    "Escalations currently open or claimed.",
    registry=REGISTRY,
)
ACTIONS = Counter(
    "lgsotf_actions_total",
    "Response action transitions, by action type and resulting status.",
    ["action_type", "status"],
    registry=REGISTRY,
)

LLM_TOKEN_KINDS = ("input", "output", "cache_read", "cache_write")


def observe_http_request(route: str, method: str, status: int, seconds: float) -> None:
    """``route`` must be the route template (``/api/v1/alerts/{id}``), never the raw path."""
    HTTP_REQUESTS.labels(route=route, method=method.upper(), status=str(status)).inc()
    HTTP_REQUEST_SECONDS.labels(route=route, method=method.upper()).observe(seconds)


def set_queue_depth(stream: str, depth: int) -> None:
    QUEUE_DEPTH.labels(stream=stream).set(depth)


def set_queue_pending(stream: str, pending: int) -> None:
    QUEUE_PENDING.labels(stream=stream).set(pending)


def record_run(outcome: str) -> None:
    RUNS.labels(outcome=outcome).inc()


def observe_node(node: str, seconds: float) -> None:
    NODE_SECONDS.labels(node=node).observe(seconds)


@contextmanager
def time_node(node: str) -> Iterator[None]:
    """Observe node duration whether the body succeeds or raises."""
    start = time.perf_counter()
    try:
        yield
    finally:
        observe_node(node, time.perf_counter() - start)


def record_llm_call(model: str, agent: str, outcome: str) -> None:
    LLM_CALLS.labels(model=model, agent=agent, outcome=outcome).inc()


def record_llm_tokens(model: str, kind: str, tokens: int) -> None:
    if kind not in LLM_TOKEN_KINDS:
        raise ValueError(f"unknown token kind {kind!r}")
    if tokens > 0:
        LLM_TOKENS.labels(model=model, kind=kind).inc(tokens)


def record_llm_cost(model: str, usd: float) -> None:
    if usd > 0:
        LLM_COST_USD.labels(model=model).inc(usd)


def set_escalations_open(count: int) -> None:
    ESCALATIONS_OPEN.set(count)


def record_action(action_type: str, status: str) -> None:
    ACTIONS.labels(action_type=action_type, status=status).inc()


def render_latest() -> Tuple[bytes, str]:
    """Exposition payload and content type for a ``/metrics`` endpoint."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
