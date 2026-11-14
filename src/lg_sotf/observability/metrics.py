"""Prometheus metrics (architecture section 13).

All metrics live on a module registry so importing this module twice, or
running tests in the same process, never collides with the global default
registry. Labels are low-cardinality only: never tenant, alert or user ids.

The pipeline's series (nodes, LLM calls, tokens, cost, refusals, skipped
calls, enrichment lookups, LLM slot waits) carry ``mode`` (``live`` or ``shadow``,
:mod:`lg_sotf.run_mode`): a shadow run never moves a production series, and
dashboards and alerts select ``mode="live"``.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Tuple

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from lg_sotf.run_mode import run_mode

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
    ["node", "mode"],
    buckets=_NODE_BUCKETS,
    registry=REGISTRY,
)
LLM_SLOT_WAIT_SECONDS = Histogram(
    "lgsotf_llm_slot_wait_seconds",
    "Time a model call waited for a per-process concurrency slot (llm.<tier>.max_concurrency).",
    ["tier", "mode"],
    buckets=_NODE_BUCKETS,
    registry=REGISTRY,
)
LLM_CALLS = Counter(
    "lgsotf_llm_calls_total",
    "LLM calls, by model, calling agent and outcome.",
    ["model", "agent", "outcome", "mode"],
    registry=REGISTRY,
)
LLM_TOKENS = Counter(
    "lgsotf_llm_tokens_total",
    "LLM tokens, by model and kind (input, output, cache_read, cache_write).",
    ["model", "kind", "mode"],
    registry=REGISTRY,
)
LLM_COST_USD = Counter(
    "lgsotf_llm_cost_usd_total",
    "Estimated LLM spend in US dollars, by model.",
    ["model", "mode"],
    registry=REGISTRY,
)
LLM_REFUSALS = Counter(
    "lgsotf_llm_refusals_total",
    "LLM calls the model declined, by calling agent and refusal category.",
    ["agent", "category", "mode"],
    registry=REGISTRY,
)
LLM_SKIPPED = Counter(
    "lgsotf_llm_skipped_total",
    "LLM calls an agent did not make, by agent and reason (rules decisive, budget, disabled, ...).",
    ["agent", "reason", "mode"],
    registry=REGISTRY,
)
# A confirmed threat could not revoke the benign learning (verdict cache, suppression rules) for an alert.
REVOCATION_FAILURES = Counter(
    "lgsotf_revocation_failures_total",
    "Confirmed threats whose cached benign verdicts and matching suppression rules could not be revoked, by path.",
    ["path"],
    registry=REGISTRY,
)
RETRO_REOPEN_FAILURES = Counter(
    "lgsotf_retro_reopen_failures_total",
    "Threats whose related model-closed alerts could not all be linked or reopened (decision policy v3 safety net), "
    "by path.",
    ["path"],
    registry=REGISTRY,
)
RETRO_REOPENED = Counter(
    "lgsotf_retro_reopened_total",
    "Model-closed alerts reopened because a person confirmed a related threat, by path.",
    ["path"],
    registry=REGISTRY,
)
RETRO_LINKED = Counter(
    "lgsotf_retro_linked_total",
    "Model-closed alerts linked to a related threat that only a model judged (they stay closed), by path.",
    ["path"],
    registry=REGISTRY,
)
ENRICHMENT_LOOKUPS = Counter(
    "lgsotf_enrichment_lookups_total",
    "Indicator enrichment lookups, by provider and result status (cache hits are status 'cached').",
    ["provider", "status", "mode"],
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
DB_STALE_STATEMENT_RETRIES = Counter(
    "lgsotf_db_stale_statement_retries_total",
    "Transactions run again because a migration made a cached prepared statement stale (rolling upgrade).",
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
    NODE_SECONDS.labels(node=node, mode=run_mode()).observe(seconds)


@contextmanager
def time_node(node: str) -> Iterator[None]:
    """Observe node duration whether the body succeeds or raises."""
    start = time.perf_counter()
    try:
        yield
    finally:
        observe_node(node, time.perf_counter() - start)


def record_llm_slot_wait(tier: str, seconds: float) -> None:
    LLM_SLOT_WAIT_SECONDS.labels(tier=tier, mode=run_mode()).observe(max(0.0, seconds))


def record_llm_call(model: str, agent: str, outcome: str) -> None:
    LLM_CALLS.labels(model=model, agent=agent, outcome=outcome, mode=run_mode()).inc()


def record_llm_tokens(model: str, kind: str, tokens: int) -> None:
    if kind not in LLM_TOKEN_KINDS:
        raise ValueError(f"unknown token kind {kind!r}")
    if tokens > 0:
        LLM_TOKENS.labels(model=model, kind=kind, mode=run_mode()).inc(tokens)


def record_llm_cost(model: str, usd: float) -> None:
    if usd > 0:
        LLM_COST_USD.labels(model=model, mode=run_mode()).inc(usd)


# Refusal categories are an open set on the provider side; unknown values collapse to "other"
# so a new category can never create unbounded label cardinality.
REFUSAL_CATEGORIES = frozenset(
    {"cyber", "bio", "chem", "frontier_llm", "reasoning_extraction", "general_harms", "safety", "content_filter",
     "prohibited_content", "blocklist", "spii", "unknown"}
)
LLM_SKIP_REASONS = frozenset(
    {"rules_decisive", "no_related_alerts", "budget_exceeded", "disabled", "no_candidates", "refusal", "error"}
)
ENRICHMENT_STATUSES = frozenset(
    {"ok", "not_found", "not_configured", "unsupported", "rate_limited", "error", "cached", "skipped"}
)


def refusal_category_label(category: object) -> str:
    if category is None:
        return "unknown"
    text = str(category).strip().lower()[:32]
    return text if text in REFUSAL_CATEGORIES else "other"


def record_llm_refusal(agent: str, category: object) -> None:
    LLM_REFUSALS.labels(agent=agent, category=refusal_category_label(category), mode=run_mode()).inc()


def record_llm_skipped(agent: str, reason: str) -> None:
    LLM_SKIPPED.labels(agent=agent, reason=reason if reason in LLM_SKIP_REASONS else "other", mode=run_mode()).inc()


def record_enrichment_lookup(provider: str, status: str) -> None:
    status = status if status in ENRICHMENT_STATUSES else "other"
    ENRICHMENT_LOOKUPS.labels(provider=provider, status=status, mode=run_mode()).inc()


def set_escalations_open(count: int) -> None:
    ESCALATIONS_OPEN.set(count)


def record_action(action_type: str, status: str) -> None:
    ACTIONS.labels(action_type=action_type, status=status).inc()


def record_stale_statement_retry() -> None:
    DB_STALE_STATEMENT_RETRIES.inc()


def render_latest() -> Tuple[bytes, str]:
    """Exposition payload and content type for a ``/metrics`` endpoint."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
