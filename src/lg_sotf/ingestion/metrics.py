"""Ingestion metrics. Labels are source types and outcomes only.

They live on their own registry because ``lg_sotf.observability.metrics.REGISTRY``
holds exactly the contract section 13 set; the metrics endpoint must also
render :data:`REGISTRY` here to export them (until the contract lists them).
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

INGEST_EVENTS = Counter(
    "lgsotf_ingest_events_total",
    "Events received for ingestion, by source type and outcome (inserted/duplicate/rejected).",
    ["source_type", "outcome"],
    registry=REGISTRY,
)
SOURCE_POLLS = Counter(
    "lgsotf_source_polls_total",
    "Pull-source polls, by source type and outcome (ok/error).",
    ["source_type", "outcome"],
    registry=REGISTRY,
)
SOURCE_POLL_SECONDS = Histogram(
    "lgsotf_source_poll_seconds",
    "Duration of a pull-source poll in seconds, by source type.",
    ["source_type"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0),
    registry=REGISTRY,
)
SOURCE_HTTP_RETRIES = Counter(
    "lgsotf_source_http_retries_total",
    "HTTP retries by pull connectors, by source type and reason (rate_limited/server_error/network/auth_refresh).",
    ["source_type", "reason"],
    registry=REGISTRY,
)
LLM_NORMALIZATIONS = Counter(
    "lgsotf_ingest_llm_normalizations_total",
    "LLM normalization fallback attempts, by outcome (success/error/timeout).",
    ["outcome"],
    registry=REGISTRY,
)


def record_events(source_type: str, outcome: str, count: int) -> None:
    if count > 0:
        INGEST_EVENTS.labels(source_type=source_type, outcome=outcome).inc(count)


def record_poll(source_type: str, ok: bool, seconds: float) -> None:
    SOURCE_POLLS.labels(source_type=source_type, outcome="ok" if ok else "error").inc()
    SOURCE_POLL_SECONDS.labels(source_type=source_type).observe(seconds)


def record_http_retry(source_type: str, reason: str) -> None:
    SOURCE_HTTP_RETRIES.labels(source_type=source_type, reason=reason).inc()


def record_llm_normalization(outcome: str) -> None:
    LLM_NORMALIZATIONS.labels(outcome=outcome).inc()
