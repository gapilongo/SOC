"""Prometheus metrics defined by the architecture contract."""

from __future__ import annotations

import pytest

from lg_sotf.observability import metrics
from lg_sotf.observability.metrics import REGISTRY

CONTRACT_METRICS = {
    "lgsotf_http_requests_total": ("route", "method", "status"),
    "lgsotf_http_request_seconds": ("route", "method"),
    "lgsotf_queue_depth": ("stream",),
    "lgsotf_queue_pending": ("stream",),
    "lgsotf_runs_total": ("outcome",),
    "lgsotf_node_seconds": ("node",),
    "lgsotf_llm_calls_total": ("model", "agent", "outcome"),
    "lgsotf_llm_tokens_total": ("model", "kind"),
    "lgsotf_llm_cost_usd_total": ("model",),
    "lgsotf_escalations_open": (),
    "lgsotf_actions_total": ("action_type", "status"),
}
FORBIDDEN_LABELS = {"tenant_id", "alert_id", "user_id", "request_id", "thread_id"}


def _value(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_registry_has_exactly_the_contract_metrics() -> None:
    families = {}
    for family in REGISTRY.collect():
        name = family.name + ("_total" if family.type == "counter" else "")
        families[name] = family
    assert set(families) == set(CONTRACT_METRICS)
    for name, collector in (
        ("lgsotf_http_requests_total", metrics.HTTP_REQUESTS),
        ("lgsotf_llm_calls_total", metrics.LLM_CALLS),
        ("lgsotf_node_seconds", metrics.NODE_SECONDS),
        ("lgsotf_escalations_open", metrics.ESCALATIONS_OPEN),
    ):
        assert tuple(collector._labelnames) == CONTRACT_METRICS[name]
    for labels in CONTRACT_METRICS.values():
        assert not FORBIDDEN_LABELS & set(labels)


def test_helpers_update_values() -> None:
    before = _value("lgsotf_http_requests_total", route="/api/v1/alerts/{id}", method="GET", status="200")
    metrics.observe_http_request("/api/v1/alerts/{id}", "get", 200, 0.02)
    assert _value("lgsotf_http_requests_total", route="/api/v1/alerts/{id}", method="GET", status="200") == before + 1
    assert _value("lgsotf_http_request_seconds_count", route="/api/v1/alerts/{id}", method="GET") >= 1

    metrics.set_queue_depth("high", 7)
    metrics.set_queue_pending("high", 2)
    assert _value("lgsotf_queue_depth", stream="high") == 7
    assert _value("lgsotf_queue_pending", stream="high") == 2

    runs = _value("lgsotf_runs_total", outcome="completed")
    metrics.record_run("completed")
    assert _value("lgsotf_runs_total", outcome="completed") == runs + 1

    metrics.set_escalations_open(3)
    assert _value("lgsotf_escalations_open") == 3

    actions = _value("lgsotf_actions_total", action_type="block_ip", status="dry_run")
    metrics.record_action("block_ip", "dry_run")
    assert _value("lgsotf_actions_total", action_type="block_ip", status="dry_run") == actions + 1


def test_time_node_records_on_failure() -> None:
    before = _value("lgsotf_node_seconds_count", node="triage")
    with pytest.raises(RuntimeError):
        with metrics.time_node("triage"):
            raise RuntimeError("x")
    with metrics.time_node("triage"):
        pass
    assert _value("lgsotf_node_seconds_count", node="triage") == before + 2


def test_llm_helpers() -> None:
    with pytest.raises(ValueError):
        metrics.record_llm_tokens("m", "bogus", 1)
    before = _value("lgsotf_llm_tokens_total", model="m", kind="output")
    metrics.record_llm_tokens("m", "output", 0)
    metrics.record_llm_tokens("m", "output", 5)
    assert _value("lgsotf_llm_tokens_total", model="m", kind="output") == before + 5
    cost = _value("lgsotf_llm_cost_usd_total", model="m")
    metrics.record_llm_cost("m", 0.5)
    metrics.record_llm_cost("m", 0.0)
    assert _value("lgsotf_llm_cost_usd_total", model="m") == pytest.approx(cost + 0.5)


def test_render_latest() -> None:
    payload, content_type = metrics.render_latest()
    assert content_type.startswith("text/plain")
    text = payload.decode()
    for name in CONTRACT_METRICS:
        assert name in text or name.removesuffix("_total") in text
