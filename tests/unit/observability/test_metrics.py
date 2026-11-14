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
    "lgsotf_node_seconds": ("node", "mode"),
    "lgsotf_llm_calls_total": ("model", "agent", "outcome", "mode"),
    "lgsotf_llm_slot_wait_seconds": ("tier", "mode"),
    "lgsotf_llm_tokens_total": ("model", "kind", "mode"),
    "lgsotf_llm_cost_usd_total": ("model", "mode"),
    "lgsotf_escalations_open": (),
    "lgsotf_actions_total": ("action_type", "status"),
    "lgsotf_db_stale_statement_retries_total": (),
    # LLM agent quality/cost (architecture section 13 addendum).
    "lgsotf_llm_refusals_total": ("agent", "category", "mode"),
    "lgsotf_llm_skipped_total": ("agent", "reason", "mode"),
    "lgsotf_enrichment_lookups_total": ("provider", "status", "mode"),
    "lgsotf_revocation_failures_total": ("path",),
    "lgsotf_retro_reopen_failures_total": ("path",),
    "lgsotf_retro_reopened_total": ("path",),
    "lgsotf_retro_linked_total": ("path",),
    # Integrations outbox and ticket sync (docs/integrations.md).
    "lgsotf_integration_deliveries_total": ("kind", "outcome"),
    "lgsotf_ticket_syncs_total": ("system", "outcome"),
}
FORBIDDEN_LABELS = {"tenant_id", "alert_id", "user_id", "request_id", "thread_id"}


MODED = ("lgsotf_node_seconds", "lgsotf_llm_calls_total", "lgsotf_llm_tokens_total", "lgsotf_llm_cost_usd_total", "lgsotf_llm_refusals_total", "lgsotf_llm_skipped_total", "lgsotf_enrichment_lookups_total")


def _value(name: str, **labels: str) -> float:
    """A sample; the pipeline series are read in ``mode="live"`` unless the test names another mode."""
    if name.startswith(MODED):
        labels.setdefault("mode", "live")
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

    retries = _value("lgsotf_db_stale_statement_retries_total")
    metrics.record_stale_statement_retry()
    assert _value("lgsotf_db_stale_statement_retries_total") == retries + 1


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


def test_quality_and_cost_counters_keep_labels_bounded() -> None:
    assert tuple(metrics.LLM_REFUSALS._labelnames) == CONTRACT_METRICS["lgsotf_llm_refusals_total"]
    cyber = _value("lgsotf_llm_refusals_total", agent="analysis", category="cyber")
    other = _value("lgsotf_llm_refusals_total", agent="analysis", category="other")
    unknown = _value("lgsotf_llm_refusals_total", agent="analysis", category="unknown")
    metrics.record_llm_refusal("analysis", "CYBER")
    metrics.record_llm_refusal("analysis", "a-brand-new-category-" + "x" * 200)
    metrics.record_llm_refusal("analysis", None)
    assert _value("lgsotf_llm_refusals_total", agent="analysis", category="cyber") == cyber + 1
    assert _value("lgsotf_llm_refusals_total", agent="analysis", category="other") == other + 1
    assert _value("lgsotf_llm_refusals_total", agent="analysis", category="unknown") == unknown + 1

    skipped = _value("lgsotf_llm_skipped_total", agent="triage", reason="rules_decisive")
    metrics.record_llm_skipped("triage", "rules_decisive")
    metrics.record_llm_skipped("triage", "free-text reason")
    assert _value("lgsotf_llm_skipped_total", agent="triage", reason="rules_decisive") == skipped + 1
    assert _value("lgsotf_llm_skipped_total", agent="triage", reason="other") >= 1

    lookups = _value("lgsotf_enrichment_lookups_total", provider="virustotal", status="ok")
    metrics.record_enrichment_lookup("virustotal", "ok")
    metrics.record_enrichment_lookup("virustotal", "weird")
    assert _value("lgsotf_enrichment_lookups_total", provider="virustotal", status="ok") == lookups + 1
    assert _value("lgsotf_enrichment_lookups_total", provider="virustotal", status="other") >= 1


def test_render_latest() -> None:
    payload, content_type = metrics.render_latest()
    assert content_type.startswith("text/plain")
    text = payload.decode()
    for name in CONTRACT_METRICS:
        assert name in text or name.removesuffix("_total") in text
