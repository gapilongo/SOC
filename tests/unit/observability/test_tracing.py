"""OpenTelemetry setup is a no-op unless an OTLP endpoint is configured."""

from __future__ import annotations

from typing import Callable, Iterator

import pytest
from opentelemetry import trace

from lg_sotf.observability import tracing
from lg_sotf.settings import Settings


@pytest.fixture(autouse=True)
def reset_tracing() -> Iterator[None]:
    tracing.shutdown_tracing()
    yield
    tracing.shutdown_tracing()


def test_noop_without_endpoint(make_settings: Callable[..., Settings]) -> None:
    provider_before = trace.get_tracer_provider()
    assert tracing.setup_tracing(make_settings()) is False
    assert trace.get_tracer_provider() is provider_before
    tracing.get_tracer("x").start_span("noop").end()


def test_provider_built_for_endpoint(make_settings: Callable[..., Settings]) -> None:
    from opentelemetry.sdk.trace import TracerProvider

    s = make_settings(observability={"otlp_endpoint": "http://127.0.0.1:4318", "service_name": "lg-sotf-api"})
    provider = tracing.build_tracer_provider(s)
    try:
        assert isinstance(provider, TracerProvider)
        attrs = provider.resource.attributes
        assert attrs["service.name"] == "lg-sotf-api"
        assert attrs["deployment.environment"] == "test"
        [processor] = provider._active_span_processor._span_processors
        assert processor.span_exporter._endpoint == "http://127.0.0.1:4318/v1/traces"
    finally:
        provider.shutdown()


def test_setup_is_idempotent(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(observability={"otlp_endpoint": "http://127.0.0.1:4318/v1/traces"})
    assert tracing.setup_tracing(s, set_global=False) is True
    first = tracing._provider
    assert tracing.setup_tracing(s, set_global=False) is True
    assert tracing._provider is first
    tracing.shutdown_tracing()
    assert tracing._provider is None


def test_build_requires_endpoint(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValueError):
        tracing.build_tracer_provider(make_settings())
