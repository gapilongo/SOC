"""OpenTelemetry tracing. A no-op unless ``observability.otlp_endpoint`` is set."""

from __future__ import annotations

import threading
from typing import Any, Optional

from opentelemetry import trace

from lg_sotf.settings import Settings, get_settings

_lock = threading.Lock()
_provider: Optional[Any] = None


def build_tracer_provider(settings: Settings) -> Any:
    """Create an SDK tracer provider exporting to the configured OTLP/HTTP endpoint."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    from lg_sotf import __version__

    endpoint = settings.observability.otlp_endpoint
    if not endpoint:
        raise ValueError("observability.otlp_endpoint is not set")
    traces_endpoint = endpoint if endpoint.rstrip("/").endswith("/v1/traces") else endpoint.rstrip("/") + "/v1/traces"
    resource = Resource.create(
        {
            "service.name": settings.observability.service_name,
            "service.version": __version__,
            "deployment.environment": settings.environment,
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=traces_endpoint)))
    return provider


def setup_tracing(settings: Optional[Settings] = None, *, set_global: bool = True) -> bool:
    """Install the OTLP exporter once per process. Returns whether tracing is active."""
    global _provider
    s = settings or get_settings()
    if not s.observability.otlp_endpoint:
        return False
    with _lock:
        if _provider is not None:
            return True
        provider = build_tracer_provider(s)
        if set_global:
            trace.set_tracer_provider(provider)
        _provider = provider
    return True


def shutdown_tracing() -> None:
    """Flush and stop the exporter (call during graceful shutdown)."""
    global _provider
    with _lock:
        provider, _provider = _provider, None
    if provider is not None:
        provider.shutdown()


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)
