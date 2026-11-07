"""``observability.otlp_endpoint`` is still accepted after tracing was removed, with a warning (ADR-0008)."""

from __future__ import annotations

import importlib.util
import io
import json
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog

from lg_sotf.observability.logging import clear_context, configure_logging
from lg_sotf.settings import Settings

# Shaped like a collector URL with credentials in it, built at runtime: it must never reach the logs.
ENDPOINT = "https://" + "collector-user" + ":" + "x" * 12 + "@otel.example.com:4318"


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    clear_context()
    structlog.reset_defaults()
    root.handlers[:] = handlers
    root.setLevel(level)
    logging.captureWarnings(False)


def _lines(make_settings: Callable[..., Settings], **obs: Any) -> List[Dict[str, Any]]:
    stream = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "json", "log_level": "INFO", **obs}), stream=stream)
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_a_configured_endpoint_still_loads_and_logs_one_warning(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(observability={"otlp_endpoint": ENDPOINT})
    assert settings.observability.otlp_endpoint == ENDPOINT
    lines = _lines(make_settings, otlp_endpoint=ENDPOINT)
    assert [(line["event"], line["level"]) for line in lines] == [("observability.otlp_endpoint_deprecated", "warning")]
    assert "ADR-0008" in lines[0]["detail"]
    assert "otel.example.com" not in json.dumps(lines)


def test_no_warning_without_an_endpoint(make_settings: Callable[..., Settings]) -> None:
    assert _lines(make_settings) == []
    assert _lines(make_settings, otlp_endpoint="") == []


def test_opentelemetry_is_no_longer_a_dependency_of_the_package() -> None:
    import lg_sotf.observability as observability

    assert not hasattr(observability, "setup_tracing")
    assert importlib.util.find_spec("lg_sotf.observability.tracing") is None
