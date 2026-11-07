"""api.unhandled_error logs the error type and a frames-only stack, never the message or a traceback (ADR-0005)."""

from __future__ import annotations

import io
import json
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient

from lg_sotf.api import errors as api_errors
from lg_sotf.api import middleware as api_middleware
from lg_sotf.api.errors import install_error_handlers
from lg_sotf.api.middleware import RequestContextMiddleware
from lg_sotf.observability.logging import clear_context, configure_logging, get_logger
from lg_sotf.settings import Settings

# Built at runtime so no committed string looks like a credential.
FAKE_JWT = "eyJ" + "x" * 20 + "." + "eyJ" + "y" * 20 + "." + "z" * 24
ALERT_TEXT = "powershell -enc SQBFAFgA host=FIN-WS-0042 user=j.doe@victim.example"
LEAKS = (FAKE_JWT, "eyJ" + "x" * 20, "FIN-WS-0042", "victim.example", "powershell", "Traceback")


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


@pytest.fixture
def stream(make_settings: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    out = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "json", "log_level": "INFO"}), stream=out)
    # structlog caches a module logger on first use (cache_logger_on_first_use): if an earlier test in
    # this process used these loggers under another configuration, they would not write to `out`.
    monkeypatch.setattr(api_errors, "log", get_logger(api_errors.__name__))
    monkeypatch.setattr(api_middleware, "log", get_logger("lg_sotf.api.access"))
    return out


def _unhandled(out: io.StringIO) -> List[Dict[str, Any]]:
    records = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    return [r for r in records if r.get("event") == "api.unhandled_error"]


def _fail() -> None:
    raise RuntimeError(f"enrichment of {ALERT_TEXT} failed: bearer {FAKE_JWT}")


def test_the_exception_handler_logs_no_message_or_traceback(stream: io.StringIO) -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        _fail()

    response = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert response.status_code == 500
    [record] = _unhandled(stream)
    assert record["error_type"] == "RuntimeError" and record["error"] == "RuntimeError"
    assert record["stack"].endswith(" in _fail") and "exception" not in record
    for leaked in LEAKS:
        assert leaked not in stream.getvalue()


async def test_the_middleware_logs_no_message_or_traceback(stream: io.StringIO) -> None:
    async def app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
        _fail()

    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [], "scheme": "https"}
    await RequestContextMiddleware(app)(scope, receive, send)
    assert sent[0]["status"] == 500
    [record] = _unhandled(stream)
    assert record["error_type"] == "RuntimeError" and record["error"] == "RuntimeError"
    assert record["stack"].endswith(" in _fail") and "exception" not in record
    for leaked in LEAKS:
        assert leaked not in stream.getvalue()
