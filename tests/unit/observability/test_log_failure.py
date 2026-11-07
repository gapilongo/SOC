"""log_failure: failure logs carry the error type, a frames-only stack and the cause types, never the message."""

from __future__ import annotations

import io
import json
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog

from lg_sotf.observability.logging import (
    STACK_FRAMES,
    cause_types,
    clear_context,
    configure_logging,
    get_logger,
    log_failure,
    stack_summary,
)
from lg_sotf.settings import Settings

# Built at runtime so no committed string looks like a credential.
FAKE_JWT = "eyJ" + "x" * 20 + "." + "eyJ" + "y" * 20 + "." + "z" * 24
ALERT_TEXT = "powershell -enc SQBFAFgA host=FIN-WS-0042 user=j.doe@victim.example"
SOURCE_MARKER = "source-line-marker-never-logged"


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


@pytest.fixture(params=["json", "console"])
def stream(request: pytest.FixtureRequest, make_settings: Callable[..., Settings]) -> io.StringIO:
    out = io.StringIO()
    configure_logging(make_settings(observability={"log_format": request.param, "log_level": "DEBUG"}), stream=out)
    return out


def _json(make_settings: Callable[..., Settings]) -> io.StringIO:
    out = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "json", "log_level": "DEBUG"}), stream=out)
    return out


def _records(out: io.StringIO) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def _parse_alert(payload: str) -> None:
    # The marker sits on the raising line: a summary that read source text would carry it.
    raise ValueError(f"cannot parse {payload}: bearer {FAKE_JWT}")  # source-line-marker-never-logged


def _enrich(payload: str) -> None:
    try:
        _parse_alert(payload)
    except ValueError as exc:
        raise RuntimeError(f"enrichment failed for {payload} with {FAKE_JWT}") from exc


def _caught(fn: Callable[[], None]) -> BaseException:
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - the test inspects whatever was raised
        return exc
    raise AssertionError("expected an exception")


def test_message_with_jwt_and_alert_text_never_reaches_the_output(stream: io.StringIO) -> None:
    exc = _caught(lambda: _enrich(ALERT_TEXT))
    log_failure(get_logger("lg_sotf.test"), "worker.message_failed", exc, entry_id="1-0")
    text = stream.getvalue()
    assert "worker.message_failed" in text and "RuntimeError" in text
    for leaked in (FAKE_JWT, "eyJ" + "x" * 20, "powershell", "FIN-WS-0042", "victim.example", "cannot parse"):
        assert leaked not in text
    assert SOURCE_MARKER not in text and "raise ValueError" not in text
    assert "Traceback" not in text


def test_record_fields(make_settings: Callable[..., Settings]) -> None:
    out = _json(make_settings)
    exc = _caught(lambda: _enrich(ALERT_TEXT))
    log_failure(get_logger("lg_sotf.test"), "scheduler.job_failed", exc, job="sweep")
    [record] = _records(out)
    assert record["event"] == "scheduler.job_failed" and record["job"] == "sweep"
    assert record["level"] == "error"
    assert record["error"] == "RuntimeError"
    assert record["cause_types"] == ["ValueError"]
    stack = record["stack"].split("\n")
    assert stack[0] == f"{__name__}:{_caught.__code__.co_firstlineno + 2} in _caught"
    # The raised (outer) exception's own traceback ends where it was raised.
    assert stack[-1] == f"{__name__}:{_enrich.__code__.co_firstlineno + 4} in _enrich"
    assert len(stack) == 3
    assert "exception" not in record and "exc_info" not in record


@pytest.mark.parametrize("level", ["debug", "info", "warning", "error", "critical"])
def test_level(make_settings: Callable[..., Settings], level: Any) -> None:
    out = _json(make_settings)
    log_failure(get_logger("lg_sotf.test"), "health.not_ready", TimeoutError(), level=level, dependency="redis")
    [record] = _records(out)
    assert record["level"] == level and record["dependency"] == "redis"
    assert record["error"] == "TimeoutError" and record["stack"] == "" and record["cause_types"] == []


def test_caller_cannot_put_the_message_back(make_settings: Callable[..., Settings]) -> None:
    out = _json(make_settings)
    exc = _caught(lambda: _parse_alert(ALERT_TEXT))
    log_failure(get_logger("lg_sotf.test"), "x.failed", exc, error=str(exc), stack=str(exc), cause_types=str(exc))
    [record] = _records(out)
    assert record["error"] == "ValueError"
    assert FAKE_JWT not in json.dumps(record) and "FIN-WS-0042" not in json.dumps(record)


def test_stack_keeps_the_innermost_frames() -> None:
    def recurse(n: int) -> None:
        if n == 0:
            raise KeyError("k")
        recurse(n - 1)

    exc = _caught(lambda: recurse(40))
    stack = stack_summary(exc)
    assert len(stack) == STACK_FRAMES
    assert all(frame.endswith("in test_stack_keeps_the_innermost_frames.<locals>.recurse") for frame in stack)
    assert len(stack_summary(exc, limit=3)) == 3


def test_cause_types_follow_the_printed_chain() -> None:
    def implicit() -> None:
        try:
            raise KeyError("a")
        except KeyError:
            raise OSError("b")  # noqa: B904 - implicit context is what this pins

    assert cause_types(_caught(implicit)) == ["KeyError"]

    def suppressed() -> None:
        try:
            raise KeyError("a")
        except KeyError:
            raise OSError("b") from None

    assert cause_types(_caught(suppressed)) == []

    def explicit() -> None:
        try:
            raise KeyError("a")
        except KeyError:
            raise OSError("b") from ValueError("c")

    assert cause_types(_caught(explicit)) == ["ValueError"]


def test_cause_cycle_terminates() -> None:
    a, b = ValueError("a"), KeyError("b")
    a.__cause__, b.__cause__ = b, a
    assert cause_types(a) == ["KeyError"]
    long = ValueError("0")
    current = long
    for i in range(30):
        nxt = ValueError(str(i))
        current.__cause__ = nxt
        current = nxt
    assert len(cause_types(long)) == 8
