"""Structured logging: JSON output, context binding, redaction, stdlib bridging."""

from __future__ import annotations

import io
import json
import logging
from typing import Any, Callable, Dict, Iterator, List

import pytest
import structlog

from lg_sotf.observability.logging import (
    bind_context,
    bound_context,
    clear_context,
    configure_logging,
    current_context,
    get_logger,
    is_configured,
    unbind_context,
)
from lg_sotf.settings import Settings


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


def _configure(make_settings: Callable[..., Settings], **obs: Any) -> io.StringIO:
    stream = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "json", "log_level": "INFO", **obs}), stream=stream)
    return stream


def _lines(stream: io.StringIO) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_json_output_with_context(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings, service_name="lg-sotf-test")
    bind_context(request_id="req-1", tenant_id="t1", alert_id=None)
    get_logger("lg_sotf.test").info("alert.triaged", node="triage", score=42)
    [record] = _lines(stream)
    assert record["event"] == "alert.triaged"
    assert record["request_id"] == "req-1" and record["tenant_id"] == "t1"
    assert "alert_id" not in record
    assert record["node"] == "triage" and record["score"] == 42
    assert record["level"] == "info"
    assert record["logger"] == "lg_sotf.test"
    assert record["service"] == "lg-sotf-test" and record["env"] == "test"
    assert record["timestamp"].endswith("Z")


def test_caller_fields_never_overwrite_or_spoof_record_fields(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings, service_name="lg-sotf-test")
    get_logger("lg_sotf.test").warning(
        "escalation.sla_breach_handled", level="L3", logger="spoofed", timestamp="then", service="evil", env="prod"
    )
    [record] = _lines(stream)
    assert record["level"] == "warning" and record["level_"] == "L3"
    assert record["logger"] == "lg_sotf.test" and record["logger_"] == "spoofed"
    assert record["timestamp"].endswith("Z") and record["timestamp_"] == "then"
    assert (record["service"], record["env"]) == ("lg-sotf-test", "test")
    assert (record["service_"], record["env_"]) == ("evil", "prod")


def test_stdlib_records_are_bridged(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings)
    bind_context(thread_id="t1:a1")
    logging.getLogger("third.party").warning("disk %s at %d%%", "/var", 91)
    [record] = _lines(stream)
    assert record["event"] == "disk /var at 91%"
    assert record["level"] == "warning" and record["logger"] == "third.party"
    assert record["thread_id"] == "t1:a1"


def test_level_filtering(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings, log_level="WARNING")
    log = get_logger("x")
    log.info("hidden")
    logging.getLogger("y").info("hidden too")
    log.warning("shown")
    assert [r["event"] for r in _lines(stream)] == ["shown"]


def test_secrets_are_redacted(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings)
    log = get_logger("x")
    log.info("connecting to postgresql://soc:hunter2@db:5432/soc", header="Authorization: Bearer abcdefghijklmnop123")
    try:
        raise ValueError("bad password=s3cr3t-value")
    except ValueError:
        log.exception("failed")
    logging.getLogger("z").error("token=abcdef123456")
    output = stream.getvalue()
    for secret in ("hunter2", "abcdefghijklmnop123", "s3cr3t-value", "abcdef123456"):
        assert secret not in output
    records = _lines(stream)
    assert "ValueError" in records[1]["exception"]


def test_context_helpers(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings)
    log = get_logger("x", component="worker")
    bind_context(request_id="r1", node="gate")
    unbind_context("node")
    with bound_context(alert_id="a1", request_id="r2"):
        assert current_context()["request_id"] == "r2"
        log.info("inside")
    assert current_context() == {"request_id": "r1"}
    clear_context()
    log.info("after")
    inside, after = _lines(stream)
    assert inside["alert_id"] == "a1" and inside["request_id"] == "r2" and inside["component"] == "worker"
    assert "request_id" not in after and "alert_id" not in after


def test_console_format(make_settings: Callable[..., Settings]) -> None:
    stream = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "console"}), stream=stream)
    get_logger("x").info("hello", tenant_id="t1", password="hunter2")
    output = stream.getvalue()
    assert "hello" in output and "t1" in output
    assert "hunter2" not in output


def test_reconfigure_does_not_duplicate_handlers(make_settings: Callable[..., Settings]) -> None:
    _configure(make_settings)
    stream = _configure(make_settings)
    marked = [h for h in logging.getLogger().handlers if getattr(h, "_lg_sotf_handler", False)]
    assert len(marked) == 1
    get_logger("x").info("once")
    assert len(_lines(stream)) == 1


def test_noisy_loggers_quietened(make_settings: Callable[..., Settings]) -> None:
    _configure(make_settings, log_level="DEBUG")
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger().level == logging.DEBUG


def test_invalid_level(make_settings: Callable[..., Settings]) -> None:
    with pytest.raises(ValueError):
        configure_logging(make_settings(observability={"log_level": "LOUD"}), stream=io.StringIO())


class _Leaky:
    def __repr__(self) -> str:
        return "Leaky(password='hunter2', api_key='sk-ant-api03-abcdefghijklmnop')"


@pytest.mark.parametrize("log_format", ["json", "console"])
def test_objects_and_exceptions_are_redacted(make_settings: Callable[..., Settings], log_format: str) -> None:
    stream = io.StringIO()
    configure_logging(make_settings(observability={"log_format": log_format}), stream=stream)
    get_logger("x").warning(
        "objects",
        obj=_Leaky(),
        error=ValueError("password=hunter2"),
        nested={"errors": [KeyError("token=abcdef123456")], "item": _Leaky()},
        credentials={"user": "bob", "secret_value": "hunter2"},
    )
    output = stream.getvalue()
    for secret in ("hunter2", "sk-ant-api03-abcdefghijklmnop", "abcdef123456"):
        assert secret not in output
    if log_format == "json":
        [record] = _lines(stream)
        assert record["obj"] == "Leaky(password='[REDACTED]', api_key='[REDACTED:api_key]')"
        assert record["error"] == "ValueError: password=[REDACTED]"
        assert record["nested"]["errors"] == ["KeyError: 'token=[REDACTED]'"]
        assert record["credentials"] == "[REDACTED]"


def test_simple_types_render_as_strings_and_numbers_stay_numbers(make_settings: Callable[..., Settings]) -> None:
    import uuid
    from datetime import UTC, datetime

    stream = _configure(make_settings)
    uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    get_logger("x").info("typed", id=uid, at=datetime(2024, 1, 1, tzinfo=UTC), input_tokens=900, ratio=0.5, ok=True, none=None)
    [record] = _lines(stream)
    assert record["id"] == str(uid)
    assert record["at"] == "2024-01-01 00:00:00+00:00"
    assert (record["input_tokens"], record["ratio"], record["ok"], record["none"]) == (900, 0.5, True, None)


def test_exc_info_objects_still_render_tracebacks(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings)
    try:
        raise RuntimeError("password=hunter2")
    except RuntimeError as exc:
        get_logger("x").error("failed", exc_info=exc)
    [record] = _lines(stream)
    assert "Traceback" in record["exception"] and "RuntimeError" in record["exception"]
    assert "hunter2" not in record["exception"]


def test_is_configured_detects_foreign_reconfiguration(make_settings: Callable[..., Settings]) -> None:
    structlog.reset_defaults()
    assert not is_configured()
    _configure(make_settings)
    assert is_configured()
    structlog.configure(processors=[structlog.processors.JSONRenderer()])
    assert not is_configured()


def test_numeric_counts_under_plural_credential_names_are_kept(make_settings: Callable[..., Settings]) -> None:
    """A retention report logs how many refresh tokens it deleted: a count, not a credential."""
    stream = _configure(make_settings)
    report = {"alerts": 4, "refresh_tokens": 12, "api_keys": 3, "complete": True, "dropped_partitions": []}
    get_logger("x").info(
        "retention.completed",
        report=report,
        refresh_tokens=7,
        revokedApiKeys=2,
        secrets=1.5,
        tokens_by_kind=[{"refresh_tokens": 5}],
    )
    [record] = _lines(stream)
    assert record["report"] == report
    assert (record["refresh_tokens"], record["revokedApiKeys"], record["secrets"]) == (7, 2, 1.5)
    assert record["tokens_by_kind"] == [{"refresh_tokens": 5}]


def test_values_that_denote_a_credential_are_still_masked(make_settings: Callable[..., Settings]) -> None:
    stream = _configure(make_settings)
    get_logger("x").info(
        "login",
        password=123456,
        token=987654321,
        refresh_tokens="rt_live_4f9a8b7c6d5e4f3a2b1c",
        api_keys=["lgk-a", "lgk-b"],
        huge_count_like={"refresh_tokens": 4111111111111111},
        nested={"session_token": 42, "passwords": True},
    )
    [record] = _lines(stream)
    assert record["password"] == "[REDACTED]" and record["token"] == "[REDACTED]"
    assert record["refresh_tokens"] == "[REDACTED]"
    assert record["api_keys"] == "[REDACTED]"
    assert record["huge_count_like"] == {"refresh_tokens": "[REDACTED]"}
    assert record["nested"]["session_token"] == "[REDACTED]"
    assert "4111111111111111" not in stream.getvalue() and "rt_live_4f9a8b7c6d5e4f3a2b1c" not in stream.getvalue()
