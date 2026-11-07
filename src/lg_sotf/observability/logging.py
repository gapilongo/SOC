"""Structured logging.

``configure_logging`` routes both structlog and stdlib ``logging`` records
through one handler that renders JSON (production) or a console format
(development). Request/alert identifiers bound with :func:`bind_context`
travel with every record in the current task. A redaction pass converts every
value to its rendered form (objects and exceptions become strings) and strips
credentials from it; formatted tracebacks are redacted as well. Numeric values
under plural credential names (``refresh_tokens=12`` in a retention report)
are counts, not secrets, and are kept; a singular name (``token``,
``password``) still hides any value.

A caught exception is logged with :func:`log_failure`: the error type, a
frames-only stack and the cause types, never the message (ADR-0005).
"""

from __future__ import annotations

import logging
import re
import sys
import traceback
from collections import deque
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any, Iterator, Literal, Mapping, MutableMapping, Optional, Protocol, TextIO
from uuid import UUID

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from lg_sotf.security.redaction import REDACTED, is_secret_key, redact, redact_text
from lg_sotf.settings import Settings, get_settings

_HANDLER_MARKER = "_lg_sotf_handler"
_NOISY_LOGGERS = ("httpx", "httpx2", "httpcore", "anthropic", "openai", "urllib3", "asyncio", "hpack", "aiokafka")
CONTEXT_KEYS = ("request_id", "tenant_id", "alert_id", "thread_id", "node")
# Consumed by structlog/ProcessorFormatter later in the chain; they must keep their types.
_STRUCTLOG_META = frozenset({"exc_info", "stack_info", "_record", "_from_structlog"})
_STR_TYPES = (datetime, date, time, UUID, Decimal, Enum, PurePath)
# Written by the processor chain; a caller field of the same name is kept as "<key>_".
RESERVED_FIELDS = ("level", "logger", "timestamp", "service", "env")
_MAX_LOG_DEPTH = 32


def _loggable(value: Any, depth: int = 0) -> Any:
    """JSON-shaped copy of ``value`` in which every non-primitive object is already a string.

    Renderers fall back to ``repr()`` for unknown objects, which would bypass
    redaction; converting here means the redaction pass sees the final text.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if depth >= _MAX_LOG_DEPTH:
        return "[truncated: nesting too deep]"
    if isinstance(value, Mapping):
        return {k if isinstance(k, str) else str(k): _loggable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_loggable(v, depth + 1) for v in value]
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {value}"
    if isinstance(value, _STR_TYPES):
        return str(value)
    return repr(value)


_KEY_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# Counts are logged as plain integers; anything with more digits than this could be a numeric secret.
_MAX_COUNT_DIGITS = 12


def _is_count_key(key: str) -> bool:
    """Whether ``key`` names a *number of* credentials (``refresh_tokens``, ``api_keys``) rather than one.

    The redaction rules treat a key that ends in a credential label as a
    secret whatever its value; for a plural label with a numeric value that
    hides operational counts (retention reports, cleanup totals). A singular
    label (``token``, ``pin_code``-style ``password``) still denotes a value.
    """
    if len(key) > 128:
        return False
    parts = [p for p in _KEY_SPLIT.split(_CAMEL_BOUNDARY.sub("_", key).lower()) if p]
    if not parts or not parts[-1].endswith("s") or len(parts[-1]) < 3:
        return False
    singular = "_".join([*parts[:-1], parts[-1][:-1]])
    return is_secret_key(singular) or is_secret_key(parts[-1][:-1])


def _is_count_value(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float):
        return True
    return len(str(abs(value))) <= _MAX_COUNT_DIGITS


def _restore_counts(original: Any, redacted: Any, depth: int = 0) -> Any:
    """Undo masking of numeric values under plural credential keys (``{"refresh_tokens": 3}``)."""
    if depth >= _MAX_LOG_DEPTH:
        return redacted
    if isinstance(original, Mapping) and isinstance(redacted, dict):
        out = dict(redacted)
        for k, v in original.items():
            if k not in out:
                continue
            if isinstance(k, str) and out[k] == REDACTED and _is_count_value(v) and _is_count_key(k):
                out[k] = v
            elif isinstance(v, (Mapping, list)):
                out[k] = _restore_counts(v, out[k], depth + 1)
        return out
    if isinstance(original, list) and isinstance(redacted, list) and len(original) == len(redacted):
        return [_restore_counts(o, r, depth + 1) for o, r in zip(original, redacted, strict=True)]
    return redacted


def _redact_event(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    for key, value in list(event_dict.items()):
        if key in _STRUCTLOG_META:
            continue
        if isinstance(key, str):
            # Through a one-key mapping so secret-labelled keys hide values of any type.
            wrapped = {key: _loggable(value)}
            redacted, _n = redact(wrapped)
            event_dict[key] = _restore_counts(wrapped, redacted)[key]
        else:
            event_dict[key] = redact_text(str(_loggable(value)))[0]
    return event_dict


def _redact_exception(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    exc = event_dict.get("exception")
    if isinstance(exc, str):
        event_dict["exception"] = redact_text(exc)[0]
    return event_dict


def _keep_caller_fields(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    """Rename caller fields that the chain itself writes (``level`` etc.) to ``<key>_``.

    Without this ``log.info("x", level="L3")`` would lose the value to the log
    level (or spoof ``service``/``env``). Runs before those fields are added,
    so anything already present came from the caller or the bound context.
    """
    for key in RESERVED_FIELDS:
        if key in event_dict:
            event_dict[f"{key}_"] = event_dict.pop(key)
    return event_dict


def _static_fields(service: str, environment: str) -> Processor:
    def processor(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("service", service)
        event_dict.setdefault("env", environment)
        return event_dict

    return processor


def _parse_level(level: str) -> int:
    value = logging.getLevelName(level.upper())
    if not isinstance(value, int):
        raise ValueError(f"invalid log level {level!r}")
    return value


def configure_logging(settings: Optional[Settings] = None, *, stream: Optional[TextIO] = None) -> None:
    """Configure structlog and the stdlib root logger. Safe to call repeatedly."""
    s = settings or get_settings()
    obs = s.observability
    level = _parse_level(obs.log_level)
    out = stream or sys.stdout

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        _keep_caller_fields,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
        _static_fields(obs.service_name, s.environment),
        structlog.processors.StackInfoRenderer(),
        # Redact before any handler sees the record, not only in our formatter.
        _redact_event,
    ]

    renderer: Processor
    if obs.log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=bool(getattr(out, "isatty", lambda: False)()))
    final: list[Processor] = [structlog.processors.format_exc_info, _redact_exception, renderer]

    structlog.configure(
        processors=[structlog.stdlib.filter_by_level, *shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *final],
    )
    handler = logging.StreamHandler(out)
    handler.setFormatter(formatter)
    setattr(handler, _HANDLER_MARKER, True)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(max(level, logging.WARNING))
    logging.captureWarnings(True)
    if obs.otlp_endpoint:  # the value is not logged: an endpoint URL can carry credentials
        get_logger(__name__).warning(
            "observability.otlp_endpoint_deprecated",
            detail="tracing was removed (ADR-0008); observability.otlp_endpoint is ignored",
        )


def is_configured() -> bool:
    """Whether structlog still runs this module's processor chain.

    Another ``structlog.configure()`` call (for example a legacy component
    configuring its own renderer) silently drops context binding and
    redaction; startup checks and tests use this to detect that.
    """
    processors = structlog.get_config().get("processors", ())
    return _redact_event in processors and any(
        getattr(h, _HANDLER_MARKER, False) for h in logging.getLogger().handlers
    )


def get_logger(name: Optional[str] = None, **initial: Any) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger.bind(**initial) if initial else logger


STACK_FRAMES = 15
_MAX_CAUSES = 8
FailureLevel = Literal["debug", "info", "warning", "error", "critical"]
# Written by log_failure; a caller field of the same name is ignored so the message can never ride along.
FAILURE_FIELDS = ("error", "stack", "cause_types")


class _FailureLogger(Protocol):
    def debug(self, event: str, **kw: Any) -> Any: ...
    def info(self, event: str, **kw: Any) -> Any: ...
    def warning(self, event: str, **kw: Any) -> Any: ...
    def error(self, event: str, **kw: Any) -> Any: ...
    def critical(self, event: str, **kw: Any) -> Any: ...


def stack_summary(exc: BaseException, limit: int = STACK_FRAMES) -> list[str]:
    """The innermost ``limit`` frames of ``exc``'s traceback as ``module:lineno in func``.

    Built from code objects only: no source line is read, so nothing the
    failing line quoted (a literal, a formatted message) reaches the log.
    """
    frames: deque[str] = deque(maxlen=limit)
    for frame, lineno in traceback.walk_tb(exc.__traceback__):
        code = frame.f_code
        module = frame.f_globals.get("__name__", "?")
        frames.append(f"{module}:{lineno} in {getattr(code, 'co_qualname', code.co_name)}")
    return list(frames)


def cause_types(exc: BaseException) -> list[str]:
    """Type names along the chain Python prints: ``__cause__``, else ``__context__`` unless suppressed."""
    out: list[str] = []
    seen = {id(exc)}
    current: Optional[BaseException] = exc
    while current is not None and len(out) < _MAX_CAUSES:
        nxt = current.__cause__ if current.__cause__ is not None else (
            None if current.__suppress_context__ else current.__context__
        )
        if nxt is None or id(nxt) in seen:
            break
        seen.add(id(nxt))
        out.append(type(nxt).__name__)
        current = nxt
    return out


def failure_fields(exc: BaseException) -> dict[str, Any]:
    """The fields :func:`log_failure` adds: the error type, a frames-only stack and the cause types.

    ``stack`` is one string, outermost frame first, one frame per line: the
    console renderer prints a ``stack`` field as a block and requires text.
    """
    return {"error": type(exc).__name__, "stack": "\n".join(stack_summary(exc)), "cause_types": cause_types(exc)}


def log_failure(
    logger: _FailureLogger, event: str, exc: BaseException, *, level: FailureLevel = "error", **fields: Any
) -> None:
    """Log a caught failure without its message (ADR-0005).

    Exception messages can quote JWTs, API keys and alert text, so the record
    carries ``error`` (the type name), ``stack`` (:func:`stack_summary`) and
    ``cause_types``, never ``str(exc)`` or a formatted traceback. Pass the
    event's other fields as keywords; ``error``, ``stack`` and
    ``cause_types`` are always the ones computed here.
    """
    getattr(logger, level)(event, **{**fields, **failure_fields(exc)})


def bind_context(**values: Any) -> None:
    """Bind identifiers (request_id, tenant_id, alert_id, thread_id, node) to the current context."""
    structlog.contextvars.bind_contextvars(**{k: v for k, v in values.items() if v is not None})


def unbind_context(*keys: str) -> None:
    structlog.contextvars.unbind_contextvars(*keys)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()


def current_context() -> MutableMapping[str, Any]:
    return structlog.contextvars.get_contextvars()


@contextmanager
def bound_context(**values: Any) -> Iterator[None]:
    """Bind values for the duration of a block, restoring previous values afterwards."""
    tokens = structlog.contextvars.bind_contextvars(**{k: v for k, v in values.items() if v is not None})
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)
