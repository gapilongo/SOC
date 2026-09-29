"""Structured logging.

``configure_logging`` routes both structlog and stdlib ``logging`` records
through one handler that renders JSON (production) or a console format
(development). Request/alert identifiers bound with :func:`bind_context`
travel with every record in the current task. A redaction pass converts every
value to its rendered form (objects and exceptions become strings) and strips
credentials from it; formatted tracebacks are redacted as well.
"""

from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any, Iterator, Mapping, MutableMapping, Optional, TextIO
from uuid import UUID

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from lg_sotf.security.redaction import redact, redact_text
from lg_sotf.settings import Settings, get_settings

_HANDLER_MARKER = "_lg_sotf_handler"
_NOISY_LOGGERS = ("httpx", "httpx2", "httpcore", "anthropic", "openai", "urllib3", "asyncio", "hpack", "aiokafka")
CONTEXT_KEYS = ("request_id", "tenant_id", "alert_id", "thread_id", "node")
# Consumed by structlog/ProcessorFormatter later in the chain; they must keep their types.
_STRUCTLOG_META = frozenset({"exc_info", "stack_info", "_record", "_from_structlog"})
_STR_TYPES = (datetime, date, time, UUID, Decimal, Enum, PurePath)
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


def _redact_event(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    for key, value in list(event_dict.items()):
        if key in _STRUCTLOG_META:
            continue
        if isinstance(key, str):
            # Through a one-key mapping so secret-labelled keys hide values of any type.
            redacted, _n = redact({key: _loggable(value)})
            event_dict[key] = redacted[key]
        else:
            event_dict[key] = redact_text(str(_loggable(value)))[0]
    return event_dict


def _redact_exception(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    exc = event_dict.get("exception")
    if isinstance(exc, str):
        event_dict["exception"] = redact_text(exc)[0]
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
