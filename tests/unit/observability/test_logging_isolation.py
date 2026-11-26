"""Logging configured by one test never reaches the next (issue #382).

The fixtures ``_no_cached_loggers`` and ``_isolate_logging`` in tests/conftest.py see to it.

The first test below does what the CLI entry points do when a test calls them in-process: it configures
logging and logs through a module-level logger, and cleans nothing up. The tests after it run in the same
process (one file is one xdist worker's) and must see the state they would see alone.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Callable

import structlog
from structlog.testing import capture_logs

from lg_sotf.observability.logging import configure_logging, get_logger, is_configured
from lg_sotf.settings import Settings

# A module-level logger, as every product module holds one.
LOG = get_logger("lg_sotf.tests.logging_isolation")


def _app_handlers() -> list[logging.Handler]:
    root = logging.getLogger()
    return [h for h in root.handlers if isinstance(h.formatter, structlog.stdlib.ProcessorFormatter)]


def test_a_test_configures_logging_and_leaves_it_configured(make_settings: Callable[..., Settings]) -> None:
    out = io.StringIO()
    configure_logging(make_settings(observability={"log_format": "json", "log_level": "INFO"}), stream=out)
    LOG.info("isolation.first")
    assert json.loads(out.getvalue())["event"] == "isolation.first"
    assert is_configured() and len(_app_handlers()) == 1


def test_the_next_test_starts_from_the_default_logging_state() -> None:
    assert not structlog.is_configured() and not is_configured()
    assert _app_handlers() == []


def test_capture_logs_sees_a_logger_that_an_earlier_test_used_under_configure_logging() -> None:
    """The defect: structlog's logger cache bound ``LOG`` for good to the first test's processors. Once
    anything replaced the configuration (here the reset the logging tests' own fixtures do),
    ``capture_logs``, which swaps the processors of the current configuration, saw nothing from it."""
    structlog.reset_defaults()
    with capture_logs() as logs:
        LOG.info("isolation.second", answer=42)
    assert logs == [{"event": "isolation.second", "answer": 42, "log_level": "info"}]


def test_a_logger_is_never_cached_while_the_suite_runs(make_settings: Callable[..., Settings]) -> None:
    configure_logging(make_settings(), stream=io.StringIO())
    assert structlog.get_config()["cache_logger_on_first_use"] is False
    structlog.configure(cache_logger_on_first_use=True)
    assert structlog.get_config()["cache_logger_on_first_use"] is False
