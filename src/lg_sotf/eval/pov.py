"""The backtest of a proof-of-value run (PRD-11.1), started by the scheduler: no CLI step.

``POST /pov/runs`` records a run with its backtest ``pending``. The
scheduler's ``pov_backtests`` job calls :func:`run_next_pov_backtest`, which
takes the oldest waiting run, replays the alerts analysts decided in its
history window with :func:`lg_sotf.eval.history.run_history_backtest` and
stores the outcome on the run:

* ``completed`` with the evaluation report, without its per-alert items
  (metrics, notes, model provenance and the ids of the threats the replay
  would have closed: no alert title or body);
* ``no_data`` when no analyst decided an alert in the window;
* ``failed`` with a short, redacted reason.

The replay is the CLI backtest's, with the same guarantees: read-only
transactions, no system transaction, it stops at the routing decision, no
LLM accounting and no Redis. The only rows this module writes are the run's
own backtest columns. A backtest cut short (the scheduler stopped) stays
``running`` and is taken again on a later pass, at most
:data:`~lg_sotf.domain.pov.MAX_BACKTEST_ATTEMPTS` times.

This module sits above ``runtime`` in the layering (it runs the agents), so
the scheduler receives the job from the CLI (:func:`pov_backtest_job`).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from lg_sotf.agents.registry import AgentSet
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import PovRun, Repositories
from lg_sotf.domain.pov import BACKTEST_ALERT_LIMIT, MAX_BACKTEST_ERROR_CHARS, backtest_days
from lg_sotf.eval.history import NoDecidedAlerts, run_history_backtest
from lg_sotf.eval.report import build_report
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.redaction import safe_error_text
from lg_sotf.settings import Settings

log = get_logger(__name__)

# The stored result: the evaluation report without the per-alert rows and the per-split copies.
RESULT_KEYS = (
    "schema_version", "generated_at", "lg_sotf_version", "dataset", "run", "notes", "closure", "metrics",
    "llm_provenance",
)


def backtest_result(report: Mapping[str, Any]) -> Dict[str, Any]:
    """What a run stores of its backtest's report: every aggregate, no per-alert item."""
    return {key: report[key] for key in RESULT_KEYS if key in report}


async def run_next_pov_backtest(
    settings: Settings, db: Database, *, secret_box: Optional[SecretBox] = None, agents: Optional[AgentSet] = None
) -> Optional[PovRun]:
    """Run the oldest waiting backtest, if any, and store its outcome. Returns the run as it was claimed.

    ``db`` must be allowed to write the backtest columns (the scheduler's owner connection); the replay
    itself uses it read-only.
    """
    repos = Repositories.create(db)
    run = await repos.pov_runs.claim_backtest()
    if run is None or run.backtest_status != "running":
        return run
    try:
        history = await run_history_backtest(
            settings, tenant_id=run.tenant_id, days=backtest_days(run.backtest_start, run.backtest_end),
            limit=BACKTEST_ALERT_LIMIT, db=db, now=run.backtest_end, until=run.backtest_end, agents=agents,
            secret_box=secret_box,
        )
    except NoDecidedAlerts:
        await repos.pov_runs.finish_backtest(run, "no_data")
        log.info("pov.backtest_no_data", run_id=str(run.id))
        return run
    except Exception as exc:  # noqa: BLE001 - a failed backtest is recorded on its run, not raised to the scheduler
        log_failure(log, "pov.backtest_failed", exc, run_id=str(run.id), error_type=type(exc).__name__)
        await repos.pov_runs.finish_backtest(run, "failed", error=safe_error_text(exc, MAX_BACKTEST_ERROR_CHARS))
        return run
    report = build_report(history.results, dataset=history.dataset, run_info=history.info)
    stored = await repos.pov_runs.finish_backtest(run, "completed", result=backtest_result(report))
    log.info("pov.backtest_completed", run_id=str(run.id), items=len(history.results), stored=stored)
    return run


def pov_backtest_job(
    settings: Settings, db: Database, secret_box: Optional[SecretBox]
) -> Callable[[], Awaitable[None]]:
    """The scheduler's ``pov_backtests`` job: one backtest per pass (each can take long)."""

    async def job() -> None:
        await run_next_pov_backtest(settings, db, secret_box=secret_box)

    return job
