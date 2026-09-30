"""Backtest: replay the alerts analysts decided through the current pipeline and model, with no side effects.

``lg-sotf eval --from-history --tenant T --days N`` reads the tenant's
alerts whose analyst decision (the latest one other than
``needs_more_info``, as in ``docs/tools/export_feedback.sql``) was recorded
in the last N days, runs each through the *current* triage, correlation and
analysis agents and the routing policy (``decide``), and scores what the
platform would conclude now against what the analyst decided, with the
metrics and report module of the evaluation harness. Use it to try another
model or provider on your own history before switching.

Side effects are disabled by construction:

* every database access goes through :class:`ReadOnlyDatabase`: read-only
  transactions (a write raises), scoped to the tenant, and no system
  (RLS-bypassing) transactions;
* the replay stops at ``decide``: no escalation, response plan, action,
  approval request, notification, event or alert update is ever created,
  and response execution does not run at all (stronger than dry run);
* agents run with ``persist=False``: no LLM accounting on the alert, no
  indicator sightings; no token budget is reserved (the tenant's daily
  budget is not consumed) and the usage metering is never flushed to
  ``llm_usage_daily`` in this process;
* the queue, the verdict cache and the event bus are not used (no Redis).

Context is approximated *as of the alert's ingestion*: correlation and the
history lookups see only indicator sightings from before that moment (the
window is shifted back, see :class:`PointInTimeIndicatorsRepo`), and a
related alert that was still open then shows no outcome
(:class:`PointInTimeAlertsRepo`). Limits (also in ``docs/reporting.md``):
suppression rules and the verdict cache are skipped (both were derived from
the decisions being scored); external threat-intelligence lookups answer as
of today; model calls are real and billed to the configured provider.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, cast

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.registry import AgentSet
from lg_sotf.core import routing
from lg_sotf.core.graph import cap_alert
from lg_sotf.core.routing import RoutingThresholds, refused_by
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Alert, Repositories
from lg_sotf.db.repos._base import Connection
from lg_sotf.db.repos.alerts import AlertsRepo
from lg_sotf.db.repos.indicators import IndicatorsRepo, RelatedAlert
from lg_sotf.db.repos.reports import DecidedAlert
from lg_sotf.eval.dataset import Dataset, EvalItem, Expected
from lg_sotf.eval.results import ItemResult
from lg_sotf.llm import UsageTally, merge_usage_summary
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings

log = get_logger(__name__)

HISTORY_SPLIT = "history"
DEFAULT_HISTORY_LIMIT = 500
MAX_HISTORY_DAYS = 366
MAX_ERROR_CHARS = 300
EXPECTED_BY_DECISION = {
    "true_positive": "malicious",
    "false_positive": "benign",
    "benign_positive": "benign",
}
_ITEM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
Progress = Callable[[int, int, ItemResult], None]


class HistoryBacktestError(RuntimeError):
    """The backtest cannot run (message is safe to print)."""


class ReplayWriteBlocked(RuntimeError):
    """Something tried to open a transaction that could write during a replay."""


class ReadOnlyDatabase:
    """A view of :class:`~lg_sotf.db.pool.Database` whose transactions are all read-only.

    PostgreSQL rejects any write inside them (``ReadOnlySQLTransactionError``),
    so a replay cannot change the tenant's data even through a code path this
    module does not know about. System (RLS-bypassing) transactions are refused.
    """

    def __init__(self, inner: Database) -> None:
        self._inner = inner

    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str, *, readonly: bool = True) -> AsyncIterator[Connection]:
        async with self._inner.tenant_tx(tenant_id, readonly=True) as conn:
            yield conn

    @asynccontextmanager
    async def system_tx(self, *, readonly: bool = True) -> AsyncIterator[Connection]:
        raise ReplayWriteBlocked("system transactions are not available during a replay")
        yield  # pragma: no cover - makes this an async generator

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[Connection]:
        async with self._inner.connection() as conn:
            async with conn.transaction(readonly=True):
                yield conn


class PointInTimeIndicatorsRepo(IndicatorsRepo):
    """Indicator lookups as they would have answered at ``cutoff``; sightings are never recorded.

    Agents compute look-back windows from the wall clock. Every window is
    moved back by ``offset`` (wall clock minus ``cutoff``) and bounded by
    ``cutoff``, and returned ``last_seen`` values are moved forward again, so
    "within the last hour" and burst checks mean the hour before the alert
    was ingested.
    """

    def __init__(self, db: Any, *, cutoff: datetime, offset: timedelta) -> None:
        super().__init__(db)
        self._cutoff = cutoff
        self._offset = offset

    async def add_sightings(self, tenant_id: str, alert_id: str, sightings: Any, *, conn: Any = None) -> int:
        return 0

    async def related_alerts(
        self,
        tenant_id: str,
        indicators: Sequence[Tuple[str, str]],
        *,
        since: datetime,
        until: Optional[datetime] = None,
        limit: int = 20,
        exclude_alert_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> List[RelatedAlert]:
        bound = self._cutoff if until is None else min(until - self._offset, self._cutoff)
        rows = await super().related_alerts(
            tenant_id,
            indicators,
            since=since - self._offset,
            until=bound,
            limit=limit,
            exclude_alert_id=exclude_alert_id,
            conn=conn,
        )
        return [r.model_copy(update={"last_seen": r.last_seen + self._offset}) for r in rows]


def as_of(alert: Alert, cutoff: datetime) -> Alert:
    """``alert`` as it looked at ``cutoff``: an alert not closed by then shows no outcome."""
    if alert.status == "closed" and alert.closed_at is not None and alert.closed_at <= cutoff:
        return alert
    return alert.model_copy(update={"status": "processing", "disposition": None, "closed_at": None, "summary": {}})


class PointInTimeAlertsRepo(AlertsRepo):
    """Related-alert reads (correlation digests, history outcomes) as of ``cutoff``."""

    def __init__(self, db: Any, *, cutoff: datetime) -> None:
        super().__init__(db)
        self._cutoff = cutoff

    async def get(self, tenant_id: str, alert_id: str, *, conn: Optional[Connection] = None) -> Alert:
        return as_of(await super().get(tenant_id, alert_id, conn=conn), self._cutoff)


def replay_repositories(db: Database, *, cutoff: datetime, offset: timedelta) -> Repositories:
    """Read-only repositories with the point-in-time alert and indicator views."""
    ro = cast(Database, ReadOnlyDatabase(db))
    base = Repositories.create(ro)
    return dataclasses.replace(
        base,
        alerts=PointInTimeAlertsRepo(ro, cutoff=cutoff),
        indicators=PointInTimeIndicatorsRepo(ro, cutoff=cutoff, offset=offset),
    )


def initial_state(tenant_id: str, alert: Alert, llm_budget_limit: Any = None) -> Dict[str, Any]:
    """The workflow's initial state for ``alert`` (as :meth:`WorkflowEngine._initial_state` builds it)."""
    canonical: Dict[str, Any] = dict(alert.normalized)
    canonical.update(
        {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "category": alert.category if alert.category is not None else canonical.get("category"),
            "source_id": alert.source_id,
            "source_alert_id": alert.source_alert_id,
            "fingerprint": alert.fingerprint,
            "occurred_at": alert.occurred_at.isoformat(),
        }
    )
    if "raw" not in canonical:
        canonical["raw"] = alert.raw
    return {
        "tenant_id": tenant_id,
        "alert_id": alert.id,
        "severity": alert.severity,
        "fingerprint": alert.fingerprint,
        "alert": cap_alert(canonical),
        "confidence": 50,
        "gate": {"suppressed": False},
        "triage": {},
        "correlation": {},
        "analysis": {},
        "analysis_runs": 0,
        "more_info_loops": 0,
        "decision": {},
        "analyst": None,
        "llm_budget_exceeded": False,
        "llm_budget_limit": llm_budget_limit if isinstance(llm_budget_limit, int) else None,
    }


@dataclass
class Replay:
    """What the pipeline concluded for one alert: final state, route and LLM usage."""

    state: Dict[str, Any]
    route: str
    usage: Dict[str, Any] = field(default_factory=dict)


def item_id_for(alert_id: str) -> str:
    if _ITEM_ID.match(alert_id):
        return alert_id
    return "h-" + hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:32]


def classify(result: ItemResult, replay: Replay) -> None:
    """Fill ``result`` from a replay, with the harness's ``predicted`` semantics."""
    state = replay.state
    decision = state.get("decision") or {}
    analysis = state.get("analysis") or {}
    result.route = replay.route
    result.decision_code = decision.get("code")
    result.model_refused = refused_by(state) is not None
    if replay.route == "close":
        disposition = str(decision.get("disposition") or "benign")
        result.status = "closed"
        result.disposition = disposition
        result.predicted = disposition
        result.close_reason = "policy:close" if decision else "triage:false_positive"
    elif replay.route == "plan_response":
        result.status = "waiting_approval"
        result.approval_requested = True
        result.predicted = "malicious"
    else:
        verdict = analysis.get("verdict")
        result.status = "waiting_human"
        result.escalated = True
        result.predicted = verdict if verdict in ("malicious", "benign", "inconclusive") else "inconclusive"
    usage = replay.usage
    result.llm_calls = int(usage.get("calls") or 0)
    result.input_tokens = int(usage.get("input_tokens") or 0)
    result.output_tokens = int(usage.get("output_tokens") or 0)
    result.total_tokens = int(usage.get("total_tokens") or 0)
    result.cost_usd = float(usage.get("cost_usd") or 0.0)


@dataclass
class HistoryReplayer:
    """Replays decided alerts of one tenant; the caller owns the database and the agents."""

    tenant_id: str
    settings: Settings
    db: Database
    agents: AgentSet
    thresholds: RoutingThresholds
    run_timeout_s: float = 900.0
    concurrency: int = 1
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    tenant_settings: Mapping[str, Any] = field(default_factory=dict)

    async def run(self, decided: Sequence[DecidedAlert], progress: Optional[Progress] = None) -> List[ItemResult]:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        results: List[Optional[ItemResult]] = [None] * len(decided)
        semaphore = asyncio.Semaphore(self.concurrency)
        done = 0

        async def one(index: int, item: DecidedAlert) -> None:
            nonlocal done
            async with semaphore:
                result = await self.evaluate(item)
            results[index] = result
            done += 1
            if progress is not None:
                progress(done, len(decided), result)

        if self.concurrency == 1:
            for index, item in enumerate(decided):
                await one(index, item)
        else:
            await asyncio.gather(*(one(i, item) for i, item in enumerate(decided)))
        return [r for r in results if r is not None]

    async def evaluate(self, decided: DecidedAlert) -> ItemResult:
        alert = decided.alert
        expected = EXPECTED_BY_DECISION[decided.decision]
        result = ItemResult(
            item_id=item_id_for(alert.id),
            split=HISTORY_SPLIT,
            tags=[f"severity:{alert.severity}", f"decision:{decided.decision}"],
            source_type="canonical",
            expected=expected,
            status="error",
            alert_id=alert.id,
            severity=alert.severity,
            labels={"analyst": expected},
        )
        started = time.perf_counter()
        try:
            replay = await asyncio.wait_for(self.replay(alert), self.run_timeout_s)
            classify(result, replay)
        except TimeoutError:
            result.error = f"replay timed out after {self.run_timeout_s:.0f} s"
        except Exception as exc:  # one failing alert must not stop the backtest
            result.status = "error"
            result.error = f"{type(exc).__name__}: {str(exc)[:200]}"[:MAX_ERROR_CHARS]
            log.warning("backtest.item_failed", alert_id=alert.id, error_type=type(exc).__name__)
        result.latency_s = time.perf_counter() - started
        return result

    async def replay(self, alert: Alert) -> Replay:
        """triage -> correlation -> analysis -> decide, as the graph routes them; nothing is written."""
        cutoff = alert.ingested_at
        offset = max(self.clock() - cutoff, timedelta(0))
        repos = replay_repositories(self.db, cutoff=cutoff, offset=offset)
        state = initial_state(self.tenant_id, alert, self.tenant_settings.get("llm_daily_token_budget"))
        tallies: List[UsageTally] = []

        def context() -> AgentContext:
            ctx = AgentContext(
                tenant_id=self.tenant_id,
                alert_id=alert.id,
                settings=self.settings,
                repos=repos,
                budget=None,
                llm_budget_exceeded=bool(state.get("llm_budget_exceeded")),
                persist=False,
            )
            tallies.append(ctx.usage)
            return ctx

        def usage() -> Dict[str, Any]:
            merged: Dict[str, Any] = {}
            for tally in tallies:
                merged = merge_usage_summary(merged, tally)
            return merged

        ctx = context()
        triage = await self.agents.triage.run(ctx, state["alert"])
        state.update(triage=triage.digest(), confidence=triage.confidence, llm_budget_exceeded=ctx.llm_budget_exceeded)
        if routing.route_after_triage(state, self.thresholds) == "close":
            return Replay(state=state, route="close", usage=usage())

        ctx = context()
        correlation = await self.agents.correlation.run(
            ctx, state["alert"], base_confidence=float(state.get("confidence", 50))
        )
        state.update(
            correlation=correlation.digest(),
            confidence=correlation.confidence,
            llm_budget_exceeded=ctx.llm_budget_exceeded,
        )
        if routing.route_after_correlation(state, self.thresholds) == "analysis":
            ctx = context()
            analysis = await self.agents.analysis.run(
                ctx, state["alert"], triage=state["triage"], correlation=state["correlation"]
            )
            state.update(analysis=analysis.digest(), analysis_runs=1, llm_budget_exceeded=ctx.llm_budget_exceeded)
        decision = routing.decide(state, self.thresholds)
        state["decision"] = decision.as_dict()
        return Replay(state=state, route=decision.route, usage=usage())


def history_dataset(tenant_id: str, days: int, decided: Sequence[DecidedAlert]) -> Dataset:
    """A :class:`Dataset` describing the replayed alerts (for the report and baseline comparison).

    Items carry only the alert title and severity: the report never includes
    alert bodies. The sha256 covers the alert ids and decisions, so two runs
    over the same decisions are comparable as baselines.
    """
    items = [
        EvalItem(
            id=item_id_for(d.alert.id),
            source_type="canonical",
            alert={"title": d.alert.title[:200], "severity": d.alert.severity},
            expected=Expected(disposition=EXPECTED_BY_DECISION[d.decision]),
            split=HISTORY_SPLIT,
            tags=[f"severity:{d.alert.severity}", f"decision:{d.decision}"],
        )
        for d in decided
    ]
    digest = hashlib.sha256("\n".join(f"{d.alert.id}\t{d.decision}" for d in decided).encode("utf-8")).hexdigest()
    return Dataset(
        items=items,
        meta={
            "synthetic": False,
            "description": f"Alerts analysts decided in tenant {tenant_id} in the last {days} days",
            "source": "history",
        },
        path=f"history:{tenant_id}:{days}d",
        sha256=digest,
    )


@dataclass
class HistoryRun:
    dataset: Dataset
    results: List[ItemResult]
    info: Dict[str, Any]


async def run_history_backtest(
    settings: Settings,
    *,
    tenant_id: str,
    days: int,
    limit: int = DEFAULT_HISTORY_LIMIT,
    concurrency: int = 1,
    progress: Optional[Progress] = None,
    agents: Optional[AgentSet] = None,
    db: Optional[Database] = None,
    now: Optional[datetime] = None,
    before_replay: Optional[Callable[[Dataset], None]] = None,
) -> HistoryRun:
    """Replay the tenant's decided alerts of the last ``days`` days (at most ``limit``, oldest first).

    Opens its own database pool (used read-only) unless ``db`` is given.
    ``before_replay`` sees the selected items before any model call and may
    raise to stop the run (baseline checks). Raises
    :class:`HistoryBacktestError` when the tenant does not exist or has no
    decided alerts in the window.
    """
    from lg_sotf.db.errors import DatabaseError, NotFound

    if not 1 <= days <= MAX_HISTORY_DAYS:
        raise HistoryBacktestError(f"--days must be between 1 and {MAX_HISTORY_DAYS}")
    started = time.perf_counter()
    now = now or datetime.now(UTC)
    owned_db = db is None
    database = db or Database(settings.database, application_name="lg-sotf-backtest")
    agent_set = agents or AgentSet.build(settings)
    if owned_db:
        try:
            await database.open()
        except DatabaseError as exc:
            raise HistoryBacktestError(f"database unavailable: {exc}") from exc
    try:
        repos = Repositories.create(cast(Database, ReadOnlyDatabase(database)))
        try:
            tenant = await repos.tenants.get(tenant_id)
        except NotFound as exc:
            raise HistoryBacktestError(f"tenant {tenant_id!r} does not exist") from exc
        decided = await repos.reports.decided_alerts(tenant_id, now - timedelta(days=days), limit=limit)
        if not decided:
            raise HistoryBacktestError(
                f"tenant {tenant_id!r} has no analyst-decided alerts in the last {days} days; nothing to replay"
            )
        dataset = history_dataset(tenant_id, days, decided)
        if before_replay is not None:
            before_replay(dataset)
        if agents is None:
            await agent_set.initialize()
        try:
            replayer = HistoryReplayer(
                tenant_id=tenant_id,
                settings=settings,
                db=database,
                agents=agent_set,
                thresholds=RoutingThresholds.from_settings(settings.routing),
                run_timeout_s=settings.worker.run_timeout_s,
                concurrency=concurrency,
                tenant_settings=tenant.settings or {},
            )
            results = await replayer.run(decided, progress=progress)
        finally:
            if agents is None:
                await agent_set.cleanup()
    finally:
        if owned_db:
            await database.close()
    fake = settings.llm.provider == "fake"
    info: Dict[str, Any] = {
        "mode": "history",
        "tenant_id": tenant_id,
        "days": days,
        "limit": limit,
        "since": (now - timedelta(days=days)).isoformat(),
        "side_effects": "none: read-only replay up to the routing decision",
        "llm_provider": settings.llm.provider if settings.llm.enabled else "disabled",
        "fast_model": "fake" if fake else settings.llm.fast.model,
        "deep_model": "fake" if fake else settings.llm.deep.model,
        "environment": settings.environment,
        "concurrency": concurrency,
        "duration_s": round(time.perf_counter() - started, 3),
    }
    return HistoryRun(dataset=dataset, results=results, info=info)
