"""Run labelled alerts through the real ingestion service and workflow engine.

Each item is ingested with :class:`~lg_sotf.ingestion.service.IngestionService`
(canonical items through the reserved ``api`` source, vendor items through a
push source of that format, generic webhook items through a source with the
item's field map, email items as raw messages through the reserved
``email:eval`` source, exactly as ``POST /ingest/email`` does) and processed with
:meth:`~lg_sotf.core.workflow.WorkflowEngine.run`: the same graph,
checkpointer, agents, routing policy, escalation and response services a
worker uses, minus the queue.

A run that stops at an analyst or approval interrupt is left waiting and
recorded as ``review="unreviewed"``; an ``eval.review_not_performed`` event is
appended to the alert's timeline. The harness never resumes a run with an
invented analyst decision.

Items run in dataset order, one at a time by default: correlation reads the
tenant's earlier alerts, so a fixed order keeps a run reproducible. With
``concurrency > 1`` runs overlap and correlation-dependent outcomes may vary.

Isolation: by default (``isolate="splits"``) every split runs in its own
fresh tenant, so correlation, tenant history and escalation grouping from one
split never shape another split's outcomes and ``--split adversarial`` gives
the same per-item results as that split inside a full run. ``isolate="none"``
runs every item in one tenant (the pre-0.2 behaviour; split metrics are then
not independent).

:func:`run_evaluation` owns every resource (database pool, Redis client,
engine, fresh tenants) for the CLI and checks the database, schema and Redis
before the first item, so an unreachable service is a setup error rather
than a report full of per-item errors. Tests and embedders construct
:class:`EvalRunner` with their own services.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Awaitable, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple

from lg_sotf.core.workflow import RunOutcome, WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.routing import refused_by
from lg_sotf.eval.dataset import DISPOSITIONS, Dataset, EvalItem
from lg_sotf.eval.results import REVIEW_UNREVIEWED, ItemResult, llm_provenance
from lg_sotf.ingestion.batch import IngestResult
from lg_sotf.ingestion.service import API_SOURCE_ID, IngestionService, email_source_id
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.redaction import safe_error_text
from lg_sotf.security.shadow import REFUSE, egress
from lg_sotf.settings import Settings

log = get_logger(__name__)

MAX_ERROR_CHARS = 300
VENDOR_PUSH_FORMATS = ("splunk", "crowdstrike", "sentinel", "wazuh", "guardduty", "qradar")
Progress = Callable[[int, int, ItemResult], None]
Isolation = Literal["splits", "none"]
ISOLATION_MODES: Tuple[str, ...] = ("splits", "none")
MAX_TENANT_ID_CHARS = 63
EMAIL_EVAL_SOURCE = email_source_id("eval")


class EvalSetupError(RuntimeError):
    """The evaluation environment cannot be prepared (database, tenant, configuration)."""


def _usage(summary: Mapping[str, Any]) -> Dict[str, Any]:
    usage = summary.get("llm_usage")
    return usage if isinstance(usage, Mapping) else {}  # type: ignore[return-value]


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0 else 0


def _float(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0 else 0.0


def _apply_usage(result: ItemResult, summary: Mapping[str, Any]) -> None:
    usage = _usage(summary)
    result.llm_calls = _int(usage.get("calls"))
    result.input_tokens = _int(usage.get("input_tokens"))
    result.output_tokens = _int(usage.get("output_tokens"))
    result.total_tokens = _int(usage.get("total_tokens"))
    result.cost_usd = _float(usage.get("cost_usd"))
    result.llm_provenance = llm_provenance(usage)


@dataclass
class EvalRunner:
    """Evaluate items in one tenant with the given services (which the caller owns)."""

    tenant_id: str
    repos: Repositories
    ingestion: IngestionService
    engine: WorkflowEngine
    run_timeout_s: float = 900.0
    concurrency: int = 1
    _sources: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _source_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def run(self, items: Sequence[EvalItem], progress: Optional[Progress] = None) -> List[ItemResult]:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        results: List[Optional[ItemResult]] = [None] * len(items)
        semaphore = asyncio.Semaphore(self.concurrency)
        done = 0

        async def one(index: int, item: EvalItem) -> None:
            nonlocal done
            async with semaphore:
                result = await self.evaluate(item)
            results[index] = result
            done += 1
            if progress is not None:
                progress(done, len(items), result)

        if self.concurrency == 1:
            for index, item in enumerate(items):
                await one(index, item)
        else:
            await asyncio.gather(*(one(i, item) for i, item in enumerate(items)))
        return [r for r in results if r is not None]

    async def evaluate(self, item: EvalItem) -> ItemResult:
        result = ItemResult(
            item_id=item.id,
            split=item.split,
            tags=list(item.tags),
            source_type=item.source_type,
            expected=item.expected.disposition,
            status="error",
            expected_route=item.expected.route,
            expected_escalation=item.expected.escalation,
            labels={label.annotator: label.disposition for label in item.labels},
        )
        started = time.perf_counter()
        try:
            ingested = await self._ingest(item)
            outcome = ingested.items[0] if ingested.items else None
            if outcome is None or outcome.status != "inserted" or outcome.alert_id is None:
                status = outcome.status if outcome is not None else "missing"
                reason = (outcome.reason if outcome is not None else None) or status
                result.error = f"ingest {status}: {reason}"[:MAX_ERROR_CHARS]
                result.latency_s = time.perf_counter() - started
                return result
            result.alert_id = outcome.alert_id
            run = await asyncio.wait_for(self.engine.run(self.tenant_id, outcome.alert_id), self.run_timeout_s)
            result.latency_s = time.perf_counter() - started
            await self._collect(result, run)
        except TimeoutError:
            result.latency_s = time.perf_counter() - started
            result.status = "error"
            result.error = f"run timed out after {self.run_timeout_s:.0f} s"
            await self._usage_after_error(result)
        except Exception as exc:  # noqa: BLE001 - one failing item must not stop the evaluation
            result.latency_s = time.perf_counter() - started
            result.status = "error"
            result.error = safe_error_text(exc, MAX_ERROR_CHARS)
            log_failure(log, "eval.item_failed", exc, level="warning", item_id=item.id, error_type=type(exc).__name__)
            await self._usage_after_error(result)
        return result

    async def _usage_after_error(self, result: ItemResult) -> None:
        """Best effort: model calls made before a failure are still billed, so record them."""
        if result.alert_id is None:
            return
        try:
            alert = await self.repos.alerts.get(self.tenant_id, result.alert_id)
            _apply_usage(result, alert.summary or {})
        except Exception as exc:  # noqa: BLE001 - the item already failed; usage is informational
            log_failure(
                log, "eval.usage_unavailable", exc, level="warning", item_id=result.item_id,
                error_type=type(exc).__name__,
            )

    async def _collect(self, result: ItemResult, run: RunOutcome) -> None:
        assert result.alert_id is not None
        alert = await self.repos.alerts.get(self.tenant_id, result.alert_id)
        snapshot = await self.engine.graph.aget_state(
            {"configurable": {"thread_id": thread_id_for(self.tenant_id, result.alert_id)}}
        )
        state: Mapping[str, Any] = snapshot.values or {}
        summary: Mapping[str, Any] = alert.summary or {}
        decision = state.get("decision") or {}
        analysis = state.get("analysis") or {}
        gate = state.get("gate") or {}

        result.severity = alert.severity
        result.disposition = alert.disposition
        result.decision_code = decision.get("code")
        result.close_reason = state.get("close_reason") or summary.get("close_reason")
        result.model_refused = refused_by(state) is not None
        if decision.get("route"):
            result.route = str(decision["route"])
        elif gate.get("suppressed") or run.status == "completed":
            result.route = "close"  # closed by the gate or by triage before ``decide``
        result.escalated = bool(state.get("escalation_id")) or run.status == "waiting_human"

        _apply_usage(result, summary)

        verdict = analysis.get("verdict")
        if run.status == "completed" and alert.status == "closed":
            result.status = "closed"
            result.predicted = alert.disposition if alert.disposition in DISPOSITIONS else "inconclusive"
        elif run.status == "waiting_approval":
            result.status = "waiting_approval"
            result.approval_requested = True
            result.predicted = "malicious"
            result.review = REVIEW_UNREVIEWED
        elif run.status == "waiting_human":
            result.status = "waiting_human"
            result.predicted = verdict if verdict in DISPOSITIONS else "inconclusive"
            result.review = REVIEW_UNREVIEWED
        else:
            result.status = "error"
            result.error = f"run ended with alert status {alert.status!r}"
            return
        if result.review == REVIEW_UNREVIEWED:
            await self.repos.alert_events.append(
                self.tenant_id,
                result.alert_id,
                "eval.review_not_performed",
                node="eval",
                actor_type="system",
                actor_id="eval",
                data={"waiting_for": run.status, "item_id": result.item_id[:128]},
            )

    async def _ingest(self, item: EvalItem) -> IngestResult:
        source_id = await self._source_for(item)
        if item.source_type == "email":
            message = item.email
            return await self.ingestion.ingest_email(
                self.tenant_id, source_id, [message.mime.encode("utf-8")], reporter=message.reporter
            )
        return await self.ingestion.ingest(self.tenant_id, source_id, [dict(item.alert)])

    async def _source_for(self, item: EvalItem) -> str:
        if item.source_type == "canonical":
            return API_SOURCE_ID
        if item.source_type == "email":
            return EMAIL_EVAL_SOURCE
        if item.source_type in VENDOR_PUSH_FORMATS:
            config: Dict[str, Any] = {"format": item.source_type}
        else:
            config = {"format": "generic", **(item.source_config or {})}
        digest = hashlib.sha256(json.dumps(config, sort_keys=True, default=str).encode()).hexdigest()[:12]
        key = f"eval-{item.source_type}-{digest}"
        async with self._source_lock:
            if key not in self._sources:
                await self.repos.sources.create(
                    self.tenant_id, "webhook", f"Evaluation ({item.source_type})", source_id=key, config=config
                )
                self._sources[key] = key
        return key


def new_eval_tenant_id(now: Optional[datetime] = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    return f"eval-{stamp}-{secrets.token_hex(3)}"


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")
    return slug or "split"


def split_tenant_ids(base: str, splits: Sequence[str]) -> Dict[str, str]:
    """One valid, distinct tenant id per split, derived from ``base``."""
    out: Dict[str, str] = {}
    for index, split in enumerate(splits):
        suffix = f"-{index}-{_slug(split)}"
        room = MAX_TENANT_ID_CHARS - len(base)
        if room < 4:
            raise EvalSetupError(f"tenant id {base!r} is too long to derive per-split tenants; use a shorter --tenant")
        out[split] = (base + suffix)[:MAX_TENANT_ID_CHARS].rstrip("-_")
    return out


def group_by_split(items: Sequence[EvalItem]) -> List[Tuple[str, List[EvalItem]]]:
    """Items grouped by split, splits in order of first appearance, dataset order kept within a split."""
    groups: Dict[str, List[EvalItem]] = {}
    for item in items:
        groups.setdefault(item.split, []).append(item)
    return list(groups.items())


async def apply_tenant_settings(repos: Repositories, tenant_id: str, patch: Mapping[str, Any]) -> None:
    """Merge the dataset's ``_meta.tenant_settings`` into a fresh evaluation tenant."""
    if patch:
        await repos.tenants.update_settings(tenant_id, dict(patch))


@dataclass
class EvalRun:
    results: List[ItemResult]
    info: Dict[str, Any]


async def check_services(db: Any, redis: Any) -> None:
    """Fail fast (``EvalSetupError``) when the database, its schema or Redis is not usable."""
    import asyncpg
    from redis.exceptions import RedisError

    from lg_sotf.db.errors import DatabaseError

    try:
        await db.ping(acquire_timeout_s=5.0)
        async with db.connection() as conn:
            missing = await conn.fetchval(
                "SELECT array_remove(ARRAY["
                "CASE WHEN to_regclass('alerts') IS NULL THEN 'alerts' END, "
                "CASE WHEN to_regclass('workflow_runs') IS NULL THEN 'workflow_runs' END, "
                "CASE WHEN to_regclass('checkpoints') IS NULL THEN 'checkpoints' END"
                "], NULL)"
            )
    except (DatabaseError, asyncpg.PostgresError, OSError) as exc:
        raise EvalSetupError(f"database unavailable: {exc}") from exc
    if missing:
        raise EvalSetupError(
            f"database schema is not migrated (missing {', '.join(missing)}); run `lg-sotf migrate` against it first"
        )
    try:
        await redis.ping()
    except (RedisError, OSError) as exc:
        raise EvalSetupError(f"redis unavailable: {safe_error_text(exc, 200)}") from exc


@egress("database_connection", REFUSE)
async def run_evaluation(
    settings: Settings,
    dataset: Dataset,
    *,
    tenant_id: Optional[str] = None,
    concurrency: int = 1,
    isolate: Isolation = "splits",
    progress: Optional[Progress] = None,
    create_tenant: Optional[Callable[[Settings, str], Awaitable[None]]] = None,
    secret_box: Optional[SecretBox] = None,
) -> EvalRun:
    """Evaluate ``dataset`` against the database and Redis named by ``settings``.

    Fresh tenants are created with the schema-owner connection, so results
    never mix with existing data or earlier runs: one per split
    (``<base>-<n>-<split>``) with ``isolate="splits"``, or ``<base>`` itself
    with ``isolate="none"``; ``<base>`` is ``tenant_id`` or
    ``eval-<timestamp>-<random>``. The schema and LangGraph checkpoint tables
    must exist (``lg-sotf migrate``); the database, schema and Redis are
    checked before any tenant is created. Point the settings at a dedicated
    evaluation database: runs, escalations and alerts stay there afterwards.
    ``secret_box`` (built by the CLI) decrypts tenant credentials, as in a worker.
    """
    import asyncpg

    from lg_sotf.db.errors import DatabaseError
    from lg_sotf.db.pool import Database
    from lg_sotf.errors import OperationError
    from lg_sotf.queue.redis import ShadowSafeRedis
    from lg_sotf.runtime.ops import create_tenant as ops_create_tenant

    if settings.environment == "production":
        raise EvalSetupError(
            "refusing to run an evaluation with environment=production; point the settings at a dedicated "
            "evaluation database"
        )
    if isolate not in ISOLATION_MODES:
        raise EvalSetupError(f"unknown isolation mode {isolate!r}; use one of {', '.join(ISOLATION_MODES)}")
    base = tenant_id or new_eval_tenant_id()
    if isolate == "splits":
        groups = group_by_split(dataset.items)
        tenants = split_tenant_ids(base, [name for name, _ in groups])
        plan = [(tenants[name], group) for name, group in groups]
    else:
        tenants = {}
        plan = [(base, list(dataset.items))]

    async def default_create(s: Settings, t: str) -> None:
        await ops_create_tenant(s, tenant_id=t, name=f"Evaluation {t}")

    started = time.perf_counter()
    async with AsyncExitStack() as stack:
        db = Database(settings.database, application_name="lg-sotf-eval")
        try:
            await db.open()
        except DatabaseError as exc:
            raise EvalSetupError(f"database unavailable: {exc}") from exc
        stack.push_async_callback(db.close)
        redis = ShadowSafeRedis.from_url(settings.redis.url.get_secret_value(), decode_responses=False)
        stack.push_async_callback(redis.aclose)
        await check_services(db, redis)

        ingestion = IngestionService(db, settings, secret_box=secret_box)
        stack.push_async_callback(ingestion.close)
        try:
            engine = await WorkflowEngine.create(
                settings=settings,
                db=db,
                redis=redis,
                events=None,
                checkpoint_pool_size=max(2, min(concurrency + 1, settings.database.pool_max)),
                secret_box=secret_box,
            )
        except (DatabaseError, asyncpg.PostgresError, OSError) as exc:
            raise EvalSetupError(f"cannot start the workflow engine: {type(exc).__name__}: {exc}") from exc
        stack.push_async_callback(engine.close)
        # Tenants last: a configuration or service problem above leaves nothing behind.
        for tenant, _ in plan:
            try:
                await (create_tenant or default_create)(settings, tenant)
            except OperationError as exc:
                raise EvalSetupError(str(exc)) from exc
            except (DatabaseError, asyncpg.PostgresError, OSError) as exc:
                raise EvalSetupError(f"cannot create evaluation tenant {tenant!r}: {exc}") from exc
        repos = Repositories.create(db)
        for tenant, _ in plan:
            await apply_tenant_settings(repos, tenant, dataset.tenant_settings)
        total = len(dataset.items)
        done = 0

        def forward(_done: int, _total: int, result: ItemResult) -> None:
            nonlocal done
            done += 1
            if progress is not None:
                progress(done, total, result)

        by_id: Dict[str, ItemResult] = {}
        for tenant, group in plan:
            runner = EvalRunner(
                tenant_id=tenant,
                repos=repos,
                ingestion=ingestion,
                engine=engine,
                run_timeout_s=settings.worker.run_timeout_s,
                concurrency=concurrency,
            )
            for result in await runner.run(group, progress=forward):
                by_id[result.item_id] = result
        results = [by_id[item.id] for item in dataset.items if item.id in by_id]
    return EvalRun(results=results, info=_run_info(settings, base, isolate, tenants, concurrency, started))


def _run_info(
    settings: Settings, base: str, isolate: Isolation, tenants: Dict[str, str], concurrency: int, started: float
) -> Dict[str, Any]:
    """``report.run`` of an evaluation: where it ran, with which models, and how long it took."""
    fake = settings.llm.provider == "fake"
    return {
        "tenant_id": base if isolate == "none" else None,
        "isolation": isolate,
        "tenants": tenants if isolate == "splits" else {"*": base},
        "llm_provider": settings.llm.provider if settings.llm.enabled else "disabled",
        "fast_model": "fake" if fake else settings.llm.fast.model,
        "deep_model": "fake" if fake else settings.llm.deep.model,
        "environment": settings.environment,
        "concurrency": concurrency,
        "duration_s": round(time.perf_counter() - started, 3),
    }
