"""Durable workflow engine: the compiled LangGraph with a Postgres checkpointer.

One engine per worker process. ``run`` starts a fresh run from the alert row
or continues an unfinished checkpoint; ``resume`` feeds an analyst decision
or an approval into the pending interrupt. The engine owns alert status and
summary writes, alert events, event publishing, escalations and the action
ledger; it never touches the queue, and of ``workflow_runs`` (the worker's)
only ``graph_version``.

Graph versions: the engine compiles every graph in
:data:`~lg_sotf.core.graph.GRAPH_BUILDERS` (the current one and N-1). A
fresh thread starts on the current graph, after its version is stamped on
``workflow_runs.graph_version``; a run with a checkpoint continues or resumes
on the graph of its stamped version. A version this worker does not have
raises :class:`UnknownGraphVersion` before anything is written: the run is
marked failed with that error and retried (a worker of another release may
have the version), then dead-lettered like any failing run.

Alert status transitions (contract section 6): ``new``/``queued``/``failed``
-> ``processing`` when a run or resume starts; ``waiting_human`` or
``waiting_approval`` on interrupt; ``closed`` by the ``close`` node;
``failed`` when a node still fails after its retry policy, in which case the
error is re-raised.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Dict, List, Literal, Mapping, Optional, Tuple, Union

from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from pydantic import ValidationError as PydanticValidationError
from redis.asyncio import Redis

from lg_sotf.agents.registry import AgentSet
from lg_sotf.core.graph import (
    GRAPH_BUILDERS,
    UNVERSIONED_GRAPH,
    GraphBuilder,
    WorkflowState,
    initial_state,
)
from lg_sotf.core.nodes import NodeDeps, WorkflowNodes
from lg_sotf.core.retry import attempts_within_budget, build_retry_policy
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.checkpointer import TenantScopedPostgresSaver
from lg_sotf.db.errors import DatabaseError, InvalidTransition, NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Alert, Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.db.urls import to_libpq_url, with_query_params
from lg_sotf.domain.events import EventPublisher, publish_event
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.errors import InvalidResumePayload, WorkflowError
from lg_sotf.llm import TokenBudget
from lg_sotf.models.tenant_settings import token_budget
from lg_sotf.models.vocabulary import Decision
from lg_sotf.observability.logging import bound_context, get_logger, log_failure
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import indicator_hmac_key
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.response import Connector, ResponseService
from lg_sotf.settings import Settings

__all__ = [
    "AnalystDecisionPayload",
    "ApprovalPayload",
    "EventPublisher",
    "RunOutcome",
    "UnknownGraphVersion",
    "WorkflowEngine",
    "validate_resume_payload",
]

log = get_logger(__name__)

RECURSION_LIMIT = 60
WAITING_STATUS = {"analyst_decision": "waiting_human", "approval": "waiting_approval"}


class UnknownGraphVersion(WorkflowError):
    """The run's checkpoint is on a graph version this worker cannot run."""


@dataclass(frozen=True)
class RunOutcome:
    status: Literal["completed", "waiting_human", "waiting_approval"]
    alert_status: str
    interrupt: Optional[dict]


class AnalystDecisionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["analyst_decision"]
    escalation_id: str = Field(min_length=1, max_length=128)
    decision: Decision
    approved_actions: List[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        default_factory=list, max_length=50
    )
    decided_by: str = Field(min_length=1, max_length=128)
    notes: str = Field(default="", max_length=4_000)
    # Set by the API from the authenticated principal: high/critical actions in
    # approved_actions are pre-approved only for "admin" (contract section 10).
    approver_role: Optional[Literal["analyst", "admin"]] = None


class ApprovalPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["approval"]
    approved_action_ids: List[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=100
    )
    rejected_action_ids: List[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=100
    )
    decided_by: str = Field(min_length=1, max_length=128)
    # False (per-action approve/reject): actions not named stay awaiting approval.
    # True: every other pending action of the alert is rejected and the run moves on.
    reject_remaining: bool = False


_RESUME_ADAPTER: TypeAdapter[Union[AnalystDecisionPayload, ApprovalPayload]] = TypeAdapter(
    Annotated[Union[AnalystDecisionPayload, ApprovalPayload], Field(discriminator="type")]
)


def validate_resume_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a resume payload against the contract; raises :class:`InvalidResumePayload`."""
    try:
        model = _RESUME_ADAPTER.validate_python(dict(payload))
    except PydanticValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors()[:5])
        raise InvalidResumePayload(f"invalid resume payload ({fields})") from exc
    if isinstance(model, ApprovalPayload) and set(model.approved_action_ids) & set(model.rejected_action_ids):
        raise InvalidResumePayload("an action cannot be both approved and rejected")
    return model.model_dump()


def checkpointer_conninfo(settings: Settings) -> str:
    db = settings.database
    return with_query_params(
        to_libpq_url(db.url.get_secret_value()),
        {"sslmode": db.ssl_mode, "sslrootcert": db.ssl_root_cert},
        override=True,
    )


def _retry_policies(settings: Settings) -> Dict[str, Any]:
    """``build_graph``'s retry arguments: node retries fit in the run timeout; analysis has its own timeout."""
    worker = settings.worker
    return {
        "retry_policy": build_retry_policy(attempts_within_budget(worker.node_timeout_s, worker.run_timeout_s)),
        "node_retry_policies": {
            "analysis": build_retry_policy(attempts_within_budget(worker.analysis_timeout_s, worker.run_timeout_s))
        },
    }


class WorkflowEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        repos: Repositories,
        graphs: Mapping[int, CompiledStateGraph],
        pool: AsyncConnectionPool,
        checkpointer: TenantScopedPostgresSaver,
        agents: AgentSet,
        escalations: EscalationService,
        events: Optional[EventPublisher],
    ) -> None:
        self.settings = settings
        self.repos = repos
        self.graphs = dict(graphs)
        self.graph_version = max(self.graphs)
        self.graph = self.graphs[self.graph_version]
        """The current graph: every fresh thread starts on it."""
        self.agents = agents
        self._pool = pool
        self._checkpointer = checkpointer
        self._escalations = escalations
        self._events = events

    @classmethod
    async def create(
        cls,
        *,
        settings: Settings,
        db: Database,
        redis: Redis,
        events: Optional[EventPublisher],
        agents: Optional[AgentSet] = None,
        connectors: Optional[Mapping[str, Connector]] = None,
        checkpoint_pool_size: Optional[int] = None,
        secret_box: Optional[SecretBox] = None,
        graph_builders: Mapping[int, GraphBuilder] = GRAPH_BUILDERS,
    ) -> WorkflowEngine:
        """Build agents and services, open the checkpointer pool and compile the graphs.

        The checkpoint tables must exist (``lg-sotf migrate`` runs
        ``AsyncPostgresSaver.setup()``). Raises
        :class:`~lg_sotf.security.hashing.SecurityConfigError` when
        ``security.indicator_hmac_key`` is missing or unusable: correlation
        needs it for every alert with indicators, so a worker without it
        must not start and fail each run instead. ``secret_box`` is the
        process's (built once by its composition root): the response service
        and analysis enrichment decrypt tenant credentials with it.
        ``graph_builders`` maps each graph version to its builder; the highest
        version is the current graph.
        """
        indicator_hmac_key(settings)
        repos = Repositories.create(db)
        agent_set = agents or AgentSet.build(settings, secret_box=secret_box)
        await agent_set.initialize()
        escalations = EscalationService(repos, events, settings)
        responses = ResponseService(repos, settings, events, connectors=connectors, secret_box=secret_box)
        deps = NodeDeps(
            settings=settings,
            repos=repos,
            agents=agent_set,
            escalations=escalations,
            responses=responses,
            verdicts=VerdictCache(redis, settings.redis.key_prefix),
            thresholds=RoutingThresholds.from_settings(settings.routing),
            events=events,
            budget=TokenBudget(redis, settings, usage_seed=repos.llm_usage.day_tokens),
        )
        size = checkpoint_pool_size or max(2, min(settings.database.pool_max, settings.worker.concurrency))
        pool: AsyncConnectionPool = AsyncConnectionPool(
            conninfo=checkpointer_conninfo(settings),
            min_size=1,
            max_size=size,
            kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
            open=False,
            name="lgsotf-checkpoints",
            # Verify a connection before handing it out: after a database restart or
            # failover, idle connections are dead and would fail the next run (which
            # then waits worker.visibility_timeout_s for redelivery).
            check=AsyncConnectionPool.check_connection,
            max_idle=300.0,
            max_lifetime=1_800.0,
        )
        await pool.open(wait=True, timeout=settings.database.command_timeout_s)
        checkpointer = TenantScopedPostgresSaver(pool)  # type: ignore[arg-type]
        nodes = WorkflowNodes(deps)
        graphs = {
            version: build(nodes, deps.thresholds, **_retry_policies(settings)).compile(checkpointer=checkpointer)
            for version, build in graph_builders.items()
        }
        return cls(
            settings=settings,
            repos=repos,
            graphs=graphs,
            pool=pool,
            checkpointer=checkpointer,
            agents=agent_set,
            escalations=escalations,
            events=events,
        )

    async def close(self) -> None:
        await self.agents.cleanup()
        await self._pool.close()

    @staticmethod
    def _config(tenant_id: str, alert_id: str) -> RunnableConfig:
        return {"configurable": {"thread_id": thread_id_for(tenant_id, alert_id)}, "recursion_limit": RECURSION_LIMIT}

    @staticmethod
    def _pending_interrupt(snapshot: Any) -> Optional[Dict[str, Any]]:
        for task in getattr(snapshot, "tasks", ()) or ():
            for intr in getattr(task, "interrupts", ()) or ():
                value = getattr(intr, "value", None)
                if isinstance(value, dict):
                    return value
        return None

    @staticmethod
    def _unfinished(snapshot: Any) -> Tuple[str, ...]:
        """Nodes still to run from the latest checkpoint; empty only when the graph finished.

        ``snapshot.next`` leaves out tasks whose writes were already saved. A
        process killed after a step's writes but before that step's checkpoint
        (e.g. right after ``__start__``) leaves such tasks and an empty
        ``next``; the thread is still unfinished and ``ainvoke(None)`` continues
        it from the saved writes.
        """
        remaining = tuple(snapshot.next or ())
        if remaining:
            return remaining
        return tuple(str(getattr(t, "name", "")) for t in (getattr(snapshot, "tasks", ()) or ()))

    # ------------------------------------------------------------------ run

    async def run(self, tenant_id: str, alert_id: str) -> RunOutcome:
        """Process an alert: continue its unfinished checkpoint, or start from the alert row.

        A run already waiting for a human returns its waiting outcome; a
        finished run returns ``completed`` unless the alert was re-queued
        (reprocess), which starts a fresh thread.
        """
        config = self._config(tenant_id, alert_id)
        with bound_context(tenant_id=tenant_id, alert_id=alert_id, thread_id=config["configurable"]["thread_id"]):
            alert = await self.repos.alerts.get(tenant_id, alert_id)
            graph = await self._thread_graph(tenant_id, alert_id, config)
            snapshot = await graph.aget_state(config)
            pending = self._pending_interrupt(snapshot)
            if pending is not None:
                return await self._waiting(tenant_id, alert_id, pending)
            if self._unfinished(snapshot):
                return await self._continue(graph, tenant_id, alert_id, snapshot, config)
            if snapshot.values:
                if alert.status not in ("new", "queued"):
                    return RunOutcome("completed", alert.status, None)
                await self._checkpointer.adelete_thread(config["configurable"]["thread_id"])
            await self._mark_processing(tenant_id, alert_id)
            initial = await self._initial_state(tenant_id, alert)
            # Stamped before the thread's first checkpoint: no checkpoint is ever on an unrecorded graph.
            await self.repos.runs.set_graph_version(tenant_id, alert_id, self.graph_version)
            log.info("workflow.started", graph_version=self.graph_version)
            return await self._invoke(self.graph, tenant_id, alert_id, initial, config)

    async def resume(self, tenant_id: str, alert_id: str, payload: Mapping[str, Any]) -> RunOutcome:
        """Deliver an analyst decision or approval to the run's pending interrupt."""
        data = validate_resume_payload(payload)
        config = self._config(tenant_id, alert_id)
        with bound_context(tenant_id=tenant_id, alert_id=alert_id, thread_id=config["configurable"]["thread_id"]):
            graph = await self._thread_graph(tenant_id, alert_id, config)
            snapshot = await graph.aget_state(config)
            pending = self._pending_interrupt(snapshot)
            if pending is None:
                if self._unfinished(snapshot):
                    return await self._continue(graph, tenant_id, alert_id, snapshot, config)
                if snapshot.values:
                    alert = await self.repos.alerts.get(tenant_id, alert_id)
                    return RunOutcome("completed", alert.status, None)
                raise InvalidResumePayload("there is no workflow run to resume for this alert")
            if pending.get("type") != data["type"]:
                raise InvalidResumePayload(
                    f"run is waiting for {pending.get('type')!r}, got a {data['type']!r} payload"
                )
            if data["type"] == "analyst_decision":
                if data["escalation_id"] != pending.get("escalation_id"):
                    raise InvalidResumePayload("escalation_id does not match the pending escalation")
                await self._escalations.close_after_resume(
                    tenant_id,
                    data["escalation_id"],
                    decision=data["decision"],
                    decided_by=data["decided_by"],
                    notes=data["notes"] or None,
                    approved_actions=data["approved_actions"],
                )
                await self.repos.alert_events.append(
                    tenant_id,
                    alert_id,
                    "analyst.decision",
                    node="await_analyst",
                    actor_type="user",
                    actor_id=data["decided_by"],
                    data={"decision": data["decision"], "escalation_id": data["escalation_id"]},
                )
            else:
                await self.repos.alert_events.append(
                    tenant_id,
                    alert_id,
                    "actions.approval",
                    node="await_approval",
                    actor_type="user",
                    actor_id=data["decided_by"],
                    data={"approved": len(data["approved_action_ids"]), "rejected": len(data["rejected_action_ids"])},
                )
            await self._mark_processing(tenant_id, alert_id)
            log.info("workflow.resumed", resume_type=data["type"])
            return await self._invoke(graph, tenant_id, alert_id, Command(resume=data), config)

    # ------------------------------------------------------------ internals

    async def _thread_graph(self, tenant_id: str, alert_id: str, config: RunnableConfig) -> CompiledStateGraph:
        """The graph of the version the alert's thread started on (the current graph when it has none yet).

        Raises :class:`UnknownGraphVersion` when a checkpoint exists on a
        version this worker does not have: such a run never runs on another graph.
        """
        try:
            version = (await self.repos.runs.get(tenant_id, alert_id)).graph_version
        except NotFound:  # an engine call without a run row (eval)
            version = None
        version = UNVERSIONED_GRAPH if version is None else version
        graph = self.graphs.get(version)
        if graph is not None:
            return graph
        if await self._checkpointer.aget_tuple(config) is None:
            return self.graph  # nothing ran on that version: a fresh thread starts on the current graph
        log.error("workflow.unknown_graph_version", graph_version=version, known=sorted(self.graphs))
        raise UnknownGraphVersion(
            f"run is checkpointed on graph version {version}; this worker runs versions {sorted(self.graphs)}"
        )

    async def _continue(
        self, graph: CompiledStateGraph, tenant_id: str, alert_id: str, snapshot: Any, config: RunnableConfig
    ) -> RunOutcome:
        """Continue an unfinished checkpoint.

        When only ``close`` is left, the alert may already be ``closed`` (the
        close transaction committed but its checkpoint was not written);
        ``close`` is idempotent, so it simply runs again.
        """
        remaining = self._unfinished(snapshot)
        log.info("workflow.continue_checkpoint", next=list(remaining))
        alert = await self.repos.alerts.get(tenant_id, alert_id)
        if not (alert.status == "closed" and set(remaining) <= {"close"}):
            await self._mark_processing(tenant_id, alert_id)
        return await self._invoke(graph, tenant_id, alert_id, None, config)

    async def _initial_state(self, tenant_id: str, alert: Alert) -> WorkflowState:
        tenant = await self.repos.tenants.get(tenant_id)
        return initial_state(tenant_id, alert, llm_budget_limit=token_budget(tenant.settings))

    async def _invoke(
        self, graph: CompiledStateGraph, tenant_id: str, alert_id: str, graph_input: Any, config: RunnableConfig
    ) -> RunOutcome:
        try:
            await graph.ainvoke(graph_input, config, durability="sync")
        except Exception as exc:
            log_failure(log, "workflow.run_failed", exc, error_type=type(exc).__name__)
            await self._mark_failed(tenant_id, alert_id)
            raise
        snapshot = await graph.aget_state(config)
        pending = self._pending_interrupt(snapshot)
        if pending is not None:
            return await self._waiting(tenant_id, alert_id, pending)
        if remaining := self._unfinished(snapshot):
            raise WorkflowError(f"workflow stopped before finishing (next={list(remaining)})")
        alert = await self.repos.alerts.get(tenant_id, alert_id)
        await self._prune_checkpoints(config)
        log.info("workflow.completed", alert_status=alert.status, disposition=alert.disposition)
        return RunOutcome("completed", alert.status, None)

    async def _prune_checkpoints(self, config: RunnableConfig) -> None:
        """Keep only the final checkpoint of a finished run (the one ``aget_state`` reads).

        Each node boundary writes a checkpoint (``durability="sync"``), about
        eight per alert; once the run is finished only the last one is ever
        read again. Best effort: retention removes whatever a failure leaves.
        """
        try:
            removed = await self._checkpointer.aprune_thread(config["configurable"]["thread_id"])
        except Exception as exc:  # noqa: BLE001 - storage housekeeping must never fail a finished run
            log_failure(log, "workflow.checkpoint_prune_failed", exc, level="warning", error_type=type(exc).__name__)
            return
        log.debug("workflow.checkpoints_pruned", removed=removed)

    async def _waiting(self, tenant_id: str, alert_id: str, pending: Dict[str, Any]) -> RunOutcome:
        target = WAITING_STATUS.get(str(pending.get("type")))
        if target is None:
            raise WorkflowError(f"unknown interrupt type {pending.get('type')!r}")
        alert = await self.repos.alerts.get(tenant_id, alert_id)
        if alert.status != target:
            if alert.status != "processing":
                await self._mark_processing(tenant_id, alert_id)
            alert = await self.repos.alerts.update_status(tenant_id, alert_id, target)
            await publish_event(self._events, "alert.updated", tenant_id, alert_id, {"status": target})
        log.info("workflow.waiting", alert_status=target)
        return RunOutcome(target, alert.status, dict(pending))  # type: ignore[arg-type]

    async def _mark_processing(self, tenant_id: str, alert_id: str) -> None:
        alert = await self.repos.alerts.get(tenant_id, alert_id)
        path: Tuple[str, ...] = ()
        if alert.status == "new":
            path = ("queued", "processing")
        elif alert.status in ("queued", "failed", "waiting_human", "waiting_approval"):
            path = ("processing",)
        elif alert.status != "processing":
            raise InvalidTransition("alert", alert_id, alert.status, "processing")
        for status in path:
            await self.repos.alerts.update_status(tenant_id, alert_id, status)
        if path:
            await publish_event(self._events, "alert.updated", tenant_id, alert_id, {"status": "processing"})

    async def _mark_failed(self, tenant_id: str, alert_id: str) -> None:
        try:
            alert = await self.repos.alerts.get(tenant_id, alert_id)
            if alert.status == "closed":
                # Only close's own bookkeeping failed; the redelivered run finishes it.
                return
            await self.repos.alerts.update_status(tenant_id, alert_id, "failed")
        except (DatabaseError, OSError) as exc:
            # The original node error is what the worker must see; this write is secondary.
            log_failure(log, "workflow.mark_failed_error", exc, error_type=type(exc).__name__)
            return
        await publish_event(self._events, "alert.updated", tenant_id, alert_id, {"status": "failed"})
