"""Durable workflow engine: the compiled LangGraph with a Postgres checkpointer.

One engine per worker process. ``run`` starts a fresh run from the alert row
or continues an unfinished checkpoint; ``resume`` feeds an analyst decision
or an approval into the pending interrupt. The engine owns alert status and
summary writes, alert events, event publishing, escalations and the action
ledger; it never touches ``workflow_runs`` or the queue (the worker does).

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
from lg_sotf.core.checkpointer import TenantScopedPostgresSaver
from lg_sotf.core.events import EventPublisher, publish_event
from lg_sotf.core.graph import build_graph, cap_alert
from lg_sotf.core.nodes import NodeDeps, WorkflowNodes
from lg_sotf.core.retry import attempts_within_budget, build_retry_policy
from lg_sotf.core.verdict_cache import VerdictCache
from lg_sotf.db.errors import DatabaseError, InvalidTransition
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Alert, Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.db.urls import to_libpq_url, with_query_params
from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.errors import InvalidResumePayload, WorkflowError
from lg_sotf.llm import TokenBudget
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.security.hashing import indicator_hmac_key
from lg_sotf.services.escalation import EscalationService
from lg_sotf.services.response import Connector, ResponseService
from lg_sotf.settings import Settings

__all__ = [
    "AnalystDecisionPayload",
    "ApprovalPayload",
    "EventPublisher",
    "RunOutcome",
    "WorkflowEngine",
    "validate_resume_payload",
]

log = get_logger(__name__)

RECURSION_LIMIT = 60
WAITING_STATUS = {"analyst_decision": "waiting_human", "approval": "waiting_approval"}


@dataclass(frozen=True)
class RunOutcome:
    status: Literal["completed", "waiting_human", "waiting_approval"]
    alert_status: str
    interrupt: Optional[dict]


class AnalystDecisionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["analyst_decision"]
    escalation_id: str = Field(min_length=1, max_length=128)
    decision: Literal["true_positive", "false_positive", "benign_positive", "needs_more_info"]
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


class WorkflowEngine:
    def __init__(
        self,
        *,
        settings: Settings,
        repos: Repositories,
        graph: CompiledStateGraph,
        pool: AsyncConnectionPool,
        checkpointer: TenantScopedPostgresSaver,
        agents: AgentSet,
        escalations: EscalationService,
        events: Optional[EventPublisher],
    ) -> None:
        self.settings = settings
        self.repos = repos
        self.graph = graph
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
    ) -> WorkflowEngine:
        """Build agents and services, open the checkpointer pool and compile the graph.

        The checkpoint tables must exist (``lg-sotf migrate`` runs
        ``AsyncPostgresSaver.setup()``). Raises
        :class:`~lg_sotf.security.hashing.SecurityConfigError` when
        ``security.indicator_hmac_key`` is missing or unusable: correlation
        needs it for every alert with indicators, so a worker without it
        must not start and fail each run instead.
        """
        indicator_hmac_key(settings)
        repos = Repositories.create(db)
        agent_set = agents or AgentSet.build(settings)
        await agent_set.initialize()
        escalations = EscalationService(repos, events, settings)
        responses = ResponseService(repos, settings, events, connectors=connectors)
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
        graph = build_graph(
            WorkflowNodes(deps),
            deps.thresholds,
            retry_policy=build_retry_policy(
                attempts_within_budget(settings.worker.node_timeout_s, settings.worker.run_timeout_s)
            ),
            node_retry_policies={
                "analysis": build_retry_policy(
                    attempts_within_budget(settings.worker.analysis_timeout_s, settings.worker.run_timeout_s)
                )
            },
        ).compile(checkpointer=checkpointer)
        return cls(
            settings=settings,
            repos=repos,
            graph=graph,
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
            snapshot = await self.graph.aget_state(config)
            pending = self._pending_interrupt(snapshot)
            if pending is not None:
                return await self._waiting(tenant_id, alert_id, pending)
            if self._unfinished(snapshot):
                return await self._continue(tenant_id, alert_id, snapshot, config)
            if snapshot.values:
                if alert.status not in ("new", "queued"):
                    return RunOutcome("completed", alert.status, None)
                await self._checkpointer.adelete_thread(config["configurable"]["thread_id"])
            await self._mark_processing(tenant_id, alert_id)
            initial = await self._initial_state(tenant_id, alert)
            log.info("workflow.started")
            return await self._invoke(tenant_id, alert_id, initial, config)

    async def resume(self, tenant_id: str, alert_id: str, payload: Mapping[str, Any]) -> RunOutcome:
        """Deliver an analyst decision or approval to the run's pending interrupt."""
        data = validate_resume_payload(payload)
        config = self._config(tenant_id, alert_id)
        with bound_context(tenant_id=tenant_id, alert_id=alert_id, thread_id=config["configurable"]["thread_id"]):
            snapshot = await self.graph.aget_state(config)
            pending = self._pending_interrupt(snapshot)
            if pending is None:
                if self._unfinished(snapshot):
                    return await self._continue(tenant_id, alert_id, snapshot, config)
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
            return await self._invoke(tenant_id, alert_id, Command(resume=data), config)

    # ------------------------------------------------------------ internals

    async def _continue(self, tenant_id: str, alert_id: str, snapshot: Any, config: RunnableConfig) -> RunOutcome:
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
        return await self._invoke(tenant_id, alert_id, None, config)

    async def _initial_state(self, tenant_id: str, alert: Alert) -> Dict[str, Any]:
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
        tenant = await self.repos.tenants.get(tenant_id)
        limit = tenant.settings.get("llm_daily_token_budget")
        return {
            "tenant_id": tenant_id,
            "alert_id": alert.id,
            "severity": alert.severity,
            "fingerprint": alert.fingerprint,
            "alert": cap_alert(canonical),
            "confidence": 50,
            "gate": {},
            "triage": {},
            "correlation": {},
            "analysis": {},
            "analysis_runs": 0,
            "more_info_loops": 0,
            "decision": {},
            "escalation_id": None,
            "analyst": None,
            "plan": {},
            "awaiting_actions": [],
            "approval": None,
            "executed": {},
            "disposition": None,
            "close_reason": None,
            "llm_budget_exceeded": False,
            "llm_budget_limit": limit if isinstance(limit, int) and not isinstance(limit, bool) else None,
            "notes": [],
        }

    async def _invoke(self, tenant_id: str, alert_id: str, graph_input: Any, config: RunnableConfig) -> RunOutcome:
        try:
            await self.graph.ainvoke(graph_input, config, durability="sync")
        except Exception as exc:
            log.error("workflow.run_failed", error_type=type(exc).__name__)
            await self._mark_failed(tenant_id, alert_id)
            raise
        snapshot = await self.graph.aget_state(config)
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
            log.warning("workflow.checkpoint_prune_failed", error_type=type(exc).__name__)
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
            log.error("workflow.mark_failed_error", error_type=type(exc).__name__)
            return
        await publish_event(self._events, "alert.updated", tenant_id, alert_id, {"status": "failed"})
