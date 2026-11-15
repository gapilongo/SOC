"""The investigation executor (AI-E3.3): code that runs a skill's queries and writes the fact ledger.

:meth:`SkillInvestigator.investigate` is called by the analysis agent before the deep model. For an alert
whose source has evidence tools (a skill applies) and whose tenant switched every one of those tools on
(``tenants.settings.tools.<setting>.enabled`` exactly ``true``), it

1. builds the alert's typed view from the fields the detector wrote (:mod:`lg_sotf.domain.skill_views`);
2. runs the skill's queries in the order of the file, each through the tool registry
   (``ToolRegistry.call``) for the run's own tenant and alert, with arguments bound by code;
3. records every call on the run's fact ledger, whatever its outcome (``success``, ``empty``,
   ``failed``), so the ids a verdict may cite exist before any model sees them;
4. stops at a budget (:mod:`lg_sotf.domain.investigation_budget`) or when the breaker opens: after
   ``investigation.breaker_failures`` calls in a row gave no answer, the rest are skipped. A call that
   says the alert has no event data to read at all (:data:`NO_SOURCE_ERRORS`) skips the rest at once.
   A failed step's reason is the tool's own fixed code (``unreachable``, ``credentials_refused``...).

It makes no model call and takes no input from one: the plan is the reviewed file, the values are the
view's, the budget is the install's and the tenant's. Text inside a returned fact is data on the ledger
and changes none of them.

**It never fails the alert's run.** Any stop that is not ``finished``, a run that returned no fact, and
any error in here give :attr:`InvestigationRun.context` ``None``: the analysis then runs exactly as it
does without the harness, and :attr:`InvestigationRun.reason` says why. Nothing here closes or escalates
an alert.

**Resume and retry.** A query whose answer is already on the run's ledger (same evidence id, tool, version
and input hash; ``success`` or ``empty``) is not sent again: its entries are reused. So a node retried
after a crash between two calls sends only the calls that have no answer yet. A call that failed is asked
again when the run is analysed again (a retried node, an analyst who asked for more): the breaker bounds
that to a few calls, and the ledger keeps one entry for the same failure, however often it repeats.

**No settle delay** (Amendment 1 point 2): the queries run at once. A fact whose window had not closed
says ``complete: false``, which the tools compute.

For any other alert :meth:`investigate` returns ``None`` and nothing is recorded: today's path, unchanged.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import ValidationError

from lg_sotf.agents.base import AgentContext
from lg_sotf.agents.investigation.catalog import check_catalog, load_catalog
from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.domain.investigation_budget import Budget, BudgetLimits, tenant_limits
from lg_sotf.domain.ledger import LedgerEntry, ToolStep
from lg_sotf.domain.skill_views import VIEWS
from lg_sotf.domain.skills import bind, indicator_states, select_skill
from lg_sotf.llm.trace import tool_input_hash
from lg_sotf.models.skill import EvidenceRef, SkillSpec
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.settings import Settings
from lg_sotf.tools.registry import ToolRegistry, ToolSpec

__all__ = ["AGENT", "InvestigationRun", "SkillInvestigator", "StepRecord", "switched_on"]

log = get_logger(__name__)

AGENT = "investigation"
WALL_SHARE = 0.25
"""The most of the analysis node's time an investigation may take; the model's own share comes after it."""
FINISHED = "finished"
CIRCUIT_OPEN = "circuit_open"
BUDGET_WALL = "budget_wall"
SKIPPED = "skipped"
NO_FACTS, NO_RUN_ID, ERROR = "no_facts", "no_run_id", "error"
NO_SOURCE, NO_MODEL = "no_source", "no_model"
NO_BINDING, BINDING_REFUSED = "no_binding", "binding_refused"
BUDGET_STOPS = ("budget_steps", BUDGET_WALL, "budget_tokens", "budget_usd")
"""What :meth:`lg_sotf.domain.investigation_budget.Budget.spent` answers when a budget is spent."""
DEGRADED_REASONS = (*BUDGET_STOPS, CIRCUIT_OPEN, NO_SOURCE, NO_FACTS, NO_RUN_ID, NO_MODEL, ERROR)
"""Every value of :attr:`InvestigationRun.reason`: why the analysis ran without the evidence."""
SKIP_REASONS = (NO_BINDING, BINDING_REFUSED, CIRCUIT_OPEN, NO_SOURCE, *BUDGET_STOPS)
"""Every reason of a skipped :class:`StepRecord`. The investigation view has a sentence for each of both."""
NO_SOURCE_ERRORS = frozenset({"no_wazuh_source", "not_configured", "no_telemetry"})
"""A tool's fixed error codes that say this alert has no event data to read at all (an alert pushed by a
source that is not a Wazuh indexer source; an alert the telemetry store does not hold): no other query of
the alert can answer, so the rest are skipped at once."""
REPORTED = "reported"


def switched_on(tenant_settings: Any, tool_settings: Sequence[str]) -> bool:
    """Whether the tenant turned every one of ``tool_settings`` on: ``tools.<setting>.enabled`` exactly ``True``.

    Stricter than the registry's own switch, which lets a tool run when its entry is absent: the harness
    is opt-in, so anything missing, malformed or unreadable is off.
    """
    tools = tenant_settings.get("tools") if isinstance(tenant_settings, Mapping) else None
    if not isinstance(tools, Mapping) or not tool_settings:
        return False
    entries = [tools.get(setting) for setting in tool_settings]
    return all(isinstance(entry, Mapping) and entry.get("enabled") is True for entry in entries)


@dataclass(frozen=True)
class StepRecord:
    """One query of the plan: what became of it, and the ledger ids it produced."""

    evidence_id: str
    tool: str
    outcome: str
    """``success``, ``empty`` or ``failed`` (on the ledger), or ``skipped`` (no call was made)."""
    reason: Optional[str] = None
    fact_ids: Tuple[str, ...] = ()
    complete: bool = False
    reused: bool = False
    """The call was already on the run's ledger (a resumed or retried run): it was not sent again."""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id, "tool": self.tool, "outcome": self.outcome, "reason": self.reason,
            "fact_ids": list(self.fact_ids), "complete": self.complete, "reused": self.reused,
        }


@dataclass
class InvestigationRun:
    """What one investigation did. ``context`` is what the deep model is shown; ``None``: today's path."""

    skill_id: str
    skill_version: str
    run_id: Optional[str] = None
    stop_reason: str = FINISHED
    steps: List[StepRecord] = field(default_factory=list)
    budget: Dict[str, Dict[str, float]] = field(default_factory=dict)
    indicators: Dict[str, str] = field(default_factory=dict)
    facts: int = 0
    context: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    """Why the analysis went on without the evidence (``None`` when it was shown): one of
    :data:`DEGRADED_REASONS`."""
    ledger: Tuple[LedgerEntry, ...] = field(default=(), repr=False)
    """The run's ledger as the executor left it: what a claim's citations are checked against. Not stored."""

    def _count(self, outcome: str) -> int:
        return sum(step.outcome == outcome for step in self.steps)

    def digest(self) -> Dict[str, Any]:
        """Small enough for graph state and the node's timeline event: counts and codes, no fact."""
        return {
            "status": "completed" if self.reason is None else "degraded", "reason": self.reason,
            "skill": self.skill_id, "skill_version": self.skill_version, "stop_reason": self.stop_reason,
            "lookups": len(self.steps) - self._count(SKIPPED), "facts": self.facts,
            "empty": self._count("empty"), "failed": self._count("failed"), "skipped": self._count(SKIPPED),
        }

    def record(self) -> Dict[str, Any]:
        """For ``alerts.summary.analysis.investigation``: the digest, the plan's steps, budgets and indicators."""
        return {
            **self.digest(), "run_id": self.run_id, "steps": [step.as_dict() for step in self.steps],
            "budget": self.budget, "indicators": self.indicators,
        }


def _occurred_at(alert: Mapping[str, Any]) -> Optional[datetime]:
    try:
        at = datetime.fromisoformat(str(alert.get("occurred_at")))
    except ValueError:
        return None
    return at if at.tzinfo is not None else None


def _step(ref: EvidenceRef, entries: Sequence[LedgerEntry], *, reused: bool) -> StepRecord:
    first = entries[0]
    return StepRecord(
        ref.id, ref.tool_name, first.outcome, first.reason, tuple(entry.fact_id for entry in entries),
        all(entry.complete for entry in entries), reused,
    )


class SkillInvestigator:
    """Runs the skill of an alert. One per process: it holds no state of a run."""

    def __init__(
        self,
        registry: ToolRegistry,
        settings: Settings,
        *,
        catalog: Optional[Sequence[SkillSpec]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Raises :class:`lg_sotf.agents.investigation.catalog.SkillError` for a catalogue that does not
        fit the registry: an invalid skill stops the process, it never runs half."""
        self.registry = registry
        self.catalog: Tuple[SkillSpec, ...] = tuple(catalog) if catalog is not None else load_catalog()
        check_catalog(self.catalog, registry)
        self._config = settings.investigation
        self._wall_cap_s = max(settings.worker.analysis_timeout_s * WALL_SHARE, 0.001)
        self._clock = clock

    def limits(self, tenant_settings: Any) -> BudgetLimits:
        default, maximum = self._config.budget, self._config.tenant_max
        return tenant_limits(
            BudgetLimits(default.steps, default.wall_s, default.tokens, default.usd),
            BudgetLimits(maximum.steps, maximum.wall_s, maximum.tokens, maximum.usd),
            tenant_settings if isinstance(tenant_settings, Mapping) else None,
            wall_cap_s=self._wall_cap_s,
        )

    def _tool_settings(self, skill: SkillSpec) -> List[str]:
        specs = [self.registry.get(ref.tool_name) for ref in skill.evidence]
        return sorted({spec.tenant_setting for spec in specs if spec.tenant_setting is not None})

    async def investigate(self, ctx: AgentContext, alert: Mapping[str, Any]) -> Optional[InvestigationRun]:
        """Run the alert's skill; ``None`` when no skill applies or the tenant has not switched it on."""
        skill = select_skill(alert, self.catalog)
        if skill is None or ctx.repos is None:
            return None
        run = InvestigationRun(skill.id, skill.version, ctx.investigation_run_id)
        try:
            tenant = await ctx.repos.tenants.get(ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001 - a switch that cannot be read is off: today's path, no record
            log_failure(log, "investigation.switch_unreadable", exc, level="warning", error_type=type(exc).__name__)
            return None
        try:
            if not switched_on(tenant.settings, self._tool_settings(skill)):
                return None
            if not ctx.investigation_run_id:  # a run started before the id existed has no ledger
                run.stop_reason = run.reason = NO_RUN_ID
                return run
            await self._run(ctx, alert, skill, run, Budget(self.limits(tenant.settings), self._clock))
        except Exception as exc:  # noqa: BLE001 - an investigation never fails the alert's run
            log_failure(log, "investigation.failed", exc, level="warning", error_type=type(exc).__name__, skill=skill.id)
            run.stop_reason = run.reason = ERROR
            run.context = None
        return run

    async def _run(
        self, ctx: AgentContext, alert: Mapping[str, Any], skill: SkillSpec, run: InvestigationRun, budget: Budget
    ) -> None:
        ledger = FactLedger.for_run(ctx)
        view, at = VIEWS[skill.view](alert), _occurred_at(alert)
        failures = 0
        halted: Optional[str] = None
        try:
            for ref in skill.evidence:
                spec = self.registry.get(ref.tool_name)
                broken = CIRCUIT_OPEN if failures >= self._config.breaker_failures else None
                stop = halted or broken or budget.spent(next_usd=spec.price_usd)
                if stop is not None:
                    run.stop_reason = stop
                    run.steps.append(StepRecord(ref.id, ref.tool_name, SKIPPED, stop))
                    continue
                done = await self._query(ctx, ledger, ref, spec, bind(ref.args, view, at) if at else None, budget)
                run.steps.append(done)
                if done.outcome == "failed":
                    failures += 1
                    if done.reason == BUDGET_WALL:  # cut while it ran: the budget is spent even if it was the last
                        run.stop_reason = BUDGET_WALL
                    elif done.reason in NO_SOURCE_ERRORS:  # nothing to read for this alert: ask nothing more
                        run.stop_reason = halted = NO_SOURCE
                elif done.outcome in ("success", "empty"):
                    failures = 0
        finally:
            run.budget = budget.used()
        entries = await ledger.facts()
        run.ledger = entries
        run.facts = sum(entry.fact is not None for entry in entries)
        run.indicators = indicator_states(skill, entries)
        if run.stop_reason != FINISHED:
            run.reason = run.stop_reason
        elif run.facts == 0:
            run.reason = NO_FACTS
        else:
            run.context = await ledger.planner_context()
        log.info("investigation.completed", **run.digest())

    async def _query(
        self, ctx: AgentContext, ledger: FactLedger, ref: EvidenceRef, spec: ToolSpec,
        args: Optional[Dict[str, Any]], budget: Budget,
    ) -> StepRecord:
        """One query of the plan: skipped without values, reused from the ledger, or called and recorded."""
        if args is None:
            return StepRecord(ref.id, ref.tool_name, SKIPPED, NO_BINDING)
        try:
            valid = spec.params.model_validate(args)
        except ValidationError:  # a view value the tool's own parameter model refuses: the query is skipped
            return StepRecord(ref.id, ref.tool_name, SKIPPED, BINDING_REFUSED)
        input_hash = tool_input_hash(spec.traced_as, valid.model_dump(mode="json"))
        call = (ref.id, spec.name, spec.version, input_hash)
        known = [
            e for e in await ledger.facts()
            if (e.evidence_id, e.tool, e.tool_version, e.input_hash) == call and e.outcome != "failed"
        ]
        if known:  # an answer the run already has (a resumed or retried run): not asked again
            budget.charge(steps=1)
            return _step(ref, known, reused=True)
        budget.charge(steps=1, usd=spec.price_usd)
        deadline = asyncio.timeout(budget.remaining_s)
        try:
            async with deadline:
                result = await self.registry.call(ctx, ref.tool_name, args, agent=AGENT)
            step = tool_step(ref.id, spec, result)
            error = getattr(result.value, "error", None)
            if step.outcome == "failed" and step.reason == REPORTED and isinstance(error, str) and error:
                step = replace(step, reason=error[:64])  # the tool's own fixed code says why, not "reported"
        except TimeoutError:
            if not deadline.expired():  # not this budget's timeout: an error like any other
                raise
            step = ToolStep(ref.id, spec.name, spec.version, input_hash, None, "failed", False, BUDGET_WALL)
        return _step(ref, await ledger.record(step), reused=False)
