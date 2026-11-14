"""The fact ledger of one investigation run (AI-E3.2): the only place a fact gets an id.

The executor calls a tool through the registry and hands the result to the ledger::

    ledger = FactLedger.for_run(ctx)
    result = await registry.call(ctx, "wazuh.host_activity", params, agent="investigation")
    entries = await ledger.record(tool_step("host", registry.get("wazuh.host_activity"), result))
    ...
    await ledger.facts()            # everything the run observed, in order
    await ledger.planner_context()  # what a prompt may show of it, for the untrusted tool_data block

:meth:`FactLedger.record` mints the ids (``host:0``, ``host:1``...), binds each entry to the call (tool,
version, the trace step's hashes, outcome, completeness, time) and appends it to the tenant's
``evidence_facts`` before anything can cite it. An empty or failed call is recorded too, as an entry
without a fact. The model never writes to the ledger and never supplies an id: a verdict's citations are
checked against :meth:`FactLedger.facts` with :func:`lg_sotf.domain.ledger.check_citations`.

**The run.** The tenant, the alert and the investigation run id come from the run's context
(``ctx.investigation_run_id``, minted with the workflow run's first state), never from a parameter. A
resumed run and a retried node have the same id and so the same ledger; a reprocessed alert has a new
one and starts empty. A context without the id has no ledger: :meth:`FactLedger.for_run` raises.

**Recording twice.** The same call recorded again (a node retried after a crash) returns the entries the
run already has and mints nothing. A call that does not fit in the run's ledger is recorded as one failed
entry (``ledger_capacity``), never an exception.

**The store is the ledger.** A ``FactLedger`` keeps no copy: every ``record`` and ``facts`` reads the
run's entries from the store, so two ledgers of one run always agree, and the table refuses an id minted
twice (the loser reads again and takes the next number). Keep one ledger per run all the same.

**Shadow runs and replays.** A shadow run writes nothing: its entries stay with the shadow run
(``ShadowRun.ledger``), shared by every ledger made for it. A replay that does not persist
(``ctx.persist`` false) keeps its entries in the one ``FactLedger`` it made: make one per replayed run.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple, get_args

from lg_sotf.agents.base import AgentContext
from lg_sotf.db.errors import Conflict
from lg_sotf.domain.ledger import LedgerEntry, LedgerError, ToolStep, plan_record, planner_view
from lg_sotf.models.evidence_fact import EvidenceFact
from lg_sotf.security.shadow import active_shadow_run
from lg_sotf.tools.registry import ToolResult, ToolSpec

__all__ = ["FactLedger", "LedgerStore", "MemoryLedgerStore", "tool_step"]

_FACT_TYPES: Tuple[type, ...] = get_args(get_args(EvidenceFact)[0])
_Row = Tuple[Tuple[str, str, str], LedgerEntry]


class LedgerStore(Protocol):
    """Where a run's entries are kept (``lg_sotf.db.repos.evidence_facts.EvidenceFactsRepo`` is one).

    ``append`` raises :class:`lg_sotf.db.errors.Conflict` for an id the run already has.
    """

    async def append(self, tenant_id: str, alert_id: str, run_id: str, entries: Sequence[LedgerEntry]) -> int: ...

    async def list_for_run(self, tenant_id: str, alert_id: str, run_id: str) -> Sequence[LedgerEntry]: ...


class MemoryLedgerStore:
    """A store in memory, for a run that writes nothing: the rows live in the list it is given."""

    def __init__(self, rows: Optional[List[Any]] = None) -> None:
        self._rows: List[_Row] = rows if rows is not None else []

    async def append(self, tenant_id: str, alert_id: str, run_id: str, entries: Sequence[LedgerEntry]) -> int:
        key = (tenant_id, alert_id, run_id)
        taken = {entry.fact_id for at, entry in self._rows if at == key}
        if taken & {entry.fact_id for entry in entries}:
            raise Conflict("a ledger entry with the same id already exists in the run")
        self._rows.extend((key, entry) for entry in entries)
        return len(entries)

    async def list_for_run(self, tenant_id: str, alert_id: str, run_id: str) -> Sequence[LedgerEntry]:
        return [entry for at, entry in self._rows if at == (tenant_id, alert_id, run_id)]


def _typed_facts(value: Any) -> Tuple[EvidenceFact, ...]:
    """The answer's facts when it is a collection of typed evidence facts and nothing else; otherwise none."""
    if isinstance(value, (list, tuple)) and value and all(isinstance(item, _FACT_TYPES) for item in value):
        return tuple(value)
    return ()


def tool_step(
    evidence_id: str, spec: ToolSpec, result: ToolResult[Any], facts: Optional[Sequence[EvidenceFact]] = None
) -> ToolStep:
    """One registry call as the ledger records it.

    ``facts`` are the typed facts a mapper made of the answer; by default, the answer itself when it is a
    collection of evidence facts. Anything else a tool returned (text, provider rows) is not a fact and
    never enters the ledger. A fact of a kind the tool did not declare (``ToolSpec.produces``) is refused.
    """
    if facts is not None:
        found = tuple(facts)
    else:
        found = _typed_facts(result.value) if result.outcome == "success" else ()
    undeclared = sorted({fact.kind for fact in found} - set(spec.produces))
    if undeclared:
        raise LedgerError(f"{spec.name} does not declare the fact kinds: {', '.join(undeclared)}")
    return ToolStep(
        evidence_id=evidence_id, tool=spec.name, tool_version=spec.version, input_hash=result.input_hash,
        output_hash=result.output_hash or None, outcome=result.outcome, complete=result.complete,
        reason=result.reason, facts=found,
    )


def _now() -> datetime:
    return datetime.now(UTC)


class FactLedger:
    """What one investigation run observed. Bound to the run's tenant, alert and run id for its whole life."""

    def __init__(
        self,
        tenant_id: str,
        alert_id: str,
        run_id: str,
        store: Optional[LedgerStore] = None,
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if not run_id:
            raise LedgerError("a ledger belongs to an investigation run: it needs the run's id")
        self.tenant_id = tenant_id
        self.alert_id = alert_id
        self.run_id = run_id
        self._store: LedgerStore = store if store is not None else MemoryLedgerStore()
        self._clock = clock
        self._lock = asyncio.Lock()

    @classmethod
    def for_run(cls, ctx: AgentContext) -> FactLedger:
        """The ledger of the investigation run ``ctx`` belongs to.

        Stored under the run's tenant when the run persists; kept with the shadow run in shadow mode; in
        memory for a replay that does not persist. Raises without ``ctx.investigation_run_id`` (a run
        started before the id existed): the alert's thread id is never used in its place, because a
        reprocessed alert keeps its thread id and would inherit the earlier investigation's facts.
        """
        if not ctx.investigation_run_id:
            raise LedgerError("the run has no investigation run id: it has no fact ledger")
        shadow = active_shadow_run()
        store: LedgerStore
        if shadow is not None:
            store = MemoryLedgerStore(shadow.ledger)
        elif ctx.repos is not None and ctx.persist:
            store = ctx.repos.evidence_facts
        else:
            store = MemoryLedgerStore()
        return cls(ctx.tenant_id, ctx.alert_id, ctx.investigation_run_id, store)

    async def _entries(self) -> Sequence[LedgerEntry]:
        return await self._store.list_for_run(self.tenant_id, self.alert_id, self.run_id)

    async def record(self, step: ToolStep) -> Tuple[LedgerEntry, ...]:
        """Record one tool call: an entry per typed fact, or one entry without a fact. Returns the call's entries.

        The entries are stored before they are returned, so nothing can cite a fact the ledger does not
        hold. The same call again returns the entries it already has. A call that does not fit is one
        failed entry (``ledger_capacity``, ``fact_too_large``). A step the ledger refuses (a fact on a
        failed call, an evidence id that is not one) or a store that is down raises and records nothing.
        """
        async with self._lock:
            planned = plan_record(step, await self._entries(), self._clock())
            if not planned.new:
                return planned.entries
            try:
                await self._store.append(self.tenant_id, self.alert_id, self.run_id, planned.new)
            except Conflict:
                # Another writer of the run took the id between the read and the write: read again, once.
                planned = plan_record(step, await self._entries(), self._clock())
                if planned.new:
                    await self._store.append(self.tenant_id, self.alert_id, self.run_id, planned.new)
            return planned.entries

    async def facts(self) -> Tuple[LedgerEntry, ...]:
        """Every entry of the run as the store holds it now, in the order it was recorded: the ledger a
        verdict's citations are checked against."""
        return tuple(await self._entries())

    async def planner_context(self) -> Dict[str, Any]:
        """The run's observations for a prompt's untrusted ``tool_data`` block: typed fields only, bounded.

        ``omitted`` is how many entries did not fit (``lg_sotf.domain.ledger.MAX_PLANNER_CHARS``).
        """
        entries = await self.facts()
        shown = planner_view(entries)
        return {"observations": shown, "total": len(entries), "omitted": len(entries) - len(shown)}
