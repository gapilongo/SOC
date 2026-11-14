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
``evidence_facts`` before anything can cite it. The tenant, the alert and the run come from the run's
context, never from a parameter. An empty or failed call is recorded too, as an entry without a fact.
The model never writes to the ledger and never supplies an id: a verdict's citations are checked against
:meth:`FactLedger.facts` with :func:`lg_sotf.domain.ledger.check_citations`.

A shadow run and a replay that does not persist (``ctx.persist`` false) keep their ledger in memory.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Tuple, get_args

from lg_sotf.agents.base import AgentContext
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.ledger import LedgerEntry, LedgerError, ToolStep, build_entries, planner_view
from lg_sotf.models.evidence_fact import EvidenceFact
from lg_sotf.tools.registry import ToolResult, ToolSpec

__all__ = ["FactLedger", "LedgerStore", "tool_step"]

_FACT_TYPES: Tuple[type, ...] = get_args(get_args(EvidenceFact)[0])


class LedgerStore(Protocol):
    """Where a run's entries are kept (``lg_sotf.db.repos.evidence_facts.EvidenceFactsRepo`` is one)."""

    async def append(self, tenant_id: str, alert_id: str, run_id: str, entries: Sequence[LedgerEntry]) -> int: ...

    async def list_for_run(self, tenant_id: str, alert_id: str, run_id: str) -> Sequence[LedgerEntry]: ...


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
    """What one run observed. Bound to the run's tenant, alert and run id for its whole life."""

    def __init__(
        self,
        tenant_id: str,
        alert_id: str,
        run_id: str,
        store: Optional[LedgerStore] = None,
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.tenant_id = tenant_id
        self.alert_id = alert_id
        self.run_id = run_id
        self._store = store
        self._clock = clock
        self._entries: Optional[List[LedgerEntry]] = None
        self._lock = asyncio.Lock()

    @classmethod
    def for_run(cls, ctx: AgentContext) -> FactLedger:
        """The ledger of the run ``ctx`` belongs to, stored under the run's tenant when the run persists."""
        store = ctx.repos.evidence_facts if ctx.repos is not None and ctx.persist else None
        return cls(ctx.tenant_id, ctx.alert_id, ctx.run_id or thread_id_for(ctx.tenant_id, ctx.alert_id), store)

    async def _loaded(self) -> List[LedgerEntry]:
        """The run's entries: what the store already holds for it (a resumed run), then what this ledger added."""
        if self._entries is None:
            stored = await self._store.list_for_run(self.tenant_id, self.alert_id, self.run_id) if self._store else ()
            self._entries = list(stored)
        return self._entries

    async def record(self, step: ToolStep) -> Tuple[LedgerEntry, ...]:
        """Record one tool call: an entry per typed fact, or one entry without a fact. Returns the new entries.

        The entries are stored before they are returned, so nothing can cite a fact the ledger does not
        hold. A step the ledger or the store refuses raises and records nothing; after a refused write the
        run's entries are read again, so an id another writer of the same run took is not minted twice.
        """
        async with self._lock:
            entries = await self._loaded()
            new = build_entries(step, [entry.fact_id for entry in entries], self._clock())
            if self._store is not None:
                try:
                    await self._store.append(self.tenant_id, self.alert_id, self.run_id, new)
                except Exception:
                    self._entries = None
                    raise
            entries.extend(new)
            return new

    async def facts(self) -> Tuple[LedgerEntry, ...]:
        """Every entry of the run, in the order it was recorded: the ledger a verdict's citations are checked against."""
        async with self._lock:
            return tuple(await self._loaded())

    async def planner_context(self) -> Dict[str, Any]:
        """The run's observations for a prompt's untrusted ``tool_data`` block: typed fields only."""
        return {"observations": planner_view(await self.facts())}
