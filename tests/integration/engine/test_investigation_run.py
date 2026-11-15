"""The investigation run id (AI-E3.2): minted when a workflow run starts, kept in its state, new on reprocess.

The fact ledger is kept under this id, never under the alert's thread id: a reprocessed alert keeps its
thread id, and would otherwise inherit the earlier investigation's facts. Driven through the real engine
(PostgreSQL checkpointer): a node that crashes and runs again, an analyst's decision, a reprocess.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

import pytest

from lg_sotf.agents.investigation.ledger import FactLedger, tool_step
from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.domain.ledger import RUN_ID_PATTERN
from tests.integration.db._support import TENANT_A
from tests.integration.engine._support import analyst, suspicious_alert
from tests.unit.agents.investigation._support import TOOL, fact_tools, host_fact
from tests.unit.tools._support import Handler, P

pytestmark = pytest.mark.integration


async def test_a_run_keeps_its_ledger_through_a_retry_and_a_resume_and_a_reprocess_starts_a_new_one(
    engine: WorkflowEngine, repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    alert_id = await suspicious_alert(repos)
    config = {"configurable": {"thread_id": thread_id_for(TENANT_A, alert_id)}}
    tools = fact_tools(Handler(answer=(host_fact(),)))
    triage = engine.agents.triage.run
    runs: List[Optional[str]] = []
    recorded: List[Tuple[str, ...]] = []
    found_on_arrival: List[int] = []

    async def investigating(ctx: Any, *args: Any, **kwargs: Any) -> Any:
        """What the executor will do in a node: call a tool, record it on the run's ledger."""
        runs.append(ctx.investigation_run_id)
        ledger = FactLedger.for_run(ctx)
        found_on_arrival.append(len(await ledger.facts()))
        result = await tools.call(ctx, TOOL, P, agent="investigation")
        recorded.append(tuple(e.fact_id for e in await ledger.record(tool_step("host", tools.get(TOOL), result))))
        if len(runs) == 1:
            raise RuntimeError("the node crashed after it recorded")
        return await triage(ctx, *args, **kwargs)

    monkeypatch.setattr(engine.agents.triage, "run", investigating)

    with pytest.raises(RuntimeError, match="crashed after it recorded"):
        await engine.run(TENANT_A, alert_id)
    first = await engine.run(TENANT_A, alert_id)  # the unfinished run goes on: the node runs again
    assert first.status == "waiting_human"

    # The retried node is the same investigation: same id, and the same call is on the ledger once.
    run_id = runs[0]
    assert run_id is not None and re.fullmatch(RUN_ID_PATTERN, run_id) and runs == [run_id, run_id]
    assert recorded == [("host:0",), ("host:0",)]
    assert [e.fact_id for e in await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)] == ["host:0"]
    assert (await engine.graph.aget_state(config)).values["investigation_run_id"] == run_id

    # A resume (the analyst decides) is still that run.
    done = await engine.resume(
        TENANT_A, alert_id,
        {"type": "analyst_decision", "escalation_id": first.interrupt["escalation_id"], "decision": "false_positive",
         "approved_actions": [], "decided_by": await analyst(repos), "notes": "known admin tooling"},
    )
    assert done.alert_status == "closed"
    assert (await engine.graph.aget_state(config)).values["investigation_run_id"] == run_id

    # The alert is processed again on the same thread id: a new investigation, with an empty ledger.
    await repos.alerts.update_status(TENANT_A, alert_id, "queued")
    await engine.run(TENANT_A, alert_id)
    again = runs[2]
    assert len(runs) == 3 and again is not None and again != run_id and recorded[2] == ("host:0",)
    earlier = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, run_id)
    later = await repos.evidence_facts.list_for_run(TENANT_A, alert_id, again)
    assert [e.fact_id for e in earlier] == [e.fact_id for e in later] == ["host:0"] and earlier[0].id != later[0].id
    # The retry found what the run had recorded; the new run found nothing, so the first run's fact cites
    # nothing there. The investigation view reads the newest run.
    assert found_on_arrival == [0, 1, 0]
    latest = await repos.evidence_facts.latest_run(TENANT_A, alert_id)
    assert (latest.total, [e.run_id for e in latest.entries]) == (1, [again])
