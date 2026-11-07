"""Graph versions (ARCH-E1.1): a run waiting on graph N-1 is resumed and decided on N-1 after an upgrade to N.

Each graph here is the real graph whose nodes also leave a ``graph-<version>:<node>``
note in the state, so the test can tell which graph ran each step.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

import pytest
from langgraph.graph import StateGraph

from lg_sotf.core.graph import GraphNodes, NodeFn, WorkflowState, build_graph
from lg_sotf.core.workflow import UnknownGraphVersion, WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.routing import RoutingThresholds
from tests.integration.db._support import TENANT_A
from tests.integration.engine._support import analyst, decide, suspicious_alert

pytestmark = pytest.mark.integration


class _TaggedNodes:
    def __init__(self, nodes: GraphNodes, version: int) -> None:
        self._nodes = nodes
        self._version = version

    def node(self, name: str) -> NodeFn:
        inner = self._nodes.node(name)
        tag = f"graph-{self._version}:{name}"

        async def tagged(state: WorkflowState) -> Dict[str, Any]:
            update = await inner(state)
            return {**update, "notes": [*update.get("notes", []), tag]}

        return tagged


def tagged_graph(version: int) -> Callable[..., StateGraph]:
    def build(nodes: GraphNodes, thresholds: RoutingThresholds, **kwargs: Any) -> StateGraph:
        return build_graph(_TaggedNodes(nodes, version), thresholds, **kwargs)

    return build


async def _waiting_run(engine: WorkflowEngine, repos: Repositories) -> tuple[str, str]:
    """A suspicious alert queued like the API does, run until it waits for an analyst: (alert id, escalation id)."""
    alert_id = await suspicious_alert(repos)
    await repos.runs.upsert_queued(TENANT_A, alert_id)
    outcome = await engine.run(TENANT_A, alert_id)
    assert outcome.status == "waiting_human"
    return alert_id, outcome.interrupt["escalation_id"]


async def _notes(engine: WorkflowEngine, version: int, alert_id: str) -> List[str]:
    snapshot = await engine.graphs[version].aget_state(engine._config(TENANT_A, alert_id))
    return list(snapshot.values["notes"])


async def test_run_waiting_on_graph_n_minus_1_resumes_and_is_decided_after_upgrade(
    engine_factory: Any, repos: Repositories
) -> None:
    before = await engine_factory(graph_builders={1: tagged_graph(1)})
    alert_id, escalation_id = await _waiting_run(before, repos)
    assert (await repos.runs.get(TENANT_A, alert_id)).graph_version == 1

    # The upgrade: graph 2 is current and graph 1 is kept to drain the runs waiting on it.
    after = await engine_factory(graph_builders={1: tagged_graph(1), 2: tagged_graph(2)})
    assert after.graph_version == 2
    # A new run after the upgrade starts on graph 2.
    new_alert_id, _ = await _waiting_run(after, repos)
    assert (await repos.runs.get(TENANT_A, new_alert_id)).graph_version == 2
    assert "graph-2:escalate" in await _notes(after, 2, new_alert_id)

    outcome = await decide(after, repos, alert_id, escalation_id, "false_positive", await analyst(repos))

    assert outcome.status == "completed" and outcome.alert_status == "closed"
    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert (alert.status, alert.disposition) == ("closed", "benign")
    notes = await _notes(after, 1, alert_id)
    assert notes[-2:] == ["graph-1:await_analyst", "graph-1:close"]
    assert not [n for n in notes if n.startswith("graph-2:")]
    assert (await repos.runs.get(TENANT_A, alert_id)).graph_version == 1


async def test_a_run_on_a_graph_the_worker_does_not_have_fails_without_side_effects(
    engine_factory: Any, repos: Repositories
) -> None:
    before = await engine_factory(graph_builders={1: tagged_graph(1)})
    alert_id, escalation_id = await _waiting_run(before, repos)
    events_before = (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items
    # Two upgrades later: graph 1 is no longer kept.
    after = await engine_factory(graph_builders={2: tagged_graph(2), 3: tagged_graph(3)})

    with pytest.raises(UnknownGraphVersion, match="graph version 1; this worker runs versions \\[2, 3\\]"):
        await decide(after, repos, alert_id, escalation_id, "false_positive", await analyst(repos))
    with pytest.raises(UnknownGraphVersion):
        await after.run(TENANT_A, alert_id)

    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "waiting_human"
    assert (await repos.alert_events.list_for_alert(TENANT_A, alert_id)).items == events_before
    assert (await repos.runs.get(TENANT_A, alert_id)).graph_version == 1

    # A run with no checkpoint yet (graph_version NULL) is not blocked: it starts on the current graph.
    fresh_id, _ = await _waiting_run(after, repos)
    assert (await repos.runs.get(TENANT_A, fresh_id)).graph_version == 3
