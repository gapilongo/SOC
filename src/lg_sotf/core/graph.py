"""Workflow state schema and graph construction (contract section 8).

::

    START -> gate -> triage -> correlation -> analysis -> decide
    gate          -> close | triage
    triage        -> close | correlation
    correlation   -> analysis | decide
    analysis      -> decide
    decide        -> escalate | plan_response | close
    escalate      -> await_analyst
    await_analyst -> plan_response | close | analysis (once) | escalate
    plan_response -> execute_actions | await_approval | close | escalate
    await_approval -> execute_actions
    execute_actions -> await_approval | close | escalate
    close         -> END

State holds identifiers, the size-capped canonical alert, scores and small
digests. Tool outputs and full reasoning live in ``alerts.summary`` and
``alert_events``.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import RetryPolicy

from lg_sotf.core import routing
from lg_sotf.core.routing import RoutingThresholds

MAX_NOTES = 50
MAX_NOTE_CHARS = 300
MAX_ALERT_JSON_CHARS = 32_000
MAX_RAW_JSON_CHARS = 12_000
MAX_FIELD_CHARS = 2_000
MAX_LIST_ITEMS = 50
MAX_DEPTH = 6

NODE_NAMES = (
    "gate",
    "triage",
    "correlation",
    "analysis",
    "decide",
    "escalate",
    "await_analyst",
    "plan_response",
    "await_approval",
    "execute_actions",
    "close",
)


def capped_notes(left: Optional[List[str]], right: Optional[List[str]]) -> List[str]:
    """Append reducer that keeps the newest :data:`MAX_NOTES` short notes."""
    merged = list(left or []) + [str(n)[:MAX_NOTE_CHARS] for n in (right or [])]
    return merged[-MAX_NOTES:]


class WorkflowState(TypedDict, total=False):
    tenant_id: str
    alert_id: str
    severity: str
    fingerprint: str
    alert: Dict[str, Any]
    confidence: float
    gate: Dict[str, Any]
    triage: Dict[str, Any]
    correlation: Dict[str, Any]
    analysis: Dict[str, Any]
    analysis_runs: int
    more_info_loops: int
    decision: Dict[str, Any]
    escalation_id: Optional[str]
    analyst: Optional[Dict[str, Any]]
    plan: Dict[str, Any]
    awaiting_actions: List[str]
    approval: Optional[Dict[str, Any]]
    executed: Dict[str, str]
    disposition: Optional[str]
    close_reason: Optional[str]
    llm_budget_exceeded: bool
    llm_budget_limit: Optional[int]
    notes: Annotated[List[str], capped_notes]


def _cap(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return "[truncated: nesting]"
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD_CHARS else value[: MAX_FIELD_CHARS - 3] + "..."
    if isinstance(value, Mapping):
        return {str(k)[:128]: _cap(v, depth + 1) for k, v in list(value.items())[:MAX_LIST_ITEMS * 2]}
    if isinstance(value, (list, tuple)):
        return [_cap(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_FIELD_CHARS]


def _json_len(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")))


MAX_OMITTED_KEYS = 20
MAX_OMITTED_KEY_CHARS = 64
OMITTED_RESERVE_CHARS = 1_600
PROTECTED_ALERT_KEYS = frozenset(
    {"id", "title", "severity", "category", "source_id", "occurred_at", "fingerprint", "entities", "email"}
)
# (items per list, chars per string, keys per mapping, depth), tried in order until entities fit.
ENTITY_SHRINK_STEPS = (
    (25, 1_024, 50, 4),
    (15, 512, 40, 3),
    (10, 256, 30, 3),
    (5, 128, 20, 2),
    (3, 64, 15, 2),
)


def _shrink(value: Any, items: int, chars: int, keys: int, depth: int) -> Any:
    if isinstance(value, str):
        return value if len(value) <= chars else value[: max(0, chars - 3)] + "..."
    if isinstance(value, Mapping):
        if depth <= 0:
            return str(value)[:chars]
        return {k: _shrink(v, items, chars, keys, depth - 1) for k, v in list(value.items())[:keys]}
    if isinstance(value, (list, tuple)):
        if depth <= 0:
            return str(value)[:chars]
        return [_shrink(v, items, chars, keys, depth - 1) for v in list(value)[:items]]
    return value


def cap_alert(canonical: Mapping[str, Any]) -> Dict[str, Any]:
    """Size-cap the canonical alert for graph state: per-field, per-list and total limits.

    ``raw`` is kept only while it fits :data:`MAX_RAW_JSON_CHARS`. The whole
    document is bounded by :data:`MAX_ALERT_JSON_CHARS`: first the largest
    unprotected keys are dropped, then ``entities`` is shrunk step by step
    (fewer items, shorter strings) so indicators and response targets
    survive, and only as a last resort are whole entity kinds dropped.
    Every loop removes something, so this always terminates.
    """
    limit = MAX_ALERT_JSON_CHARS - OMITTED_RESERVE_CHARS
    capped: Dict[str, Any] = _cap(dict(canonical))
    capped.pop("_omitted_keys", None)
    omitted: List[str] = []
    if "raw" in capped and _json_len(capped["raw"]) > MAX_RAW_JSON_CHARS:
        capped["raw"] = {"_omitted": "raw event too large for workflow state"}
    while _json_len(capped) > limit:
        candidates = [k for k in capped if k not in PROTECTED_ALERT_KEYS]
        if not candidates:
            break
        largest = max(candidates, key=lambda k: _json_len(capped[k]))
        capped.pop(largest)
        omitted.append(largest)
    entities = capped.get("entities")
    if _json_len(capped) > limit and entities is not None:
        for step in ENTITY_SHRINK_STEPS:
            capped["entities"] = _shrink(entities, *step)
            if _json_len(capped) <= limit:
                break
        shrunk = capped["entities"]
        if isinstance(shrunk, dict):
            while _json_len(capped) > limit and shrunk:
                kind = max(shrunk, key=lambda k: _json_len(shrunk[k]))
                shrunk.pop(kind)
                omitted.append(f"entities.{kind}")
        elif _json_len(capped) > limit:
            capped.pop("entities")
            omitted.append("entities")
        capped["_entities_truncated"] = True
    if omitted:
        capped["_omitted_keys"] = [k[:MAX_OMITTED_KEY_CHARS] for k in omitted[:MAX_OMITTED_KEYS]]
    return capped


NodeFn = Callable[[WorkflowState], Awaitable[Dict[str, Any]]]


class GraphNodes(Protocol):
    """Node callables the graph is built from (wrapped by the engine)."""

    def node(self, name: str) -> NodeFn: ...


def build_graph(
    nodes: GraphNodes,
    thresholds: RoutingThresholds,
    *,
    retry_policy: Optional[RetryPolicy] = None,
    node_retry_policies: Optional[Mapping[str, Optional[RetryPolicy]]] = None,
) -> StateGraph:
    """Assemble the workflow graph.

    ``node_retry_policies`` overrides ``retry_policy`` per node (``None``
    disables retries). ``await_*`` nodes never retry: they only interrupt.
    """
    overrides = dict(node_retry_policies or {})
    graph: StateGraph = StateGraph(WorkflowState)
    for name in NODE_NAMES:
        policy = None if name.startswith("await_") else overrides.get(name, retry_policy)
        graph.add_node(name, nodes.node(name), retry_policy=policy)  # type: ignore[call-overload]  # async node alias

    graph.add_edge(START, "gate")
    graph.add_conditional_edges("gate", routing.route_after_gate, {"triage": "triage", "close": "close"})
    graph.add_conditional_edges(
        "triage",
        lambda s: routing.route_after_triage(s, thresholds),
        {"correlation": "correlation", "close": "close"},
    )
    graph.add_conditional_edges(
        "correlation",
        lambda s: routing.route_after_correlation(s, thresholds),
        {"analysis": "analysis", "decide": "decide"},
    )
    graph.add_edge("analysis", "decide")
    graph.add_conditional_edges(
        "decide",
        routing.route_after_decide,
        {"escalate": "escalate", "plan_response": "plan_response", "close": "close"},
    )
    graph.add_edge("escalate", "await_analyst")
    graph.add_conditional_edges(
        "await_analyst",
        lambda s: routing.route_after_analyst(s, thresholds),
        {"plan_response": "plan_response", "close": "close", "analysis": "analysis", "escalate": "escalate"},
    )
    graph.add_conditional_edges(
        "plan_response",
        routing.route_after_plan,
        {"execute_actions": "execute_actions", "await_approval": "await_approval", "close": "close", "escalate": "escalate"},
    )
    graph.add_edge("await_approval", "execute_actions")
    graph.add_conditional_edges(
        "execute_actions",
        routing.route_after_execute,
        {"await_approval": "await_approval", "close": "close", "escalate": "escalate"},
    )
    graph.add_edge("close", END)
    return graph
