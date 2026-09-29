"""Node wrapper: the node's own time budget raises NodeTimeout, inner timeouts stay transient."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from lg_sotf.core.exceptions import NodeTimeout
from lg_sotf.core.nodes import WorkflowNodes
from lg_sotf.core.retry import is_transient


class Events:
    def __init__(self) -> None:
        self.appended: List[Dict[str, Any]] = []

    async def append(self, *args: Any, **kwargs: Any) -> None:
        self.appended.append(kwargs)


def nodes() -> WorkflowNodes:
    wn = WorkflowNodes.__new__(WorkflowNodes)
    wn.deps = SimpleNamespace(repos=SimpleNamespace(alert_events=Events()), events=None)  # type: ignore[assignment]
    return wn


STATE: Dict[str, Any] = {"tenant_id": "t1", "alert_id": "a1"}


async def test_node_budget_expiry_raises_node_timeout() -> None:
    async def stuck(state: Any) -> Dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    with pytest.raises(NodeTimeout) as info:
        await nodes()._wrap("analysis", stuck, 0.05)(STATE)
    assert info.value.node == "analysis" and not is_transient(info.value)


async def test_inner_timeout_error_is_left_transient() -> None:
    async def flaky(state: Any) -> Dict[str, Any]:
        raise TimeoutError("redis command timed out")

    with pytest.raises(TimeoutError) as info:
        await nodes()._wrap("triage", flaky, 5.0)(STATE)
    assert not isinstance(info.value, NodeTimeout) and is_transient(info.value)


async def test_completed_node_records_a_small_event() -> None:
    wn = nodes()

    async def ok(state: Any) -> Dict[str, Any]:
        return {"x": 1, "_event": {"score": 5, "blob": "y" * 5_000}}

    update = await wn._wrap("decide", ok, 5.0)(STATE)
    assert update == {"x": 1}
    [event] = wn.deps.repos.alert_events.appended
    assert event["node"] == "decide" and event["data"]["score"] == 5 and len(event["data"]["blob"]) == 300
