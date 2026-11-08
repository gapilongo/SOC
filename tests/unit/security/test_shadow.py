"""Shadow mode (AI-E1.5a): the run-mode flag and the egress boundary decorator."""

from __future__ import annotations

import asyncio
from typing import Any, List

import pytest

from lg_sotf.security.shadow import (
    EGRESS_POINTS,
    MAX_EFFECTS,
    REFUSE,
    RunMode,
    ShadowEgressRefused,
    ShadowRun,
    allow,
    egress,
    run_mode,
    shadow_run_id,
    shadow_scope,
    sink,
)

pytestmark = pytest.mark.unit

calls: List[str] = []


class Mailer:
    @egress("test_mail", REFUSE)
    def send(self, to: str, *, body: str) -> str:
        calls.append(f"send {to}")
        return "sent"

    @egress("test_alert", sink(lambda a: f"stand-in for {a['alert_id']}", detail=lambda a: {"status": a["status"]}))
    async def update(self, tenant_id: str, alert_id: str, status: str) -> str:
        calls.append(f"update {alert_id}")
        return "updated"

    @egress("test_event", sink())
    async def publish(self, tenant_id: str, event: str, *, conn: Any = None, token: str = "") -> None:
        calls.append("publish")

    @egress("test_lookup", allow("reads a public value"))
    async def lookup(self, key: str) -> str:
        calls.append(f"lookup {key}")
        return "value"


@pytest.fixture(autouse=True)
def _clear() -> None:
    calls.clear()


def shadow_run() -> ShadowRun:
    return ShadowRun("shadow/test")


async def test_live_calls_run_unchanged() -> None:
    mailer = Mailer()
    assert run_mode() is RunMode.LIVE and shadow_run_id() is None
    assert mailer.send("a@example.com", body="hi") == "sent"
    assert await mailer.update("t", "a1", "closed") == "updated"
    assert calls == ["send a@example.com", "update a1"]


async def test_a_shadow_run_sinks_or_refuses_every_boundary_and_records_it() -> None:
    mailer = Mailer()
    with shadow_scope(shadow_run()) as run:
        assert run_mode() is RunMode.SHADOW and shadow_run_id() == "shadow/test"
        assert await mailer.update("t", "a1", status="closed") == "stand-in for a1"
        await mailer.publish("t", "alert.updated", conn=object(), token="test-only-value")
        with pytest.raises(ShadowEgressRefused):
            mailer.send("a@example.com", body="hi")
        assert await mailer.lookup("k") == "value"

    assert calls == ["lookup k"]
    assert [(e.seq, e.boundary, e.operation, e.outcome, e.detail) for e in run.sink.effects] == [
        (0, "test_alert", "Mailer.update", "sunk", {"status": "closed"}),
        # By default only the names of the arguments passed are recorded, never their values.
        (1, "test_event", "Mailer.publish", "sunk", {"arguments": ["event", "token"]}),
        (2, "test_mail", "Mailer.send", "refused", {}),
    ]
    assert run_mode() is RunMode.LIVE


def test_boundaries_are_registered_with_their_policy() -> None:
    point = EGRESS_POINTS[f"{__name__}:Mailer.send"]
    assert (point.boundary, point.policy.action) == ("test_mail", "refuse")
    assert EGRESS_POINTS[f"{__name__}:Mailer.lookup"].policy.reason == "reads a public value"
    with pytest.raises(ValueError):
        allow(" ")


async def test_the_mode_cannot_nest_or_outlive_its_scope() -> None:
    with pytest.raises(ValueError):
        with shadow_scope(ShadowRun("tenant-a:alert-1")):
            pass
    with pytest.raises(RuntimeError, match="boom"):
        with shadow_scope(shadow_run()):
            with pytest.raises(RuntimeError, match="inside another shadow run"):
                with shadow_scope(ShadowRun("shadow/other")):
                    pass
            assert run_mode() is RunMode.SHADOW
            raise RuntimeError("boom")
    assert run_mode() is RunMode.LIVE


async def test_tasks_and_threads_started_in_a_shadow_run_stay_in_shadow_mode() -> None:
    mailer = Mailer()
    seen: List[RunMode] = []
    started_before = asyncio.Event()
    release = asyncio.Event()

    async def live_task() -> None:
        started_before.set()
        await release.wait()
        seen.append(run_mode())

    background = asyncio.create_task(live_task())
    await started_before.wait()
    with shadow_scope(shadow_run()) as run:
        await asyncio.create_task(mailer.update("t", "a2", "closed"))
        with pytest.raises(ShadowEgressRefused):
            await asyncio.to_thread(mailer.send, "b@example.com", body="hi")
        release.set()
        await background

    assert calls == []
    assert [e.operation for e in run.sink.effects] == ["Mailer.update", "Mailer.send"]
    assert seen == [RunMode.LIVE], "a task started before the run is not part of it"


async def test_the_sink_keeps_a_bounded_record() -> None:
    mailer = Mailer()
    with shadow_scope(shadow_run()) as run:
        for _ in range(MAX_EFFECTS + 3):
            await mailer.update("t", "a" * 500, "x" * 500)
    assert len(run.sink.effects) == MAX_EFFECTS and run.sink.dropped == 3
    assert len(run.sink.effects[0].detail["status"]) == 200
