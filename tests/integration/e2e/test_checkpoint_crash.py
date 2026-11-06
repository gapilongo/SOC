"""A worker killed between a step's saved writes and that step's checkpoint.

LangGraph saves each task's writes as they finish and the next checkpoint
after the step. A process killed in between (the smoke stack's SIGKILL hit
it right after ``__start__``) leaves a checkpoint whose ``snapshot.next`` is
empty, because ``next`` leaves out tasks that already have writes, while
``snapshot.tasks`` still lists them. The retry must continue that thread,
not report the run ``completed`` with the alert stuck in ``processing``.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest

from lg_sotf.db.repos import Repositories
from tests.integration.db._support import TENANT_A
from tests.integration.e2e._support import SUSPICIOUS_EVENT, Stack

pytestmark = pytest.mark.integration

SETTLED = ("waiting_human", "waiting_approval", "closed")


class _Killed(BaseException):
    """Stands in for SIGKILL: nothing after it runs in the engine."""


async def test_retry_continues_a_thread_killed_after_start_writes(
    stack_factory: Callable[..., Stack], repos: Repositories, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = stack_factory()
    result = await stack.ingest(TENANT_A, "api", [SUSPICIOUS_EVENT])
    alert_id = result.inserted[0].alert_id
    await stack.dispatch(TENANT_A, result)
    engine = await stack.engine()
    saver = engine._checkpointer
    original_aput = saver.aput
    puts = []

    async def aput_then_die(*args: Any, **kwargs: Any) -> Any:
        puts.append(1)
        if len(puts) >= 2:  # the input checkpoint is saved; the step-0 checkpoint never is
            raise _Killed()
        return await original_aput(*args, **kwargs)

    async def no_cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(saver, "aput", aput_then_die)
    monkeypatch.setattr(engine, "_mark_failed", no_cleanup)  # a killed process marks nothing
    with pytest.raises(_Killed):
        await engine.run(TENANT_A, alert_id)
    monkeypatch.setattr(saver, "aput", original_aput)

    config = engine._config(TENANT_A, alert_id)
    snapshot = await engine.graph.aget_state(config)
    assert not snapshot.next and snapshot.tasks, "the crash left start writes without the step-0 checkpoint"
    assert (await repos.alerts.get(TENANT_A, alert_id)).status == "processing"

    outcome = await engine.run(TENANT_A, alert_id)

    alert = await repos.alerts.get(TENANT_A, alert_id)
    assert alert.status in SETTLED, (outcome, alert.status)
    assert outcome.alert_status in SETTLED
