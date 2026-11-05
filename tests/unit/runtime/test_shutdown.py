"""Characterization of runtime/shutdown.py: signal escalation, cancellation and the stop-aware sleep."""

from __future__ import annotations

import asyncio
import gc
import signal
import threading
import time
from typing import Any, AsyncIterator, Callable, Dict, List, Tuple

import pytest

from lg_sotf.runtime import shutdown as shutdown_module
from lg_sotf.runtime.shutdown import (
    HANDLED_SIGNALS,
    GracefulShutdown,
    cancel_and_wait,
    cancel_current_task,
    wait_or_stop,
)


class RecordingLog:
    def __init__(self) -> None:
        self.records: List[Tuple[str, str, Dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Callable[..., None]:
        def record(event: str, **fields: Any) -> None:
            self.records.append((level, event, fields))

        return record


@pytest.fixture
def log(monkeypatch: pytest.MonkeyPatch) -> RecordingLog:
    recorder = RecordingLog()
    monkeypatch.setattr(shutdown_module, "log", recorder)
    return recorder


@pytest.fixture
async def loop_errors() -> AsyncIterator[List[Dict[str, Any]]]:
    """Everything the test's loop reports through its exception handler ("never retrieved", "destroyed")."""
    seen: List[Dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: seen.append(context))
    yield seen
    loop.set_exception_handler(previous)


class Counter:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> None:
        self.calls += 1


# -- GracefulShutdown ----------------------------------------------------------


def test_first_signal_stops_and_second_forces_once(log: RecordingLog) -> None:
    stop, force = Counter(), Counter()
    shutdown = GracefulShutdown(stop, force)

    shutdown.handle(signal.SIGTERM)
    assert (stop.calls, force.calls) == (1, 0)
    shutdown.handle(signal.SIGINT)
    assert (stop.calls, force.calls) == (1, 1)
    assert [(level, event, f["signal"]) for level, event, f in log.records] == [
        ("info", "runtime.shutdown_requested", "SIGTERM"),
        ("warning", "runtime.shutdown_forced", "SIGINT"),
    ]


def test_every_signal_after_the_first_forces_again() -> None:
    stop, force = Counter(), Counter()
    shutdown = GracefulShutdown(stop, force)
    for _ in range(4):
        shutdown.handle(signal.SIGTERM)
    assert (stop.calls, force.calls) == (1, 3)


def test_without_on_force_the_second_signal_is_a_no_op(log: RecordingLog) -> None:
    stop = Counter()
    shutdown = GracefulShutdown(stop)
    shutdown.handle(signal.SIGTERM)
    shutdown.handle(signal.SIGTERM)
    shutdown.handle(signal.SIGINT)
    assert stop.calls == 1
    assert [event for _level, event, _f in log.records] == ["runtime.shutdown_requested"]


def test_install_outside_the_main_thread_installs_nothing() -> None:
    result: Dict[str, Any] = {}

    def in_thread() -> None:
        loop = asyncio.new_event_loop()
        try:
            shutdown = GracefulShutdown(Counter())
            shutdown.install(loop)
            result["installed"] = list(shutdown._installed)
            shutdown.uninstall()
        except BaseException as exc:  # noqa: BLE001 - reported to the main thread
            result["error"] = exc
        finally:
            loop.close()

    before = {sig: signal.getsignal(sig) for sig in HANDLED_SIGNALS}
    thread = threading.Thread(target=in_thread)
    thread.start()
    thread.join(5)
    assert not thread.is_alive()
    assert "error" not in result, result.get("error")
    assert result["installed"] == []
    assert {sig: signal.getsignal(sig) for sig in HANDLED_SIGNALS} == before


async def test_install_in_the_main_thread_routes_signals_and_uninstall_removes_them() -> None:
    stop = Counter()
    shutdown = GracefulShutdown(stop)
    loop = asyncio.get_running_loop()
    shutdown.install()
    try:
        assert shutdown._installed == list(HANDLED_SIGNALS)
        signal.raise_signal(signal.SIGTERM)
        for _ in range(50):
            if stop.calls:
                break
            await asyncio.sleep(0.01)
        assert stop.calls == 1
    finally:
        shutdown.uninstall()
    assert shutdown._installed == []
    assert all(not loop.remove_signal_handler(sig) for sig in HANDLED_SIGNALS)


def test_uninstall_before_install_is_harmless() -> None:
    GracefulShutdown(Counter()).uninstall()


async def test_cancel_current_task_cancels_the_task_that_built_it() -> None:
    async def main() -> None:
        cancel = cancel_current_task()
        cancel()
        await asyncio.sleep(1)

    task = asyncio.create_task(main())
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_cancel_current_task_outside_a_task_is_a_no_op() -> None:
    built: List[Callable[[], None]] = []
    asyncio.get_running_loop().call_soon(lambda: built.append(cancel_current_task()))
    await asyncio.sleep(0)
    built[0]()  # a plain loop callback has no current task: nothing to cancel
    await asyncio.sleep(0)


# -- cancel_and_wait -----------------------------------------------------------


async def test_cancel_and_wait_recancels_a_task_that_swallows_cancellation(
    log: RecordingLog, loop_errors: List[Dict[str, Any]]
) -> None:
    swallowed: List[int] = []

    async def stubborn() -> str:
        while True:
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                swallowed.append(1)
                if len(swallowed) >= 3:
                    return "gave up"

    task = asyncio.create_task(stubborn())
    await asyncio.sleep(0)
    started = time.monotonic()

    await asyncio.wait_for(cancel_and_wait([task], recancel_s=0.01), timeout=2)

    assert time.monotonic() - started < 1.0
    assert task.done() and not task.cancelled() and task.result() == "gave up"
    assert len(swallowed) == 3
    warned = [f for _level, event, f in log.records if event == "runtime.task_running_after_cancel"]
    assert warned == [{"tasks": 1}, {"tasks": 1}]
    del task
    gc.collect()
    await asyncio.sleep(0)
    assert loop_errors == []


async def test_cancel_and_wait_retrieves_exceptions_and_skips_finished_tasks(
    log: RecordingLog, loop_errors: List[Dict[str, Any]]
) -> None:
    async def raises_on_cancel() -> None:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            raise RuntimeError("cleanup failed") from None

    async def already_failed() -> None:
        raise ValueError("before shutdown")

    async def obedient() -> None:
        await asyncio.sleep(10)

    failed_early = asyncio.create_task(already_failed())
    tasks = [asyncio.create_task(raises_on_cancel()), failed_early, asyncio.create_task(obedient())]
    await asyncio.sleep(0)
    assert failed_early.done()

    await cancel_and_wait(tasks, recancel_s=0.01)

    assert all(t.done() for t in tasks)
    assert isinstance(tasks[0].exception(), RuntimeError)
    assert tasks[2].cancelled()
    assert [event for _level, event, _f in log.records] == []
    del tasks, failed_early
    gc.collect()
    await asyncio.sleep(0)
    assert loop_errors == []


async def test_cancel_and_wait_accepts_nothing_and_generators() -> None:
    await cancel_and_wait([])
    await cancel_and_wait(t for t in ())


# -- wait_or_stop --------------------------------------------------------------


async def test_wait_or_stop_times_out_false() -> None:
    started = time.monotonic()
    assert await wait_or_stop(asyncio.Event(), 0.02) is False
    assert time.monotonic() - started >= 0.015


async def test_wait_or_stop_returns_true_when_stop_is_set_meanwhile() -> None:
    stop = asyncio.Event()
    asyncio.get_running_loop().call_later(0.01, stop.set)
    started = time.monotonic()
    assert await wait_or_stop(stop, 5) is True
    assert time.monotonic() - started < 1.0


async def test_wait_or_stop_returns_true_when_stop_was_already_set() -> None:
    stop = asyncio.Event()
    stop.set()
    assert await wait_or_stop(stop, 5) is True
    # A zero or negative timeout still reports a stop that was already requested.
    assert await wait_or_stop(stop, 0) is True
    assert await wait_or_stop(stop, -1) is True


async def test_wait_or_stop_with_non_positive_timeout_returns_immediately() -> None:
    started = time.monotonic()
    assert await wait_or_stop(asyncio.Event(), 0) is False
    assert await wait_or_stop(asyncio.Event(), -5) is False
    assert time.monotonic() - started < 0.5
