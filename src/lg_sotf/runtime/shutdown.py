"""Signal handling and small task helpers shared by the long-running roles."""

from __future__ import annotations

import asyncio
import signal
from typing import Callable, Iterable, Optional, Set

from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGINT)


class GracefulShutdown:
    """First SIGTERM/SIGINT requests a graceful stop; a second one forces it.

    ``on_stop`` is called once on the first signal; ``on_force`` on the second.
    """

    def __init__(self, on_stop: Callable[[], None], on_force: Optional[Callable[[], None]] = None) -> None:
        self._on_stop = on_stop
        self._on_force = on_force
        self._signals = 0
        self._installed: list[signal.Signals] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def install(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self._loop = loop or asyncio.get_running_loop()
        for sig in HANDLED_SIGNALS:
            try:
                self._loop.add_signal_handler(sig, self.handle, sig)
            except (NotImplementedError, RuntimeError):
                # Not the main thread or no signal support (e.g. tests, Windows).
                continue
            self._installed.append(sig)

    def uninstall(self) -> None:
        if self._loop is None:
            return
        for sig in self._installed:
            self._loop.remove_signal_handler(sig)
        self._installed.clear()

    def handle(self, sig: signal.Signals) -> None:
        self._signals += 1
        if self._signals == 1:
            log.info("runtime.shutdown_requested", signal=sig.name)
            self._on_stop()
        elif self._on_force is not None:
            log.warning("runtime.shutdown_forced", signal=sig.name)
            self._on_force()


def cancel_current_task() -> Callable[[], None]:
    """Callback that cancels the task running now (the process main task), for a forced shutdown."""
    task = asyncio.current_task()

    def cancel() -> None:
        if task is not None:
            task.cancel()

    return cancel


async def cancel_and_wait(tasks: Iterable[asyncio.Task[object]]) -> None:
    """Cancel tasks and wait until they have finished (their exceptions are discarded)."""
    pending: Set[asyncio.Task[object]] = {t for t in tasks if not t.done()}
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def wait_or_stop(stop: asyncio.Event, timeout_s: float) -> bool:
    """Sleep up to ``timeout_s``; True if ``stop`` was set meanwhile."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=max(timeout_s, 0))
    except TimeoutError:
        return stop.is_set()
    return True
