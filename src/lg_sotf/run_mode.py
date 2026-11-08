"""The run mode of the current task: ``live``, or ``shadow`` inside a shadow run.

The lowest layer of the package (standard library only), so the kernel
modules can read it: the metrics label their series with it. Only
:func:`lg_sotf.security.shadow.shadow_scope` changes it; everything else reads it.
"""

from __future__ import annotations

import enum
from contextvars import ContextVar, Token


class RunMode(enum.StrEnum):
    LIVE = "live"
    SHADOW = "shadow"


_MODE: ContextVar[RunMode] = ContextVar("lg_sotf_run_mode", default=RunMode.LIVE)


def run_mode() -> RunMode:
    return _MODE.get()


def _enter(mode: RunMode) -> Token[RunMode]:
    """For ``shadow_scope`` only."""
    return _MODE.set(mode)


def _leave(token: Token[RunMode]) -> None:
    """For ``shadow_scope`` only."""
    _MODE.reset(token)
