"""Workflow core: graph state and the durable workflow engine.

Importing this package has no side effects; the engine and agents are loaded
only when :class:`WorkflowEngine` or :class:`RunOutcome` is first accessed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lg_sotf.core.workflow import RunOutcome, WorkflowEngine

__all__ = ["RunOutcome", "WorkflowEngine"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from lg_sotf.core import workflow

        return getattr(workflow, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
