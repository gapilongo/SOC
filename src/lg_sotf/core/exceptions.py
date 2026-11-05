"""Exception hierarchy shared across LG-SOTF."""


class LG_SOTFError(Exception):
    """Base exception for LG-SOTF."""


class WorkflowError(LG_SOTFError):
    """Workflow execution errors."""


class InvalidResumePayload(WorkflowError, ValueError):
    """A resume payload does not match the schema or the run's pending interrupt."""


class NodeError(LG_SOTFError):
    """Node execution errors."""


class NodeTimeout(NodeError):
    """A node exceeded its own time budget.

    Deliberately not a ``TimeoutError``: the node budget bounds a stuck node,
    so it is never retried inside the run (the queue's delivery limit applies).
    """

    def __init__(self, node: str, timeout_s: float) -> None:
        super().__init__(f"node {node!r} exceeded its {timeout_s:g}s timeout")
        self.node = node
        self.timeout_s = timeout_s


class AgentError(LG_SOTFError):
    """Agent execution errors."""


class StorageError(LG_SOTFError):
    """Storage-related errors."""
