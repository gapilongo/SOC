"""Root exception classes shared across LG-SOTF (kernel layer).

This module imports nothing from ``lg_sotf`` (an import-linter contract
enforces it), so every layer can raise and catch these without importing the
package that uses them most. Class names are part of the record:
``type(exc).__name__`` is written to logs and ``sources.last_error``.
"""


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


class IngestionError(Exception):
    """Base class for ingestion failures."""


class SourceConfigError(IngestionError):
    """A source's configuration or credentials are missing or invalid."""


class OperationError(Exception):
    """A user-facing failure of an operations command (bad input or state)."""
