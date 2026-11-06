"""The kernel error module (roadmap F1): class identity and names survive the move."""

from __future__ import annotations

import lg_sotf.errors as kernel
from lg_sotf.ingestion import errors as ingestion_errors
from lg_sotf.runtime import ops


def test_ingestion_roots_are_the_kernel_classes() -> None:
    assert ingestion_errors.IngestionError is kernel.IngestionError
    assert ingestion_errors.SourceConfigError is kernel.SourceConfigError
    assert issubclass(kernel.SourceConfigError, kernel.IngestionError)
    assert issubclass(ingestion_errors.DecryptedSecretError, kernel.SourceConfigError)
    assert issubclass(ingestion_errors.SourceError, kernel.IngestionError)


def test_operation_error_is_the_kernel_class() -> None:
    assert ops.OperationError is kernel.OperationError
    assert kernel.OperationError.__bases__ == (Exception,)


def test_class_names_are_unchanged() -> None:
    # type(exc).__name__ is written to logs and sources.last_error.
    names = {
        cls.__name__
        for cls in vars(kernel).values()
        if isinstance(cls, type) and issubclass(cls, BaseException)
    }
    assert names == {
        "LG_SOTFError",
        "WorkflowError",
        "InvalidResumePayload",
        "NodeError",
        "NodeTimeout",
        "AgentError",
        "StorageError",
        "IngestionError",
        "SourceConfigError",
        "OperationError",
    }
