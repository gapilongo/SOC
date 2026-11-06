"""Alert ingestion: normalizers, fingerprints, pull connectors and the ingestion service (contract section 12).

Importing the package loads only the errors and the fingerprint; import
connectors, the service and the normalizers from their modules.
"""

from lg_sotf.ingestion.errors import (
    IngestionError,
    NormalizationError,
    SourceAuthError,
    SourceConfigError,
    SourceDisabled,
    SourceError,
    SourceNotPullable,
    SourceNotPushable,
    SourceRateLimited,
    SourceUnavailable,
    UnrecognizedEvent,
)
from lg_sotf.ingestion.fingerprint import compute_fingerprint

__all__ = [
    "IngestionError",
    "NormalizationError",
    "SourceAuthError",
    "SourceConfigError",
    "SourceDisabled",
    "SourceError",
    "SourceNotPullable",
    "SourceNotPushable",
    "SourceRateLimited",
    "SourceUnavailable",
    "UnrecognizedEvent",
    "compute_fingerprint",
]
