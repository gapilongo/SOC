"""Alert ingestion: normalizers, fingerprints, pull connectors and the ingestion service (contract section 12)."""

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
from lg_sotf.ingestion.sources import SourceHealth, encrypt_source_secret, source_secret_context
from lg_sotf.ingestion.sources.netpolicy import DestinationRefused

__all__ = [
    "DestinationRefused",
    "IngestionError",
    "NormalizationError",
    "SourceAuthError",
    "SourceConfigError",
    "SourceDisabled",
    "SourceError",
    "SourceHealth",
    "SourceNotPullable",
    "SourceNotPushable",
    "SourceRateLimited",
    "SourceUnavailable",
    "UnrecognizedEvent",
    "compute_fingerprint",
    "encrypt_source_secret",
    "source_secret_context",
]
