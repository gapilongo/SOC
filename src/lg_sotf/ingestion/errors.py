"""Ingestion errors.

Messages are safe to store in ``sources.last_error`` and to return to API
clients: they never contain credentials, response bodies or alert content.
"""

from __future__ import annotations

from typing import Optional


class IngestionError(Exception):
    """Base class for ingestion failures."""


class NormalizationError(IngestionError):
    """An event could not be turned into a canonical alert (the event is rejected)."""


class UnrecognizedEvent(NormalizationError):
    """The event does not look like this source's format (the LLM fallback may try it)."""


class SourceConfigError(IngestionError):
    """A source's configuration or credentials are missing or invalid."""


class DecryptedSecretError(SourceConfigError):
    """Stored credentials cannot be decrypted (wrong key or context) or are malformed."""


class SourceNotPullable(SourceConfigError):
    """The source type is push-only (webhook, GuardDuty via EventBridge)."""


class SourceNotPushable(IngestionError):
    """Events may not be pushed to this source id (a pull source, or an unregistered non-reserved id)."""


class SourceDisabled(IngestionError):
    """Events for a disabled source are refused."""


class SourceError(IngestionError):
    """A remote source failed."""


class SourceAuthError(SourceError):
    """Credentials were rejected (401/403 or token endpoint refusal)."""


class SourceUnavailable(SourceError):
    """Network failure, timeout or 5xx after retries."""


class SourceRateLimited(SourceError):
    def __init__(self, message: str, *, retry_after_s: Optional[float] = None):
        super().__init__(message)
        self.retry_after_s = retry_after_s


class SourceRequestError(SourceError):
    """The source rejected a request (4xx other than auth and rate limits)."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class SourceProtocolError(SourceError):
    """The source answered with something that does not match its API."""
