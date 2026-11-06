"""Typed view of the free-form ``settings.ingestion`` section.

Keys (all optional)::

    ingestion:
      llm_fallback: false          # LLM normalization for events no normalizer recognizes
      llm_fallback_max_per_call: 20  # further unrecognized events in one call are rejected
      llm_fallback_concurrency: 4  # LLM normalizations in flight per call
      llm_fallback_timeout_s: 60   # total time for one call's LLM normalizations
      batch_size: 500              # rows per INSERT
      max_event_bytes: 1048576     # larger events are rejected
      max_raw_bytes: 262144        # alerts.raw cap (compact JSON), truncated with a marker
      redact_in_thread_bytes: 65536  # redaction runs in a worker thread above this size
      max_future_skew_s: 900       # later occurrence times are clamped to now and flagged
      page_size: 200               # pull connectors: events per page
      max_pages_per_poll: 20       # pull connectors: resumable cursor after this many pages
      overlap_s: 300               # pull connectors: re-read window before the watermark
      http_timeout_s: 30
      http_connect_timeout_s: 10
      http_max_retries: 4
      http_backoff_base_s: 0.5
      http_backoff_max_s: 30
      http_max_retry_after_s: 120  # longer Retry-After ends the poll instead of sleeping
      allow_private_destinations: false  # install-level: let sources reach RFC 1918 / ULA addresses

``allow_private_destinations`` is deliberately not overridable per source:
it is a decision for whoever runs the install, not for a tenant admin.

Pull sources may override ``page_size``, ``max_pages_per_poll``,
``overlap_s``, ``http_timeout_s`` and ``http_max_retries`` in their own config.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from pydantic import ValidationError

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.settings import IngestionSection, Settings

SOURCE_OVERRIDABLE = ("page_size", "max_pages_per_poll", "overlap_s", "http_timeout_s", "http_max_retries")


class IngestionOptions(IngestionSection):
    """The strict reader of ``settings.ingestion``: an invalid section raises :class:`SourceConfigError`.

    The fields live on :class:`~lg_sotf.settings.IngestionSection`;
    :func:`lg_sotf.net.egress.egress_policy` is the lenient reader of
    ``allow_private_destinations`` for integrations and webhooks (ADR-0007).
    """

    @classmethod
    def from_settings(cls, settings: Settings) -> IngestionOptions:
        try:
            return cls.model_validate(settings.ingestion or {})
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise SourceConfigError(f"invalid ingestion settings: {', '.join(fields)}") from exc

    def for_source(self, config: Optional[Mapping[str, Any]]) -> IngestionOptions:
        overrides = {k: config[k] for k in SOURCE_OVERRIDABLE if config and k in config}
        if not overrides:
            return self
        try:
            return type(self).model_validate({**self.model_dump(), **overrides})
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
            raise SourceConfigError(f"invalid source settings: {', '.join(fields)}") from exc
