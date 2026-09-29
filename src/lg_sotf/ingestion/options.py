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

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.settings import Settings

SOURCE_OVERRIDABLE = ("page_size", "max_pages_per_poll", "overlap_s", "http_timeout_s", "http_max_retries")


class IngestionOptions(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    llm_fallback: bool = False
    llm_fallback_max_per_call: int = Field(default=20, ge=0, le=1_000)
    llm_fallback_concurrency: int = Field(default=4, ge=1, le=64)
    llm_fallback_timeout_s: float = Field(default=60.0, gt=0, le=3_600)
    batch_size: int = Field(default=500, ge=1, le=5_000)
    max_event_bytes: int = Field(default=1_048_576, ge=1_024)
    max_raw_bytes: int = Field(default=262_144, ge=1_024)
    redact_in_thread_bytes: int = Field(default=65_536, ge=0)
    max_future_skew_s: float = Field(default=900.0, ge=0)
    page_size: int = Field(default=200, ge=1, le=10_000)
    max_pages_per_poll: int = Field(default=20, ge=1, le=10_000)
    overlap_s: float = Field(default=300.0, ge=0, le=86_400)
    http_timeout_s: float = Field(default=30.0, gt=0, le=600)
    http_connect_timeout_s: float = Field(default=10.0, gt=0, le=120)
    http_max_retries: int = Field(default=4, ge=0, le=10)
    http_backoff_base_s: float = Field(default=0.5, ge=0)
    http_backoff_max_s: float = Field(default=30.0, ge=0)
    http_max_retry_after_s: float = Field(default=120.0, ge=0)
    allow_private_destinations: bool = False

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
