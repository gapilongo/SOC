"""IngestionService: vendor events in, deduplicated alert rows out.

Per event, in order:

1. must be a JSON object; NUL characters are removed from keys and values
   and lone UTF-16 surrogates replaced with U+FFFD;
2. larger than ``ingestion.max_event_bytes`` (compact JSON) -> rejected;
3. secrets are redacted (:func:`lg_sotf.security.redact`, in a worker thread
   for events above ``ingestion.redact_in_thread_bytes``) - everything
   persisted or shown to an LLM comes from the redacted copy;
4. the source's normalizer maps it to a :class:`CanonicalAlert`; events it
   does not recognize go to the LLM fallback when ``ingestion.llm_fallback``
   is on, and are rejected otherwise;
5. ``raw`` is capped at ``ingestion.max_raw_bytes`` with a marker, the
   fingerprint is computed and the row is inserted with
   ``ON CONFLICT DO NOTHING`` on ``(tenant_id, source_id, source_alert_id)``.

Normalization runs in a worker thread for events above
``redact_in_thread_bytes`` so a large event cannot stall the event loop. The
per-event pipeline is total: any failure while preparing one event rejects
that event (``event could not be processed (<ErrorType>)``) and never fails
the call, so one malformed event cannot block a batch or wedge a pull
source's cursor.

All rows of one call (or one polled page, together with that page's cursor)
are written in one transaction. Callers enqueue ``IngestResult.inserted``.

Push (:meth:`IngestionService.ingest`) is accepted for:

* registered push sources (``webhook``, ``guardduty``); their type (and
  ``config.format``) picks the normalizer;
* the reserved ids ``api`` and ``api:<suffix>`` when no source is registered
  under them, as canonical-format events (``POST /ingest/alerts``; the API
  chooses the id, e.g. :func:`api_source_id` of the API key, never the
  client);
* the reserved id ``demo:samples`` (the onboarding sample alerts), also
  canonical; its alerts are flagged ``sample`` and never metered.

Every stored alert is counted in ``usage_daily`` (invoicing, daily quota) in
the transaction that inserts it.

Raw emails (``POST /ingest/email``) go through :meth:`IngestionService.ingest_email`
instead: the MIME is parsed here, in a worker thread, under the reserved ids
``email`` and ``email:<suffix>`` (:func:`email_source_id`), and the parsed
document takes the path above with the ``email`` normalizer.

Pushing to a pull source or to any other unregistered id raises
:class:`SourceNotPushable`: alerts are deduplicated on ``(source_id,
source_alert_id)``, so a pushed row could otherwise pre-empt, and silently
hide, a real detection that the pull connector fetches later.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple

import httpx

from lg_sotf.db.errors import NotFound
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import NewAlert, Repositories, Source
from lg_sotf.db.repos.usage import SAMPLE_SOURCE_ID
from lg_sotf.ingestion.email import EmailLimits, EmailParseError, parse_email
from lg_sotf.ingestion.errors import (
    IngestionError,
    NormalizationError,
    SourceConfigError,
    SourceDisabled,
    SourceError,
    SourceNotPullable,
    SourceNotPushable,
    SourceUnavailable,
    UnrecognizedEvent,
)
from lg_sotf.ingestion.fingerprint import compute_fingerprint
from lg_sotf.ingestion.llm_fallback import llm_normalize
from lg_sotf.ingestion.metrics import record_events, record_llm_normalization, record_poll
from lg_sotf.ingestion.normalizers import EMAIL, NormalizeContext, Normalizer, get_normalizer, resolve_format
from lg_sotf.ingestion.normalizers.email import email_error_event
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources import (
    PUSH_ONLY_TYPES,
    ConnectorDeps,
    FetchedPage,
    PullConnector,
    SourceHealth,
    create_connector,
    load_credentials,
)
from lg_sotf.llm import USE_DEFAULT, BudgetLimit, TokenBudget
from lg_sotf.llm.errors import LLMBudgetExceeded
from lg_sotf.models.alert import TRUNCATED_MARKER, CanonicalAlert, IngestedAlert, cap_mapping, json_size
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.redaction import redact, redact_text
from lg_sotf.settings import Settings, get_settings

log = get_logger(__name__)

_SURROGATE = re.compile("[\ud800-\udfff]")
SOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FLAG_RAW_TRUNCATED = "raw_truncated"
FLAG_REDACTED = "secrets_redacted"
FLAG_SAMPLE = "sample"
MAX_CACHED_CONNECTORS = 512
MAX_ERROR_CHARS = 500
API_SOURCE_ID = "api"
API_SOURCE_PREFIX = "api:"
EMAIL_SOURCE_ID = "email"
EMAIL_SOURCE_PREFIX = "email:"
PUSH_TYPES = PUSH_ONLY_TYPES
UNREACHABLE_DETAIL = "source is unreachable or did not respond"

ItemStatus = Literal["inserted", "duplicate", "rejected"]
ConnectorFactory = Callable[[Source, Mapping[str, Any]], PullConnector]


@dataclass(frozen=True)
class RejectedEvent:
    index: int
    reason: str


@dataclass(frozen=True)
class IngestItem:
    """Per-event outcome, in input order (``POST /ingest/*`` returns these)."""

    index: int
    status: ItemStatus
    alert_id: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class IngestResult:
    inserted: List[IngestedAlert] = field(default_factory=list)
    duplicates: int = 0
    rejected: List[RejectedEvent] = field(default_factory=list)
    items: List[IngestItem] = field(default_factory=list)
    # poll_source only: pages committed, whether the page cap stopped the poll, and the failure (secret-free).
    pages: int = 0
    more_pending: bool = False
    error: Optional[str] = None

    def extend(self, other: IngestResult) -> None:
        offset = len(self.items)
        self.inserted.extend(other.inserted)
        self.duplicates += other.duplicates
        self.rejected.extend(RejectedEvent(r.index + offset, r.reason) for r in other.rejected)
        self.items.extend(
            IngestItem(i.index + offset, i.status, i.alert_id, i.reason) for i in other.items
        )


@dataclass
class _Prepared:
    index: int
    row: NewAlert


@dataclass
class _Outcome:
    prepared: Optional[_Prepared] = None
    reason: Optional[str] = None
    # Redacted event waiting for the LLM fallback.
    pending_llm: Optional[Dict[str, Any]] = None


@dataclass
class _CachedConnector:
    config_key: str
    connector: PullConnector
    users: int = 0
    retired: bool = False


def is_email_source_id(source_id: str) -> bool:
    """Ids reserved for the email push endpoint (``email``, ``email:<suffix>``)."""
    return source_id == EMAIL_SOURCE_ID or source_id.startswith(EMAIL_SOURCE_PREFIX)


def is_reserved_source_id(source_id: str) -> bool:
    """Ids reserved by the server: the push endpoints (``api``, ``api:<suffix>``, ``email``, ``email:<suffix>``) and the samples."""
    return (
        source_id in (API_SOURCE_ID, SAMPLE_SOURCE_ID)
        or source_id.startswith(API_SOURCE_PREFIX)
        or is_email_source_id(source_id)
    )


def api_source_id(api_key_id: Optional[str] = None) -> str:
    """The source id ``POST /ingest/alerts`` should use: ``api`` or ``api:<api key id>``."""
    if api_key_id is None:
        return API_SOURCE_ID
    source_id = f"{API_SOURCE_PREFIX}{api_key_id}"
    if not SOURCE_ID_PATTERN.match(source_id):
        raise ValueError("api key id is not usable in a source id")
    return source_id


def email_source_id(api_key_id: Optional[str] = None) -> str:
    """The source id ``POST /ingest/email`` should use: ``email`` or ``email:<api key id>``."""
    if api_key_id is None:
        return EMAIL_SOURCE_ID
    source_id = f"{EMAIL_SOURCE_PREFIX}{api_key_id}"
    if not SOURCE_ID_PATTERN.match(source_id):
        raise ValueError("api key id is not usable in a source id")
    return source_id


def clean_text(value: str) -> str:
    """Remove NUL and replace lone surrogates, neither of which PostgreSQL or UTF-8 can hold."""
    if "\x00" in value:
        value = value.replace("\x00", "")
    if not value.isascii():
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            value = _SURROGATE.sub("\ufffd", value)
    return value


def strip_nul_deep(value: Any, depth: int = 0) -> Any:
    """:func:`clean_text` over every key and string value (nesting beyond 64 levels is left as is)."""
    if depth > 64:
        return value
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, Mapping):
        return {clean_text(str(k)): strip_nul_deep(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [strip_nul_deep(v, depth + 1) for v in value]
    return value


def describe_error(exc: BaseException) -> str:
    """Secret-free description for ``sources.last_error`` and API responses."""
    if isinstance(exc, IngestionError):
        text, _ = redact_text(str(exc))
        return text[:MAX_ERROR_CHARS] or type(exc).__name__
    return type(exc).__name__


def _config_key(source: Source) -> str:
    material = repr((source.type, sorted((source.config or {}).items(), key=lambda kv: kv[0]), source.secret_ciphertext))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class IngestionService:
    def __init__(
        self,
        db: Database,
        settings: Optional[Settings] = None,
        secret_box: Optional[SecretBox] = None,
        *,
        repos: Optional[Repositories] = None,
        budget: Optional[TokenBudget] = None,
        connector_deps: Optional[ConnectorDeps] = None,
        connector_factory: Optional[ConnectorFactory] = None,
    ):
        self._db = db
        self._repos = repos or Repositories.create(db)
        self._settings = settings or get_settings()
        self._options = IngestionOptions.from_settings(self._settings)
        try:
            self._email_limits = EmailLimits.from_settings(self._settings.ingestion)
        except ValueError as exc:
            raise SourceConfigError(str(exc)) from exc
        self._box = secret_box
        self._budget = budget
        self._deps = connector_deps
        self._factory = connector_factory
        self._connectors: OrderedDict[Tuple[str, str], _CachedConnector] = OrderedDict()

    @property
    def options(self) -> IngestionOptions:
        return self._options

    @property
    def email_limits(self) -> EmailLimits:
        return self._email_limits

    # -- push ------------------------------------------------------------------

    async def ingest(self, tenant_id: str, source_id: str, events: Sequence[Mapping[str, Any]]) -> IngestResult:
        """Normalize and store pushed ``events`` for ``source_id`` (see the module docstring).

        Raises :class:`SourceNotPushable` for pull sources and unregistered
        non-reserved ids, :class:`SourceDisabled` and :class:`SourceConfigError`.
        """
        if not SOURCE_ID_PATTERN.match(source_id or ""):
            raise ValueError("source_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        try:
            source: Optional[Source] = await self._repos.sources.get(tenant_id, source_id)
        except NotFound:
            source = None
        if source is None:
            if is_email_source_id(source_id):
                raise SourceNotPushable("raw emails are pushed with ingest_email (POST /ingest/email)")
            if not is_reserved_source_id(source_id):
                raise SourceNotPushable(f"no push source {source_id} is registered")
            fmt = resolve_format(None)
            return await self._ingest(tenant_id, source_id, "canonical", fmt, {}, events, page=None)
        if source.type not in PUSH_TYPES:
            raise SourceNotPushable(f"source {source_id} is a {source.type} pull source; events cannot be pushed to it")
        if not source.enabled:
            raise SourceDisabled(f"source {source_id} is disabled")
        fmt = resolve_format(source.type, source.config)
        return await self._ingest(tenant_id, source_id, source.type, fmt, source.config, events, page=None)

    async def ingest_email(
        self,
        tenant_id: str,
        source_id: str,
        messages: Sequence[bytes],
        *,
        reporter: Optional[str] = None,
    ) -> IngestResult:
        """Parse raw RFC 5322 ``messages`` (user reports) and store them for the reserved ``source_id``.

        Parsing runs in a worker thread under :attr:`email_limits`; a message
        that cannot be parsed (too large, too deeply nested, malformed) is
        rejected with the reason. ``reporter`` overrides the reporter read from
        a forwarded report's envelope. Deduplication is on the message's
        Message-ID plus the reporter.
        """
        if not SOURCE_ID_PATTERN.match(source_id or "") or not is_email_source_id(source_id):
            raise ValueError("email pushes use the reserved source ids 'email' and 'email:<suffix>'")
        received_at = datetime.now(UTC)
        events: List[Dict[str, Any]] = []
        for data in messages:
            try:
                events.append(
                    await asyncio.to_thread(
                        parse_email, data, limits=self._email_limits, reporter=reporter, received_at=received_at
                    )
                )
            except EmailParseError as exc:
                events.append(email_error_event(str(exc)))
        return await self._ingest(tenant_id, source_id, EMAIL, EMAIL, {}, events, page=None)

    # -- pull ------------------------------------------------------------------

    async def poll_source(
        self,
        tenant_id: str,
        source: Source,
        *,
        on_page: Optional[Callable[[IngestResult], Awaitable[None]]] = None,
    ) -> IngestResult:
        """Fetch new events since the stored cursor, ingest them and record the poll.

        Each page is committed together with its cursor, so the cursor only
        advances past events that are stored. A failure part-way keeps the
        pages already committed (returned in ``inserted`` for dispatch),
        records the failure on the source and is reported in
        ``IngestResult.error``; it is not raised. Push-only and disabled
        sources raise :class:`SourceConfigError`/:class:`SourceDisabled`.

        Pulled alerts get their ``queued`` run in the page's own transaction.
        ``on_page`` (the scheduler's dispatch) is awaited after each committed
        page, so a poll cancelled later (rolling deploy, leadership loss)
        has already handed the earlier pages to the workers; a page whose
        dispatch was interrupted is recovered by the orphaned-run sweep.
        """
        if source.tenant_id != tenant_id:
            raise ValueError("source belongs to another tenant")
        if source.type in PUSH_ONLY_TYPES:
            raise SourceNotPullable(f"{source.type} sources are push-only")
        if not source.enabled:
            raise SourceDisabled(f"source {source.id} is disabled")
        started = time.monotonic()
        result = IngestResult()
        try:
            fmt = resolve_format(source.type, source.config)
            async with self._lease(source) as connector:
                stream = connector.pages(source.cursor)
                try:
                    async for page in stream:
                        page_result = await self._ingest(
                            tenant_id, source.id, source.type, fmt, source.config, page.events, page=page
                        )
                        result.extend(page_result)
                        if on_page is not None and page_result.inserted:
                            await on_page(page_result)
                        result.pages += 1
                        if result.pages >= connector.options.max_pages_per_poll:
                            result.more_pending = True
                            break
                finally:
                    await stream.aclose()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - recorded on the source and returned; committed pages stay dispatchable
            result.error = describe_error(exc)
            if isinstance(exc, SourceConfigError):
                await self._retire((tenant_id, source.id))
            log.warning(
                "ingestion.poll_failed",
                tenant_id=tenant_id,
                source_id=source.id,
                source_type=source.type,
                error_type=type(exc).__name__,
                pages=result.pages,
                inserted=len(result.inserted),
            )
            record_poll(source.type, False, time.monotonic() - started)
            await self._repos.sources.record_poll_result(tenant_id, source.id, ok=False, error=result.error)
            return result
        record_poll(source.type, True, time.monotonic() - started)
        await self._repos.sources.record_poll_result(
            tenant_id, source.id, ok=True, next_poll_at=datetime.now(UTC) if result.more_pending else None
        )
        log.info(
            "ingestion.polled",
            tenant_id=tenant_id,
            source_id=source.id,
            source_type=source.type,
            pages=result.pages,
            inserted=len(result.inserted),
            duplicates=result.duplicates,
            rejected=len(result.rejected),
            more_pending=result.more_pending,
        )
        return result

    async def test_source(self, tenant_id: str, source: Source) -> SourceHealth:
        """Check a source's configuration and connectivity without ingesting anything.

        Never raises for a failing source: every failure becomes an unhealthy
        :class:`SourceHealth`. Network failures share one message so the
        result cannot be used to probe which hosts or ports exist.
        """
        if source.tenant_id != tenant_id:
            raise ValueError("source belongs to another tenant")
        try:
            resolve_format(source.type, source.config)
        except SourceConfigError as exc:
            return SourceHealth(False, describe_error(exc))
        if source.type in PUSH_ONLY_TYPES:
            return SourceHealth(True, "push source: events are received on the webhook endpoint")
        connector: Optional[PullConnector] = None
        try:
            connector = self._build_connector(source)
            return await connector.test()
        except asyncio.CancelledError:
            raise
        except SourceUnavailable:
            return SourceHealth(False, UNREACHABLE_DETAIL)
        except (SourceError, SourceConfigError) as exc:
            return SourceHealth(False, describe_error(exc))
        except Exception as exc:  # noqa: BLE001 - a malformed vendor response is a health result, not a 500
            log.warning("ingestion.source_test_failed", source_type=source.type, error_type=type(exc).__name__)
            return SourceHealth(False, f"unexpected response ({type(exc).__name__})")
        finally:
            if connector is not None:
                await connector.aclose()

    async def validate_source(self, tenant_id: str, source: Source) -> None:
        """Validate a source's configuration and destinations before it is saved (API create/update).

        Builds the connector (config and credential checks, https in
        production), then resolves every URL it will call and applies the
        destination policy. Raises :class:`SourceConfigError` (including
        :class:`~lg_sotf.ingestion.sources.netpolicy.DestinationRefused`).
        """
        if source.tenant_id != tenant_id:
            raise ValueError("source belongs to another tenant")
        resolve_format(source.type, source.config)
        if source.type in PUSH_ONLY_TYPES:
            return
        connector = self._build_connector(source)
        try:
            await connector.check_destinations()
        except httpx.TransportError as exc:
            raise SourceConfigError("source host could not be resolved") from exc
        finally:
            await connector.aclose()

    async def close(self) -> None:
        for key in list(self._connectors):
            await self._retire(key)

    # -- internals -------------------------------------------------------------

    def _build_connector(self, source: Source) -> PullConnector:
        credentials = load_credentials(self._box, source)
        if self._factory is not None:
            return self._factory(source, credentials)
        return create_connector(
            source, credentials, settings=self._settings, options=self._options, deps=self._deps
        )

    @asynccontextmanager
    async def _lease(self, source: Source) -> AsyncIterator[PullConnector]:
        """One cached connector (and HTTP client) per source, held open while a poll uses it.

        The cache is rebuilt when the source's type, config or secret changes.
        Eviction and :meth:`close` only close connectors nobody is using; a
        connector in use is closed when its last user releases it.
        """
        key = (source.tenant_id, source.id)
        wanted = _config_key(source)
        entry = self._connectors.get(key)
        if entry is not None and entry.config_key == wanted:
            self._connectors.move_to_end(key)
        else:
            await self._retire(key)
            entry = _CachedConnector(wanted, self._build_connector(source))
            self._connectors[key] = entry
        entry.users += 1
        try:
            await self._evict_idle()
            yield entry.connector
        finally:
            entry.users -= 1
            if entry.retired and entry.users == 0:
                await entry.connector.aclose()

    async def _evict_idle(self) -> None:
        excess = len(self._connectors) - MAX_CACHED_CONNECTORS
        if excess <= 0:
            return
        idle = [k for k, e in self._connectors.items() if e.users == 0][:excess]
        for key in idle:
            await self._retire(key)

    async def _retire(self, key: Tuple[str, str]) -> None:
        entry = self._connectors.pop(key, None)
        if entry is None:
            return
        entry.retired = True
        if entry.users == 0:
            await entry.connector.aclose()

    async def _prepare_event(
        self, index: int, event: Any, ctx: NormalizeContext, normalizer: Normalizer
    ) -> _Outcome:
        """Total: every failure becomes a rejection of this event only."""
        try:
            if not isinstance(event, Mapping):
                return _Outcome(reason="event must be a JSON object")
            cleaned = strip_nul_deep(event)
            size = json_size(cleaned)
            if size > self._options.max_event_bytes:
                return _Outcome(reason=f"event is larger than {self._options.max_event_bytes} bytes")
            if size > self._options.redact_in_thread_bytes:
                return await asyncio.to_thread(self._normalize_event, index, cleaned, ctx, normalizer)
            return self._normalize_event(index, cleaned, ctx, normalizer)
        except Exception as exc:  # noqa: BLE001 - one malformed event must not fail the batch or wedge a cursor
            log.warning("ingestion.event_failed", normalizer=normalizer.name, error_type=type(exc).__name__)
            return _Outcome(reason=f"event could not be processed ({type(exc).__name__})")

    def _normalize_event(
        self, index: int, cleaned: Mapping[str, Any], ctx: NormalizeContext, normalizer: Normalizer
    ) -> _Outcome:
        """Redact, normalize and build the row (synchronous; large events run it in a thread)."""
        redacted, redactions = redact(cleaned)
        try:
            alert = normalizer.normalize(redacted, ctx)
        except UnrecognizedEvent as exc:
            if self._options.llm_fallback:
                return _Outcome(pending_llm=redacted)
            return _Outcome(reason=str(exc))
        except NormalizationError as exc:
            return _Outcome(reason=str(exc))
        return _Outcome(prepared=self._finish(index, alert, redacted, redactions))

    def _finish(self, index: int, alert: CanonicalAlert, redacted: Mapping[str, Any], redactions: int) -> _Prepared:
        raw = cap_mapping(redacted, self._options.max_raw_bytes)
        flags = list(alert.flags)
        if TRUNCATED_MARKER in raw and TRUNCATED_MARKER not in redacted:
            flags.append(FLAG_RAW_TRUNCATED)
        if redactions:
            flags.append(FLAG_REDACTED)
        if alert.source_id == SAMPLE_SOURCE_ID:
            flags.append(FLAG_SAMPLE)
        alert = alert.model_copy(update={"raw": raw, "flags": flags})
        row = NewAlert(
            source_id=alert.source_id,
            source_alert_id=alert.source_alert_id,
            fingerprint=compute_fingerprint(alert),
            title=alert.title,
            severity=alert.severity,
            category=alert.category,
            occurred_at=alert.occurred_at,
            raw=raw,
            normalized=alert.normalized_document(),
        )
        return _Prepared(index, row)

    async def _llm_prepare(
        self,
        tenant_id: str,
        index: int,
        redacted: Dict[str, Any],
        ctx: NormalizeContext,
        budget_limit: BudgetLimit = USE_DEFAULT,
    ) -> _Outcome:
        try:
            alert = await llm_normalize(
                redacted, ctx, settings=self._settings, tenant_id=tenant_id, budget=self._budget, budget_limit=budget_limit
            )
            prepared = self._finish(index, alert, redacted, 0)
        except asyncio.CancelledError:
            raise
        except LLMBudgetExceeded:
            record_llm_normalization("budget_exceeded")
            return _Outcome(reason="unrecognized event format (LLM budget exceeded)")
        except NormalizationError as exc:
            record_llm_normalization("error")
            log.warning("ingestion.llm_normalization_failed", error_type=type(exc).__name__)
            return _Outcome(reason="unrecognized event format (LLM normalization failed)")
        except Exception as exc:  # noqa: BLE001 - provider errors (timeouts, 429, 5xx) reject this event only
            record_llm_normalization("error")
            log.warning("ingestion.llm_normalization_failed", error_type=type(exc).__name__)
            return _Outcome(reason="unrecognized event format (LLM normalization unavailable)")
        record_llm_normalization("success")
        return _Outcome(prepared=prepared)

    async def _tenant_budget_limit(self, tenant_id: str) -> BudgetLimit:
        """The tenant's ``llm_daily_token_budget`` (what the workflow honours), else the install default."""
        try:
            tenant = await self._repos.tenants.get(tenant_id)
        except NotFound:
            return USE_DEFAULT
        limit = tenant.settings.get("llm_daily_token_budget")
        return limit if isinstance(limit, int) and not isinstance(limit, bool) else USE_DEFAULT

    async def _llm_phase(
        self, tenant_id: str, pending: List[Tuple[int, Dict[str, Any]]], ctx: NormalizeContext
    ) -> Dict[int, _Outcome]:
        """LLM normalization for one call: bounded concurrency and a total time limit."""
        results: Dict[int, _Outcome] = {}
        if not pending:
            return results
        slots = asyncio.Semaphore(self._options.llm_fallback_concurrency)
        budget_limit = await self._tenant_budget_limit(tenant_id)

        async def one(index: int, redacted: Dict[str, Any]) -> None:
            async with slots:
                results[index] = await self._llm_prepare(tenant_id, index, redacted, ctx, budget_limit)

        try:
            async with asyncio.timeout(self._options.llm_fallback_timeout_s):
                async with asyncio.TaskGroup() as group:
                    for index, redacted in pending:
                        group.create_task(one(index, redacted))
        except TimeoutError:
            unfinished = sum(1 for index, _ in pending if index not in results)
            log.warning("ingestion.llm_fallback_timeout", tenant_id=tenant_id, unfinished=unfinished)
        for index, _ in pending:
            if index not in results:
                record_llm_normalization("timeout")
                results[index] = _Outcome(reason="unrecognized event format (LLM normalization timed out)")
        return results

    async def _ingest(
        self,
        tenant_id: str,
        source_id: str,
        source_type: str,
        fmt: str,
        config: Mapping[str, Any],
        events: Sequence[Any],
        *,
        page: Optional[FetchedPage],
    ) -> IngestResult:
        normalizer = get_normalizer(fmt)
        now = datetime.now(UTC)
        ctx = NormalizeContext(
            source_id=source_id,
            source_type=source_type,
            config=config or {},
            now=now,
            max_future=timedelta(seconds=self._options.max_future_skew_s),
        )
        prepared: List[_Prepared] = []
        reasons: Dict[int, str] = {}
        pending: List[Tuple[int, Dict[str, Any]]] = []
        outcomes: List[Tuple[int, _Outcome]] = []
        for index, event in enumerate(events):
            outcome = await self._prepare_event(index, event, ctx, normalizer)
            waiting = outcome.pending_llm
            if waiting is not None:
                if len(pending) >= self._options.llm_fallback_max_per_call:
                    outcome = _Outcome(reason="unrecognized event format (LLM fallback limit reached for this batch)")
                else:
                    pending.append((index, waiting))
                    continue
            outcomes.append((index, outcome))
        outcomes.extend((await self._llm_phase(tenant_id, pending, ctx)).items())
        for index, outcome in sorted(outcomes, key=lambda pair: pair[0]):
            if outcome.prepared is not None:
                prepared.append(outcome.prepared)
            else:
                reasons[index] = outcome.reason or "rejected"

        unique: List[_Prepared] = []
        seen: Dict[str, int] = {}
        in_batch_dupes: Dict[int, str] = {}
        for p in prepared:
            if p.row.source_alert_id in seen:
                in_batch_dupes[p.index] = p.row.source_alert_id
                continue
            seen[p.row.source_alert_id] = p.index
            unique.append(p)

        inserted_ids: set[str] = set()
        existing: Dict[str, str] = {}
        async with self._db.tenant_tx(tenant_id) as conn:
            batch = self._options.batch_size
            for start in range(0, len(unique), batch):
                chunk = [p.row for p in unique[start : start + batch]]
                inserted_ids.update(await self._repos.alerts.insert_many_if_absent(tenant_id, chunk, conn=conn))
            if inserted_ids and source_id != SAMPLE_SOURCE_ID:
                await self._repos.usage.add_ingested(tenant_id, len(inserted_ids), conn=conn)
            dup_keys = [p.row.source_alert_id for p in unique if p.row.id not in inserted_ids]
            dup_keys.extend(in_batch_dupes.values())
            if dup_keys:
                existing = await self._repos.alerts.ids_by_source_keys(
                    tenant_id, source_id, sorted(set(dup_keys)), conn=conn
                )
            if page is not None:
                # Pulled alerts get their queued run in the transaction that moves the cursor
                # past them: if the poll is cancelled (rolling deploy, leadership loss) before
                # the scheduler enqueues them, the orphaned-run sweep still finds the runs.
                if inserted_ids:
                    await self._repos.runs.queue_alerts(
                        tenant_id, [p.row.id for p in unique if p.row.id in inserted_ids], conn=conn
                    )
                advanced = await self._repos.sources.set_cursor(
                    tenant_id, source_id, page.cursor, page.watermark, conn=conn
                )
                if not advanced:
                    log.warning("ingestion.cursor_not_advanced", tenant_id=tenant_id, source_id=source_id)

        result = IngestResult()
        by_index = {p.index: p for p in unique}
        for index in range(len(events)):
            if index in reasons:
                result.rejected.append(RejectedEvent(index, reasons[index]))
                result.items.append(IngestItem(index, "rejected", reason=reasons[index]))
            elif index in in_batch_dupes:
                result.duplicates += 1
                result.items.append(IngestItem(index, "duplicate", alert_id=existing.get(in_batch_dupes[index])))
            else:
                p = by_index[index]
                if p.row.id in inserted_ids:
                    result.inserted.append(IngestedAlert(alert_id=p.row.id, severity=p.row.severity))
                    result.items.append(IngestItem(index, "inserted", alert_id=p.row.id))
                else:
                    result.duplicates += 1
                    result.items.append(
                        IngestItem(index, "duplicate", alert_id=existing.get(p.row.source_alert_id))
                    )
        record_events(source_type, "inserted", len(result.inserted))
        record_events(source_type, "duplicate", result.duplicates)
        record_events(source_type, "rejected", len(result.rejected))
        if events:
            log.info(
                "ingestion.batch",
                tenant_id=tenant_id,
                source_id=source_id,
                source_type=source_type,
                received=len(events),
                inserted=len(result.inserted),
                duplicates=result.duplicates,
                rejected=len(result.rejected),
            )
        return result
