"""Pull connector contract.

A connector turns a persisted cursor into a stream of :class:`FetchedPage`.
Each page carries the cursor to store **after** that page's alerts are
committed, so a crash or a page cap resumes exactly after the last committed
page and a failure never skips one. Cursors are JSON objects owned by the
connector (``{"v": 1, ...}``); the ``watermark`` is the source time the
cursor stands for and never moves backwards (``sources.set_cursor`` refuses
to rewind it).

Time-window connectors (Splunk, Sentinel, CrowdStrike, Wazuh) query
``[since - overlap, until]`` where ``until`` is fixed when the query starts.
While a query is being paged, the cursor holds the query position and the
old ``since``; once the query is drained ``since`` becomes
``max(old since, newest event time returned, until - overlap)``. Re-reading
the overlap window is harmless because inserts are deduplicated on
``(source_id, source_alert_id)``.
"""

from __future__ import annotations

import abc
import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncGenerator, Callable, ClassVar, Dict, List, Mapping, Optional

import httpx

from lg_sotf.db.repos import Source
from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources.http import AuthStrategy, SleepFn, SourceHttpClient, build_verify
from lg_sotf.ingestion.sources.netpolicy import DestinationPolicy, Resolver, system_resolve
from lg_sotf.ingestion.timeparse import parse_timestamp
from lg_sotf.settings import Settings

CURSOR_VERSION = 1
DEFAULT_INITIAL_LOOKBACK_S = 3_600


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class FetchedPage:
    events: List[Dict[str, Any]]
    cursor: Dict[str, Any]
    watermark: datetime


@dataclass(frozen=True)
class SourceHealth:
    ok: bool
    detail: str


@dataclass
class ConnectorDeps:
    """Injection points; tests pass an ``httpx.MockTransport``, a fake sleep/clock and a fake resolver.

    An injected ``transport`` still goes through the destination policy
    (with ``resolver``, the system resolver by default); it is only not
    pinned to the resolved address.
    """

    transport: Optional[httpx.AsyncBaseTransport] = None
    resolver: Optional[Resolver] = None
    sleep: SleepFn = asyncio.sleep
    now: Callable[[], datetime] = utcnow
    rand: Optional[Callable[[], float]] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class PullConnector(abc.ABC):
    source_type: ClassVar[str]

    def __init__(
        self,
        source: Source,
        credentials: Mapping[str, Any],
        *,
        settings: Settings,
        options: IngestionOptions,
        deps: Optional[ConnectorDeps] = None,
    ):
        self.source = source
        self.config: Mapping[str, Any] = source.config or {}
        self._credentials = dict(credentials)
        self.settings = settings
        self.options = options.for_source(self.config)
        self.deps = deps or ConnectorDeps()
        self.policy = DestinationPolicy(
            require_https=settings.is_production, allow_private=options.allow_private_destinations
        )
        self._clients: List[SourceHttpClient] = []
        self._destinations: List[str] = []

    def __repr__(self) -> str:
        return f"{type(self).__name__}(tenant_id={self.source.tenant_id!r}, source_id={self.source.id!r})"

    @abc.abstractmethod
    def pages(self, cursor: Optional[Mapping[str, Any]]) -> AsyncGenerator[FetchedPage, None]:
        """Yield pages from ``cursor`` onwards; the last page carries the drained cursor."""

    @abc.abstractmethod
    async def test(self) -> SourceHealth:
        """Check connectivity and credentials with a cheap read; raises :class:`SourceError`."""

    def destination(self, url: str) -> str:
        """Register a URL this connector will call (base URLs, token endpoints); checks its scheme."""
        self.policy.check_url(url)
        self._destinations.append(url)
        return url

    async def check_destinations(self) -> None:
        """Resolve every registered URL and apply the destination policy (for source create/update)."""
        resolver = self.deps.resolver or system_resolve
        for url in self._destinations:
            await self.policy.check(url, resolver)

    async def aclose(self) -> None:
        clients, self._clients = self._clients, []
        for client in clients:
            await client.aclose()

    # -- helpers ---------------------------------------------------------------

    def config_str(self, key: str, default: Optional[str] = None) -> str:
        value = self.config.get(key, default)
        if not isinstance(value, str) or not value.strip():
            raise SourceConfigError(f"{self.source_type} source requires config.{key}")
        return value.strip()

    def config_seconds(self, key: str, default: float, low: float, high: float) -> float:
        """A number of seconds from config, in ``[low, high]``; anything else (null, text, NaN) is a config error."""
        value = self.config.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise SourceConfigError(f"{self.source_type} config.{key} must be a number of seconds between {low:g} and {high:g}")
        return float(value)

    def credential(self, key: str) -> str:
        value = self._credentials.get(key)
        if not isinstance(value, str) or not value:
            raise SourceConfigError(f"{self.source_type} source requires the '{key}' credential")
        return value

    def has_credential(self, key: str) -> bool:
        value = self._credentials.get(key)
        return isinstance(value, str) and bool(value)

    def http(self, base_url: str, auth: Optional[AuthStrategy] = None, **kwargs: Any) -> SourceHttpClient:
        o = self.options
        extra: Dict[str, Any] = {}
        if self.deps.rand is not None:
            extra["rand"] = self.deps.rand
        client = SourceHttpClient(
            source_type=self.source_type,
            base_url=self.destination(base_url),
            auth=auth,
            verify=build_verify(self.config, production=self.settings.is_production),
            timeout_s=o.http_timeout_s,
            connect_timeout_s=o.http_connect_timeout_s,
            max_retries=o.http_max_retries,
            backoff_base_s=o.http_backoff_base_s,
            backoff_max_s=o.http_backoff_max_s,
            max_retry_after_s=o.http_max_retry_after_s,
            transport=self.deps.transport,
            sleep=self.deps.sleep,
            policy=self.policy,
            resolver=self.deps.resolver,
            **extra,
            **kwargs,
        )
        self._clients.append(client)
        return client

    @property
    def overlap(self) -> timedelta:
        return timedelta(seconds=self.options.overlap_s)

    def initial_since(self) -> datetime:
        lookback = self.config.get("initial_lookback_s", DEFAULT_INITIAL_LOOKBACK_S)
        if isinstance(lookback, bool) or not isinstance(lookback, (int, float)) or not 0 <= lookback <= 90 * 86_400:
            raise SourceConfigError("initial_lookback_s must be between 0 and 7776000 seconds")
        return self.deps.now() - timedelta(seconds=float(lookback))

    def cursor_since(self, cursor: Optional[Mapping[str, Any]]) -> datetime:
        if cursor and cursor.get("since"):
            parsed = parse_timestamp(cursor["since"], now=self.deps.now(), max_future=timedelta(days=1))
            if parsed.value is not None:
                return parsed.value
        return self.initial_since()

    def drained_since(self, since: datetime, until: datetime, newest: Optional[datetime]) -> datetime:
        candidates = [since, until - self.overlap]
        if newest is not None:
            candidates.append(min(newest, until))
        return max(candidates)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def window_cursor(since: datetime, **state: Any) -> Dict[str, Any]:
    cursor: Dict[str, Any] = {"v": CURSOR_VERSION, "since": iso(since)}
    cursor.update({k: v for k, v in state.items() if v is not None})
    return cursor
