"""Enrichment interface: providers, requests and compact results.

An :class:`EnrichmentProvider` looks up one indicator (``ip``, ``domain``,
``url``, ``hash`` and, for internal history, ``user``/``host``/``process``)
and returns an :class:`EnrichmentResult`. Results are compact, bounded
dictionaries of scalars so they can be shown to an LLM and stored in
``alerts.summary`` without growing either. A provider that cannot answer says
so with a status (``not_configured``, ``rate_limited``, ``error`` ...); no
provider ever fabricates or simulates data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, Literal, Mapping, Optional, Protocol, runtime_checkable

from lg_sotf.security.redaction import redact_text

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories
    from lg_sotf.settings import Settings

IndicatorKind = Literal["ip", "domain", "url", "hash", "user", "host", "process"]
Status = Literal["ok", "not_found", "not_configured", "unsupported", "rate_limited", "error", "skipped"]
Verdict = Literal["malicious", "suspicious", "harmless", "unknown"]

EXTERNAL_KINDS: FrozenSet[str] = frozenset({"ip", "domain", "url", "hash"})
MAX_DATA_KEYS = 16
MAX_TEXT_CHARS = 160
MAX_LIST_ITEMS = 5
# Result statuses worth caching: a definitive answer from the provider.
CACHEABLE_STATUSES: FrozenSet[str] = frozenset({"ok", "not_found"})


@dataclass(frozen=True)
class ProviderCredentials:
    """Credentials resolved for one tenant and provider. ``repr`` never shows the key."""

    api_key: str
    source: Literal["tenant", "install"]

    def __repr__(self) -> str:
        return f"ProviderCredentials(source={self.source!r}, api_key=<redacted>)"


@dataclass(frozen=True)
class LookupRequest:
    tenant_id: str
    kind: str
    value: str
    settings: Settings
    credentials: Optional[ProviderCredentials] = None
    repos: Optional[Repositories] = None
    exclude_alert_id: Optional[str] = None


def _compact_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [_compact_value(v) for v in list(value)[:MAX_LIST_ITEMS] if not isinstance(v, (dict, list, tuple))]
    text, _ = redact_text(str(value))
    return text if len(text) <= MAX_TEXT_CHARS else text[: MAX_TEXT_CHARS - 3] + "..."


def compact(data: Mapping[str, Any]) -> Dict[str, Any]:
    """At most :data:`MAX_DATA_KEYS` scalar (or short scalar-list) values, strings redacted and capped."""
    out: Dict[str, Any] = {}
    for key, value in data.items():
        if len(out) >= MAX_DATA_KEYS:
            break
        if isinstance(value, Mapping):
            continue
        out[str(key)[:48]] = _compact_value(value)
    return out


@dataclass(frozen=True)
class EnrichmentResult:
    provider: str
    kind: str
    status: Status
    verdict: Verdict = "unknown"
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    retry_after_s: Optional[float] = None
    cached: bool = False

    @classmethod
    def ok(cls, provider: str, kind: str, verdict: Verdict, data: Mapping[str, Any]) -> EnrichmentResult:
        return cls(provider, kind, "ok", verdict, compact(data))

    @classmethod
    def failed(
        cls, provider: str, kind: str, status: Status, error: Optional[str] = None, retry_after_s: Optional[float] = None
    ) -> EnrichmentResult:
        return cls(provider, kind, status, "unknown", {}, error, retry_after_s)

    def as_dict(self) -> Dict[str, Any]:
        """Compact form for prompts and summaries."""
        out: Dict[str, Any] = {"provider": self.provider, "status": self.status, "verdict": self.verdict}
        if self.data:
            out["data"] = dict(self.data)
        if self.error:
            out["error"] = self.error
        if self.retry_after_s is not None:
            out["retry_after_s"] = round(self.retry_after_s, 1)
        if self.cached:
            out["cached"] = True
        return out


@runtime_checkable
class EnrichmentProvider(Protocol):
    """A source of indicator context. Implementations hold no per-alert state."""

    name: str
    kinds: FrozenSet[str]
    external: bool
    """Whether lookups send the indicator to a third party (and so need a tenant-configured key)."""
    cache_ttl_s: float

    def requires_credentials(self) -> bool: ...

    async def lookup(self, request: LookupRequest) -> EnrichmentResult: ...

    async def aclose(self) -> None: ...
