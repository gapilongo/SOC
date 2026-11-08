"""Enrichment service: credentials, per-tenant cache, rate limits and fan-out over providers.

One instance per process (held by the analysis agent); it keeps no per-alert
state. For every lookup it:

1. resolves the provider's API key for the tenant: the tenant's own key from
   ``tenants.settings.tools.<provider>.api_key_ciphertext`` (encrypted with
   :class:`~lg_sotf.security.crypto.SecretBox`, bound to the tenant and
   provider), else the install key ``settings.tools.<provider>.api_key``.
   Sending a tenant's indicators to a third party under the install key
   needs consent: either the install shares its key with every tenant
   (``share_with_tenants: true``, the natural choice for a single-organisation
   install) or the tenant opts in with ``tenants.settings.tools.<provider>.
   enabled: true``. A tenant can turn a provider off with ``enabled: false``.
   No usable key means ``not_configured``;
2. never sends a tenant's internal names: domains and URL hosts equal to, or
   under, the tenant's internal domains (``tenants.settings.tools.
   internal_domains``, the domains of ``protected_assets``, and the install's
   ``settings.tools.internal_domains``) are ``skipped``, like private IPs;
3. answers from a bounded per-tenant TTL cache when it can (results are
   never shared between tenants);
4. honours a backoff after a provider said 429 (``Retry-After``) and a
   client-side ``requests_per_minute`` budget, returning ``rate_limited``
   instead of calling. Both are kept per *credential*: every tenant using the
   shared install key draws on one budget and backs off together, while a
   tenant's own key has its own. (The budget is per process; with several
   workers set ``requests_per_minute`` to the key's quota divided by the
   worker count.)
5. runs the provider under a deadline; a failure becomes an ``error`` result,
   never an exception that fails the workflow node.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, replace
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Hashable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from urllib.parse import urlsplit

import httpx

from lg_sotf.net.egress import allowed_hosts, host_on_list
from lg_sotf.observability.logging import get_logger
from lg_sotf.observability.metrics import record_enrichment_lookup
from lg_sotf.security.crypto import DecryptionError, SecretBox
from lg_sotf.security.hashing import normalize_indicator
from lg_sotf.security.shadow import Arguments, egress, sink
from lg_sotf.tools.enrichment.base import (
    CACHEABLE_STATUSES,
    EnrichmentProvider,
    EnrichmentResult,
    LookupRequest,
    ProviderCredentials,
)
from lg_sotf.tools.enrichment.history import HistoryProvider
from lg_sotf.tools.enrichment.providers import (
    AbuseIPDBProvider,
    VirusTotalProvider,
    normal_hash,
    public_domain,
    public_ip,
    public_url,
)

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories
    from lg_sotf.settings import Settings

log = get_logger(__name__)

DEFAULT_LOOKUP_TIMEOUT_S = 20.0
DEFAULT_CACHE_ENTRIES_PER_TENANT = 2_000
DEFAULT_CACHE_TENANTS = 512
CREDENTIAL_TTL_S = 60.0
MAX_TRACKED_LIMITS = 4_096
TENANT_TOOLS_KEY = "tools"
_TOOLS_CACHE_KEY = ("tenant-settings", "tools")
MAX_INTERNAL_DOMAINS = 256
Clock = Callable[[], float]


def tool_secret_context(tenant_id: str, provider: str) -> str:
    """Encryption context binding a tenant's provider key to that tenant and provider."""
    return f"tool:{tenant_id}:{provider}"


def encrypt_tool_secret(box: SecretBox, tenant_id: str, provider: str, api_key: str) -> str:
    """Ciphertext for ``tenants.settings.tools.<provider>.api_key_ciphertext`` (used by the settings API)."""
    if not api_key:
        raise ValueError("api_key must not be empty")
    return box.encrypt_json({"api_key": api_key}, context=tool_secret_context(tenant_id, provider))


class TenantTTLCache:
    """LRU + TTL cache partitioned by tenant, bounded in tenants and entries per tenant."""

    def __init__(
        self,
        *,
        max_entries_per_tenant: int = DEFAULT_CACHE_ENTRIES_PER_TENANT,
        max_tenants: int = DEFAULT_CACHE_TENANTS,
        clock: Clock = time.monotonic,
    ) -> None:
        if max_entries_per_tenant < 1 or max_tenants < 1:
            raise ValueError("cache bounds must be >= 1")
        self.max_entries_per_tenant = max_entries_per_tenant
        self.max_tenants = max_tenants
        self._clock = clock
        self._data: OrderedDict[str, OrderedDict[Hashable, Tuple[float, Any]]] = OrderedDict()

    def get(self, tenant_id: str, key: Hashable) -> Optional[Any]:
        bucket = self._data.get(tenant_id)
        if bucket is None:
            return None
        entry = bucket.get(key)
        if entry is None:
            return None
        expires, value = entry
        if expires <= self._clock():
            del bucket[key]
            return None
        bucket.move_to_end(key)
        self._data.move_to_end(tenant_id)
        return value

    def set(self, tenant_id: str, key: Hashable, value: Any, ttl_s: float) -> None:
        if ttl_s <= 0:
            return
        bucket = self._data.get(tenant_id)
        if bucket is None:
            bucket = self._data[tenant_id] = OrderedDict()
            while len(self._data) > self.max_tenants:
                self._data.popitem(last=False)
        bucket[key] = (self._clock() + ttl_s, value)
        bucket.move_to_end(key)
        self._data.move_to_end(tenant_id)
        while len(bucket) > self.max_entries_per_tenant:
            bucket.popitem(last=False)

    def size(self, tenant_id: Optional[str] = None) -> int:
        if tenant_id is not None:
            return len(self._data.get(tenant_id, ()))
        return sum(len(b) for b in self._data.values())

    def drop(self, tenant_id: str) -> None:
        self._data.pop(tenant_id, None)

    def clear(self) -> None:
        self._data.clear()


def limit_scope(tenant_id: str, credentials: Optional[ProviderCredentials]) -> str:
    """The rate-limit scope of a lookup: the credential it spends, not the tenant asking.

    Every tenant using the shared install key shares one scope; a tenant's
    own key is its own scope.
    """
    if credentials is not None and credentials.source == "install":
        return "install"
    return f"tenant:{tenant_id}"


class RateLimiter:
    """Sliding one-minute request budget plus provider-imposed backoff, per (scope, provider).

    ``scope`` identifies the credential (see :func:`limit_scope`).
    """

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._windows: OrderedDict[Tuple[str, str], Deque[float]] = OrderedDict()
        self._backoff: OrderedDict[Tuple[str, str], float] = OrderedDict()

    def backoff_remaining(self, scope: str, provider: str) -> Optional[float]:
        until = self._backoff.get((scope, provider))
        if until is None:
            return None
        remaining = until - self._clock()
        if remaining <= 0:
            del self._backoff[(scope, provider)]
            return None
        return remaining

    def back_off(self, scope: str, provider: str, seconds: float) -> None:
        key = (scope, provider)
        self._backoff[key] = self._clock() + max(seconds, 1.0)
        self._backoff.move_to_end(key)
        while len(self._backoff) > MAX_TRACKED_LIMITS:
            self._backoff.popitem(last=False)

    def try_acquire(self, scope: str, provider: str, per_minute: int) -> Optional[float]:
        """None when a request may go now (and counts it), else seconds until one may."""
        if per_minute <= 0:
            return None
        key = (scope, provider)
        now = self._clock()
        window = self._windows.get(key)
        if window is None:
            window = self._windows[key] = deque()
            while len(self._windows) > MAX_TRACKED_LIMITS:
                self._windows.popitem(last=False)
        self._windows.move_to_end(key)
        while window and window[0] <= now - 60.0:
            window.popleft()
        if len(window) >= per_minute:
            return max(window[0] + 60.0 - now, 0.1)
        window.append(now)
        return None


SHADOW_CACHE_MISS = "shadow run: threat-intelligence answers come from the cache only"


def _cache_miss_in_shadow(args: Arguments) -> EnrichmentResult:
    return EnrichmentResult.failed(args["provider"].name, args["request"].kind, "skipped", SHADOW_CACHE_MISS)


def _lookup_detail(args: Arguments) -> Dict[str, Any]:
    return {"provider": args["provider"].name, "kind": args["request"].kind}


@dataclass(frozen=True)
class _Resolved:
    credentials: Optional[ProviderCredentials]
    problem: Optional[str] = None


@dataclass(frozen=True)
class _TenantTools:
    """The parts of ``tenants.settings`` enrichment needs, read once per tenant per TTL."""

    tools: Mapping[str, Any]
    internal_domains: FrozenSet[str]


def _domain_suffixes(values: Any) -> List[str]:
    """Normalised domain suffixes from a list of names (``*.corp.example`` -> ``corp.example``)."""
    out: List[str] = []
    if not isinstance(values, (list, tuple)):
        return out
    for value in list(values)[:MAX_INTERNAL_DOMAINS]:
        if not isinstance(value, str):
            continue
        name = value.strip().lower().rstrip(".")
        while name.startswith(("*.", ".")):
            name = name[2:] if name.startswith("*.") else name[1:]
        if name and "*" not in name and "?" not in name and "/" not in name:
            out.append(name)
    return out


def is_internal_domain(host: str, suffixes: FrozenSet[str]) -> bool:
    """Whether ``host`` equals, or is a subdomain of, one of ``suffixes``."""
    name = host.strip().lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in suffixes)


class CredentialResolver:
    """Tenant key (encrypted in tenant settings) first, then the install key; cached briefly per tenant.

    Also resolves the tenant's internal domains (never sent to third parties).
    """

    def __init__(self, settings: Settings, *, box: Optional[SecretBox] = None, clock: Clock = time.monotonic) -> None:
        self.settings = settings
        self._box = box  # the process's (injected); None: tenant keys cannot be read
        self._cache = TenantTTLCache(max_entries_per_tenant=16, max_tenants=DEFAULT_CACHE_TENANTS, clock=clock)
        self._install_internal = frozenset(_domain_suffixes(settings.tools.get("internal_domains")))

    def _install(self, provider: str, *, tenant_opted_in: bool) -> _Resolved:
        cfg = self.settings.tools.get(provider)
        if not isinstance(cfg, Mapping) or cfg.get("enabled") is False:
            return _Resolved(None)
        key: Any = cfg.get("api_key")
        secret = key.get_secret_value() if hasattr(key, "get_secret_value") else key
        shared = cfg.get("share_with_tenants") is True or tenant_opted_in
        if isinstance(secret, str) and secret.strip() and shared:
            return _Resolved(ProviderCredentials(secret.strip(), "install"))
        return _Resolved(None)

    async def tenant_tools(self, tenant_id: str, repos: Optional[Repositories]) -> _TenantTools:
        """The tenant's tool settings and internal domains (cached per tenant for ``CREDENTIAL_TTL_S``)."""
        cached = self._cache.get(tenant_id, _TOOLS_CACHE_KEY)
        if isinstance(cached, _TenantTools):
            return cached
        tools: Mapping[str, Any] = {}
        internal = list(self._install_internal)
        if repos is not None:
            tenant = await repos.tenants.get(tenant_id)
            settings = tenant.settings if isinstance(tenant.settings, Mapping) else {}
            raw_tools = settings.get(TENANT_TOOLS_KEY)
            tools = raw_tools if isinstance(raw_tools, Mapping) else {}
            internal += _domain_suffixes(tools.get("internal_domains"))
            assets = settings.get("protected_assets")
            if isinstance(assets, Mapping):
                internal += _domain_suffixes(assets.get("domains"))
        result = _TenantTools(tools, frozenset(internal))
        self._cache.set(tenant_id, _TOOLS_CACHE_KEY, result, CREDENTIAL_TTL_S)
        return result

    async def resolve(self, tenant_id: str, provider: str, repos: Optional[Repositories]) -> _Resolved:
        cached = self._cache.get(tenant_id, provider)
        if isinstance(cached, _Resolved):
            return cached
        resolved = await self._resolve_uncached(tenant_id, provider, repos)
        self._cache.set(tenant_id, provider, resolved, CREDENTIAL_TTL_S)
        return resolved

    async def _resolve_uncached(self, tenant_id: str, provider: str, repos: Optional[Repositories]) -> _Resolved:
        tools = (await self.tenant_tools(tenant_id, repos)).tools
        entry = tools.get(provider)
        opted_in = False
        if isinstance(entry, Mapping):
            if entry.get("enabled") is False:
                return _Resolved(None)
            opted_in = entry.get("enabled") is True
            ciphertext = entry.get("api_key_ciphertext")
            if isinstance(ciphertext, str) and ciphertext:
                box = self._box
                if box is None:
                    log.error("enrichment.tenant_key_unreadable", provider=provider, reason="no_encryption_keys")
                    return _Resolved(None, "credentials unreadable")
                try:
                    value = box.decrypt_json(ciphertext, context=tool_secret_context(tenant_id, provider))
                except DecryptionError:
                    log.error("enrichment.tenant_key_unreadable", provider=provider, reason="decryption_failed")
                    return _Resolved(None, "credentials unreadable")
                api_key = value.get("api_key") if isinstance(value, Mapping) else None
                if isinstance(api_key, str) and api_key.strip():
                    return _Resolved(ProviderCredentials(api_key.strip(), "tenant"))
                return _Resolved(None, "credentials unreadable")
        return self._install(provider, tenant_opted_in=opted_in)

    def invalidate(self, tenant_id: Optional[str] = None) -> None:
        """Forget cached credentials of one tenant (or all) after provider settings change."""
        if tenant_id is None:
            self._cache.clear()
        else:
            self._cache.drop(tenant_id)


class EnrichmentService:
    def __init__(
        self,
        providers: Sequence[EnrichmentProvider],
        settings: Settings,
        *,
        credentials: Optional[CredentialResolver] = None,
        cache: Optional[TenantTTLCache] = None,
        limiter: Optional[RateLimiter] = None,
        lookup_timeout_s: Optional[float] = None,
    ) -> None:
        self.settings = settings
        self._providers: Dict[str, EnrichmentProvider] = {}
        for provider in providers:
            if provider.name in self._providers:
                raise ValueError(f"enrichment provider {provider.name!r} registered twice")
            self._providers[provider.name] = provider
        self.credentials = credentials or CredentialResolver(settings)
        raw_cache_cfg = settings.tools.get("cache")
        cache_cfg: Mapping[str, Any] = raw_cache_cfg if isinstance(raw_cache_cfg, Mapping) else {}
        self.cache = cache or TenantTTLCache(
            max_entries_per_tenant=int(cache_cfg.get("max_entries_per_tenant", DEFAULT_CACHE_ENTRIES_PER_TENANT)),
            max_tenants=int(cache_cfg.get("max_tenants", DEFAULT_CACHE_TENANTS)),
        )
        self.limiter = limiter or RateLimiter()
        self.lookup_timeout_s = float(
            lookup_timeout_s if lookup_timeout_s is not None else settings.tools.get("lookup_timeout_s", DEFAULT_LOOKUP_TIMEOUT_S)
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        secret_box: Optional[SecretBox] = None,
    ) -> EnrichmentService:
        """VirusTotal, AbuseIPDB and history providers configured from ``settings.tools``.

        ``secret_box`` (the process's, injected by its composition root) decrypts tenant tool keys.
        """
        tools = settings.tools

        def section(name: str) -> Mapping[str, Any]:
            value = tools.get(name)
            return value if isinstance(value, Mapping) else {}

        production = settings.is_production
        external: List[Union[VirusTotalProvider, AbuseIPDBProvider]] = [
            VirusTotalProvider(section("virustotal"), production=production, transport=transport),
            AbuseIPDBProvider(section("abuseipdb"), production=production, transport=transport),
        ]
        # The egress allow-list (ingestion.allowed_destination_hosts) leaves out providers whose host is not on it.
        hosts = allowed_hosts(settings)
        providers: List[EnrichmentProvider] = [
            p for p in external if hosts is None or host_on_list(urlsplit(p.base_url).hostname or "", hosts)
        ]
        providers.append(HistoryProvider(section("history")))
        return cls(providers, settings, credentials=CredentialResolver(settings, box=secret_box))

    def provider(self, name: str) -> EnrichmentProvider:
        return self._providers[name]

    @property
    def provider_names(self) -> List[str]:
        return list(self._providers)

    def _external(self, kind: Optional[str] = None) -> List[EnrichmentProvider]:
        return [p for p in self._providers.values() if p.external and (kind is None or kind in p.kinds)]

    async def shareable(
        self, tenant_id: str, kind: str, value: str, repos: Optional[Repositories]
    ) -> Optional[str]:
        """The form of ``value`` that may be sent to a third party for this tenant, or None.

        Public IPs, hex hashes, public domains and ``scheme://host/path`` URLs
        without secret-looking path segments; never a name under one of the
        tenant's internal domains.
        """
        host: Optional[str] = None
        if kind == "ip":
            return public_ip(value)
        if kind == "hash":
            return normal_hash(value)
        if kind == "domain":
            reduced = host = public_domain(value)
        elif kind == "url":
            reduced = public_url(value)
            host = urlsplit(reduced).hostname if reduced else None
        else:
            return None
        if reduced is None:
            return None
        internal = (await self.credentials.tenant_tools(tenant_id, repos)).internal_domains
        if host and internal and is_internal_domain(host, internal):
            return None
        return reduced

    async def configured_kinds(self, tenant_id: str, repos: Optional[Repositories]) -> Dict[str, List[str]]:
        """Indicator kind -> external providers with credentials for this tenant."""
        out: Dict[str, List[str]] = {}
        for provider in self._external():
            if provider.requires_credentials():
                resolved = await self.credentials.resolve(tenant_id, provider.name, repos)
                if resolved.credentials is None:
                    continue
            for kind in sorted(provider.kinds):
                out.setdefault(kind, []).append(provider.name)
        return out

    async def lookup(
        self,
        tenant_id: str,
        kind: str,
        value: str,
        *,
        repos: Optional[Repositories] = None,
        exclude_alert_id: Optional[str] = None,
        providers: Optional[Sequence[str]] = None,
    ) -> List[EnrichmentResult]:
        """Query every external provider that supports ``kind`` (or the named ones) concurrently."""
        chosen = [
            p for p in self._external(kind) if providers is None or p.name in providers
        ]
        if not chosen:
            return [EnrichmentResult.failed("none", kind, "not_configured", "no provider supports this indicator")]
        return list(
            await asyncio.gather(
                *(self._lookup_one(p, tenant_id, kind, value, repos, exclude_alert_id) for p in chosen)
            )
        )

    async def history(
        self,
        tenant_id: str,
        kind: str,
        value: str,
        *,
        repos: Optional[Repositories],
        exclude_alert_id: Optional[str] = None,
    ) -> EnrichmentResult:
        provider = self._providers.get(HistoryProvider.name)
        if provider is None:
            return EnrichmentResult.failed(HistoryProvider.name, kind, "not_configured")
        return await self._lookup_one(provider, tenant_id, kind, value, repos, exclude_alert_id)

    async def _lookup_one(
        self,
        provider: EnrichmentProvider,
        tenant_id: str,
        kind: str,
        value: str,
        repos: Optional[Repositories],
        exclude_alert_id: Optional[str],
    ) -> EnrichmentResult:
        result = await self._resolve_and_call(provider, tenant_id, kind, value, repos, exclude_alert_id)
        record_enrichment_lookup(provider.name, "cached" if result.cached else result.status)
        if result.status not in ("ok", "not_found") and not result.cached:
            log.info("enrichment.lookup", provider=provider.name, kind=kind, status=result.status, error=result.error)
        return result

    async def _resolve_and_call(
        self,
        provider: EnrichmentProvider,
        tenant_id: str,
        kind: str,
        value: str,
        repos: Optional[Repositories],
        exclude_alert_id: Optional[str],
    ) -> EnrichmentResult:
        if kind not in provider.kinds:
            return EnrichmentResult.failed(provider.name, kind, "unsupported")
        sent = value
        if provider.external:
            shared = await self.shareable(tenant_id, kind, value, repos)
            if shared is None:
                return EnrichmentResult.failed(provider.name, kind, "skipped", "not a public indicator")
            sent = shared
        credentials: Optional[ProviderCredentials] = None
        if provider.requires_credentials():
            resolved = await self.credentials.resolve(tenant_id, provider.name, repos)
            if resolved.credentials is None:
                if resolved.problem:
                    return EnrichmentResult.failed(provider.name, kind, "error", resolved.problem)
                return EnrichmentResult.failed(provider.name, kind, "not_configured")
            credentials = resolved.credentials
        # The history provider's answer depends on the excluded alert; external answers do not.
        cache_key = (provider.name, kind, normalize_indicator(kind, value), exclude_alert_id if not provider.external else None)
        cached = self.cache.get(tenant_id, cache_key)
        if isinstance(cached, EnrichmentResult):
            return replace(cached, cached=True)
        request = LookupRequest(
            tenant_id=tenant_id,
            kind=kind,
            value=sent,
            settings=self.settings,
            credentials=credentials,
            repos=repos,
            exclude_alert_id=exclude_alert_id,
        )
        if provider.external:
            result = await self._ask_provider(provider, request)
        else:
            result = await self._ask(provider, request)
        if result.status in CACHEABLE_STATUSES:
            self.cache.set(tenant_id, cache_key, result, float(provider.cache_ttl_s))
        return result

    async def _ask(self, provider: EnrichmentProvider, request: LookupRequest) -> EnrichmentResult:
        try:
            async with asyncio.timeout(self.lookup_timeout_s):
                return await provider.lookup(request)
        except TimeoutError:
            return EnrichmentResult.failed(provider.name, request.kind, "error", "lookup timed out")

    @egress("enrichment_lookup", sink(_cache_miss_in_shadow, detail=_lookup_detail))
    async def _ask_provider(self, provider: EnrichmentProvider, request: LookupRequest) -> EnrichmentResult:
        """A third-party lookup under the provider's rate limit and 429 back-off.

        A shadow run answers from the cache only (the caller's cache read): a miss is ``skipped``, so the
        indicator never leaves the platform for a shadow run and production's request budget is untouched.
        """
        scope = limit_scope(request.tenant_id, request.credentials)
        remaining = self.limiter.backoff_remaining(scope, provider.name)
        if remaining is not None:
            return EnrichmentResult.failed(
                provider.name, request.kind, "rate_limited", "backing off after HTTP 429", remaining
            )
        per_minute = int(getattr(provider, "requests_per_minute", 0) or 0)
        wait = self.limiter.try_acquire(scope, provider.name, per_minute)
        if wait is not None:
            return EnrichmentResult.failed(provider.name, request.kind, "rate_limited", "request budget used", wait)
        result = await self._ask(provider, request)
        if result.status == "rate_limited":
            self.limiter.back_off(scope, provider.name, result.retry_after_s or 60.0)
        return result

    async def aclose(self) -> None:
        for provider in self._providers.values():
            await provider.aclose()
