"""Shared HTTP plumbing for third-party enrichment providers.

* One ``httpx.AsyncClient`` per provider instance, created on first use and
  closed with the provider; TLS verification is always on (an install may
  add a CA bundle, never turn verification off).
* Every request has connect/read timeouts and an overall deadline; bodies
  are capped at ``max_response_bytes``; redirects are not followed (a lookup
  API never needs one, and following them could leak the API key header).
* ``Retry-After`` (seconds or HTTP date) is parsed for 429/503 responses so
  the enrichment service can back off per tenant and provider.
* Error strings name the provider and status only, never headers, keys or
  bodies.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import urlsplit

import httpx

USER_AGENT = "lg-sotf-enrichment/1"
DEFAULT_TIMEOUT_S = 10.0
DEFAULT_CONNECT_TIMEOUT_S = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RETRY_AFTER_S = 3_600.0
DEFAULT_RETRY_AFTER_S = 60.0


class ProviderHTTPError(Exception):
    """A request failed in a way the provider result reports as ``error`` (never carries secrets)."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: Optional[Any]
    retry_after_s: Optional[float]


def parse_retry_after(value: Optional[str], *, now: Optional[datetime] = None) -> Optional[float]:
    """Seconds to wait from a ``Retry-After`` header (delta seconds or HTTP date), capped."""
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        return min(float(text), MAX_RETRY_AFTER_S)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    delta = (when - (now or datetime.now(UTC))).total_seconds()
    return min(max(delta, 0.0), MAX_RETRY_AFTER_S)


def validate_base_url(url: str, *, production: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc or parts.username or parts.password:
        raise ValueError("enrichment base_url must be an absolute http(s) URL without credentials")
    if production and parts.scheme != "https":
        raise ValueError("enrichment base_url must use https in staging/production")
    return url.rstrip("/")


class JsonHttpClient:
    """Minimal JSON GET client for lookup APIs."""

    def __init__(
        self,
        provider: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        verify: Union[bool, str] = True,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be > 0")
        if verify is False:
            raise ValueError("TLS verification cannot be disabled for enrichment providers")
        self.provider = provider
        self.timeout_s = timeout_s
        self.max_response_bytes = max_response_bytes
        self._verify = verify
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        async with self._lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout_s, connect=min(DEFAULT_CONNECT_TIMEOUT_S, self.timeout_s)),
                    verify=self._verify,
                    follow_redirects=False,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                    transport=self._transport,
                    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                )
            return self._client

    async def get_json(
        self, url: str, *, headers: Mapping[str, str], params: Optional[Mapping[str, Any]] = None
    ) -> HttpResponse:
        client = await self._get_client()
        try:
            async with asyncio.timeout(self.timeout_s * 2):
                async with client.stream("GET", url, headers=dict(headers), params=params) as response:
                    retry_after = None
                    if response.status_code in (429, 503):
                        retry_after = parse_retry_after(response.headers.get("Retry-After"))
                    declared = response.headers.get("Content-Length")
                    if declared is not None and declared.isdigit() and int(declared) > self.max_response_bytes:
                        raise ProviderHTTPError(f"{self.provider}: response larger than the configured limit")
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self.max_response_bytes:
                            raise ProviderHTTPError(f"{self.provider}: response larger than the configured limit")
                        chunks.append(chunk)
                    status = response.status_code
        except TimeoutError as exc:
            raise ProviderHTTPError(f"{self.provider}: request timed out") from exc
        except httpx.TimeoutException as exc:
            raise ProviderHTTPError(f"{self.provider}: request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderHTTPError(f"{self.provider}: request failed ({type(exc).__name__})") from exc
        body: Optional[Any] = None
        raw = b"".join(chunks)
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
        return HttpResponse(status=status, body=body, retry_after_s=retry_after)

    async def aclose(self) -> None:
        async with self._lock:
            if self._client is not None:
                await self._client.aclose()
                self._client = None


def as_mapping(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
