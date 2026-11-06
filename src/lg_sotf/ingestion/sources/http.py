"""HTTP plumbing shared by the pull connectors.

One :class:`SourceHttpClient` (one ``httpx.AsyncClient``) per source instance.

* TLS verification is on by default. A source may add a CA certificate
  (``ca_cert_pem`` PEM text; ``ca_bundle``, a server file path, only in
  development); ``tls_verify: false`` is refused in staging/production.
* With a :class:`~lg_sotf.net.egress.DestinationPolicy`
  every request (token endpoints included) is checked and pinned to an
  allowed address; see that module.
* Every request has a connect timeout and an overall deadline.
* 429 and 5xx responses and network errors are retried with exponential
  backoff plus jitter; ``Retry-After`` (seconds or HTTP date) is honoured,
  and a wait longer than ``max_retry_after_s`` ends the request with
  :class:`SourceRateLimited` instead of stalling the poller.
* OAuth2 client-credentials tokens are cached and refreshed shortly before
  they expire; a 401 invalidates the token and the request is retried once
  (a loop with a flag, never recursion).
* Response bodies are capped at ``max_response_bytes``.

Error messages carry the source type, method, path and status only - never
headers, credentials or bodies.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Protocol

import httpx

from lg_sotf.ingestion.errors import (
    SourceAuthError,
    SourceConfigError,
    SourceProtocolError,
    SourceRateLimited,
    SourceRequestError,
    SourceResponseTooLarge,
    SourceUnavailable,
)
from lg_sotf.ingestion.metrics import record_http_retry
from lg_sotf.net.egress import DestinationPolicy, GuardedTransport, Resolver, system_resolve
from lg_sotf.net.retry import exp_backoff, parse_retry_after
from lg_sotf.net.tls import Verify

SleepFn = Callable[[float], Awaitable[None]]

DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
USER_AGENT = "lg-sotf-ingestion/1"


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes = field(repr=False)

    def json(self) -> Any:
        try:
            return json.loads(self.content)
        except ValueError as exc:
            raise SourceProtocolError(f"response is not valid JSON (HTTP {self.status_code})") from exc


class AuthStrategy(Protocol):
    refreshable: bool

    async def headers(self, http: SourceHttpClient) -> Mapping[str, str]: ...

    def invalidate(self) -> None: ...


class NoAuth:
    refreshable = False

    async def headers(self, http: SourceHttpClient) -> Mapping[str, str]:
        return {}

    def invalidate(self) -> None:
        return None


class HeaderAuth:
    """Static credential headers (Splunk bearer token, QRadar ``SEC`` token)."""

    refreshable = False

    def __init__(self, headers: Mapping[str, str]):
        self._headers = dict(headers)

    def __repr__(self) -> str:
        return f"HeaderAuth(names={sorted(self._headers)})"

    async def headers(self, http: SourceHttpClient) -> Mapping[str, str]:
        return self._headers

    def invalidate(self) -> None:
        return None


class BasicAuth(HeaderAuth):
    def __init__(self, username: str, password: str):
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        super().__init__({"Authorization": f"Basic {token}"})


class OAuth2ClientCredentials:
    """Client-credentials grant with a cached token, refreshed ``refresh_margin_s`` before expiry."""

    refreshable = True

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: Optional[str] = None,
        extra_form: Optional[Mapping[str, str]] = None,
        refresh_margin_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._token_url = token_url
        self._form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        if scope:
            self._form["scope"] = scope
        self._form.update(extra_form or {})
        self._margin = refresh_margin_s
        self._clock = clock
        self._token: Optional[str] = None
        self._refresh_at = 0.0
        self._lock = asyncio.Lock()
        self.fetches = 0

    def __repr__(self) -> str:
        return f"OAuth2ClientCredentials(token_url={self._token_url!r})"

    async def headers(self, http: SourceHttpClient) -> Mapping[str, str]:
        async with self._lock:
            if self._token is None or self._clock() >= self._refresh_at:
                await self._fetch(http)
            assert self._token is not None
            return {"Authorization": f"Bearer {self._token}"}

    def invalidate(self) -> None:
        self._token = None

    async def _fetch(self, http: SourceHttpClient) -> None:
        self.fetches += 1
        resp = await http.send("POST", self._token_url, data=self._form, headers={"Accept": "application/json"})
        if resp.status_code in (400, 401, 403):
            raise SourceAuthError(f"{http.source_type} token endpoint rejected the client credentials "
                                  f"(HTTP {resp.status_code})")
        if resp.status_code >= 300:
            raise SourceProtocolError(f"{http.source_type} token endpoint returned HTTP {resp.status_code}")
        body = resp.json()
        token = body.get("access_token") if isinstance(body, Mapping) else None
        if not isinstance(token, str) or not token:
            raise SourceProtocolError(f"{http.source_type} token endpoint returned no access_token")
        try:
            expires_in = float(body.get("expires_in", 3600))
        except (TypeError, ValueError):
            expires_in = 3600.0
        expires_in = max(expires_in, 1.0)
        self._token = token
        self._refresh_at = self._clock() + expires_in - min(self._margin, expires_in / 2)


class SourceHttpClient:
    def __init__(
        self,
        *,
        source_type: str,
        base_url: str,
        auth: Optional[AuthStrategy] = None,
        verify: Verify = True,
        timeout_s: float = 30.0,
        connect_timeout_s: float = 10.0,
        max_retries: int = 4,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 30.0,
        max_retry_after_s: float = 120.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        headers: Optional[Mapping[str, str]] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: SleepFn = asyncio.sleep,
        rand: Callable[[], float] = random.random,
        policy: Optional[DestinationPolicy] = None,
        resolver: Optional[Resolver] = None,
    ):
        """``transport`` is a test hook; with a ``policy`` it is wrapped but not pinned."""
        if not base_url.lower().startswith(("https://", "http://")):
            raise SourceConfigError(f"{source_type} base URL must be http(s)")
        if policy is not None:
            policy.check_url(base_url)
            inner = transport or httpx.AsyncHTTPTransport(verify=verify)
            transport = GuardedTransport(inner, policy, resolver or system_resolve, pin=transport is None)
        self.source_type = source_type
        self.auth: AuthStrategy = auth or NoAuth()
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._backoff_base_s = backoff_base_s
        self._backoff_max_s = backoff_max_s
        self._max_retry_after_s = max_retry_after_s
        self._max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._rand = rand
        self._client = httpx.AsyncClient(
            base_url=base_url,
            verify=verify,
            timeout=httpx.Timeout(timeout_s, connect=min(connect_timeout_s, timeout_s)),
            headers={"User-Agent": USER_AGENT, **(headers or {})},
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _backoff(self, attempt: int) -> float:
        return exp_backoff(attempt, self._backoff_base_s, self._backoff_max_s, self._rand)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        data: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> HttpResponse:
        """Authenticated request; raises on any non-2xx/3xx outcome."""
        refreshed = False
        while True:
            auth_headers = await self.auth.headers(self)
            resp = await self.send(
                method, url, params=params, json_body=json_body, data=data, headers={**(headers or {}), **auth_headers}
            )
            if resp.status_code == 401 and self.auth.refreshable and not refreshed:
                refreshed = True
                self.auth.invalidate()
                record_http_retry(self.source_type, "auth_refresh")
                continue
            if resp.status_code in (401, 403):
                raise SourceAuthError(f"{self.source_type} rejected the credentials (HTTP {resp.status_code})")
            if resp.status_code >= 400:
                raise SourceRequestError(
                    f"{self.source_type} {method} {_path(url)} failed with HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            return resp

    async def send(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        data: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> HttpResponse:
        """One logical request with retries on network errors, 429 and 5xx; returns the final response."""
        attempt = 0
        while True:
            try:
                resp = await self._once(method, url, params=params, json_body=json_body, data=data, headers=headers)
            except (httpx.TransportError, TimeoutError) as exc:
                if attempt >= self._max_retries:
                    raise SourceUnavailable(
                        f"{self.source_type} {method} {_path(url)} failed after {attempt + 1} attempts "
                        f"({type(exc).__name__})"
                    ) from exc
                record_http_retry(self.source_type, "network")
                await self._sleep(self._backoff(attempt))
                attempt += 1
                continue
            status = resp.status_code
            if status != 429 and status < 500:
                return resp
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            if retry_after is not None and retry_after > self._max_retry_after_s:
                raise _retry_error(self.source_type, method, url, status, retry_after)
            if attempt >= self._max_retries:
                raise _retry_error(self.source_type, method, url, status, retry_after, attempts=attempt + 1)
            record_http_retry(self.source_type, "rate_limited" if status == 429 else "server_error")
            await self._sleep(retry_after if retry_after is not None else self._backoff(attempt))
            attempt += 1

    async def _once(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]],
        json_body: Any,
        data: Optional[Mapping[str, Any]],
        headers: Optional[Mapping[str, str]],
    ) -> HttpResponse:
        request = self._client.build_request(
            method, url, params=params, json=json_body, data=data, headers=dict(headers or {})
        )
        async with asyncio.timeout(self._timeout_s):
            response = await self._client.send(request, stream=True)
            try:
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        raise SourceResponseTooLarge(
                            f"{self.source_type} response exceeded {self._max_response_bytes} bytes"
                        )
                    chunks.append(chunk)
            finally:
                await response.aclose()
        return HttpResponse(response.status_code, response.headers, b"".join(chunks))


def _path(url: str) -> str:
    return url.split("?", 1)[0][:200]


def _retry_error(
    source_type: str, method: str, url: str, status: int, retry_after: Optional[float], *, attempts: Optional[int] = None
) -> Exception:
    tail = f" after {attempts} attempts" if attempts else f" (Retry-After {retry_after:.0f}s exceeds the limit)"
    if status == 429:
        return SourceRateLimited(f"{source_type} rate limited {method} {_path(url)}{tail}", retry_after_s=retry_after)
    return SourceUnavailable(f"{source_type} {method} {_path(url)} returned HTTP {status}{tail}")


def json_mapping(resp: HttpResponse, what: str) -> Dict[str, Any]:
    body = resp.json()
    if not isinstance(body, dict):
        raise SourceProtocolError(f"{what} response is not a JSON object")
    return body
