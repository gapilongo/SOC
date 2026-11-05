"""Outbound HTTP for integrations, always through the destination policy.

Integration URLs (webhook receivers, Jira and ServiceNow instances) are
tenant-controlled, so every request goes through
:class:`~lg_sotf.ingestion.sources.netpolicy.GuardedTransport`: ``https``
only in staging and production, loopback / link-local / metadata addresses
always refused, private ranges only when the install sets
``ingestion.allow_private_destinations``, and the connection pinned to the
address that was checked. Redirects are never followed, every request has a
timeout, and response bodies are read up to a cap.

Errors are raised as :class:`DeliveryError` with a message that is safe to
store and show to a tenant admin: it never contains the request URL (Slack
and Teams webhook URLs are credentials) nor request headers, and a
receiver's error body is redacted and truncated.
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Optional

import httpx

from lg_sotf.ingestion.errors import SourceConfigError
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.ingestion.sources.http import Verify, build_verify, parse_retry_after
from lg_sotf.ingestion.sources.netpolicy import DestinationPolicy, GuardedTransport, Resolver, system_resolve
from lg_sotf.security.redaction import redact_text
from lg_sotf.settings import Settings

USER_AGENT = "lg-sotf-integrations/1"
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
MAX_ERROR_BODY_CHARS = 300
MAX_RETRY_AFTER_S = 3_600.0
RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
# Failures before the request reached the server: safe to retry even for a non-idempotent write.
_NOT_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)

SleepFn = Callable[[float], Awaitable[None]]


class DeliveryError(Exception):
    """A request failed. ``retryable``: worth trying again later; ``retry_after``: the receiver's hint (s)."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status: Optional[int] = None,
        retry_after: Optional[float] = None,
        code: str = "error",
    ) -> None:
        super().__init__(message[:500])
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after
        self.code = code


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: httpx.Headers
    body: bytes = field(repr=False)

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None


class _TooLarge(Exception):
    pass


def error_snippet(body: bytes) -> str:
    """A receiver's error body, redacted and truncated, for ``last_error``."""
    text = body[:4_096].decode("utf-8", "replace")
    text, _ = redact_text(" ".join(text.split()))
    return text[:MAX_ERROR_BODY_CHARS]


def destination_policy(settings: Settings) -> DestinationPolicy:
    try:
        allow_private = IngestionOptions.from_settings(settings).allow_private_destinations
    except SourceConfigError:
        allow_private = False
    return DestinationPolicy(require_https=settings.is_production, allow_private=allow_private)


def tls_verify(config: Mapping[str, Any]) -> Verify:
    """System CAs, plus the integration's own ``ca_cert_pem`` (private CA of an on-prem Jira/ServiceNow)."""
    pem = config.get("ca_cert_pem")
    try:
        return build_verify({"ca_cert_pem": pem} if pem else {}, production=True)
    except SourceConfigError as exc:
        raise DeliveryError(str(exc), retryable=False, code="invalid_ca") from exc


class IntegrationHttp:
    """Makes guarded requests; ``transport``/``resolver`` are test hooks (a transport is wrapped, not pinned)."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        timeout_s: Optional[float] = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        sleep: SleepFn = asyncio.sleep,
        rand: Callable[[], float] = random.random,
    ) -> None:
        self._policy = destination_policy(settings)
        self._transport = transport
        self._resolver = resolver or system_resolve
        self._timeout_s = float(timeout_s if timeout_s is not None else settings.integrations.http_timeout_s)
        self._max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._rand = rand

    @property
    def policy(self) -> DestinationPolicy:
        return self._policy

    def check_url(self, url: str) -> None:
        """Shape and scheme check (the address check happens when the request is sent)."""
        try:
            self._policy.check_url(url)
        except SourceConfigError as exc:
            raise DeliveryError(f"destination rejected: {exc}", retryable=False, code="destination_refused") from exc

    def _client(self, verify: Verify) -> httpx.AsyncClient:
        inner = self._transport or httpx.AsyncHTTPTransport(verify=verify)
        guarded = GuardedTransport(inner, self._policy, self._resolver, pin=self._transport is None)
        return httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(self._timeout_s, connect=min(5.0, self._timeout_s)),
            transport=guarded,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        content: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        auth: Optional[httpx.Auth] = None,
        params: Optional[Mapping[str, str]] = None,
        verify: Verify = True,
        retries: int = 0,
        expect_ok: bool = True,
        idempotent: bool = True,
    ) -> HttpResult:
        """One request, with up to ``retries`` retries of transient failures (backoff with jitter).

        With ``expect_ok`` a non-2xx answer raises :class:`DeliveryError`
        (retryable for 408/425/429/5xx, with ``Retry-After`` when given).

        A write that must not happen twice (creating a ticket, posting a
        comment) passes ``idempotent=False``: it is then retried here only
        when the server cannot have acted on it (no connection was made, or
        429). After a read timeout or a 5xx the write may have happened, so the
        error is raised for the caller, which can look before it writes again.
        """
        self.check_url(url)
        attempt = 0
        async with self._client(verify) as client:
            while True:
                try:
                    result = await self._send(client, method, url, json_body, content, headers, auth, params)
                except SourceConfigError as exc:
                    raise DeliveryError("destination refused by the network policy", retryable=False,
                                        code="destination_refused") from exc
                except _TooLarge:
                    raise DeliveryError("response too large", retryable=False, code="response_too_large") from None
                except (httpx.TransportError, TimeoutError) as exc:
                    if attempt < retries and (idempotent or isinstance(exc, _NOT_SENT)):
                        await self._sleep(self._backoff(attempt))
                        attempt += 1
                        continue
                    raise DeliveryError(
                        f"network error ({type(exc).__name__})", retryable=True, code="network_error"
                    ) from exc
                if result.status in RETRYABLE_STATUSES and attempt < retries and (idempotent or result.status == 429):
                    hint = parse_retry_after(result.headers.get("Retry-After"))
                    if hint is None or hint <= 15.0:
                        await self._sleep(hint if hint is not None else self._backoff(attempt))
                        attempt += 1
                        continue
                if expect_ok:
                    raise_for_status(result)
                return result

    def _backoff(self, attempt: int) -> float:
        return min(8.0, 0.5 * (2**attempt)) * (0.5 + self._rand() / 2)

    async def _send(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        json_body: Any,
        content: Optional[bytes],
        headers: Optional[Mapping[str, str]],
        auth: Optional[httpx.Auth],
        params: Optional[Mapping[str, str]],
    ) -> HttpResult:
        request = client.build_request(
            method, url, json=json_body, content=content, headers=dict(headers or {}), params=params
        )
        async with asyncio.timeout(self._timeout_s + 1.0):
            response = await client.send(request, auth=auth, stream=True)
            try:
                chunks = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        raise _TooLarge()
                    chunks.append(chunk)
            finally:
                await response.aclose()
        return HttpResult(response.status_code, response.headers, b"".join(chunks))


def raise_for_status(result: HttpResult) -> None:
    status = result.status
    if 200 <= status < 300:
        return
    if 300 <= status < 400:
        raise DeliveryError(f"unexpected redirect (HTTP {status})", retryable=False, status=status,
                            code="unexpected_redirect")
    snippet = error_snippet(result.body)
    message = f"HTTP {status}" + (f": {snippet}" if snippet else "")
    if status in RETRYABLE_STATUSES:
        retry_after = parse_retry_after(result.headers.get("Retry-After"))
        raise DeliveryError(
            message,
            retryable=True,
            status=status,
            retry_after=min(retry_after, MAX_RETRY_AFTER_S) if retry_after is not None else None,
            code="http_status",
        )
    raise DeliveryError(message, retryable=False, status=status, code="http_status")
