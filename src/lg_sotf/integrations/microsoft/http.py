"""HTTP to Microsoft Graph and the Defender for Endpoint API: fixed hosts, bounded, retried, never leaking credentials.

:class:`MicrosoftHttpFactory` (one per process) hands out a
:class:`MicrosoftApi` bound to one integration's credentials and one API.
The host comes from the credentials' :class:`~lg_sotf.integrations.microsoft.clouds.CloudProfile`,
never from configuration or from the caller.

Paths
    ``path`` starts with ``/v1.0/`` (Graph) or ``/api/`` (Defender), has no
    query or fragment, and is built only from
    :func:`~lg_sotf.integrations.microsoft.odata.segment` values (``.``/``..``
    segments, control characters and raw ``?``/``#`` are refused).

Query parameters
    Names are sent literally (``$filter``); values are percent-encoded once
    with ``quote(value, safe="")``: ``+`` -> ``%2B``, ``'`` -> ``%27``,
    ``#`` -> ``%23``, ``&`` -> ``%26``, ``%`` -> ``%25``. Pass raw OData text.

Transport
    Every request goes through
    :class:`~lg_sotf.net.egress.GuardedTransport` (``https``
    only, the resolved address checked and pinned, system CAs), follows no
    redirect, reads at most 1 MiB (4 MiB per page in :meth:`MicrosoftApi.pages`)
    and times out after ``min(response.microsoft_timeout_s, deadline - now)``.
    Each attempt sends a fresh ``client-request-id`` and the bearer token of
    :class:`~lg_sotf.integrations.microsoft.auth.TokenProvider`; a 401 drops
    the cached token and retries once.

Retries (at most ``response.microsoft_retries``, jittered exponential
backoff, ``Retry-After`` honoured)
    * always: 429 and 503;
    * only when ``idempotent`` (default: GET and DELETE yes, POST and PATCH
      no): network errors, 500 (Defender documents ``InternalServerError``
      as retryable), 502, 504 and Graph 409
      ``Directory_ConcurrencyViolation``.

    A ``Retry-After`` longer than the time left (``deadline - now - 1``)
    raises ``throttled`` with ``retry_after_s`` instead of sleeping past the
    deadline. A network error, 500, 502 or 504 on a non-idempotent request
    raises with ``ambiguous=True``: the write may or may not have happened,
    and the handler's re-run must reconcile (it reads before it writes).

Errors
    :class:`MicrosoftApiError` with a ``kind`` (see :data:`ERROR_KINDS`), the
    HTTP status, Microsoft's error ``code`` and the request id (``request-id``
    header, ``innerError.request-id`` or Defender's ``target``). Microsoft's
    free-text ``message`` is never kept. 403 -> ``forbidden``, 404 ->
    ``not_found`` (or a normal response with ``not_found_ok``), 409 ->
    ``conflict``, other 4xx -> ``bad_request``, 5xx -> ``server``.

Rate limit
    A client-side token bucket per (integration, API): Defender 60 requests
    per minute. Graph has no global bucket (mail concurrency is the mail
    capability's job).

Nothing here logs or stores the ``Authorization`` header, request bodies or
response bodies.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import ssl
import uuid
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Collection,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Tuple,
)
from urllib.parse import quote, urlencode

import httpx

from lg_sotf.errors import SourceConfigError
from lg_sotf.integrations.http import destination_policy
from lg_sotf.integrations.microsoft.clouds import Api
from lg_sotf.net.egress import DestinationPolicy, GuardedTransport, Resolver, system_resolve
from lg_sotf.net.retry import parse_retry_after
from lg_sotf.observability.logging import get_logger

if TYPE_CHECKING:
    from lg_sotf.integrations.microsoft.auth import AppCredentials, TokenProvider
    from lg_sotf.settings import Settings

log = get_logger(__name__)

ErrorKind = Literal[
    "throttled", "forbidden", "not_found", "bad_request", "conflict", "server", "network", "auth", "deadline", "size"
]
ERROR_KINDS: Tuple[str, ...] = (
    "throttled", "forbidden", "not_found", "bad_request", "conflict", "server", "network", "auth", "deadline", "size"
)
Method = Literal["GET", "POST", "PATCH", "DELETE"]
USER_AGENT = "lg-sotf-response/1.1 (microsoft)"
MAX_BODY_BYTES = 1024 * 1024
MAX_PAGE_BYTES = 4 * 1024 * 1024
MIN_ATTEMPT_S = 0.5
BACKOFF_BASE_S = 0.5
BACKOFF_MAX_S = 8.0
DEFENDER_REQUESTS_PER_MINUTE = 60
API_PREFIXES: Mapping[str, str] = {"graph": "/v1.0/", "defender": "/api/"}
RETRY_ALWAYS = frozenset({429, 503})
RETRY_IDEMPOTENT = frozenset({500, 502, 504})
CONCURRENCY_CODE = "directory_concurrencyviolation"
_PARAM_NAME = re.compile(r"^\$?[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_PATH_CHARS = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]+$")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SAFE_CODE = re.compile(r"[^A-Za-z0-9_.:-]")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_RESERVED_HEADERS = frozenset({"authorization", "host", "client-request-id", "content-length", "cookie"})

SleepFn = Callable[[float], Awaitable[None]]


class MicrosoftApiError(Exception):
    """A Microsoft call failed. The message is safe to store and show (no Microsoft free text, no URL, no token).

    ``kind``: one of :data:`ERROR_KINDS`. ``retryable``: worth running the
    action again later. ``ambiguous``: a non-idempotent write may or may not
    have reached Microsoft. ``retry_after_s``: Microsoft's (or the client
    rate limit's) hint for ``throttled``.
    """

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        status: int = 0,
        code: str = "",
        request_id: str = "",
        retry_after_s: Optional[float] = None,
        retryable: Optional[bool] = None,
        ambiguous: bool = False,
    ) -> None:
        super().__init__(message[:300])
        self.kind: ErrorKind = kind
        self.status = status
        self.code = _safe_code(code)
        self.request_id = _safe_code(request_id)
        self.retry_after_s = retry_after_s
        self.retryable = (
            retryable if retryable is not None else kind in ("throttled", "server", "network", "deadline")
        )
        self.ambiguous = ambiguous

    @property
    def ledger_error(self) -> str:
        """The ledger ``result.error`` code for this failure (``docs/microsoft.md``, error codes)."""
        return ledger_error(self)


def _safe_code(value: Any) -> str:
    return _SAFE_CODE.sub("", str(value or ""))[:100]


def ledger_error(exc: MicrosoftApiError) -> str:
    """Map an API error to the shared ledger error codes."""
    if exc.kind == "forbidden":
        code = exc.code.lower()
        if code in ("disabledfeature", "featurenotenabled"):
            return "feature_disabled"
        if "licens" in code:
            return "not_licensed"
        return "permission_denied"
    return {
        "throttled": "throttled",
        "not_found": "not_found",
        "bad_request": "bad_request",
        "conflict": "bad_request",
        "server": "ms_server_error",
        "network": "network_error",
        "auth": "credentials_invalid",
        "deadline": "deadline",
        "size": "ms_server_error",
    }.get(exc.kind, "bad_request")


@dataclass(frozen=True)
class MsResponse:
    """A successful (or ``not_found_ok``) response. ``body`` is the parsed JSON, or ``None``."""

    status: int
    body: Any
    headers: Mapping[str, str] = field(repr=False)
    request_id: str


class ReadOnlyViolation(RuntimeError):
    """A write was attempted through a read-only client (a handler bug; never sent)."""


class _TooLarge(Exception):
    pass


class _Bucket:
    """Token bucket with reservations (``tokens`` goes negative while callers wait their turn)."""

    def __init__(self, per_minute: int, now: float) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.updated = now

    def reserve(self, now: float) -> float:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        self.tokens -= 1.0
        return 0.0 if self.tokens >= 0 else -self.tokens / self.rate

    def refund(self) -> None:
        self.tokens = min(self.capacity, self.tokens + 1.0)


def _lookup(mapping: Any, *names: str) -> Any:
    """Case-insensitive key lookup in a JSON object."""
    if not isinstance(mapping, Mapping):
        return None
    wanted = {n.lower() for n in names}
    for key, value in mapping.items():
        if isinstance(key, str) and key.lower() in wanted:
            return value
    return None


def parse_error(body: Any, headers: Mapping[str, str]) -> Tuple[str, str]:
    """(code, request id) of a Microsoft error envelope ``{error: {code, message, innerError|innererror, target}}``.

    Keys are matched case-insensitively; ``message`` is ignored on purpose.
    """
    error = _lookup(body, "error")
    code = _lookup(error, "code") if isinstance(error, Mapping) else (error if isinstance(error, str) else None)
    inner = _lookup(error, "innerError", "innererror")
    request_id = (
        _lookup(inner, "request-id", "requestId")
        or headers.get("request-id")
        or _lookup(error, "target")
        or headers.get("x-ms-request-id")
        or ""
    )
    return _safe_code(code), _safe_code(request_id)


def _decode(content: bytes) -> Any:
    if not content:
        return None
    try:
        return json.loads(content)
    except ValueError:
        return None


class MicrosoftHttpFactory:
    """Builds :class:`MicrosoftApi` clients; one per process (``transport``/``resolver`` are test hooks).

    An injected ``transport`` is still wrapped by the destination policy but
    not pinned (it must see the original host), as in
    :class:`~lg_sotf.services.connectors.registry.ConnectorRegistry`.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        resolver: Optional[Resolver] = None,
        sleep: SleepFn = asyncio.sleep,
        rand: Callable[[], float] = random.random,
    ) -> None:
        self._settings = settings
        base = destination_policy(settings)
        # Microsoft endpoints are https, whatever the environment.
        self._policy = DestinationPolicy(require_https=True, allow_private=base.allow_private)
        self._transport = transport
        self._resolver = resolver or system_resolve
        self._sleep = sleep
        self._rand = rand
        self._ssl: Optional[ssl.SSLContext] = None
        self._buckets: Dict[Tuple[str, str], _Bucket] = {}

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def timeout_s(self) -> float:
        return float(self._settings.response.microsoft_timeout_s)

    @property
    def retries(self) -> int:
        return max(0, int(self._settings.response.microsoft_retries))

    def api(self, creds: AppCredentials, api: Api, tokens: TokenProvider, *, read_only: bool = False) -> MicrosoftApi:
        """A client for ``api`` with ``creds`` (the host is the credentials' cloud's fixed host).

        ``read_only`` clients refuse every method but GET (rehearsals,
        verification and connection-test probes get one).
        """
        return MicrosoftApi(self, creds, api, tokens, read_only=read_only)

    # -- plumbing shared with the token provider --------------------------------

    def backoff(self, attempt: int) -> float:
        return min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2**attempt)) * (0.5 + self._rand() / 2)

    async def sleep(self, seconds: float) -> None:
        await self._sleep(max(0.0, seconds))

    def _ssl_context(self) -> ssl.SSLContext:
        if self._ssl is None:
            self._ssl = httpx.create_ssl_context()
        return self._ssl

    def _client(self, timeout_s: float) -> httpx.AsyncClient:
        verify: Any = self._ssl_context() if self._transport is None else True
        inner = self._transport or httpx.AsyncHTTPTransport(verify=verify)
        guarded = GuardedTransport(inner, self._policy, self._resolver, pin=self._transport is None)
        return httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(timeout_s, connect=min(5.0, timeout_s)),
            transport=guarded,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    async def send_once(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        content: Optional[bytes],
        timeout_s: float,
        max_bytes: int,
    ) -> Tuple[int, bytes, httpx.Headers]:
        """One attempt on a fresh connection (a 503 is always retried on a new connection)."""
        async with self._client(timeout_s) as client:
            request = client.build_request(method, url, headers=dict(headers), content=content)
            async with asyncio.timeout(timeout_s + 0.5):
                response = await client.send(request, stream=True)
                try:
                    chunks: List[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise _TooLarge()
                        chunks.append(chunk)
                finally:
                    await response.aclose()
        return response.status_code, b"".join(chunks), response.headers

    async def post_form(
        self, url: str, form: Mapping[str, str], *, timeout_s: float
    ) -> Tuple[int, Any, httpx.Headers]:
        """A form-encoded POST (the token endpoint); returns (status, parsed JSON or None, headers)."""
        status, content, headers = await self.send_once(
            "POST",
            url,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
                     "client-request-id": str(uuid.uuid4())},
            content=urlencode(dict(form)).encode("ascii"),
            timeout_s=timeout_s,
            max_bytes=64 * 1024,
        )
        return status, _decode(content), headers

    def bucket(self, integration_id: str, api: Api) -> Optional[_Bucket]:
        if api != "defender":
            return None
        key = (integration_id, api)
        found = self._buckets.get(key)
        if found is None:
            if len(self._buckets) > 10_000:
                self._buckets.clear()
            found = _Bucket(DEFENDER_REQUESTS_PER_MINUTE, asyncio.get_running_loop().time())
            self._buckets[key] = found
        return found


class MicrosoftApi:
    """Requests to one Microsoft API with one integration's credentials. See the module docstring for the rules."""

    def __init__(
        self,
        factory: MicrosoftHttpFactory,
        creds: AppCredentials,
        api: Api,
        tokens: TokenProvider,
        *,
        read_only: bool = False,
    ) -> None:
        if api not in API_PREFIXES:
            raise ValueError(f"unknown Microsoft API {str(api)[:16]!r}")
        self.read_only = read_only
        self._factory = factory
        self._creds = creds
        self._tokens = tokens
        self.api: Api = api
        # Fixed per cloud; geo only for Defender (validated with the integration config).
        self.host: str = creds.cloud.host(api, creds.defender_geo)

    def _check_path(self, path: str) -> str:
        prefix = API_PREFIXES[self.api]
        if not isinstance(path, str) or not path.startswith(prefix) or len(path) > 4_096:
            raise ValueError(f"{self.api} paths must start with {prefix}")
        if not _PATH_CHARS.match(path) or _BAD_ESCAPE.search(path) or "//" in path:
            raise ValueError("path contains characters that must be encoded with odata.segment()")
        segments = path.split("/")
        if any(s in (".", "..") for s in segments):
            raise ValueError("path may not contain . or .. segments")
        return path

    def _url(self, path: str, params: Optional[Mapping[str, str]]) -> str:
        url = f"https://{self.host}{self._check_path(path)}"
        if not params:
            return url
        parts: List[str] = []
        for name, value in params.items():
            if not _PARAM_NAME.match(str(name)):
                raise ValueError(f"invalid query parameter name {str(name)[:64]!r}")
            if not isinstance(value, str):
                raise ValueError(f"query parameter {name} must be a string")
            parts.append(f"{name}={quote(value, safe='')}")
        return f"{url}?{'&'.join(parts)}"

    @staticmethod
    def _extra_headers(headers: Optional[Mapping[str, str]]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for name, value in (headers or {}).items():
            if not _HEADER_NAME.match(name) or name.lower() in _RESERVED_HEADERS:
                raise ValueError(f"header {str(name)[:64]!r} may not be set by a handler")
            if not isinstance(value, str) or any(ch in value for ch in "\r\n"):
                raise ValueError(f"header {name} has an invalid value")
            out[name] = value
        return out

    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        json: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        ok: Collection[int] = (200, 201, 202, 204),
        not_found_ok: bool = False,
        idempotent: Optional[bool] = None,
        deadline: float,
    ) -> MsResponse:
        """One logical request (with the retries of the module docstring), finished by ``deadline`` (``loop.time()``)."""
        if method not in ("GET", "POST", "PATCH", "DELETE"):
            raise ValueError(f"unsupported method {str(method)[:16]!r}")
        if self.read_only and method != "GET":
            raise ReadOnlyViolation(f"{method} is not allowed here: rehearsal, verification and probes only read")
        return await self._send(
            method,
            self._url(path, params),
            json_body=json,
            headers=self._extra_headers(headers),
            ok=ok,
            not_found_ok=not_found_ok,
            idempotent=idempotent,
            deadline=deadline,
            max_bytes=MAX_BODY_BYTES,
        )

    async def pages(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        max_items: int,
        deadline: float,
    ) -> List[Dict[str, Any]]:
        """GET a collection and follow ``@odata.nextLink`` (verbatim, same scheme and host only) up to ``max_items``.

        ``headers`` (e.g. ``ConsistencyLevel``) are sent on every page.
        """
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        extra = self._extra_headers(headers)
        url: Optional[str] = self._url(path, params)
        items: List[Dict[str, Any]] = []
        while url is not None and len(items) < max_items:
            response = await self._send(
                "GET", url, json_body=None, headers=extra, ok=(200,), not_found_ok=False, idempotent=True,
                deadline=deadline, max_bytes=MAX_PAGE_BYTES,
            )
            body = response.body if isinstance(response.body, Mapping) else {}
            values = body.get("value")
            if not isinstance(values, list):
                raise MicrosoftApiError(
                    "bad_request", f"{self.api} returned a page without a value list", status=response.status,
                    request_id=response.request_id, retryable=False,
                )
            items.extend(v for v in values if isinstance(v, dict))
            url = self._next_link(body.get("@odata.nextLink"))
        return items[:max_items]

    def _next_link(self, link: Any) -> Optional[str]:
        if link is None:
            return None
        try:
            parsed = httpx.URL(str(link))
        except (httpx.InvalidURL, TypeError, ValueError):
            parsed = None
        if (
            parsed is None
            or parsed.scheme != "https"
            or (parsed.host or "").lower() != self.host
            or parsed.port not in (None, 443)
            or parsed.userinfo
        ):
            raise MicrosoftApiError(
                "bad_request", f"{self.api} returned a next link to another origin (refused)", code="foreign_next_link",
                retryable=False,
            )
        return str(link)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        json_body: Any,
        headers: Mapping[str, str],
        ok: Collection[int],
        not_found_ok: bool,
        idempotent: Optional[bool],
        deadline: float,
        max_bytes: int,
    ) -> MsResponse:
        factory = self._factory
        loop = asyncio.get_running_loop()
        idem = idempotent if idempotent is not None else method in ("GET", "DELETE")
        content = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
        attempt = 0
        reauthenticated = False
        bucket = factory.bucket(str(self._creds.integration_id), self.api)
        while True:
            remaining = deadline - loop.time()
            if remaining < MIN_ATTEMPT_S:
                raise MicrosoftApiError(
                    "deadline", f"{self.api} request not started: the deadline was reached", retryable=True,
                    ambiguous=attempt > 0 and not idem,
                )
            if bucket is not None:
                wait = bucket.reserve(loop.time())
                if wait > 0:
                    if wait > deadline - loop.time() - 1.0:
                        bucket.refund()
                        raise MicrosoftApiError(
                            "throttled", f"client rate limit for {self.api} ({DEFENDER_REQUESTS_PER_MINUTE}/min)",
                            code="client_rate_limit", retry_after_s=wait,
                        )
                    await factory.sleep(wait)
            token = await self._tokens.token(self._creds, self.api, deadline=deadline)
            client_request_id = str(uuid.uuid4())
            send_headers = {
                **headers,
                "Authorization": f"Bearer {token}",
                "client-request-id": client_request_id,
                "Accept": "application/json",
            }
            if content is not None:
                send_headers["Content-Type"] = "application/json"
            timeout_s = max(0.1, min(factory.timeout_s, deadline - loop.time()))
            try:
                status, raw, response_headers = await factory.send_once(
                    method, url, headers=send_headers, content=content, timeout_s=timeout_s, max_bytes=max_bytes
                )
            except _TooLarge:
                raise MicrosoftApiError(
                    "size", f"{self.api} response exceeded {max_bytes} bytes", retryable=False,
                    ambiguous=not idem,
                ) from None
            except SourceConfigError:
                raise MicrosoftApiError(
                    "network", f"{self.api} host refused by the network policy", code="destination_refused",
                    retryable=False,
                ) from None
            except (httpx.TransportError, TimeoutError) as exc:
                late = loop.time() >= deadline - 0.05
                kind: ErrorKind = "deadline" if late else "network"
                log.warning(
                    "microsoft.request_error", api=self.api, method=method, error_type=type(exc).__name__,
                    attempt=attempt + 1, request_id=client_request_id,
                )
                if not idem:
                    raise MicrosoftApiError(
                        kind, f"{self.api} {method} failed on the network ({type(exc).__name__}); outcome unknown",
                        request_id=client_request_id, retryable=True, ambiguous=True,
                    ) from None
                if attempt < factory.retries and not late:
                    delay = factory.backoff(attempt)
                    if loop.time() + delay + MIN_ATTEMPT_S < deadline:
                        await factory.sleep(delay)
                        attempt += 1
                        continue
                raise MicrosoftApiError(
                    kind, f"{self.api} request failed on the network ({type(exc).__name__})",
                    request_id=client_request_id, retryable=True,
                ) from None
            lowered = {k.lower(): v for k, v in response_headers.items() if k.lower() in (
                "request-id", "client-request-id", "retry-after", "x-ms-request-id", "location", "content-type",
                "odata-version",
            )}
            body = _decode(raw)
            request_id = _safe_code(lowered.get("request-id") or lowered.get("x-ms-request-id") or client_request_id)
            if status == 401 and not reauthenticated:
                self._tokens.invalidate(self._creds, self.api)
                reauthenticated = True
                continue
            if status in ok or (status == 404 and not_found_ok):
                return MsResponse(status=status, body=body, headers=lowered, request_id=request_id)
            code, error_request_id = parse_error(body, lowered)
            request_id = error_request_id or request_id
            retry_after = parse_retry_after(lowered.get("retry-after"))
            concurrency = status == 409 and code.lower() == CONCURRENCY_CODE and self.api == "graph"
            retry = status in RETRY_ALWAYS or (idem and (status in RETRY_IDEMPOTENT or concurrency))
            log.warning(
                "microsoft.request_failed", api=self.api, method=method, http_status=status, ms_code=code,
                request_id=request_id, attempt=attempt + 1,
            )
            if retry:
                wait = retry_after if retry_after is not None else factory.backoff(attempt)
                left = deadline - loop.time() - 1.0
                if attempt < factory.retries and wait <= left:
                    await factory.sleep(wait)
                    attempt += 1
                    continue
                if status in RETRY_ALWAYS and (wait > left or status == 429):
                    raise MicrosoftApiError(
                        "throttled", f"{self.api} throttled the request (HTTP {status})", status=status, code=code,
                        request_id=request_id, retry_after_s=wait,
                    )
            raise self._error(status, code, request_id, method, idem, retry_after)

    def _error(
        self, status: int, code: str, request_id: str, method: str, idempotent: bool, retry_after: Optional[float]
    ) -> MicrosoftApiError:
        where = f"{self.api} {method}"
        if status == 401:
            return MicrosoftApiError(
                "auth", f"{where} rejected a freshly issued token (HTTP 401)", status=status, code=code,
                request_id=request_id, retryable=False,
            )
        if status == 403:
            return MicrosoftApiError("forbidden", f"{where} was refused (HTTP 403 {code or 'Forbidden'})",
                                     status=status, code=code, request_id=request_id, retryable=False)
        if status == 404:
            return MicrosoftApiError("not_found", f"{where}: not found (HTTP 404)", status=status, code=code,
                                     request_id=request_id, retryable=False)
        if 300 <= status < 400:
            return MicrosoftApiError("bad_request", f"{where}: unexpected redirect (HTTP {status}, not followed)",
                                     status=status, code=code or "unexpected_redirect", request_id=request_id,
                                     retryable=False)
        if status == 409:
            return MicrosoftApiError("conflict", f"{where}: conflict (HTTP 409 {code})", status=status, code=code,
                                     request_id=request_id, retryable=False)
        if 400 <= status < 500:
            return MicrosoftApiError("bad_request", f"{where}: rejected (HTTP {status} {code})", status=status,
                                     code=code, request_id=request_id, retryable=False)
        ambiguous = not idempotent and status in RETRY_IDEMPOTENT
        return MicrosoftApiError(
            "server", f"{where}: Microsoft server error (HTTP {status})", status=status, code=code,
            request_id=request_id, retry_after_s=retry_after, retryable=True, ambiguous=ambiguous,
        )


__all__ = [
    "API_PREFIXES",
    "ERROR_KINDS",
    "ErrorKind",
    "MAX_BODY_BYTES",
    "MAX_PAGE_BYTES",
    "MicrosoftApi",
    "MicrosoftApiError",
    "MicrosoftHttpFactory",
    "MsResponse",
    "ReadOnlyViolation",
    "ledger_error",
    "parse_error",
]
