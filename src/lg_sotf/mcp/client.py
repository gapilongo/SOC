"""Bounded HTTP client of the LG-SOTF REST API, used by the MCP tools.

The destination is the operator's own LG-SOTF API, configured in
``settings.mcp.api_url`` on the machine that runs ``lg-sotf mcp`` (usually
an analyst's workstation or a jump host). It is not tenant-controlled, so
the SSRF address policy that guards source connectors
(:mod:`lg_sotf.net.egress`, which refuses loopback and
private addresses) does not apply beyond its URL shape checks: ``http(s)``
only, no credentials in the URL, a host present. Plain ``http`` is accepted
only for a loopback host (``localhost``, ``127.0.0.0/8``, ``::1``), so the
API key never crosses a network unencrypted.

Every request:

* sends the API key in ``X-API-Key`` (never logged, never in error text);
* has a total timeout (``settings.mcp.timeout_s``);
* never follows redirects, so the key cannot be forwarded to another host;
* reads at most ``settings.mcp.max_response_bytes`` of the body;
* ignores proxy and ``.netrc`` environment settings (``trust_env=False``).

Reads (``GET``) are retried a bounded number of times on 429, 502, 503, 504
and transport errors, honouring ``Retry-After`` (seconds, fractional or not,
or an HTTP date) up to :data:`MAX_RETRY_AFTER_S`. Writes are never retried (a
note must not be added twice).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import uuid
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple, Union

import httpx

from lg_sotf import __version__
from lg_sotf.errors import SourceConfigError
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.net.retry import parse_retry_after
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

RETRY_STATUSES = frozenset({429, 502, 503, 504})
MAX_RETRY_AFTER_S = 10.0
BACKOFF_BASE_S = 0.5
MAX_ERROR_MESSAGE_CHARS = 300
API_KEY_SOURCES = "the API key (LG_SOTF_MCP__API_KEY or LG_SOTF_MCP__API_KEY_FILE)"
"""How messages name the key: it comes from the variable or from the file the other variable names."""

QueryValue = Union[str, int, float, bool, Sequence[str], None]
Sleep = Callable[[float], Awaitable[None]]


class ApiConfigError(ValueError):
    """The configured API URL or key is not usable."""


class ApiCallError(Exception):
    """An API call failed. ``str()`` is safe to show to the MCP client (no credentials)."""

    def __init__(self, message: str, *, status: Optional[int] = None, code: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _is_loopback(host: str) -> bool:
    if host.lower() in ("localhost", "localhost."):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_api_url(url: str) -> str:
    """The base URL without a trailing ``/``; raises :class:`ApiConfigError` when it is not allowed."""
    try:
        parsed = httpx.URL(url.strip())
    except (httpx.InvalidURL, TypeError) as exc:
        raise ApiConfigError("LG_SOTF_MCP__API_URL is not a valid URL") from exc
    if parsed.query or parsed.fragment:
        raise ApiConfigError("LG_SOTF_MCP__API_URL must not contain a query or fragment")
    loopback_http = parsed.scheme.lower() == "http" and _is_loopback(parsed.host)
    try:
        DestinationPolicy(require_https=not loopback_http).check_url(parsed)
    except SourceConfigError as exc:
        message = str(exc).replace("source URLs must use https in staging and production", "must use https")
        raise ApiConfigError(
            f"LG_SOTF_MCP__API_URL is not allowed: {message.replace('source URL', 'URL')} "
            "(plain http is accepted for loopback hosts only)"
        ) from exc
    return str(parsed).rstrip("/")


def _safe_text(value: Any, limit: int = MAX_ERROR_MESSAGE_CHARS) -> str:
    text = value if isinstance(value, str) else str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _error_from(response_status: int, body: bytes) -> ApiCallError:
    code: Optional[str] = None
    message = f"the LG-SOTF API answered HTTP {response_status}"
    request_id: Optional[str] = None
    try:
        parsed = json.loads(body.decode("utf-8")) if body else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    envelope = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(envelope, dict):
        if isinstance(envelope.get("code"), str):
            code = _safe_text(envelope["code"], 64)
        if isinstance(envelope.get("message"), str) and envelope["message"]:
            message = f"{message}: {_safe_text(envelope['message'])}"
        if isinstance(envelope.get("request_id"), str):
            request_id = _safe_text(envelope["request_id"], 128)
    if code:
        message = f"{message} ({code})"
    if request_id:
        message = f"{message} [request id {request_id}]"
    if response_status in (401, 403):
        message += f". Check that {API_KEY_SOURCES} is valid and has the scope this tool needs."
    return ApiCallError(message, status=response_status, code=code)


class LgSotfApiClient:
    """Async client of ``{api_url}/api/v1``. Create one per server; close with :meth:`aclose`."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout_s: float = 30.0,
        max_retries: int = 2,
        max_response_bytes: int = 4_194_304,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ApiConfigError(f"{API_KEY_SOURCES} is not set")
        if not all(c.isascii() and c.isprintable() and not c.isspace() for c in api_key.strip()):
            raise ApiConfigError(f"{API_KEY_SOURCES} contains invalid characters")
        self._base = validate_api_url(api_url)
        self._key = api_key.strip()
        self._max_retries = max(0, max_retries)
        self._max_bytes = max_response_bytes
        self._sleep = sleep
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"Accept": "application/json", "User-Agent": f"lg-sotf-mcp/{__version__}"},
        )

    def __repr__(self) -> str:
        return f"LgSotfApiClient(base={self._base!r})"

    @property
    def base_url(self) -> str:
        return self._base

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, path: str, params: Optional[Mapping[str, QueryValue]] = None) -> Any:
        return await self._call("GET", path, params=params)

    async def post(self, path: str, body: Mapping[str, Any]) -> Any:
        return await self._call("POST", path, body=body)

    async def _call(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, QueryValue]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        if not path.startswith("/api/v1/"):
            raise ValueError("path must start with /api/v1/")
        attempts = 1 + (self._max_retries if method == "GET" else 0)
        query = _query(params)
        for attempt in range(attempts):
            last = attempt == attempts - 1
            try:
                status, headers, content = await self._send(method, path, query, body)
            except httpx.TransportError as exc:
                log.warning("mcp.api_transport_error", method=method, error_type=type(exc).__name__, attempt=attempt)
                if last:
                    raise ApiCallError(
                        f"the LG-SOTF API could not be reached ({type(exc).__name__}); check LG_SOTF_MCP__API_URL"
                    ) from exc
                await self._sleep(BACKOFF_BASE_S * (2**attempt))
                continue
            if status in RETRY_STATUSES and not last:
                log.warning("mcp.api_retry", method=method, status=status, attempt=attempt)
                await self._sleep(_retry_delay(headers.get("retry-after"), attempt))
                continue
            if 300 <= status < 400:
                raise ApiCallError(
                    f"the LG-SOTF API answered with a redirect (HTTP {status}); redirects are not followed. "
                    "Set LG_SOTF_MCP__API_URL to the API's final address.",
                    status=status,
                )
            if status >= 400:
                raise _error_from(status, content)
            if not content:
                return None
            try:
                return json.loads(content.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ApiCallError("the LG-SOTF API returned a response that is not JSON", status=status) from exc
        raise ApiCallError("the LG-SOTF API did not answer")  # pragma: no cover - loop always returns or raises

    async def _send(
        self, method: str, path: str, query: Sequence[Tuple[str, str]], body: Optional[Mapping[str, Any]]
    ) -> Tuple[int, httpx.Headers, bytes]:
        headers = {"X-API-Key": self._key, "X-Request-ID": f"mcp-{uuid.uuid4().hex}"}
        request = self._client.build_request(
            method,
            self._base + path,
            params=list(query),
            json=dict(body) if body is not None else None,
            headers=headers,
        )
        response = await self._client.send(request, stream=True)
        try:
            declared = response.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > self._max_bytes:
                raise ApiCallError(f"the API response is larger than the {self._max_bytes}-byte limit")
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > self._max_bytes:
                    raise ApiCallError(f"the API response is larger than the {self._max_bytes}-byte limit")
                chunks.append(chunk)
            return response.status_code, response.headers, b"".join(chunks)
        finally:
            await response.aclose()


def _query(params: Optional[Mapping[str, QueryValue]]) -> Sequence[Tuple[str, str]]:
    out = []
    for key, value in (params or {}).items():
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            out.append((key, "true" if value else "false"))
        elif isinstance(value, (list, tuple)):
            out.extend((key, str(v)) for v in value)
        else:
            out.append((key, str(value)))
    return out


def _retry_delay(retry_after: Optional[str], attempt: int) -> float:
    hint = parse_retry_after(retry_after, cap=MAX_RETRY_AFTER_S)
    if hint is not None:
        return hint
    backoff: float = BACKOFF_BASE_S * (2**attempt)
    return min(backoff, MAX_RETRY_AFTER_S)


def json_params(values: Dict[str, Any]) -> Dict[str, QueryValue]:
    """Drop ``None`` values (helper for tool handlers)."""
    return {k: v for k, v in values.items() if v is not None}


__all__ = ["ApiCallError", "ApiConfigError", "LgSotfApiClient", "json_params", "validate_api_url"]
