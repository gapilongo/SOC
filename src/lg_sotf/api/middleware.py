"""Pure ASGI middleware: request context and access log, security headers, body size limits.

Order (outermost first, see :func:`lg_sotf.api.app.create_app`):
``RequestContextMiddleware`` -> ``SecurityHeadersMiddleware`` -> CORS ->
``BodyLimitMiddleware`` -> routes.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, List, MutableMapping, Optional, Sequence, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from lg_sotf.api.errors import BodyTooLarge, error_body
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.observability.metrics import observe_http_request

log = get_logger("lg_sotf.api.access")

REQUEST_ID_HEADER = "x-request-id"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
UNMATCHED_ROUTE = "unmatched"

# The API serves JSON only; the interactive docs pages load their assets from a CDN.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
DOCS_PATHS = ("/docs", "/redoc")
HSTS_VALUE = "max-age=63072000; includeSubDomains"


def incoming_request_id(headers: Sequence[Tuple[bytes, bytes]]) -> str:
    """The caller's ``X-Request-ID`` when it is well formed, otherwise a fresh id."""
    for name, value in headers:
        if name == REQUEST_ID_HEADER.encode():
            try:
                text = value.decode("ascii")
            except UnicodeDecodeError:
                break
            if _REQUEST_ID_RE.fullmatch(text):
                return text
            break
    return uuid.uuid4().hex


def _set_header(headers: List[Tuple[bytes, bytes]], name: str, value: str) -> None:
    key = name.lower().encode("latin-1")
    headers[:] = [(k, v) for k, v in headers if k.lower() != key]
    headers.append((key, value.encode("latin-1")))


def _has_header(headers: List[Tuple[bytes, bytes]], name: str) -> bool:
    key = name.lower().encode("latin-1")
    return any(k.lower() == key for k, _ in headers)


async def send_error(
    send: Send, status: int, code: str, message: str, extra_headers: Optional[Dict[str, str]] = None
) -> None:
    body = json.dumps(error_body(code, message), separators=(",", ":")).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    for name, value in (extra_headers or {}).items():
        headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def route_template(scope: Scope) -> str:
    """The matched route's full path template (low-cardinality metric label), or ``unmatched``.

    FastAPI keeps included routers' original route objects (whose ``path``
    lacks the include prefix) and records the effective, prefixed route in
    its own scope entry, so that is preferred when present.
    """
    effective = (scope.get("fastapi") or {}).get("effective_route_context")
    path = getattr(effective, "path", None) or getattr(scope.get("route"), "path", None)
    return path if isinstance(path, str) and path else UNMATCHED_ROUTE


class RequestContextMiddleware:
    """Request id, structured access log, HTTP metrics and the last-resort 500 envelope.

    The access log records method, route template, status, duration and
    client address; never the query string (WebSocket tokens travel there),
    headers or bodies.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        rid = incoming_request_id(scope.get("headers") or [])
        scope.setdefault("state", {})["request_id"] = rid
        started = time.perf_counter()
        status_holder = {"status": 0, "started": False}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                status_holder["started"] = True
                headers = list(message.get("headers") or [])
                _set_header(headers, "X-Request-ID", rid)
                message = {**message, "headers": headers}
            await send(message)

        with bound_context(request_id=rid):
            try:
                await self.app(scope, receive, send_wrapper)
            except Exception as exc:  # noqa: BLE001 - last resort: log with stack, answer with a bare envelope
                log.error("api.unhandled_error", error_type=type(exc).__name__, exc_info=exc)
                if scope["type"] == "http" and not status_holder["started"]:
                    await send_error(send_wrapper, 500, "internal_error", "internal server error")
                elif scope["type"] == "http":
                    status_holder["status"] = 500
            finally:
                self._log(scope, status_holder["status"], time.perf_counter() - started)

    @staticmethod
    def _log(scope: Scope, status: int, seconds: float) -> None:
        template = route_template(scope)
        method = scope.get("method", "WS") if scope["type"] == "http" else "WS"
        client = scope.get("client")
        state = scope.get("state") or {}
        if scope["type"] == "http":
            observe_http_request(template, method, status or 500, seconds)
        log.info(
            "http.request",
            method=method,
            route=template,
            status=status,
            duration_ms=round(seconds * 1000, 2),
            client_ip=client[0] if client else None,
            tenant_id=state.get("tenant_id"),
            principal=state.get("principal_id"),
        )


class SecurityHeadersMiddleware:
    """Hardening headers on every HTTP response (HSTS only when the request came over HTTPS)."""

    def __init__(self, app: ASGIApp, *, force_hsts: bool = False) -> None:
        self.app = app
        self.force_hsts = force_hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        https = scope.get("scheme") == "https" or self.force_hsts
        path = scope.get("path", "")
        docs = path in DOCS_PATHS or path.startswith("/docs/")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                _set_header(headers, "X-Content-Type-Options", "nosniff")
                _set_header(headers, "X-Frame-Options", "DENY")
                _set_header(headers, "Referrer-Policy", "no-referrer")
                _set_header(headers, "Cross-Origin-Opener-Policy", "same-origin")
                _set_header(headers, "Cross-Origin-Resource-Policy", "same-origin")
                _set_header(headers, "Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                # A response that sets its own, stricter-than-docs policy keeps it (the monthly HTML
                # report allows only its inline stylesheet, by hash); everything else gets the default.
                if not _has_header(headers, "Content-Security-Policy"):
                    _set_header(headers, "Content-Security-Policy", DOCS_CSP if docs else API_CSP)
                if not _has_header(headers, "Cache-Control"):
                    _set_header(headers, "Cache-Control", "no-store")
                if https:
                    _set_header(headers, "Strict-Transport-Security", HSTS_VALUE)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


LimitFor = Callable[[str], int]


class BodyLimitMiddleware:
    """Refuses request bodies over the route's limit, counted while the body streams in.

    ``Content-Length`` over the limit is refused before the body is read; a
    chunked (or lying) body is cut off as soon as the running total exceeds
    the limit, so a client cannot make the server buffer more than the
    limit. The endpoint sees :class:`BodyTooLarge`, which renders as 413.
    """

    def __init__(self, app: ASGIApp, *, limit_for: LimitFor) -> None:
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope.get("path", ""))
        declared = self._content_length(scope)
        if declared is not None and declared > limit:
            await send_error(
                send, 413, "payload_too_large", f"request body exceeds {limit} bytes", {"connection": "close"}
            )
            return
        received = 0
        started = {"value": False}

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge(limit)
            return message

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                started["value"] = True
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except BodyTooLarge as exc:
            if started["value"]:
                raise
            await send_error(send, 413, "payload_too_large", str(exc.detail), {"connection": "close"})

    @staticmethod
    def _content_length(scope: Scope) -> Optional[int]:
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    return int(value)
                except ValueError:
                    return None
        return None


def mark_principal(scope: MutableMapping[str, Any], tenant_id: str, principal_id: str) -> None:
    """Record who made the request for the access log (called by the auth dependency)."""
    state = scope.setdefault("state", {})
    state["tenant_id"] = tenant_id
    state["principal_id"] = principal_id


AsyncCall = Callable[..., Awaitable[Any]]
