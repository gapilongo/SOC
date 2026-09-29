"""ASGI middleware in isolation: body limits while streaming, security headers, request ids, error envelope."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from lg_sotf.api.errors import ApiError, install_error_handlers
from lg_sotf.api.middleware import (
    BodyLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    incoming_request_id,
)
from lg_sotf.db.errors import AlreadyInState, Conflict, InvalidCursor, InvalidTransition, InvalidValue, NotFound


async def _drive(
    app: Any, chunks: List[bytes], headers: Optional[List[Tuple[bytes, bytes]]] = None
) -> Tuple[int, Dict[str, str], bytes]:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": headers or [],
        "scheme": "https",
        "query_string": b"",
    }
    messages = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    sent: List[dict] = []

    async def receive() -> dict:
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}, body


async def _echo(scope: dict, receive: Any, send: Any) -> None:
    total = 0
    while True:
        message = await receive()
        total += len(message.get("body", b""))
        if not message.get("more_body"):
            break
    body = json.dumps({"received": total}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


async def test_body_limit_cuts_off_a_streamed_body() -> None:
    app = BodyLimitMiddleware(_echo, limit_for=lambda path: 100)
    status, _, body = await _drive(app, [b"a" * 60, b"b" * 60, b"c" * 60])
    assert status == 413
    assert json.loads(body)["error"]["code"] == "payload_too_large"
    ok_status, _, ok_body = await _drive(app, [b"a" * 50, b"b" * 50])
    assert ok_status == 200 and json.loads(ok_body) == {"received": 100}


async def test_body_limit_refuses_large_content_length_without_reading() -> None:
    reads = []

    async def app(scope: dict, receive: Any, send: Any) -> None:
        reads.append(1)
        await _echo(scope, receive, send)

    status, headers, _ = await _drive(
        BodyLimitMiddleware(app, limit_for=lambda p: 10), [b"x"], [(b"content-length", b"11")]
    )
    assert status == 413 and reads == []
    assert headers["connection"] == "close"


async def test_security_headers_are_added() -> None:
    status, headers, _ = await _drive(SecurityHeadersMiddleware(_echo), [b""])
    assert status == 200
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["strict-transport-security"].startswith("max-age=")
    assert headers["referrer-policy"] == "no-referrer"


def test_request_id_validation() -> None:
    assert incoming_request_id([(b"x-request-id", b"abc-12345678")]) == "abc-12345678"
    for bad in (b"short", b"has space in it", b"x" * 200, b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8"):
        generated = incoming_request_id([(b"x-request-id", bad)])
        assert generated != bad.decode("latin-1") and len(generated) == 32


async def test_unhandled_errors_become_a_bare_500_envelope() -> None:
    async def boom(scope: dict, receive: Any, send: Any) -> None:
        raise RuntimeError("database password is hunter2")

    status, headers, body = await _drive(RequestContextMiddleware(boom), [b""], [(b"x-request-id", b"req-abcdefgh")])
    assert status == 500
    assert headers["x-request-id"] == "req-abcdefgh"
    assert json.loads(body) == {
        "error": {"code": "internal_error", "message": "internal server error", "request_id": "req-abcdefgh"}
    }


@pytest.mark.parametrize(
    ("exc", "status", "code"),
    [
        (NotFound("alert", "a1"), 404, "not_found"),
        (InvalidValue("bad"), 400, "invalid_value"),
        (InvalidCursor("bad cursor"), 400, "invalid_cursor"),
        (Conflict("dup"), 409, "conflict"),
        (InvalidTransition("alert", "a1", "closed", "processing"), 409, "invalid_transition"),
        (AlreadyInState("action", "x", "approved"), 409, "already_in_state"),
        (ValueError("internal detail"), 400, "invalid_request"),
        (ApiError(418, "teapot", "short and stout"), 418, "teapot"),
    ],
)
def test_error_mapping(exc: Exception, status: int, code: str) -> None:
    app = FastAPI()
    install_error_handlers(app)
    app.add_middleware(RequestContextMiddleware)

    @app.get("/raise")
    async def raise_it(request: Request) -> None:
        raise exc

    with TestClient(app) as client:
        response = client.get("/raise")
    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == code
    assert error["request_id"] == response.headers["x-request-id"]
    if isinstance(exc, ValueError) and not isinstance(exc, InvalidValue | InvalidCursor):
        assert "internal detail" not in response.text


def test_validation_errors_never_echo_input() -> None:
    from pydantic import BaseModel

    class Body(BaseModel):
        password: int

    app = FastAPI()
    install_error_handlers(app)

    @app.post("/v")
    async def v(body: Body) -> None:
        return None

    with TestClient(app) as client:
        response = client.post("/v", json={"password": "my-secret-value"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "my-secret-value" not in response.text
