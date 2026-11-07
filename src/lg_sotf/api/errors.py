"""Error envelope and exception mapping.

Every error response has the shape ``{"error": {"code", "message",
"request_id"}}`` (plus ``details`` for validation failures). Messages come
from exceptions whose text is safe for clients; anything unexpected becomes a
generic 500 and its stack trace goes to the log only.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple, Type

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from lg_sotf.db.errors import (
    AlreadyInState,
    Conflict,
    DatabaseUnavailable,
    InvalidCursor,
    InvalidTenantId,
    InvalidTransition,
    InvalidValue,
    NotFound,
)
from lg_sotf.domain.suppression import InvalidRule
from lg_sotf.ingestion.errors import SourceConfigError, SourceDisabled, SourceNotPushable
from lg_sotf.observability.logging import current_context, get_logger, log_failure
from lg_sotf.services.response import ResponsePolicyError
from lg_sotf.services.review import ReviewDenied, ReviewError

log = get_logger(__name__)

MAX_MESSAGE_CHARS = 300
MAX_DETAILS = 20

_STATUS_CODES: Mapping[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


# Exceptions answered with a fixed status and code and their own (client-safe) message.
SIMPLE_ERRORS: Tuple[Tuple[Type[Exception], int, str], ...] = (
    (NotFound, 404, "not_found"),
    (InvalidCursor, 400, "invalid_cursor"),
    (InvalidValue, 400, "invalid_value"),
    (InvalidTenantId, 400, "invalid_tenant"),
    (Conflict, 409, "conflict"),
    (InvalidTransition, 409, "invalid_transition"),
    (AlreadyInState, 409, "already_in_state"),
    (ReviewError, 400, "invalid_request"),
    (ReviewDenied, 403, "forbidden"),
    (InvalidRule, 422, "invalid_rule"),
    (SourceNotPushable, 404, "source_not_found"),
    (SourceDisabled, 409, "source_disabled"),
    (SourceConfigError, 422, "invalid_source"),
)


class ApiError(StarletteHTTPException):
    """An error with an explicit machine-readable ``code`` (message is shown to the client)."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        details: Optional[List[Any]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code = code
        self.details = details


class BodyTooLarge(ApiError):
    """Raised while the request body streams in, once it exceeds the route's limit.

    It is an ``HTTPException`` so FastAPI's body parsing re-raises it
    instead of turning it into a generic 400.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(413, "payload_too_large", f"request body exceeds {limit} bytes")
        self.limit = limit


def request_id() -> Optional[str]:
    value = current_context().get("request_id")
    return value if isinstance(value, str) else None


def _clip(message: str) -> str:
    message = " ".join(str(message).split())
    return message if len(message) <= MAX_MESSAGE_CHARS else message[: MAX_MESSAGE_CHARS - 3] + "..."


def error_body(code: str, message: str, *, details: Optional[List[Any]] = None) -> Dict[str, Any]:
    error: Dict[str, Any] = {"code": code, "message": _clip(message), "request_id": request_id()}
    if details:
        error["details"] = details[:MAX_DETAILS]
    return {"error": error}


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
    details: Optional[List[Any]] = None,
) -> JSONResponse:
    return JSONResponse(
        error_body(code, message, details=details), status_code=status_code, headers=dict(headers or {})
    )


async def _http_exception(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = getattr(exc, "code", None) or _STATUS_CODES.get(exc.status_code, "error")
    message = exc.detail if isinstance(exc.detail, str) and exc.detail else code.replace("_", " ")
    return error_response(exc.status_code, code, message, headers=exc.headers, details=getattr(exc, "details", None))


async def _validation(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    details = []
    for err in exc.errors()[:MAX_DETAILS]:
        loc = [str(p) for p in err.get("loc", ()) if p != "body"]
        # Never echo the offending input back (it may be a password or a secret).
        details.append({"loc": ".".join(loc), "message": _clip(str(err.get("msg", "invalid value")))})
    summary = "; ".join(f"{d['loc']}: {d['message']}" if d["loc"] else d["message"] for d in details[:3])
    return error_response(422, "validation_error", summary or "request validation failed", details=details)


def _simple(
    status_code: int, code: str, *, use_message: bool = True
) -> Callable[[Request, Exception], Awaitable[JSONResponse]]:
    async def handler(_: Request, exc: Exception) -> JSONResponse:
        message = str(exc) if use_message and str(exc) else code.replace("_", " ")
        return error_response(status_code, code, message)

    return handler


def describe_error(exc: BaseException) -> Optional[Tuple[int, str, str]]:
    """``(status, code, message)`` a request failing with ``exc`` answers, when :data:`SIMPLE_ERRORS` maps it.

    Resolved like Starlette resolves handlers (the closest class in the MRO), so a bulk endpoint reports
    an item's error exactly as the single-item endpoint would answer it.
    """
    table = {cls: (status, code) for cls, status, code in SIMPLE_ERRORS}
    for cls in type(exc).__mro__:
        if cls in table:
            status, code = table[cls]
            return status, code, _clip(str(exc) or code.replace("_", " "))
    return None


async def _policy(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ResponsePolicyError)
    problems = [_clip(p) for p in exc.problems]
    return error_response(422, "invalid_settings", "tenant settings are invalid", details=problems)


async def _unavailable(_: Request, exc: Exception) -> JSONResponse:
    log_failure(log, "api.dependency_unavailable", exc, level="warning", error_type=type(exc).__name__)
    return error_response(503, "service_unavailable", "a backing service is unavailable; retry later")


async def _value_error(_: Request, exc: Exception) -> JSONResponse:
    # Repository input checks raise ValueError; its text may quote internal names, so it is not echoed.
    log_failure(log, "api.invalid_request", exc, level="info", error_type=type(exc).__name__)
    return error_response(400, "invalid_request", "invalid request parameters")


async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
    log.error("api.unhandled_error", error_type=type(exc).__name__, exc_info=exc)
    return error_response(500, "internal_error", "internal server error")


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation)
    # Order does not matter: Starlette picks the handler of the closest class in the MRO.
    for cls, status_code, code in SIMPLE_ERRORS:
        app.add_exception_handler(cls, _simple(status_code, code))
    app.add_exception_handler(DatabaseUnavailable, _unavailable)
    app.add_exception_handler(ResponsePolicyError, _policy)
    app.add_exception_handler(ValueError, _value_error)
    app.add_exception_handler(Exception, _unhandled)
