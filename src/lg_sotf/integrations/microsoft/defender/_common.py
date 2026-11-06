"""Pieces shared by the Defender for Endpoint capabilities: outcomes, error mapping, ids, times and probes.

Handlers raise :class:`Refused` for an outcome that ends the action as
``failed`` with a ledger error code (``not_found``, ``ambiguous_target``,
``conflicting_indicator``, ``rollback_not_needed`` ...) and :class:`Defer`
when the call cannot finish now; :func:`settle` turns both, and the
Defender API errors that need a capability-specific hint, into a
:class:`~lg_sotf.domain.connectors.ConnectorResult`. Every other
error (throttling, ambiguous writes, server and network errors, token
failures, :class:`~lg_sotf.integrations.microsoft.capability.CheckpointLost`)
propagates to the connector, which maps it for all capabilities alike.

Defender error mapping (``docs/microsoft-defender.md``):

* 403 ``DisabledFeature`` -> ``feature_disabled``, with a hint naming the
  advanced feature to turn on;
* 403 ``Forbidden`` (or any other 403) -> ``permission_denied``, with a hint
  naming the WindowsDefenderATP permission (a token for the wrong audience
  also answers 403);
* 400 ``OsPlatformNotSupported`` / ``ClientVersionNotSupported`` ->
  ``unsupported_target``.

Ids read back from Defender (machine, machine action and indicator ids) are
checked with :func:`ms_id` before they go into a path, and still encoded
with :func:`~lg_sotf.integrations.microsoft.odata.segment`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Awaitable, Dict, List, Mapping, Optional

from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.integrations.microsoft.capability import MARKER_PREFIX, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.http import MicrosoftApiError, MsResponse, ledger_error
from lg_sotf.observability.logging import get_logger

log = get_logger(__name__)

MAX_SUMMARY_CHARS = 200
PLATFORM_CODES = frozenset({"osplatformnotsupported", "clientversionnotsupported"})
PLATFORM_HINT = "the device's operating system or Defender client version does not support this action"
FEATURE_HINT = (
    "a Defender for Endpoint feature this action needs is turned off (Settings > Endpoints > General > "
    "Advanced features)"
)
_MS_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class Hints:
    """Operator guidance for the two 403 outcomes of one capability."""

    permission: str
    feature: str = FEATURE_HINT


class Refused(Exception):
    """The action ends ``failed`` with ledger ``error`` (the message is ``summary``: safe to store)."""

    def __init__(
        self,
        error: str,
        summary: str,
        *,
        hint: str = "",
        retryable: bool = False,
        exc: Optional[MicrosoftApiError] = None,
        **extra: Any,
    ) -> None:
        super().__init__(summary[:MAX_SUMMARY_CHARS])
        self.error = error
        self.summary = summary[:MAX_SUMMARY_CHARS]
        self.hint = hint
        self.retryable = retryable
        self.exc = exc
        self.extra = extra

    def result(self, external_ref: Optional[Dict[str, Any]] = None) -> ConnectorResult:
        return failure(self.error, self.summary, exc=self.exc, hint=self.hint, retryable=self.retryable,
                       external_ref=external_ref, **self.extra)


class Defer(Exception):
    """The call cannot finish now; run it again after ``retry_after_s`` (the re-run reconciles)."""

    def __init__(self, reason: str, summary: str, retry_after_s: float = 60.0) -> None:
        super().__init__(summary[:MAX_SUMMARY_CHARS])
        self.reason = reason
        self.summary = summary[:MAX_SUMMARY_CHARS]
        self.retry_after_s = retry_after_s


def failure(
    error: str,
    summary: str,
    *,
    exc: Optional[MicrosoftApiError] = None,
    hint: str = "",
    retryable: Optional[bool] = None,
    external_ref: Optional[Dict[str, Any]] = None,
    **extra: Any,
) -> ConnectorResult:
    """A ``failed`` result with the shared failure fields (no Microsoft free text)."""
    detail: Dict[str, Any] = {
        "summary": summary[:MAX_SUMMARY_CHARS],
        "changed": False,
        "error": error,
        "http_status": exc.status if exc is not None and exc.status else None,
        "ms_code": exc.code if exc is not None and exc.code else None,
        "request_id": exc.request_id if exc is not None and exc.request_id else None,
        "retryable": bool(retryable) if retryable is not None else bool(exc is not None and exc.retryable),
        "hint": hint or None,
        **extra,
    }
    return ConnectorResult("failed", detail, external_ref=external_ref)


def refusal_for(exc: MicrosoftApiError, hints: Hints) -> Optional[Refused]:
    """The capability-specific outcome of a Defender error, or ``None`` to let the connector map it."""
    code = exc.code.lower()
    if exc.kind == "forbidden":
        error = ledger_error(exc)
        if error == "feature_disabled":
            return Refused(error, f"Defender refused the request: a tenant feature is disabled ({exc.code})",
                           hint=hints.feature, exc=exc)
        if error == "not_licensed":
            return Refused(error, f"Defender refused the request: not licensed ({exc.code})",
                           hint="the Defender for Endpoint licence of the tenant does not include this action", exc=exc)
        return Refused("permission_denied", f"Defender refused the request (HTTP 403 {exc.code or 'Forbidden'})",
                       hint=hints.permission, exc=exc)
    if exc.kind == "bad_request" and code in PLATFORM_CODES:
        return Refused("unsupported_target", f"the device cannot run this action ({exc.code})", hint=PLATFORM_HINT,
                       exc=exc)
    return None


async def settle(work: Awaitable[ConnectorResult], hints: Hints) -> ConnectorResult:
    """Await a handler's execution and turn :class:`Refused`, :class:`Defer` and mapped API errors into results."""
    try:
        return await work
    except Refused as refused:
        return refused.result()
    except Defer as deferred:
        return ConnectorResult(
            "deferred", {"summary": deferred.summary, "changed": False, "deferred": deferred.reason},
            retry_after_s=deferred.retry_after_s,
        )
    except MicrosoftApiError as exc:
        refusal = refusal_for(exc, hints)
        if refusal is None:
            raise
        return refusal.result()


def ms_id(value: Any, what: str) -> str:
    """A Defender object id (machine, machine action, indicator) that is safe to put in a path."""
    text = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not _MS_ID.match(text):
        raise MicrosoftApiError("bad_request", f"Defender returned an unusable {what}", code="invalid_response",
                                retryable=False)
    return text


def values(response: MsResponse, what: str) -> List[Dict[str, Any]]:
    """The ``value`` list of a Defender collection response (a 404 answer counts as empty)."""
    if response.status == 404:
        return []
    body = response.body if isinstance(response.body, Mapping) else {}
    items = body.get("value")
    if not isinstance(items, list):
        raise MicrosoftApiError("bad_request", f"Defender returned {what} without a value list",
                                code="invalid_response", status=response.status, request_id=response.request_id,
                                retryable=False)
    return [item for item in items if isinstance(item, dict)]


def text(value: Any, limit: int = 300) -> str:
    """A bounded, single-line string from a Defender field ('' when absent)."""
    if not isinstance(value, str):
        return ""
    return _WHITESPACE.sub(" ", value).strip()[:limit]


def parse_time(value: Any) -> Optional[datetime]:
    """A Defender timestamp (``2026-09-30T08:15:02.1234567Z``) as an aware datetime, or ``None``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def iso_z(dt: datetime) -> str:
    """``2026-10-30T08:15:02Z`` (the format Defender request bodies use)."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(UTC)


async def alert_title(ctx: HandlerContext, limit: int = 100) -> str:
    """The alert title for a comment (one line, at most ``limit`` characters; '' when unavailable).

    The title is untrusted alert text: the marker prefix is removed from it,
    so a crafted title can never make a machine action look like another
    ledger action's.
    """
    try:
        view = await ctx.alert()
    except Exception as exc:  # noqa: BLE001 - the title only decorates a comment; the marker is what matters
        log.info("defender.alert_title_unavailable", error_type=type(exc).__name__)
        return ""
    return text(text(view.title, 1_000).replace(MARKER_PREFIX, ""), limit)


def comment(ctx: HandlerContext, suffix: str = "") -> str:
    """A machine-action comment: the action marker, then ``suffix`` (``<marker>: <suffix>``)."""
    return f"{ctx.marker}: {suffix}" if suffix else ctx.marker


async def probe_get(
    ctx: HandlerContext,
    name: str,
    path: str,
    *,
    permission: str,
    params: Optional[Mapping[str, str]] = None,
    not_found_ok: bool = False,
) -> ProbeCheck:
    """One read-only connection-test check (token failures propagate to the connection test)."""
    try:
        await ctx.api("defender").request("GET", path, params=params, not_found_ok=not_found_ok,
                                          deadline=ctx.deadline)
    except MicrosoftApiError as exc:
        if exc.kind == "auth":
            raise
        status_line = f"HTTP {exc.status} {exc.code}".strip()
        if exc.kind == "forbidden":
            error = ledger_error(exc)
            if error == "feature_disabled":
                return ProbeCheck(name, "error", permission=permission, detail=f"feature disabled ({status_line})")
            return ProbeCheck(name, "not_licensed" if error == "not_licensed" else "forbidden",
                              permission=permission, detail=status_line[:300])
        if exc.kind == "not_found":
            return ProbeCheck(name, "not_found", permission=permission, detail=status_line[:300])
        return ProbeCheck(name, "error", permission=permission, detail=f"{exc.ledger_error} ({status_line})"[:300])
    return ProbeCheck(name, "ok", permission=permission)


__all__ = [
    "Defer",
    "Hints",
    "Refused",
    "alert_title",
    "comment",
    "failure",
    "iso_z",
    "ms_id",
    "now",
    "parse_time",
    "probe_get",
    "refusal_for",
    "settle",
    "text",
    "values",
]
