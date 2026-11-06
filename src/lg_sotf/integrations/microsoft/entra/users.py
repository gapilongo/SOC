"""Resolving the target user of an Entra action, and the result helpers every Entra handler shares.

:func:`resolve_user` turns an untrusted ledger target into one
:class:`DirectoryUser` (its object id and the properties the handlers
decide on); every later request addresses ``/v1.0/users/{object id}``.

* An object id: ``GET /v1.0/users/{id}``.
* A user principal name or email address: ``GET`` on
  :func:`~lg_sotf.integrations.microsoft.odata.user_path` (``#`` encoded as
  ``%23`` for guests, the ``('...')`` key form for a UPN starting with
  ``$``). Graph answers 404 ``Request_ResourceNotFound`` for a mail or
  proxy address that is not the UPN, so a 404 falls back to four separate
  default queries (no ``ConsistencyLevel``: advanced queries read an
  eventually consistent index): ``userPrincipalName eq``, ``mail eq``, and
  ``proxyAddresses/any(x:x eq 'smtp:...')`` with lower- and upper-case
  prefixes (neither case-insensitivity of the prefix nor mixing ``any()``
  with ``or`` is documented). Exactly one distinct object id must match:
  none is ``not_found``, more than one ``ambiguous_target``.
* ``DOMAIN\\sam`` and bare account names are ``invalid_target``: Graph
  cannot resolve them.

Every request selects the properties it needs (``accountEnabled``,
``onPremisesSyncEnabled``, ``signInSessionsValidFromDateTime``,
``lastPasswordChangeDateTime`` and ``userType`` are returned only when
selected); a ``202 Accepted`` counts as success.

The helpers at the end build the ledger outcomes shared by the handlers:
refusals, failed writes (a 403 is never retried and never deferred) and
connection-test probes. Results never carry Microsoft free text.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Mapping, Optional, TypeVar

from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.capability import HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

USER_SELECT = (
    "id,userPrincipalName,mail,userType,accountEnabled,onPremisesSyncEnabled,"
    "signInSessionsValidFromDateTime,lastPasswordChangeDateTime"
)
USER_OK = (200, 202)
USERS_PATH = "/v1.0/users"
# More matches than this are not read: two already make the target ambiguous.
MAX_MATCHES = 5
# Tolerated difference between this server's clock and Microsoft's when comparing timestamps.
CLOCK_SKEW = timedelta(seconds=60)
# An inline re-read right after a write may hit a directory replica that has not seen it yet.
INLINE_READS = 3
INLINE_REREAD_DELAY_S = 1.0
MAX_SUMMARY_CHARS = 200
WRITE_DENIED_HINT = (
    "missing application permission or the User Administrator role, or the target is out of scope"
)
LICENCE_HINT = "the Microsoft tenant lacks the licence this action needs"

T = TypeVar("T")


class Refused(Exception):
    """The handler will not act on this user; ``code`` is the ledger ``result.error``.

    ``summary`` (one line), ``detail`` and ``hint`` are safe to store and show.
    ``retryable``: running the action again later may succeed.
    """

    def __init__(
        self,
        code: str,
        summary: str,
        detail: Optional[Mapping[str, Any]] = None,
        *,
        hint: str = "",
        retryable: bool = False,
    ) -> None:
        super().__init__(summary[:MAX_SUMMARY_CHARS])
        self.code = code
        self.summary = summary[:MAX_SUMMARY_CHARS]
        self.detail: Dict[str, Any] = dict(detail or {})
        self.hint = hint
        self.retryable = retryable


def parse_time(value: Any) -> Optional[datetime]:
    """A Graph DateTimeOffset (``2026-09-30T12:00:00Z``, up to 7 fractional digits) as an aware datetime."""
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, _, rest = text.partition(".")
        digits = len(rest) - len(rest.lstrip("0123456789"))
        text = f"{head}.{rest[:min(digits, 6)]}{rest[digits:]}" if digits else head + rest[digits:]
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def iso(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(UTC).isoformat() if value is not None else None


def _text(value: Any, limit: int) -> Optional[str]:
    return value[:limit] if isinstance(value, str) and value else None


@dataclass(frozen=True)
class DirectoryUser:
    """The target user as Graph returned it (``id`` is a validated, lower-case object id)."""

    id: str
    upn: str
    mail: Optional[str] = None
    user_type: str = "Member"
    account_enabled: Optional[bool] = None
    synced: bool = False
    sessions_valid_from: Optional[datetime] = None
    last_password_change: Optional[datetime] = None

    @property
    def is_guest(self) -> bool:
        return self.user_type.lower() == "guest"

    @property
    def path(self) -> str:
        """``/v1.0/users/{object id}``: the only form writes use."""
        return f"{USERS_PATH}/{odata.segment(self.id)}"

    def brief(self) -> Dict[str, Any]:
        """What results record about the user (no other properties)."""
        return {"id": self.id, "upn": self.upn}

    def describe(self) -> Dict[str, Any]:
        """What a rehearsal shows about the user."""
        return {"id": self.id, "upn": self.upn, "synced": self.synced, "user_type": self.user_type}


def directory_user(body: Any) -> DirectoryUser:
    """A :class:`DirectoryUser` from a Graph user object (``bad_request`` when it has no valid object id)."""
    user_id = body.get("id") if isinstance(body, Mapping) else None
    if not isinstance(user_id, str) or not odata.is_guid(user_id):
        raise MicrosoftApiError(
            "bad_request", "Microsoft Graph returned a user without a valid object id", code="unexpected_response",
            retryable=False,
        )
    assert isinstance(body, Mapping)
    enabled = body.get("accountEnabled")
    return DirectoryUser(
        id=user_id.lower(),
        upn=_text(body.get("userPrincipalName"), odata.MAX_EMAIL_CHARS) or user_id.lower(),
        mail=_text(body.get("mail"), odata.MAX_EMAIL_CHARS),
        user_type=_text(body.get("userType"), 32) or "Member",
        account_enabled=enabled if isinstance(enabled, bool) else None,
        synced=body.get("onPremisesSyncEnabled") is True,
        sessions_valid_from=parse_time(body.get("signInSessionsValidFromDateTime")),
        last_password_change=parse_time(body.get("lastPasswordChangeDateTime")),
    )


async def user_by_id(ctx: HandlerContext, user_id: str, *, select: str = USER_SELECT) -> DirectoryUser:
    """The user with this object id; :class:`Refused` ``not_found`` when it does not exist (any more)."""
    if not odata.is_guid(user_id):
        raise odata.InvalidTarget("invalid_target", "not a user object id")
    response = await ctx.api("graph").request(
        "GET", f"{USERS_PATH}/{odata.segment(user_id.lower())}", params={"$select": select}, ok=USER_OK,
        not_found_ok=True, deadline=ctx.deadline,
    )
    if response.status == 404:
        raise Refused("not_found", "the user does not exist in Microsoft Entra ID", {"user_id": user_id.lower()})
    return directory_user(response.body)


def _account_name(target: str) -> str:
    text = target.strip() if isinstance(target, str) else ""
    if "\\" in text or "@" not in text:
        raise odata.InvalidTarget(
            "invalid_target",
            "the target is not a user principal name, email address or object id "
            "(DOMAIN\\user and bare account names cannot be resolved in Entra ID)",
        )
    return odata.upn(text)


async def resolve_user(ctx: HandlerContext, target: str) -> DirectoryUser:
    """Resolve an untrusted target to exactly one user (see the module docstring)."""
    text = target.strip() if isinstance(target, str) else ""
    if odata.is_guid(text):
        return await user_by_id(ctx, text)
    name = _account_name(text)
    api = ctx.api("graph")
    response = await api.request(
        "GET", odata.user_path(name), params={"$select": USER_SELECT}, ok=USER_OK, not_found_ok=True,
        deadline=ctx.deadline,
    )
    if response.status != 404:
        return directory_user(response.body)
    filters = (
        odata.odata_eq("userPrincipalName", name),
        odata.odata_eq("mail", name),
        odata.odata_any_eq("proxyAddresses", f"smtp:{name}"),
        odata.odata_any_eq("proxyAddresses", f"SMTP:{name}"),
    )
    matches: Dict[str, Dict[str, Any]] = {}
    for expression in filters:
        found = await api.pages(
            USERS_PATH, params={"$filter": expression, "$select": USER_SELECT}, max_items=MAX_MATCHES,
            deadline=ctx.deadline,
        )
        for item in found:
            object_id = item.get("id")
            if isinstance(object_id, str) and odata.is_guid(object_id):
                matches.setdefault(object_id.lower(), item)
    if not matches:
        raise Refused("not_found", "no Microsoft Entra ID user has this name or address")
    if len(matches) > 1:
        raise Refused(
            "ambiguous_target", f"{len(matches)} Microsoft Entra ID users match this address; refusing to guess",
            {"matches": len(matches)}, hint="use the user's object id or user principal name as the target",
        )
    return directory_user(next(iter(matches.values())))


def mapping(value: Any) -> Dict[str, Any]:
    """``value`` as a dict when it is a JSON object (``external_ref`` fields), else empty."""
    return dict(value) if isinstance(value, Mapping) else {}


def not_before(action: ResponseAction) -> datetime:
    """The earliest Microsoft timestamp that proves this action's change (execution time minus the clock skew)."""
    return (action.executed_at or datetime.now(UTC)) - CLOCK_SKEW


def at_or_after(value: Optional[datetime], threshold: datetime) -> bool:
    return value is not None and value >= threshold


# --------------------------------------------------------------------------- results


def summary(text: str) -> str:
    return text[:MAX_SUMMARY_CHARS]


def refused_result(exc: Refused, user: Optional[DirectoryUser] = None) -> ConnectorResult:
    """A ``failed`` outcome for a refusal (nothing was written)."""
    detail: Dict[str, Any] = {
        "summary": exc.summary,
        "changed": False,
        "error": exc.code,
        "retryable": exc.retryable,
        "hint": exc.hint or None,
        **exc.detail,
    }
    if user is not None:
        detail["user"] = user.brief()
    return ConnectorResult("failed", detail)


def write_failure(
    exc: MicrosoftApiError,
    what: str,
    user: DirectoryUser,
    *,
    denied_hint: str = WRITE_DENIED_HINT,
    licence_hint: str = LICENCE_HINT,
    forbidden: Optional[Callable[[MicrosoftApiError], str]] = None,
    bad_request: Optional[Callable[[MicrosoftApiError], str]] = None,
) -> Optional[ConnectorResult]:
    """The ``failed`` outcome of a refused request, or ``None`` to re-raise ``exc``.

    403 -> ``permission_denied`` (or ``not_licensed``/``feature_disabled``,
    or what ``forbidden`` maps the code to), never retried (Microsoft cannot
    tell a missing permission from a missing role or an out-of-scope target,
    so a human looks); 404 -> ``not_found``; 400/409 -> ``bad_request`` (or
    what ``bad_request`` maps the code to; a 409 is retryable). Throttling,
    server and network errors, token failures and ambiguous writes are
    re-raised: the connector defers or classifies them.
    """
    if isinstance(exc, MicrosoftAuthError) or exc.ambiguous:
        return None
    if exc.kind == "forbidden":
        error = forbidden(exc) if forbidden is not None else exc.ledger_error
        hint = {"permission_denied": denied_hint, "not_licensed": licence_hint}.get(error, "")
    elif exc.kind == "not_found":
        error, hint = "not_found", "the user no longer exists in Microsoft Entra ID"
    elif exc.kind in ("bad_request", "conflict"):
        error, hint = (bad_request(exc) if bad_request is not None else "bad_request"), ""
    else:
        return None
    detail: Dict[str, Any] = {
        "summary": summary(f"Microsoft Graph refused to {what} {user.upn} ({error}, HTTP {exc.status})"),
        "changed": False,
        "error": error,
        "http_status": exc.status or None,
        "ms_code": exc.code or None,
        "request_id": exc.request_id or None,
        # A conflict (Directory_ConcurrencyViolation after the client's retries) passes; the rest needs a human.
        "retryable": exc.kind == "conflict",
        "hint": hint or None,
        "user": user.brief(),
    }
    return ConnectorResult("failed", detail)


async def reread(
    ctx: HandlerContext,
    read: Callable[[], Awaitable[T]],
    done: Callable[[T], bool],
    *,
    attempts: int = INLINE_READS,
) -> T:
    """``read()`` until ``done(value)``, at most ``attempts`` times, pausing between reads (never past the deadline)."""
    value = await read()
    for _ in range(attempts - 1):
        if done(value) or ctx.remaining_s() < INLINE_REREAD_DELAY_S + 2.0:
            break
        await asyncio.sleep(INLINE_REREAD_DELAY_S)
        value = await read()
    return value


def inline_read_failed(exc: Exception) -> Dict[str, Any]:
    """Why an inline verification read failed (the write stands; verification continues later)."""
    if isinstance(exc, MicrosoftApiError):
        return {"inline_check": exc.ledger_error, "http_status": exc.status or None}
    return {"inline_check": type(exc).__name__}


async def probe_get(
    ctx: HandlerContext,
    name: str,
    path: str,
    *,
    permission: str,
    params: Optional[Mapping[str, str]] = None,
    headers: Optional[Mapping[str, str]] = None,
    unlicensed: Optional[Callable[[MicrosoftApiError], bool]] = None,
) -> ProbeCheck:
    """One connection-test GET as a :class:`ProbeCheck` (a 403 is ``forbidden``, or ``not_licensed`` when
    ``unlicensed(exc)`` says the code points to a missing licence)."""
    try:
        await ctx.api("graph").request("GET", path, params=params, headers=headers, deadline=ctx.deadline)
    except MicrosoftAuthError:
        raise
    except MicrosoftApiError as exc:
        detail = f"HTTP {exc.status} {exc.code}".strip()[:300]
        if exc.kind == "forbidden":
            licence = exc.ledger_error == "not_licensed" or (unlicensed is not None and unlicensed(exc))
            return ProbeCheck(name, "not_licensed" if licence else "forbidden", permission=permission, detail=detail)
        if exc.kind == "not_found":
            return ProbeCheck(name, "not_found", permission=permission, detail=detail)
        return ProbeCheck(name, "error", permission=permission, detail=f"{exc.ledger_error} ({detail})"[:300])
    return ProbeCheck(name, "ok", permission=permission)


__all__ = [
    "CLOCK_SKEW",
    "DirectoryUser",
    "Refused",
    "USER_SELECT",
    "WRITE_DENIED_HINT",
    "at_or_after",
    "directory_user",
    "inline_read_failed",
    "iso",
    "mapping",
    "not_before",
    "parse_time",
    "probe_get",
    "refused_result",
    "reread",
    "resolve_user",
    "summary",
    "user_by_id",
    "write_failure",
]
