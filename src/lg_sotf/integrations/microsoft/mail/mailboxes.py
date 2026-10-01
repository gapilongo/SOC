"""Microsoft Graph mailbox plumbing shared by ``mail.remediate`` and ``mail.notify``.

Requests
    Every request goes to Microsoft Graph ``/v1.0`` and sends ``Prefer:
    IdType="ImmutableId"`` (the header applies only to the request that
    carries it; with it a message keeps its id when it moves between folders
    of the same mailbox). A mailbox path is ``/v1.0/users/{segment(address)}``
    of a validated, lower-cased address; ids Microsoft returned reach a path
    only through :func:`~lg_sotf.integrations.microsoft.odata.segment`, and a
    Message-ID reaches ``$filter`` only as an
    :func:`~lg_sotf.integrations.microsoft.odata.odata_string` literal (the
    framework percent-encodes the whole filter once). Folder ids are constant
    in Exchange; the well-known names used here are ``inbox``, ``sentitems``,
    ``deleteditems``, ``recoverableitemsdeletions`` and ``drafts``.

Recipients
    ``mail.remediate`` searches the mailboxes of the alert's recipients (and
    the reporter), or every recipient Exchange message trace reports
    (``GET /v1.0/admin/exchange/tracing/messageTraces``, global cloud only,
    windows of at most 10 days starting at most 90 days back, see
    :func:`trace_windows`). Addresses are validated, lower-cased and
    de-duplicated.

    Graph addresses a mailbox only by the user's object id or user
    principal name: an alias or proxy address that is not the UPN (common
    in hybrid tenants, and what message trace reports) answers 404. On a
    404 the address is looked up in the directory
    (:func:`mailbox_owners`: ``mail eq`` and ``proxyAddresses/any(...)``,
    ``User.Read.All``) and the mailbox is addressed as
    ``/v1.0/users/{object id}``; the id is recorded on the step
    (``user_id``) so re-runs, the proof and the restore use it too. Only an
    address no directory user has, or a user without a mailbox, is
    ``mailbox_not_found``; two users with the address fail the step with
    ``ambiguous_target``.

Steps
    A purge or a restore works mailbox by mailbox. Its progress is the list
    ``external_ref.steps`` of ``{mailbox, status, items: [{id, folder}],
    error?, reason?}`` (a list, so the actions page renders it as a table),
    written whole with every checkpoint (``ctx.checkpoint`` merges top-level
    keys only) under a lock. ``folder`` is the item's folder before the change
    (``inbox`` for the Inbox, else the folder id). The state is kept under
    :data:`MAX_STATE_BYTES` so the row's 64 KiB ``external_ref`` limit is
    never reached: a mailbox whose handles would not fit fails with
    ``state_limit`` before anything in it is changed.

    Step statuses: ``pending`` (not finished; with ``items`` once its
    handles were recorded, before the first change), ``done``, ``not_found``
    (no such message), ``mailbox_not_found`` (no directory user has the
    address, or the user has no mailbox),
    ``skipped`` (found, but nothing to change: ``reason`` says why) and
    ``failed`` (``error`` is a ledger error code; ``items`` are kept so a
    retry reconciles them).

Concurrency and errors
    At most :data:`MAILBOX_CONCURRENCY` mailboxes are processed at once, one
    request at a time in each (Outlook allows 4 concurrent requests per app
    and mailbox), and no new mailbox is started with less than
    :data:`MIN_START_S` left before the deadline (the rest stay
    ``pending``). A failure confined to one mailbox (403 outside the
    Exchange RBAC scope, a server error after retries, an invalid id) fails
    that step only. Throttling beyond the deadline, a write whose outcome is
    unknown (``ambiguous``) and token failures stop the run: the mailboxes
    in flight finish and the error propagates. The framework defers the
    action (throttling, an unknown outcome, a token endpoint that is briefly
    unavailable) and the re-run resumes from the recorded steps; otherwise
    (invalid credentials, attempts exhausted) it fails the action keeping the
    recorded steps, ``partial`` and reversible when a mailbox was done, so
    Retry and Roll back stay available.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.capability import HandlerContext, ProbeCheck, ProbeStatus
from lg_sotf.integrations.microsoft.http import MicrosoftApiError, MsResponse
from lg_sotf.services.connectors.base import ConnectorResult

if TYPE_CHECKING:
    from lg_sotf.integrations.microsoft.http import Method

PREFER_IMMUTABLE_ID: Mapping[str, str] = {"Prefer": 'IdType="ImmutableId"'}
FOLDER_INBOX = "inbox"
FOLDER_SENT = "sentitems"
FOLDER_DELETED = "deleteditems"
FOLDER_RECOVERABLE = "recoverableitemsdeletions"
FOLDER_DRAFTS = "drafts"
WELL_KNOWN_FOLDERS = frozenset({FOLDER_INBOX, FOLDER_SENT, FOLDER_DELETED, FOLDER_RECOVERABLE, FOLDER_DRAFTS})
FIND_SELECT = "id,parentFolderId,internetMessageId,from,subject,receivedDateTime"
MAILBOX_CONCURRENCY = 4
MIN_START_S = 5.0
MAX_ITEMS_PER_MAILBOX = 10
MAX_ID_CHARS = 1_024
MAX_STATE_BYTES = 56 * 1024
MAX_SUMMARY_CHARS = 200
MAX_LISTED = 20

USERS_PATH = "/v1.0/users"
# More owners than this are not read: two already make the address ambiguous.
MAX_OWNERS = 5

TRACE_PATH = "/v1.0/admin/exchange/tracing/messageTraces"
TRACE_LEAD = timedelta(days=1)
TRACE_WINDOW = timedelta(days=10)
TRACE_LOOKBACK = timedelta(days=90)
# A window clamped to the 90-day limit starts this much later, so it is still inside the limit when it arrives.
TRACE_FLOOR_MARGIN = timedelta(minutes=10)
TRACE_PAGE = "1000"
MAX_TRACE_ROWS = 5_000

STEP_STATUSES = ("pending", "done", "not_found", "mailbox_not_found", "skipped", "failed")
FINAL_STATUSES = frozenset(STEP_STATUSES) - {"pending"}


def now_utc() -> datetime:
    return datetime.now(UTC)


def item_id(value: Any) -> Optional[str]:
    """A Microsoft object id as received (text, 1-1024 characters, no control characters), else ``None``."""
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARS:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    return value


def mailbox_address(value: Any) -> str:
    """A mailbox address: :func:`~lg_sotf.integrations.microsoft.odata.email_address` whose local part is also a
    dot-atom (no leading, trailing or doubled dot), so ``../`` never reaches a user path, even encoded."""
    address = odata.email_address(value)
    local = address.rsplit("@", 1)[0]
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise odata.InvalidTarget("invalid_target", "not a mailbox address")
    return address


def values(body: Any) -> List[Dict[str, Any]]:
    """The ``value`` list of a Graph collection response (objects only)."""
    found = body.get("value") if isinstance(body, Mapping) else None
    return [v for v in found if isinstance(v, dict)] if isinstance(found, list) else []


# ----------------------------------------------------------------------------- outcomes


def failed(
    error: str,
    summary: str,
    *,
    retryable: bool = False,
    hint: str = "",
    changed: bool = False,
    http_status: Optional[int] = None,
    ms_code: Optional[str] = None,
    request_id: Optional[str] = None,
    external_ref: Optional[Dict[str, Any]] = None,
    **extra: Any,
) -> ConnectorResult:
    """A ``failed`` result with the detail keys every Microsoft failure carries."""
    detail: Dict[str, Any] = {
        "summary": summary[:MAX_SUMMARY_CHARS],
        "changed": changed,
        "error": error,
        "http_status": http_status,
        "ms_code": ms_code,
        "request_id": request_id,
        "retryable": retryable,
        "hint": hint or None,
        **extra,
    }
    return ConnectorResult("failed", detail, external_ref=external_ref)


class Refusal(Exception):
    """The handler decided not to act (before any change): becomes a ``failed`` result with ``error``."""

    def __init__(self, error: str, summary: str, *, hint: str = "", retryable: bool = False, **extra: Any) -> None:
        super().__init__(summary[:MAX_SUMMARY_CHARS])
        self.error = error
        self.summary = summary[:MAX_SUMMARY_CHARS]
        self.hint = hint
        self.retryable = retryable
        self.extra = extra

    def result(self, external_ref: Optional[Dict[str, Any]] = None) -> ConnectorResult:
        return failed(self.error, self.summary, retryable=self.retryable, hint=self.hint, external_ref=external_ref,
                      **self.extra)


# ----------------------------------------------------------------------------- one mailbox


class AmbiguousMailbox(Exception):
    """More than one directory user has the address (the step fails with ``ambiguous_target``)."""


async def mailbox_owners(ctx: HandlerContext, address: str) -> List[str]:
    """Object ids of the directory users whose ``mail`` or proxy address is ``address`` (``User.Read.All``).

    Three separate default queries (``mail eq``, then ``proxyAddresses``
    with the ``smtp:`` and ``SMTP:`` prefixes, like the Entra package):
    neither mixing ``any()`` with ``or`` nor a case-insensitive prefix is
    documented.
    """
    filters = (
        odata.odata_eq("mail", address),
        odata.odata_any_eq("proxyAddresses", f"smtp:{address}"),
        odata.odata_any_eq("proxyAddresses", f"SMTP:{address}"),
    )
    found: Dict[str, None] = {}
    for expression in filters:
        rows = await ctx.api("graph").pages(
            USERS_PATH, params={"$filter": expression, "$select": "id"}, max_items=MAX_OWNERS, deadline=ctx.deadline,
        )
        for row in rows:
            user_id = row.get("id")
            if isinstance(user_id, str) and odata.is_guid(user_id):
                found.setdefault(user_id.lower(), None)
    return list(found)


class Mailbox:
    """Graph mail requests for one mailbox (see the module docstring). Folder ids are cached per instance.

    ``user_id`` is the owner's object id when an earlier run resolved the
    address (an alias or proxy address); the mailbox is then addressed by it.
    """

    def __init__(self, ctx: HandlerContext, address: str, user_id: Any = None) -> None:
        self.address = mailbox_address(address)
        self._ctx = ctx
        self.user_id: Optional[str] = user_id.lower() if isinstance(user_id, str) and odata.is_guid(user_id) else None
        self.path = self._path()
        self._folders: Dict[str, Optional[str]] = {}

    def _path(self) -> str:
        if self.user_id is not None:
            return f"{USERS_PATH}/{odata.segment(self.user_id)}"
        return odata.user_path(self.address)

    async def locate(self) -> bool:
        """Address the mailbox by its owner's object id when the address is an alias; ``False``: no such user.

        Raises :class:`AmbiguousMailbox` when more than one user has the address.
        """
        owners = await mailbox_owners(self._ctx, self.address)
        if len(owners) > 1:
            raise AmbiguousMailbox(f"{len(owners)} directory users have this address")
        if not owners:
            return False
        self.user_id = owners[0]
        self.path = self._path()
        self._folders.clear()
        return True

    async def request(
        self,
        method: Method,
        path: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        json_body: Any = None,
        ok: Sequence[int] = (200,),
        not_found_ok: bool = False,
    ) -> MsResponse:
        return await self._ctx.api("graph").request(
            method, self.path + path, params=params, json=json_body, headers=PREFER_IMMUTABLE_ID, ok=ok,
            not_found_ok=not_found_ok, deadline=self._ctx.deadline,
        )

    async def find(self, message_id: str) -> Optional[List[Dict[str, Any]]]:
        """Messages with this Internet Message-ID in the mailbox (Deleted Items included); ``None``: no such mailbox.

        A 404 for an address is ambiguous (Graph takes only the UPN or the
        object id): the owner is looked up and the search repeated by id
        before the mailbox counts as missing.
        """
        params = {
            "$filter": odata.odata_eq("internetMessageId", message_id),
            "$select": FIND_SELECT,
            "$top": str(MAX_ITEMS_PER_MAILBOX),
        }
        response = await self.request("GET", "/messages", params=params, not_found_ok=True)
        if response.status == 404 and self.user_id is None and await self.locate():
            response = await self.request("GET", "/messages", params=params, not_found_ok=True)
        if response.status == 404:
            return None
        return [m for m in values(response.body) if item_id(m.get("id"))][:MAX_ITEMS_PER_MAILBOX]

    async def message(self, message: str) -> Optional[Dict[str, Any]]:
        """``{id, parentFolderId}`` of one message, or ``None`` when Graph no longer finds it by this id."""
        response = await self.request(
            "GET", f"/messages/{odata.segment(message)}", params={"$select": "id,parentFolderId"}, not_found_ok=True
        )
        if response.status == 404 or not isinstance(response.body, dict):
            return None
        return response.body

    async def folder_id(self, folder: str) -> Optional[str]:
        """The id of a folder (a well-known name or an id), ``None`` when it does not exist (cached)."""
        if folder not in self._folders:
            response = await self.request(
                "GET", f"/mailFolders/{odata.segment(folder)}", params={"$select": "id"}, not_found_ok=True
            )
            body = response.body if response.status != 404 and isinstance(response.body, Mapping) else {}
            self._folders[folder] = item_id(body.get("id"))
        return self._folders[folder]

    async def resolve(self, folder: str) -> Optional[str]:
        """A folder's id: a well-known name is looked up, an id is returned as it is."""
        return await self.folder_id(folder) if folder in WELL_KNOWN_FOLDERS else item_id(folder)

    async def search(self, folder: str, filter_text: str, select: str) -> List[Dict[str, Any]]:
        """Messages of one folder matching an OData filter (``[]`` when the folder no longer exists)."""
        response = await self.request(
            "GET",
            f"/mailFolders/{odata.segment(folder)}/messages",
            params={"$filter": filter_text, "$select": select, "$top": str(MAX_ITEMS_PER_MAILBOX)},
            not_found_ok=True,
        )
        if response.status == 404:
            return []
        return [m for m in values(response.body) if item_id(m.get("id"))]

    async def in_folder(self, folder: str, message_id: str) -> List[str]:
        """Ids of the messages with this Internet Message-ID in one folder."""
        found = await self.search(folder, odata.odata_eq("internetMessageId", message_id), "id")
        return [str(m["id"]) for m in found]

    async def delete(self, message: str) -> bool:
        """Soft-delete one message (``DELETE``, 204); ``False`` when it was already gone (404)."""
        response = await self.request("DELETE", f"/messages/{odata.segment(message)}", ok=(204, 200),
                                      not_found_ok=True)
        return response.status != 404

    async def move(self, message: str, destination: str) -> Optional[Dict[str, Any]]:
        """Move one message (``POST .../move``, 201): the moved message, or ``None`` on 404."""
        response = await self.request(
            "POST", f"/messages/{odata.segment(message)}/move", json_body={"destinationId": destination},
            ok=(201, 200), not_found_ok=True,
        )
        if response.status == 404:
            return None
        return response.body if isinstance(response.body, dict) else {}


async def probe_get(
    ctx: HandlerContext, name: str, permission: str, path: str, params: Mapping[str, str]
) -> ProbeCheck:
    """One connection-test GET as a :class:`ProbeCheck` (token failures propagate: the test reports them)."""
    try:
        await ctx.api("graph").request("GET", path, params=params, headers=PREFER_IMMUTABLE_ID, deadline=ctx.deadline)
    except MicrosoftAuthError:
        raise
    except MicrosoftApiError as exc:
        where = f"HTTP {exc.status} {exc.code}".strip()
        if exc.kind == "forbidden":
            denied: ProbeStatus = "not_licensed" if exc.ledger_error == "not_licensed" else "forbidden"
            return ProbeCheck(name, denied, permission=permission, detail=(
                f"{where}: grant {permission} (Exchange RBAC for Applications scope, or admin consent); "
                "check with Test-ServicePrincipalAuthorization"
            )[:300])
        return ProbeCheck(name, "not_found" if exc.kind == "not_found" else "error", permission=permission,
                          detail=f"{where} ({exc.ledger_error})"[:300])
    return ProbeCheck(name, "ok", permission=permission)


# ----------------------------------------------------------------------------- recipients


def mailbox_addresses(candidates: Iterable[Any]) -> Tuple[List[str], int]:
    """Valid, lower-cased, de-duplicated mailbox addresses (in order) and how many candidates were dropped."""
    found: Dict[str, None] = {}
    dropped = 0
    for candidate in candidates:
        if not isinstance(candidate, str):
            dropped += 1
            continue
        try:
            found.setdefault(mailbox_address(candidate), None)
        except odata.InvalidTarget:
            dropped += 1
    return list(found), dropped


def trace_window(received_at: Optional[datetime], now: datetime) -> Tuple[datetime, datetime]:
    """The message trace window: one day before reception, at most 10 days long, never in the future.

    A reception time in the future (the email's ``Date`` header is
    sender-controlled) counts as now.
    """
    received = min(received_at, now) if received_at is not None else now
    start = received - TRACE_LEAD
    return start, min(start + TRACE_WINDOW, now)


def trace_windows(
    received_at: Optional[datetime], now: datetime, reported_at: Optional[datetime] = None
) -> List[Tuple[datetime, datetime]]:
    """The message trace windows to search: each at most 10 days, never in the future, within the last 90 days.

    The email's ``Date`` header (``received_at``) is set by the sender, who
    can backdate or future-date it; the time the report reached LG-SOTF
    (``reported_at``, the alert's ingestion) is not. With it, the first
    window covers the nine days before the report and the day after, so a
    forged ``Date`` never moves the search off the delivery. The ``Date``
    window is added when it reaches further back (a message reported long
    after delivery). Empty: nothing within the last 90 days to search.
    """
    lookback = now - TRACE_LOOKBACK
    windows: List[Tuple[datetime, datetime]] = []
    if reported_at is not None:
        reported = min(reported_at, now)
        start = max(reported - (TRACE_WINDOW - TRACE_LEAD), lookback + TRACE_FLOOR_MARGIN)
        end = min(reported + TRACE_LEAD, now)
        if end > start:
            windows.append((start, end))
    start, end = trace_window(received_at, now)
    covered = any(first <= start and end <= last for first, last in windows)
    if start >= lookback and not covered:
        windows.append((start, end))
    return windows


async def traced_recipients(
    ctx: HandlerContext, message_id: str, received_at: Optional[datetime], reported_at: Optional[datetime] = None
) -> List[Any]:
    """Every ``recipientAddress`` Exchange message trace reports for the message (global cloud only).

    Searches each of :func:`trace_windows`; a message older than 90 days is refused (``invalid_target``).
    """
    windows = trace_windows(received_at, now_utc(), reported_at)
    if not windows:
        raise Refusal(
            "invalid_target", "message older than 90 days: message trace cannot find its recipients",
            hint="use recipient_source=alert, or remove the message with Microsoft Purview or Defender",
        )
    recipients: List[Any] = []
    for start, end in windows:
        trace_filter = (
            f"{odata.odata_eq('messageId', message_id)}"
            f" and receivedDateTime ge {odata.graph_datetime(start)}"
            f" and receivedDateTime le {odata.graph_datetime(end)}"
        )
        rows = await ctx.api("graph").pages(
            TRACE_PATH, params={"$filter": trace_filter, "$top": TRACE_PAGE}, headers=PREFER_IMMUTABLE_ID,
            max_items=MAX_TRACE_ROWS, deadline=ctx.deadline,
        )
        recipients.extend(row.get("recipientAddress") for row in rows)
    return recipients


# ----------------------------------------------------------------------------- steps


class StateLimit(Exception):
    """The steps would outgrow :data:`MAX_STATE_BYTES` (the mailbox fails with ``state_limit``, unchanged)."""


def _state_size(state: Mapping[str, Any]) -> int:
    return len(json.dumps(state, separators=(",", ":"), default=str))


class StepBook:
    """The per-mailbox steps of one purge or restore, checkpointed whole into ``external_ref`` (module docstring).

    ``header`` holds the run's fixed facts (``mode``, ``internet_message_id``,
    ...) and is written with every checkpoint.
    """

    def __init__(self, ctx: HandlerContext, header: Mapping[str, Any], steps: Iterable[Mapping[str, Any]] = ()) -> None:
        self._ctx = ctx
        self.header: Dict[str, Any] = dict(header)
        self._steps: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        for step in steps:
            self._steps[str(step["mailbox"])] = dict(step)

    @staticmethod
    def recorded(external_ref: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """The well-formed steps of an ``external_ref`` (anything else is ignored)."""
        raw = external_ref.get("steps") if isinstance(external_ref, Mapping) else None
        out: List[Dict[str, Any]] = []
        for step in raw if isinstance(raw, list) else []:
            if not isinstance(step, Mapping) or step.get("status") not in STEP_STATUSES:
                continue
            mailbox = step.get("mailbox")
            if not isinstance(mailbox, str) or not mailbox:
                continue
            items = [
                {"id": str(i["id"]), "folder": str(i["folder"])}
                for i in step.get("items") or []
                if isinstance(i, Mapping) and item_id(i.get("id")) and item_id(i.get("folder"))
            ]
            clean = {k: v for k, v in step.items() if k != "items"}
            if items:
                clean["items"] = items
            out.append(clean)
        return out

    def mailboxes(self) -> List[str]:
        return list(self._steps)

    def status(self, mailbox: str) -> str:
        return str(self._steps.get(mailbox, {}).get("status") or "pending")

    def step(self, mailbox: str) -> Dict[str, Any]:
        return dict(self._steps.get(mailbox) or {"mailbox": mailbox, "status": "pending"})

    def items(self, mailbox: str) -> List[Dict[str, str]]:
        return [dict(i) for i in self._steps.get(mailbox, {}).get("items") or []]

    def steps(self) -> List[Dict[str, Any]]:
        return [dict(s) for s in self._steps.values()]

    def counts(self) -> Dict[str, int]:
        counted = Counter(self.status(m) for m in self._steps)
        return {status: counted.get(status, 0) for status in STEP_STATUSES}

    def state(self) -> Dict[str, Any]:
        return {**self.header, "steps": self.steps()}

    async def _write(self, steps: Dict[str, Dict[str, Any]]) -> None:
        state = {**self.header, "steps": [dict(s) for s in steps.values()]}
        if _state_size(state) > MAX_STATE_BYTES:
            raise StateLimit()
        await self._ctx.checkpoint(state)
        self._steps = steps

    async def start(self, mailboxes: Sequence[str]) -> None:
        """Write-ahead: record the mailboxes (all ``pending``) before anything is changed."""
        async with self._lock:
            await self._write({m: {"mailbox": m, "status": "pending"} for m in mailboxes})

    def user_id(self, mailbox: str) -> Optional[str]:
        """The owner's object id recorded for a mailbox addressed by an alias (see :class:`Mailbox`)."""
        user_id = self._steps.get(mailbox, {}).get("user_id")
        return user_id if isinstance(user_id, str) and odata.is_guid(user_id) else None

    async def save(
        self, mailbox: str, status: str, *, items: Optional[Sequence[Mapping[str, str]]] = None, **extra: Any
    ) -> None:
        """Record one mailbox's step (``StateLimit`` when it would not fit; nothing is written then).

        A recorded ``user_id`` is kept unless ``extra`` gives one.
        """
        step: Dict[str, Any] = {"mailbox": mailbox, "status": status}
        if items:
            step["items"] = [{"id": str(i["id"]), "folder": str(i["folder"])} for i in items]
        extra.setdefault("user_id", self.user_id(mailbox))
        step.update({k: v for k, v in extra.items() if v is not None and v is not False})
        async with self._lock:
            await self._write({**self._steps, mailbox: step})

    async def fail(self, mailbox: str, error: str, *, retryable: bool = False, ms_code: Optional[str] = None) -> None:
        """Mark one mailbox ``failed``, keeping its recorded handles so a retry reconciles them."""
        items = self.items(mailbox)
        try:
            await self.save(mailbox, "failed", items=items, error=error, retryable=retryable, ms_code=ms_code or None)
        except StateLimit:
            await self.save(mailbox, "failed", error=error)


Work = Callable[[str], Awaitable[None]]


async def each_mailbox(
    ctx: HandlerContext,
    mailboxes: Sequence[str],
    work: Work,
    *,
    concurrency: int = MAILBOX_CONCURRENCY,
    min_start_s: float = MIN_START_S,
) -> int:
    """Run ``work(mailbox)`` for up to ``concurrency`` mailboxes at a time; returns how many were started.

    No mailbox is started with less than ``min_start_s`` left before the
    deadline. The first exception stops new starts; it is raised once the
    mailboxes in flight have finished.
    """
    queue = list(mailboxes)
    raised: List[Exception] = []
    started = 0

    async def worker() -> None:
        nonlocal started
        while queue and not raised:
            if ctx.remaining_s() < min_start_s:
                return
            mailbox = queue.pop(0)
            started += 1
            try:
                await work(mailbox)
            except Exception as exc:  # noqa: BLE001 - re-raised below, after the other workers stopped
                raised.append(exc)
                return

    await asyncio.gather(*(worker() for _ in range(min(concurrency, len(queue)))))
    if raised:
        raise raised[0]
    return started


def stops_run(exc: MicrosoftApiError) -> bool:
    """Errors that stop the whole run (the framework defers or fails the action) rather than one mailbox."""
    return isinstance(exc, MicrosoftAuthError) or exc.kind == "throttled" or exc.ambiguous


async def guarded_step(book: StepBook, mailbox: str, body: Callable[[], Awaitable[None]]) -> None:
    """Run one mailbox's step; a failure confined to the mailbox is recorded on its step (module docstring)."""
    try:
        await body()
    except MicrosoftApiError as exc:
        if stops_run(exc):
            raise
        if exc.kind == "deadline":
            return  # not sent: the step stays as it is, a re-run continues it
        await book.fail(mailbox, exc.ledger_error, retryable=exc.retryable, ms_code=exc.code or None)
    except odata.InvalidTarget as exc:
        await book.fail(mailbox, exc.code)
    except AmbiguousMailbox:
        await book.fail(mailbox, "ambiguous_target")
    except StateLimit:
        await book.fail(mailbox, "state_limit")


def failure_summary(steps: Sequence[Mapping[str, Any]]) -> Tuple[str, bool, Optional[str]]:
    """(most common error, any retryable, its Microsoft code) of the failed steps (``deadline``: only unfinished ones)."""
    failures = [s for s in steps if s.get("status") == "failed"]
    if not failures:
        return "deadline", True, None
    errors = Counter(str(s.get("error") or "connector_exception") for s in failures)
    error = errors.most_common(1)[0][0]
    code = next((s.get("ms_code") for s in failures if s.get("error") == error and s.get("ms_code")), None)
    return error, any(bool(s.get("retryable")) for s in failures), code


def listed(mailboxes: Iterable[str]) -> List[str]:
    """At most :data:`MAX_LISTED` mailboxes (results stay small)."""
    return list(mailboxes)[:MAX_LISTED]


__all__ = [
    "FINAL_STATUSES",
    "FOLDER_DELETED",
    "FOLDER_DRAFTS",
    "FOLDER_INBOX",
    "FOLDER_RECOVERABLE",
    "FOLDER_SENT",
    "MAILBOX_CONCURRENCY",
    "MAX_STATE_BYTES",
    "MIN_START_S",
    "PREFER_IMMUTABLE_ID",
    "STEP_STATUSES",
    "TRACE_PATH",
    "USERS_PATH",
    "AmbiguousMailbox",
    "Mailbox",
    "Refusal",
    "StateLimit",
    "StepBook",
    "each_mailbox",
    "failed",
    "failure_summary",
    "guarded_step",
    "item_id",
    "listed",
    "mailbox_address",
    "mailbox_addresses",
    "mailbox_owners",
    "probe_get",
    "stops_run",
    "trace_window",
    "trace_windows",
    "traced_recipients",
    "values",
]
