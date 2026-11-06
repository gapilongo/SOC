"""Defender for Endpoint machine actions: listing, polling, requesting and verifying them.

Isolation, release, stop-and-quarantine and investigation packages are
*machine actions*: the POST answers ``201`` with a MachineAction whose
``status`` moves from ``Pending``/``InProgress`` to one of the final states
``Succeeded``, ``Failed``, ``TimeOut`` or ``Cancelled``. The Machine entity
has no isolation state, so the state of a device is read from its latest
machine actions.

* :func:`list_actions` - ``GET /api/machineactions?$filter=machineId eq '<id>' and type eq '<Type>'&$top=50``
  (only ``and`` is documented for this filter; ``or``/``in`` are not used),
  sorted client-side by ``creationDateTimeUtc``. Both spellings of the
  update time are read (``lastUpdateDateTimeUtc`` on the entity and by id,
  ``lastUpdateTimeUtc`` in lists).
* :func:`get_action` - ``GET /api/machineactions/{id}``.
* :func:`ours` - the actions whose ``requestorComment`` carries the action
  marker (``LG-SOTF action <uuid>``): how a re-run finds what an interrupted
  run requested, instead of requesting it twice.
* :func:`post_action` - the POST; a 400 while an action of the same type is
  pending (``ActiveRequestAlreadyExists``, "Action is already in progress",
  "pending machine action", or "a collection is already running") adopts
  the pending action. Microsoft's message text is never read: the pending
  action in the list is the evidence.
* :func:`verification_from` - ``Pending``/``InProgress`` -> ``pending``,
  ``Succeeded`` -> ``verified``, ``Failed``/``TimeOut``/``Cancelled`` -> ``failed``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from lg_sotf.domain.connectors import VerificationResult
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import HandlerContext
from lg_sotf.integrations.microsoft.defender._common import Defer, ms_id, parse_time, text, values
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

ACTIONS_PATH = "/api/machineactions"
LIST_TOP = "50"
PENDING = frozenset({"Pending", "InProgress"})
SUCCEEDED = "Succeeded"
FINAL_FAILED = frozenset({"Failed", "TimeOut", "Cancelled"})
IN_PROGRESS_CODE = "activerequestalreadyexists"
# 400 codes that describe the request itself; never an action already in progress.
REQUEST_CODES = frozenset({
    "invalidrequestbody", "missingrequiredparameter", "invalidinput", "osplatformnotsupported",
    "clientversionnotsupported", "odataerror",
})
IN_PROGRESS_RETRY_S = 60.0


@dataclass(frozen=True)
class MachineAction:
    """The MachineAction fields the capabilities use (``requestor_comment`` is only matched, never shown)."""

    id: str
    type: str
    status: str
    machine_id: str
    requestor_comment: str
    cancellation_comment: str
    created: Optional[datetime]
    last_update: Optional[datetime]

    @property
    def pending(self) -> bool:
        return self.status in PENDING

    @property
    def succeeded(self) -> bool:
        return self.status == SUCCEEDED

    @property
    def final_failed(self) -> bool:
        return self.status in FINAL_FAILED

    @property
    def when(self) -> Optional[datetime]:
        """When the action last changed (its completion time once final)."""
        return self.last_update or self.created

    def out(self) -> Dict[str, Any]:
        return {
            "machine_action_id": self.id,
            "type": self.type,
            "status": self.status,
            "last_update": self.when.isoformat() if self.when is not None else None,
        }


def parse_action(item: Any) -> Optional[MachineAction]:
    """A :class:`MachineAction` from a Defender entity (``None`` without a usable id)."""
    if not isinstance(item, Mapping):
        return None
    try:
        action_id = ms_id(item.get("id"), "machine action id")
    except MicrosoftApiError:
        return None
    return MachineAction(
        id=action_id,
        type=text(item.get("type"), 64),
        status=text(item.get("status"), 32),
        machine_id=text(item.get("machineId"), 128),
        requestor_comment=text(item.get("requestorComment"), 1_000),
        cancellation_comment=text(item.get("cancellationComment"), 1_000),
        created=parse_time(item.get("creationDateTimeUtc")),
        last_update=parse_time(item.get("lastUpdateDateTimeUtc") or item.get("lastUpdateTimeUtc")),
    )


def _created_key(action: MachineAction) -> Tuple[int, float]:
    created = action.created
    return (0, 0.0) if created is None else (1, created.timestamp())


async def list_actions(ctx: HandlerContext, machine_id: str, action_type: str) -> List[MachineAction]:
    """The machine's recent actions of ``action_type`` (at most 50), oldest first."""
    filter_text = f"{odata.odata_eq('machineId', machine_id)} and {odata.odata_eq('type', action_type)}"
    response = await ctx.api("defender").request(
        "GET", ACTIONS_PATH, params={"$filter": filter_text, "$top": LIST_TOP}, not_found_ok=True,
        deadline=ctx.deadline,
    )
    parsed = [parse_action(item) for item in values(response, "the machine action list")]
    # Only the requested machine and type count, whatever the service returned.
    actions = [a for a in parsed if a is not None and a.type == action_type
               and (not a.machine_id or a.machine_id == machine_id)]
    return sorted(actions, key=_created_key)


async def get_action(ctx: HandlerContext, action_id: str) -> MachineAction:
    """One machine action by id (``not_found`` propagates as a :class:`MicrosoftApiError`)."""
    response = await ctx.api("defender").request(
        "GET", f"{ACTIONS_PATH}/{odata.segment(ms_id(action_id, 'machine action id'))}", deadline=ctx.deadline
    )
    action = parse_action(response.body)
    if action is None:
        raise MicrosoftApiError("bad_request", "Defender returned a machine action without an id",
                                code="invalid_response", status=response.status, request_id=response.request_id,
                                retryable=False)
    return action


def ours(actions: List[MachineAction], marker: str) -> List[MachineAction]:
    """The actions requested for this ledger action (their comment carries ``marker``), oldest first."""
    if not marker:
        return []
    return [a for a in actions if marker in a.requestor_comment]


def latest(actions: List[MachineAction], predicate: Callable[[MachineAction], bool]) -> Optional[MachineAction]:
    """The most recent action matching ``predicate`` (by completion, else creation time)."""
    matching = [a for a in actions if predicate(a)]
    if not matching:
        return None
    return max(matching, key=lambda a: (a.when is not None, a.when.timestamp() if a.when else 0.0))


async def post_action(
    ctx: HandlerContext, machine_id: str, verb: str, body: Mapping[str, Any], action_type: str
) -> Tuple[MachineAction, bool]:
    """POST ``/api/machines/{id}/{verb}``: ``(action, requested_by_us)``.

    A 400 while an action of ``action_type`` is pending on the machine
    adopts that action (ours first, else the latest pending one, which is
    then not ours). ``ActiveRequestAlreadyExists`` with nothing pending in
    the list defers the call (the action appears later and is adopted).
    """
    path = f"/api/machines/{odata.segment(ms_id(machine_id, 'machine id'))}/{verb}"
    try:
        response = await ctx.api("defender").request("POST", path, json=dict(body), ok=(200, 201),
                                                     deadline=ctx.deadline)
    except MicrosoftApiError as exc:
        code = exc.code.lower()
        if exc.kind != "bad_request" or exc.status != 400 or code in REQUEST_CODES:
            raise
        pending = [a for a in await list_actions(ctx, machine_id, action_type) if a.pending]
        mine = ours(pending, ctx.marker)
        if mine:
            return mine[-1], True
        if pending:
            return pending[-1], False
        if code == IN_PROGRESS_CODE:
            raise Defer("action_in_progress", f"Defender reports a {action_type} action in progress that is not "
                        "listed yet; will check again", IN_PROGRESS_RETRY_S) from None
        raise
    action = parse_action(response.body)
    if action is None:
        # The request was accepted; a re-run finds the action by its marker.
        raise MicrosoftApiError("server", f"Defender accepted the {action_type} request without a machine action id",
                                code="invalid_response", status=response.status, request_id=response.request_id,
                                retryable=True, ambiguous=True)
    return action, True


def verification_from(action: MachineAction) -> VerificationResult:
    """Pending -> ``pending``; ``Succeeded`` -> ``verified``; ``Failed``/``TimeOut``/``Cancelled`` -> ``failed``."""
    detail = action.out()
    if action.succeeded:
        return VerificationResult("verified", detail)
    if action.final_failed:
        return VerificationResult("failed", {**detail, "reason": f"machine_action_{action.status.lower()}"})
    return VerificationResult("pending", detail)


__all__ = [
    "ACTIONS_PATH",
    "FINAL_FAILED",
    "PENDING",
    "SUCCEEDED",
    "MachineAction",
    "get_action",
    "latest",
    "list_actions",
    "ours",
    "parse_action",
    "post_action",
    "verification_from",
]
