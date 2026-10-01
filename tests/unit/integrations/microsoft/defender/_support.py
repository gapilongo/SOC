"""A stateful fake of the Defender for Endpoint API on top of :class:`~tests.fixtures.microsoft.FakeMicrosoft`.

It follows the verified API facts the capabilities code against:

* ``GET /api/machines`` filters on ``computerDnsName eq '<name>'`` and
  ``startswith(computerDnsName,'<prefix>')`` and answers **404** when the
  tenant has no (recent) machines;
* machine actions are created ``Pending`` by ``POST /api/machines/{id}/<verb>``
  (201, a MachineAction whose ``requestorComment`` is the ``Comment``),
  listed with ``$filter=machineId eq '<id>' and type eq '<Type>'`` (the list
  uses ``lastUpdateTimeUtc``, get-by-id ``lastUpdateDateTimeUtc``), polled by
  id and cancelled with ``POST /api/machineactions/{id}/cancel`` (200);
* indicators are listed with ``$filter=indicatorValue eq '<v>' and indicatorType eq '<T>'``
  (active only), created with ``POST /api/indicators`` (200) and deleted with
  ``DELETE /api/indicators/{id}`` (204, 404 when unknown);
* errors use the Defender envelope ``{error: {code, message, target}}``.

Body keys are checked case-sensitively (a wrong case answers 400
``InvalidRequestBody``), as Microsoft documents. Ids are built at runtime.
"""

from __future__ import annotations

import itertools
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

import httpx

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.capability import CapabilitySpec
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult
from tests.fixtures.microsoft import FakeMicrosoft, defender_error, make_context

_EQ = re.compile(r"^(\w+) eq '((?:[^']|'')*)'$")
_STARTSWITH = re.compile(r"^startswith\((\w+),'((?:[^']|'')*)'\)$")
MACHINE_VERBS = {
    "isolate": ("Isolate", {"Comment"}, {"Comment", "IsolationType"}),
    "unisolate": ("Unisolate", {"Comment"}, {"Comment"}),
    "StopAndQuarantineFile": ("StopAndQuarantineFile", {"Comment", "Sha1"}, {"Comment", "Sha1"}),
    "collectInvestigationPackage": ("CollectInvestigationPackage", {"Comment"}, {"Comment"}),
}
INDICATOR_REQUIRED = {"indicatorValue", "indicatorType", "action", "title", "description"}
INDICATOR_KEYS = INDICATOR_REQUIRED | {"expirationTime", "severity", "generateAlert", "rbacGroupNames", "application",
                                       "recommendedActions", "educateUrl"}


def machine_id() -> str:
    """A Defender-shaped machine id (40 hex characters), random per call."""
    return (uuid.uuid4().hex + uuid.uuid4().hex)[:40]


def ts(delta: timedelta = timedelta()) -> str:
    """A Defender timestamp (7 fractional digits, ``Z``) relative to now."""
    return (datetime.now(UTC) + delta).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def parse_filter(text: str) -> List[Tuple[str, str, str]]:
    """``[(op, field, value)]`` of an ``and``-joined filter (``eq`` and ``startswith`` only)."""
    clauses: List[Tuple[str, str, str]] = []
    for part in text.split(" and "):
        eq = _EQ.match(part)
        starts = _STARTSWITH.match(part)
        if eq:
            clauses.append(("eq", eq.group(1), eq.group(2).replace("''", "'")))
        elif starts:
            clauses.append(("startswith", starts.group(1), starts.group(2).replace("''", "'")))
        else:
            raise ValueError(f"unsupported filter clause {part!r}")
    return clauses


def _matches(item: Mapping[str, Any], clauses: List[Tuple[str, str, str]]) -> bool:
    for op, name, value in clauses:
        field = str(item.get(name, ""))
        if op == "eq" and field.lower() != value.lower():
            return False
        if op == "startswith" and not field.lower().startswith(value.lower()):
            return False
    return True


class FakeDefender:
    """Machines, machine actions and indicators behind ``fake`` (see the module docstring).

    :meth:`fail` scripts a reply for the next matching requests before the
    state machine sees them.
    """

    def __init__(self, fake: Optional[FakeMicrosoft] = None) -> None:
        self.fake = fake or FakeMicrosoft()
        self.machines: List[Dict[str, Any]] = []
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.indicators: Dict[str, Dict[str, Any]] = {}
        self.no_machines_404 = True
        self._indicator_ids = itertools.count(1000)
        self._failures: List[Tuple[str, re.Pattern[str], Callable[[httpx.Request], httpx.Response], List[int]]] = []
        self.fake.route("GET", "defender", re.compile(r"/api/.*"), self._handle)
        for method in ("POST", "DELETE"):
            self.fake.route(method, "defender", re.compile(r"/api/.*"), self._handle)

    # -- state -------------------------------------------------------------

    def machine(self, name: str, *, health: str = "Active", mid: Optional[str] = None, **extra: Any) -> str:
        machine = {"id": mid or machine_id(), "computerDnsName": name, "healthStatus": health,
                   "osPlatform": "Windows11", "lastSeen": ts(-timedelta(hours=1)), **extra}
        self.machines.append(machine)
        return str(machine["id"])

    def action(
        self,
        machine: str,
        action_type: str,
        status: str = "Pending",
        *,
        comment: str = "someone else",
        age: timedelta = timedelta(minutes=5),
        cancellation_comment: Optional[str] = None,
    ) -> str:
        action_id = str(uuid.uuid4())
        self.actions[action_id] = {
            "id": action_id, "type": action_type, "status": status, "machineId": machine,
            "requestor": "analyst@contoso.example", "requestorComment": comment,
            "cancellationComment": cancellation_comment,
            "creationDateTimeUtc": ts(-age), "lastUpdateDateTimeUtc": ts(-age + timedelta(minutes=1)),
        }
        return action_id

    def set_status(self, action_id: str, status: str) -> None:
        self.actions[action_id]["status"] = status
        self.actions[action_id]["lastUpdateDateTimeUtc"] = ts()

    def indicator(self, value: str, indicator_type: str, action: str = "Block", *, description: str = "other team",
                  expires: timedelta = timedelta(days=10)) -> str:
        indicator_id = str(next(self._indicator_ids))
        self.indicators[indicator_id] = {
            "id": indicator_id, "indicatorValue": value, "indicatorType": indicator_type, "action": action,
            "title": "existing", "description": description, "expirationTime": ts(expires),
            "createdBySource": "User",
        }
        return indicator_id

    def fail(
        self,
        method: str,
        path: str,
        reply: Union[httpx.Response, Callable[[httpx.Request], httpx.Response]],
        *,
        times: int = 1,
    ) -> None:
        """Answer the next ``times`` matching requests with ``reply`` (a response, or a function of the request)."""
        answer = reply if callable(reply) else (lambda _r: reply)
        self._failures.append((method, re.compile(path), answer, [times]))

    # -- inspection ----------------------------------------------------------

    def writes(self) -> List[httpx.Request]:
        return self.fake.writes()

    @staticmethod
    def body(request: httpx.Request) -> Dict[str, Any]:
        return dict(json.loads(request.content))

    def posts(self, suffix: str) -> List[httpx.Request]:
        return [r for r in self.fake.writes() if r.method == "POST" and r.url.path.endswith(suffix)]

    # -- handler ---------------------------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for method, pattern, reply, left in self._failures:
            if left[0] > 0 and request.method == method and pattern.fullmatch(path):
                left[0] -= 1
                return reply(request)
        if request.method == "GET":
            return self._get(request, path)
        if request.method == "DELETE":
            match = re.fullmatch(r"/api/indicators/([^/]+)", path)
            if match and match.group(1) in self.indicators:
                del self.indicators[match.group(1)]
                return httpx.Response(204)
            return defender_error(404, "ResourceNotFound")
        return self._post(request, path)

    def _get(self, request: httpx.Request, path: str) -> httpx.Response:
        params = request.url.params
        clauses = parse_filter(params["$filter"]) if "$filter" in params else []
        top = int(params.get("$top", "10000"))
        if path == "/api/machines":
            if not self.machines and self.no_machines_404:
                return defender_error(404, "NotFound")
            found = [m for m in self.machines if _matches(m, clauses)][:top]
            return httpx.Response(200, json={"@odata.context": "machines", "value": found})
        if path == "/api/machineactions":
            found = [self._listed(a) for a in self.actions.values() if _matches(a, clauses)][:top]
            return httpx.Response(200, json={"@odata.context": "machineactions", "value": found})
        match = re.fullmatch(r"/api/machineactions/([^/]+)", path)
        if match:
            action = self.actions.get(match.group(1))
            return httpx.Response(200, json=action) if action else defender_error(404, "ResourceNotFound")
        if path == "/api/indicators":
            now = datetime.now(UTC)
            active = [i for i in self.indicators.values()
                      if datetime.fromisoformat(i["expirationTime"]) > now and _matches(i, clauses)][:top]
            return httpx.Response(200, json={"@odata.context": "indicators", "value": active})
        return defender_error(404, "ResourceNotFound")

    @staticmethod
    def _listed(action: Mapping[str, Any]) -> Dict[str, Any]:
        # The list documentation spells the update time lastUpdateTimeUtc.
        listed = dict(action)
        listed["lastUpdateTimeUtc"] = listed.pop("lastUpdateDateTimeUtc")
        return listed

    def _post(self, request: httpx.Request, path: str) -> httpx.Response:
        try:
            body = json.loads(request.content)
        except ValueError:
            return defender_error(400, "InvalidRequestBody")
        machine = re.fullmatch(r"/api/machines/([^/]+)/([A-Za-z]+)", path)
        if machine:
            return self._machine_action(machine.group(1), machine.group(2), body)
        cancel = re.fullmatch(r"/api/machineactions/([^/]+)/cancel", path)
        if cancel:
            action = self.actions.get(cancel.group(1))
            if action is None:
                return defender_error(404, "ResourceNotFound")
            if action["status"] not in ("Pending", "InProgress"):
                return defender_error(400, "BadRequest")
            action.update(status="Cancelled", cancellationComment=body.get("Comment"),
                          cancellationDateTimeUtc=ts(), lastUpdateDateTimeUtc=ts())
            return httpx.Response(200, json=action)
        if path == "/api/indicators":
            return self._indicator(body)
        return defender_error(404, "ResourceNotFound")

    def _machine_action(self, mid: str, verb: str, body: Mapping[str, Any]) -> httpx.Response:
        if verb not in MACHINE_VERBS:
            return defender_error(404, "ResourceNotFound")
        action_type, required, allowed = MACHINE_VERBS[verb]
        if not required <= set(body) or not set(body) <= allowed:
            return defender_error(400, "InvalidRequestBody")
        if not any(m["id"] == mid for m in self.machines):
            return defender_error(404, "ResourceNotFound")
        action_id = self.action(mid, action_type, "Pending", comment=str(body["Comment"]), age=timedelta())
        return httpx.Response(201, json=self.actions[action_id])

    def _indicator(self, body: Mapping[str, Any]) -> httpx.Response:
        if not INDICATOR_REQUIRED <= set(body) or not set(body) <= INDICATOR_KEYS:
            return defender_error(400, "InvalidRequestBody")
        indicator_id = str(next(self._indicator_ids))
        stored = {"id": indicator_id, **body, "createdBySource": "AadApp"}
        stored.setdefault("expirationTime", ts(timedelta(days=3650)))
        self.indicators[indicator_id] = stored
        return httpx.Response(200, json=stored)


# ----------------------------------------------------------------------------- running handlers


async def execute(defender: FakeDefender, spec: CapabilitySpec, action: ResponseAction,
                  **context: Any) -> Tuple[ConnectorResult, Dict[str, Any]]:
    """``spec``'s handler executes ``action`` against ``defender``: ``(result, checkpoint store)``."""
    ctx, store = make_context(defender.fake, spec, action=action, **context)
    return await spec.handler(ctx).execute(action), store


async def verify(defender: FakeDefender, spec: CapabilitySpec, action: ResponseAction,
                 **context: Any) -> VerificationResult:
    ctx, _ = make_context(defender.fake, spec, action=action, read_only=True, **context)
    return await spec.handler(ctx).verify(action)


async def rehearse(defender: FakeDefender, spec: CapabilitySpec, action: ResponseAction,
                   **context: Any) -> Dict[str, Any]:
    ctx, _ = make_context(defender.fake, spec, action=action, read_only=True, **context)
    return await spec.handler(ctx).rehearse(action)


def rerun(action: ResponseAction, store: Mapping[str, Any], **fields: Any) -> ResponseAction:
    """The same ledger row as a re-run sees it: ``external_ref`` holds what the interrupted run checkpointed."""
    return action.model_copy(update={"external_ref": dict(store), **fields})


def marker(action: ResponseAction) -> str:
    return f"LG-SOTF action {action.id}"
