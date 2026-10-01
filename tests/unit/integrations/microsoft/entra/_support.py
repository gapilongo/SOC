"""A fake Microsoft Entra directory behind :class:`~tests.fixtures.microsoft.FakeMicrosoft` for the Entra tests.

:class:`Directory` answers the Graph v1.0 calls of the Entra package from
in-memory users, as the verified Microsoft behaviour describes it:

* ``GET /v1.0/users/{id | upn}`` and ``/v1.0/users('{upn}')``: the UPN
  only (a mail or proxy address is 404 ``Request_ResourceNotFound``), only
  the ``$select``-ed properties;
* ``GET /v1.0/users?$filter=`` with ``userPrincipalName eq``, ``mail eq`` and
  ``proxyAddresses/any(x:x eq ...)`` (anything else is 400
  ``Request_UnsupportedQuery``);
* ``PATCH /v1.0/users/{id}`` (``accountEnabled``, ``passwordProfile``; 204),
  ``POST .../revokeSignInSessions`` (200 ``{"value": true}``);
* the guard reads (``roleAssignments``, ``memberOf``, ``ownedObjects``);
* Identity Protection ``riskyUsers`` (read, ``confirmCompromised``,
  ``dismiss``; 204), optionally still ``isProcessing``.

:meth:`Directory.override` answers one call differently (an error, a
throttle) before the directory sees it. Object ids come from ``uuid4``;
nothing here is credential-shaped.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple, Union

import httpx

from tests.fixtures.microsoft import FakeMicrosoft, graph_error

Reply = Union[httpx.Response, Callable[[httpx.Request], httpx.Response]]

_LITERAL = r"'((?:[^']|'')*)'"
_EQ = re.compile(rf"^(userPrincipalName|mail|principalId) eq {_LITERAL}$")
_ANY = re.compile(rf"^proxyAddresses/any\((\w+):\1 eq {_LITERAL}\)$")
_USER = re.compile(r"^/v1\.0/users/([^/()]+)$")
_USER_KEY = re.compile(r"^/v1\.0/users\('((?:[^']|'')*)'\)$")
_USER_SUB = re.compile(r"^/v1\.0/users/([^/]+)/(memberOf|ownedObjects|revokeSignInSessions)$")
_RISKY = re.compile(r"^/v1\.0/identityProtection/riskyUsers(?:/([^/]+))?$")
GRAPH_TIME = "%Y-%m-%dT%H:%M:%SZ"


def graph_time(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(UTC).strftime(GRAPH_TIME) if value is not None else None


def role_group(assignable: Optional[bool] = True, *, with_flag: bool = True) -> Dict[str, Any]:
    group: Dict[str, Any] = {"@odata.type": "#microsoft.graph.group", "id": str(uuid.uuid4())}
    if with_flag:
        group["isAssignableToRole"] = assignable
    return group


def admin_unit(restricted: Optional[bool] = True) -> Dict[str, Any]:
    return {"@odata.type": "#microsoft.graph.administrativeUnit", "id": str(uuid.uuid4()),
            "isMemberManagementRestricted": restricted}


@dataclass
class FakeUser:
    upn: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mail: Optional[str] = None
    proxy_addresses: List[str] = field(default_factory=list)
    user_type: str = "Member"
    enabled: bool = True
    synced: bool = False
    sessions_valid_from: Optional[datetime] = field(default_factory=lambda: datetime.now(UTC) - timedelta(days=3))
    last_password_change: Optional[datetime] = field(
        default_factory=lambda: datetime.now(UTC) - timedelta(days=40)
    )
    force_change: bool = False
    role_assignments: int = 0
    member_of: List[Dict[str, Any]] = field(default_factory=list)
    owned: List[Dict[str, Any]] = field(default_factory=list)
    risk: Optional[Dict[str, Any]] = None

    def json(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "userPrincipalName": self.upn,
            "mail": self.mail,
            "userType": self.user_type,
            "accountEnabled": self.enabled,
            "onPremisesSyncEnabled": True if self.synced else None,
            "signInSessionsValidFromDateTime": graph_time(self.sessions_valid_from),
            "lastPasswordChangeDateTime": graph_time(self.last_password_change),
            "passwordProfile": {"password": None, "forceChangePasswordNextSignIn": self.force_change,
                                "forceChangePasswordNextSignInWithMfa": False},
            "displayName": self.upn.split("@")[0],
        }


@dataclass
class _Override:
    method: str
    pattern: Pattern[str]
    reply: Reply
    times: Optional[int]
    calls: int = 0


class Directory:
    """In-memory Entra users served on ``fake``'s Graph host (see the module docstring)."""

    def __init__(self, fake: FakeMicrosoft) -> None:
        self.fake = fake
        self.users: Dict[str, FakeUser] = {}
        self.overrides: List[_Override] = []
        self.password_bodies: List[Dict[str, Any]] = []
        # Identity Protection keeps processing a confirmation or dismissal until finish_risk_processing().
        self.risk_processing = False
        # The riskyUser read answers {"value": [...]} like the documentation's example.
        self.wrap_risk = False
        # revokeSignInSessions takes effect only after reveal_revocation() (Microsoft's documented lag).
        self.revocation_lag = False
        self._pending_revocations: List[str] = []
        for method in ("GET", "POST", "PATCH", "DELETE"):
            fake.route(method, "graph", re.compile(r"/v1\.0/.*"), self._handle)

    # -- scripting -------------------------------------------------------------

    def add(self, upn: str = "alice@contoso.example", **fields: Any) -> FakeUser:
        user = FakeUser(upn=upn, **fields)
        self.users[user.id] = user
        return user

    def override(self, method: str, path: Union[str, Pattern[str]], reply: Reply, *, times: Optional[int] = 1) -> None:
        """Answer ``method path`` (decoded path, a full match) with ``reply`` before the directory does."""
        pattern = path if isinstance(path, re.Pattern) else re.compile(re.escape(path))
        self.overrides.append(_Override(method.upper(), pattern, reply, times))

    def finish_risk_processing(self) -> None:
        for user in self.users.values():
            if user.risk and user.risk.get("isProcessing"):
                final = user.risk.pop("_final", {})
                user.risk.update(final, isProcessing=False)

    def reveal_revocation(self) -> None:
        for user_id in self._pending_revocations:
            self.users[user_id].sessions_valid_from = datetime.now(UTC)
        self._pending_revocations.clear()

    # -- inspection ------------------------------------------------------------

    def graph_writes(self) -> List[httpx.Request]:
        return [r for r in self.fake.writes() if r.url.host == self.fake.profile.graph_host]

    def patches(self) -> List[Dict[str, Any]]:
        return [json.loads(r.content) for r in self.graph_writes() if r.method == "PATCH"]

    # -- the fake --------------------------------------------------------------

    def _find(self, key: str) -> Optional[FakeUser]:
        lowered = key.lower()
        for user in self.users.values():
            if user.id == lowered or user.upn.lower() == lowered:
                return user
        return None

    @staticmethod
    def _select(data: Dict[str, Any], request: httpx.Request) -> Dict[str, Any]:
        select = request.url.params.get("$select")
        if not select:
            return {k: v for k, v in data.items() if k in ("id", "userPrincipalName", "mail", "displayName")}
        return {k: v for k, v in data.items() if k in select.split(",")}

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for override in self.overrides:
            if override.method == request.method and (override.times is None or override.calls < override.times):
                if override.pattern.fullmatch(path):
                    override.calls += 1
                    reply = override.reply
                    return reply(request) if callable(reply) else reply
        if path == "/v1.0/users":
            return self._list(request)
        if path == "/v1.0/roleManagement/directory/roleAssignments":
            return self._assignments(request)
        match = _RISKY.fullmatch(path)
        if match:
            return self._risky(request, match.group(1))
        match = _USER_SUB.fullmatch(path)
        if match:
            return self._user_sub(request, match.group(1), match.group(2))
        match = _USER.fullmatch(path) or _USER_KEY.fullmatch(path)
        if match:
            key = match.group(1).replace("''", "'")
            if key.startswith("$") and _USER.fullmatch(path):
                return graph_error(400, "Request_BadRequest")  # Graph needs the ('...') form for these
            return self._user(request, key)
        return graph_error(404, "Request_ResourceNotFound")

    def _user(self, request: httpx.Request, key: str) -> httpx.Response:
        user = self._find(key)
        if user is None:
            return graph_error(404, "Request_ResourceNotFound")
        if request.method == "GET":
            return httpx.Response(200, json=self._select(user.json(), request))
        if request.method == "PATCH":
            body = json.loads(request.content)
            if "accountEnabled" in body:
                user.enabled = bool(body["accountEnabled"])
            if "passwordProfile" in body:
                self.password_bodies.append(body)
                profile = body["passwordProfile"]
                if profile.get("password"):
                    user.last_password_change = datetime.now(UTC)
                user.force_change = bool(profile.get("forceChangePasswordNextSignIn"))
            return httpx.Response(204)
        return graph_error(405, "Request_BadRequest")

    def _user_sub(self, request: httpx.Request, key: str, what: str) -> httpx.Response:
        user = self._find(key)
        if user is None:
            return graph_error(404, "Request_ResourceNotFound")
        if what == "revokeSignInSessions" and request.method == "POST":
            if self.revocation_lag:
                self._pending_revocations.append(user.id)
            else:
                user.sessions_valid_from = datetime.now(UTC)
            return httpx.Response(200, json={"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean",
                                             "value": True})
        if request.method != "GET":
            return graph_error(405, "Request_BadRequest")
        items = user.member_of if what == "memberOf" else user.owned
        return httpx.Response(200, json={"value": list(items)})

    def _filter(self, expression: str) -> Tuple[Optional[str], str]:
        match = _EQ.fullmatch(expression)
        if match:
            return match.group(1), match.group(2).replace("''", "'")
        match = _ANY.fullmatch(expression)
        if match:
            return "proxyAddresses", match.group(2).replace("''", "'")
        return None, ""

    def _list(self, request: httpx.Request) -> httpx.Response:
        expression = request.url.params.get("$filter")
        users = list(self.users.values())
        if expression is not None:
            prop, value = self._filter(expression)
            if prop == "userPrincipalName":
                users = [u for u in users if u.upn.lower() == value.lower()]
            elif prop == "mail":
                users = [u for u in users if (u.mail or "").lower() == value.lower()]
            elif prop == "proxyAddresses":
                users = [u for u in users if value in u.proxy_addresses]
            else:
                return graph_error(400, "Request_UnsupportedQuery")
        top = int(request.url.params.get("$top", "100"))
        return httpx.Response(200, json={"value": [self._select(u.json(), request) for u in users[:top]]})

    def _assignments(self, request: httpx.Request) -> httpx.Response:
        expression = request.url.params.get("$filter")
        if expression is None:
            return httpx.Response(200, json={"value": []})
        prop, value = self._filter(expression)
        if prop != "principalId":
            return graph_error(400, "Request_UnsupportedQuery")
        user = self.users.get(value)
        count = user.role_assignments if user is not None else 0
        return httpx.Response(200, json={"value": [
            {"id": str(uuid.uuid4()), "roleDefinitionId": str(uuid.uuid4())} for _ in range(count)
        ]})

    def _risky(self, request: httpx.Request, key: Optional[str]) -> httpx.Response:
        if key is None:
            return httpx.Response(200, json={"value": []})
        if key in ("confirmCompromised", "dismiss") and request.method == "POST":
            for user_id in json.loads(request.content)["userIds"]:
                user = self.users.get(user_id)
                if user is None:
                    return graph_error(404, "Request_ResourceNotFound")
                final = (
                    {"riskState": "confirmedCompromised", "riskLevel": "high",
                     "riskDetail": "adminConfirmedUserCompromised"}
                    if key == "confirmCompromised"
                    else {"riskState": "dismissed", "riskLevel": "none", "riskDetail": "adminDismissedAllRiskForUser"}
                )
                risk = user.risk or {"id": user.id, "riskState": "none", "riskLevel": "none", "riskDetail": "none"}
                if self.risk_processing:
                    risk = {**risk, "isProcessing": True, "_final": final}
                else:
                    risk = {**risk, **final, "isProcessing": False}
                user.risk = {**risk, "id": user.id, "userPrincipalName": user.upn, "isDeleted": False}
            return httpx.Response(204)
        if request.method != "GET":
            return graph_error(405, "Request_BadRequest")
        user = self.users.get(key)
        if user is None or user.risk is None:
            return graph_error(404, "Request_ResourceNotFound")
        body = {k: v for k, v in user.risk.items() if not k.startswith("_")}
        return httpx.Response(200, json={"value": [body]} if self.wrap_risk else body)


def requests_summary(fake: FakeMicrosoft) -> List[str]:
    """``METHOD path`` of every API request (token requests left out), for order assertions."""
    return [f"{r.method} {r.url.path}" for r in fake.api_requests()]


def guard_paths(user: FakeUser) -> List[str]:
    return [
        "GET /v1.0/roleManagement/directory/roleAssignments",
        f"GET /v1.0/users/{user.id}/memberOf",
        f"GET /v1.0/users/{user.id}/ownedObjects",
    ]
