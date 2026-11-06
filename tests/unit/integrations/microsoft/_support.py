"""Fake capabilities for the framework tests (the real mail, Entra and Defender packages are never used here).

``defender.fake_isolation`` isolates a machine through Defender-shaped
endpoints of :class:`~tests.fixtures.microsoft.FakeMicrosoft` and verifies
through the machine action (pending until the fake says ``Succeeded``).
``entra.fake_account`` disables and re-enables a user with one Graph PATCH
and proves it inline (``verified``). Both follow the handler rules:
read before write, checkpoint before the non-idempotent write, the action
marker on what they create, targets only through ``odata``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, List, Literal, Optional

import httpx
from pydantic import Field

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.db.repos.integrations import Integration
from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.config import encrypt_secret, validate_config
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.auth import TokenProvider
from lg_sotf.integrations.microsoft.capability import (
    ActionSupport,
    CapabilityOptions,
    CapabilitySpec,
    HandlerContext,
    NoOptions,
    Permission,
    ProbeCheck,
    ProtectedLookup,
    nothing_protected,
)
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS, GLOBAL_ONLY, Cloud
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.connectors.microsoft import MicrosoftConnector, build_microsoft_connector
from lg_sotf.settings import Settings
from tests.fixtures.microsoft import FakeMicrosoft, fake_config, ms_settings

MACHINE_ID = "m" * 40
OPERATION_ID = "op-" + "1" * 8
USER_ID = str(uuid.uuid4())


class IsolationOptions(CapabilityOptions):
    mode: Literal["normal", "strict"] = "normal"
    limit: int = Field(default=5, ge=1, le=10)
    note: str = Field(default="", max_length=20)
    tags: List[str] = Field(default_factory=list, max_length=3)

    def problems(self, cloud: Cloud) -> List[str]:
        return ["strict mode needs a note"] if self.mode == "strict" and not self.note else []


class IsolationHandler:
    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    async def _machine(self, host: str) -> Dict[str, Any]:
        name = odata.hostname(host)
        machines = await self.ctx.api("defender").pages(
            "/api/machines", params={"$filter": odata.odata_eq("computerDnsName", name)}, max_items=2,
            deadline=self.ctx.deadline,
        )
        if len(machines) != 1:
            raise odata.InvalidTarget("invalid_target", f"{len(machines)} machines named {name}")
        return machines[0]

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        machine = await self._machine(action.target)
        return {"machine_id": machine["id"], "summary": f"would isolate {machine['id']}"}

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        api = self.ctx.api("defender")
        if action.action_type == "release_host":
            original = self.ctx.original
            machine_id = str((original.external_ref or {}).get("machine_id")) if original else ""
            response = await api.request(
                "POST", f"/api/machines/{odata.segment(machine_id)}/unisolate", json={"Comment": self.ctx.marker},
                deadline=self.ctx.deadline,
            )
            return ConnectorResult(
                "succeeded", {"summary": "released", "changed": True},
                external_ref={"machine_id": machine_id, "operation_id": response.body["id"]},
                verify=VerifyPlan(state="verified", detail={"released": True}),
            )
        machine = await self._machine(action.target)
        if machine.get("isolated"):
            return ConnectorResult("succeeded", {"summary": "already isolated", "changed": False, "already": True},
                                   external_ref={"machine_id": machine["id"]})
        ref = action.external_ref or {}
        if ref.get("operation_id"):
            operation_id = str(ref["operation_id"])  # adopt the pending operation of an interrupted run
        else:
            await self.ctx.checkpoint({"machine_id": machine["id"], "step": "isolating"})
            response = await api.request(
                "POST", f"/api/machines/{odata.segment(machine['id'])}/isolate",
                json={"Comment": self.ctx.marker, "IsolationType": "Full"}, deadline=self.ctx.deadline,
            )
            operation_id = str(response.body["id"])
            await self.ctx.checkpoint({"operation_id": operation_id})
        return ConnectorResult(
            "succeeded", {"summary": f"isolation requested ({operation_id})", "changed": True},
            external_ref={"machine_id": machine["id"], "operation_id": operation_id, "reversible": True},
            verify=VerifyPlan(state="pending", first_check_s=5, max_duration_s=600, detail={"operation_id": operation_id}),
        )

    async def verify(self, action: ResponseAction) -> VerificationResult:
        operation_id = str((action.external_ref or {}).get("operation_id") or "")
        response = await self.ctx.api("defender").request(
            "GET", f"/api/machineactions/{odata.segment(operation_id)}", deadline=self.ctx.deadline
        )
        status = response.body.get("status")
        if status == "Succeeded":
            return VerificationResult("verified", {"status": status})
        if status in ("Failed", "TimeOut", "Cancelled"):
            return VerificationResult("failed", {"status": status, "reason": "machine_action_" + status.lower()})
        return VerificationResult("pending", {"status": status}, retry_after_s=10)

    async def probe(self) -> List[ProbeCheck]:
        await self.ctx.api("defender").request("GET", "/api/machines", params={"$top": "1"}, deadline=self.ctx.deadline)
        return [ProbeCheck("list machines", "ok", permission="Machine.Read.All")]


class AccountHandler:
    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        user = await self.ctx.api("graph").request(
            "GET", odata.user_path(action.target), params={"$select": "id,accountEnabled"}, deadline=self.ctx.deadline
        )
        return {"user_id": user.body["id"], "account_enabled": user.body["accountEnabled"]}

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        enable = action.action_type == "enable_user"
        path = odata.user_path(action.target)
        api = self.ctx.api("graph")
        user = await api.request("GET", path, params={"$select": "id,accountEnabled"}, deadline=self.ctx.deadline)
        if user.body["accountEnabled"] is enable:
            return ConnectorResult("succeeded", {"summary": "already in state", "changed": False, "already": True})
        await api.request("PATCH", path, json={"accountEnabled": enable}, idempotent=True, deadline=self.ctx.deadline)
        return ConnectorResult(
            "succeeded", {"summary": "enabled" if enable else "disabled", "changed": True},
            external_ref={"user_id": user.body["id"]},
            verify=VerifyPlan(state="verified", detail={"accountEnabled": enable}),
        )

    async def verify(self, action: ResponseAction) -> VerificationResult:
        user = await self.ctx.api("graph").request(
            "GET", odata.user_path(action.target), params={"$select": "accountEnabled"}, deadline=self.ctx.deadline
        )
        wanted = action.action_type == "enable_user"
        return VerificationResult("verified" if user.body["accountEnabled"] is wanted else "failed", {})

    async def probe(self) -> List[ProbeCheck]:
        return []


ISOLATION = CapabilitySpec(
    key="defender.fake_isolation",
    package="defender",
    api="defender",
    title="Fake isolation",
    description="Isolates machines (test double).",
    actions={"isolate_host": ActionSupport(reversible=True, rollback_window_s=86_400), "release_host": ActionSupport()},
    permissions=(
        Permission("defender", "Machine.Isolate", "isolate machines"),
        Permission("defender", "Machine.Read.All", "find machines"),
        Permission("graph", "User.Read.All", "strict lookups", required=True, when="mode=strict"),
    ),
    options=IsolationOptions,
    handler=IsolationHandler,
    clouds=GLOBAL_ONLY,
    licence="Defender for Endpoint P1",
    live_confirmation="Isolated machines lose network access.",
)

ACCOUNT = CapabilitySpec(
    key="entra.fake_account",
    package="entra",
    api="graph",
    title="Fake account",
    description="Disables and enables users (test double).",
    actions={"disable_user": ActionSupport(reversible=True), "enable_user": ActionSupport()},
    permissions=(
        Permission("graph", "User.EnableDisableAccount.All", "disable users", directory_role="User Administrator"),
        Permission("graph", "User.Read.All", "read users", exchange_rbac="Application Mail.Read"),
    ),
    options=NoOptions,
    handler=AccountHandler,
    clouds=ALL_CLOUDS,
)

FAKE_SPECS = (ISOLATION, ACCOUNT)


def script_isolation(fake: FakeMicrosoft, *, isolated: bool = False, action_status: str = "Succeeded") -> None:
    """Defender routes for one machine ``ws-042`` and its isolation."""
    machine = {"id": MACHINE_ID, "computerDnsName": "ws-042", "isolated": isolated}
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": [machine]}))
    fake.route("POST", "defender", f"/api/machines/{MACHINE_ID}/isolate",
               httpx.Response(201, json={"id": OPERATION_ID, "status": "Pending"}))
    fake.route("POST", "defender", f"/api/machines/{MACHINE_ID}/unisolate",
               httpx.Response(201, json={"id": "op-release", "status": "Pending"}))
    fake.route("GET", "defender", f"/api/machineactions/{OPERATION_ID}",
               httpx.Response(200, json={"id": OPERATION_ID, "status": action_status}))


def script_account(fake: FakeMicrosoft, upn: str = "alice@contoso.example", *, enabled: bool = True) -> None:
    fake.route("GET", "graph", f"/v1.0/users/{odata.segment(upn)}",
               httpx.Response(200, json={"id": USER_ID, "accountEnabled": enabled}))
    fake.route("PATCH", "graph", f"/v1.0/users/{odata.segment(upn)}", httpx.Response(204))


# ----------------------------------------------------------------------------- connector harness


class FakeCheckpoints:
    """The part of ActionsRepo the connector uses: checkpoints and the original of a rollback."""

    def __init__(self) -> None:
        self.patches: List[Dict[str, Any]] = []
        self.rows: Dict[Any, ResponseAction] = {}
        self.executing = True

    async def checkpoint(self, tenant_id: str, action_id: Any, patch: Any, **_: Any) -> bool:
        if not self.executing:
            return False
        self.patches.append(dict(patch))
        return True

    async def get(self, tenant_id: str, action_id: Any, **_: Any) -> ResponseAction:
        return self.rows[action_id]


def microsoft_integration(
    config: Dict[str, Any], ciphertext: str, *, tenant_id: str = "tenant-a", enabled: bool = True,
    integration_id: Optional[uuid.UUID] = None,
) -> Integration:
    now = datetime.now(UTC)
    return Integration.model_validate({
        "id": integration_id or uuid.uuid4(), "tenant_id": tenant_id, "kind": "microsoft", "name": "Microsoft",
        "enabled": enabled, "config": config, "secret_ciphertext": ciphertext, "events": [], "min_severity": "low",
        "created_by": None, "created_at": now, "updated_at": now,
    })


@dataclass
class ConnectorHarness:
    connector: MicrosoftConnector
    checkpoints: FakeCheckpoints
    secret: Dict[str, Any]
    integration: Integration
    box: SecretBox


def build_connector(
    fake: FakeMicrosoft,
    capabilities: Dict[str, Dict[str, Any]],
    *,
    settings: Optional[Settings] = None,
    credential: str = "client_secret",
    tenant_id: str = "tenant-a",
    enabled: bool = True,
    protected: Optional[ProtectedLookup] = nothing_protected,
) -> ConnectorHarness:
    """A MicrosoftConnector for ``fake`` with the given capability config (call inside ``override_for_tests``)."""
    settings = settings or ms_settings()

    async def no_sleep(_: float) -> None:
        return None

    config, secret = fake_config(credential=credential, capabilities=capabilities, cloud=fake.cloud)
    if fake.geo:
        config["defender_geo"] = fake.geo
    config = validate_config("microsoft", config, require_https=True)
    box = SecretBox.from_settings(settings)
    integration_id = uuid.uuid4()
    ciphertext = encrypt_secret(box, tenant_id, integration_id, secret)
    assert ciphertext is not None
    integration = microsoft_integration(config, ciphertext, tenant_id=tenant_id, enabled=enabled,
                                        integration_id=integration_id)
    http = MicrosoftHttpFactory(settings, transport=fake.transport(), resolver=fake.resolver(), sleep=no_sleep)
    checkpoints = FakeCheckpoints()
    connector = build_microsoft_connector(
        None, settings, box, integration, tokens=TokenProvider(http), http=http,
        checkpoints=checkpoints,  # type: ignore[arg-type]
        protected=protected,
    )
    return ConnectorHarness(connector, checkpoints, secret, integration, box)
