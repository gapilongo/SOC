"""Helpers for the Microsoft integration tests: real Postgres (ledger, audit, outbox), a fake Microsoft behind httpx.MockTransport.

``microsoft_env`` builds a tenant with dry run off and one Microsoft
integration with the given capabilities, and wires the response service,
the background executor and the verification service to a
:class:`~tests.fixtures.microsoft.FakeMicrosoft`::

    async def test_flow(microsoft_env):
        env = await microsoft_env({"entra.account": {"options": {...}}})   # live=True by default
        env.fake.route(...)
        action = await env.propose("disable_user", "alice@contoso.example")
        statuses = await env.service.execute(env.tenant_id, action.alert_id, [str(action.id)])
        await env.run_background()
        await env.make_verifications_due()
        await env.run_verify()

The capability keys must exist in the active catalog: connector packages
use their real capabilities, the framework's tests wrap the catalog with
``override_for_tests`` and a fake capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from lg_sotf.db.repos import Integration, Repositories, ResponseAction
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.background import BackgroundExecutor
from lg_sotf.services.response import ACTION_CATALOG, ResponseService
from lg_sotf.services.verification import VerificationService
from lg_sotf.settings import Settings
from tests.fixtures.microsoft import FakeMicrosoft
from tests.integration.db._support import make_alert
from tests.unit.services.fakes import FakeEvents

DEFAULT_TENANT_SETTINGS: Dict[str, Any] = {
    "response": {"dry_run": False},
    "autonomy": {"low": "approval", "medium": "approval", "high": "approval", "critical": "approval"},
}


@dataclass
class MicrosoftEnv:
    service: ResponseService
    fake: FakeMicrosoft
    tenant_id: str
    repos: Repositories
    settings: Settings
    integration: Integration
    box: SecretBox
    secret: Dict[str, Any]
    events: FakeEvents
    alert_id: Optional[str] = None
    background: BackgroundExecutor = field(init=False)
    verification: VerificationService = field(init=False)

    def __post_init__(self) -> None:
        self.background = BackgroundExecutor(self.service)
        self.verification = VerificationService(self.service, rand=lambda: 0.5)

    async def alert(self, **kwargs: Any) -> str:
        """The environment's alert (created once), with a live workflow run."""
        if self.alert_id is None:
            self.alert_id = await make_alert(self.repos, self.tenant_id, **kwargs)
            await self.repos.runs.upsert_queued(self.tenant_id, self.alert_id)
        return self.alert_id

    async def propose(
        self,
        action_type: str,
        target: str,
        *,
        status: str = "approved",
        alert_id: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> ResponseAction:
        """A ledger row of the environment's alert (``approved`` by default, as after an approval)."""
        alert = alert_id or await self.alert()
        action, _ = await self.repos.actions.propose(
            self.tenant_id, alert, action_type, target, ACTION_CATALOG[action_type].risk, params=params,
            status=status, requested_by="test", **kwargs,
        )
        return action

    async def execute(self, action: ResponseAction) -> str:
        """Run one workflow row as the ``execute_actions`` node would."""
        statuses = await self.service.execute(self.tenant_id, action.alert_id, [str(action.id)])
        return statuses.get(str(action.id), "")

    async def run_background(self, *, limit: int = 20) -> int:
        return await self.background.run_once(limit=limit)

    async def run_verify(self, *, limit: int = 100) -> int:
        return await self.verification.run_due(limit=limit)

    async def make_verifications_due(self) -> None:
        async with self.repos.db.system_tx() as conn:
            await conn.execute(
                "UPDATE response_actions SET verify_after = now() - interval '1 second' "
                "WHERE tenant_id = $1 AND verification = 'pending'",
                self.tenant_id,
            )

    async def expire_leases(self) -> None:
        """Make leased scheduler rows due now (as if their lease or deferral had ended)."""
        async with self.repos.db.system_tx() as conn:
            await conn.execute(
                "UPDATE response_actions SET lease_until = now() - interval '1 second' "
                "WHERE tenant_id = $1 AND lease_until IS NOT NULL",
                self.tenant_id,
            )

    async def get(self, action: ResponseAction) -> ResponseAction:
        return await self.repos.actions.get(self.tenant_id, action.id)


MicrosoftEnvFactory = Callable[..., Awaitable[MicrosoftEnv]]
