"""First-run setup of an install: what the setup wizard saves and when it is done.

The wizard belongs to the platform admin that ``lg-sotf migrate`` created
(the bootstrap admin) and works on that admin's home tenant, the install's
first tenant. Its state lives in ``tenants.onboarding`` next to the
getting-started marks:

* ``organisation``: the organisation's display name;
* ``llm_profile``: the language-model profile the admin picked
  (:mod:`lg_sotf.onboarding.llm_profiles`; a record of intent, the running
  model stays install configuration);
* ``setup_completed_at``: set when the admin finishes or skips the wizard.

The tenant name is the ``tenants.name`` column. Each change is audited in the
same transaction (``onboarding.setup_saved``, ``onboarding.setup_completed``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import Repositories, Tenant
from lg_sotf.onboarding.progress import record_step

SETUP_MARK = "setup_completed_at"


@dataclass(frozen=True)
class SetupState:
    tenant_id: str
    tenant_name: str
    organisation: Optional[str]
    llm_profile: Optional[str]
    completed_at: Optional[str]

    @property
    def completed(self) -> bool:
        return self.completed_at is not None


def setup_state(tenant: Tenant) -> SetupState:
    marks = dict(tenant.onboarding or {})
    completed = marks.get(SETUP_MARK)
    return SetupState(
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        organisation=marks.get("organisation"),
        llm_profile=marks.get("llm_profile"),
        completed_at=str(completed) if completed else None,
    )


async def save_setup(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    organisation: str,
    tenant_name: str,
    llm_profile: Optional[str],
) -> SetupState:
    """Rename the tenant and store the organisation and model profile, audited, in one transaction."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        before = await repos.tenants.get(tenant_id, for_update=True, conn=conn)
        old = setup_state(before)
        if tenant_name != before.name:
            await repos.tenants.update_admin(tenant_id, name=tenant_name, conn=conn)
        after = await repos.tenants.set_onboarding_fields(
            tenant_id, {"organisation": organisation, "llm_profile": llm_profile}, conn=conn
        )
        new = setup_state(after)
        changes: Dict[str, Any] = {
            key: {"from": getattr(old, key), "to": getattr(new, key)}
            for key in ("organisation", "tenant_name", "llm_profile")
            if getattr(old, key) != getattr(new, key)
        }
        await audit.record(
            tenant_id,
            "onboarding.setup_saved",
            "tenant",
            tenant_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={"changes": changes},
            conn=conn,
        )
    return new


async def complete_setup(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, *, skipped: bool
) -> SetupState:
    """Mark the first-run setup done (kept as first set) and audit it."""
    await record_step(
        repos, audit, tenant_id, actor, "onboarding.setup_completed", mark=SETUP_MARK, details={"skipped": skipped}
    )
    return setup_state(await repos.tenants.get(tenant_id))


__all__ = ["SETUP_MARK", "SetupState", "complete_setup", "save_setup", "setup_state"]
