"""The authenticated caller of a request."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import FrozenSet, Literal, Optional
from uuid import UUID

from lg_sotf.audit.logger import Actor
from lg_sotf.models.vocabulary import ROLE_RANK, Role, Scope
from lg_sotf.models.vocabulary import ROLES as ROLES
from lg_sotf.models.vocabulary import SCOPES as SCOPES

PrincipalKind = Literal["user", "api_key"]
AuthMethod = Literal["password", "oidc", "api_key"]


def role_at_least(role: Optional[str], minimum: Role) -> bool:
    """Whether ``role`` ranks at least ``minimum``; an unknown or missing role never does."""
    return role is not None and ROLE_RANK.get(role, -1) >= ROLE_RANK[minimum]


@dataclass(frozen=True)
class Principal:
    """``{user_id | api_key_id, tenant_id, role, scopes, is_platform_admin}`` (contract section 10).

    ``tenant_id`` is the tenant the request acts on; it differs from
    ``home_tenant_id`` only when ``X-Tenant-ID`` was honoured: for a member
    of an MSSP organisation acting under a grant (``grant_id`` set, the
    grant's role, no platform powers), or for a platform admin.
    Users have a ``role``; API keys have ``scopes`` and no role. An OIDC
    identity without a provisioned local account has no ``user_id``.
    """

    kind: PrincipalKind
    tenant_id: str
    home_tenant_id: str
    auth_method: AuthMethod
    role: Optional[Role] = None
    scopes: FrozenSet[Scope] = field(default_factory=frozenset)
    user_id: Optional[UUID] = None
    api_key_id: Optional[UUID] = None
    email: Optional[str] = None
    subject: Optional[str] = None
    is_platform_admin: bool = False
    expires_at: Optional[datetime] = None
    token_id: Optional[str] = None
    grant_id: Optional[UUID] = None

    @property
    def is_user(self) -> bool:
        return self.kind == "user"

    @property
    def is_api_key(self) -> bool:
        return self.kind == "api_key"

    @property
    def overridden(self) -> bool:
        return self.tenant_id != self.home_tenant_id

    @property
    def delegated(self) -> bool:
        """Acting in another tenant under a grant to the caller's organisation."""
        return self.grant_id is not None

    @property
    def local_user_id(self) -> Optional[UUID]:
        """``user_id`` usable as a foreign key in ``tenant_id`` (``None`` under an override).

        A platform admin's account lives in the home tenant; referencing it from
        another tenant's rows would violate the tenant-scoped user foreign keys.
        The audit log records the actor and home tenant instead.
        """
        return None if self.overridden else self.user_id

    @property
    def id(self) -> str:
        """Stable identifier for rate limits and logs."""
        if self.api_key_id is not None:
            return f"key:{self.api_key_id}"
        if self.user_id is not None:
            return f"user:{self.user_id}"
        return f"oidc:{self.subject}"

    @property
    def actor_type(self) -> str:
        """``audit_log.actor_type`` for this principal."""
        return "api_key" if self.is_api_key else "user"

    @property
    def actor_id(self) -> str:
        if self.api_key_id is not None:
            return str(self.api_key_id)
        if self.user_id is not None:
            return str(self.user_id)
        return f"oidc:{self.subject}"

    @property
    def actor(self) -> Actor:
        """This principal as the actor of an audited change."""
        return Actor(self.actor_type, self.actor_id)

    def acting_on(self, tenant_id: str) -> Principal:
        return replace(self, tenant_id=tenant_id)

    def under_grant(self, tenant_id: str, grant_id: UUID, role: Role) -> Principal:
        """This principal acting in ``tenant_id`` through a grant: ``role`` and nothing more."""
        return replace(self, tenant_id=tenant_id, grant_id=grant_id, role=role, is_platform_admin=False)
