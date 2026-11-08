"""Request and response bodies of delegated access: organisations, members and tenant grants."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import Field

from lg_sotf.api.schemas import In, Out, RoleStr
from lg_sotf.db.tenancy import TENANT_ID_PATTERN
from lg_sotf.models.vocabulary import Role

MAX_GRANT_DAYS = 365


class OrganisationIn(In):
    name: str = Field(min_length=1, max_length=200)


class OrganisationOut(Out):
    tenant_id: str = Field(description="The organisation's home tenant: its staff accounts and its audit chain.")
    name: str
    created_at: datetime


class MemberOut(Out):
    tenant_id: str
    user_id: UUID
    added_by: Optional[str] = None
    created_at: datetime


class GrantIn(In):
    organisation_id: str = Field(pattern=TENANT_ID_PATTERN, description="The organisation's home tenant id.")
    role: Role = Field(description="The role its staff get in this tenant (never above their own role).")
    reason: str = Field(min_length=1, max_length=500, description="Why, e.g. a contract or ticket reference.")
    expires_at: datetime = Field(description=f"In the future, at most {MAX_GRANT_DAYS} days ahead.")
    user_id: Optional[UUID] = Field(default=None, description="Grant one member of the organisation only.")
    allow_api_keys: bool = Field(
        default=False,
        description="Let the organisation's API keys (whose creator is a member) use this grant; "
        "never for a grant to one member.",
    )


class GrantOut(Out):
    id: UUID
    tenant_id: str = Field(description="The customer tenant the grant opens.")
    organisation_id: str
    user_id: Optional[UUID] = None
    role: RoleStr
    allow_api_keys: bool = False
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
