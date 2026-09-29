"""FastAPI dependencies for authentication, role/scope checks and per-principal rate limits.

Access rules (contract section 10):

* users need at least the endpoint's role (``viewer`` < ``analyst`` <
  ``admin``);
* API keys need the endpoint's scope; endpoints without a scope (user,
  API key, source, settings administration, reprocessing) refuse API keys;
* endpoints whose effect is attributed to a person (claiming and deciding
  escalations, approving actions) also need a provisioned user account, and
  refuse a platform admin acting on another tenant via ``X-Tenant-ID`` (the
  decision must be made by a member of that tenant);
* platform endpoints (tenant provisioning) need an admin user with the
  platform-admin flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Depends, Request

from lg_sotf.api.auth.authenticate import authenticate, forbidden
from lg_sotf.api.auth.principal import Principal, role_at_least
from lg_sotf.api.context import ApiContext, get_ctx

INGEST_BUCKET = "ingest"
API_BUCKET = "api"


@dataclass(frozen=True)
class Access:
    role: Optional[str] = None
    scope: Optional[str] = None
    api_key_only: bool = False
    user_account: bool = False
    any_api_key: bool = False
    home_tenant_only: bool = False
    platform_admin: bool = False
    bucket: str = API_BUCKET

    def check(self, principal: Principal) -> None:
        if principal.is_api_key:
            if self.any_api_key:
                return
            if self.scope is None:
                raise forbidden("API keys cannot use this endpoint")
            if self.scope not in principal.scopes:
                raise forbidden(f"API key lacks the '{self.scope}' scope")
            return
        if self.api_key_only:
            raise forbidden("this endpoint requires an API key")
        if self.role is not None and not role_at_least(principal.role, self.role):
            raise forbidden(f"requires the {self.role} role")
        if self.user_account and principal.user_id is None:
            raise forbidden("this action requires a provisioned user account")
        if self.platform_admin and not principal.is_platform_admin:
            raise forbidden("requires a platform admin")
        if self.home_tenant_only and principal.overridden:
            raise forbidden("this action cannot be performed with an X-Tenant-ID override")


def _limit(ctx: ApiContext, bucket: str) -> int:
    api = ctx.settings.api
    return api.ingest_rate_limit_per_minute if bucket == INGEST_BUCKET else api.rate_limit_per_minute


def require(access: Access) -> Callable[..., object]:
    async def dependency(request: Request) -> Principal:
        ctx = get_ctx(request)
        principal = await authenticate(ctx, request)
        access.check(principal)
        await ctx.limiter.enforce(
            access.bucket, principal.id, _limit(ctx, access.bucket), tenant_id=principal.home_tenant_id
        )
        return principal

    return dependency


def principal_dep(access: Access) -> object:
    return Depends(require(access))


VIEWER = Access(role="viewer", scope="read")
ANALYST = Access(role="analyst", scope="write")
REVIEWER = Access(role="analyst", user_account=True, home_tenant_only=True)
ADMIN = Access(role="admin")
ADMIN_USER = Access(role="admin", user_account=True)
ANY = Access(role="viewer", any_api_key=True)
PLATFORM_ADMIN = Access(role="admin", platform_admin=True)
INGEST = Access(scope="ingest", api_key_only=True, bucket=INGEST_BUCKET)
