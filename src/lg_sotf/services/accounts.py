"""Audited account changes: users, MFA factors, API keys and the SSO role sync.

Each function runs one change and its audit entry in a single
``db.tenant_tx``: when the audit entry cannot be written the change rolls
back and the error propagates, so nothing is reported as done that the
audit log does not show. Validation, secret generation and hashing happen
before the call; the callers (``api.auth``, ``api.routers.identity``) map
the results to HTTP.
"""

from __future__ import annotations

from typing import List, Optional, Sequence
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import ApiKey, Repositories, User, UserMfa
from lg_sotf.services.tenancy import ensure_capacity


async def create_user(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    email: str,
    role: str,
    password_hash: Optional[str],
    is_platform_admin: bool,
    is_active: bool,
) -> User:
    """Create an account; an active one counts against ``max_users`` (``QuotaExceeded``). Audited ``user.created``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if is_active:
            await ensure_capacity(repos, tenant_id, "max_users", conn=conn)
        user = await repos.users.create(
            tenant_id,
            email,
            role,
            password_hash=password_hash,
            is_platform_admin=is_platform_admin,
            is_active=is_active,
            conn=conn,
        )
        await audit.record(
            tenant_id,
            "user.created",
            "user",
            str(user.id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={"role": user.role, "sso_only": password_hash is None},
            conn=conn,
        )
    return user


async def create_api_key(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    *,
    name: str,
    prefix: str,
    key_hash: str,
    scopes: Sequence[str],
    created_by: Optional[UUID],
    key_id: UUID,
) -> ApiKey:
    """Store a new API key (its hash only); audited ``api_key.created`` with the scopes and name."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        key = await repos.api_keys.create(
            tenant_id, name, prefix, key_hash, scopes, created_by=created_by, key_id=key_id, conn=conn
        )
        await audit.record(
            tenant_id,
            "api_key.created",
            "api_key",
            str(key.id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={"scopes": key.scopes, "name": key.name},
            conn=conn,
        )
    return key


async def revoke_api_key(repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, key_id: UUID) -> bool:
    """Revoke a key (audited ``api_key.revoked``); ``False`` when it is unknown or already revoked."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        if not await repos.api_keys.revoke(tenant_id, key_id, conn=conn):
            return False
        await audit.record(
            tenant_id,
            "api_key.revoked",
            "api_key",
            str(key_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={},
            conn=conn,
        )
    return True


async def activate_mfa(
    repos: Repositories,
    audit: AuditLogger,
    user: User,
    *,
    pending_ciphertext: str,
    step: int,
    recovery_code_hashes: List[str],
    actor_type: str,
    actor_id: str,
) -> Optional[UserMfa]:
    """Activate the pending secret (audited ``auth.mfa_enrolled``); ``None`` when the enrollment changed meanwhile."""
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        activated = await repos.user_mfa.activate(
            user.tenant_id,
            user.id,
            pending_ciphertext=pending_ciphertext,
            step=step,
            recovery_code_hashes=recovery_code_hashes,
            conn=conn,
        )
        if activated is None:
            return None
        await audit.record(
            user.tenant_id,
            "auth.mfa_enrolled",
            "user",
            str(user.id),
            actor_type=actor_type,
            actor_id=actor_id,
            details={"method": "totp", "recovery_codes": len(recovery_code_hashes)},
            conn=conn,
        )
    return activated


async def consume_recovery_code(repos: Repositories, audit: AuditLogger, user: User, code_hash: str) -> Optional[int]:
    """Use up a recovery code (audited ``auth.mfa_recovery_code_used``); the codes left, ``None`` when it is unknown."""
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        remaining = await repos.user_mfa.consume_recovery_code(user.tenant_id, user.id, code_hash, conn=conn)
        if remaining is None:
            return None
        await audit.record(
            user.tenant_id,
            "auth.mfa_recovery_code_used",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"recovery_codes_remaining": remaining},
            conn=conn,
        )
    return remaining


async def replace_recovery_codes(
    repos: Repositories, audit: AuditLogger, user: User, hashes: List[str]
) -> Optional[UserMfa]:
    """New recovery codes for an enabled factor (audited); ``None`` when MFA is not enabled."""
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        updated = await repos.user_mfa.replace_recovery_codes(user.tenant_id, user.id, hashes, conn=conn)
        if updated is None:
            return None
        await audit.record(
            user.tenant_id,
            "auth.mfa_recovery_codes_regenerated",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"recovery_codes": len(hashes)},
            conn=conn,
        )
    return updated


async def disable_mfa(repos: Repositories, audit: AuditLogger, user: User, *, required_by_policy: bool) -> None:
    """Remove the user's own factor (audited ``auth.mfa_disabled``).

    ``required_by_policy`` is computed by the caller before the transaction,
    so no policy read holds the transaction open.
    """
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        await repos.user_mfa.delete(user.tenant_id, user.id, conn=conn)
        await audit.record(
            user.tenant_id,
            "auth.mfa_disabled",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"required_by_policy": required_by_policy},
            conn=conn,
        )


async def sync_sso_role(repos: Repositories, audit: AuditLogger, user: User, role: str) -> User:
    """Set an SSO-provisioned account's stored role to the IdP's (audited ``user.role_synced``)."""
    async with repos.db.tenant_tx(user.tenant_id) as conn:
        updated = await repos.users.update(user.tenant_id, user.id, role=role, conn=conn)
        await audit.record(
            user.tenant_id,
            "user.role_synced",
            "user",
            str(user.id),
            actor_type="system",
            actor_id="oidc",
            details={"from": user.role, "to": role, "via": "oidc_role_map"},
            conn=conn,
        )
    return updated
