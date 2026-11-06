"""Audited account changes: users, MFA factors, API keys and the SSO role sync.

Each function runs one change and its audit entry in a single
``db.tenant_tx``: when the audit entry cannot be written the change rolls
back and the error propagates, so nothing is reported as done that the
audit log does not show. Validation, secret generation and hashing happen
before the call; the callers (``api.auth``, ``api.routers.identity``) map
the results to HTTP.
"""

from __future__ import annotations

from typing import AbstractSet, List, Literal, Optional, Sequence, Union
from uuid import UUID

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.repos import UNSET, ApiKey, Repositories, User, UserMfa
from lg_sotf.services.tenancy import ensure_capacity

# Why a change to another account is refused; nothing has changed when one is returned.
# * platform_admin_target: only a platform admin may modify or delete a platform-admin account
#   (otherwise a tenant admin could reset its password, sign in as it and act across tenants);
# * last_admin: the tenant must keep at least one active admin.
UserRefusal = Literal["platform_admin_target", "last_admin"]


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


async def update_user(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    user_id: UUID,
    *,
    by_platform_admin: bool,
    fields: AbstractSet[str],
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_platform_admin: Optional[bool] = None,
    password_hash: Optional[str] = UNSET,
) -> Union[User, UserRefusal]:
    """Change role, status, platform flag or password (``None``/``UNSET``: keep); audited ``user.updated``.

    A new password or a deactivation revokes the user's refresh tokens.
    Reactivating an account counts against ``max_users`` (``QuotaExceeded``).
    ``fields`` are the request's field names, recorded in the audit entry.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        current = await repos.users.get(tenant_id, user_id, conn=conn)
        if current.is_platform_admin and not by_platform_admin:
            return "platform_admin_target"
        demoting = (
            current.role == "admin"
            and current.is_active
            and ((role is not None and role != "admin") or is_active is False)
        )
        if demoting and await repos.users.count_active_admins(tenant_id, conn=conn) <= 1:
            return "last_admin"
        if is_active is True and not current.is_active:
            await ensure_capacity(repos, tenant_id, "max_users", conn=conn)
        user = await repos.users.update(
            tenant_id,
            user_id,
            role=role if role is not None else UNSET,
            is_active=is_active if is_active is not None else UNSET,
            is_platform_admin=is_platform_admin if is_platform_admin is not None else UNSET,
            password_hash=password_hash,
            conn=conn,
        )
        revoked = 0
        if password_hash is not UNSET or is_active is False:
            revoked = await repos.refresh_tokens.revoke_all_for_user(tenant_id, user_id, conn=conn)
        await audit.record(
            tenant_id,
            "user.updated",
            "user",
            str(user_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={
                "fields": sorted(fields - {"password"}) + (["password"] if "password" in fields else []),
                "role": user.role,
                "revoked_sessions": revoked,
            },
            conn=conn,
        )
    return user


async def reset_mfa(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    user_id: UUID,
    *,
    by_platform_admin: bool,
    actor_home_tenant_id: str,
) -> Optional[UserRefusal]:
    """Remove another user's MFA (lost device) and revoke their sessions; audited ``auth.mfa_reset``."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        current = await repos.users.get(tenant_id, user_id, conn=conn)
        if current.is_platform_admin and not by_platform_admin:
            return "platform_admin_target"
        state = await repos.user_mfa.get(tenant_id, user_id, conn=conn)
        await repos.user_mfa.delete(tenant_id, user_id, conn=conn)
        revoked = await repos.refresh_tokens.revoke_all_for_user(tenant_id, user_id, conn=conn)
        await audit.record(
            tenant_id,
            "auth.mfa_reset",
            "user",
            str(user_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={
                "was_enabled": state is not None and state.enabled,
                "revoked_sessions": revoked,
                "by_platform_admin": by_platform_admin,
                "actor_home_tenant_id": actor_home_tenant_id,
            },
            conn=conn,
        )
    return None


async def delete_user(
    repos: Repositories, audit: AuditLogger, tenant_id: str, actor: Actor, user_id: UUID, *, by_platform_admin: bool
) -> Optional[UserRefusal]:
    """Delete an account and its sessions; audited ``user.deleted`` with the email's domain only.

    ``Conflict`` (nothing changed) when review history still references the user.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        current = await repos.users.get(tenant_id, user_id, conn=conn)
        if current.is_platform_admin and not by_platform_admin:
            return "platform_admin_target"
        if (
            current.role == "admin"
            and current.is_active
            and await repos.users.count_active_admins(tenant_id, conn=conn) <= 1
        ):
            return "last_admin"
        await repos.refresh_tokens.revoke_all_for_user(tenant_id, user_id, conn=conn)
        await repos.users.delete(tenant_id, user_id, conn=conn)
        await audit.record(
            tenant_id,
            "user.deleted",
            "user",
            str(user_id),
            actor_type=actor.type,
            actor_id=actor.id,
            details={"email_domain": current.email.rpartition("@")[2]},
            conn=conn,
        )
    return None


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


async def provision_sso_user(
    repos: Repositories, audit: AuditLogger, tenant_id: str, *, email: str, subject: str, role: str
) -> User:
    """Just-in-time account for a verified SSO identity (no password, never a platform admin).

    Counts against ``max_users`` (``QuotaExceeded``). ``Conflict`` when the
    subject or email already has an account (a concurrent first sign-in won);
    ``ValueError`` when the email is not a valid address. Nothing changes in
    either case. Audited ``user.provisioned`` (actor ``system``/``oidc``) with
    the email's domain only.
    """
    async with repos.db.tenant_tx(tenant_id) as conn:
        await ensure_capacity(repos, tenant_id, "max_users", conn=conn)
        user = await repos.users.create(
            tenant_id,
            email,
            role,
            password_hash=None,
            is_platform_admin=False,
            oidc_subject=subject,
            conn=conn,
        )
        await audit.record(
            tenant_id,
            "user.provisioned",
            "user",
            str(user.id),
            actor_type="system",
            actor_id="oidc",
            details={"role": role, "via": "oidc_jit", "email_domain": user.email.rpartition("@")[2]},
            conn=conn,
        )
    return user
