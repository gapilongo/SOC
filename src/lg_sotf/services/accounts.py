"""Audited account changes: MFA factors, API keys and the SSO role sync.

Each function runs one change and its audit entry in a single
``db.tenant_tx``: when the audit entry cannot be written the change rolls
back and the error propagates, so nothing is reported as done that the
audit log does not show. Validation, secret generation and hashing happen
before the call; the callers (``api.auth``, ``api.routers.identity``) map
the results to HTTP.
"""

from __future__ import annotations

from typing import List, Optional

from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.repos import Repositories, User, UserMfa


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
