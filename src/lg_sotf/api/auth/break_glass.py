"""Break-glass sign-in: a short platform-admin session from the install's sealed credential.

For the emergency in which nobody can sign in the normal way (the identity
provider is down or misconfigured, every platform admin lost a factor);
``docs/runbooks/break-glass.md`` is the procedure.

* Off unless the operator set ``auth.break_glass_credential_hash`` (the
  argon2id hash of the sealed credential) and the alert can be mailed
  (``Settings.break_glass_enabled``). No API call and no tenant setting
  turns it on; while it is off the route is not mounted at all
  (:func:`lg_sotf.api.app.create_app`).
* The caller presents the credential, a reason and the email of an active
  platform-admin account. The session is that account's, without its
  password or MFA: an access token of ``auth.break_glass_ttl_s`` seconds and
  no refresh token, so it ends on its own and cannot be extended. The token
  says ``auth_method: break_glass``: no MSSP grant is honoured for it, and
  every audit entry of the session carries that method.
* Before the token is returned, the use is audited and an alert to every
  platform admin is queued, in one transaction
  (:func:`lg_sotf.services.break_glass.record_use`). If that fails, so does
  the sign-in.
* A wrong credential or account gets the same 401 after the same argon2
  work. The caller's ``email`` is never stored as sent (a credential pasted
  into the wrong field must not reach the append-only log): a wrong
  credential is audited only when it names a real platform admin, in that
  account's tenant, as a failed login is; an unknown account is only logged,
  with a short hash of the name. The right credential with a wrong account
  is audited with that hash in the bootstrap tenant's log.
"""

from __future__ import annotations

from typing import Optional, Tuple

from lg_sotf.api.auth.service import invalid_credentials
from lg_sotf.api.auth.tokens import IssuedToken
from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.repos import User
from lg_sotf.observability.logging import get_logger
from lg_sotf.security.hashing import averify_password, sha256_hex
from lg_sotf.services.break_glass import BREAK_GLASS_FAILED, record_use

log = get_logger(__name__)


async def _platform_admin(ctx: ApiContext, email: str, tenant_id: Optional[str]) -> Optional[User]:
    """The one active platform-admin account with this email (in ``tenant_id`` when given), else ``None``."""
    wanted = email.strip().lower()
    admins = await ctx.repos.users.platform_admins_all_tenants()
    matches = [a for a in admins if a.email == wanted and tenant_id in (None, a.tenant_id)]
    if len(matches) != 1:
        return None
    return await ctx.repos.users.get(matches[0].tenant_id, matches[0].id)


async def _audit_failure(ctx: ApiContext, user: Optional[User], verified: bool, email: str, client_ip: str) -> None:
    """Record a refused attempt (see the module docstring for what is written where)."""
    reason = "unknown_account" if verified else "bad_credential"
    hint = sha256_hex(email.strip().lower())[:16]
    log.warning("auth.break_glass_failed", reason=reason, client_ip=client_ip, account_sha256=hint)
    audit = AuditLogger(ctx.repos)
    details = {"reason": reason, "client_ip": client_ip}
    if user is not None:
        await audit.record_event(
            user.tenant_id, BREAK_GLASS_FAILED, "user", str(user.id), actor_type="user", actor_id=str(user.id),
            details=details,
        )
    elif verified:
        home = ctx.settings.auth.bootstrap_tenant_id
        if await ctx.tenants.get(home) is not None:
            await audit.record_event(
                home, BREAK_GLASS_FAILED, "tenant", home, details={**details, "account_sha256": hint}
            )


async def break_glass_sign_in(
    ctx: ApiContext, *, email: str, tenant_id: Optional[str], credential: str, reason: str, client_ip: str
) -> Tuple[User, IssuedToken]:
    """The platform-admin account and its short access token; the use is already audited and its alerts queued."""
    stored = ctx.settings.auth.break_glass_credential_hash
    if stored is None or not ctx.settings.break_glass_enabled:
        raise ApiError(404, "not_found", "Not Found")
    verified = await averify_password(stored.get_secret_value(), credential)
    user = await _platform_admin(ctx, email, tenant_id)
    if user is None or not verified:
        await _audit_failure(ctx, user, verified, email, client_ip)
        raise invalid_credentials()
    token = ctx.tokens.issue_access(user, break_glass=True)
    notified = await record_use(
        ctx.repos, user, reason=reason, client_ip=client_ip, token_id=token.jti, expires_at=token.expires_at
    )
    log.warning("auth.break_glass_used", tenant_id=user.tenant_id, client_ip=client_ip, admins_notified=notified)
    return user, token
