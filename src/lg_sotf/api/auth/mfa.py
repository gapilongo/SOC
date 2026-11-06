"""TOTP multi-factor authentication for local accounts.

* **Secrets** are encrypted with the install's ``SecretBox`` under a context
  bound to the tenant and user (``mfa:<tenant>:<user>``), so a ciphertext
  copied onto another account does not decrypt. They leave the server only
  once, in the enrollment response. After an encryption-key rotation a
  secret is re-encrypted under the new primary key on its next use.
* **Enrollment** stores a *pending* secret; it becomes active only when a
  code generated from it is confirmed. Confirmation returns ten recovery
  codes once; only their keyed hashes are stored
  (:func:`lg_sotf.security.totp.hash_recovery_code`, key derived from
  ``security.indicator_hmac_key``).
* **Codes are single-use**: the matched time step must be newer than the last
  one used (atomic in the database), recovery codes are removed when used.
* **Policy**: MFA is required for a local account when the tenant setting
  ``security.require_mfa`` is on, or when the account is a platform admin and
  ``auth.require_mfa_for_platform_admins`` applies (default: staging and
  production). A required account without MFA can sign in only as far as
  enrollment.
* Every enrollment, disable, reset, recovery-code use and failed verification
  is written to the tenant's audit log.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, List, Literal, Mapping, Optional

from lg_sotf.api.context import ApiContext
from lg_sotf.api.errors import ApiError
from lg_sotf.audit.logger import AuditLogger
from lg_sotf.db.repos import User, UserMfa
from lg_sotf.observability.logging import get_logger
from lg_sotf.security import qr, totp
from lg_sotf.security.crypto import DecryptionError, SecretBox
from lg_sotf.security.hashing import SecurityConfigError, indicator_hmac_key

log = get_logger(__name__)

#: A pending (unconfirmed) secret is usable for this long.
PENDING_TTL_S = 15 * 60
MAX_CODE_CHARS = 32

CodeMethod = Literal["totp", "recovery_code"]

#: Wall clock for TOTP time steps (replaceable in tests).
clock: Callable[[], float] = time.time


def secret_context(tenant_id: str, user_id: object) -> str:
    return f"mfa:{tenant_id}:{user_id}"


def invalid_code(status: int = 401) -> ApiError:
    """401 while signing in; 400 on authenticated endpoints (a 401 there would read as an ended session)."""
    return ApiError(status, "invalid_mfa_code", "the verification code is not valid")


def mfa_unavailable(reason: str) -> ApiError:
    return ApiError(503, "mfa_unavailable", reason)


def tenant_requires_mfa(settings: Optional[Mapping[str, object]]) -> bool:
    security = (settings or {}).get("security")
    return isinstance(security, Mapping) and security.get("require_mfa") is True


@dataclass(frozen=True)
class Enrollment:
    secret: str
    otpauth_uri: str
    qr: Optional[List[str]]

    def __repr__(self) -> str:
        return "Enrollment(secret=***)"


@dataclass(frozen=True)
class CodeCheck:
    method: CodeMethod
    recovery_codes_remaining: Optional[int] = None


class MfaService:
    def __init__(self, ctx: ApiContext) -> None:
        self._ctx = ctx
        self._audit = AuditLogger(ctx.repos)

    # ------------------------------------------------------------------ policy

    async def state(self, user: User) -> Optional[UserMfa]:
        return await self._ctx.repos.user_mfa.get(user.tenant_id, user.id)

    async def required_for(self, user: User) -> bool:
        """Whether policy requires ``user`` (a local account) to use MFA."""
        if user.is_platform_admin and self._ctx.settings.platform_admin_mfa_required:
            return True
        tenant = await self._ctx.tenants.get(user.tenant_id)
        return tenant is not None and tenant_requires_mfa(tenant.settings)

    # ----------------------------------------------------------------- secrets

    def _box(self) -> SecretBox:
        if self._ctx.secret_box is None:
            raise mfa_unavailable("MFA needs security.encryption_keys to be configured on this server")
        return self._ctx.secret_box

    def _recovery_key(self) -> bytes:
        try:
            return totp.recovery_key(indicator_hmac_key(self._ctx.settings))
        except SecurityConfigError as exc:
            raise mfa_unavailable("MFA needs security.indicator_hmac_key to be configured on this server") from exc

    def _decrypt(self, user: User, ciphertext: str) -> str:
        try:
            value = self._box().decrypt_json(ciphertext, context=secret_context(user.tenant_id, user.id))
        except DecryptionError as exc:
            log.error("mfa.secret_undecryptable", tenant_id=user.tenant_id, user_id=str(user.id))
            raise mfa_unavailable("the stored MFA secret cannot be decrypted; an admin must reset MFA") from exc
        if not isinstance(value, str):
            raise mfa_unavailable("the stored MFA secret is malformed; an admin must reset MFA")
        return value

    def _hash_codes(self, user: User, codes: List[str]) -> List[str]:
        key = self._recovery_key()
        return [totp.hash_recovery_code(key, user.tenant_id, str(user.id), c) for c in codes]

    # -------------------------------------------------------------- enrollment

    async def begin_enrollment(self, user: User) -> Enrollment:
        """A new pending secret for ``user`` (refused while MFA is active: disable it first)."""
        current = await self.state(user)
        if current is not None and current.enabled:
            raise ApiError(409, "mfa_already_enabled", "MFA is already enabled; disable it before enrolling again")
        self._recovery_key()  # fail before handing out a secret that could not be confirmed
        secret = totp.generate_secret()
        ciphertext = self._box().encrypt_json(secret, context=secret_context(user.tenant_id, user.id))
        await self._ctx.repos.user_mfa.set_pending(user.tenant_id, user.id, ciphertext)
        uri = totp.provisioning_uri(secret, user.email, self._ctx.settings.auth.mfa_issuer)
        try:
            matrix: Optional[List[str]] = qr.matrix_rows(uri)
        except qr.QrTooLong:
            matrix = None
        return Enrollment(secret=secret, otpauth_uri=uri, qr=matrix)

    async def confirm_enrollment(
        self, user: User, code: str, *, actor_type: str, actor_id: str, failure_status: int = 400
    ) -> List[str]:
        """Activate the pending secret with a code from it; returns the recovery codes (shown once)."""
        current = await self.state(user)
        if current is not None and current.enabled:
            raise ApiError(409, "mfa_already_enabled", "MFA is already enabled")
        if current is None or current.pending_secret_ciphertext is None or current.pending_created_at is None:
            raise ApiError(409, "mfa_not_enrolling", "start enrollment first")
        age = (datetime.now(UTC) - current.pending_created_at).total_seconds()
        if age > PENDING_TTL_S:
            raise ApiError(409, "mfa_not_enrolling", "the enrollment expired; start again")
        secret = self._decrypt(user, current.pending_secret_ciphertext)
        step = totp.verify_totp(secret, code, at=clock()) if len(code) <= MAX_CODE_CHARS else None
        if step is None:
            await self._audit_failure(user, "enrollment_bad_code", actor_type=actor_type, actor_id=actor_id)
            raise invalid_code(failure_status)
        codes = totp.generate_recovery_codes()
        activated = await self._ctx.repos.user_mfa.activate(
            user.tenant_id,
            user.id,
            pending_ciphertext=current.pending_secret_ciphertext,
            step=step,
            recovery_code_hashes=self._hash_codes(user, codes),
        )
        if activated is None:
            raise ApiError(409, "mfa_not_enrolling", "the enrollment changed meanwhile; start again")
        await self._audit.record(
            user.tenant_id,
            "auth.mfa_enrolled",
            "user",
            str(user.id),
            actor_type=actor_type,
            actor_id=actor_id,
            details={"method": "totp", "recovery_codes": len(codes)},
        )
        return codes

    # ------------------------------------------------------------ verification

    async def check_code(self, user: User, code: str, *, allow_recovery: bool = True) -> Optional[CodeCheck]:
        """Verify and *consume* a TOTP or recovery code; ``None`` when it is not valid (or already used)."""
        current = await self.state(user)
        if current is None or not current.enabled or current.secret_ciphertext is None:
            return None
        if len(code) > MAX_CODE_CHARS:
            return None
        if allow_recovery and totp.looks_like_recovery_code(code):
            code_hash = self._hash_codes(user, [code])[0]
            remaining = await self._ctx.repos.user_mfa.consume_recovery_code(user.tenant_id, user.id, code_hash)
            if remaining is None:
                return None
            await self._audit.record(
                user.tenant_id,
                "auth.mfa_recovery_code_used",
                "user",
                str(user.id),
                actor_type="user",
                actor_id=str(user.id),
                details={"recovery_codes_remaining": remaining},
            )
            return CodeCheck(method="recovery_code", recovery_codes_remaining=remaining)
        secret = self._decrypt(user, current.secret_ciphertext)
        step = totp.verify_totp(secret, code, at=clock(), after_step=current.last_used_step)
        if step is None:
            return None
        if not await self._ctx.repos.user_mfa.consume_step(user.tenant_id, user.id, step):
            return None  # a concurrent request used this step first
        await self._rewrap(user, current.secret_ciphertext)
        return CodeCheck(method="totp")

    async def _rewrap(self, user: User, ciphertext: str) -> None:
        """After an encryption-key rotation, move the secret to the primary key on its next use."""
        box = self._box()
        if box.is_primary(ciphertext):
            return
        try:
            await self._ctx.repos.user_mfa.rewrap_secret(user.tenant_id, user.id, ciphertext, box.rotate(ciphertext))
        except DecryptionError:
            log.warning("mfa.secret_rewrap_failed", tenant_id=user.tenant_id)

    async def audit_failure(self, user: User, reason: str, *, client_ip: Optional[str] = None) -> None:
        await self._audit_failure(user, reason, actor_type="user", actor_id=str(user.id), client_ip=client_ip)

    async def _audit_failure(
        self, user: User, reason: str, *, actor_type: str, actor_id: str, client_ip: Optional[str] = None
    ) -> None:
        details = {"reason": reason}
        if client_ip is not None:
            details["client_ip"] = client_ip
        await self._audit.record_event(
            user.tenant_id,
            "auth.mfa_failed",
            "user",
            str(user.id),
            actor_type=actor_type,
            actor_id=actor_id,
            details=details,
        )

    # -------------------------------------------------------------- management

    async def regenerate_recovery_codes(self, user: User) -> List[str]:
        codes = totp.generate_recovery_codes()
        updated = await self._ctx.repos.user_mfa.replace_recovery_codes(
            user.tenant_id, user.id, self._hash_codes(user, codes)
        )
        if updated is None:
            raise ApiError(409, "mfa_not_enabled", "MFA is not enabled")
        await self._audit.record(
            user.tenant_id,
            "auth.mfa_recovery_codes_regenerated",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"recovery_codes": len(codes)},
        )
        return codes

    async def disable(self, user: User) -> None:
        await self._ctx.repos.user_mfa.delete(user.tenant_id, user.id)
        await self._audit.record(
            user.tenant_id,
            "auth.mfa_disabled",
            "user",
            str(user.id),
            actor_type="user",
            actor_id=str(user.id),
            details={"required_by_policy": await self.required_for(user)},
        )
