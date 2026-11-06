"""``entra.password``: reset a user's password to a random one nobody knows (``reset_password``; not reversible).

``PATCH /v1.0/users/{id}`` with ``passwordProfile``: a new random password
of :data:`PASSWORD_LENGTH` characters from :mod:`secrets` (upper case, lower
case, digits and symbols guaranteed), ``forceChangePasswordNextSignIn:
true`` and ``forceChangePasswordNextSignInWithMfa`` from the
``require_mfa_on_change`` option. The force flag is never sent alone:
whoever knows the current password (the attacker) would get to choose the
next one. The new password is never logged, checkpointed, stored, returned
or put in an exception; the legitimate user gets back in through the
helpdesk or a Temporary Access Pass. The old password cannot be restored.

Refused: guests (``guest_refused``) and synced users
(``synced_user_refused``: the reset must happen on-premises, twice, and a
cloud reset of a synced user is overwritten). ``passwordProfile`` cannot be
used for federated users; a 400 whose code names federation is
``federated_user``, any other 400 ``bad_request`` (only the error code is
kept).

Idempotency: the reset is not idempotent (every call sets another
password), so the request is never retried after a network error; the
action is deferred and its re-run reads ``lastPasswordChangeDateTime``
first. A re-run whose earlier attempt already reset the password
(``external_ref.requested`` and the timestamp at or after ``executed_at``
minus 60 s) sends nothing again. A recent change by anyone else (possibly
the attacker) does not skip the reset.

Verification: ``lastPasswordChangeDateTime`` at or after the execution time
(minus the skew) and, when Graph returns ``passwordProfile``,
``forceChangePasswordNextSignIn`` true: ``verified``; otherwise ``pending``
(30 s, for up to 10 minutes).

Permissions: ``User-PasswordProfile.ReadWrite.All`` plus the **User
Administrator** directory role on the service principal (app-only password
resets require it), ``User.Read.All``, and the guard's permissions.
"""

from __future__ import annotations

import secrets
import string
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.entra.guard import rehearsal, screen, unresolved
from lg_sotf.integrations.microsoft.entra.users import (
    USERS_PATH,
    DirectoryUser,
    Refused,
    at_or_after,
    inline_read_failed,
    iso,
    not_before,
    parse_time,
    probe_get,
    refused_result,
    resolve_user,
    summary,
    write_failure,
)
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

PASSWORD_LENGTH = 40
# Characters Microsoft Entra ID accepts in passwords (no spaces, quotes or Unicode).
SYMBOL_CHARACTERS = "!#$%&*+-.:=?@^_~"
PASSWORD_CLASSES = (string.ascii_uppercase, string.ascii_lowercase, string.digits, SYMBOL_CHARACTERS)
VERIFY_SELECT = "id,lastPasswordChangeDateTime,passwordProfile"
RESET = {"method": "PATCH", "path_template": "/v1.0/users/{id}"}
FIRST_CHECK_S = 30.0
MAX_S = 600.0
ACCESS_NOTE = (
    "the new password is not stored or shown: the user regains access through the helpdesk or a Temporary Access Pass"
)


class EntraPasswordOptions(CapabilityOptions):
    """``require_mfa_on_change``: the user must complete MFA before choosing the new password."""

    require_mfa_on_change: bool = False


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    """A random password of ``length`` (at least 32) characters with every character class (CSPRNG)."""
    if length < 32:
        raise ValueError("passwords are at least 32 characters")
    alphabet = "".join(PASSWORD_CLASSES)
    chars = [secrets.choice(group) for group in PASSWORD_CLASSES]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _bad_request(exc: MicrosoftApiError) -> str:
    return "federated_user" if "federat" in exc.code.lower() else "bad_request"


def refuse_guests_and_synced(user: DirectoryUser) -> None:
    if user.is_guest:
        raise Refused(
            "guest_refused", f"refused: {user.upn} is a guest (B2B) account",
            hint="a guest's password belongs to their home tenant",
        )
    if user.synced:
        raise Refused(
            "synced_user_refused", f"refused: {user.upn} is synced from on-premises Active Directory",
            hint="reset the password on-premises (twice, against pass-the-hash); a cloud reset is overwritten",
        )


def _force_flag(profile: Any) -> Optional[bool]:
    if not isinstance(profile, Mapping):
        return None
    value = profile.get("forceChangePasswordNextSignIn")
    return value if isinstance(value, bool) else None


class PasswordHandler:
    """Reset Entra ID passwords (module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    @property
    def options(self) -> EntraPasswordOptions:
        options = self.ctx.options
        return options if isinstance(options, EntraPasswordOptions) else EntraPasswordOptions()

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        try:
            user = await resolve_user(self.ctx, action.target)
        except Refused as exc:
            return unresolved(action, exc, RESET)
        return await rehearsal(self.ctx, action, user, RESET, refuse_guests_and_synced)

    async def _observe(self, user_id: str, action: ResponseAction) -> VerificationResult:
        """Whether Graph shows this action's reset (``verified``) or not yet (``pending``)."""
        response = await self.ctx.api("graph").request(
            "GET", f"{USERS_PATH}/{odata.segment(user_id)}", params={"$select": VERIFY_SELECT},
            ok=(200, 202), deadline=self.ctx.deadline,
        )
        body = response.body if isinstance(response.body, Mapping) else {}
        changed_at = parse_time(body.get("lastPasswordChangeDateTime"))
        force = _force_flag(body.get("passwordProfile"))
        state = {"last_password_change": iso(changed_at), "force_change": force}
        if at_or_after(changed_at, not_before(action)) and force is not False:
            return VerificationResult("verified", state)
        return VerificationResult("pending", state)

    async def _send_reset(self, user: DirectoryUser) -> None:
        """The one request that carries a password; it keeps no reference to it afterwards."""
        body: Dict[str, Any] = {
            "passwordProfile": {
                "password": generate_password(),
                "forceChangePasswordNextSignIn": True,
                "forceChangePasswordNextSignInWithMfa": self.options.require_mfa_on_change,
            }
        }
        try:
            await self.ctx.api("graph").request("PATCH", user.path, json=body, deadline=self.ctx.deadline)
        except MicrosoftApiError as exc:
            # Drop the frames (and their request body) from the error before anything can report it.
            raise exc.with_traceback(None) from None
        finally:
            body["passwordProfile"].pop("password", None)
            body.clear()

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        ref = dict(action.external_ref or {})
        user: Optional[DirectoryUser] = None
        try:
            user = await resolve_user(self.ctx, action.target)
            await screen(self.ctx, user, refuse_guests_and_synced)
        except Refused as exc:
            return refused_result(exc, user)
        result_ref = {"user_id": user.id, "upn": user.upn, "requested": True, "reversible": False}
        detail: Dict[str, Any] = {
            "changed": True, "user": user.brief(), "force_change_with_mfa": self.options.require_mfa_on_change,
            "note": ACCESS_NOTE,
        }
        already = bool(ref.get("requested")) and at_or_after(user.last_password_change, not_before(action))
        if already:
            detail.update(summary=summary(f"the password of {user.upn} was already reset by this action"), already=True)
        else:
            await self.ctx.checkpoint({"user_id": user.id, "requested": True})
            try:
                await self._send_reset(user)
            except MicrosoftApiError as exc:
                failure = write_failure(exc, "reset the password of", user, bad_request=_bad_request)
                if failure is None:
                    raise
                return failure
            detail["summary"] = summary(f"reset the password of {user.upn}; a change is required at next sign-in")
        try:
            observed = await self._observe(user.id, action)
        except (MicrosoftApiError, Refused) as exc:
            observed = VerificationResult("pending", inline_read_failed(exc))
        if observed.state == "verified":
            verify = VerifyPlan("verified", detail=dict(observed.detail))
        else:
            verify = VerifyPlan("pending", first_check_s=FIRST_CHECK_S, max_duration_s=MAX_S, detail=dict(observed.detail))
        return ConnectorResult("succeeded", detail, external_ref=result_ref, verify=verify)

    async def verify(self, action: ResponseAction) -> VerificationResult:
        user_id = (action.external_ref or {}).get("user_id")
        try:
            if not (isinstance(user_id, str) and odata.is_guid(user_id)):
                user_id = (await resolve_user(self.ctx, action.target)).id
            return await self._observe(user_id, action)
        except Refused as exc:
            return VerificationResult("inconclusive", {"reason": exc.code})

    async def probe(self) -> List[ProbeCheck]:
        return [
            await probe_get(self.ctx, "read users' password change times", USERS_PATH, permission="User.Read.All",
                            params={"$top": "1", "$select": "id,lastPasswordChangeDateTime"}),
        ]


__all__ = ["EntraPasswordOptions", "PasswordHandler", "generate_password"]
