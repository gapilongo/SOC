"""``entra.sessions``: revoke a user's sign-in sessions (``revoke_sessions``; not reversible).

``POST /v1.0/users/{id}/revokeSignInSessions`` (no body, any 2xx is
success) invalidates the refresh tokens issued to applications and the
browser session cookies by setting ``signInSessionsValidFromDateTime`` to
the current time. It does not reach:

* access tokens already issued: they stay valid until they expire (about
  1 h) unless the application supports continuous access evaluation (CAE);
* sessions an application issued itself;
* guests (B2B): their sessions live in their home tenant, so guests are
  refused (``guest_refused``) rather than reported as contained.

Idempotency: the call is idempotent. A re-run of this action whose earlier
attempt already moved ``signInSessionsValidFromDateTime`` to the execution
time (``external_ref.requested`` and the timestamp at or after
``executed_at`` minus 60 s of clock skew) sends nothing again. A recent
revocation by someone else does *not* skip the call: an attacker who
revoked the sessions just before and signed in again would keep that new
session.

Verification: ``signInSessionsValidFromDateTime`` at or after the execution
time (minus the skew) is ``verified``; revocation can take a few minutes,
so otherwise it stays ``pending`` (first check after 30 s, for up to 10
minutes).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.entra.guard import rehearsal, screen, unresolved
from lg_sotf.integrations.microsoft.entra.users import (
    USERS_PATH,
    DirectoryUser,
    Refused,
    at_or_after,
    inline_read_failed,
    iso,
    not_before,
    probe_get,
    refused_result,
    resolve_user,
    summary,
    user_by_id,
    write_failure,
)
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

SESSIONS_SELECT = "id,signInSessionsValidFromDateTime"
REVOKE = {"method": "POST", "path_template": "/v1.0/users/{id}/revokeSignInSessions"}
FIRST_CHECK_S = 30.0
MAX_S = 600.0
REVOCATION_NOTE = "existing access tokens stay valid until they expire (about 1 h) unless the app supports CAE"


def refuse_guests(user: DirectoryUser) -> None:
    if user.is_guest:
        raise Refused(
            "guest_refused", f"refused: {user.upn} is a guest (B2B) account",
            hint="a guest's sessions live in their home tenant; ask that tenant's administrators to revoke them",
        )


class SessionsHandler:
    """Revoke Entra ID sign-in sessions (module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    async def _valid_from(self, user_id: str) -> DirectoryUser:
        return await user_by_id(self.ctx, user_id, select=SESSIONS_SELECT)

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        try:
            user = await resolve_user(self.ctx, action.target)
        except Refused as exc:
            return unresolved(action, exc, REVOKE)
        return await rehearsal(self.ctx, action, user, REVOKE, refuse_guests)

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        ref = dict(action.external_ref or {})
        user: Optional[DirectoryUser] = None
        try:
            user = await resolve_user(self.ctx, action.target)
            await screen(self.ctx, user, refuse_guests)
        except Refused as exc:
            return refused_result(exc, user)
        since = not_before(action)
        result_ref = {"user_id": user.id, "upn": user.upn, "requested": True, "reversible": False}
        detail: Dict[str, Any] = {"changed": True, "user": user.brief(), "note": REVOCATION_NOTE}
        if ref.get("requested") and at_or_after(user.sessions_valid_from, since):
            return ConnectorResult(
                "succeeded",
                {**detail, "summary": summary(f"sign-in sessions of {user.upn} were already revoked by this action"),
                 "already": True},
                external_ref=result_ref,
                verify=VerifyPlan("verified", detail={"sessions_valid_from": iso(user.sessions_valid_from)}),
            )
        await self.ctx.checkpoint({"user_id": user.id, "requested": True})
        try:
            await self.ctx.api("graph").request(
                "POST", f"{user.path}/revokeSignInSessions", idempotent=True, deadline=self.ctx.deadline
            )
        except MicrosoftApiError as exc:
            failure = write_failure(exc, "revoke the sign-in sessions of", user)
            if failure is None:
                raise
            return failure
        detail["summary"] = summary(f"revoked the sign-in sessions of {user.upn}")
        try:
            observed = (await self._valid_from(user.id)).sessions_valid_from
        except (MicrosoftApiError, Refused) as exc:
            return ConnectorResult(
                "succeeded", detail, external_ref=result_ref,
                verify=VerifyPlan("pending", first_check_s=FIRST_CHECK_S, max_duration_s=MAX_S,
                                  detail=inline_read_failed(exc)),
            )
        state = {"sessions_valid_from": iso(observed)}
        if at_or_after(observed, since):
            return ConnectorResult("succeeded", detail, external_ref=result_ref, verify=VerifyPlan("verified", detail=state))
        return ConnectorResult(
            "succeeded", detail, external_ref=result_ref,
            verify=VerifyPlan("pending", first_check_s=FIRST_CHECK_S, max_duration_s=MAX_S, detail=state),
        )

    async def verify(self, action: ResponseAction) -> VerificationResult:
        user_id = (action.external_ref or {}).get("user_id")
        try:
            if isinstance(user_id, str) and odata.is_guid(user_id):
                observed = (await self._valid_from(user_id)).sessions_valid_from
            else:
                observed = (await resolve_user(self.ctx, action.target)).sessions_valid_from
        except Refused as exc:
            return VerificationResult("inconclusive", {"reason": exc.code})
        state = {"sessions_valid_from": iso(observed)}
        if at_or_after(observed, not_before(action)):
            return VerificationResult("verified", state)
        return VerificationResult("pending", state)

    async def probe(self) -> List[ProbeCheck]:
        return [
            await probe_get(self.ctx, "read users' session validity", USERS_PATH, permission="User.Read.All",
                            params={"$top": "1", "$select": SESSIONS_SELECT}),
        ]


__all__ = ["SessionsHandler", "refuse_guests"]
