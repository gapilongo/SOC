"""``entra.account``: disable a user's account (``disable_user``) and re-enable it as its rollback (``enable_user``).

disable_user
    Resolve the user, refuse guests (unless ``allow_guests``) and synced
    users (when ``allow_synced_users`` is off), run the privileged-target
    guard. An account that is already disabled is ``succeeded`` with
    ``already: true`` and nothing to roll back, unless this action's own
    earlier attempt disabled it (``external_ref.requested``: a re-run after a
    crash, still reversible). Otherwise checkpoint
    ``{user_id, prior: {accountEnabled: true}, synced, requested}``, send
    ``PATCH /v1.0/users/{id} {"accountEnabled": false}`` (204; idempotent, so
    Graph's ``Directory_ConcurrencyViolation``, 429 and 503 are retried) and
    re-read ``accountEnabled``:

    * disabled, cloud-only user: ``verified``;
    * disabled, synced (hybrid) user: ``pending`` for 40 minutes, checked
      until 60 minutes: Entra Connect re-enables the account at its next
      sync (30 minutes by default) unless the on-premises account is
      disabled too, so a cloud-only disable of a synced user is temporary
      (``failed`` verification, ``reverted_by_sync``, when that happens);
    * still enabled after a few re-reads: ``failed`` with ``not_verified``.

enable_user (rollback; ``ctx.original`` is the disable)
    Only when the disable changed something (``prior.accountEnabled`` true
    and ``requested``); otherwise ``succeeded`` with
    ``error: "rollback_not_needed"``. The user is the recorded object id (not
    the name, which may since belong to someone else); the guard runs again,
    then ``PATCH {"accountEnabled": true}`` and an inline re-read.

Permissions: ``User.EnableDisableAccount.All`` plus ``User.Read.All``, and
the service principal needs the **User Administrator** directory role
(app-only updates of ``accountEnabled`` require an administrator role);
``RoleManagement.Read.Directory`` and ``GroupMember.Read.All`` for the guard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.capability import CapabilityOptions, HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.entra.guard import (
    ROLE_ASSIGNMENTS_PATH,
    no_refusals,
    rehearsal,
    screen,
    unresolved,
)
from lg_sotf.integrations.microsoft.entra.users import (
    USERS_PATH,
    DirectoryUser,
    Refused,
    inline_read_failed,
    mapping,
    probe_get,
    refused_result,
    reread,
    resolve_user,
    summary,
    user_by_id,
    write_failure,
)
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

ACCOUNT_SELECT = "id,accountEnabled"
USER_WRITE = {"method": "PATCH", "path_template": "/v1.0/users/{id}"}
CLOUD_FIRST_CHECK_S = 30.0
CLOUD_MAX_S = 900.0
SYNCED_FIRST_CHECK_S = 2_400.0
SYNCED_MAX_S = 3_600.0
SYNCED_NOTE = (
    "synced (hybrid) account: Entra Connect re-enables it at its next sync unless the on-premises account is "
    "disabled too (Disable-ADAccount), and the on-premises password should be reset twice"
)
NOT_VERIFIED_HINT = (
    "Microsoft accepted the change but the account still reads as {state}; retry, or look for an automation "
    "or sync that reverts it"
)


class EntraAccountOptions(CapabilityOptions):
    """``allow_guests``: also disable B2B guests. ``allow_synced_users``: also disable synced (hybrid) users."""

    allow_guests: bool = False
    allow_synced_users: bool = True


class AccountHandler:
    """Disable and re-enable Entra ID accounts (module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    @property
    def options(self) -> EntraAccountOptions:
        options = self.ctx.options
        return options if isinstance(options, EntraAccountOptions) else EntraAccountOptions()

    def _refusals(self, user: DirectoryUser) -> None:
        if user.is_guest and not self.options.allow_guests:
            raise Refused(
                "guest_refused", f"refused: {user.upn} is a guest (B2B) account",
                hint="guests are refused unless the capability option allow_guests is on",
            )
        if user.synced and not self.options.allow_synced_users:
            raise Refused(
                "synced_user_refused", f"refused: {user.upn} is synced from on-premises Active Directory",
                hint="disable the account on-premises, or turn the capability option allow_synced_users on",
            )

    async def _enabled(self, user_id: str) -> Optional[bool]:
        return (await user_by_id(self.ctx, user_id, select=ACCOUNT_SELECT)).account_enabled

    @staticmethod
    def _recorded_user(ref: Optional[Mapping[str, Any]]) -> Optional[str]:
        user_id = (ref or {}).get("user_id")
        return user_id if isinstance(user_id, str) and odata.is_guid(user_id) else None

    async def _target(self, action: ResponseAction) -> DirectoryUser:
        original = self.ctx.original
        recorded = self._recorded_user(original.external_ref if original is not None else None)
        if action.action_type == "enable_user" and recorded is not None:
            return await user_by_id(self.ctx, recorded)
        return await resolve_user(self.ctx, action.target)

    # ------------------------------------------------------------------ rehearse

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        try:
            user = await self._target(action)
        except Refused as exc:
            return unresolved(action, exc, USER_WRITE)
        refusals = no_refusals if action.action_type == "enable_user" else self._refusals
        return await rehearsal(self.ctx, action, user, USER_WRITE, refusals)

    # ------------------------------------------------------------------- execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        if action.action_type == "enable_user":
            return await self._enable(action)
        return await self._disable(action)

    async def _disable(self, action: ResponseAction) -> ConnectorResult:
        ref = dict(action.external_ref or {})
        user: Optional[DirectoryUser] = None
        try:
            user = await resolve_user(self.ctx, action.target)
            await screen(self.ctx, user, self._refusals)
        except Refused as exc:
            return refused_result(exc, user)
        if user.account_enabled is False:
            if ref.get("requested"):
                # This action's interrupted earlier attempt disabled it: the change is ours (reversible).
                prior = mapping(ref.get("prior")) or {"accountEnabled": True}
                return await self._disabled(user, prior, observed=False)
            return ConnectorResult(
                "succeeded",
                {"summary": summary(f"{user.upn} is already disabled; nothing changed"), "changed": False,
                 "already": True, "user": user.brief()},
                external_ref={"user_id": user.id, "upn": user.upn, "synced": user.synced, "reversible": False},
                verify=VerifyPlan("verified", detail={"accountEnabled": False}),
            )
        prior = {"accountEnabled": user.account_enabled}
        await self.ctx.checkpoint({"user_id": user.id, "prior": prior, "synced": user.synced, "requested": True})
        try:
            await self.ctx.api("graph").request(
                "PATCH", user.path, json={"accountEnabled": False}, idempotent=True, deadline=self.ctx.deadline
            )
        except MicrosoftApiError as exc:
            failure = write_failure(exc, "disable", user)
            if failure is None:
                raise
            return failure
        return await self._disabled(user, prior)

    async def _disabled(
        self, user: DirectoryUser, prior: Dict[str, Any], *, observed: Optional[bool] = None
    ) -> ConnectorResult:
        """The outcome after the disable was sent: proven inline, pending (synced users), or disproved."""
        ref = {
            "user_id": user.id, "upn": user.upn, "prior": prior, "synced": user.synced, "requested": True,
            "reversible": prior.get("accountEnabled") is True,
        }
        first, longest = (SYNCED_FIRST_CHECK_S, SYNCED_MAX_S) if user.synced else (CLOUD_FIRST_CHECK_S, CLOUD_MAX_S)
        state = observed
        failed_read: Dict[str, Any] = {}
        if state is None:
            try:
                state = await reread(self.ctx, lambda: self._enabled(user.id), lambda enabled: enabled is False)
            except (MicrosoftApiError, Refused) as exc:
                failed_read = inline_read_failed(exc)
        if state is True:
            return ConnectorResult(
                "failed",
                {"summary": summary(f"disabling {user.upn} was accepted but the account still reads as enabled"),
                 "changed": False, "error": "not_verified", "observed": {"accountEnabled": True}, "retryable": True,
                 "hint": NOT_VERIFIED_HINT.format(state="enabled"), "user": user.brief()},
                external_ref={**ref, "reversible": False},
            )
        detail: Dict[str, Any] = {"summary": summary(f"disabled {user.upn}"), "changed": True, "user": user.brief(),
                                  "synced": user.synced}
        if user.synced:
            detail["summary"] = summary(f"disabled {user.upn} (synced: temporary until disabled on-premises too)")
            detail["note"] = SYNCED_NOTE
        if state is False and not user.synced:
            verify = VerifyPlan("verified", detail={"accountEnabled": False})
        else:
            observed_state: Dict[str, Any] = {"accountEnabled": state, "temporary": user.synced, **failed_read}
            verify = VerifyPlan("pending", first_check_s=first, max_duration_s=longest, detail=observed_state)
        return ConnectorResult("succeeded", detail, external_ref=ref, verify=verify)

    async def _enable(self, action: ResponseAction) -> ConnectorResult:
        original = self.ctx.original
        oref = dict(original.external_ref or {}) if original is not None else {}
        prior = mapping(oref.get("prior"))
        if original is None or prior.get("accountEnabled") is not True or not oref.get("requested"):
            return ConnectorResult(
                "succeeded",
                {"summary": "nothing to undo: the account was not enabled before, or was not disabled by this action",
                 "changed": False, "error": "rollback_not_needed"},
                external_ref={"reversible": False},
            )
        user: Optional[DirectoryUser] = None
        try:
            user = await self._target(action)
            await screen(self.ctx, user, no_refusals)
        except Refused as exc:
            return refused_result(exc, user)
        ref = {"user_id": user.id, "upn": user.upn, "requested": True, "reversible": False}
        if user.account_enabled is True:
            return ConnectorResult(
                "succeeded",
                {"summary": summary(f"{user.upn} is already enabled; nothing changed"), "changed": False,
                 "already": True, "user": user.brief()},
                external_ref=ref, verify=VerifyPlan("verified", detail={"accountEnabled": True}),
            )
        await self.ctx.checkpoint({"user_id": user.id, "requested": True})
        try:
            await self.ctx.api("graph").request(
                "PATCH", user.path, json={"accountEnabled": True}, idempotent=True, deadline=self.ctx.deadline
            )
        except MicrosoftApiError as exc:
            failure = write_failure(exc, "re-enable", user)
            if failure is None:
                raise
            return failure
        try:
            state = await reread(self.ctx, lambda: self._enabled(user.id), lambda enabled: enabled is True)
        except (MicrosoftApiError, Refused) as exc:
            return ConnectorResult(
                "succeeded", {"summary": summary(f"re-enabled {user.upn}"), "changed": True, "user": user.brief()},
                external_ref=ref,
                verify=VerifyPlan("pending", first_check_s=CLOUD_FIRST_CHECK_S, max_duration_s=CLOUD_MAX_S,
                                  detail=inline_read_failed(exc)),
            )
        if state is not True:
            return ConnectorResult(
                "failed",
                {"summary": summary(f"re-enabling {user.upn} was accepted but the account still reads as disabled"),
                 "changed": False, "error": "not_verified", "observed": {"accountEnabled": state}, "retryable": True,
                 "hint": NOT_VERIFIED_HINT.format(state="disabled"), "user": user.brief()},
                external_ref=ref,
            )
        return ConnectorResult(
            "succeeded", {"summary": summary(f"re-enabled {user.upn}"), "changed": True, "user": user.brief()},
            external_ref=ref, verify=VerifyPlan("verified", detail={"accountEnabled": True}),
        )

    # -------------------------------------------------------------------- verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        ref = action.external_ref or {}
        wanted = action.action_type == "enable_user"
        try:
            user_id = self._recorded_user(ref) or (await resolve_user(self.ctx, action.target)).id
            enabled = await self._enabled(user_id)
        except Refused as exc:
            return VerificationResult("inconclusive", {"reason": exc.code})
        if enabled is None:
            return VerificationResult("pending", {"accountEnabled": None})
        if enabled is wanted:
            return VerificationResult("verified", {"accountEnabled": enabled, "synced": bool(ref.get("synced"))})
        if wanted:
            return VerificationResult("failed", {"reason": "disabled_again", "accountEnabled": False})
        reason = "reverted_by_sync" if ref.get("synced") else "re_enabled"
        return VerificationResult("failed", {"reason": reason, "accountEnabled": True})

    # --------------------------------------------------------------------- probe

    async def probe(self) -> List[ProbeCheck]:
        return [
            await probe_get(self.ctx, "read users", USERS_PATH, permission="User.Read.All",
                            params={"$top": "1", "$select": ACCOUNT_SELECT}),
            await probe_get(self.ctx, "read directory role assignments", ROLE_ASSIGNMENTS_PATH,
                            permission="RoleManagement.Read.Directory", params={"$top": "1"}),
        ]


__all__ = ["AccountHandler", "EntraAccountOptions"]
