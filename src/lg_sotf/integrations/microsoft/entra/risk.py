"""``entra.risk``: confirm a user as compromised in Entra ID Protection, and dismiss the risk as its rollback.

confirm_compromised
    Resolve the user, run the guard, read the prior risk
    (``GET /v1.0/identityProtection/riskyUsers/{id}`` with
    ``Prefer: include-unknown-enum-members``; a 404 means no risk record; the
    documented example wraps the object in ``{"value": [...]}``, so both
    shapes are parsed). Already ``confirmedCompromised``: ``succeeded`` with
    ``already: true`` and nothing to roll back (unless this action's own
    earlier attempt confirmed it). Otherwise checkpoint
    ``{user_id, prior: {riskState, riskLevel}, requested}`` and send
    ``POST /v1.0/identityProtection/riskyUsers/confirmCompromised
    {"userIds": [id]}`` (204; idempotent). Identity Protection processes it
    asynchronously (``isProcessing``), so verification re-reads the risk
    until ``riskState`` is ``confirmedCompromised`` (first check after 60 s,
    for up to 30 minutes).

dismiss_user_risk (rollback, compensating)
    ``POST /v1.0/identityProtection/riskyUsers/dismiss {"userIds": [id]}``
    only when the confirmation changed something; verified when
    ``riskState`` is ``dismissed`` or ``riskLevel`` is ``none``. It is not a
    true inverse: it clears the user's risk and cannot restore the earlier
    risk state or level (kept in ``prior`` for the record). Risk cannot be
    dismissed for a user deleted from the directory.

Licensing: Microsoft Entra ID P2 (or Microsoft Entra Suite). A 403 whose
error code names a licence (or a non-premium tenant) is ``not_licensed``;
other 403s are ``permission_denied``. The risky-user endpoints allow about
one request per second per tenant and send no ``Retry-After``; the HTTP
client backs off on 429.

Permissions: ``IdentityRiskyUser.ReadWrite.All`` (confirm, dismiss),
``IdentityRiskyUser.Read.All`` (the only permission the read lists),
``User.Read.All`` and the guard's permissions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

from lg_sotf.domain.connectors import ConnectorResult, VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.capability import HandlerContext, ProbeCheck
from lg_sotf.integrations.microsoft.entra.guard import no_refusals, rehearsal, screen, unresolved
from lg_sotf.integrations.microsoft.entra.users import (
    DirectoryUser,
    Refused,
    inline_read_failed,
    mapping,
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

RISKY_USERS_PATH = "/v1.0/identityProtection/riskyUsers"
PREFER_UNKNOWN_ENUMS = {"Prefer": "include-unknown-enum-members"}
CONFIRM = {"method": "POST", "path_template": f"{RISKY_USERS_PATH}/confirmCompromised"}
DISMISS = {"method": "POST", "path_template": f"{RISKY_USERS_PATH}/dismiss"}
CONFIRMED = "confirmedCompromised"
FIRST_CHECK_S = 60.0
MAX_S = 1_800.0
LICENCE_CODES = ("licens", "premium")
DENIED_HINT = (
    "missing IdentityRiskyUser.ReadWrite.All or IdentityRiskyUser.Read.All (admin consent), "
    "or the tenant lacks Microsoft Entra ID P2"
)
LICENCE_HINT = "Identity Protection needs Microsoft Entra ID P2 (or Microsoft Entra Suite)"
NOT_RESTORED = "the earlier risk state was not restored"
_ENUM = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def licence_denied(exc: MicrosoftApiError) -> bool:
    """Whether a 403's error code points to a missing licence (Microsoft's message text is never read)."""
    code = exc.code.lower()
    return exc.kind == "forbidden" and any(marker in code for marker in LICENCE_CODES)


def _forbidden_error(exc: MicrosoftApiError) -> str:
    return "not_licensed" if licence_denied(exc) else exc.ledger_error


def _enum(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and _ENUM.match(value) else None


@dataclass(frozen=True)
class RiskState:
    """A user's Identity Protection risk as read (``found`` is false without a risk record)."""

    found: bool
    risk_state: Optional[str] = None
    risk_level: Optional[str] = None
    risk_detail: Optional[str] = None
    processing: bool = False
    deleted: bool = False

    def observed(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "riskState": self.risk_state,
            "riskLevel": self.risk_level,
            "riskDetail": self.risk_detail,
            "isProcessing": self.processing,
        }

    @property
    def confirmed(self) -> bool:
        return self.risk_state == CONFIRMED and not self.processing

    @property
    def cleared(self) -> bool:
        return not self.processing and (self.risk_state == "dismissed" or self.risk_level == "none")


def parse_risky_user(body: Any, user_id: str) -> RiskState:
    """The risk of ``user_id`` from a riskyUser object or a ``{"value": [...]}`` wrapper."""
    item: Any = body
    if isinstance(body, Mapping) and isinstance(body.get("value"), list):
        entries = [v for v in body["value"] if isinstance(v, Mapping)]
        same = [v for v in entries if str(v.get("id") or "").lower() == user_id]
        item = same[0] if same else (entries[0] if len(entries) == 1 and "id" not in entries[0] else None)
    if not isinstance(item, Mapping):
        return RiskState(found=False)
    return RiskState(
        found=True,
        risk_state=_enum(item.get("riskState")),
        risk_level=_enum(item.get("riskLevel")),
        risk_detail=_enum(item.get("riskDetail")),
        processing=item.get("isProcessing") is True,
        deleted=item.get("isDeleted") is True,
    )


class RiskHandler:
    """Confirm users compromised in Entra ID Protection, and dismiss their risk (module docstring)."""

    def __init__(self, ctx: HandlerContext) -> None:
        self.ctx = ctx

    async def read_risk(self, user_id: str) -> RiskState:
        response = await self.ctx.api("graph").request(
            "GET", f"{RISKY_USERS_PATH}/{odata.segment(user_id)}", headers=PREFER_UNKNOWN_ENUMS, not_found_ok=True,
            deadline=self.ctx.deadline,
        )
        if response.status == 404:
            return RiskState(found=False)
        return parse_risky_user(response.body, user_id)

    async def _target(self, action: ResponseAction) -> DirectoryUser:
        original = self.ctx.original
        recorded = (original.external_ref or {}).get("user_id") if original is not None else None
        if action.action_type == "dismiss_user_risk" and isinstance(recorded, str) and odata.is_guid(recorded):
            return await user_by_id(self.ctx, recorded)
        return await resolve_user(self.ctx, action.target)

    async def _post(self, operation: str, user: DirectoryUser, what: str) -> Optional[ConnectorResult]:
        """``POST riskyUsers/{operation}`` for the user; a failed outcome, or ``None`` when it was accepted."""
        try:
            await self.ctx.api("graph").request(
                "POST", f"{RISKY_USERS_PATH}/{operation}", json={"userIds": [user.id]}, idempotent=True,
                deadline=self.ctx.deadline,
            )
        except MicrosoftApiError as exc:
            failure = self._refused_request(exc, what, user)
            if failure is None:
                raise
            return failure
        return None

    @staticmethod
    def _refused_request(exc: MicrosoftApiError, what: str, user: DirectoryUser) -> Optional[ConnectorResult]:
        return write_failure(exc, what, user, denied_hint=DENIED_HINT, licence_hint=LICENCE_HINT,
                             forbidden=_forbidden_error)

    def _read_refused(self, exc: MicrosoftApiError, user: Optional[DirectoryUser]) -> Optional[ConnectorResult]:
        """A 403 on the risk read (no P2 licence, or no IdentityRiskyUser.Read.All) is reported, never retried."""
        if user is None or exc.kind != "forbidden":
            return None
        return self._refused_request(exc, "read the risk of", user)

    async def _outcome(
        self, user: DirectoryUser, detail: Dict[str, Any], ref: Dict[str, Any], *, dismiss: bool
    ) -> ConnectorResult:
        """Re-read the risk after the POST: ``verified`` when it already shows, else a pending verification."""
        try:
            state = await self.read_risk(user.id)
        except (MicrosoftApiError, Refused) as exc:
            observed: Dict[str, Any] = inline_read_failed(exc)
            done = False
        else:
            observed, done = state.observed(), (state.cleared if dismiss else state.confirmed)
        if done:
            verify = VerifyPlan("verified", detail=observed)
        else:
            verify = VerifyPlan("pending", first_check_s=FIRST_CHECK_S, max_duration_s=MAX_S, detail=observed)
        return ConnectorResult("succeeded", detail, external_ref=ref, verify=verify)

    # ------------------------------------------------------------------ rehearse

    async def rehearse(self, action: ResponseAction) -> Dict[str, Any]:
        would = DISMISS if action.action_type == "dismiss_user_risk" else CONFIRM
        try:
            user = await self._target(action)
        except Refused as exc:
            return unresolved(action, exc, would)
        report = await rehearsal(self.ctx, action, user, would, no_refusals)
        try:
            report["risk"] = (await self.read_risk(user.id)).observed()
        except MicrosoftAuthError:
            raise
        except MicrosoftApiError as exc:
            report["risk_error"] = "not_licensed" if licence_denied(exc) else exc.ledger_error
        return report

    # ------------------------------------------------------------------- execute

    async def execute(self, action: ResponseAction) -> ConnectorResult:
        if action.action_type == "dismiss_user_risk":
            return await self._dismiss(action)
        return await self._confirm(action)

    async def _confirm(self, action: ResponseAction) -> ConnectorResult:
        ref = dict(action.external_ref or {})
        user: Optional[DirectoryUser] = None
        try:
            user = await resolve_user(self.ctx, action.target)
            await screen(self.ctx, user, no_refusals)
            state = await self.read_risk(user.id)
        except Refused as exc:
            return refused_result(exc, user)
        except MicrosoftApiError as exc:
            failure = self._read_refused(exc, user)
            if failure is None:
                raise
            return failure
        mine = bool(ref.get("requested"))
        if state.risk_state == CONFIRMED and not mine:
            return ConnectorResult(
                "succeeded",
                {"summary": summary(f"{user.upn} is already confirmed compromised; nothing changed"),
                 "changed": False, "already": True, "user": user.brief()},
                external_ref={"user_id": user.id, "upn": user.upn, "reversible": False},
                verify=VerifyPlan("verified", detail=state.observed()),
            )
        prior = (mapping(ref.get("prior")) if mine else {}) or {
            "riskState": state.risk_state, "riskLevel": state.risk_level,
        }
        result_ref = {"user_id": user.id, "upn": user.upn, "prior": prior, "requested": True, "reversible": True}
        detail: Dict[str, Any] = {
            "summary": summary(f"confirmed {user.upn} as compromised in Identity Protection (user risk high)"),
            "changed": True, "user": user.brief(), "prior": prior,
        }
        if state.risk_state == CONFIRMED:
            # This action's interrupted earlier attempt confirmed it.
            detail["already"] = True
            return ConnectorResult("succeeded", detail, external_ref=result_ref,
                                   verify=VerifyPlan("verified", detail=state.observed()))
        await self.ctx.checkpoint({"user_id": user.id, "prior": prior, "requested": True})
        failure = await self._post("confirmCompromised", user, "confirm as compromised")
        if failure is not None:
            return failure
        return await self._outcome(user, detail, result_ref, dismiss=False)

    async def _dismiss(self, action: ResponseAction) -> ConnectorResult:
        original = self.ctx.original
        oref = dict(original.external_ref or {}) if original is not None else {}
        if original is None or not oref.get("requested") or oref.get("reversible") is False:
            return ConnectorResult(
                "succeeded",
                {"summary": "nothing to undo: the confirmation did not change the user's risk",
                 "changed": False, "error": "rollback_not_needed"},
                external_ref={"reversible": False},
            )
        user: Optional[DirectoryUser] = None
        try:
            user = await self._target(action)
            await screen(self.ctx, user, no_refusals)
            state = await self.read_risk(user.id)
        except Refused as exc:
            return refused_result(exc, user)
        except MicrosoftApiError as exc:
            failure = self._read_refused(exc, user)
            if failure is None:
                raise
            return failure
        prior = mapping(oref.get("prior")) or None
        ref = {"user_id": user.id, "upn": user.upn, "requested": True, "reversible": False}
        detail: Dict[str, Any] = {"changed": True, "user": user.brief(), "note": NOT_RESTORED, "prior": prior}
        if state.cleared:
            mine = bool((action.external_ref or {}).get("requested"))
            detail.update(summary=summary(f"the risk of {user.upn} is already dismissed or none"), already=True,
                          changed=mine)
            return ConnectorResult("succeeded", detail, external_ref=ref,
                                   verify=VerifyPlan("verified", detail=state.observed()))
        await self.ctx.checkpoint({"user_id": user.id, "requested": True})
        failure = await self._post("dismiss", user, "dismiss the risk of")
        if failure is not None:
            return failure
        detail["summary"] = summary(f"dismissed the Identity Protection risk of {user.upn} ({NOT_RESTORED})")
        return await self._outcome(user, detail, ref, dismiss=True)

    # -------------------------------------------------------------------- verify

    async def verify(self, action: ResponseAction) -> VerificationResult:
        user_id = (action.external_ref or {}).get("user_id")
        try:
            if not (isinstance(user_id, str) and odata.is_guid(user_id)):
                user_id = (await resolve_user(self.ctx, action.target)).id
            state = await self.read_risk(user_id)
        except Refused as exc:
            return VerificationResult("inconclusive", {"reason": exc.code})
        done = state.cleared if action.action_type == "dismiss_user_risk" else state.confirmed
        return VerificationResult("verified" if done else "pending", state.observed())

    # --------------------------------------------------------------------- probe

    async def probe(self) -> List[ProbeCheck]:
        return [
            await probe_get(self.ctx, "read risky users", RISKY_USERS_PATH, permission="IdentityRiskyUser.Read.All",
                            params={"$top": "1"}, unlicensed=licence_denied),
        ]


__all__ = ["RiskHandler", "RiskState", "licence_denied", "parse_risky_user"]
