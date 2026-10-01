"""The privileged-target guard: LG-SOTF never contains an Entra administrator (or a protected user) by itself.

:func:`screen` runs before every write of the Entra package: the
capability's own refusals, then :func:`ensure_not_protected` (the resolved
user's UPN, mail and object id against the tenant's protected assets: the
guardrails only saw the literal target, which may be an alias or an object
id), then :func:`ensure_not_privileged`.

:func:`ensure_not_privileged` runs before every write of the Entra package
(also the rollbacks ``enable_user`` and ``dismiss_user_risk``) and refuses,
with ``privileged_target_refused``, a user who

1. holds an active directory role assignment
   (``GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '<id>'``),
   ``reason: directory_role``;
2. is a member of a role-assignable group (``isAssignableToRole``;
   ``role_assignable_group``) or of a restricted management administrative
   unit (``isMemberManagementRestricted``; ``restricted_admin_unit``), read
   from ``GET /v1.0/users/{id}/memberOf`` (an activated directory role in
   ``memberOf`` also counts as ``directory_role``);
3. owns a role-assignable group (``GET /v1.0/users/{id}/ownedObjects``;
   ``role_assignable_group_owner``).

Why: only a Privileged Authentication Administrator or a Global
Administrator may disable, reset or revoke such users, and nobody but a role
scoped to the unit may change a member of a restricted management unit
(application permissions do not apply there). Holding those roles would make
the SOC daemon a Tier-0 identity; refusing and escalating to a human is
safer, so the app gets **User Administrator** only.

The guard fails closed: any 403, missing property (``GroupMember.Read.All``
lets Graph return ``isAssignableToRole``; without it directory objects come
back with an id only), unreadable answer or more than
:data:`MAX_DIRECTORY_OBJECTS` memberships gives
``privileged_guard_unavailable`` and nothing is written. A 403 is never
retried. Token failures and throttling propagate unchanged (the connector
reports the credential error or defers the action; nothing is written
either way).

Known gap: PIM-*eligible* roles that are not activated are not returned by
``roleAssignments`` and are not seen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Mapping

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.capability import HandlerContext
from lg_sotf.integrations.microsoft.entra.users import DirectoryUser, Refused
from lg_sotf.integrations.microsoft.http import MicrosoftApiError

if TYPE_CHECKING:
    from lg_sotf.db.repos import ResponseAction

ROLE_ASSIGNMENTS_PATH = "/v1.0/roleManagement/directory/roleAssignments"
MAX_DIRECTORY_OBJECTS = 2_000
GROUP = "#microsoft.graph.group"
ADMINISTRATIVE_UNIT = "#microsoft.graph.administrativeUnit"
DIRECTORY_ROLE = "#microsoft.graph.directoryRole"
PRIVILEGED_HINT = (
    "privileged users are refused on purpose: a human with the Privileged Authentication Administrator role "
    "(or a role scoped to the restricted administrative unit) must act"
)
PROTECTED_HINT = (
    "the target resolved to a user on the tenant's protected assets list (response settings); a human must act"
)
UNAVAILABLE_HINT = (
    "grant RoleManagement.Read.Directory and GroupMember.Read.All (admin consent); the guard fails closed"
)
_SUMMARIES: Mapping[str, str] = {
    "directory_role": "holds a Microsoft Entra directory role",
    "role_assignable_group": "is a member of a role-assignable group",
    "restricted_admin_unit": "is a member of a restricted management administrative unit",
    "role_assignable_group_owner": "owns a role-assignable group",
}


def _refuse(user: DirectoryUser, reason: str, **detail: Any) -> Refused:
    return Refused(
        "privileged_target_refused",
        f"refused: {user.upn} {_SUMMARIES[reason]}",
        {"reason": reason, **detail},
        hint=PRIVILEGED_HINT,
    )


def _unavailable(step: str, reason: str, **detail: Any) -> Refused:
    return Refused(
        "privileged_guard_unavailable",
        f"refused: the privileged-target check could not read {step} ({reason})",
        {"reason": reason, "step": step, **detail},
        hint=UNAVAILABLE_HINT,
        retryable=reason not in ("forbidden", "incomplete_read", "too_many_objects"),
    )


async def _read(ctx: HandlerContext, step: str, path: str, params: Mapping[str, str], limit: int) -> List[Dict[str, Any]]:
    try:
        return await ctx.api("graph").pages(path, params=params, max_items=limit, deadline=ctx.deadline)
    except (MicrosoftAuthError, odata.InvalidTarget):
        raise
    except MicrosoftApiError as exc:
        if exc.kind == "throttled":
            raise
        reason = "forbidden" if exc.kind == "forbidden" else exc.ledger_error
        raise _unavailable(step, reason, http_status=exc.status or None, ms_code=exc.code or None) from None


def _flag(item: Mapping[str, Any], name: str, step: str) -> bool:
    """A Boolean property of a directory object; absent means Graph did not let us see it (fail closed)."""
    if name not in item:
        raise _unavailable(step, "incomplete_read", missing=name)
    return item[name] is True


async def ensure_not_privileged(ctx: HandlerContext, user: DirectoryUser) -> None:
    """Raise :class:`~lg_sotf.integrations.microsoft.entra.users.Refused` unless ``user`` is safe to act on."""
    assignments = await _read(
        ctx, "role_assignments", ROLE_ASSIGNMENTS_PATH,
        {"$filter": odata.odata_eq("principalId", user.id), "$select": "id,roleDefinitionId"}, 1,
    )
    if assignments:
        raise _refuse(user, "directory_role")
    memberships = await _read(
        ctx, "member_of", f"{user.path}/memberOf",
        {"$select": "id,isAssignableToRole,isMemberManagementRestricted"}, MAX_DIRECTORY_OBJECTS + 1,
    )
    if len(memberships) > MAX_DIRECTORY_OBJECTS:
        raise _unavailable("member_of", "too_many_objects", limit=MAX_DIRECTORY_OBJECTS)
    for item in memberships:
        kind = item.get("@odata.type")
        if not isinstance(kind, str):
            raise _unavailable("member_of", "incomplete_read", missing="@odata.type")
        if kind == DIRECTORY_ROLE:
            raise _refuse(user, "directory_role")
        if kind == GROUP and _flag(item, "isAssignableToRole", "member_of"):
            raise _refuse(user, "role_assignable_group")
        if kind == ADMINISTRATIVE_UNIT and _flag(item, "isMemberManagementRestricted", "member_of"):
            raise _refuse(user, "restricted_admin_unit")
    owned = await _read(
        ctx, "owned_objects", f"{user.path}/ownedObjects", {"$select": "id,isAssignableToRole"},
        MAX_DIRECTORY_OBJECTS + 1,
    )
    if len(owned) > MAX_DIRECTORY_OBJECTS:
        raise _unavailable("owned_objects", "too_many_objects", limit=MAX_DIRECTORY_OBJECTS)
    for item in owned:
        kind = item.get("@odata.type")
        if not isinstance(kind, str):
            raise _unavailable("owned_objects", "incomplete_read", missing="@odata.type")
        if kind == GROUP and _flag(item, "isAssignableToRole", "owned_objects"):
            raise _refuse(user, "role_assignable_group_owner")


def ensure_not_protected(ctx: HandlerContext, user: DirectoryUser) -> None:
    """Refuse (``protected_asset``) a resolved user whose UPN, mail or object id is a protected asset.

    The guardrails matched only the literal target; an alias, a proxy
    address or an object id resolves here to a user they never saw. A
    rollback of a restorative type (``enable_user``, ``dismiss_user_risk``)
    is exempt, as in the guardrails (``ctx.protected`` answers ``None``).
    """
    for name, value in (("upn", user.upn), ("mail", user.mail), ("id", user.id)):
        if not value:
            continue
        category = ctx.protected("user", value)
        if category is not None:
            raise Refused(
                "protected_asset",
                f"refused: {user.upn} is on the tenant's protected assets list",
                {"reason": "protected_asset", "category": category, "matched": name},
                hint=PROTECTED_HINT,
            )


async def screen(ctx: HandlerContext, user: DirectoryUser, refusals: Callable[[DirectoryUser], None]) -> None:
    """The capability's own refusals (guests, synced users), the protected assets, then the privileged-target guard."""
    refusals(user)
    ensure_not_protected(ctx, user)
    await ensure_not_privileged(ctx, user)


async def rehearsal(
    ctx: HandlerContext,
    action: ResponseAction,
    user: DirectoryUser,
    would_execute: Mapping[str, str],
    refusals: Callable[[DirectoryUser], None],
) -> Dict[str, Any]:
    """What a rehearsal reports: the resolved user and whether the checks would let the write through (GETs only)."""
    guard: Any = "passed"
    try:
        await screen(ctx, user, refusals)
    except Refused as exc:
        guard = {"refused": exc.code, **exc.detail}
    verdict = "would" if guard == "passed" else "would refuse to"
    return {
        "summary": f"rehearsal: {verdict} run {action.action_type} on {user.upn}"[:200],
        "would_execute": dict(would_execute),
        "user": user.describe(),
        "guard": guard,
    }


def unresolved(action: ResponseAction, exc: Refused, would_execute: Mapping[str, str]) -> Dict[str, Any]:
    """What a rehearsal reports when the target user could not be resolved (``not_found``, ``ambiguous_target``)."""
    return {
        "summary": f"rehearsal: {exc.summary}"[:200],
        "would_execute": dict(would_execute),
        "user": None,
        "guard": "not_run",
        "refused": exc.code,
        **exc.detail,
    }


def no_refusals(user: DirectoryUser) -> None:
    """For actions every non-privileged user may undergo."""


__all__ = [
    "MAX_DIRECTORY_OBJECTS",
    "ensure_not_privileged",
    "ensure_not_protected",
    "no_refusals",
    "rehearsal",
    "screen",
    "unresolved",
]
