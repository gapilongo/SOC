"""The Entra ID capabilities: ``entra.account``, ``entra.sessions``, ``entra.password`` and ``entra.risk``.

All four use Microsoft Graph v1.0 only (no beta endpoint) and exist in every
supported cloud. Every write is preceded by the privileged-target guard
(:mod:`~lg_sotf.integrations.microsoft.entra.guard`), which needs
``RoleManagement.Read.Directory`` and ``GroupMember.Read.All``; resolving the
user needs ``User.Read.All``. The service principal gets the **User
Administrator** directory role at tenant scope (app-only changes of
``accountEnabled`` and ``passwordProfile`` require an administrator role),
never Privileged Authentication Administrator or Global Administrator:
privileged targets are refused and escalated to a human on purpose.
``docs/microsoft-entra.md`` is the operator documentation.
"""

from __future__ import annotations

from lg_sotf.integrations.microsoft.capability import ActionSupport, CapabilitySpec, NoOptions, Permission
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS
from lg_sotf.integrations.microsoft.entra.account import AccountHandler, EntraAccountOptions
from lg_sotf.integrations.microsoft.entra.password import EntraPasswordOptions, PasswordHandler
from lg_sotf.integrations.microsoft.entra.risk import RiskHandler
from lg_sotf.integrations.microsoft.entra.sessions import SessionsHandler

USER_ADMINISTRATOR = "User Administrator"

RESOLVE = Permission("graph", "User.Read.All", "resolve the user")
GUARD_ROLES = Permission("graph", "RoleManagement.Read.Directory", "privileged-target guard")
GUARD_GROUPS = Permission("graph", "GroupMember.Read.All", "privileged-target guard")

ENTRA_ACCOUNT = CapabilitySpec(
    key="entra.account",
    package="entra",
    api="graph",
    title="Disable and re-enable accounts",
    description=(
        "Disables a compromised user's Microsoft Entra ID account (PATCH accountEnabled=false), proves it by "
        "re-reading the account, and re-enables it as the rollback. Privileged users are refused."
    ),
    actions={"disable_user": ActionSupport(reversible=True), "enable_user": ActionSupport()},
    permissions=(
        Permission(
            "graph", "User.EnableDisableAccount.All", "disable and enable the account",
            directory_role=USER_ADMINISTRATOR,
        ),
        RESOLVE,
        GUARD_ROLES,
        GUARD_GROUPS,
    ),
    options=EntraAccountOptions,
    handler=AccountHandler,
    clouds=ALL_CLOUDS,
    live_confirmation=(
        "Disabling a synced (hybrid) account is temporary: Entra Connect re-enables it unless the on-premises "
        "account is disabled too."
    ),
)

ENTRA_SESSIONS = CapabilitySpec(
    key="entra.sessions",
    package="entra",
    api="graph",
    title="Revoke sign-in sessions",
    description=(
        "Invalidates a user's refresh tokens and browser session cookies (revokeSignInSessions) and proves it "
        "from signInSessionsValidFromDateTime. Guests and privileged users are refused."
    ),
    actions={
        "revoke_sessions": ActionSupport(
            note="existing access tokens stay valid until they expire (about 1 h) unless the app supports CAE"
        )
    },
    permissions=(
        Permission("graph", "User.RevokeSessions.All", "revoke refresh tokens and session cookies"),
        RESOLVE,
        GUARD_ROLES,
        GUARD_GROUPS,
    ),
    options=NoOptions,
    handler=SessionsHandler,
    clouds=ALL_CLOUDS,
)

ENTRA_PASSWORD = CapabilitySpec(
    key="entra.password",
    package="entra",
    api="graph",
    title="Reset passwords",
    description=(
        "Sets a random password nobody knows and forces a change at next sign-in, so a stolen password stops "
        "working. Guests, synced and privileged users are refused."
    ),
    actions={"reset_password": ActionSupport(note="the old password cannot be restored")},
    permissions=(
        Permission(
            "graph", "User-PasswordProfile.ReadWrite.All", "reset the password and require a change",
            directory_role=USER_ADMINISTRATOR,
        ),
        RESOLVE,
        GUARD_ROLES,
        GUARD_GROUPS,
    ),
    options=EntraPasswordOptions,
    handler=PasswordHandler,
    clouds=ALL_CLOUDS,
    live_confirmation=(
        "The user is locked out until the helpdesk issues a new password or a Temporary Access Pass."
    ),
)

ENTRA_RISK = CapabilitySpec(
    key="entra.risk",
    package="entra",
    api="graph",
    title="Confirm compromised (ID Protection)",
    description=(
        "Confirms a user as compromised in Microsoft Entra ID Protection (user risk high, so risk-based "
        "Conditional Access applies); the rollback dismisses the user's risk."
    ),
    actions={
        "confirm_compromised": ActionSupport(
            reversible=True, note="undo dismisses the user's risk; it cannot restore the earlier risk state"
        ),
        "dismiss_user_risk": ActionSupport(),
    },
    permissions=(
        Permission("graph", "IdentityRiskyUser.ReadWrite.All", "confirm compromised and dismiss risk"),
        Permission("graph", "IdentityRiskyUser.Read.All", "read the user's risk (the read lists only this permission)"),
        RESOLVE,
        GUARD_ROLES,
        GUARD_GROUPS,
    ),
    options=NoOptions,
    handler=RiskHandler,
    clouds=ALL_CLOUDS,
    licence="Microsoft Entra ID P2 (or Entra Suite)",
)

__all__ = ["ENTRA_ACCOUNT", "ENTRA_PASSWORD", "ENTRA_RISK", "ENTRA_SESSIONS"]
