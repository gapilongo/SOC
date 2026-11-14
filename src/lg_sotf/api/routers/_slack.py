"""Slack interactive approvals for the integrations router: who may decide from Slack, the decision, the reply.

Not a router (the routers-independent contract lists routers only); it stays
in the API layer because the approver check uses :mod:`lg_sotf.api.auth.mfa`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Dict, Optional, Tuple

from lg_sotf.api.auth.mfa import MfaService
from lg_sotf.api.common import reopen_for_approval
from lg_sotf.api.context import ApiContext
from lg_sotf.audit.logger import Actor
from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.repos import ResponseAction, User
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp
from lg_sotf.integrations.slack import Interaction, outcome_text, verified_email
from lg_sotf.models.vocabulary import REVIEWER_ROLES
from lg_sotf.services.review import ReviewDenied, enqueue_resumes

#: The reply for each outcome that is not an action status (``sso_login_required`` names the configured window).
OUTCOME_MESSAGES: Dict[str, str] = {
    "unmapped_user": "LG-SOTF: your Slack account is not linked to an active analyst or admin of this tenant "
    "(the verified Slack email must match an LG-SOTF user).",
    "denied": "LG-SOTF: your role may not decide this action (high and critical risk need an admin).",
    "not_pending": "LG-SOTF: this action is no longer awaiting approval.",
    "not_found": "LG-SOTF: this action no longer exists.",
    "slack_api_error": "LG-SOTF: your Slack user could not be looked up; check the bot token and its users:read.email scope.",
    "mfa_required": "LG-SOTF: this tenant requires multi-factor authentication. Enroll an authenticator in the "
    "LG-SOTF web app before approving or rejecting actions from Slack.",
}


async def slack_approver_refusal(ctx: ApiContext, user: User) -> Optional[str]:
    """Why ``user`` may not decide actions from Slack, where no LG-SOTF sign-in happens (``None``: allowed).

    * ``mfa_required``: MFA policy applies to the account (tenant ``security.require_mfa``) and it has not
      enrolled; the web app would not let it past sign-in either.
    * ``sso_login_required``: an SSO (OIDC-provisioned) account whose last sign-in is older than
      ``integrations.slack_sso_max_age_hours``, so an identity disabled at the IdP stops approving soon after.
    """
    if user.oidc_subject is None:
        mfa = MfaService(ctx)
        state = await mfa.state(user)
        if not (state is not None and state.enabled) and await mfa.required_for(user):
            return "mfa_required"
        return None
    max_age = timedelta(hours=ctx.settings.integrations.slack_sso_max_age_hours)
    if user.last_login_at is None or datetime.now(UTC) - user.last_login_at > max_age:
        return "sso_login_required"
    return None


async def decide_from_slack(
    ctx: ApiContext, http: IntegrationHttp, bot_token: str, tenant: str, interaction: Interaction
) -> Tuple[Optional[User], Optional[ResponseAction], str]:
    """Approve or reject the clicked action as the Slack user's verified LG-SOTF account: ``(user, acted, outcome)``.

    ``outcome`` is the action's new status, or why nothing was decided (a key of :data:`OUTCOME_MESSAGES`,
    or ``sso_login_required``). ``user`` is the matched account, ``acted`` the action once decided.
    """
    user = None
    acted = None
    outcome = "unmapped_user"
    try:
        email = await verified_email(http, bot_token, interaction.slack_user_id)
        found = await ctx.repos.users.get_by_email(tenant, email) if email else None
        if found is not None and found.is_active and found.role in REVIEWER_ROLES:
            user = found
            refusal = await slack_approver_refusal(ctx, found)
            if refusal is not None:
                outcome = refusal
            else:
                review = ctx.review.approve_actions if interaction.approve else ctx.review.reject_actions
                resumes = await review(tenant, [interaction.action_id], found.id, found.role)
                await enqueue_resumes(ctx.queue, tenant, resumes)
                acted = await ctx.repos.actions.get(tenant, interaction.action_id)
                outcome = acted.status
                if interaction.approve:
                    await reopen_for_approval(ctx, tenant, acted, Actor("user", str(found.id)))
    except ReviewDenied:
        outcome = "denied"
    except InvalidTransition:
        outcome = "not_pending"
    except NotFound:
        outcome = "not_found"
    except DeliveryError:
        outcome = "slack_api_error"
    return user, acted, outcome


def reply_text(ctx: ApiContext, approve: bool, outcome: str, acted: Optional[ResponseAction]) -> str:
    """The ephemeral reply to the Slack user for ``outcome``."""
    if outcome == "sso_login_required":
        return (
            "LG-SOTF: sign in to the LG-SOTF web app with single sign-on (at least every "
            f"{ctx.settings.integrations.slack_sso_max_age_hours:g} hours) before approving or rejecting actions from Slack."
        )
    return OUTCOME_MESSAGES.get(outcome) or outcome_text(
        approve, outcome, {"type": acted.action_type, "target": acted.target} if acted is not None else {}
    )
