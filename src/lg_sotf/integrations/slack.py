"""Slack interactive approvals: request verification, user mapping and the approval itself.

A Slack integration with ``config.interactive_approvals`` adds Approve and
Reject buttons to ``action.awaiting_approval`` messages. Slack posts clicks
to ``POST /api/v1/integrations/slack/interactions?tenant=<id>&integration=<id>``
(the app's Interactivity Request URL). Each request is:

1. verified with the app's signing secret: ``X-Slack-Signature`` is
   ``v0=<hex>`` HMAC-SHA256 over ``"v0:<X-Slack-Request-Timestamp>:<raw body>"``,
   compared in constant time; timestamps more than five minutes away are
   refused, and a signature already seen is refused (replay cache in Redis);
2. mapped to an LG-SOTF user: the clicking Slack user's email is read with
   the app's bot token (``users.info``, scope ``users:read.email``) and used
   only when Slack reports it confirmed; it must belong to an active user of
   the integration's tenant;
3. applied through the same service call as the UI
   (:meth:`~lg_sotf.services.review.ReviewService.approve_actions` /
   ``reject_actions``), so the same authorisation holds: analysts approve low
   and medium risk, admins also high and critical, nobody what the tenant's
   autonomy policy disables. Approving an approved action (a double click)
   changes nothing.

Every attempt that passes signature verification is audited
(``integration.slack_interaction``) with the Slack user and the outcome.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib.parse import parse_qs
from uuid import UUID

import httpx

from lg_sotf.integrations.http import DeliveryError, IntegrationHttp

SIGNATURE_VERSION = "v0"
TOLERANCE_S = 300
REPLAY_TTL_S = 600
SLACK_API = "https://slack.com/api"
RESPONSE_URL_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
APPROVE = "lgsotf_approve"
REJECT = "lgsotf_reject"
MAX_BODY_BYTES = 64 * 1024


class SlackRequestError(ValueError):
    """The interaction is malformed or not for us (message is safe to show in Slack)."""


def slack_signature(secret: str, timestamp: str, body: bytes) -> str:
    base = f"{SIGNATURE_VERSION}:{timestamp}:".encode() + body
    return f"{SIGNATURE_VERSION}=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


def verify_slack_request(
    secret: str,
    timestamp: Optional[str],
    body: bytes,
    signature: Optional[str],
    *,
    now: Optional[float] = None,
    tolerance_s: int = TOLERANCE_S,
) -> bool:
    """Slack's v0 request signing, with a timestamp window against replays of old requests."""
    if not secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    return hmac.compare_digest(slack_signature(secret, timestamp, body), signature)


def replay_key(prefix: str, tenant_id: str, signature: str) -> str:
    return f"{prefix}:t:{tenant_id}:slack:replay:{hashlib.sha256(signature.encode()).hexdigest()[:32]}"


@dataclass(frozen=True)
class Interaction:
    approve: bool
    action_id: UUID
    slack_user_id: str
    slack_team_id: Optional[str]
    response_url: Optional[str]


def parse_interaction(body: bytes) -> Interaction:
    """The button click in a ``block_actions`` payload (form-encoded ``payload=<json>``)."""
    try:
        form = parse_qs(body.decode("utf-8"), strict_parsing=False, max_num_fields=10)
        payload = json.loads(form.get("payload", [""])[0])
    except (UnicodeDecodeError, ValueError) as exc:
        raise SlackRequestError("malformed interaction payload") from exc
    if not isinstance(payload, dict) or payload.get("type") != "block_actions":
        raise SlackRequestError("only button clicks (block_actions) are supported")
    actions = payload.get("actions")
    if not isinstance(actions, list) or not actions or not isinstance(actions[0], Mapping):
        raise SlackRequestError("the interaction has no action")
    action = actions[0]
    action_type = action.get("action_id")
    if action_type not in (APPROVE, REJECT):
        raise SlackRequestError("not an LG-SOTF approval button")
    try:
        action_id = UUID(str(action.get("value")))
    except ValueError as exc:
        raise SlackRequestError("the button does not name an action") from exc
    user = payload.get("user") if isinstance(payload.get("user"), Mapping) else {}
    slack_user = str((user or {}).get("id") or "")
    if not slack_user or len(slack_user) > 64:
        raise SlackRequestError("the interaction has no Slack user")
    team = payload.get("team") if isinstance(payload.get("team"), Mapping) else {}
    response_url = payload.get("response_url")
    return Interaction(
        approve=action_type == APPROVE,
        action_id=action_id,
        slack_user_id=slack_user,
        slack_team_id=str((team or {}).get("id") or "") or None,
        response_url=response_url if isinstance(response_url, str) else None,
    )


async def verified_email(http: IntegrationHttp, bot_token: str, slack_user_id: str) -> Optional[str]:
    """The Slack user's email when Slack says it is confirmed (``users:read.email``), else ``None``."""
    result = await http.request(
        "GET",
        f"{SLACK_API}/users.info",
        params={"user": slack_user_id},
        headers={"Authorization": f"Bearer {bot_token}"},
        retries=1,
    )
    data = result.json()
    if not isinstance(data, dict) or not data.get("ok"):
        error = data.get("error") if isinstance(data, dict) else None
        raise DeliveryError(f"Slack users.info failed ({str(error)[:60]})", retryable=False, code="slack_api")
    user = data.get("user") if isinstance(data.get("user"), Mapping) else {}
    if not (user or {}).get("is_email_confirmed") or (user or {}).get("deleted"):
        return None
    profile = (user or {}).get("profile") if isinstance((user or {}).get("profile"), Mapping) else {}
    email = (profile or {}).get("email")
    return email.strip().lower() if isinstance(email, str) and "@" in email else None


async def reply(http: IntegrationHttp, response_url: Optional[str], text: str) -> None:
    """Best-effort ephemeral reply to the clicking user (only to Slack's own response URLs)."""
    if not response_url:
        return
    try:
        if httpx.URL(response_url).host not in RESPONSE_URL_HOSTS:
            return
        await http.request(
            "POST", response_url, json_body={"response_type": "ephemeral", "replace_original": False, "text": text[:2_000]}
        )
    except (DeliveryError, httpx.InvalidURL):
        return


def outcome_text(approve: bool, status: str, action: Mapping[str, Any]) -> str:
    verb = "approved" if approve else "rejected"
    return f"LG-SOTF: {action.get('type', 'action')} on {action.get('target', '?')} {verb} ({status})."
