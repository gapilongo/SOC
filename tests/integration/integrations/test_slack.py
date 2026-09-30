"""Slack interactive approvals: signature, replay, user mapping by verified email, and the UI's authorisation rules."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode
from uuid import uuid4

import httpx
import pytest

from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.slack import slack_signature
from lg_sotf.security.crypto import SecretBox
from lg_sotf.services.response import PlanContext, ResponseService
from tests.integration.api.conftest import ApiHarness
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.integrations.conftest import Receiver, add_integration, fake_secret, public_resolver, slack_url
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration

RESPONSE_URL = "https://hooks.slack.com/actions/T0/1/" + "r" * 16
SLACK_USERS: Dict[str, Dict[str, Any]] = {
    "UADMIN": {"email": "boss@tenant-a.example.com", "confirmed": True},
    "UANALYST": {"email": "ana@tenant-a.example.com", "confirmed": True},
    "USHADY": {"email": "boss@tenant-a.example.com", "confirmed": False},
}


def users_info(request: httpx.Request) -> httpx.Response:
    user = SLACK_USERS.get(request.url.params.get("user", ""))
    if user is None:
        return httpx.Response(200, json={"ok": False, "error": "user_not_found"})
    return httpx.Response(200, json={"ok": True, "user": {"id": request.url.params["user"], "is_email_confirmed": user["confirmed"],
                                                          "profile": {"email": user["email"]}}})


async def setup(api: ApiHarness, box: SecretBox, *, interactive: bool = True) -> Tuple[str, Dict[str, str], Receiver]:
    signing = fake_secret("slack-signing")
    integration = await add_integration(
        api.repos, box, TENANT_A, "slack", config={"interactive_approvals": interactive},
        secret={"webhook_url": slack_url(), "signing_secret": signing, "bot_token": fake_secret("bot")},
        events=("action.awaiting_approval",),
    )
    await api.user(TENANT_A, "admin", email="boss@tenant-a.example.com")
    await api.user(TENANT_A, "analyst", email="ana@tenant-a.example.com")
    receiver = Receiver({"GET /api/users.info": users_info})
    api.app.state.integrations_http = IntegrationHttp(api.ctx.settings, transport=httpx.MockTransport(receiver),
                                                      resolver=public_resolver)
    alert_id = await add_alert(api.repos, TENANT_A, entities={"hosts": ["ws-042"]})
    plan = await ResponseService(api.repos, api.ctx.settings).plan(
        TENANT_A, alert_id,
        PlanContext(severity="high", title="t", evidence="analyst", recommended_actions=["isolate_host", "create_ticket"],
                    hosts=["ws-042"], entities={"host": ["ws-042"]}),
    )
    ledger = {a.action_type: str(a.id) for a in (await api.repos.actions.list(TENANT_A, alert_id=alert_id)).items
              if str(a.id) in plan.awaiting}
    path = f"/api/v1/integrations/slack/interactions?tenant={TENANT_A}&integration={integration.id}"
    return path, {"signing": signing, **ledger}, receiver


def click(action_id: str, slack_user: str, *, approve: bool = True) -> bytes:
    # Every Slack click carries its own trigger_id, so two clicks never share a body (or a signature)
    # even within the same second: the replay cache refuses only a true replay.
    payload = {
        "type": "block_actions",
        "trigger_id": uuid4().hex,
        "user": {"id": slack_user, "username": "someone"},
        "team": {"id": "T0"},
        "response_url": RESPONSE_URL,
        "actions": [{"action_id": "lgsotf_approve" if approve else "lgsotf_reject", "value": action_id}],
    }
    return urlencode({"payload": json.dumps(payload)}).encode()


async def post(api: ApiHarness, path: str, body: bytes, secret: str, *, ts: Optional[int] = None,
               signature: Optional[str] = None) -> httpx.Response:
    timestamp = str(ts if ts is not None else int(time.time()))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Slack-Request-Timestamp": timestamp,
        "X-Slack-Signature": signature or slack_signature(secret, timestamp, body),
    }
    return await api.client.post(path, content=body, headers=headers)


async def test_admin_approves_high_risk_action_from_slack(api: ApiHarness, box: SecretBox) -> None:
    path, ids, receiver = await setup(api, box)
    body = click(ids["isolate_host"], "UADMIN")
    response = await post(api, path, body, ids["signing"])
    assert response.status_code == 200, response.text
    action = await api.repos.actions.get(TENANT_A, ids["isolate_host"])
    admin = await api.repos.users.get_by_email(TENANT_A, "boss@tenant-a.example.com")
    assert admin is not None and action.status == "approved" and action.approved_by == str(admin.id)
    audit = {e.action: e for e in (await api.repos.audit.list(TENANT_A, resource_id=ids["isolate_host"])).items}
    assert audit["integration.slack_interaction"].details["outcome"] == "approved"
    assert audit["integration.slack_interaction"].actor_id == str(admin.id)
    assert audit["response_action.approved"].actor_id == str(admin.id)
    reply = [r for r in receiver.requests if r.url.host == "hooks.slack.com"]
    assert json.loads(reply[-1].content)["response_type"] == "ephemeral" and "approved" in json.loads(reply[-1].content)["text"]

    # A true replay (same body, timestamp and signature) is refused.
    first_ts = int(response.request.headers["X-Slack-Request-Timestamp"])
    replay = await post(api, path, body, ids["signing"], signature=response.request.headers["X-Slack-Signature"],
                        ts=first_ts)
    assert replay.status_code == 401
    # A second genuine click (its own body and timestamp) is accepted and changes nothing.
    again = await post(api, path, click(ids["isolate_host"], "UADMIN"), ids["signing"], ts=first_ts - 5)
    assert again.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "approved"
    outcomes = [e.details["outcome"] for e in (await api.repos.audit.list(TENANT_A, action="integration.slack_interaction")).items]
    assert outcomes == ["approved", "approved"]  # the replay was refused before it was audited as a click


async def test_same_authorisation_rules_as_the_ui(api: ApiHarness, box: SecretBox) -> None:
    path, ids, _ = await setup(api, box)
    denied = await post(api, path, click(ids["isolate_host"], "UANALYST"), ids["signing"])
    assert denied.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"
    rejected = await post(api, path, click(ids["create_ticket"], "UANALYST", approve=False), ids["signing"])
    assert rejected.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["create_ticket"])).status == "rejected"
    unverified = await post(api, path, click(ids["isolate_host"], "USHADY"), ids["signing"])
    assert unverified.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"
    outcomes = [e.details["outcome"] for e in (await api.repos.audit.list(TENANT_A, action="integration.slack_interaction")).items]
    assert sorted(outcomes) == ["denied", "rejected", "unmapped_user"]


async def test_unsigned_stale_or_misrouted_requests_are_refused(api: ApiHarness, box: SecretBox) -> None:
    path, ids, _ = await setup(api, box)
    body = click(ids["isolate_host"], "UADMIN")
    assert (await post(api, path, body, fake_secret("wrong"))).status_code == 401
    assert (await post(api, path, body, ids["signing"], ts=int(time.time()) - 400)).status_code == 401
    assert (await api.client.post(path, content=body)).status_code == 401
    other_tenant = path.replace(f"tenant={TENANT_A}", f"tenant={TENANT_B}")
    assert (await post(api, other_tenant, body, ids["signing"])).status_code == 401
    assert (await post(api, path.replace("tenant=tenant-a", "tenant=Bad!"), body, ids["signing"])).status_code == 401
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"


async def test_integration_without_interactivity_accepts_nothing(api: ApiHarness, box: SecretBox) -> None:
    path, ids, _ = await setup(api, box, interactive=False)
    response = await post(api, path, click(ids["isolate_host"], "UADMIN"), ids["signing"])
    assert response.status_code == 401
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"


def _replies(receiver: Receiver) -> List[str]:
    return [json.loads(r.content)["text"] for r in receiver.requests if r.url.host == "hooks.slack.com"]


async def _outcomes(api: ApiHarness) -> List[str]:
    entries = await api.repos.audit.list(TENANT_A, action="integration.slack_interaction")
    return sorted(e.details["outcome"] for e in entries.items)


async def test_tenant_mfa_policy_applies_to_slack_approvals(api: ApiHarness, box: SecretBox) -> None:
    path, ids, receiver = await setup(api, box)
    await api.repos.tenants.update_settings(TENANT_A, {"security": {"require_mfa": True}})
    api.ctx.tenants.invalidate(TENANT_A)
    refused = await post(api, path, click(ids["isolate_host"], "UADMIN"), ids["signing"])
    assert refused.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"
    assert "multi-factor" in _replies(receiver)[-1]
    assert await _outcomes(api) == ["mfa_required"]

    # Once the admin has enrolled, the same click is accepted.
    admin = await api.repos.users.get_by_email(TENANT_A, "boss@tenant-a.example.com")
    assert admin is not None
    await api.repos.user_mfa.set_pending(TENANT_A, admin.id, "pending-ciphertext")
    await api.repos.user_mfa.activate(TENANT_A, admin.id, pending_ciphertext="pending-ciphertext", step=1,
                                      recovery_code_hashes=[])
    accepted = await post(api, path, click(ids["isolate_host"], "UADMIN"), ids["signing"])
    assert accepted.status_code == 200
    assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "approved"


async def test_sso_accounts_need_a_recent_sign_in_to_approve_from_slack(api: ApiHarness, box: SecretBox) -> None:
    path, ids, receiver = await setup(api, box)
    SLACK_USERS["USSO"] = {"email": "sso-admin@tenant-a.example.com", "confirmed": True}
    try:
        sso = await api.repos.users.create(TENANT_A, "sso-admin@tenant-a.example.com", "admin", password_hash=None,
                                           oidc_subject="idp-subject-1")
        # Never signed in, then last signed in beyond integrations.slack_sso_max_age_hours (12): refused.
        refused = await post(api, path, click(ids["isolate_host"], "USSO"), ids["signing"])
        assert refused.status_code == 200 and "single sign-on" in _replies(receiver)[-1]
        await api.repos.users.record_sign_in(TENANT_A, sso.id, now=datetime.now(UTC) - timedelta(hours=13))
        stale = await post(api, path, click(ids["isolate_host"], "USSO"), ids["signing"])
        assert stale.status_code == 200
        assert (await api.repos.actions.get(TENANT_A, ids["isolate_host"])).status == "awaiting_approval"

        await api.repos.users.record_sign_in(TENANT_A, sso.id, now=datetime.now(UTC) - timedelta(hours=1))
        fresh = await post(api, path, click(ids["isolate_host"], "USSO"), ids["signing"])
        assert fresh.status_code == 200
        action = await api.repos.actions.get(TENANT_A, ids["isolate_host"])
        assert action.status == "approved" and action.approved_by == str(sso.id)
        assert await _outcomes(api) == ["approved", "sso_login_required", "sso_login_required"]
    finally:
        SLACK_USERS.pop("USSO", None)
