"""ARCH-E4.1d/e: a generated cross-tenant leak suite over every route, the WebSocket channel and every MCP tool.

Tenants: the MSSP organisation ``ORG``; a customer ``GRANTED`` that gave it
an admin grant (API keys allowed); a ``VICTIM`` whose only live grants are a
viewer grant to ``OTHER_ORG`` and a viewer grant to one ORG member
(``insider``); and ``SUSPENDED``, an organisation with a grant to GRANTED
whose own tenant is suspended. The victim's rows carry a marker string.

Each persona calls every operation of the OpenAPI contract as it is when the
test runs (path ids are the victim's own; the body is the minimal valid body
built from the contract, :mod:`tests.integration.api._bodies`), the evidence
pack as HTML, every registered MCP tool, the WebSocket channel at both paths
and the Slack interactions route with a valid signature. A route added later
is covered without editing this file; a new path parameter or MCP tool makes
it fail until its value is added here.

A leak is a response carrying the marker or a victim ``tenant_id``, a
persona that must be refused answering anything but 403, or any change to
the victim's rows (its audit chain included, access entries aside).
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlencode
from uuid import uuid4

import httpx
import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from lg_sotf.db.repos import NewAlert
from lg_sotf.domain.pov import plan_windows
from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.slack import slack_signature
from lg_sotf.mcp.base import ToolContext
from lg_sotf.mcp.client import LgSotfApiClient
from lg_sotf.mcp.runs import RunStore
from lg_sotf.mcp.tools import TOOLS, call_tool, parse_arguments
from lg_sotf.queue.events import make_event
from tests.integration.api._bodies import request_body
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, recv_json, serve_api
from tests.integration.db._support import TENANT_TABLES, new_alert
from tests.integration.integrations._support import Receiver, public_resolver, slack_url

pytestmark = pytest.mark.integration

ORG = "mssp-org"
OTHER_ORG = "other-mssp"
SUSPENDED = "suspended-mssp"
GRANTED = TENANT_A
VICTIM = TENANT_B
MARKER = "victim-marker-7f3a"
API = "/api/v1"
# Revokes the caller's own token: it would end the run, and it touches no tenant data.
SKIPPED = {("POST", f"{API}/auth/logout")}
# Reached without the principal (credentials in the body, a cookie or a Slack signature): X-Tenant-ID means nothing.
PUBLIC = {
    ("POST", f"{API}/auth/login"), ("POST", f"{API}/auth/refresh"), ("POST", f"{API}/auth/mfa/verify"),
    ("POST", f"{API}/integrations/slack/interactions"), ("POST", f"{API}/auth/break-glass"),
}
LATER = datetime.now(UTC) + timedelta(days=1)


def _tenant_ids(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "tenant_id" and isinstance(item, str):
                yield item
            else:
                yield from _tenant_ids(item)
    elif isinstance(value, list):
        for item in value:
            yield from _tenant_ids(item)


def _leaks(text: str) -> bool:
    if MARKER in text:
        return True
    try:
        body = json.loads(text)
    except ValueError:
        return False
    return VICTIM in set(_tenant_ids(body))


async def _grant(api: ApiHarness, tenant_id: str, org: str, role: str, **kw: Any) -> Any:
    return await api.repos.grants.create(
        tenant_id, org, role, reason=kw.pop("reason", "cover"), created_by="customer-admin",
        expires_at=kw.pop("expires_at", LATER), **kw,
    )


async def _seed_victim(api: ApiHarness) -> Dict[str, str]:
    """A row of every kind a route addresses by id, each carrying the marker."""
    alert: NewAlert = new_alert(title=f"{MARKER} alert", raw={"note": MARKER}, normalized={"title": MARKER})
    await api.repos.alerts.insert_many_if_absent(VICTIM, [alert])
    escalation, _ = await api.repos.escalations.create_or_attach(
        VICTIM, alert.id, reason=MARKER, sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    action, _ = await api.repos.actions.propose(
        VICTIM, alert.id, "block_ip", "203.0.113.77", "low", status="awaiting_approval"
    )
    source = await api.repos.sources.create(VICTIM, "webhook", f"{MARKER} hook", config={"format": "generic"})
    rule = await api.repos.suppressions.create(VICTIM, f"{MARKER} rule", {"title": MARKER})
    integration = await api.repos.integrations.create(VICTIM, "email", f"{MARKER} mail", config={"recipients": ["a@b.co"]})
    user = await api.user(VICTIM, "admin", email=f"{MARKER}@victim.example.com")
    key, _ = await api.api_key(VICTIM, ["read"])
    await api.repos.tenants.create(OTHER_ORG, "Other MSSP")
    await api.repos.organisations.upsert(OTHER_ORG, "Other MSSP")
    grant = await _grant(api, VICTIM, OTHER_ORG, "viewer", reason=MARKER)
    await api.repos.audit.append(VICTIM, "user", str(user.id), "alert.viewed", "alert", alert.id, {"m": MARKER})
    now = datetime.now(UTC)
    await api.repos.blind_audit.create_run(
        VICTIM, since=now - timedelta(days=7), until=now, seed=1, sample_rate=0.02, min_sample=0, fixed_size=None,
        frame_size=1, items=[(alert.id, 1, "benign")], trigger="cli", created_by=MARKER,
    )
    item = (await api.repos.blind_audit.list_items(VICTIM)).items[0]
    pov = await api.repos.pov_runs.create(
        VICTIM, f"{MARKER} pov", plan_windows(now, backtest_days=30, shadow_days=14), created_by=MARKER
    )
    return {
        "alert_id": alert.id, "escalation_id": escalation.id, "action_id": str(action.id), "source_id": source.id,
        "rule_id": rule.id, "integration_id": str(integration.id), "user_id": str(user.id), "key_id": str(key.id),
        "grant_id": str(grant.id), "tenant_id": VICTIM, "item_id": str(item.id), "run_id": "shr_" + "0" * 32,
        "pov_run_id": str(pov.id),
    }


async def _member(api: ApiHarness, org: str, role: str = "admin") -> Any:
    user = await api.user(org, role)
    await api.repos.organisations.add_member(org, user.id)
    return user


async def _personas(api: ApiHarness) -> Tuple[Dict[str, Dict[str, str]], Set[str], Set[str]]:
    """Headers per persona, the personas refused everywhere (403), and the legitimate victim viewers."""
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await _member(api, ORG)
    await _grant(api, GRANTED, ORG, "admin", allow_api_keys=True)
    key = {"X-API-Key": (await api.client.post(
        f"{API}/api-keys", json={"name": "ops", "scopes": ["read", "write", "ingest"]}, headers=api.auth(staff)
    )).json()["key"]}
    insider = await _member(api, ORG, "viewer")
    await _grant(api, VICTIM, ORG, "viewer", user_id=insider.id, allow_api_keys=True)  # personal: never for keys
    revoked_holder, expired_holder = await _member(api, ORG), await _member(api, ORG)
    revoked = await _grant(api, VICTIM, ORG, "admin", user_id=revoked_holder.id)
    await api.repos.grants.revoke(VICTIM, revoked.id, revoked_by="victim-admin")
    past = datetime.now(UTC) - timedelta(days=2)
    await _grant(api, VICTIM, ORG, "admin", user_id=expired_holder.id, now=past, expires_at=past + timedelta(hours=1))
    non_member = await api.user(ORG, "admin")
    await api.repos.tenants.create(SUSPENDED, "Suspended MSSP")
    await api.repos.organisations.upsert(SUSPENDED, "Suspended MSSP")
    suspended = await _member(api, SUSPENDED)
    await _grant(api, GRANTED, SUSPENDED, "admin")
    await api.repos.tenants.set_status(SUSPENDED, "suspended")
    grantee = await _member(api, OTHER_ORG, "admin")  # the victim's real grantee, with a viewer grant
    customer = await api.login_headers(GRANTED, "admin")
    member = api.auth(staff)
    personas = {
        "member->victim": {**member, "X-Tenant-ID": VICTIM},
        "member->granted": {**member, "X-Tenant-ID": GRANTED},
        "org key->victim": {**key, "X-Tenant-ID": VICTIM},
        "org key->granted": {**key, "X-Tenant-ID": GRANTED},
        "revoked holder->victim": {**api.auth(revoked_holder), "X-Tenant-ID": VICTIM},
        "expired holder->victim": {**api.auth(expired_holder), "X-Tenant-ID": VICTIM},
        "non-member->victim": {**api.auth(non_member), "X-Tenant-ID": VICTIM},
        "non-member->granted": {**api.auth(non_member), "X-Tenant-ID": GRANTED},
        "suspended org->granted": {**api.auth(suspended), "X-Tenant-ID": GRANTED},
        "customer admin": customer,
        "customer admin->victim": {**customer, "X-Tenant-ID": VICTIM},
        "grantee viewer->victim": {**api.auth(grantee), "X-Tenant-ID": VICTIM},
        "insider viewer->victim": {**api.auth(insider), "X-Tenant-ID": VICTIM},
    }
    refused = {name for name in personas if name.endswith("->victim")} | {"non-member->granted", "suspended org->granted"}
    viewers = {"grantee viewer->victim", "insider viewer->victim"}
    return personas, refused - viewers, viewers


async def _victim_state(api: ApiHarness) -> Dict[str, str]:
    """A digest of every victim row per tenant table; access entries of its legitimate viewers aside."""
    state: Dict[str, str] = {}
    async with api.ctx.db.system_tx() as conn:
        for table in TENANT_TABLES:
            # Entries the victim's legitimate viewers cause (their access, an evidence export) are theirs to cause.
            access = (
                " AND action <> 'grant.tenant_access' AND NOT details ? 'delegation'" if table == "audit_log" else ""
            )
            state[table] = await conn.fetchval(
                f"SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM {table} t "  # noqa: S608
                f"WHERE tenant_id = $1{access}",
                VICTIM,
            )
    return state


def _operations(api: ApiHarness, ids: Dict[str, str]) -> List[Tuple[str, str, str, Optional[Any], Dict[str, str]]]:
    """Every (method, template, URL, body, query) of the API contract, ids filled with the victim's."""
    spec = api.app.openapi()
    found: List[Tuple[str, str, str, Optional[Any], Dict[str, str]]] = []
    for path, operations in spec["paths"].items():
        if not path.startswith(API):
            continue
        for method in operations:
            if (method.upper(), path) in SKIPPED:
                continue
            url = path.format(**ids)  # a new path parameter raises KeyError here
            found.append((method.upper(), path, url, request_body(spec, path, method), {}))
    evidence = f"{API}/alerts/{{alert_id}}/evidence"
    found.append(("GET", evidence, evidence.format(**ids), None, {"format": "html"}))
    return found


async def test_cross_tenant_leak(api: ApiHarness) -> None:
    ids = await _seed_victim(api)
    personas, refused, viewers = await _personas(api)
    before = await _victim_state(api)
    operations = _operations(api, ids)
    assert len(operations) > 100

    leaks: List[str] = []
    for name, headers in personas.items():
        for method, template, url, body, query in operations:
            response = await api.client.request(method, url, json=body, params=query, headers=headers)
            public = (method, template) in PUBLIC
            if name in viewers and (method == "GET" or public):
                continue  # the victim let these organisations read it
            if _leaks(response.text):
                leaks.append(f"{name} {method} {url}: {response.status_code} {response.text[:200]}")
            if not public and (name in refused or name in viewers) and response.status_code != 403:
                leaks.append(f"{name} {method} {url}: answered {response.status_code}, not 403")

    assert leaks == []
    assert await _victim_state(api) == before


def _click(action_id: str) -> bytes:
    payload = {
        "type": "block_actions", "trigger_id": uuid4().hex, "user": {"id": "UGRANTED", "username": "someone"},
        "team": {"id": "T0"}, "response_url": "https://hooks.slack.com/actions/T0/1/" + "r" * 16,
        "actions": [{"action_id": "lgsotf_approve", "value": action_id}],
    }
    return urlencode({"payload": json.dumps(payload)}).encode()


async def test_a_signed_slack_click_cannot_reach_another_tenant(api: ApiHarness) -> None:
    """The granted customer's own Slack app, validly signed, aimed at the victim's action and integration."""
    ids = await _seed_victim(api)
    personas, _, _ = await _personas(api)
    signing = "granted-signing-" + "x" * 24
    made = await api.client.post(
        f"{API}/integrations",
        json={"kind": "slack", "name": "SOC", "events": ["action.awaiting_approval"],
              "config": {"interactive_approvals": True},
              "secret": {"webhook_url": slack_url(), "signing_secret": signing, "bot_token": "xoxb-" + "g" * 24}},
        headers=personas["customer admin"],
    )
    assert made.status_code == 201, made.text

    def users_info(request: httpx.Request) -> httpx.Response:
        email = "granted-admin@" + "tenant-a.example.com"
        return httpx.Response(200, json={"ok": True, "user": {"id": "UGRANTED", "is_email_confirmed": True,
                                                                "profile": {"email": email}}})

    api.app.state.integrations_http = IntegrationHttp(
        api.ctx.settings, transport=httpx.MockTransport(Receiver({"GET /api/users.info": users_info})),
        resolver=public_resolver,
    )
    await api.user(GRANTED, "admin", email="granted-admin@tenant-a.example.com")
    before = await _victim_state(api)
    for tenant, integration in ((GRANTED, made.json()["id"]), (VICTIM, made.json()["id"]), (VICTIM, ids["integration_id"])):
        body = _click(ids["action_id"])
        ts = str(int(time.time()))
        response = await api.client.post(
            f"{API}/integrations/slack/interactions?tenant={tenant}&integration={integration}", content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": ts,
                     "X-Slack-Signature": slack_signature(signing, ts, body)},
        )
        assert not _leaks(response.text), (tenant, response.text)
    assert (await api.repos.actions.get(VICTIM, ids["action_id"])).status == "awaiting_approval"
    assert await _victim_state(api) == before


def _mcp_arguments(ids: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    alert = ids["alert_id"]
    return {
        "search_alerts": {"q": MARKER},
        "get_alert": {"alert_id": alert},
        "get_alert_timeline": {"alert_id": alert},
        "list_escalations": {"alert_id": alert},
        "get_escalation": {"escalation_id": ids["escalation_id"]},
        "dashboard_summary": {},
        "add_note": {"alert_id": alert, "text": "probe"},
        "get_evidence_pack": {"alert_id": alert},
        "whoami": {},
        "get_verdict": {"alert_id": alert},
        "list_actions": {"alert_id": alert},
        "get_action": {"action_id": ids["action_id"]},
        "ingest_test_alerts": {"items": [{"alert": {"title": "probe", "severity": "low"}}]},
        "wait_for_verdict": {"alert_ids": [alert], "timeout_s": 0},
        "get_test_run": {"run_handle": "run_" + "0" * 32},
    }


async def test_mcp_tools_do_not_leak(api: ApiHarness) -> None:
    """The MCP server with an organisation key, pinned to the granted customer or to the victim."""
    ids = await _seed_victim(api)
    personas, _, _ = await _personas(api)
    token = personas["org key->granted"]["X-API-Key"]
    before = await _victim_state(api)
    arguments = _mcp_arguments(ids)
    assert set(arguments) == set(TOOLS), "cover every MCP tool"

    async def no_sleep(_: float) -> None:
        return None

    leaks: List[str] = []
    for pinned in (GRANTED, VICTIM):
        client = LgSotfApiClient(
            "http://127.0.0.1", token, transport=httpx.ASGITransport(app=api.app), tenant_id=pinned, sleep=no_sleep
        )
        ctx = ToolContext(client, RunStore(), sleep=no_sleep, poll_interval_s=0)
        try:
            for name, tool in TOOLS.items():
                result = await call_tool(ctx, tool, parse_arguments(tool, arguments[name]), max_chars=60_000)
                text = result["content"][0]["text"]
                if MARKER in text:
                    leaks.append(f"{pinned} {name}: {text[:200]}")
                if pinned == VICTIM and name != "get_test_run" and not result["isError"]:
                    leaks.append(f"{pinned} {name}: served without a grant")
        finally:
            await client.aclose()
    assert leaks == []
    assert await _victim_state(api) == before


@pytest.mark.parametrize("ws_path", ["/ws", "/api/v1/ws"])
async def test_websocket_channel_does_not_leak(make_api: Any, ws_path: str) -> None:
    api = await make_api(api={"ws_revalidate_s": 0.2})
    await _seed_victim(api)
    await _personas(api)
    staff = await _member(api, ORG, "analyst")
    token = api.token(staff)
    async with serve_api(api) as served:
        for target in (VICTIM, "Bad.Tenant"):
            with pytest.raises(InvalidStatus):
                async with connect(f"{served}{ws_path}?token={token}&tenant={target}"):
                    pass
        async with connect(f"{served}{ws_path}?token={token}&tenant={GRANTED}") as ws:
            hello = await recv_json(ws)
            assert hello["tenant_id"] == GRANTED
            await api.ctx.events.publish(VICTIM, make_event("alert.created", VICTIM, MARKER, {"title": MARKER}))
            await api.ctx.events.publish(GRANTED, make_event("alert.created", GRANTED, "granted-1", {}))
            event = await recv_json(ws)
            assert (event["tenant_id"], event["alert_id"]) == (GRANTED, "granted-1")
            with pytest.raises(asyncio.TimeoutError):
                await recv_json(ws, wait_s=0.3)
            # Revoking the grant closes the socket at the next revalidation.
            for grant in await api.repos.grants.list_for_tenant(GRANTED):
                if grant.revoked_at is None:
                    await api.repos.grants.revoke(GRANTED, grant.id, revoked_by="granted-admin")
            with pytest.raises(ConnectionClosed) as closed:
                while True:
                    await recv_json(ws, wait_s=3.0)
            assert closed.value.rcvd is not None and closed.value.rcvd.code == 1008
    accesses = (await api.repos.audit.list(GRANTED, action="grant.tenant_access")).items
    assert [e.details["method"] for e in accesses] == ["WS"]
    assert [e.action for e in (await api.repos.audit.list(ORG, action="delegated.grant.tenant_access")).items] == [
        "delegated.grant.tenant_access"
    ]
