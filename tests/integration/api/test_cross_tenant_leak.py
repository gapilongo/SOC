"""ARCH-E4.1d: a generated cross-tenant leak suite over every route, the WebSocket channel and every MCP tool.

Three tenants: the MSSP organisation ``ORG``, a customer ``GRANTED`` that
gave it an admin grant, and a ``VICTIM`` that gave it nothing. The victim's
rows carry a marker string. The attackers below call every operation of the
OpenAPI contract (path ids are the victim's own; the body is ``{}``), every
MCP tool, and the WebSocket channel:

* an organisation member and an organisation API key, with ``X-Tenant-ID``
  naming the victim (no grant) or the granted customer (a grant, but not to
  the victim);
* the granted customer's own admin, in its own tenant and with
  ``X-Tenant-ID`` naming the victim.

A leak is a response carrying the marker or a victim ``tenant_id``, or any
change to the victim's rows (its audit chain included). The suite expects
none. A new route, path parameter or MCP tool fails the suite until it is
covered here.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Iterator, List, Tuple

import httpx
import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from lg_sotf.db.repos import NewAlert
from lg_sotf.mcp.base import ToolContext
from lg_sotf.mcp.client import LgSotfApiClient
from lg_sotf.mcp.runs import RunStore
from lg_sotf.mcp.tools import TOOLS, call_tool, parse_arguments
from lg_sotf.queue.events import make_event
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness, recv_json, serve_api
from tests.integration.db._support import TENANT_TABLES, new_alert

pytestmark = pytest.mark.integration

ORG = "mssp-org"
OTHER_ORG = "other-mssp"
GRANTED = TENANT_A
VICTIM = TENANT_B
MARKER = "victim-marker-7f3a"
API = "/api/v1"
# Revokes the caller's own token: it would end the run, and it touches no tenant data.
SKIPPED = {("POST", f"{API}/auth/logout")}


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


async def _seed_victim(api: ApiHarness) -> Dict[str, str]:
    """A row of every kind a route addresses by id, each carrying the marker."""
    alert: NewAlert = new_alert(title=f"{MARKER} alert", raw={"note": MARKER}, normalized={"title": MARKER})
    await api.repos.alerts.insert_many_if_absent(VICTIM, [alert])
    escalation, _ = await api.repos.escalations.create_or_attach(
        VICTIM, alert.id, reason=MARKER, sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    action, _ = await api.repos.actions.propose(VICTIM, alert.id, "block_ip", "203.0.113.77", "low")
    source = await api.repos.sources.create(VICTIM, "webhook", f"{MARKER} hook", config={"format": "generic"})
    rule = await api.repos.suppressions.create(VICTIM, f"{MARKER} rule", {"title": MARKER})
    integration = await api.repos.integrations.create(VICTIM, "email", f"{MARKER} mail", config={"recipients": ["a@b.co"]})
    user = await api.user(VICTIM, "admin", email=f"{MARKER}@victim.example.com")
    key, _ = await api.api_key(VICTIM, ["read"])
    await api.repos.tenants.create(OTHER_ORG, "Other MSSP")
    await api.repos.organisations.upsert(OTHER_ORG, "Other MSSP")
    grant = await api.repos.grants.create(
        VICTIM, OTHER_ORG, "viewer", reason=MARKER, created_by="victim-admin",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    await api.repos.audit.append(VICTIM, "user", str(user.id), "alert.viewed", "alert", alert.id, {"m": MARKER})
    return {
        "alert_id": alert.id, "escalation_id": escalation.id, "action_id": str(action.id), "source_id": source.id,
        "rule_id": rule.id, "integration_id": str(integration.id), "user_id": str(user.id), "key_id": str(key.id),
        "grant_id": str(grant.id), "tenant_id": VICTIM,
    }


async def _attackers(api: ApiHarness) -> Dict[str, Dict[str, str]]:
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    await api.repos.grants.create(
        GRANTED, ORG, "admin", reason="cover", created_by="granted-admin", expires_at=datetime.now(UTC) + timedelta(days=1)
    )
    key = await api.key_headers(ORG, ["read", "write", "ingest"])
    customer = await api.login_headers(GRANTED, "admin")
    member = api.auth(staff)
    return {
        "member->victim": {**member, "X-Tenant-ID": VICTIM},
        "member->granted": {**member, "X-Tenant-ID": GRANTED},
        "org key->victim": {**key, "X-Tenant-ID": VICTIM},
        "org key->granted": {**key, "X-Tenant-ID": GRANTED},
        "customer admin": customer,
        "customer admin->victim": {**customer, "X-Tenant-ID": VICTIM},
    }


async def _victim_state(api: ApiHarness) -> Dict[str, str]:
    """A digest of every victim row, per tenant table (audit chain included)."""
    state: Dict[str, str] = {}
    async with api.ctx.db.system_tx() as conn:
        for table in TENANT_TABLES:
            state[table] = await conn.fetchval(
                f"SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM {table} t "  # noqa: S608
                "WHERE tenant_id = $1",
                VICTIM,
            )
    return state


def _operations(api: ApiHarness, ids: Dict[str, str]) -> List[Tuple[str, str]]:
    """Every (method, URL) of the API contract, path parameters filled with the victim's ids."""
    found: List[Tuple[str, str]] = []
    for path, operations in api.app.openapi()["paths"].items():
        if not path.startswith(API):
            continue
        for method in operations:
            if (method.upper(), path) in SKIPPED:
                continue
            found.append((method.upper(), path.format(**ids)))  # a new path parameter raises KeyError here
    return found


async def test_cross_tenant_leak(api: ApiHarness) -> None:
    ids = await _seed_victim(api)
    attackers = await _attackers(api)
    before = await _victim_state(api)
    operations = _operations(api, ids)
    assert len(operations) > 100

    leaks: List[str] = []
    for name, headers in attackers.items():
        for method, url in operations:
            response = await api.client.request(method, url, json={}, headers=headers)
            if _leaks(response.text):
                leaks.append(f"{name} {method} {url}: {response.status_code} {response.text[:200]}")
            if name.endswith("->victim") and response.status_code not in (401, 403, 404, 422):
                leaks.append(f"{name} {method} {url}: answered {response.status_code} for the victim tenant")

    assert leaks == []
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
    await _attackers(api)
    _, token = await api.api_key(ORG, ["read", "write", "ingest"])
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


async def test_websocket_channel_does_not_leak(make_api: Any) -> None:
    api = await make_api(api={"ws_revalidate_s": 0.2})
    await _seed_victim(api)
    await _attackers(api)
    staff = await api.user(ORG, "analyst")
    await api.repos.organisations.add_member(ORG, staff.id)
    token = api.token(staff)
    async with serve_api(api) as served:
        for target in (VICTIM, "Bad.Tenant"):
            with pytest.raises(InvalidStatus):
                async with connect(f"{served}/ws?token={token}&tenant={target}"):
                    pass
        async with connect(f"{served}/ws?token={token}&tenant={GRANTED}") as ws:
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
                await api.repos.grants.revoke(GRANTED, grant.id, revoked_by="granted-admin")
            with pytest.raises(ConnectionClosed) as closed:
                while True:
                    await recv_json(ws, wait_s=3.0)
            assert closed.value.rcvd is not None and closed.value.rcvd.code == 1008
    accesses = (await api.repos.audit.list(GRANTED, action="grant.tenant_access")).items
    assert [e.details["method"] for e in accesses] == ["WS"]
