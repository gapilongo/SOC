"""ARCH-E4.1c: writing and deciding in a customer tenant under a grant, with dual audit.

Every audit entry written under a grant lands in the customer's chain (naming
the organisation and the grant) and, as ``delegated.<action>``, in the
organisation's chain (naming the customer entry by id and hash). The
member's account belongs to the organisation's home tenant, so the
customer's user columns stay empty and the audit log names the actor.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Tuple

import pytest

from lg_sotf.db.repos import AuditEntry, User
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.integration.db._support import make_alert

pytestmark = pytest.mark.integration

API = "/api/v1"
ORG = "mssp-org"


async def _member(api: ApiHarness, grant_role: str = "analyst", home_role: str = "admin") -> User:
    await api.repos.tenants.create(ORG, "MSSP")
    await api.repos.organisations.upsert(ORG, "MSSP")
    staff = await api.user(ORG, home_role)
    await api.repos.organisations.add_member(ORG, staff.id)
    await api.repos.grants.create(
        TENANT_B, ORG, grant_role, reason="24/7 cover", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=8),
    )
    return staff


async def _escalation(api: ApiHarness) -> Tuple[str, Any]:
    alert_id = await make_alert(api.repos, TENANT_B, title="B")
    escalation, _ = await api.repos.escalations.create_or_attach(
        TENANT_B, alert_id, reason="review", sla_deadline=datetime.now(UTC) + timedelta(hours=1)
    )
    return alert_id, escalation


async def _entries(api: ApiHarness, tenant_id: str, action: str) -> List[AuditEntry]:
    return (await api.repos.audit.list(tenant_id, action=action, limit=100)).items


async def test_grant_writes(api: ApiHarness) -> None:
    """Deciding in a granted tenant writes one entry to each audit chain."""
    staff = await _member(api)
    _, escalation = await _escalation(api)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}

    decided = await api.client.post(
        f"{API}/escalations/{escalation.id}/decision",
        json={"decision": "false_positive", "notes": "known scanner", "version": escalation.version},
        headers=headers,
    )

    assert decided.status_code == 200, decided.text
    [tenant_entry] = await _entries(api, TENANT_B, "escalation.decided")
    [org_entry] = await _entries(api, ORG, "delegated.escalation.decided")
    grant = (await api.repos.grants.list_for_tenant(TENANT_B))[0]
    assert (tenant_entry.actor_id, org_entry.actor_id) == (str(staff.id), str(staff.id))
    assert tenant_entry.details["delegation"] == {"organisation_id": ORG, "grant_id": str(grant.id)}
    assert org_entry.resource_id == escalation.id
    assert org_entry.details == {
        "tenant_id": TENANT_B, "grant_id": str(grant.id), "entry_id": tenant_entry.id, "entry_hash": tenant_entry.hash
    }
    assert "notes" not in str(org_entry.details)  # the customer's content stays in the customer's chain
    for chain in (TENANT_B, ORG):
        assert (await api.repos.audit.verify_chain(chain)).ok
    stored = await api.repos.escalations.get(TENANT_B, escalation.id)
    assert (stored.status, stored.decided_by) == ("decided", None)
    # Every customer entry written under the grant has its organisation entry, and only those.
    customer = {e.id: e for e in (await api.repos.audit.list(TENANT_B, limit=100)).items if "delegation" in e.details}
    mirrored = [e for e in (await api.repos.audit.list(ORG, limit=100)).items if e.action.startswith("delegated.")]
    assert sorted(e.details["entry_id"] for e in mirrored) == sorted(customer)
    for entry in mirrored:
        source = customer[entry.details["entry_id"]]
        assert (entry.action, entry.details["entry_hash"]) == (f"delegated.{source.action}", source.hash)


async def test_approvals_and_writes_under_a_grant(api: ApiHarness) -> None:
    staff = await _member(api, "admin")
    alert_id, _ = await _escalation(api)
    action, _ = await api.repos.actions.propose(
        TENANT_B, alert_id, "block_ip", "203.0.113.9", "low", status="awaiting_approval"
    )
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}

    approved = await api.client.post(f"{API}/actions/{action.id}/approve", json={}, headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["action"]["approved_by"] == str(staff.id)
    rule = await api.client.post(
        f"{API}/suppressions", json={"name": "B scanner", "match": {"fingerprint": "fp-b"}}, headers=headers
    )
    assert rule.status_code == 201 and rule.json()["created_by"] is None
    for action_name in ("response_action.approved", "suppression.created"):
        assert len(await _entries(api, TENANT_B, action_name)) == 1
        assert len(await _entries(api, ORG, f"delegated.{action_name}")) == 1


async def test_what_a_grant_never_allows(api: ApiHarness) -> None:
    """No claim (it assigns to an account of the customer) and no credentials that would outlive the grant."""
    staff = await _member(api, "admin")
    _, escalation = await _escalation(api)
    headers = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    refused: List[Tuple[str, str, Dict[str, Any]]] = [
        ("POST", f"{API}/escalations/{escalation.id}/claim", {"version": escalation.version}),
        ("POST", f"{API}/escalations/bulk/claim", {"items": [{"escalation_id": escalation.id, "version": 1}]}),
        ("POST", f"{API}/users", {"email": "backdoor@b.example.com", "role": "admin", "password": "x" * 20}),
        ("POST", f"{API}/api-keys", {"name": "persist", "scopes": ["read"]}),
        ("POST", f"{API}/tenant/grants", {"organisation_id": ORG, "role": "admin", "reason": "x",
                                         "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()}),
    ]
    for method, path, body in refused:
        response = await api.client.request(method, path, json=body, headers=headers)
        assert response.status_code == 403, (path, response.text)
    assert (await api.repos.escalations.get(TENANT_B, escalation.id)).status == "open"
    assert (await api.repos.users.get_by_email(TENANT_B, "backdoor@b.example.com")) is None


async def test_a_viewer_grant_cannot_decide_and_the_platform_override_still_cannot(api: ApiHarness) -> None:
    staff = await _member(api, "viewer")
    _, escalation = await _escalation(api)
    body = {"decision": "true_positive", "version": escalation.version}
    as_viewer = {**api.auth(staff), "X-Tenant-ID": TENANT_B}
    assert (await api.client.post(f"{API}/escalations/{escalation.id}/decision", json=body, headers=as_viewer)).status_code == 403
    platform = {**(await api.login_headers(TENANT_A, "admin", platform_admin=True)), "X-Tenant-ID": TENANT_B}
    response = await api.client.post(f"{API}/escalations/{escalation.id}/decision", json=body, headers=platform)
    assert response.status_code == 403 and "X-Tenant-ID" in response.json()["error"]["message"]
    assert await _entries(api, ORG, "delegated.escalation.decided") == []
