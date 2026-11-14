"""``POST /onboarding/connectors/wazuh/check``: who may run it, what it refuses, and the push-source cases.

The walk through every misconfiguration is ``tests/integration/e2e/test_guided_wazuh.py``.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import httpx
import pytest

from lg_sotf.api.routers.guided import SETUP_CHECK_PER_MINUTE
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

CHECK = "/api/v1/onboarding/connectors/wazuh/check"
ORG = "mssp-org"
PASSWORD = f"test-only-{secrets.token_hex(8)}"
PULL = {"pull": {"config": {"base_url": "https://wazuh.example.com:9200"}, "secret": {"username": "u", "password": PASSWORD}}}


def _offline(api: ApiHarness, sent: List[httpx.Request]) -> None:
    """Outbound requests of the checks land in ``sent`` instead of on the network."""

    async def resolve(host: str, port: int) -> List[str]:
        return ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(401, text="Unauthorized")

    ctx = api.ctx
    ctx.ingestion = IngestionService(
        ctx.db, ctx.settings, secret_box=ctx.secret_box, repos=ctx.repos,
        connector_deps=ConnectorDeps(resolver=resolve, transport=httpx.MockTransport(handler)),
    )


async def test_only_the_tenants_own_admins_run_the_checks(api: ApiHarness) -> None:
    sent: List[httpx.Request] = []
    _offline(api, sent)
    for role in ("viewer", "analyst"):
        refused = await api.client.post(CHECK, json=PULL, headers=await api.login_headers(TENANT_A, role))
        assert refused.status_code == 403, role
    key = await api.key_headers(TENANT_A, ["read", "write", "ingest"])
    assert (await api.client.post(CHECK, json=PULL, headers=key)).status_code == 403

    # An MSSP admin acting under a grant cannot point the customer's install at a host of their choosing.
    await api.repos.tenants.create(ORG, ORG)
    await api.repos.organisations.upsert(ORG, ORG)
    staff = await api.user(ORG, "admin")
    await api.repos.organisations.add_member(ORG, staff.id)
    await api.repos.grants.create(
        TENANT_B, ORG, "admin", reason="cover", created_by="customer-admin",
        expires_at=datetime.now(UTC) + timedelta(hours=8),
    )
    under_grant = await api.client.post(CHECK, json=PULL, headers={**api.auth(staff), "X-Tenant-ID": TENANT_B})
    assert under_grant.status_code == 403
    assert sent == [], "a refused request sends nothing"

    allowed = await api.client.post(CHECK, json=PULL, headers=await api.login_headers(TENANT_A, "admin"))
    assert allowed.status_code == 200 and len(sent) == 1
    assert [c["id"] for c in allowed.json()["checks"] if c["status"] == "failed"] == ["credentials"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"pull": {"config": {"base_url": "https://wazuh.example.com:9200"}}},
        {"pull": {"secret": {"username": "u", "password": "p"}}},
        {"push": {"source_id": "not a source id"}},
        {"push": {"api_key": "k" * 301}},
        {"pull": PULL["pull"], "extra": 1},
    ],
)
async def test_a_malformed_request_is_refused_without_echoing_it(api: ApiHarness, body: Dict[str, Any]) -> None:
    sent: List[httpx.Request] = []
    _offline(api, sent)
    response = await api.client.post(CHECK, json=body, headers=await api.login_headers(TENANT_A, "admin"))
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert PASSWORD not in response.text and "k" * 20 not in response.text and sent == []


async def test_pull_and_push_can_be_checked_in_one_call(api: ApiHarness) -> None:
    sent: List[httpx.Request] = []
    _offline(api, sent)
    admin = await api.login_headers(TENANT_A, "admin")
    response = await api.client.post(CHECK, json={**PULL, "push": {}}, headers=admin)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is False
    assert [c["id"] for c in body["checks"]] == [
        "settings", "reachable", "tls", "credentials", "index_permission", "index", "clock", "push_source", "push_key",
    ]
    assert body["checks"][7]["message"] == "This tenant has no source with the id wazuh-push."
    entry = (await api.repos.audit.list(TENANT_A, resource_type="source")).items[0]
    assert entry.action == "source.setup_checked"
    assert entry.details == {
        "kind": "wazuh", "modes": ["pull", "push"], "ok": False, "failed": ["credentials", "push_source", "push_key"],
    }


async def test_a_source_that_cannot_take_wazuh_alerts_is_named_with_its_fix(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    await api.api_key(TENANT_A, ["ingest"])
    await api.repos.sources.create(
        TENANT_A, "wazuh", "Indexer", source_id="wazuh-pull", config={"base_url": "https://wazuh.example.com:9200"}
    )
    await api.repos.sources.create(TENANT_A, "webhook", "Odd", source_id="odd", config={"format": "no-such-format"})
    await api.repos.sources.create(
        TENANT_A, "webhook", "Off", source_id="off", config={"format": "wazuh"}, enabled=False
    )
    await api.repos.sources.create(TENANT_B, "webhook", "Theirs", source_id="theirs", config={"format": "wazuh"})

    async def source_check(source_id: str) -> Dict[str, Any]:
        response = await api.client.post(CHECK, json={"push": {"source_id": source_id}}, headers=admin)
        assert response.status_code == 200, response.text
        check = response.json()["checks"][0]
        assert (check["id"], check["status"]) == ("push_source", "failed") and check["fix"]
        return check

    pull = await source_check("wazuh-pull")
    assert pull["message"] == "wazuh-pull is a wazuh pull source: alerts cannot be pushed to it."
    odd = await source_check("odd")
    assert "unknown event format" in odd["message"] and odd["fix"] == "Set config.format of the source odd to wazuh."
    off = await source_check("off")
    assert off["message"] == "The source off is disabled: pushed alerts are refused."
    assert off["fix"] == "Enable the source off."
    # Another tenant's source does not exist here.
    theirs = await source_check("theirs")
    assert theirs["message"] == "This tenant has no source with the id theirs."


async def test_the_checks_are_rate_limited_per_tenant(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    statuses = [
        (await api.client.post(CHECK, json={"push": {}}, headers=admin)).status_code for _ in range(SETUP_CHECK_PER_MINUTE + 1)
    ]
    assert statuses[:SETUP_CHECK_PER_MINUTE] == [200] * SETUP_CHECK_PER_MINUTE and statuses[-1] == 429
    other = await api.client.post(CHECK, json={"push": {}}, headers=await api.login_headers(TENANT_B, "admin"))
    assert other.status_code == 200, "another tenant has its own allowance"
