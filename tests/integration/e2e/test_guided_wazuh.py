"""e2e_guided_wazuh (PRD-13.2a): the guided Wazuh setup names the fix for every misconfiguration.

An admin connects a Wazuh indexer through ``POST /onboarding/connectors/wazuh/check``,
over HTTP, the way the Sources page does. The indexer is
:class:`~tests.fixtures.wazuh_lab.fake.FakeWazuhIndexer`, which answers as
the Wazuh 4.14 indexer of the lab does (``tests/live/wazuh/test_guided_setup.py``
runs the same checks against the real one). Everything is wrong at first.
Each run fails exactly one check, whose message names what is missing (the
host, the CA, the permission and the index pattern, the index, the clock);
the test applies that fix and runs the checks again, until the source can be
saved and tested. The push path (the Wazuh manager posting to the ingest
webhook) is walked the same way: the push source, then the API key and its
``ingest`` scope.

No answer and no audit entry may hold the password, the user name or the API key.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
import pytest

from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps
from tests.fixtures.vendors import vendor_events
from tests.fixtures.wazuh_lab.fake import UNTRUSTED_ISSUER, FakeWazuhIndexer
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness

pytestmark = pytest.mark.integration

API = "/api/v1"
CHECK = f"{API}/onboarding/connectors/wazuh/check"
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
BASE_URL = "https://wazuh.example.com:9200"
USERNAME = "soc-reader"
PASSWORD = f"test-only-{secrets.token_hex(8)}"
PULL_ORDER = ["settings", "reachable", "tls", "credentials", "index_permission", "index", "clock"]


async def _resolve(host: str, port: int) -> List[str]:
    return ["93.184.216.34"]


def _connect(api: ApiHarness, indexer: FakeWazuhIndexer) -> None:
    """Point the API's ingestion service at the fake indexer (a public address, the test's clock)."""
    ctx = api.ctx
    ctx.ingestion = IngestionService(
        ctx.db,
        ctx.settings,
        secret_box=ctx.secret_box,
        repos=ctx.repos,
        connector_deps=ConnectorDeps(resolver=_resolve, transport=httpx.MockTransport(indexer), now=lambda: NOW),
    )


class Guide:
    """The admin's side of the guided flow: run the checks, read the one that failed."""

    def __init__(self, api: ApiHarness, headers: Dict[str, str], never_shown: List[str]):
        self.api = api
        self.headers = headers
        self.never_shown = never_shown

    async def run(self, body: Dict[str, Any]) -> Dict[str, Any]:
        response = await self.api.client.post(CHECK, json=body, headers=self.headers)
        assert response.status_code == 200, response.text
        for secret in self.never_shown:
            assert secret not in response.text
        assert "Traceback" not in response.text and "Error(" not in response.text
        return response.json()

    async def failing(self, body: Dict[str, Any], check_id: str) -> Dict[str, Any]:
        """Run the checks; exactly ``check_id`` fails, with a message and a fix. Returns that check."""
        result = await self.run(body)
        assert result["ok"] is False
        failed = [c for c in result["checks"] if c["status"] == "failed"]
        assert [c["id"] for c in failed] == [check_id], result["checks"]
        check = failed[0]
        assert check["message"] and check["fix"], check
        if check_id in PULL_ORDER:
            states = {c["id"]: c["status"] for c in result["checks"]}
            assert [c["id"] for c in result["checks"]] == PULL_ORDER
            before, after = PULL_ORDER[: PULL_ORDER.index(check_id)], PULL_ORDER[PULL_ORDER.index(check_id) + 1 :]
            assert all(states[c] == "passed" for c in before), states
            assert all(states[c] == "skipped" for c in after), states
        return check


def _pull(index: Optional[str] = None, password: str = PASSWORD) -> Dict[str, Any]:
    config: Dict[str, Any] = {"base_url": BASE_URL}
    if index is not None:
        config["index"] = index
    return {"pull": {"config": config, "secret": {"username": USERNAME, "password": password}}}


async def test_e2e_guided_wazuh_names_the_fix_for_every_pull_misconfiguration(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    indexer = FakeWazuhIndexer(clock=lambda: NOW - timedelta(minutes=10))
    indexer.add_alerts("wazuh-alerts-4.x-2026.11.14", [NOW - timedelta(minutes=m) for m in (30, 20, 5)])
    indexer.down = True
    indexer.certificate = UNTRUSTED_ISSUER
    _connect(api, indexer)
    guide = Guide(api, admin, [PASSWORD, USERNAME])

    # 1. Nothing answers at the URL.
    check = await guide.failing(_pull(), "reachable")
    assert "wazuh.example.com:9200" in check["message"]
    assert "9200" in check["fix"] and "firewall" in check["fix"]
    indexer.down = False

    # 2. The indexer's certificate comes from Wazuh's own CA, which this server does not trust.
    check = await guide.failing(_pull(), "tls")
    assert "certificate authority this server does not trust" in check["message"]
    assert "CA certificate field" in check["fix"] and "root-ca.pem" in check["fix"]
    indexer.certificate = None

    # 3. The password is wrong (the user does not exist yet either: the indexer answers the same).
    check = await guide.failing(_pull(), "credentials")
    assert "rejected the user name or password" in check["message"] and "401" in check["message"]
    assert "Wazuh indexer user" in check["fix"]
    indexer.put_user(USERNAME, PASSWORD)
    wrong_password = f"test-only-{secrets.token_hex(8)}"
    guide.never_shown.append(wrong_password)
    await guide.failing(_pull(password=wrong_password), "credentials")

    # 4. The user signs in but its role has no read permission on the alerts index.
    check = await guide.failing(_pull(), "index_permission")
    assert "wazuh-alerts-*" in check["message"] and "indices:data/read/search" in check["message"]
    assert "index permission read" in check["fix"] and "index pattern wazuh-alerts-*" in check["fix"]
    indexer.put_user(USERNAME, PASSWORD, patterns=["wazuh-alerts-*"])

    # 5. A typo in the index pattern: it matches no index.
    check = await guide.failing(_pull(index="wazuh-alert-*"), "index")
    assert check["message"] == "No index matches wazuh-alert-*."
    assert "wazuh-alerts-*" in check["fix"] and "wazuh-alerts-4.x-YYYY.MM.DD" in check["fix"]

    # 6. The indexer's clock is ten minutes behind this server's.
    check = await guide.failing(_pull(), "clock")
    assert check["message"] == "The indexer's clock is 10 minutes behind this server's clock."
    assert "NTP" in check["fix"]
    indexer.clock = lambda: NOW + timedelta(seconds=2)

    # Everything is right: every check passes and says what it found.
    result = await guide.run(_pull())
    assert result["ok"] is True
    assert [(c["id"], c["status"]) for c in result["checks"]] == [(c, "passed") for c in PULL_ORDER]
    assert all(c["fix"] is None for c in result["checks"])
    found = {c["id"]: c["message"] for c in result["checks"]}
    assert found["index"] == "wazuh-alerts-* holds 3 alerts; the newest is dated 2026-11-14 11:55 UTC."
    assert found["index_permission"] == "The user's role may read wazuh-alerts-* (indices:data/read/search)."

    # The checked settings are saved as the source, which then tests healthy and counts as connected.
    created = await api.client.post(
        f"{API}/sources",
        json={
            "id": "wazuh", "type": "wazuh", "name": "Wazuh", "config": {"base_url": BASE_URL},
            "secret": {"username": USERNAME, "password": PASSWORD},
        },
        headers=admin,
    )
    assert created.status_code == 201, created.text
    tested = await api.client.post(f"{API}/sources/wazuh/test", headers=admin)
    assert tested.json()["ok"] is True, tested.text
    status = (await api.client.get(f"{API}/onboarding/status", headers=admin)).json()
    assert {s["id"]: s["done"] for s in status["steps"]}["source_connected"] is True

    # Nothing was stored by the checks themselves, and the audit trail names the failed checks only.
    assert [s.id for s in await api.repos.sources.list(TENANT_A)] == ["wazuh"]
    runs = [e for e in (await api.repos.audit.list(TENANT_A, resource_type="source")).items if e.action == "source.setup_checked"]
    assert len(runs) == 8
    failed_in_order = [e.details["failed"] for e in sorted(runs, key=lambda e: e.id)]
    assert failed_in_order == [
        ["reachable"], ["tls"], ["credentials"], ["credentials"], ["index_permission"], ["index"], ["clock"], [],
    ]
    trail = json.dumps([e.details for e in runs])
    assert all(secret not in trail for secret in guide.never_shown) and BASE_URL not in trail


async def test_e2e_guided_wazuh_names_the_fix_for_every_push_misconfiguration(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    _, read_only = await api.api_key(TENANT_A, ["read"])
    _, other_tenant = await api.api_key(TENANT_B, ["ingest"])
    guide = Guide(api, admin, [read_only, other_tenant])

    def push(api_key: Optional[str] = None) -> Dict[str, Any]:
        return {"push": {"source_id": "wazuh-push", **({"api_key": api_key} if api_key else {})}}

    # 1. The push source does not exist, and the tenant has no key a sender could use.
    result = await guide.run(push())
    assert result["ok"] is False
    source, key = result["checks"]
    assert (source["id"], source["status"], key["id"], key["status"]) == ("push_source", "failed", "push_key", "failed")
    assert source["message"] == "This tenant has no source with the id wazuh-push."
    assert "type webhook" in source["fix"] and "config.format set to wazuh" in source["fix"]
    assert "no active API key with the ingest scope" in key["message"]
    assert "ingest scope" in key["fix"] and "X-API-Key" in key["fix"]

    # 2. The source exists, but for another format.
    wrong_format = {"id": "wazuh-push", "type": "webhook", "name": "Wazuh push", "config": {"format": "splunk"}}
    assert (await api.client.post(f"{API}/sources", json=wrong_format, headers=admin)).status_code == 201
    check = (await guide.run(push()))["checks"][0]
    assert (check["id"], check["status"]) == ("push_source", "failed")
    assert check["message"] == "The source wazuh-push expects the splunk format, not Wazuh alerts."
    assert check["fix"] == "Set config.format of the source wazuh-push to wazuh."
    fixed = await api.client.patch(f"{API}/sources/wazuh-push", json={"config": {"format": "wazuh"}}, headers=admin)
    assert fixed.status_code == 200, fixed.text

    # 3. The key the manager sends lacks the ingest scope.
    check = await guide.failing(push(read_only), "push_key")
    assert "lacks the ingest scope (it has: read)" in check["message"] and "HTTP 403" in check["message"]
    assert "API key with the ingest scope" in check["fix"]

    # 4. A key of another tenant, a mistyped key and something that is no key at all.
    for wrong in (other_tenant, other_tenant[:-1] + ("A" if other_tenant[-1] != "A" else "B")):
        guide.never_shown.append(wrong)
        check = await guide.failing(push(wrong), "push_key")
        assert check["message"].startswith("This key is not an API key of this tenant")
    check = await guide.failing(push("wazuh-integration-password"), "push_key")
    assert "starts with lgk_" in check["message"]

    # 5. A revoked key.
    revoked_key, revoked = await api.api_key(TENANT_A, ["ingest"])
    await api.repos.api_keys.revoke(TENANT_A, revoked_key.id)
    guide.never_shown.append(revoked)
    check = await guide.failing(push(revoked), "push_key")
    assert "was revoked" in check["message"] and "HTTP 401" in check["message"]

    # A key with the ingest scope passes, and the manager's alert goes in with it.
    _, good = await api.api_key(TENANT_A, ["ingest"])
    guide.never_shown.append(good)
    without_key = await guide.run(push())
    assert without_key["ok"] is True and without_key["checks"][1]["status"] == "skipped"
    assert "paste the key the Wazuh manager sends" in without_key["checks"][1]["message"]
    result = await guide.run(push(good))
    assert result["ok"] is True and [c["status"] for c in result["checks"]] == ["passed", "passed"]
    assert "POST /api/v1/ingest/webhook/wazuh-push" in result["checks"][0]["message"]
    pushed = await api.client.post(
        f"{API}/ingest/webhook/wazuh-push", json=vendor_events("wazuh_alerts")[0], headers={"X-API-Key": good}
    )
    assert pushed.status_code == 202 and pushed.json()["inserted"] == 1, pushed.text
