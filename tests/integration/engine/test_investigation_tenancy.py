"""Tenancy of the investigation harness (AI-E3.3) on the real engine and the live-indexer path.

Two tenants, each with its own Wazuh source (its own indexer host, index pattern and credentials). An
investigation of one tenant's alert asks that tenant's indexer with that tenant's credentials and nothing
else, writes its ledger under that tenant, and a tenant that did not switch the lookups on is never
queried at all.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.core.workflow import WorkflowEngine
from lg_sotf.db.repos import Repositories
from lg_sotf.db.tenancy import thread_id_for
from lg_sotf.ingestion.sources import ConnectorDeps, encrypt_source_secret
from lg_sotf.ingestion.wazuh_indexer import WazuhIndexers
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A, TENANT_B, make_alert
from tests.integration.engine._harness import SWITCH_ON
from tests.unit.ingestion._support import public_resolver
from tests.unit.tools.wazuh._support import nothing_found

pytestmark = pytest.mark.integration

AT = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
SOURCE = "wazuh-indexer"


def password(tenant: str) -> str:
    return f"test-only-{tenant}-" + "p" * 8


def basic(tenant: str) -> str:
    return "Basic " + base64.b64encode(f"reader-{tenant}:{password(tenant)}".encode()).decode()


def host_of(tenant: str) -> str:
    return f"indexer.{tenant}.example"


class Indexers:
    """Every tenant's indexer behind one transport: it answers "nothing found" and remembers who asked what."""

    def __init__(self) -> None:
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json=nothing_found())

    def asked(self) -> List[Any]:
        return sorted({(r.url.host, r.url.path, r.headers["authorization"]) for r in self.requests})


async def wazuh_tenant(repos: Repositories, box: SecretBox, tenant: str, *, on: bool) -> str:
    """A Wazuh pull source of ``tenant`` with its own credentials, and an alert that came from it."""
    secret = encrypt_source_secret(box, tenant, SOURCE, {"username": f"reader-{tenant}", "password": password(tenant)})
    config = {"base_url": f"https://{host_of(tenant)}:9200", "index": f"wazuh-alerts-{tenant}-*"}
    await repos.sources.create(tenant, "wazuh", "Wazuh", source_id=SOURCE, config=config, secret_ciphertext=secret)
    if on:
        await repos.tenants.update_settings(tenant, SWITCH_ON)
    document: Dict[str, Any] = {"agent": {"name": f"SRV-{tenant.upper()}"}, "rule": {"id": "5710", "level": 5, "groups": ["sshd"]}}
    normalized = {"title": "sshd: attempt to login using a non-existent user", "normalizer": "wazuh",
                  "entities": {"hosts": [document["agent"]["name"]]}}
    return await make_alert(repos, tenant, source_id=SOURCE, title=normalized["title"], severity="low", occurred_at=AT,
                            raw=document, normalized=normalized)


async def test_an_investigation_asks_its_own_tenants_indexer_and_no_other(
    engine_factory: Callable[..., Any], engine_settings: Settings, repos: Repositories
) -> None:
    box, server = SecretBox.from_settings(engine_settings), Indexers()
    deps = ConnectorDeps(transport=httpx.MockTransport(server), resolver=public_resolver, now=lambda: AT + timedelta(hours=2))
    engine: WorkflowEngine = await engine_factory(evidence=WazuhIndexers(engine_settings, box, deps=deps), secret_box=box)
    mine = await wazuh_tenant(repos, box, TENANT_A, on=True)
    theirs = await wazuh_tenant(repos, box, TENANT_B, on=True)

    await engine.run(TENANT_A, mine)

    # Only tenant A's indexer was asked, on A's index pattern, with A's credentials.
    assert server.asked() == [(host_of(TENANT_A), f"/wazuh-alerts-{TENANT_A}-*/_search", basic(TENANT_A))]
    record = (await repos.alerts.get(TENANT_A, mine)).summary["analysis"]["investigation"]
    assert [(s["evidence_id"], s["outcome"]) for s in record["steps"]][0] == ("host", "empty")
    assert (record["status"], record["reason"]) == ("degraded", "no_facts")  # asked, and nothing was there
    # The ledger is A's: B cannot read it, even naming A's alert and run.
    run_id = (await engine.graph.aget_state({"configurable": {"thread_id": thread_id_for(TENANT_A, mine)}})).values["investigation_run_id"]
    assert [e.fact_id for e in await repos.evidence_facts.list_for_run(TENANT_A, mine, run_id)] == ["host:0"]
    assert await repos.evidence_facts.list_for_run(TENANT_B, mine, run_id) == []
    assert (await repos.evidence_facts.latest_run(TENANT_B, mine)).total == 0

    before = len(server.requests)
    await engine.run(TENANT_B, theirs)
    assert {r.url.host for r in server.requests[before:]} == {host_of(TENANT_B)}
    assert {r.headers["authorization"] for r in server.requests[before:]} == {basic(TENANT_B)}
    assert (await repos.evidence_facts.latest_run(TENANT_A, theirs)).total == 0


async def test_a_tenant_that_did_not_switch_the_lookups_on_is_never_queried(
    engine_factory: Callable[..., Any], engine_settings: Settings, repos: Repositories
) -> None:
    box, server = SecretBox.from_settings(engine_settings), Indexers()
    deps = ConnectorDeps(transport=httpx.MockTransport(server), resolver=public_resolver, now=lambda: AT + timedelta(hours=2))
    engine: WorkflowEngine = await engine_factory(evidence=WazuhIndexers(engine_settings, box, deps=deps), secret_box=box)
    await wazuh_tenant(repos, box, TENANT_A, on=True)  # the neighbour has it on
    quiet = await wazuh_tenant(repos, box, TENANT_B, on=False)

    await engine.run(TENANT_B, quiet)

    assert server.requests == []
    summary = (await repos.alerts.get(TENANT_B, quiet)).summary
    assert "investigation" not in summary["analysis"] and (await repos.evidence_facts.latest_run(TENANT_B, quiet)).total == 0
