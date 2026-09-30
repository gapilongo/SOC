"""``/integrations`` and ``/tickets`` through the real app: admin only, write-only secrets, tests, delivery log, isolation."""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from lg_sotf.integrations.http import IntegrationHttp
from tests.integration.api.conftest import ApiHarness
from tests.integration.db._support import TENANT_A, TENANT_B
from tests.integration.integrations.conftest import Receiver, fake_secret, public_resolver, slack_url
from tests.integration.services._support import add_alert

pytestmark = pytest.mark.integration


def _stub(api: ApiHarness, receiver: Receiver) -> None:
    api.app.state.integrations_http = IntegrationHttp(
        api.ctx.settings, transport=httpx.MockTransport(receiver), resolver=public_resolver
    )


async def test_crud_keeps_secrets_write_only_and_audits(api: ApiHarness) -> None:
    admin = await api.user(TENANT_A, "admin")
    headers = api.auth(admin)
    body = {
        "kind": "slack", "name": "SOC channel", "events": ["escalation.created", "action.awaiting_approval"],
        "min_severity": "medium", "config": {"channel_label": "#soc"}, "secret": {"webhook_url": slack_url()},
    }
    created = await api.client.post("/api/v1/integrations", json=body, headers=headers)
    assert created.status_code == 201, created.text
    out = created.json()
    assert out["secrets"] == {"webhook_url": True, "bot_token": False, "signing_secret": False}
    assert slack_url() not in created.text and "ciphertext" not in created.text
    integration_id = out["id"]
    stored = await api.repos.integrations.get(TENANT_A, integration_id)
    assert stored.secret_ciphertext and slack_url() not in stored.secret_ciphertext

    listed = await api.client.get("/api/v1/integrations", headers=headers)
    assert [i["name"] for i in listed.json()] == ["SOC channel"] and slack_url() not in listed.text

    token = fake_secret("bot")
    patched = await api.client.patch(
        f"/api/v1/integrations/{integration_id}",
        json={"enabled": False, "secret": {"bot_token": token}, "events": ["escalation.decided"]},
        headers=headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["secrets"] == {"webhook_url": True, "bot_token": True, "signing_secret": False}
    assert patched.json()["enabled"] is False and token not in patched.text
    removed = await api.client.patch(f"/api/v1/integrations/{integration_id}", json={"secret": {"webhook_url": None}},
                                     headers=headers)
    assert removed.status_code == 422 and "webhook_url" in removed.json()["error"]["message"]

    deleted = await api.client.delete(f"/api/v1/integrations/{integration_id}", headers=headers)
    assert deleted.status_code == 204
    audit = [e.action for e in (await api.repos.audit.list(TENANT_A, resource_type="integration")).items]
    assert sorted(audit) == ["integration.created", "integration.deleted", "integration.updated"]
    entries = (await api.repos.audit.list(TENANT_A, resource_type="integration")).items
    assert token not in json.dumps([e.details for e in entries])


@pytest.mark.parametrize(
    "body",
    [
        {"kind": "slack", "name": "x", "secret": {"webhook_url": "https://evil.example.com/x"}},
        {"kind": "slack", "name": "x", "config": {"webhook_url": "https://hooks.slack.com/x"}},
        {"kind": "jira", "name": "x", "events": ["action.failed"], "config": {"base_url": "https://a.atlassian.net",
                                                                               "email": "a@b.co", "project_key": "SOC"},
         "secret": {"api_token": "t" * 20}},
        {"kind": "webhook", "name": "x", "config": {"url": "ftp://soar.example.com"}, "secret": {"signing_secret": "s" * 20}},
        {"kind": "email", "name": "x", "config": {"recipients": []}},
        {"kind": "carrier-pigeon", "name": "x"},
    ],
)
async def test_invalid_integrations_are_refused(api: ApiHarness, body: dict) -> None:
    headers = await api.login_headers(TENANT_A, "admin")
    response = await api.client.post("/api/v1/integrations", json=body, headers=headers)
    assert response.status_code == 422, response.text
    assert await api.repos.integrations.list(TENANT_A) == []


async def test_only_admins_of_the_tenant_manage_integrations(api: ApiHarness) -> None:
    admin_a = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post(
        "/api/v1/integrations",
        json={"kind": "email", "name": "Mail", "config": {"recipients": ["soc@example.com"]}},
        headers=admin_a,
    )
    integration_id = created.json()["id"]
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.get("/api/v1/integrations", headers=analyst)).status_code == 403
    admin_b = await api.login_headers(TENANT_B, "admin")
    assert (await api.client.get("/api/v1/integrations", headers=admin_b)).json() == []
    for method, path in (
        ("GET", f"/api/v1/integrations/{integration_id}"),
        ("PATCH", f"/api/v1/integrations/{integration_id}"),
        ("DELETE", f"/api/v1/integrations/{integration_id}"),
        ("POST", f"/api/v1/integrations/{integration_id}/test"),
        ("GET", f"/api/v1/integrations/{integration_id}/deliveries"),
    ):
        response = await api.client.request(method, path, headers=admin_b, json={} if method == "PATCH" else None)
        assert response.status_code == 404, (method, path, response.status_code)
    assert (await api.repos.integrations.get(TENANT_A, integration_id)).enabled


async def test_test_message_is_sent_and_logged(api: ApiHarness) -> None:
    receiver = Receiver()
    _stub(api, receiver)
    headers = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post(
        "/api/v1/integrations",
        json={"kind": "teams", "name": "Teams", "secret": {"webhook_url": "https://prod-00.westeurope.logic.azure.com/wf"}},
        headers=headers,
    )
    integration_id = created.json()["id"]
    result = await api.client.post(f"/api/v1/integrations/{integration_id}/test", headers=headers)
    assert result.json() == {"ok": True, "detail": "test message delivered", "http_status": 200}
    card = json.loads(receiver.requests[0].content)
    assert card["attachments"][0]["content"]["type"] == "AdaptiveCard"

    receiver.default = httpx.Response(403, text="forbidden by flow")
    failed = await api.client.post(f"/api/v1/integrations/{integration_id}/test", headers=headers)
    assert failed.json()["ok"] is False and failed.json()["http_status"] == 403

    log = await api.client.get(f"/api/v1/integrations/{integration_id}/deliveries", headers=headers)
    assert [(d["operation"], d["status"]) for d in log.json()] == [("test", "dead"), ("test", "sent")]
    assert "forbidden by flow" in log.json()[0]["last_error"]
    only_sent = await api.client.get(f"/api/v1/integrations/{integration_id}/deliveries?status=sent", headers=headers)
    assert len(only_sent.json()) == 1


async def test_ticketing_test_checks_credentials(api: ApiHarness) -> None:
    receiver = Receiver({
        "GET /rest/api/3/myself": httpx.Response(200, json={"displayName": "LG-SOTF bot"}),
        "GET /rest/api/3/project/SOC": httpx.Response(200, json={"key": "SOC"}),
    })
    _stub(api, receiver)
    headers = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post(
        "/api/v1/integrations",
        json={"kind": "jira", "name": "Jira", "config": {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com",
                                                         "project_key": "SOC"},
              "secret": {"api_token": fake_secret("jira")}},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["events"] == ["escalation.created", "escalation.decided"]
    result = await api.client.post(f"/api/v1/integrations/{created.json()['id']}/test", headers=headers)
    assert result.json()["ok"] is True and receiver.paths() == ["GET /rest/api/3/myself", "GET /rest/api/3/project/SOC"]
    assert "POST" not in " ".join(receiver.paths())  # a test never opens a ticket


async def test_tickets_are_listed_for_viewers_of_the_tenant(api: ApiHarness, make_settings: Callable[..., Any]) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    created = await api.client.post(
        "/api/v1/integrations",
        json={"kind": "servicenow", "name": "SNOW",
              "config": {"instance_url": "https://acme.service-now.com", "username": "lgsotf"},
              "secret": {"password": fake_secret("snow")}},
        headers=admin,
    )
    integration_id = created.json()["id"]
    alert_id = await add_alert(api.repos, TENANT_A)
    esc, _ = await api.repos.escalations.create_or_attach(TENANT_A, alert_id, reason="r")
    await api.repos.integrations.add_ticket(
        TENANT_A, integration_id, system="servicenow", alert_id=alert_id, escalation_id=esc.id,
        external_key="INC0010003", external_id="s1", external_url="https://acme.service-now.com/nav_to.do?uri=x",
    )
    viewer = await api.login_headers(TENANT_A, "viewer")
    by_alert = await api.client.get(f"/api/v1/tickets?alert_id={alert_id}", headers=viewer)
    assert [t["external_key"] for t in by_alert.json()] == ["INC0010003"]
    by_escalation = await api.client.get(f"/api/v1/tickets?escalation_id={esc.id}&escalation_id=other", headers=viewer)
    assert [t["escalation_id"] for t in by_escalation.json()] == [esc.id]
    assert (await api.client.get("/api/v1/tickets", headers=viewer)).status_code == 400
    other = await api.login_headers(TENANT_B, "viewer")
    assert (await api.client.get(f"/api/v1/tickets?alert_id={alert_id}", headers=other)).json() == []
