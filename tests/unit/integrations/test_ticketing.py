"""Jira and ServiceNow clients against mocked HTTP: payloads, auth, idempotent search, state parsing."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.db.repos.integrations import ExternalTicket
from lg_sotf.integrations.config import IntegrationConfigError
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp
from lg_sotf.integrations.ticketing import (
    JiraClient,
    ServiceNowClient,
    correlation_token,
    decision_text,
    draft_from_event,
)
from lg_sotf.settings import Settings
from tests.unit.integrations._support import event, fake_secret, public_resolver

pytestmark = pytest.mark.unit

JIRA = {"base_url": "https://acme.atlassian.net", "email": "bot@acme.com", "project_key": "SOC",
        "issue_type": "Task", "labels": ["lg-sotf"], "resolve_transition": "Done", "priority_map": {"high": "High"}}
SNOW = {"instance_url": "https://acme.service-now.com", "username": "lgsotf", "comment_field": "work_notes",
        "resolve_on_decision": True, "resolve_state": "6", "close_code": "Solution provided",
        "assignment_group": "SOC"}


def _ticket(key: str, external_id: str = "10001") -> ExternalTicket:
    now = datetime.now(UTC)
    return ExternalTicket.model_validate({
        "id": uuid.uuid4(), "tenant_id": "tenant-a", "integration_id": uuid.uuid4(), "alert_id": "alert-1",
        "escalation_id": "esc-1", "action_id": None, "system": "jira", "external_key": key, "external_id": external_id,
        "external_url": None, "external_status": None, "resolved": False, "resolved_by": None, "last_synced_at": None,
        "sync_error": None, "created_at": now, "updated_at": now,
    })


class Server:
    def __init__(self, routes: Dict[str, Callable[[httpx.Request], httpx.Response]]) -> None:
        self.routes = routes
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.method} {request.url.path}"
        handler = self.routes.get(key)
        return handler(request) if handler else httpx.Response(404, json={"errorMessages": [key]})

    def http(self, settings: Settings) -> IntegrationHttp:
        return IntegrationHttp(settings, transport=httpx.MockTransport(self), resolver=public_resolver)


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


def test_correlation_token_is_stable_and_opaque() -> None:
    token = correlation_token("tenant-a", "escalation", "esc-1")
    assert token == correlation_token("tenant-a", "escalation", "esc-1")
    assert token != correlation_token("tenant-b", "escalation", "esc-1")
    assert token.startswith("lgsotf-") and "tenant" not in token and "esc" not in token


def test_draft_is_a_summary() -> None:
    draft = draft_from_event(event(), "https://soc.example.com", "lgsotf-abc")
    assert draft.summary.startswith("[LG-SOTF] [HIGH] ")
    assert "Reference: lgsotf-abc" in draft.lines and any(line.startswith("Entities: ") for line in draft.lines)
    assert "must-never-appear" not in json.dumps(draft.lines)


async def test_jira_cloud_create_uses_adf_labels_and_basic_auth(settings: Settings) -> None:
    token = fake_secret("jira")
    server = Server({
        "GET /rest/api/3/search/jql": lambda r: httpx.Response(200, json={"issues": []}),
        "POST /rest/api/3/issue": lambda r: httpx.Response(201, json={"id": "10001", "key": "SOC-7"}),
    })
    client = JiraClient(server.http(settings), JIRA, {"api_token": token})
    draft = draft_from_event(event(), "https://soc.example.com", "lgsotf-abc")
    assert await client.find("lgsotf-abc") is None
    ref = await client.create(draft)
    assert ref.key == "SOC-7" and ref.url == "https://acme.atlassian.net/browse/SOC-7"
    search, create = server.requests
    assert search.url.params["jql"] == 'labels = "lgsotf-abc" ORDER BY created ASC'
    fields = json.loads(create.content)["fields"]
    assert fields["project"] == {"key": "SOC"} and fields["labels"] == ["lg-sotf", "lgsotf-abc"]
    assert fields["description"]["type"] == "doc" and fields["priority"] == {"name": "High"}
    expected = "Basic " + base64.b64encode(f"bot@acme.com:{token}".encode()).decode()
    assert create.headers["Authorization"] == expected


async def test_jira_datacenter_uses_v2_and_a_bearer_token(settings: Settings) -> None:
    token = fake_secret("pat")
    server = Server({"POST /rest/api/2/issue": lambda r: httpx.Response(201, json={"id": "1", "key": "SOC-1"})})
    client = JiraClient(server.http(settings), {**JIRA, "deployment": "datacenter"}, {"api_token": token})
    await client.create(draft_from_event(event(), "https://soc.example.com", "lgsotf-abc"))
    request = server.requests[0]
    assert request.headers["Authorization"] == f"Bearer {token}"
    assert isinstance(json.loads(request.content)["fields"]["description"], str)


async def test_jira_resolve_picks_the_configured_transition(settings: Settings) -> None:
    server = Server({
        "POST /rest/api/3/issue/SOC-7/comment": lambda r: httpx.Response(201, json={}),
        "GET /rest/api/3/issue/SOC-7/transitions": lambda r: httpx.Response(200, json={"transitions": [
            {"id": "11", "name": "In Progress", "to": {"name": "In Progress"}},
            {"id": "31", "name": "Done", "to": {"name": "Done"}},
        ]}),
        "POST /rest/api/3/issue/SOC-7/transitions": lambda r: httpx.Response(204),
    })
    client = JiraClient(server.http(settings), JIRA, {"api_token": fake_secret()})
    await client.comment(_ticket("SOC-7"), decision_text(event("escalation.decided"), "https://soc.example.com"))
    assert await client.resolve(_ticket("SOC-7"), "decided") == "Done"
    assert json.loads(server.requests[-1].content) == {"transition": {"id": "31"}}
    missing = JiraClient(server.http(settings), {**JIRA, "resolve_transition": "Close"}, {"api_token": fake_secret()})
    with pytest.raises(DeliveryError, match="not available"):
        await missing.resolve(_ticket("SOC-7"), "decided")


async def test_jira_state_reports_who_resolved(settings: Settings) -> None:
    issue = {
        "key": "SOC-7",
        "fields": {"status": {"name": "Done", "statusCategory": {"key": "done"}}, "assignee": {"displayName": "Ann"}},
        "changelog": {"histories": [
            {"author": {"displayName": "Bob"}, "items": [{"field": "status"}]},
            {"author": {"displayName": "Eve"}, "items": [{"field": "labels"}]},
        ]},
    }
    server = Server({"GET /rest/api/3/issue/SOC-7": lambda r: httpx.Response(200, json=issue)})
    state = await JiraClient(server.http(settings), JIRA, {"api_token": fake_secret()}).state(_ticket("SOC-7"))
    assert state.resolved and state.status == "Done" and state.resolved_by == "Bob"


def test_missing_credentials_are_a_configuration_error(settings: Settings) -> None:
    with pytest.raises(IntegrationConfigError):
        JiraClient(IntegrationHttp(settings), JIRA, {})
    with pytest.raises(IntegrationConfigError):
        ServiceNowClient(IntegrationHttp(settings), SNOW, {})


async def test_servicenow_create_search_comment_resolve_and_state(settings: Settings) -> None:
    password = fake_secret("snow")
    row = {"sys_id": "abc123", "number": "INC0010001", "state": "1"}
    server = Server({
        "GET /api/now/table/incident": lambda r: httpx.Response(200, json={"result": []}),
        "POST /api/now/table/incident": lambda r: httpx.Response(201, json={"result": row}),
        "PATCH /api/now/table/incident/abc123": lambda r: httpx.Response(200, json={"result": row}),
    })
    client = ServiceNowClient(server.http(settings), SNOW, {"password": password})
    assert await client.find("lgsotf-abc") is None
    ref = await client.create(draft_from_event(event(), "https://soc.example.com", "lgsotf-abc"))
    assert ref.key == "INC0010001" and ref.id == "abc123" and "incident.do%3Fsys_id%3Dabc123" in ref.url
    search, create = server.requests[:2]
    assert search.url.params["sysparm_query"] == "correlation_id=lgsotf-abc"
    body = json.loads(create.content)
    assert body["correlation_id"] == "lgsotf-abc" and body["urgency"] == "1" and body["impact"] == "2"
    assert body["assignment_group"] == "SOC"
    ticket = _ticket("INC0010001", "abc123")
    await client.comment(ticket, "decided")
    assert json.loads(server.requests[-1].content) == {"work_notes": "decided"}
    assert await client.resolve(ticket, "decided") == "Resolved"
    assert json.loads(server.requests[-1].content)["state"] == "6"


async def test_servicenow_state_uses_display_values(settings: Settings) -> None:
    record = {"result": {"state": {"value": "7", "display_value": "Closed"},
                         "resolved_by": {"value": "u1", "display_value": "Dana Admin"}}}
    server = Server({"GET /api/now/table/incident/abc123": lambda r: httpx.Response(200, json=record)})
    state = await ServiceNowClient(server.http(settings), SNOW, {"password": fake_secret()}).state(_ticket("INC1", "abc123"))
    assert state.resolved and state.status == "Closed" and state.resolved_by == "Dana Admin"
    assert server.requests[0].url.params["sysparm_display_value"] == "all"


async def test_client_errors_are_permanent_and_redacted(settings: Settings) -> None:
    body: Dict[str, Any] = {"errorMessages": ["Field 'priority' cannot be set. apikey=" + "k" * 30]}
    server = Server({"POST /rest/api/3/issue": lambda r: httpx.Response(400, json=body)})
    client = JiraClient(server.http(settings), JIRA, {"api_token": fake_secret()})
    with pytest.raises(DeliveryError) as err:
        await client.create(draft_from_event(event(), "https://soc.example.com", "lgsotf-abc"))
    assert not err.value.retryable and "priority" in str(err.value) and "k" * 30 not in str(err.value)


async def test_decision_sync_sees_a_create_that_finishes_concurrently(settings: Settings) -> None:
    """The create's ticket lands between the two lookups: the decision must not be dropped as "no ticket"."""
    from types import SimpleNamespace

    from lg_sotf.integrations.ticketing import DeliveryDeferred, TicketService

    ticket = _ticket("INC0010001")
    state = {"create_done": False}
    calls: List[str] = []

    async def has_pending(*_: Any, **__: Any) -> bool:
        calls.append("has_pending")
        pending = not state["create_done"]
        state["create_done"] = True  # the concurrent create finishes right after the first lookup
        return pending

    async def find_ticket(*_: Any, **__: Any) -> Any:
        calls.append("find_ticket")
        found = ticket if state["create_done"] else None
        state["create_done"] = True
        return found

    commented: List[str] = []

    class Client:
        async def comment(self, _ticket: ExternalTicket, text: str) -> None:
            commented.append(text)

        async def resolve(self, _ticket: ExternalTicket, _text: str) -> None:
            return None

    repos = SimpleNamespace(integrations=SimpleNamespace(has_pending=has_pending, find_ticket=find_ticket))
    service = TicketService(repos, settings)  # type: ignore[arg-type]
    service.client = lambda _integration: Client()  # type: ignore[method-assign]
    integration = SimpleNamespace(tenant_id="tenant-a", id=uuid.uuid4(), config={"comment_on_decision": True})
    payload = {"alert": {"id": "alert-1"}, "escalation": {"decision": "needs_more_info"}}
    try:
        result = await service.sync_decision(integration, payload, escalation_id="esc-1")  # type: ignore[arg-type]
    except DeliveryDeferred:
        result = {"deferred": True}
    assert result != {"skipped": "no_ticket"}, calls
    assert result.get("deferred") or commented
