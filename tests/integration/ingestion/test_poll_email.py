"""Polling a Microsoft 365 reporting mailbox into alerts against real PostgreSQL (Graph mocked)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Dict, List

import httpx
import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps, encrypt_source_secret
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.settings import Settings
from tests.integration.db._support import TENANT_A
from tests.unit.ingestion._email import build, wrap
from tests.unit.ingestion._support import public_resolver

pytestmark = pytest.mark.integration

CLIENT_SECRET = "test-" + "c" * 24


def graph(messages: Dict[str, bytes], received: datetime, patched: List[str]) -> httpx.MockTransport:
    unread = dict(messages)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/oauth2/v2.0/token"):
            assert CLIENT_SECRET in request.content.decode()
            return httpx.Response(200, json={"access_token": "tok-" + "t" * 8, "expires_in": 3600})
        if path.endswith("/mailFolders/inbox/messages"):
            value = [{"id": k, "receivedDateTime": received.isoformat()} for k in sorted(unread)]
            return httpx.Response(200, json={"value": value[: int(request.url.params["$top"])]})
        message_id = path.split("/messages/", 1)[1].split("/", 1)[0]
        if path.endswith("/$value"):
            return httpx.Response(200, content=messages[message_id])
        assert request.method == "PATCH" and json.loads(request.content) == {"isRead": True}
        patched.append(message_id)
        unread.pop(message_id, None)
        return httpx.Response(200, json={})

    return httpx.MockTransport(handler)


async def test_poll_m365_mailbox_creates_alerts_and_acknowledges_messages(
    repos: Repositories, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(ingestion={"page_size": 2})
    box = SecretBox([generate_key()])
    received = datetime.now(UTC) - timedelta(minutes=5)
    messages = {f"id{i}": wrap(build(subject=f"report {i}", message_id=f"<r{i}@partner.test>")) for i in range(3)}
    patched: List[str] = []
    secret = encrypt_source_secret(box, TENANT_A, "phish-m365", {"client_id": "app", "client_secret": CLIENT_SECRET})
    source = await repos.sources.create(
        TENANT_A, "m365_mailbox", "Reported phish", source_id="phish-m365",
        config={"azure_tenant_id": "contoso.example", "mailbox": "phish@example.com"}, secret_ciphertext=secret,
    )
    service = IngestionService(
        repos.db, settings, box, repos=repos,
        connector_deps=ConnectorDeps(transport=graph(messages, received, patched), resolver=public_resolver),
    )
    try:
        result = await service.poll_source(TENANT_A, source)
    finally:
        await service.close()
    assert result.error is None and len(result.inserted) == 3 and result.pages == 2
    assert patched == ["id0", "id1", "id2"]
    stored = await repos.sources.get(TENANT_A, "phish-m365")
    assert stored.cursor is not None and stored.cursor["ack"] == ["id2"] and stored.health == "healthy"
    alert = await repos.alerts.get(TENANT_A, result.inserted[0].alert_id)
    assert alert.source_id == "phish-m365" and alert.normalized["source_type"] == "email"
    assert alert.normalized["email"]["reporter"] == "bob@example.com"
    assert alert.status == "queued"
    runs: Any = await repos.runs.get(TENANT_A, alert.id)
    assert runs.status == "queued"
