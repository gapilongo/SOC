"""Phishing over the API: POST /ingest/email, mailbox sources with write-only secrets, tenant phishing settings."""

from __future__ import annotations

import json

import httpx
import pytest

from lg_sotf.ingestion.service import IngestionService
from lg_sotf.ingestion.sources import ConnectorDeps, source_secret_context
from tests.integration.api._support import TENANT_A, TENANT_B, ApiHarness
from tests.unit.ingestion._email import auth, build, wrap

pytestmark = pytest.mark.integration

RFC822 = {"Content-Type": "message/rfc822"}
CLIENT_SECRET = "test-" + "s" * 24
IMAP_PASSWORD = "test-" + "p" * 16


def reported(subject: str = "Verify your account", reporter: str = "bob@example.com") -> bytes:
    inner = build(
        sender="it@examp1e.test", subject=subject, ar=[auth("examp1e.test", spf="fail", dmarc="fail")],
        html="<a href='http://198.51.100.9/login'>https://login.example.com</a>",
    )
    return wrap(inner, reporter)


async def test_push_a_reported_email(api: ApiHarness) -> None:
    key, token = await api.api_key(TENANT_A)
    headers = {"X-API-Key": token, **RFC822}
    first = await api.client.post("/api/v1/ingest/email", content=reported(), headers=headers)
    assert first.status_code == 202, first.text
    body = first.json()
    assert body["source_id"] == f"email:{key.id}" and body["inserted"] == 1 and body["enqueued"] == 1
    alert = await api.repos.alerts.get(TENANT_A, body["items"][0]["alert_id"])
    assert alert.category == "phishing" and alert.severity == "high" and alert.status == "queued"
    assert alert.title == "Reported email: Verify your account"
    email = alert.normalized["email"]
    assert email["reporter"] == "bob@example.com" and email["from"]["address"] == "it@examp1e.test"
    assert alert.normalized["entities"]["users"] == ["bob@example.com"]
    assert alert.raw["schema"] == "lgsotf.email.v1" and len(alert.raw["body"]["excerpt"]) <= 4_096
    # Deduplicated on Message-ID plus reporter; another reporter is a separate report.
    again = await api.client.post("/api/v1/ingest/email", content=reported(), headers=headers)
    assert again.json()["duplicates"] == 1 and again.json()["items"][0]["alert_id"] == alert.id
    other = await api.client.post(
        "/api/v1/ingest/email?reporter=carol%40example.com", content=reported(), headers=headers
    )
    assert other.json()["inserted"] == 1
    stored = await api.repos.alerts.get(TENANT_A, other.json()["items"][0]["alert_id"])
    assert stored.normalized["email"]["reporter"] == "carol@example.com"
    assert stored.normalized["email"]["reporter_source"] == "param"
    # Tenant isolation: another tenant's key never sees or collides with these.
    _, token_b = await api.api_key(TENANT_B)
    other_tenant = await api.client.post("/api/v1/ingest/email", content=reported(), headers={"X-API-Key": token_b, **RFC822})
    assert other_tenant.json()["inserted"] == 1


async def test_email_push_body_limit_follows_the_email_message_limit(make_api) -> None:
    # A larger ingestion.email.max_message_bytes applies to /ingest/email even when it exceeds
    # api.max_ingest_body_bytes; other ingest routes keep the API limit.
    api = await make_api(
        api={"max_body_bytes": 16 * 1024, "max_ingest_body_bytes": 32 * 1024},
        ingestion={"email": {"max_message_bytes": 256 * 1024}},
    )
    _, token = await api.api_key(TENANT_A)
    headers = {"X-API-Key": token, **RFC822}
    big = reported(subject="Large report " + "x" * 10)
    big = big.replace(b"Reporting this one.", b"Reporting this one. " + b"padding " * 12_000)
    assert 64 * 1024 < len(big) < 256 * 1024
    accepted = await api.client.post("/api/v1/ingest/email", content=big, headers=headers)
    assert accepted.status_code == 202, accepted.text
    too_big = await api.client.post("/api/v1/ingest/email", content=b"x" * (300 * 1024), headers=headers)
    assert too_big.status_code == 413
    alerts = await api.client.post(
        "/api/v1/ingest/alerts", content=b"[" + b" " * (64 * 1024) + b"]",
        headers={"X-API-Key": token, "Content-Type": "application/json"},
    )
    assert alerts.status_code == 413


async def test_push_validation(api: ApiHarness) -> None:
    _, token = await api.api_key(TENANT_A)
    key = {"X-API-Key": token}
    wrong_type = await api.client.post("/api/v1/ingest/email", json={"mime": "x"}, headers=key)
    assert wrong_type.status_code == 415
    empty = await api.client.post("/api/v1/ingest/email", content=b"", headers={**key, **RFC822})
    assert empty.status_code == 400
    bad_reporter = await api.client.post(
        "/api/v1/ingest/email?reporter=not-an-address", content=reported(), headers={**key, **RFC822}
    )
    assert bad_reporter.status_code == 422
    octet = await api.client.post(
        "/api/v1/ingest/email", content=reported("octet"), headers={**key, "Content-Type": "application/octet-stream"}
    )
    assert octet.status_code == 202
    _, read_token = await api.api_key(TENANT_A, scopes=("read",))
    denied = await api.client.post("/api/v1/ingest/email", content=reported(), headers={"X-API-Key": read_token, **RFC822})
    assert denied.status_code == 403
    admin = await api.login_headers(TENANT_A, "admin")
    user = await api.client.post("/api/v1/ingest/email", content=reported(), headers={**admin, **RFC822})
    assert user.status_code in (401, 403)
    # The reserved email source ids cannot be pushed to as webhooks or created as sources.
    hook = await api.client.post(f"/api/v1/ingest/webhook/email:{'x'}", json={"a": 1}, headers=key)
    assert hook.status_code == 404
    created = await api.client.post(
        "/api/v1/sources", json={"id": "email:mine", "type": "webhook", "name": "x"}, headers=admin
    )
    assert created.status_code == 422


async def test_oversized_and_unparsable_messages(make_api) -> None:  # type: ignore[no-untyped-def]
    api = await make_api(ingestion={"email": {"max_message_bytes": 2_048, "max_parts": 5}})
    _, token = await api.api_key(TENANT_A)
    headers = {"X-API-Key": token, **RFC822}
    big = await api.client.post("/api/v1/ingest/email", content=b"Subject: x\n\n" + b"a" * 4_096, headers=headers)
    assert big.status_code == 413
    deep = b"Content-Type: multipart/mixed; boundary=b\n\n" + b"\n--b\n\nx" * 500
    rejected = await api.client.post("/api/v1/ingest/email", content=deep[:2_000], headers=headers)
    assert rejected.status_code == 202
    assert rejected.json()["rejected"] == 1 and "MIME parts" in rejected.json()["items"][0]["reason"]


def _offline_ingestion(api: ApiHarness) -> None:
    async def public_resolver(host: str, port: int) -> list:
        return ["93.184.216.34"]

    ctx = api.ctx
    ctx.ingestion = IngestionService(
        ctx.db, ctx.settings, secret_box=ctx.secret_box, repos=ctx.repos,
        connector_deps=ConnectorDeps(resolver=public_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(404))),
    )


async def test_mailbox_sources_keep_their_secrets_write_only(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    _offline_ingestion(api)
    m365 = await api.client.post(
        "/api/v1/sources",
        json={
            "id": "phish-m365", "type": "m365_mailbox", "name": "Reported phish (M365)",
            "config": {"azure_tenant_id": "contoso.example", "mailbox": "phish@example.com"},
            "secret": {"client_id": "app-id", "client_secret": CLIENT_SECRET},
        },
        headers=admin,
    )
    assert m365.status_code == 201, m365.text
    assert m365.json()["has_secret"] is True and CLIENT_SECRET not in m365.text
    stored = await api.repos.sources.get(TENANT_A, "phish-m365")
    assert CLIENT_SECRET not in (stored.secret_ciphertext or "")
    assert api.ctx.secret_box.decrypt_json(
        stored.secret_ciphertext, context=source_secret_context(TENANT_A, "phish-m365")
    )["client_secret"] == CLIENT_SECRET
    imap = await api.client.post(
        "/api/v1/sources",
        json={
            "id": "phish-imap", "type": "imap", "name": "Reported phish (IMAP)",
            "config": {"host": "imap.mail.test", "folder": "INBOX"},
            "secret": {"username": "phish@example.com", "password": IMAP_PASSWORD},
        },
        headers=admin,
    )
    assert imap.status_code == 201, imap.text
    listed = await api.client.get("/api/v1/sources", headers=admin)
    assert IMAP_PASSWORD not in listed.text and CLIENT_SECRET not in listed.text
    no_secret = await api.client.post(
        "/api/v1/sources",
        json={"type": "imap", "name": "x", "config": {"host": "imap.mail.test"}},
        headers=admin,
    )
    assert no_secret.status_code == 422
    in_config = await api.client.post(
        "/api/v1/sources",
        json={"type": "m365_mailbox", "name": "x", "config": {"client_secret": CLIENT_SECRET}},
        headers=admin,
    )
    assert in_config.status_code == 422
    audit = (await api.repos.audit.list(TENANT_A, resource_type="source")).items
    assert audit and all(IMAP_PASSWORD not in json.dumps(e.details) for e in audit)


async def test_tenant_phishing_settings(api: ApiHarness) -> None:
    admin = await api.login_headers(TENANT_A, "admin")
    patch = {"phishing": {"protected_brands": ["Example Bank", "examplebank.test"], "executives": ["Jane Doe"],
                          "trusted_authserv_ids": ["mx.example.com"]}}
    ok = await api.client.patch("/api/v1/tenant/settings", json=patch, headers=admin)
    assert ok.status_code == 200, ok.text
    assert ok.json()["settings"]["phishing"]["executives"] == ["Jane Doe"]
    bad = await api.client.patch("/api/v1/tenant/settings", json={"phishing": {"brands": ["x"]}}, headers=admin)
    assert bad.status_code == 422 and "phishing" in bad.text
    too_many = await api.client.patch(
        "/api/v1/tenant/settings", json={"phishing": {"executives": [f"Person {i}" for i in range(501)]}}, headers=admin
    )
    assert too_many.status_code == 422
    removed = await api.client.patch("/api/v1/tenant/settings", json={"phishing": None}, headers=admin)
    assert "phishing" not in removed.json()["settings"]
    analyst = await api.login_headers(TENANT_A, "analyst")
    assert (await api.client.patch("/api/v1/tenant/settings", json=patch, headers=analyst)).status_code == 403
    entries = (await api.repos.audit.list(TENANT_A, resource_type="tenant")).items
    assert any(e.action == "tenant.settings_updated" and "phishing" in e.details.get("keys", []) for e in entries)
