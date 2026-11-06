"""The process's SecretBox reaches every secret reader the response path builds (F11)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Callable

import pytest

from lg_sotf.db.repos.integrations import Integration
from lg_sotf.integrations.config import encrypt_secret
from lg_sotf.security.crypto import SecretBox, generate_key
from lg_sotf.services.connectors.registry import encrypt_webhook_secret
from lg_sotf.services.connectors.webhook import WebhookConnector
from lg_sotf.services.response import ResponseService
from lg_sotf.services.review import ReviewService
from lg_sotf.settings import Settings
from tests.unit.services.fakes import FakeEvents, FakeRepos

pytestmark = pytest.mark.unit

TENANT = "t1"
HOOK = "https://tenant-soar.example.net/hook"


def _ticket_integration(box: SecretBox) -> Integration:
    integration_id = uuid.uuid4()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return Integration(
        id=integration_id,
        tenant_id=TENANT,
        kind="jira",
        name="Jira",
        enabled=True,
        config={},
        secret_ciphertext=encrypt_secret(box, TENANT, integration_id, {"api_token": "jira-token-0123456789"}),
        events=[],
        min_severity="low",
        created_by=None,
        created_at=now,
        updated_at=now,
    )


def _assert_uses(service: ResponseService, box: SecretBox) -> None:
    # The settings carry a different key, so only the injected box can read these ciphertexts.
    assert service.secret_box() is box
    tenant = {
        "response": {
            "connector": "webhook",
            "dry_run": False,
            "webhook_url": HOOK,
            "webhook_secret_ciphertext": encrypt_webhook_secret(box, TENANT, "tenant-webhook-secret-0123456789"),
        }
    }
    hook = service.connector_for(TENANT, tenant)
    assert isinstance(hook, WebhookConnector) and hook.origin == "tenant"

    integration = _ticket_integration(box)
    service._ticket_connector(integration)
    assert service._ticketing is not None
    assert service._ticketing.secret(integration) == {"api_token": "jira-token-0123456789"}


def test_response_service_forwards_its_box(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(response={"dry_run": False})
    box = SecretBox([generate_key()])
    _assert_uses(ResponseService(FakeRepos(), settings, FakeEvents(), secret_box=box), box)  # type: ignore[arg-type]


def test_review_service_forwards_its_box(make_settings: Callable[..., Settings]) -> None:
    settings = make_settings(response={"dry_run": False})
    box = SecretBox([generate_key()])
    review = ReviewService(FakeRepos(), settings, FakeEvents(), secret_box=box)  # type: ignore[arg-type]
    _assert_uses(review.responses, box)
