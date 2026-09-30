"""Integration configuration and credential validation, secret encryption and event matching."""

from __future__ import annotations

import uuid

import pytest

from lg_sotf.integrations.config import (
    IntegrationConfigError,
    decrypt_secret,
    encrypt_secret,
    merge_secret,
    rate_limit_per_minute,
    validate_config,
    validate_events,
    validate_secret,
)
from lg_sotf.integrations.outbox import operation_for
from lg_sotf.security.crypto import SecretBox, generate_key
from tests.unit.integrations._support import fake_secret, slack_url

pytestmark = pytest.mark.unit


def test_slack_needs_a_slack_webhook_url() -> None:
    assert validate_secret("slack", {"webhook_url": slack_url()}, require_https=True)["webhook_url"] == slack_url()
    with pytest.raises(IntegrationConfigError, match="required"):
        validate_secret("slack", {}, require_https=True)
    with pytest.raises(IntegrationConfigError, match="Slack incoming webhook"):
        validate_secret("slack", {"webhook_url": "https://evil.example.com/hook"}, require_https=True)
    with pytest.raises(IntegrationConfigError, match="https"):
        validate_secret("teams", {"webhook_url": "http://prod.logic.azure.com/x"}, require_https=True)


def test_unknown_config_keys_and_bad_values_are_refused() -> None:
    with pytest.raises(IntegrationConfigError, match="config"):
        validate_config("slack", {"webhook_url": slack_url()}, require_https=True)  # a secret in config
    with pytest.raises(IntegrationConfigError, match="recipients"):
        validate_config("email", {"recipients": ["not an address"]}, require_https=True)
    email = validate_config("email", {"recipients": ["SOC@Example.com", "soc@example.com"]}, require_https=True)
    assert email["recipients"] == ["soc@example.com"]
    with pytest.raises(IntegrationConfigError, match="https"):
        validate_config("webhook", {"url": "http://soar.example.com/hook"}, require_https=True)
    assert validate_config("webhook", {"url": "http://soar.example.com/hook"}, require_https=False)


def test_jira_cloud_needs_the_account_email_and_a_project_key() -> None:
    base = {"base_url": "https://acme.atlassian.net", "project_key": "SOC"}
    with pytest.raises(IntegrationConfigError, match="email"):
        validate_config("jira", base, require_https=True)
    ok = validate_config("jira", {**base, "email": "bot@acme.com"}, require_https=True)
    assert ok["issue_type"] == "Task" and ok["labels"] == ["lg-sotf"]
    assert validate_config("jira", {**base, "deployment": "datacenter"}, require_https=True)["deployment"] == "datacenter"
    with pytest.raises(IntegrationConfigError, match="project_key"):
        validate_config("jira", {**base, "email": "bot@acme.com", "project_key": "soc; drop"}, require_https=True)


def test_webhook_signing_secret_has_a_minimum_length() -> None:
    with pytest.raises(IntegrationConfigError, match="16 bytes"):
        validate_secret("webhook", {"signing_secret": "short"}, require_https=True)
    assert validate_secret("webhook", {"signing_secret": fake_secret()}, require_https=True)


def test_events_are_restricted_per_kind() -> None:
    assert validate_events("slack", ["alert.critical_received", "alert.critical_received"]) == ["alert.critical_received"]
    with pytest.raises(IntegrationConfigError, match="not available"):
        validate_events("jira", ["action.failed"])
    with pytest.raises(IntegrationConfigError):
        validate_events("slack", ["everything"])


def test_secret_merge_patch() -> None:
    merged = merge_secret({"webhook_url": "a", "bot_token": "b"}, {"bot_token": None, "signing_secret": "c"})
    assert merged == {"webhook_url": "a", "signing_secret": "c"}


def test_secrets_are_bound_to_the_tenant_and_integration() -> None:
    box = SecretBox([generate_key()])
    integration_id = uuid.uuid4()
    token = encrypt_secret(box, "tenant-a", integration_id, {"api_token": fake_secret()})
    assert token is not None and fake_secret() not in token
    assert decrypt_secret(box, "tenant-a", integration_id, token) == {"api_token": fake_secret()}
    with pytest.raises(IntegrationConfigError):
        decrypt_secret(box, "tenant-b", integration_id, token)
    with pytest.raises(IntegrationConfigError):
        decrypt_secret(box, "tenant-a", uuid.uuid4(), token)
    with pytest.raises(IntegrationConfigError, match="not configured"):
        decrypt_secret(None, "tenant-a", integration_id, token)
    assert encrypt_secret(box, "tenant-a", integration_id, {}) is None


def test_matching_by_event_severity_and_level() -> None:
    slack = {"kind": "slack", "events": ["escalation.created"], "min_severity": "high", "config": {}}
    assert operation_for(slack, "escalation.created", "critical", "L1") == "notify"
    assert operation_for(slack, "escalation.created", "medium", "L1") is None
    assert operation_for(slack, "action.failed", "critical", None) is None
    jira = {"kind": "jira", "events": ["escalation.created", "escalation.decided"], "min_severity": "low",
            "config": {"min_level": "L2"}}
    assert operation_for(jira, "escalation.created", "high", "L1") is None
    assert operation_for(jira, "escalation.created", "high", "L3") == "ticket_create"
    assert operation_for(jira, "escalation.decided", "info", "L1") == "ticket_update"


def test_rate_limit_defaults_per_kind() -> None:
    assert rate_limit_per_minute("slack", {}) == 60
    assert rate_limit_per_minute("teams", {"rate_limit_per_minute": 5}) == 5
