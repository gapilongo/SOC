"""Rollback eligibility: which executed actions can be undone, and why not."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from lg_sotf.services.response import ACTION_CATALOG, FORWARD_OF, check_guardrails
from lg_sotf.services.rollback import ROLLBACK_REASONS, RollbackService
from tests.fixtures.microsoft import make_action

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
SERVICE = RollbackService(SimpleNamespace(repos=None))  # type: ignore[arg-type]


def ms_ref(**extra: Any) -> Dict[str, Any]:
    return {"capability": "defender.isolation", "reversible": True, **extra}


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"status": "succeeded", "connector": "microsoft", "external_ref": ms_ref()}, None),
        ({"status": "succeeded", "connector": "webhook"}, None),
        ({"status": "failed", "connector": "microsoft", "external_ref": ms_ref(partial=True)}, None),
        ({"status": "failed", "connector": "microsoft", "external_ref": ms_ref()}, "not_executed"),
        ({"status": "dry_run", "connector": "dry_run"}, "not_executed"),
        ({"status": "executing", "connector": "webhook"}, "not_executed"),
        ({"status": "succeeded", "connector": "webhook", "rollback_of": uuid.uuid4()}, "is_rollback"),
        ({"status": "succeeded", "connector": "microsoft", "external_ref": {"reversible": False},
          "result": {"changed": False, "already": True}}, "nothing_changed"),
        ({"status": "succeeded", "connector": "microsoft", "external_ref": {"reversible": False},
          "result": {"changed": True}}, "irreversible"),
        ({"status": "succeeded", "connector": "microsoft",
          "external_ref": ms_ref(rollback_until=(NOW - timedelta(minutes=1)).isoformat())}, "window_expired"),
        ({"status": "succeeded", "connector": "ticketing"}, "connector_unsupported"),
        ({"status": "succeeded", "connector": "dry_run"}, "connector_unsupported"),
    ],
)
def test_eligibility_table(fields: Dict[str, Any], reason: Optional[str]) -> None:
    pinned = {"integration_id": uuid.uuid4()} if fields.get("connector") == "microsoft" else {}
    action = make_action("isolate_host", "ws-042", **{**pinned, **fields})
    result = SERVICE.eligibility(action, None, now=NOW)
    assert result.available is (reason is None) and result.reason == reason
    assert result.action_type == "release_host" and result.risk == "high"
    if reason is not None:
        assert reason in ROLLBACK_REASONS


def test_a_deleted_integration_offers_no_rollback() -> None:
    # ON DELETE SET NULL cleared the pin: every rollback would fail with connector_misconfigured, forever.
    orphan = make_action("isolate_host", "ws-042", status="succeeded", connector="microsoft", external_ref=ms_ref(),
                         integration_id=None)
    result = SERVICE.eligibility(orphan, None, now=NOW)
    assert (result.available, result.reason) == (False, "integration_gone") and "integration_gone" in ROLLBACK_REASONS
    webhook = make_action("block_ip", "185.220.101.44", status="succeeded", connector="webhook", integration_id=None)
    assert SERVICE.eligibility(webhook, None, now=NOW).available  # the webhook is not pinned to an integration


def test_irreversible_types_and_live_rollbacks() -> None:
    revoke = make_action("revoke_sessions", "a@b.example", status="succeeded", connector="webhook")
    result = SERVICE.eligibility(revoke, None, now=NOW)
    assert (result.available, result.reason, result.action_type) == (False, "irreversible", None)
    original = make_action("block_ip", "185.220.101.44", status="succeeded", connector="webhook")
    live = make_action("unblock_ip", "185.220.101.44", rollback_of=original.id, status="awaiting_approval")
    assert SERVICE.eligibility(original, live, now=NOW).reason == "rollback_exists"
    until = NOW + timedelta(days=1)
    open_window = make_action("isolate_host", "ws-1", status="succeeded", connector="microsoft",
                              integration_id=uuid.uuid4(), external_ref=ms_ref(rollback_until=until.isoformat()))
    assert SERVICE.eligibility(open_window, None, now=NOW).until == until


def test_catalog_inverses_are_consistent() -> None:
    for name, spec in ACTION_CATALOG.items():
        if spec.inverse:
            inverse = ACTION_CATALOG[spec.inverse]
            assert inverse.restorative and not inverse.plannable and inverse.target_kind == spec.target_kind, name
            assert FORWARD_OF[spec.inverse] == name
    assert ACTION_CATALOG["enable_user"].risk == "critical" and ACTION_CATALOG["confirm_compromised"].plannable
    assert "1 h" in ACTION_CATALOG["revoke_sessions"].irreversible_note


def test_restorative_guardrails() -> None:
    from lg_sotf.services.response import ResponsePolicy
    from lg_sotf.settings import Settings

    settings = Settings(_env_file=None, environment="test")
    tenant = {
        "protected_assets": {"hosts": ["ws-042"], "cidrs": ["10.0.0.0/8"]},
        "tools": {"internal_domains": ["contoso.example"]},
        "response": {"allowed_actions": ["isolate_host", "block_ip", "block_sender"]},
        "autonomy": {"critical": "approval"},
    }
    policy = ResponsePolicy.resolve(tenant, settings)
    assert check_guardrails("isolate_host", "ws-042", policy).code == "protected_asset"  # type: ignore[union-attr]
    assert check_guardrails("release_host", "ws-042", policy, restorative=True) is None
    assert check_guardrails("release_host", "ws-042", policy).code == "protected_asset"  # type: ignore[union-attr]
    assert check_guardrails("unblock_ip", "10.1.2.3", policy, restorative=True) is None
    assert check_guardrails("unblock_ip", "127.0.0.1", policy, restorative=True).code == "unroutable_ip"  # type: ignore[union-attr]
    assert check_guardrails("unblock_sender", "boss@contoso.example", policy, restorative=True) is None
    # The allowlist admits an inverse through its forward type; enable_user's forward type is not listed.
    assert check_guardrails("enable_user", "alice@contoso.example", policy, restorative=True).code == "action_not_allowed"  # type: ignore[union-attr]
