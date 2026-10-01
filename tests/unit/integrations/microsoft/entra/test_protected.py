"""Protected assets apply to the user a target *resolves* to, not only to the literal target the guardrails saw."""

from __future__ import annotations

import uuid
from typing import Any, Dict

import pytest

from lg_sotf.integrations.microsoft.catalog import capabilities
from lg_sotf.services.response import ResponsePolicy, check_guardrails, protected_lookup
from tests.fixtures.microsoft import FakeMicrosoft, make_action, ms_settings
from tests.unit.integrations.microsoft._support import build_connector
from tests.unit.integrations.microsoft.entra._support import Directory, FakeUser

CEO = "ceo@contoso.example"
ALIAS = "chief@contoso.example"
TENANT: Dict[str, Any] = {"protected_assets": {"users": [CEO]}, "autonomy": {"critical": "approval"}}
EXECUTORS = {
    "disable_user": "entra.account", "reset_password": "entra.password", "revoke_sessions": "entra.sessions",
    "confirm_compromised": "entra.risk",
}


def caps(key: str, *, live: bool = True) -> Dict[str, Any]:
    return {key: {"enabled": True, "live": live, "options": {}}}


def ceo(fake: FakeMicrosoft) -> FakeUser:
    return Directory(fake).add(CEO, mail=CEO, proxy_addresses=[f"SMTP:{CEO}", f"smtp:{ALIAS}"])


def assert_untouched(fake: FakeMicrosoft, user: FakeUser) -> None:
    assert fake.writes() == [] and user.enabled is True


@pytest.mark.parametrize("action_type", sorted(EXECUTORS))
@pytest.mark.parametrize("target", ["alias", "object_id"])
async def test_an_alias_or_object_id_of_a_protected_user_is_refused_before_any_write(
    action_type: str, target: str
) -> None:
    fake = FakeMicrosoft()
    user = ceo(fake)
    literal = ALIAS if target == "alias" else user.id
    policy = ResponsePolicy.resolve(TENANT, ms_settings())
    assert check_guardrails(action_type, literal, policy) is None  # the literal target passes the guardrails
    harness = build_connector(fake, caps(EXECUTORS[action_type]), protected=protected_lookup(TENANT))
    result = await harness.connector.execute(make_action(action_type, literal))
    assert result.status == "failed" and result.detail["error"] == "protected_asset", result.detail
    assert result.detail["category"] == "user" and result.detail["changed"] is False
    assert result.detail["user"] == {"id": user.id, "upn": CEO}  # the approver sees who it resolved to
    assert harness.checkpoints.patches == []
    assert_untouched(fake, user)


async def test_the_rehearsal_shows_the_refusal_and_the_resolved_user() -> None:
    fake = FakeMicrosoft()
    user = ceo(fake)
    harness = build_connector(fake, caps("entra.account", live=False), protected=protected_lookup(TENANT))
    result = await harness.connector.execute(make_action("disable_user", ALIAS))
    resolved = result.detail["resolved"]
    assert result.status == "dry_run" and resolved["user"]["upn"] == CEO
    assert resolved["guard"] == {"refused": "protected_asset", "reason": "protected_asset", "category": "user",
                                 "matched": "upn"}
    assert_untouched(fake, user)


async def test_an_unprotected_user_still_passes() -> None:
    fake = FakeMicrosoft()
    alice = Directory(fake).add("alice@contoso.example")
    harness = build_connector(fake, caps("entra.account"), protected=protected_lookup(TENANT))
    result = await harness.connector.execute(make_action("disable_user", "alice@contoso.example"))
    assert result.status == "succeeded" and alice.enabled is False


async def test_a_rollback_of_a_restorative_type_stays_possible_after_the_user_became_protected() -> None:
    fake = FakeMicrosoft()
    user = ceo(fake)
    user.enabled = False
    harness = build_connector(fake, caps("entra.account"), protected=protected_lookup(TENANT))
    original = make_action("disable_user", CEO, status="succeeded", external_ref={
        "user_id": user.id, "upn": CEO, "prior": {"accountEnabled": True}, "requested": True, "reversible": True,
        "capability": "entra.account",
    })
    harness.checkpoints.rows[original.id] = original
    rollback = make_action("enable_user", CEO, rollback_of=original.id, execution_owner="scheduler")
    result = await harness.connector.execute(rollback)
    assert result.status == "succeeded" and user.enabled is True


async def test_without_the_tenant_list_the_check_fails_closed() -> None:
    fake = FakeMicrosoft()
    alice = Directory(fake).add("alice@contoso.example")
    harness = build_connector(fake, caps("entra.account"), protected=None)
    result = await harness.connector.execute(make_action("disable_user", "alice@contoso.example"))
    assert result.status == "failed" and result.detail["error"] == "protected_asset"
    assert result.detail["category"] == "unavailable" and fake.writes() == [] and alice.enabled is True


def test_a_malformed_protected_list_matches_everything() -> None:
    lookup = protected_lookup({"protected_assets": {"users": [{"not": "a name"}]}})
    assert lookup("user", f"{uuid.uuid4()}@contoso.example") == "protected_assets_invalid"
    assert set(EXECUTORS.values()) <= set(capabilities())
