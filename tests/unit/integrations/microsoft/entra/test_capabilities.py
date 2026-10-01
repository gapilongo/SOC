"""The Entra capability declarations, their docs, the connector around them, and credential hygiene of the sources."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

import pytest

from lg_sotf.integrations.microsoft.catalog import capabilities, catalog_out, check_invariants
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS
from lg_sotf.integrations.microsoft.entra import CAPABILITIES
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_ACCOUNT, ENTRA_PASSWORD, ENTRA_RISK, ENTRA_SESSIONS
from tests.fixtures.microsoft import FakeMicrosoft, make_action
from tests.unit.integrations.microsoft._support import build_connector
from tests.unit.integrations.microsoft.entra._support import Directory

ROOT = Path(__file__).resolve().parents[5]
DOC = ROOT / "docs" / "microsoft-entra.md"
UPN = "alice@contoso.example"
GUARD = {"RoleManagement.Read.Directory", "GroupMember.Read.All", "User.Read.All"}
ALL_ROLES = sorted({p.role for spec in CAPABILITIES for p in spec.permissions})


def caps(*keys: str, live: bool = True) -> Dict[str, Dict[str, Any]]:
    return {key: {"enabled": True, "live": live, "options": {}} for key in keys}


def test_the_package_exports_four_capabilities_in_the_catalog() -> None:
    assert [spec.key for spec in CAPABILITIES] == ["entra.account", "entra.sessions", "entra.password", "entra.risk"]
    check_invariants(CAPABILITIES)
    catalog = capabilities()
    for spec in CAPABILITIES:
        assert catalog[spec.key] is spec and spec.package == "entra" and spec.api == "graph"
        assert spec.clouds == ALL_CLOUDS and {p.api for p in spec.permissions} == {"graph"}
        assert GUARD <= {p.role for p in spec.permissions}
    assert set(ENTRA_ACCOUNT.actions) == {"disable_user", "enable_user"} and ENTRA_ACCOUNT.actions["disable_user"].reversible
    assert set(ENTRA_SESSIONS.actions) == {"revoke_sessions"} and not ENTRA_SESSIONS.actions["revoke_sessions"].reversible
    assert set(ENTRA_PASSWORD.actions) == {"reset_password"}
    assert set(ENTRA_RISK.actions) == {"confirm_compromised", "dismiss_user_risk"}
    assert ENTRA_RISK.actions["confirm_compromised"].reversible and "P2" in ENTRA_RISK.licence
    out = {c["key"]: c for c in catalog_out()["capabilities"]}
    assert out["entra.account"]["options_defaults"] == {"allow_guests": False, "allow_synced_users": True}
    assert out["entra.password"]["options_defaults"] == {"require_mfa_on_change": False}
    assert "synced" in out["entra.account"]["live_confirmation"]
    assert "Temporary Access Pass" in out["entra.password"]["live_confirmation"]


def test_exact_permissions_and_directory_roles() -> None:
    def roles(spec: Any) -> Dict[str, Any]:
        return {p.role: p.directory_role for p in spec.permissions}

    assert roles(ENTRA_ACCOUNT)["User.EnableDisableAccount.All"] == "User Administrator"
    assert roles(ENTRA_PASSWORD)["User-PasswordProfile.ReadWrite.All"] == "User Administrator"
    assert "User.RevokeSessions.All" in roles(ENTRA_SESSIONS)
    assert {"IdentityRiskyUser.ReadWrite.All", "IdentityRiskyUser.Read.All"} <= set(roles(ENTRA_RISK))
    assert all(p.exchange_rbac is None for spec in CAPABILITIES for p in spec.permissions)


def test_every_permission_is_documented() -> None:
    text = DOC.read_text(encoding="utf-8")
    missing = [role for role in ALL_ROLES if f"`{role}`" not in text]
    assert missing == []
    for heading in ("Overview", "Actions and Microsoft calls", "Permissions and setup", "Verification", "Rollback",
                    "Limits and licensing", "Troubleshooting"):
        assert re.search(rf"^## .*{heading}", text, re.MULTILINE), heading
    for term in ("User Administrator", "PIM", "Authorization_RequestDenied", "Request_ResourceNotFound",
                 "Directory_ConcurrencyViolation", "P2"):
        assert term in text


def test_sources_and_tests_hold_no_credential_shaped_literals() -> None:
    files = [
        *sorted((ROOT / "src/lg_sotf/integrations/microsoft/entra").glob("*.py")),
        *sorted(Path(__file__).parent.glob("*.py")),
        ROOT / "tests/integration/integrations/microsoft/test_entra_flow.py",
        DOC,
    ]
    guid = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    jwt = re.compile(r"eyJ[A-Za-z0-9_-]{10,}")
    assigned = re.compile(r"""(password|client_secret|secret|token)\s*[=:]\s*["'][^"'\s]{6,}["']""", re.IGNORECASE)
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not guid.search(text), f"GUID literal in {path.name}"
        assert not jwt.search(text), f"JWT-like literal in {path.name}"
        assert not assigned.search(text), f"credential literal in {path.name}"


@pytest.mark.parametrize(("key", "action_type"), [
    ("entra.account", "disable_user"), ("entra.sessions", "revoke_sessions"),
    ("entra.password", "reset_password"), ("entra.risk", "confirm_compromised"),
])
async def test_rehearsal_through_the_connector_only_reads(key: str, action_type: str) -> None:
    fake = FakeMicrosoft()
    user = Directory(fake).add(UPN)
    harness = build_connector(fake, caps(key, live=False))
    result = await harness.connector.execute(make_action(action_type, UPN))
    assert result.status == "dry_run" and result.detail["rehearsal"] is True and result.detail["capability"] == key
    resolved = result.detail["resolved"]
    assert resolved["guard"] == "passed" and resolved["user"]["id"] == user.id
    assert resolved["would_execute"]["method"] in ("PATCH", "POST")
    assert fake.writes() == [] and harness.checkpoints.patches == []


async def test_live_execution_through_the_connector() -> None:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    alice = directory.add(UPN)
    harness = build_connector(fake, caps("entra.account"))
    result = await harness.connector.execute(make_action("disable_user", UPN))
    assert result.status == "succeeded" and result.detail["capability"] == "entra.account"
    assert result.detail["connector"] == "microsoft" and result.detail["live"] is True
    assert result.external_ref is not None and result.external_ref["reversible"] is True
    assert result.external_ref["capability"] == "entra.account" and alice.enabled is False
    assert harness.checkpoints.patches == [
        {"user_id": alice.id, "prior": {"accountEnabled": True}, "synced": False, "requested": True}
    ]


async def test_refusals_and_denials_keep_the_package_hint_through_the_connector() -> None:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    directory.add(UPN, owned=[{"@odata.type": "#microsoft.graph.group", "id": "g", "isAssignableToRole": True}])
    harness = build_connector(fake, caps("entra.sessions"))
    result = await harness.connector.execute(make_action("revoke_sessions", UPN))
    assert result.status == "failed" and result.detail["error"] == "privileged_target_refused"
    assert result.detail["reason"] == "role_assignable_group_owner" and result.detail["changed"] is False
    assert result.detail["capability"] == "entra.sessions" and fake.writes() == []


async def test_the_connection_test_only_reads() -> None:
    fake = FakeMicrosoft()
    Directory(fake).add(UPN)
    fake.grant("graph", ALL_ROLES)
    harness = build_connector(fake, caps("entra.account", "entra.sessions", "entra.password", "entra.risk"))
    report = await harness.connector.probe_all()
    assert {k: v.status for k, v in report.capabilities.items() if k.startswith("entra.")} == {
        "entra.account": "ok", "entra.sessions": "ok", "entra.password": "ok", "entra.risk": "ok",
    }
    directory_roles = [p for p in report.capabilities["entra.account"].permissions if p.via == "directory_role"]
    assert [(p.role, p.status) for p in directory_roles] == [("User Administrator", "unknown")]
    assert {r.method for r in fake.api_requests()} == {"GET"} and fake.writes() == []
