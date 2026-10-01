"""The mail package's declarations: catalog entries, permissions, options, docs, the connector and hygiene."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from lg_sotf.integrations.config import IntegrationConfigError, validate_config
from lg_sotf.integrations.microsoft import catalog
from lg_sotf.integrations.microsoft.capability import ActionSupport, Permission
from lg_sotf.integrations.microsoft.clouds import ALL_CLOUDS
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.integrations.microsoft.mail import CAPABILITIES
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_NOTIFY, MAIL_REMEDIATE
from lg_sotf.integrations.microsoft.mail.remediate import MailRemediateOptions
from lg_sotf.services.connectors.microsoft import permission_hint
from tests.fixtures.microsoft import fake_config, graph_error
from tests.unit.integrations.microsoft._support import build_connector
from tests.unit.integrations.microsoft.mail._scenario import ALICE, SOC, mail_world, message_id, purge_action

ROOT = Path(__file__).resolve().parents[5]
DOC = ROOT / "docs" / "microsoft-mail.md"
PACKAGE = ROOT / "src" / "lg_sotf" / "integrations" / "microsoft" / "mail"
TESTS = Path(__file__).resolve().parent
FLOW = ROOT / "tests" / "integration" / "integrations" / "microsoft" / "test_mail_flow.py"


def test_the_package_exports_both_capabilities() -> None:
    assert CAPABILITIES == (MAIL_REMEDIATE, MAIL_NOTIFY)
    assert catalog.check_invariants(CAPABILITIES).keys() == {"mail.remediate", "mail.notify"}
    assert {"mail.remediate", "mail.notify"} <= set(catalog.capabilities())


def test_mail_remediate_declaration() -> None:
    spec = MAIL_REMEDIATE
    assert (spec.key, spec.package, spec.api, spec.clouds, spec.licence) == (
        "mail.remediate", "mail", "graph", ALL_CLOUDS, ""
    )
    assert spec.actions["purge_message"].reversible is True
    assert spec.actions["purge_message"].rollback_window_s == 14 * 86_400
    assert spec.actions["restore_message"] == ActionSupport()
    assert spec.permissions == (
        Permission("graph", "Mail.ReadWrite", "find, remove and restore the reported message in recipient mailboxes",
                   exchange_rbac="Application Mail.ReadWrite"),
        Permission("graph", "User.Read.All",
                   "find the mailbox of a recipient address that is not the user principal name (an alias or proxy "
                   "address, as in hybrid tenants and message trace)"),
        Permission("graph", "ExchangeMessageTrace.Read.All", "find every recipient of the message", required=False,
                   when="recipient_source=message_trace"),
    )


def test_mail_notify_declaration() -> None:
    spec = MAIL_NOTIFY
    assert (spec.key, spec.package, spec.api, spec.clouds) == ("mail.notify", "mail", "graph", ALL_CLOUDS)
    assert spec.actions == {"notify_reporter": ActionSupport(note="a sent email cannot be recalled")}
    assert spec.permissions == (
        Permission("graph", "Mail.Send", "send the reply from the SOC mailbox", exchange_rbac="Application Mail.Send"),
        Permission("graph", "Mail.ReadWrite", "create the draft and find it in Sent Items (idempotency and proof)",
                   exchange_rbac="Application Mail.ReadWrite"),
    )


def test_the_catalog_endpoint_renders_the_options() -> None:
    out = {c["key"]: c for c in catalog.catalog_out()["capabilities"]}
    remediate = out["mail.remediate"]
    schema = remediate["options_schema"]["properties"]
    assert schema["recipient_source"]["enum"] == ["alert", "message_trace"]
    assert schema["mode"]["enum"] == ["soft_delete", "move_to_deleted_items"]
    assert (schema["max_mailboxes"]["minimum"], schema["max_mailboxes"]["maximum"]) == (1, 200)
    assert (schema["rollback_window_days"]["minimum"], schema["rollback_window_days"]["maximum"]) == (1, 30)
    assert remediate["options_defaults"] == {
        "recipient_source": "alert", "mode": "soft_delete", "max_mailboxes": 50, "rollback_window_days": 14,
        "include_reporter": True, "probe_mailbox": "",
    }
    assert remediate["actions"]["purge_message"]["inverse"] == "restore_message"
    assert out["mail.notify"]["options_defaults"] == {
        "sender_mailbox": "", "recipient_domains": [], "require_known_disposition": False,
    }
    assert out["mail.notify"]["options_schema"]["properties"]["recipient_domains"]["maxItems"] == 50


@pytest.mark.parametrize(
    "options",
    [{"max_mailboxes": 0}, {"max_mailboxes": 201}, {"rollback_window_days": 31}, {"mode": "permanent_delete"},
     {"recipient_source": "hunting"}, {"probe_mailbox": "x" * 321}, {"unknown": True}],
)
def test_out_of_range_options_are_rejected(options: dict) -> None:
    with pytest.raises(ValidationError):
        MailRemediateOptions.model_validate(options)


def test_remediate_option_problems() -> None:
    assert MailRemediateOptions().problems("usgov_dod") == []
    assert MailRemediateOptions(recipient_source="message_trace").problems("global") == []
    assert MailRemediateOptions(recipient_source="message_trace").problems("usgov_gcc_high") == [
        "recipient_source=message_trace needs the global cloud (Graph message trace is not available in the US "
        "Government clouds)"
    ]
    assert MailRemediateOptions(probe_mailbox="not-an-address").problems("global") == [
        "probe_mailbox must be an email address"
    ]


def test_integration_config_enforces_the_option_problems() -> None:
    config, _ = fake_config(cloud="usgov_gcc_high", capabilities={
        "mail.remediate": {"enabled": True, "live": False, "options": {"recipient_source": "message_trace"}},
    })
    with pytest.raises(IntegrationConfigError, match="message_trace"):
        validate_config("microsoft", config, require_https=True)
    config, _ = fake_config(capabilities={"mail.notify": {"enabled": True, "live": False, "options": {}}})
    with pytest.raises(IntegrationConfigError, match="sender_mailbox"):
        validate_config("microsoft", config, require_https=True)
    config, _ = fake_config(capabilities={"mail.notify": {"enabled": False, "options": {}}})
    validate_config("microsoft", config, require_https=True)  # a disabled capability may be incomplete


def test_every_permission_is_documented() -> None:
    text = DOC.read_text(encoding="utf-8")
    for spec in CAPABILITIES:
        for permission in spec.permissions:
            assert permission.role in text, permission.role
            if permission.exchange_rbac:
                assert permission.exchange_rbac in text, permission.exchange_rbac
    for heading in ("Overview", "Actions and Microsoft calls", "Permissions and setup", "Verification", "Rollback",
                    "Limits and licensing", "Troubleshooting"):
        assert re.search(rf"^## (\d+\. )?{re.escape(heading)}$", text, re.M), heading


GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.")
SECRET = re.compile(r"(?i)\b(client_secret|password|private_key|access_token)\s*[=:]\s*[\"'][^\"']+[\"']")


def test_no_credential_shaped_literals() -> None:
    files = [*PACKAGE.glob("*.py"), *TESTS.glob("*.py"), FLOW]
    assert len(files) >= 12
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not GUID.search(text), f"{path.name}: GUIDs are generated with uuid4/uuid5 at runtime"
        assert not JWT.search(text), f"{path.name}: no token-shaped literal"
        assert not SECRET.search(text), f"{path.name}: no secret-shaped assignment"


# ----------------------------------------------------------------------------- through the framework connector


def mail_test_connector(fake: Any, **remediate: Any) -> Any:
    return build_connector(fake, {
        "mail.remediate": {"enabled": True, "live": True,
                           "options": {"probe_mailbox": ALICE, "recipient_source": "message_trace", **remediate}},
        "mail.notify": {"enabled": True, "live": False, "options": {"sender_mailbox": SOC}},
    })


async def test_connection_test_passes_the_recommended_exchange_rbac_only_setup_as_unverified() -> None:
    # Mail.ReadWrite and Mail.Send granted only through Exchange RBAC for Applications: not in the token.
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    exchange.mailbox(SOC)
    fake.grant("graph", ["User.Read.All", "ExchangeMessageTrace.Read.All"])
    report = await mail_test_connector(fake).connector.probe_all()
    remediate = report.capabilities["mail.remediate"]
    # The probes read; they cannot prove the write roles, so the capabilities are unverified, never missing.
    assert remediate.status == "unverified" and [c.status for c in remediate.checks] == ["ok", "ok"]
    permissions = {(p.role, p.via): p.status for p in remediate.permissions}
    assert permissions == {
        ("Mail.ReadWrite", "token"): "unknown",
        ("Application Mail.ReadWrite", "exchange_rbac"): "unknown",
        ("User.Read.All", "token"): "granted",
        ("ExchangeMessageTrace.Read.All", "token"): "granted",
    }
    notify = report.capabilities["mail.notify"]
    assert [(c.name, c.status) for c in notify.checks] == [("sender mailbox", "ok"), ("send mail", "skipped")]
    assert {(p.role, p.via): p.status for p in notify.permissions}[("Mail.Send", "token")] == "unknown"
    assert notify.status == "unverified" and report.ok
    for check in (remediate, notify):
        assert "Test-ServicePrincipalAuthorization" in check.detail
        assert all("Test-ServicePrincipalAuthorization" in p.guidance for p in check.permissions
                   if p.via == "token" and p.status == "unknown")
    assert all(not p.warning for c in report.capabilities.values() for p in c.permissions)
    assert fake.writes() == [] and {r.method for r in fake.api_requests()} == {"GET"}


async def test_a_tenant_wide_read_grant_does_not_make_mail_capabilities_ok() -> None:
    # Mail.Read consented tenant-wide and no write role anywhere: the Inbox and Sent Items reads pass, while
    # every purge and every reply would get a 403.
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    exchange.mailbox(SOC)
    fake.grant("graph", ["Mail.Read", "User.Read.All"])
    report = await mail_test_connector(fake, recipient_source="alert").connector.probe_all()
    for key in ("mail.remediate", "mail.notify"):
        check = report.capabilities[key]
        assert "ok" in {c.status for c in check.checks}
        assert check.status == "unverified", key
        assert "Test-ServicePrincipalAuthorization" in check.detail


async def test_connection_test_warns_about_tenant_wide_mail_consent() -> None:
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    exchange.mailbox(SOC)
    fake.grant("graph", ["Mail.ReadWrite", "Mail.Send", "User.Read.All", "ExchangeMessageTrace.Read.All"])
    report = await mail_test_connector(fake).connector.probe_all()
    warned = {(key, p.role) for key, c in report.capabilities.items() for p in c.permissions if p.warning}
    assert warned == {("mail.remediate", "Mail.ReadWrite"), ("mail.notify", "Mail.Send"),
                      ("mail.notify", "Mail.ReadWrite")}
    assert all("Exchange RBAC" in p.warning for c in report.capabilities.values() for p in c.permissions if p.warning)


async def test_message_trace_permission_is_required_once_message_trace_is_selected() -> None:
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    exchange.mailbox(SOC)
    fake.grant("graph", ["User.Read.All"])
    fake.route("GET", "graph", "/v1.0/admin/exchange/tracing/messageTraces", graph_error(403, "Forbidden"))
    report = await mail_test_connector(fake).connector.probe_all()
    remediate = report.capabilities["mail.remediate"]
    trace = next(p for p in remediate.permissions if p.role == "ExchangeMessageTrace.Read.All")
    assert trace.required is True and trace.status == "missing"
    assert remediate.status == "missing_permission" and not report.ok
    alert_only = await mail_test_connector(fake, recipient_source="alert").connector.probe_all()
    trace = next(p for p in alert_only.capabilities["mail.remediate"].permissions
                 if p.role == "ExchangeMessageTrace.Read.All")
    assert trace.required is False and alert_only.capabilities["mail.remediate"].status == "unverified"


async def test_a_mailbox_403_hints_at_exchange_rbac_not_tenant_wide_consent() -> None:
    fake, _ = mail_world()
    harness = build_connector(fake, {"mail.remediate": {"enabled": True, "live": True}})
    denied = MicrosoftApiError("forbidden", "refused", status=403, code="ErrorAccessDenied")
    result = harness.connector._api_failure(MAIL_REMEDIATE, purge_action(message_id()), denied)
    assert result.detail["error"] == "permission_denied"
    assert "Exchange RBAC for Applications" in result.detail["hint"]
    assert "admin consent" not in result.detail["hint"] and "tenant-wide" in result.detail["hint"]
    assert "admin consent" in permission_hint(catalog.capabilities()["entra.account"])


async def test_the_connector_rehearses_when_not_live() -> None:
    fake, exchange = mail_world()
    harness = build_connector(fake, {"mail.remediate": {"enabled": True, "live": False, "options": {}}})
    result = await harness.connector.execute(purge_action(message_id()))
    # Without a database the alert cannot be read: the rehearsal still records a dry run, nothing is written.
    assert result.status == "dry_run" and result.detail["rehearsal"] is True
    assert result.detail["capability"] == "mail.remediate" and fake.writes() == []
    assert harness.checkpoints.patches == []
