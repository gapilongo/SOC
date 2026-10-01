"""The Microsoft connection test: token requests and GETs only, permission matrix, capability statuses."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterator, List

import httpx
import pytest

from lg_sotf.integrations.microsoft.capability import Permission, ProbeCheck
from lg_sotf.integrations.microsoft.catalog import capabilities, override_for_tests
from lg_sotf.integrations.microsoft.connection_test import (
    RBAC_ONLY_GUIDANCE,
    RBAC_UNVERIFIED_DETAIL,
    TENANT_WIDE_WARNING,
)
from tests.fixtures.microsoft import TOKEN_PATH, FakeMicrosoft, defender_error, graph_error, token_error
from tests.unit.integrations.microsoft._support import ACCOUNT, FAKE_SPECS, ISOLATION, AccountHandler, build_connector

ISO = "defender.fake_isolation"
ACC = "entra.fake_account"


def only_reads(fake: FakeMicrosoft) -> bool:
    return all(r.method == "GET" or fake.is_token_request(r) for r in fake.requests)


async def test_zero_capabilities_still_checks_the_credential() -> None:
    fake = FakeMicrosoft()
    h = build_connector(fake, {})
    report = await h.connector.probe_all()
    assert report.ok and report.tokens["graph"].status == "ok" and report.tokens["defender"].status == "not_needed"
    # Every catalog capability is listed, none enabled and none probed: one Graph token request, nothing else.
    assert set(report.capabilities) == set(capabilities())
    assert all(c.status == "not_enabled" and not c.enabled and not c.checks for c in report.capabilities.values())
    assert [r.url.host for r in fake.requests] == ["login.microsoftonline.com"]


@pytest.fixture
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


@pytest.mark.usefixtures("fake_catalog")
async def test_permission_matrix_and_statuses() -> None:
    fake = FakeMicrosoft()
    fake.grant("graph", ["User.Read.All"])
    fake.grant("defender", ["Machine.Isolate"])
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    h = build_connector(fake, {ISO: {"enabled": True, "live": False}})
    report = await h.connector.probe_all()
    assert only_reads(fake) and fake.writes() == []
    assert report.tokens["defender"].roles == ["Machine.Isolate"] and report.tokens["graph"].roles == ["User.Read.All"]
    iso = report.capabilities[ISO]
    assert iso.status == "missing_permission" and iso.enabled and not iso.live
    by_role = {(p.role, p.via): p for p in iso.permissions}
    assert by_role[("Machine.Isolate", "token")].status == "granted"
    assert by_role[("Machine.Read.All", "token")].status == "missing"
    # Only needed in strict mode: reported, but not required with the default options.
    assert by_role[("User.Read.All", "token")].required is False
    assert [c.status for c in iso.checks] == ["ok"]
    account = report.capabilities[ACC]
    assert account.status == "not_enabled"
    roles = {(p.role, p.via): p.status for p in account.permissions}
    assert roles == {
        ("User.EnableDisableAccount.All", "token"): "missing",
        ("User Administrator", "directory_role"): "unknown",
        ("User.Read.All", "token"): "granted",
        ("Application Mail.Read", "exchange_rbac"): "unknown",
    }
    assert not report.ok


@pytest.mark.usefixtures("fake_catalog")
async def test_ok_when_granted_and_probes_pass() -> None:
    fake = FakeMicrosoft()
    fake.grant("defender", ["Machine.Isolate", "Machine.Read.All"])
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    h = build_connector(fake, {ISO: {"enabled": True, "live": True}})
    report = await h.connector.probe_all()
    assert report.capabilities[ISO].status == "ok" and report.ok


@pytest.mark.usefixtures("fake_catalog")
@pytest.mark.parametrize(("code", "status"), [("Forbidden", "missing_permission"), ("NotLicensed", "not_licensed")])
async def test_probe_failures(code: str, status: str) -> None:
    fake = FakeMicrosoft()
    fake.grant("defender", ["Machine.Isolate", "Machine.Read.All"])
    fake.route("GET", "defender", "/api/machines", defender_error(403, code))
    h = build_connector(fake, {ISO: {"enabled": True}})
    report = await h.connector.probe_all()
    assert report.capabilities[ISO].status == status and report.capabilities[ISO].checks[0].detail.startswith("HTTP 403")


@pytest.mark.usefixtures("fake_catalog")
async def test_unverified_without_readable_evidence() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, httpx.Response(
        200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": "opaque-" + "t" * 20}))
    h = build_connector(fake, {ACC: {"enabled": True}})
    report = await h.connector.probe_all()
    account = report.capabilities[ACC]
    assert account.status == "unverified" and {p.status for p in account.permissions} == {"unknown"}
    assert report.ok and report.tokens["graph"].roles is None


@pytest.mark.usefixtures("fake_catalog")
async def test_token_failure_reports_the_hint() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("unauthorized_client", aadsts=700016))
    h = build_connector(fake, {ACC: {"enabled": True}})
    report = await h.connector.probe_all()
    graph = report.tokens["graph"]
    assert graph.status == "failed" and graph.error == "app_not_in_tenant" and graph.aadsts == 700016 and graph.hint
    assert report.capabilities[ACC].status == "error" and not report.ok
    assert "fake description" not in report.model_dump_json()


async def test_certificate_info_is_reported() -> None:
    fake = FakeMicrosoft()
    h = build_connector(fake, {}, credential="certificate")
    report = await h.connector.probe_all()
    assert report.certificate is not None and report.certificate.days_left >= 29
    assert len(report.certificate.thumbprint_sha1) == 40 and len(report.certificate.thumbprint_sha256) == 64
    assert "client_assertion" in fake.token_forms()[0]
    assert "PRIVATE KEY" not in report.model_dump_json()


# An RBAC-scoped mailbox permission only (the shape of mail.remediate): nothing else to show in a token.
RBAC_ONLY = replace(
    ACCOUNT, key="entra.fake_rbac",
    permissions=(Permission("graph", "Mail.ReadWrite", "read mailboxes", exchange_rbac="Application Mail.ReadWrite"),),
)


@pytest.mark.usefixtures("fake_catalog")
async def test_an_rbac_scoped_permission_missing_from_the_token_is_unknown_not_missing() -> None:
    fake = FakeMicrosoft()
    fake.grant("graph", ["User.EnableDisableAccount.All"])  # User.Read.All only through Exchange RBAC
    h = build_connector(fake, {ACC: {"enabled": True}})
    report = await h.connector.probe_all()
    account = report.capabilities[ACC]
    by_role = {(p.role, p.via): p for p in account.permissions}
    token_row = by_role[("User.Read.All", "token")]
    assert token_row.status == "unknown" and token_row.guidance == RBAC_ONLY_GUIDANCE and not token_row.warning
    assert "Test-ServicePrincipalAuthorization" in token_row.guidance
    assert by_role[("Application Mail.Read", "exchange_rbac")].status == "unknown"
    # The granted token role is evidence for itself only, never for the RBAC-scoped one.
    assert account.status == "unverified" and account.detail == RBAC_UNVERIFIED_DETAIL and report.ok


class MailboxReadProbe(AccountHandler):
    """Probes the way the mail packages do: one GET, which a read-only grant passes."""

    async def probe(self) -> List[ProbeCheck]:
        await self.ctx.api("graph").request("GET", "/v1.0/users", params={"$top": "1"}, deadline=self.ctx.deadline)
        return [ProbeCheck("mailbox access", "ok", permission="Mail.ReadWrite")]


@pytest.mark.parametrize(("reply", "status"), [
    (httpx.Response(200, json={"value": []}), "unverified"),
    (graph_error(403, "ErrorAccessDenied"), "missing_permission"),
])
async def test_rbac_only_setup_is_unverified_even_when_its_read_probe_passes(reply: httpx.Response, status: str) -> None:
    fake = FakeMicrosoft()
    fake.grant("graph", ["Mail.Read"])  # tenant-wide read only: the GET passes, every write would get a 403
    fake.route("GET", "graph", "/v1.0/users", reply)
    with override_for_tests((replace(RBAC_ONLY, handler=MailboxReadProbe),)):
        report = await build_connector(fake, {"entra.fake_rbac": {"enabled": True}}).connector.probe_all()
    check = report.capabilities["entra.fake_rbac"]
    assert [(p.role, p.status) for p in check.permissions] == [
        ("Mail.ReadWrite", "unknown"), ("Application Mail.ReadWrite", "unknown"),
    ]
    assert check.status == status
    if status == "unverified":  # never ok, and never missing_permission for the recommended setup
        assert [c.status for c in check.checks] == ["ok"] and check.detail == RBAC_UNVERIFIED_DETAIL and report.ok


async def test_a_tenant_wide_grant_of_an_rbac_scoped_permission_is_a_warning_not_evidence() -> None:
    fake = FakeMicrosoft()
    fake.grant("graph", ["Mail.ReadWrite"])
    with override_for_tests((RBAC_ONLY,)):
        report = await build_connector(fake, {"entra.fake_rbac": {"enabled": True}}).connector.probe_all()
    check = report.capabilities["entra.fake_rbac"]
    token_row = next(p for p in check.permissions if p.via == "token")
    assert token_row.status == "granted" and token_row.warning == TENANT_WIDE_WARNING
    assert check.status == "unverified"


@pytest.mark.parametrize(("mode", "required", "status"), [("strict", True, "missing_permission"),
                                                         ("normal", False, "ok")])
async def test_a_conditional_permission_is_required_when_its_condition_holds(
    mode: str, required: bool, status: str
) -> None:
    # Declared the way packages do it: optional by default, needed under a condition.
    conditional = replace(ISOLATION, permissions=(
        *ISOLATION.permissions[:2],
        Permission("graph", "User.Read.All", "strict lookups", required=False, when="mode=strict"),
    ))
    fake = FakeMicrosoft()
    fake.grant("defender", ["Machine.Isolate", "Machine.Read.All"])
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    options = {"mode": mode, "note": "needed"} if mode == "strict" else {}
    with override_for_tests((conditional,)):
        h = build_connector(fake, {ISO: {"enabled": True, "options": options}})
        report = await h.connector.probe_all()
    iso = report.capabilities[ISO]
    row = next(p for p in iso.permissions if p.role == "User.Read.All")
    assert row.required is required and row.status == "missing"
    assert iso.status == status
