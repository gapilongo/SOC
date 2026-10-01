"""Probes and rehearsals only read: GET requests (and token requests), never a write."""

from __future__ import annotations

import pytest

from lg_sotf.integrations.microsoft.capability import CapabilitySpec
from lg_sotf.integrations.microsoft.defender import (
    CAPABILITIES,
    DEFENDER_FILE_INDICATORS,
    DEFENDER_FORENSICS,
    DEFENDER_INDICATORS,
    DEFENDER_ISOLATION,
    DEFENDER_STOP_QUARANTINE,
)
from lg_sotf.integrations.microsoft.http import ReadOnlyViolation
from tests.fixtures.microsoft import defender_error, make_action, make_context
from tests.unit.integrations.microsoft.defender._support import FakeDefender, rehearse

SHA1 = "e" * 40


def only_reads(defender: FakeDefender) -> bool:
    return all(r.method == "GET" or defender.fake.is_token_request(r) for r in defender.fake.requests)


@pytest.mark.parametrize("spec", CAPABILITIES, ids=lambda s: s.key)
async def test_probes_only_read_and_pass(spec: CapabilitySpec) -> None:
    defender = FakeDefender()  # no machines: GET /api/machines answers 404, which counts as ok
    ctx, _ = make_context(defender.fake, spec, read_only=True)
    checks = await spec.handler(ctx).probe()
    assert checks and all(c.status == "ok" for c in checks), checks
    assert all(c.permission in {p.role for p in spec.permissions} for c in checks)
    assert only_reads(defender) and defender.fake.api_requests()
    assert all(r.url.params.get("$top") == "1" for r in defender.fake.api_requests())


async def test_probe_reports_forbidden_and_disabled_features() -> None:
    defender = FakeDefender()
    defender.fail("GET", r"/api/indicators", defender_error(403, "Forbidden"))
    ctx, _ = make_context(defender.fake, DEFENDER_INDICATORS, read_only=True)
    (check,) = await DEFENDER_INDICATORS.handler(ctx).probe()
    assert (check.status, check.permission, check.detail) == ("forbidden", "Ti.ReadWrite.All", "HTTP 403 Forbidden")
    defender.fail("GET", r"/api/machineactions", defender_error(403, "DisabledFeature"))
    ctx, _ = make_context(defender.fake, DEFENDER_FORENSICS, read_only=True)
    (check,) = await DEFENDER_FORENSICS.handler(ctx).probe()
    assert check.status == "error" and "feature disabled" in check.detail


@pytest.mark.parametrize(
    ("spec", "action", "path"),
    [
        (DEFENDER_ISOLATION, make_action("isolate_host", "ws-042"), "/api/machines/{id}/isolate"),
        (DEFENDER_FORENSICS, make_action("collect_forensics", "ws-042"), "/api/machines/{id}/collectInvestigationPackage"),
        (DEFENDER_STOP_QUARANTINE, make_action("quarantine_file", SHA1, params={"scope": {"hosts": ["ws-042", "ws-9"]}}),
         "/api/machines/{id}/StopAndQuarantineFile"),
    ],
    ids=["isolation", "forensics", "stop_quarantine"],
)
async def test_machine_rehearsals_only_resolve(spec: CapabilitySpec, action, path: str) -> None:  # type: ignore[no-untyped-def]
    defender = FakeDefender()
    mid = defender.machine("ws-042.corp.contoso.example")
    resolved = await rehearse(defender, spec, action)
    assert resolved["would_execute"]["method"] == "POST" and resolved["would_execute"]["path_template"] == path
    machines = resolved["machines"] if "machines" in resolved else [resolved["machine"]]
    assert machines[0] == {"id": mid, "computer_dns_name": "ws-042.corp.contoso.example", "health_status": "Active"}
    assert only_reads(defender) and resolved["summary"].startswith("would ")


async def test_isolation_rehearsal_reports_an_unresolvable_host() -> None:
    defender = FakeDefender()
    resolved = await rehearse(defender, DEFENDER_ISOLATION, make_action("isolate_host", "ws-404"))
    assert resolved["machine"] is None and resolved["problem"] == "not_found" and only_reads(defender)


@pytest.mark.parametrize(
    ("spec", "action_type", "target", "indicator_type"),
    [
        (DEFENDER_INDICATORS, "block_ip", "185.220.101.44", "IpAddress"),
        (DEFENDER_FILE_INDICATORS, "quarantine_file", SHA1, "FileSha1"),
    ],
)
async def test_indicator_rehearsals_look_up_existing_indicators(
    spec: CapabilitySpec, action_type: str, target: str, indicator_type: str
) -> None:
    defender = FakeDefender()
    existing = defender.indicator(target, indicator_type, "Audit")
    resolved = await rehearse(defender, spec, make_action(action_type, target))
    assert resolved["would_execute"]["path_template"] == "/api/indicators"
    assert "expirationTime" in resolved["would_execute"]["body_keys"]
    assert resolved["indicator"]["existing"][0]["id"] == existing and resolved["indicator"]["type"] == indicator_type
    assert only_reads(defender)


async def test_a_read_only_context_refuses_writes_before_sending() -> None:
    # The framework hands rehearse/verify/probe a read-only client; execute through it never reaches Defender.
    defender = FakeDefender()
    defender.machine("ws-042")
    action = make_action("isolate_host", "ws-042")
    ctx, _ = make_context(defender.fake, DEFENDER_ISOLATION, action=action, read_only=True)
    with pytest.raises(ReadOnlyViolation):
        await DEFENDER_ISOLATION.handler(ctx).execute(action)
    assert only_reads(defender)
