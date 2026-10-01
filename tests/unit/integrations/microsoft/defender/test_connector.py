"""The Defender capabilities through the real MicrosoftConnector: rehearsal, live results, hosts, tokens, hygiene."""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from tests.fixtures.microsoft import FakeMicrosoft, defender_error, make_action
from tests.unit.integrations.microsoft._support import build_connector
from tests.unit.integrations.microsoft.defender._support import FakeDefender

ALL = ("defender.isolation", "defender.indicators", "defender.file_indicators", "defender.forensics")


def caps(*keys: str, live: bool = True, **options: Dict[str, Any]) -> Dict[str, Any]:
    return {k: {"enabled": True, "live": live, "options": options.get(k.split(".")[1], {})} for k in keys}


async def test_rehearsal_resolves_with_gets_only() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    h = build_connector(defender.fake, caps("defender.isolation", live=False))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "dry_run" and result.detail["rehearsal"] is True
    assert result.detail["capability"] == "defender.isolation" and result.detail["live"] is False
    assert result.detail["resolved"]["machine"]["id"] == mid
    assert result.detail["summary"] == "would isolate ws-042 (Full)"
    assert defender.writes() == [] and h.checkpoints.patches == []


async def test_live_isolation_carries_the_connector_fields_and_checkpoints() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    h = build_connector(defender.fake, caps("defender.isolation"))
    action = make_action("isolate_host", "ws-042")
    result = await h.connector.execute(action)
    assert result.status == "succeeded"
    assert {k: result.detail[k] for k in ("connector", "capability", "integration_id", "live", "changed")} == {
        "connector": "microsoft", "capability": "defender.isolation", "integration_id": str(h.integration.id),
        "live": True, "changed": True,
    }
    ref = result.external_ref or {}
    assert ref["capability"] == "defender.isolation" and ref["reversible"] is True
    assert h.checkpoints.patches == [{"machine_id": mid, "requested": True},
                                     {"machine_action_id": result.detail["machine_action_id"]}]
    # The comment falls back to the marker alone when the alert cannot be read (no repositories here).
    assert defender.body(defender.writes()[0])["Comment"] == f"LG-SOTF action {action.id}"


async def test_invalid_targets_and_misrouted_types_fail_visibly() -> None:
    defender = FakeDefender()
    h = build_connector(defender.fake, caps(*ALL))
    private = await h.connector.execute(make_action("block_ip", "10.1.2.3"))
    assert private.status == "failed" and private.detail["error"] == "unsupported_target"
    ambiguous = FakeDefender()
    ambiguous.machine("ws-042", health="Inactive")
    ambiguous.machine("ws-042", health="Inactive")
    h = build_connector(ambiguous.fake, caps("defender.isolation"))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "failed" and result.detail["error"] == "ambiguous_target" and result.detail["count"] == 2
    assert ambiguous.writes() == []


async def test_throttled_defender_defers_the_action() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", r"/api/machines/[^/]+/isolate", defender_error(429, "TooManyRequests",
                                                                         headers={"Retry-After": "900"}))
    h = build_connector(defender.fake, caps("defender.isolation"))
    result = await h.connector.execute(make_action("isolate_host", "ws-042", attempts=1))
    assert result.status == "deferred" and result.retry_after_s == 900.0 and result.detail["deferred"] == "throttled"


async def test_geo_host_and_token_audience() -> None:
    defender = FakeDefender(FakeMicrosoft(geo="eu"))
    defender.machine("ws-042")
    h = build_connector(defender.fake, caps("defender.isolation"))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "succeeded"
    hosts = {r.url.host for r in defender.fake.api_requests()}
    assert hosts == {"eu.api.security.microsoft.com"}
    (form,) = defender.fake.token_forms()
    assert form["scope"] == "https://api.securitycenter.microsoft.com/.default"


async def test_us_government_clouds_are_refused_before_any_request() -> None:
    gov = FakeMicrosoft(cloud="usgov_gcc_high")
    h = build_connector(gov, {})
    original = make_action("isolate_host", "ws-042", status="succeeded")
    rollback = make_action("release_host", "ws-042", rollback_of=original.id, execution_owner="scheduler")
    result = await h.connector.execute(rollback)
    assert result.status == "failed" and result.detail["error"] == "unsupported_cloud" and gov.requests == []


async def test_connection_test_reports_every_defender_capability() -> None:
    defender = FakeDefender()
    defender.fake.grant("defender", ["Machine.Isolate", "Machine.ReadWrite.All", "Ti.ReadWrite.All"])
    h = build_connector(defender.fake, caps("defender.isolation", "defender.indicators", live=False))
    report = await h.connector.probe_all()
    assert report.tokens["defender"].status == "ok"
    assert report.capabilities["defender.isolation"].status == "ok"
    assert report.capabilities["defender.indicators"].status == "ok"
    assert report.capabilities["defender.forensics"].status == "not_enabled"
    forensics = {p.role: p.status for p in report.capabilities["defender.forensics"].permissions}
    assert forensics == {"Machine.CollectForensics": "missing", "Machine.ReadWrite.All": "granted"}
    assert all(r.method == "GET" or defender.fake.is_token_request(r) for r in defender.fake.requests)


@pytest.mark.parametrize("credential", ["client_secret", "certificate"])
async def test_credentials_never_reach_results_or_requests(credential: str) -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    h = build_connector(defender.fake, caps(*ALL), credential=credential)
    results = [
        await h.connector.execute(make_action("isolate_host", "ws-042")),
        await h.connector.execute(make_action("block_ip", "185.220.101.44")),
        await h.connector.execute(make_action("collect_forensics", "ws-404")),
    ]
    secret_values = [v for v in h.secret.values() if isinstance(v, str)]
    issued = [r for r in defender.fake.requests if defender.fake.is_token_request(r)]
    assert issued
    dumped = json.dumps([{"detail": r.detail, "ref": r.external_ref} for r in results], default=str)
    for value in secret_values:
        assert value not in dumped
        assert all(value.encode() not in r.content for r in defender.fake.api_requests())
    assert "Bearer" not in dumped and "eyJ" not in dumped
