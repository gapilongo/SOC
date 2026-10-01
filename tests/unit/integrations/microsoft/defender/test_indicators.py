"""defender.indicators and defender.file_indicators: block, adopt, conflict, verify inline, unblock, encoding."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import httpx
import pytest

from lg_sotf.integrations.microsoft.defender import DEFENDER_FILE_INDICATORS, DEFENDER_INDICATORS
from lg_sotf.integrations.microsoft.odata import InvalidTarget
from tests.fixtures.microsoft import defender_error, make_action
from tests.unit.integrations.microsoft.defender._support import FakeDefender, execute, marker, rerun, verify

NET = DEFENDER_INDICATORS
FILES = DEFENDER_FILE_INDICATORS
IP = "185.220.101.44"
SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def indicator_queries(defender: FakeDefender) -> list[str]:
    return [r.url.query.decode("ascii") for r in defender.fake.api_requests()
            if r.method == "GET" and r.url.path == "/api/indicators"]


async def test_block_ip_creates_a_block_with_an_expiry_and_verifies_inline() -> None:
    defender = FakeDefender()
    action = make_action("block_ip", IP)
    result, store = await execute(defender, NET, action)
    assert result.status == "succeeded" and result.detail["changed"] is True
    (post,) = defender.writes()
    body = defender.body(post)
    expiry = datetime.fromisoformat(body.pop("expirationTime"))
    assert timedelta(days=29, hours=23) < expiry - datetime.now(UTC) <= timedelta(days=30)
    assert body == {
        "indicatorValue": IP,
        "indicatorType": "IpAddress",
        "action": "Block",
        "title": f"LG-SOTF block_ip {IP}",
        "description": f"{marker(action)}; alert alert-1",
        "severity": "High",
        "generateAlert": True,
    }
    indicator_id = result.detail["indicator"]["id"]
    assert store == {"indicator_value": IP, "indicator_type": "IpAddress", "requested": True,
                     "indicator_id": indicator_id}
    ref = result.external_ref or {}
    assert ref["created"] is True and ref["reversible"] is True and ref["indicator_id"] == indicator_id
    assert datetime.fromisoformat(ref["rollback_until"]) == expiry.replace(microsecond=0)
    plan = result.verify
    assert plan is not None and plan.state == "verified"
    assert plan.detail["enforcement"] == "configured; takes effect in up to 48 h"
    assert len(indicator_queries(defender)) == 2  # the lookup before, the inline re-read after


@pytest.mark.parametrize(
    ("action_type", "target", "indicator_type", "value"),
    [
        ("block_domain", "Evil.Example.", "DomainName", "evil.example"),
        ("block_url", "https://evil.example/login", "Url", "https://evil.example/login"),
        # Defender needs all eight IPv6 segments: the full form in the body and in the lookup.
        ("block_ip", "2001:4860:4860::8888", "IpAddress", "2001:4860:4860:0000:0000:0000:0000:8888"),
    ],
)
async def test_other_network_types(action_type: str, target: str, indicator_type: str, value: str) -> None:
    defender = FakeDefender()
    result, _ = await execute(defender, NET, make_action(action_type, target))
    body = defender.body(defender.writes()[0])
    assert result.status == "succeeded" and (body["indicatorType"], body["indicatorValue"]) == (indicator_type, value)
    lookup = unquote(indicator_queries(defender)[0])
    assert f"indicatorValue eq '{value}'" in lookup
    assert datetime.fromisoformat(body["expirationTime"]) > datetime.now(UTC) + timedelta(days=29)
    assert body["action"] == "Block"


async def test_options_expiry_severity_alert_and_device_groups() -> None:
    defender = FakeDefender()
    options = {"expiration_days": 7, "severity": "Low", "generate_alert": False,
               "rbac_group_names": [" Servers ", "Workstations", "Servers"]}
    await execute(defender, NET, make_action("block_ip", IP), options=options)
    body = defender.body(defender.writes()[0])
    expiry = datetime.fromisoformat(body["expirationTime"])
    assert timedelta(days=6, hours=23) < expiry - datetime.now(UTC) <= timedelta(days=7)
    assert (body["severity"], body["generateAlert"], body["rbacGroupNames"]) == ("Low", False, ["Servers", "Workstations"])


@pytest.mark.parametrize("existing", ["Allowed", "Warn"])
async def test_an_allow_or_warn_indicator_conflicts(existing: str) -> None:
    defender = FakeDefender()
    allowed = defender.indicator(IP, "IpAddress", existing)
    result, store = await execute(defender, NET, make_action("block_ip", IP))
    assert result.status == "failed" and result.detail["error"] == "conflicting_indicator"
    assert result.detail["indicator_id"] == allowed and result.detail["existing_action"] == existing
    assert defender.writes() == [] and store == {}


async def test_another_partys_block_is_adopted_and_never_deleted_on_rollback() -> None:
    defender = FakeDefender()
    theirs = defender.indicator(IP, "IpAddress", "Block")
    original = make_action("block_ip", IP)
    result, _ = await execute(defender, NET, original)
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert result.external_ref == {"indicator_value": IP, "indicator_type": "IpAddress", "indicator_id": theirs,
                                   "created": False, "reversible": False}
    assert defender.writes() == []
    done = original.model_copy(update={"status": "succeeded", "external_ref": result.external_ref})
    rollback = make_action("unblock_ip", IP, rollback_of=original.id, execution_owner="scheduler")
    undone, _ = await execute(defender, NET, rollback, original=done)
    assert undone.status == "failed" and undone.detail["error"] == "rollback_not_needed"
    assert defender.writes() == [] and theirs in defender.indicators


async def test_our_own_indicator_is_readopted_by_marker() -> None:
    defender = FakeDefender()
    action = make_action("block_ip", IP)
    first, store = await execute(defender, NET, action)
    # The run crashed after the POST: the indicator id was never checkpointed.
    crashed = {k: v for k, v in store.items() if k != "indicator_id"}
    second, _ = await execute(defender, NET, rerun(action, crashed, attempts=2))
    assert second.status == "succeeded" and second.detail["adopted"] is True
    assert second.detail["indicator"]["id"] == first.detail["indicator"]["id"]
    assert len(defender.writes()) == 1 and (second.external_ref or {})["created"] is True


async def test_an_upsert_of_an_existing_indicator_is_not_ours_to_delete() -> None:
    defender = FakeDefender()
    audit = defender.indicator(IP, "IpAddress", "Audit")

    def upsert(request: httpx.Request) -> httpx.Response:
        stored = defender.indicators[audit]
        stored.update(defender.body(request))
        return httpx.Response(200, json=stored)

    defender.fail("POST", r"/api/indicators", upsert)
    result, _ = await execute(defender, NET, make_action("block_ip", IP))
    assert result.status == "succeeded" and result.detail["changed"] is True
    assert (result.external_ref or {})["created"] is False and (result.external_ref or {})["reversible"] is False


async def test_missing_after_the_post_is_not_verified_and_retryable() -> None:
    defender = FakeDefender()
    defender.fail("GET", r"/api/indicators", httpx.Response(200, json={"value": []}), times=2)
    result, _ = await execute(defender, NET, make_action("block_ip", IP))
    assert result.status == "failed" and result.detail["error"] == "not_verified" and result.detail["retryable"]
    assert (result.external_ref or {})["indicator_id"] == result.detail["indicator_id"]


@pytest.mark.parametrize(("target", "code"), [
    ("10.0.0.5", "unsupported_target"),
    ("192.168.1.0/24", "invalid_target"),
    ("127.0.0.1", "unsupported_target"),
    ("fe80::1", "unsupported_target"),
])
async def test_non_global_ips_are_rejected(target: str, code: str) -> None:
    defender = FakeDefender()
    with pytest.raises(InvalidTarget) as exc:
        await execute(defender, NET, make_action("block_ip", target))
    assert exc.value.code == code and defender.fake.requests == []


async def test_indicator_values_are_encoded_exactly_once() -> None:
    defender = FakeDefender()
    url = "http://evil.example/a'b?x=1&y=%41+z#frag"
    await execute(defender, NET, make_action("block_url", url))
    first = indicator_queries(defender)[0]
    assert first == (
        "$filter=indicatorValue%20eq%20%27http%3A%2F%2Fevil.example%2Fa%27%27b%3Fx%3D1%26y%3D%2541%2Bz%23frag%27"
        "%20and%20indicatorType%20eq%20%27Url%27"
    )
    assert defender.body(defender.writes()[0])["indicatorValue"] == url


@pytest.mark.parametrize("target", ["evil.example' or indicatorType eq 'Url", "evil.example\r\n", "x"])
async def test_injection_in_domains_is_refused(target: str) -> None:
    defender = FakeDefender()
    with pytest.raises(InvalidTarget):
        await execute(defender, NET, make_action("block_domain", target))
    assert defender.fake.requests == []


# ----------------------------------------------------------------------------- unblock


async def blocked(defender: FakeDefender, action_type: str = "block_ip", target: str = IP, spec=NET):  # type: ignore[no-untyped-def]
    original = make_action(action_type, target)
    result, _ = await execute(defender, spec, original)
    assert result.status == "succeeded"
    return original.model_copy(update={"status": "succeeded", "result": result.detail,
                                       "external_ref": result.external_ref})


async def test_unblock_deletes_our_indicator_and_verifies_it_is_gone() -> None:
    defender = FakeDefender()
    original = await blocked(defender)
    indicator_id = original.external_ref["indicator_id"]
    rollback = make_action("unblock_ip", IP, rollback_of=original.id, execution_owner="scheduler")
    result, store = await execute(defender, NET, rollback, original=original)
    assert result.status == "succeeded" and result.detail["changed"] is True
    delete = defender.writes()[-1]
    assert (delete.method, delete.url.path) == ("DELETE", f"/api/indicators/{indicator_id}")
    assert indicator_id not in defender.indicators and store["indicator_id"] == indicator_id
    assert result.verify is not None and result.verify.state == "verified"
    assert "note" not in result.detail
    checked = await verify(defender, NET, rerun(rollback, result.external_ref or {}, status="succeeded"))
    assert checked.state == "verified"


async def test_unblock_404_counts_as_deleted() -> None:
    defender = FakeDefender()
    original = await blocked(defender)
    indicator_id = original.external_ref["indicator_id"]

    def gone(request: httpx.Request) -> httpx.Response:
        defender.indicators.pop(indicator_id, None)  # expired or deleted meanwhile
        return defender_error(404, "ResourceNotFound")

    defender.fail("DELETE", r"/api/indicators/.+", gone)
    rollback = make_action("unblock_ip", IP, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await execute(defender, NET, rollback, original=original)
    assert result.status == "succeeded" and result.detail["changed"] is True


async def test_unblock_of_an_indicator_that_no_longer_exists_changes_nothing() -> None:
    defender = FakeDefender()
    original = await blocked(defender)
    defender.indicators.clear()
    rollback = make_action("unblock_ip", IP, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await execute(defender, NET, rollback, original=original)
    assert result.status == "succeeded" and result.detail["already"] is True
    assert [r.method for r in defender.writes()] == ["POST"]


async def test_unblock_leaves_an_indicator_someone_else_took_over() -> None:
    defender = FakeDefender()
    original = await blocked(defender)
    defender.indicators[original.external_ref["indicator_id"]]["description"] = "managed by the network team"
    rollback = make_action("unblock_ip", IP, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await execute(defender, NET, rollback, original=original)
    assert result.status == "failed" and result.detail["error"] == "conflicting_indicator"
    assert [r.method for r in defender.writes()] == ["POST"]


async def test_verify_of_a_block_after_it_was_removed_fails() -> None:
    defender = FakeDefender()
    original = await blocked(defender)
    assert (await verify(defender, NET, original)).state == "verified"
    defender.indicators.clear()
    checked = await verify(defender, NET, original)
    assert checked.state == "failed" and checked.detail["reason"] == "indicator_missing"


# ----------------------------------------------------------------------------- file indicators


@pytest.mark.parametrize(("digest", "indicator_type"), [(SHA256, "FileSha256"), (SHA1, "FileSha1"), (MD5, "FileMd5")])
async def test_file_indicator_type_follows_the_hash_length(digest: str, indicator_type: str) -> None:
    defender = FakeDefender()
    action = make_action("quarantine_file", digest.upper())
    result, _ = await execute(defender, FILES, action)
    body = defender.body(defender.writes()[0])
    assert result.status == "succeeded"
    assert (body["indicatorType"], body["indicatorValue"], body["action"]) == (indicator_type, digest, "BlockAndRemediate")
    assert body["title"] == f"LG-SOTF quarantine_file {digest[:60]}"
    assert result.verify is not None
    assert result.verify.detail["enforcement"] == "configured; file blocks typically apply in 15-30 min"


async def test_sha512_is_unsupported() -> None:
    defender = FakeDefender()
    with pytest.raises(InvalidTarget) as exc:
        await execute(defender, FILES, make_action("quarantine_file", "d" * 128))
    assert exc.value.code == "unsupported_target" and defender.fake.requests == []


async def test_unblock_file_notes_that_quarantined_files_stay() -> None:
    defender = FakeDefender()
    original = await blocked(defender, "quarantine_file", SHA256, FILES)
    rollback = make_action("unblock_file", SHA256, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await execute(defender, FILES, rollback, original=original)
    assert result.status == "succeeded" and result.detail["note"] == "files already quarantined stay quarantined"
    assert defender.writes()[-1].method == "DELETE"


async def test_file_block_by_someone_else_is_already() -> None:
    defender = FakeDefender()
    defender.indicator(SHA256, "FileSha256", "BlockAndRemediate")
    result, _ = await execute(defender, FILES, make_action("quarantine_file", SHA256))
    assert result.detail["already"] is True and defender.writes() == []


@pytest.mark.parametrize(
    ("spec", "action_type", "target", "hint"),
    [
        (NET, "block_ip", IP, "Custom network indicators"),
        (FILES, "quarantine_file", SHA256, "Allow or block file"),
    ],
)
async def test_disabled_feature_names_the_advanced_feature(spec, action_type: str, target: str, hint: str) -> None:  # type: ignore[no-untyped-def]
    defender = FakeDefender()
    defender.fail("POST", r"/api/indicators", defender_error(403, "DisabledFeature"))
    result, _ = await execute(defender, spec, make_action(action_type, target))
    assert result.status == "failed" and result.detail["error"] == "feature_disabled" and hint in result.detail["hint"]


async def test_forbidden_names_the_permission() -> None:
    defender = FakeDefender()
    defender.fail("GET", r"/api/indicators", defender_error(403, "Forbidden"))
    result, _ = await execute(defender, NET, make_action("block_ip", IP))
    assert result.status == "failed" and result.detail["error"] == "permission_denied"
    assert "Ti.ReadWrite.All" in result.detail["hint"] and defender.writes() == []
