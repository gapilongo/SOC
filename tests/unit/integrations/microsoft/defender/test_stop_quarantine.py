"""defender.stop_quarantine: SHA-1 only, host scope, per-device steps, partial and resume, verification."""

from __future__ import annotations

from typing import Any, List

import pytest

from lg_sotf.integrations.microsoft.defender import DEFENDER_STOP_QUARANTINE
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from tests.fixtures.microsoft import defender_error, make_action, make_context
from tests.unit.integrations.microsoft.defender._support import FakeDefender, execute, marker, rerun, verify

SPEC = DEFENDER_STOP_QUARANTINE
SHA1 = "e" * 40


def quarantine(hosts: List[Any], target: str = SHA1, **fields: Any):  # type: ignore[no-untyped-def]
    return make_action("quarantine_file", target, params={"scope": {"hosts": hosts}}, **fields)


@pytest.mark.parametrize(("digest", "code"), [("f" * 64, "unsupported_target"), ("0" * 32, "unsupported_target"),
                                              ("1" * 128, "unsupported_target"), ("zz", "invalid_target")])
async def test_only_sha1_is_accepted(digest: str, code: str) -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    result, _ = await execute(defender, SPEC, quarantine(["ws-042"], digest))
    assert result.status == "failed" and result.detail["error"] == code and defender.fake.requests == []
    if code == "unsupported_target":
        assert result.detail["hint"] == "enable defender.file_indicators for SHA-256/MD5"


async def test_no_hosts_and_too_many_hosts() -> None:
    defender = FakeDefender()
    empty, _ = await execute(defender, SPEC, quarantine([]))
    assert empty.detail["error"] == "invalid_target" and empty.detail["summary"] == "no hosts in scope"
    many, _ = await execute(defender, SPEC, quarantine([f"ws-{i}" for i in range(4)]), options={"max_machines": 3})
    assert many.detail["error"] == "too_many_targets" and defender.fake.requests == []


async def test_every_device_requested_succeeds_and_verifies() -> None:
    defender = FakeDefender()
    first, second = defender.machine("ws-001"), defender.machine("ws-002")
    action = quarantine(["ws-001", "ws-002", "ws-001"])
    result, store = await execute(defender, SPEC, action)
    assert result.status == "succeeded" and result.detail["machines"] == 2
    posts = defender.posts("/StopAndQuarantineFile")
    assert [p.url.path for p in posts] == [f"/api/machines/{first}/StopAndQuarantineFile",
                                          f"/api/machines/{second}/StopAndQuarantineFile"]
    assert all(defender.body(p) == {"Comment": marker(action), "Sha1": SHA1} for p in posts)
    ref = result.external_ref or {}
    assert ref["reversible"] is False and [s["status"] for s in ref["steps"]] == ["requested", "requested"]
    assert store["steps"] == ref["steps"] and store["sha1"] == SHA1
    plan = result.verify
    assert plan is not None and (plan.state, plan.first_check_s, plan.max_duration_s) == ("pending", 60, 273_600)

    row = rerun(action, ref, status="succeeded")
    assert (await verify(defender, SPEC, row)).state == "pending"
    for step in ref["steps"]:
        defender.set_status(step["machine_action_id"], "Succeeded")
    assert (await verify(defender, SPEC, row)).state == "verified"
    defender.set_status(ref["steps"][1]["machine_action_id"], "Failed")
    checked = await verify(defender, SPEC, row)
    assert checked.state == "failed" and checked.detail["reason"] == "machine_action_failed"
    assert [m["status"] for m in checked.detail["machines"]] == ["Succeeded", "Failed"]


async def test_partial_failure_then_resume() -> None:
    defender = FakeDefender()
    defender.machine("ws-001")
    defender.machine("ws-003")
    action = quarantine(["ws-001", "ws-002", "ws-003"])
    result, _ = await execute(defender, SPEC, action)
    assert result.status == "failed" and result.detail["error"] == "partial" and result.detail["changed"] is True
    ref = result.external_ref or {}
    assert ref["partial"] is True and ref["reversible"] is False
    assert [(s["host"], s["status"], s.get("error")) for s in ref["steps"]] == [
        ("ws-001", "requested", None), ("ws-002", "failed", "not_found"), ("ws-003", "requested", None),
    ]
    assert len(defender.posts("/StopAndQuarantineFile")) == 2

    # The device comes online in Defender; a retry resumes only the failed step.
    defender.machine("ws-002")
    again, _ = await execute(defender, SPEC, rerun(action, ref, attempts=1))
    assert again.status == "succeeded" and again.detail["machines"] == 3
    assert len(defender.posts("/StopAndQuarantineFile")) == 3


async def test_every_device_failing_reports_the_device_error() -> None:
    defender = FakeDefender()
    defender.machine("ws-001")
    defender.fail("POST", r"/api/machines/[^/]+/StopAndQuarantineFile", defender_error(400, "OsPlatformNotSupported"))
    result, _ = await execute(defender, SPEC, quarantine(["ws-001"]))
    assert result.status == "failed" and result.detail["error"] == "unsupported_target"
    assert (result.external_ref or {})["steps"][0]["error"] == "unsupported_target"


async def test_rerun_adopts_a_pending_request_of_ours() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-001")
    action = quarantine(["ws-001"])
    ours = defender.action(mid, "StopAndQuarantineFile", "InProgress", comment=marker(action))
    result, _ = await execute(defender, SPEC, rerun(action, {"steps": [{"host": "ws-001", "status": "requesting"}]}))
    assert result.status == "succeeded" and defender.writes() == []
    assert (result.external_ref or {})["steps"][0]["machine_action_id"] == ours


async def test_throttling_stops_the_call_with_the_steps_checkpointed() -> None:
    defender = FakeDefender()
    defender.machine("ws-001")
    defender.machine("ws-002")
    # A Retry-After beyond the call's deadline: the whole call stops (the connector defers it).
    defender.fail("POST", r"/api/machines/[^/]+/StopAndQuarantineFile",
                  defender_error(429, "TooManyRequests", headers={"Retry-After": "600"}))
    action = quarantine(["ws-001", "ws-002"])
    ctx, store = make_context(defender.fake, SPEC, action=action)
    with pytest.raises(MicrosoftApiError) as exc:
        await SPEC.handler(ctx).execute(action)
    assert exc.value.kind == "throttled" and exc.value.retry_after_s == 600.0
    assert [(s["host"], s.get("status")) for s in store["steps"]] == [("ws-001", "requesting"), ("ws-002", None)]
    resumed, _ = await execute(defender, SPEC, rerun(action, store, attempts=2))
    assert resumed.status == "succeeded" and len(defender.posts("/StopAndQuarantineFile")) == 3
