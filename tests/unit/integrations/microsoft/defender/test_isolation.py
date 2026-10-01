"""defender.isolation: isolate (idempotent, adopt, already isolated, in-progress), release (cancel, unisolate), verify."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from lg_sotf.integrations.microsoft.capability import CheckpointLost
from lg_sotf.integrations.microsoft.defender import DEFENDER_ISOLATION
from tests.fixtures.microsoft import default_alert, defender_error, make_action, make_context
from tests.unit.integrations.microsoft.defender._support import FakeDefender, execute, marker, rerun, verify

SPEC = DEFENDER_ISOLATION
ISOLATE_PATH = r"/api/machines/[^/]+/isolate"
UNISOLATE_PATH = r"/api/machines/[^/]+/unisolate"


def isolate(host: str = "ws-042", **fields):  # type: ignore[no-untyped-def]
    return make_action("isolate_host", host, **fields)


async def test_isolate_happy_path_sends_the_exact_body() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042.corp.contoso.example")
    action = isolate("ws-042.corp.contoso.example")
    result, store = await execute(defender, SPEC, action)
    assert result.status == "succeeded"
    assert result.detail["changed"] is True and result.detail["adopted"] is False
    assert result.detail["summary"] == "isolation requested on ws-042.corp.contoso.example (Full, Pending)"
    (post,) = defender.writes()
    assert post.url.path == f"/api/machines/{mid}/isolate"
    # MDE body parameters are case-sensitive: exactly these keys.
    assert defender.body(post) == {"Comment": f"{marker(action)}: Reported phishing", "IsolationType": "Full"}
    machine_action_id = result.detail["machine_action_id"]
    assert store == {"machine_id": mid, "requested": True, "machine_action_id": machine_action_id}
    ref = result.external_ref or {}
    assert ref["reversible"] is True and ref["machine_action_id"] == machine_action_id and ref["machine_id"] == mid
    until = datetime.fromisoformat(ref["rollback_until"])
    assert timedelta(days=9, hours=23) < until - datetime.now(UTC) <= timedelta(days=10)
    plan = result.verify
    assert plan is not None and plan.state == "pending" and (plan.first_check_s, plan.max_duration_s) == (60, 273_600)


async def test_selective_isolation_option() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    result, _ = await execute(defender, SPEC, isolate(), options={"isolation_type": "Selective"})
    assert result.status == "succeeded" and defender.body(defender.writes()[0])["IsolationType"] == "Selective"


async def test_a_crafted_alert_title_cannot_carry_another_actions_marker() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    victim, action = isolate(), isolate()
    title = f"urgent {marker(victim)}\n\tplease isolate"
    result, _ = await execute(defender, SPEC, action, alert=default_alert(title=title))
    sent = defender.body(defender.writes()[0])["Comment"]
    assert result.status == "succeeded" and sent.startswith(f"{marker(action)}: urgent ")
    assert marker(victim) not in sent and "\n" not in sent


async def test_checkpoint_is_written_before_the_post() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    action = isolate()
    ctx, store = make_context(defender.fake, SPEC, action=action)
    store["_lost"] = True  # the row was settled elsewhere: the next checkpoint fails
    with pytest.raises(CheckpointLost):
        await SPEC.handler(ctx).execute(action)
    assert defender.writes() == []


async def test_pending_isolation_of_ours_is_adopted() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    action = isolate()
    ours = defender.action(mid, "Isolate", "InProgress", comment=f"{marker(action)}: Reported phishing")
    result, store = await execute(defender, SPEC, action)
    assert result.status == "succeeded" and result.detail["adopted"] is True and result.detail["changed"] is True
    assert result.detail["machine_action_id"] == ours and defender.writes() == [] and store == {}
    assert (result.external_ref or {})["reversible"] is True


async def test_crash_after_the_post_reruns_without_a_second_post() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    action = isolate()
    first, store = await execute(defender, SPEC, action)
    assert first.status == "succeeded" and len(defender.posts("/isolate")) == 1
    # The worker died after the POST, before the machine action id was checkpointed.
    crashed = {k: v for k, v in store.items() if k != "machine_action_id"}
    second, _ = await execute(defender, SPEC, rerun(action, crashed, attempts=2))
    assert second.status == "succeeded" and second.detail["adopted"] is True
    assert second.detail["machine_action_id"] == first.detail["machine_action_id"]
    assert len(defender.posts("/isolate")) == 1


async def test_already_isolated_by_someone_else_is_not_reversible() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    defender.action(mid, "Unisolate", "Succeeded", age=timedelta(days=3))
    existing = defender.action(mid, "Isolate", "Succeeded", age=timedelta(days=1))
    result, store = await execute(defender, SPEC, isolate())
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert (result.external_ref or {}) == {
        "machine_id": mid, "computer_dns_name": "ws-042", "machine_action_id": existing, "already": True,
        "reversible": False,
    }
    assert result.verify is not None and result.verify.state == "verified"
    assert defender.writes() == [] and store == {}


async def test_foreign_pending_isolation_is_adopted_as_already() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    pending = defender.action(mid, "Isolate", "Pending")
    result, _ = await execute(defender, SPEC, isolate())
    assert result.detail["already"] is True and result.detail["machine_action_id"] == pending
    assert (result.external_ref or {})["reversible"] is False and defender.writes() == []
    assert result.verify is not None and result.verify.state == "pending"


@pytest.mark.parametrize(
    ("isolated_days_ago", "released_days_ago"),
    [(3, 1), (8, None)],  # released after the isolation; isolation older than the 7-day automatic lift
)
async def test_released_or_lifted_devices_are_isolated_again(isolated_days_ago: int, released_days_ago) -> None:  # type: ignore[no-untyped-def]
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    defender.action(mid, "Isolate", "Succeeded", age=timedelta(days=isolated_days_ago))
    if released_days_ago is not None:
        defender.action(mid, "Unisolate", "Succeeded", age=timedelta(days=released_days_ago))
    result, _ = await execute(defender, SPEC, isolate())
    assert result.detail["changed"] is True and len(defender.posts("/isolate")) == 1


async def test_in_progress_400_adopts_the_pending_action() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    action = isolate()

    def in_progress(request: httpx.Request) -> httpx.Response:
        # An earlier attempt of this action got through (its reply was lost): now it is in progress.
        defender.action(mid, "Isolate", "Pending", comment=f"{marker(action)}: Reported phishing")
        return defender_error(400, "ActiveRequestAlreadyExists")

    defender.fail("POST", ISOLATE_PATH, in_progress)
    result, store = await execute(defender, SPEC, action)
    assert result.status == "succeeded" and result.detail["changed"] is True
    assert store["machine_action_id"] == result.detail["machine_action_id"]
    assert [a["status"] for a in defender.actions.values()] == ["Pending"]


async def test_in_progress_400_by_someone_else_is_already() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")

    def in_progress(request: httpx.Request) -> httpx.Response:
        defender.action(mid, "Isolate", "InProgress")
        return defender_error(400, "BadRequest")

    defender.fail("POST", ISOLATE_PATH, in_progress)
    result, _ = await execute(defender, SPEC, isolate())
    assert result.status == "succeeded" and result.detail["already"] is True
    assert (result.external_ref or {})["reversible"] is False


async def test_in_progress_without_a_listed_action_defers() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", ISOLATE_PATH, defender_error(400, "ActiveRequestAlreadyExists"))
    result, _ = await execute(defender, SPEC, isolate())
    assert result.status == "deferred" and result.detail["deferred"] == "action_in_progress"
    assert result.retry_after_s == 60.0


async def test_other_400s_are_not_adopted() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", ISOLATE_PATH, defender_error(400, "OsPlatformNotSupported"))
    result, _ = await execute(defender, SPEC, isolate())
    assert result.status == "failed" and result.detail["error"] == "unsupported_target"
    assert result.detail["http_status"] == 400 and result.detail["ms_code"] == "OsPlatformNotSupported"


@pytest.mark.parametrize(
    ("code", "error", "hint"),
    [
        ("DisabledFeature", "feature_disabled", "Advanced features"),
        ("Forbidden", "permission_denied", "Machine.Isolate"),
    ],
)
async def test_403_mapping(code: str, error: str, hint: str) -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", ISOLATE_PATH, defender_error(403, code))
    result, _ = await execute(defender, SPEC, isolate())
    assert result.status == "failed" and result.detail["error"] == error and hint in result.detail["hint"]
    assert result.detail["http_status"] == 403 and result.detail["ms_code"] == code
    assert result.detail["request_id"] and "fake error text" not in json.dumps(result.detail)


async def test_unknown_host_fails_without_writing() -> None:
    defender = FakeDefender()
    result, _ = await execute(defender, SPEC, isolate("ws-999"))
    assert result.status == "failed" and result.detail["error"] == "not_found" and defender.writes() == []


# ----------------------------------------------------------------------------- verification


@pytest.mark.parametrize(
    ("status", "state", "reason"),
    [
        ("Succeeded", "verified", None),
        ("Failed", "failed", "machine_action_failed"),
        ("TimeOut", "failed", "machine_action_timeout"),
        ("Cancelled", "failed", "machine_action_cancelled"),
        ("Pending", "pending", None),
        ("InProgress", "pending", None),
    ],
)
async def test_verification_polls_the_machine_action(status: str, state: str, reason) -> None:  # type: ignore[no-untyped-def]
    defender = FakeDefender()
    defender.machine("ws-042")
    action = isolate()
    result, _ = await execute(defender, SPEC, action)
    action_id = result.detail["machine_action_id"]
    defender.set_status(action_id, status)
    checked = await verify(defender, SPEC, rerun(action, result.external_ref or {}, status="succeeded"))
    assert checked.state == state and checked.detail["status"] == status
    assert checked.detail.get("reason") == reason
    assert all(r.method == "GET" for r in defender.fake.api_requests()[-1:])


async def test_verification_without_a_machine_action_is_inconclusive() -> None:
    checked = await verify(FakeDefender(), SPEC, isolate(external_ref={"machine_id": "x"}))
    assert checked.state == "inconclusive" and checked.detail == {"reason": "no_machine_action"}


# ----------------------------------------------------------------------------- release_host


async def isolated(defender: FakeDefender, status: str = "Succeeded"):  # type: ignore[no-untyped-def]
    defender.machine("ws-042")
    original = isolate()
    result, _ = await execute(defender, SPEC, original)
    defender.set_status(result.detail["machine_action_id"], status)
    return original.model_copy(update={"status": "succeeded", "result": result.detail,
                                       "external_ref": result.external_ref})


def release(original):  # type: ignore[no-untyped-def]
    return make_action("release_host", original.target, rollback_of=original.id, execution_owner="scheduler")


async def test_release_cancels_a_pending_isolation() -> None:
    defender = FakeDefender()
    original = await isolated(defender, status="Pending")
    rollback = release(original)
    result, store = await execute(defender, SPEC, rollback, original=original)
    assert result.status == "succeeded" and result.detail["mode"] == "cancel" and result.detail["changed"] is True
    (cancel,) = defender.posts("/cancel")
    isolation_id = original.external_ref["machine_action_id"]
    assert cancel.url.path == f"/api/machineactions/{isolation_id}/cancel"
    assert defender.body(cancel) == {"Comment": f"{marker(rollback)}: rollback"}
    assert store["mode"] == "cancel" and defender.actions[isolation_id]["status"] == "Cancelled"
    assert result.verify is not None and result.verify.state == "verified"
    assert defender.posts("/unisolate") == []
    # A re-run after a crash recognises its own cancellation.
    again, _ = await execute(defender, SPEC, rerun(rollback, store), original=original)
    assert again.status == "succeeded" and len(defender.posts("/cancel")) == 1
    checked = await verify(defender, SPEC, rerun(rollback, again.external_ref or {}))
    assert checked.state == "verified" and checked.detail["status"] == "Cancelled"


async def test_release_unisolates_a_completed_isolation_and_verifies() -> None:
    defender = FakeDefender()
    original = await isolated(defender)
    rollback = release(original)
    result, store = await execute(defender, SPEC, rollback, original=original)
    assert result.status == "succeeded" and result.detail["mode"] == "unisolate" and result.detail["changed"] is True
    (post,) = defender.posts("/unisolate")
    assert post.url.path == f"/api/machines/{original.external_ref['machine_id']}/unisolate"
    assert defender.body(post) == {"Comment": f"{marker(rollback)}: rollback"}
    assert store["machine_action_id"] == result.detail["machine_action_id"]
    plan = result.verify
    assert plan is not None and plan.state == "pending" and plan.first_check_s == 60 and plan.max_duration_s == 273_600
    row = rerun(rollback, result.external_ref or {}, status="succeeded")
    assert (await verify(defender, SPEC, row, original=original)).state == "pending"
    defender.set_status(result.detail["machine_action_id"], "Succeeded")
    assert (await verify(defender, SPEC, row, original=original)).state == "verified"


async def test_release_in_progress_400_adopts_the_pending_release() -> None:
    defender = FakeDefender()
    original = await isolated(defender)
    mid = original.external_ref["machine_id"]

    def pending_machine_action(request: httpx.Request) -> httpx.Response:
        defender.action(mid, "Unisolate", "Pending")
        return defender_error(400, "BadRequest")

    defender.fail("POST", UNISOLATE_PATH, pending_machine_action)
    result, _ = await execute(defender, SPEC, release(original), original=original)
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert result.verify is not None and result.verify.state == "pending"


async def test_release_adopts_its_own_pending_release() -> None:
    defender = FakeDefender()
    original = await isolated(defender)
    rollback = release(original)
    ours = defender.action(original.external_ref["machine_id"], "Unisolate", "Pending",
                           comment=f"{marker(rollback)}: rollback", age=timedelta(seconds=5))
    result, _ = await execute(defender, SPEC, rollback, original=original)
    assert result.detail["adopted"] is True and result.detail["machine_action_id"] == ours
    assert defender.posts("/unisolate") == []


async def test_release_after_someone_else_released_changes_nothing() -> None:
    defender = FakeDefender()
    original = await isolated(defender)
    defender.action(original.external_ref["machine_id"], "Unisolate", "Succeeded", age=timedelta(seconds=-30))
    result, _ = await execute(defender, SPEC, release(original), original=original)
    assert result.status == "succeeded" and result.detail["already"] is True and defender.posts("/unisolate") == []


async def test_rollback_not_needed_when_the_isolation_changed_nothing() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    defender.action(mid, "Isolate", "Succeeded", age=timedelta(hours=2))
    first, _ = await execute(defender, SPEC, isolate())
    original = isolate().model_copy(update={"status": "succeeded", "result": first.detail,
                                            "external_ref": first.external_ref})
    before = len(defender.fake.requests)
    result, _ = await execute(defender, SPEC, release(original), original=original)
    assert result.status == "failed" and result.detail["error"] == "rollback_not_needed"
    assert len(defender.fake.requests) == before


async def test_rollback_not_needed_when_the_isolation_failed() -> None:
    defender = FakeDefender()
    original = await isolated(defender, status="TimeOut")
    result, _ = await execute(defender, SPEC, release(original), original=original)
    assert result.status == "failed" and result.detail["error"] == "rollback_not_needed"
    assert defender.posts("/unisolate") == [] and defender.posts("/cancel") == []
