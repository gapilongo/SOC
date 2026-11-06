"""``entra.account``: disable_user and its rollback enable_user, verification, errors, rehearsal and probes."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

import httpx
import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.domain.connectors import ConnectorResult
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_ACCOUNT
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory, FakeUser, guard_paths

UPN = "alice@contoso.example"


def world(**fields: Any) -> Tuple[FakeMicrosoft, Directory, FakeUser]:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    return fake, directory, directory.add(UPN, **fields)


async def run(
    fake: FakeMicrosoft,
    action: ResponseAction,
    *,
    options: Optional[Dict[str, Any]] = None,
    original: Optional[ResponseAction] = None,
) -> Tuple[ConnectorResult, Dict[str, Any]]:
    ctx, store = make_context(fake, ENTRA_ACCOUNT, options=options or {}, action=action, original=original)
    return await ENTRA_ACCOUNT.handler(ctx).execute(action), store


async def verify(fake: FakeMicrosoft, action: ResponseAction, original: Optional[ResponseAction] = None) -> Any:
    ctx, _ = make_context(fake, ENTRA_ACCOUNT, action=action, original=original, read_only=True)
    return await ENTRA_ACCOUNT.handler(ctx).verify(action)


async def test_disable_happy_path() -> None:
    fake, directory, alice = world()
    action = make_action("disable_user", UPN)
    result, store = await run(fake, action)
    assert result.status == "succeeded" and alice.enabled is False
    assert result.detail["changed"] is True and result.detail["user"] == {"id": alice.id, "upn": UPN}
    assert result.verify is not None and result.verify.state == "verified"
    assert result.external_ref == {"user_id": alice.id, "upn": UPN, "prior": {"accountEnabled": True},
                                   "synced": False, "requested": True, "reversible": True}
    assert store == {"user_id": alice.id, "prior": {"accountEnabled": True}, "synced": False, "requested": True}
    assert directory.patches() == [{"accountEnabled": False}]
    paths = [f"{r.method} {r.url.path}" for r in fake.api_requests()]
    assert paths == ["GET /v1.0/users/alice@contoso.example", *guard_paths(alice),
                     f"PATCH /v1.0/users/{alice.id}", f"GET /v1.0/users/{alice.id}"]
    assert fake.api_requests()[-1].url.params["$select"] == "id,accountEnabled"
    assert (await verify(fake, make_action("disable_user", UPN, external_ref=result.external_ref))).state == "verified"


async def test_already_disabled_changes_nothing_and_is_not_reversible() -> None:
    fake, directory, alice = world(enabled=False)
    result, store = await run(fake, make_action("disable_user", UPN))
    assert result.status == "succeeded" and result.detail["changed"] is False and result.detail["already"] is True
    assert result.external_ref is not None and result.external_ref["reversible"] is False
    assert store == {} and fake.writes() == []


async def test_rerun_after_a_crash_following_the_patch_stays_reversible() -> None:
    fake, directory, alice = world(enabled=False)  # our PATCH went through before the crash
    checkpoint = {"user_id": alice.id, "prior": {"accountEnabled": True}, "synced": False, "requested": True}
    result, _ = await run(fake, make_action("disable_user", UPN, external_ref=checkpoint, attempts=2))
    assert result.status == "succeeded" and result.detail["changed"] is True
    assert result.external_ref is not None and result.external_ref["reversible"] is True
    assert result.external_ref["prior"] == {"accountEnabled": True}
    assert result.verify is not None and result.verify.state == "verified" and fake.writes() == []


async def test_rerun_after_a_crash_before_the_patch_disables_once() -> None:
    fake, directory, alice = world()
    checkpoint = {"user_id": alice.id, "prior": {"accountEnabled": True}, "synced": False, "requested": True}
    result, _ = await run(fake, make_action("disable_user", UPN, external_ref=checkpoint, attempts=2))
    assert result.status == "succeeded" and directory.patches() == [{"accountEnabled": False}]


async def test_synced_user_is_pending_then_reverted_by_sync() -> None:
    fake, directory, alice = world(synced=True)
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "succeeded" and result.detail["synced"] is True and "on-premises" in result.detail["note"]
    plan = result.verify
    assert plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (2400, 3600) and plan.detail["temporary"] is True
    executed = make_action("disable_user", UPN, external_ref=result.external_ref)
    assert (await verify(fake, executed)).state == "verified"
    alice.enabled = True  # the next Entra Connect cycle
    outcome = await verify(fake, executed)
    assert outcome.state == "failed" and outcome.detail["reason"] == "reverted_by_sync"


async def test_cloud_user_re_enabled_later_fails_verification() -> None:
    fake, _, alice = world()
    result, _ = await run(fake, make_action("disable_user", UPN))
    alice.enabled = True
    outcome = await verify(fake, make_action("disable_user", UPN, external_ref=result.external_ref))
    assert outcome.state == "failed" and outcome.detail["reason"] == "re_enabled"


async def test_guests_and_synced_users_follow_the_options() -> None:
    fake, _, _ = world(user_type="Guest")
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "failed" and result.detail["error"] == "guest_refused" and fake.writes() == []
    assert len(fake.api_requests()) == 1  # refused before the guard reads anything

    fake, directory, _ = world(user_type="Guest")
    result, _ = await run(fake, make_action("disable_user", UPN), options={"allow_guests": True})
    assert result.status == "succeeded" and directory.patches() == [{"accountEnabled": False}]

    fake, _, _ = world(synced=True)
    result, _ = await run(fake, make_action("disable_user", UPN), options={"allow_synced_users": False})
    assert result.status == "failed" and result.detail["error"] == "synced_user_refused" and fake.writes() == []


async def test_a_disable_that_does_not_take_is_not_verified() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", httpx.Response(204))  # accepted, never applied
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "failed" and result.detail["error"] == "not_verified"
    assert result.detail["observed"] == {"accountEnabled": True} and result.detail["retryable"] is True
    assert sum(1 for r in fake.api_requests() if r.method == "GET" and r.url.path == f"/v1.0/users/{alice.id}") == 3


async def test_a_stale_first_read_is_read_again() -> None:
    fake, directory, alice = world()
    stale = httpx.Response(200, json={"id": alice.id, "accountEnabled": True})
    directory.override("GET", f"/v1.0/users/{alice.id}", stale)
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "verified"


async def test_an_unreadable_result_leaves_verification_pending() -> None:
    fake, directory, alice = world()
    directory.override("GET", f"/v1.0/users/{alice.id}", graph_error(403, "Authorization_RequestDenied"))
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "pending"
    assert result.verify.detail["inline_check"] == "permission_denied"


async def test_403_on_the_write_is_permission_denied_and_never_retried() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", graph_error(403, "Authorization_RequestDenied"))
    result, store = await run(fake, make_action("disable_user", UPN))
    assert result.status == "failed" and result.detail["error"] == "permission_denied"
    assert result.detail["hint"] == (
        "missing application permission or the User Administrator role, or the target is out of scope"
    )
    assert result.detail["http_status"] == 403 and result.detail["ms_code"] == "Authorization_RequestDenied"
    assert result.detail["retryable"] is False and len(fake.writes()) == 1
    assert store["requested"] is True  # the checkpoint came before the write


async def test_directory_concurrency_violation_is_retried_by_the_framework() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", graph_error(409, "Directory_ConcurrencyViolation"))
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "succeeded" and len(fake.writes()) == 2 and alice.enabled is False


async def test_404_on_the_write_is_not_found() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", graph_error(404, "Request_ResourceNotFound"))
    result, _ = await run(fake, make_action("disable_user", UPN))
    assert result.status == "failed" and result.detail["error"] == "not_found"


async def test_throttled_write_propagates_for_deferral() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}",
                       graph_error(429, "TooManyRequests", headers={"Retry-After": "900"}))
    with pytest.raises(MicrosoftApiError) as exc:
        await run(fake, make_action("disable_user", UPN))
    assert exc.value.kind == "throttled"


def disabled_original(alice: FakeUser, *, prior: Any = True, requested: bool = True) -> ResponseAction:
    ref: Dict[str, Any] = {"user_id": alice.id, "prior": {"accountEnabled": prior}, "synced": False,
                           "reversible": True, "capability": "entra.account"}
    if requested:
        ref["requested"] = True
    return make_action("disable_user", UPN, status="succeeded", external_ref=ref)


async def test_enable_restores_an_account_that_was_enabled_before() -> None:
    fake, directory, alice = world(enabled=False)
    original = disabled_original(alice)
    rollback = make_action("enable_user", UPN, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await run(fake, rollback, original=original)
    assert result.status == "succeeded" and alice.enabled is True and directory.patches() == [{"accountEnabled": True}]
    assert result.verify is not None and result.verify.state == "verified"
    paths = [f"{r.method} {r.url.path}" for r in fake.api_requests()]
    assert paths[0] == f"GET /v1.0/users/{alice.id}" and paths[1:4] == guard_paths(alice)  # by object id, guarded
    done = make_action("enable_user", UPN, rollback_of=original.id, external_ref=result.external_ref)
    assert (await verify(fake, done, original)).state == "verified"


@pytest.mark.parametrize(("prior", "requested"), [(False, True), (None, True), (True, False)])
async def test_enable_only_when_the_account_was_enabled_before(prior: Any, requested: bool) -> None:
    fake, _, alice = world(enabled=False)
    original = disabled_original(alice, prior=prior, requested=requested)
    result, _ = await run(fake, make_action("enable_user", UPN, rollback_of=original.id), original=original)
    assert result.status == "succeeded" and result.detail["changed"] is False
    assert result.detail["error"] == "rollback_not_needed" and fake.requests == [] and alice.enabled is False


async def test_enable_refuses_a_user_who_became_privileged() -> None:
    fake, _, alice = world(enabled=False)
    alice.role_assignments = 1
    original = disabled_original(alice)
    result, _ = await run(fake, make_action("enable_user", UPN, rollback_of=original.id), original=original)
    assert result.status == "failed" and result.detail["error"] == "privileged_target_refused" and fake.writes() == []


async def test_rehearsal_and_probes_only_read() -> None:
    fake, _, alice = world()
    action = make_action("disable_user", UPN)
    ctx, store = make_context(fake, ENTRA_ACCOUNT, action=action, read_only=True)
    report = await ENTRA_ACCOUNT.handler(ctx).rehearse(action)
    assert report["would_execute"] == {"method": "PATCH", "path_template": "/v1.0/users/{id}"}
    assert report["user"] == {"id": alice.id, "upn": UPN, "synced": False, "user_type": "Member"}
    assert report["guard"] == "passed" and fake.writes() == [] and store == {}

    alice.member_of = [{"@odata.type": "#microsoft.graph.directoryRole", "id": "r"}]
    report = await ENTRA_ACCOUNT.handler(ctx).rehearse(action)
    assert report["guard"] == {"refused": "privileged_target_refused", "reason": "directory_role"}

    report = await ENTRA_ACCOUNT.handler(ctx).rehearse(make_action("disable_user", "nobody@contoso.example"))
    assert report["refused"] == "not_found" and report["user"] is None

    checks = await ENTRA_ACCOUNT.handler(ctx).probe()
    assert [(c.name, c.status, c.permission) for c in checks] == [
        ("read users", "ok", "User.Read.All"),
        ("read directory role assignments", "ok", "RoleManagement.Read.Directory"),
    ]
    assert {r.method for r in fake.api_requests()} == {"GET"}


async def test_probe_reports_a_forbidden_read() -> None:
    fake, directory, _ = world()
    directory.override("GET", "/v1.0/roleManagement/directory/roleAssignments",
                       graph_error(403, "Authorization_RequestDenied"))
    ctx, _ = make_context(fake, ENTRA_ACCOUNT, read_only=True)
    checks = await ENTRA_ACCOUNT.handler(ctx).probe()
    assert [c.status for c in checks] == ["ok", "forbidden"] and "Authorization_RequestDenied" in checks[1].detail


async def test_patch_body_is_exactly_the_documented_one() -> None:
    fake, _, alice = world()
    await run(fake, make_action("disable_user", UPN))
    (patch,) = [r for r in fake.writes()]
    assert patch.headers["Content-Type"] == "application/json" and json.loads(patch.content) == {"accountEnabled": False}
    assert re.fullmatch(rb"/v1\.0/users/[0-9a-f-]{36}", patch.url.raw_path)
