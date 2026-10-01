"""The privileged-target guard: every refusal, and failing closed (no write) when it cannot read."""

from __future__ import annotations

import re
from typing import Any, Dict

import httpx
import pytest

from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_ACCOUNT, ENTRA_PASSWORD, ENTRA_SESSIONS
from lg_sotf.integrations.microsoft.entra.guard import MAX_DIRECTORY_OBJECTS, ensure_not_privileged
from lg_sotf.integrations.microsoft.entra.users import Refused, resolve_user
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory, admin_unit, guard_paths, role_group

UPN = "alice@contoso.example"


async def guard(fake: FakeMicrosoft) -> None:
    ctx, _ = make_context(fake, ENTRA_ACCOUNT, action=make_action("disable_user", UPN))
    await ensure_not_privileged(ctx, await resolve_user(ctx, UPN))


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"role_assignments": 1}, "directory_role"),
        ({"member_of": [{"@odata.type": "#microsoft.graph.directoryRole", "id": "r"}]}, "directory_role"),
        ({"member_of": [role_group(False), role_group(True)]}, "role_assignable_group"),
        ({"member_of": [admin_unit(False), admin_unit(True)]}, "restricted_admin_unit"),
        ({"owned": [role_group(True)]}, "role_assignable_group_owner"),
    ],
)
async def test_each_privilege_is_refused(fields: Dict[str, Any], reason: str) -> None:
    fake = FakeMicrosoft()
    Directory(fake).add(UPN, **fields)
    with pytest.raises(Refused) as exc:
        await guard(fake)
    assert exc.value.code == "privileged_target_refused" and exc.value.detail == {"reason": reason}
    assert "Privileged Authentication Administrator" in exc.value.hint and exc.value.retryable is False


async def test_an_ordinary_user_passes_with_three_reads() -> None:
    fake = FakeMicrosoft()
    user = Directory(fake).add(UPN, member_of=[role_group(None), admin_unit(None)],
                               owned=[{"@odata.type": "#microsoft.graph.application", "id": "a"}, role_group(False)])
    await guard(fake)
    reads = fake.api_requests()[1:]
    assert [f"{r.method} {r.url.path}" for r in reads] == guard_paths(user)
    assert reads[0].url.params["$filter"] == f"principalId eq '{user.id}'"
    assert reads[1].url.params["$select"] == "id,isAssignableToRole,isMemberManagementRestricted"
    assert reads[2].url.params["$select"] == "id,isAssignableToRole"


@pytest.mark.parametrize("step", ["roleAssignments", "memberOf", "ownedObjects"])
async def test_a_403_fails_closed_without_retry_or_write(step: str) -> None:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    user = directory.add(UPN)
    directory.override("GET", re.compile(rf".*/{step}"), graph_error(403, "Authorization_RequestDenied"), times=None)
    ctx, _ = make_context(fake, ENTRA_ACCOUNT, action=make_action("disable_user", UPN))
    result = await ENTRA_ACCOUNT.handler(ctx).execute(make_action("disable_user", UPN))
    assert result.status == "failed" and result.detail["error"] == "privileged_guard_unavailable"
    assert result.detail["reason"] == "forbidden" and result.detail["http_status"] == 403
    assert result.detail["ms_code"] == "Authorization_RequestDenied" and result.detail["retryable"] is False
    assert "RoleManagement.Read.Directory" in result.detail["hint"]
    assert sum(1 for r in fake.api_requests() if r.url.path.endswith(step)) == 1  # never retried
    assert fake.writes() == [] and user.enabled is True


async def test_missing_properties_fail_closed() -> None:
    """Without GroupMember.Read.All directory objects come back with an id only: that is not "safe"."""
    fake = FakeMicrosoft()
    Directory(fake).add(UPN, member_of=[role_group(with_flag=False)])
    with pytest.raises(Refused) as exc:
        await guard(fake)
    assert exc.value.code == "privileged_guard_unavailable"
    assert exc.value.detail == {"reason": "incomplete_read", "step": "member_of", "missing": "isAssignableToRole"}

    fake = FakeMicrosoft()
    Directory(fake).add(UPN, owned=[{"id": "x"}])
    with pytest.raises(Refused) as exc:
        await guard(fake)
    assert exc.value.detail["missing"] == "@odata.type"


async def test_too_many_memberships_fail_closed() -> None:
    fake = FakeMicrosoft()
    Directory(fake).add(UPN, member_of=[role_group(False) for _ in range(MAX_DIRECTORY_OBJECTS + 1)])
    with pytest.raises(Refused) as exc:
        await guard(fake)
    assert exc.value.code == "privileged_guard_unavailable" and exc.value.detail["reason"] == "too_many_objects"


async def test_memberships_are_paged_on_the_same_host() -> None:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    user = directory.add(UPN)
    next_link = f"https://graph.microsoft.com/v1.0/users/{user.id}/memberOf?$skiptoken=page2"

    def page(request: httpx.Request) -> httpx.Response:
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [role_group(True)]})
        return httpx.Response(200, json={"value": [role_group(False)], "@odata.nextLink": next_link})

    directory.override("GET", re.compile(r".*/memberOf"), page, times=None)
    with pytest.raises(Refused) as exc:
        await guard(fake)
    assert exc.value.detail == {"reason": "role_assignable_group"}


async def test_throttling_propagates_for_the_connector_to_defer() -> None:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    directory.add(UPN)
    directory.override("GET", "/v1.0/roleManagement/directory/roleAssignments",
                       graph_error(429, "TooManyRequests", headers={"Retry-After": "600"}), times=None)
    with pytest.raises(MicrosoftApiError) as exc:
        await guard(fake)
    assert exc.value.kind == "throttled"


@pytest.mark.parametrize(("spec", "action_type"), [
    (ENTRA_ACCOUNT, "disable_user"), (ENTRA_SESSIONS, "revoke_sessions"), (ENTRA_PASSWORD, "reset_password"),
])
async def test_every_write_is_guarded(spec: Any, action_type: str) -> None:
    fake = FakeMicrosoft()
    user = Directory(fake).add(UPN, role_assignments=2)
    action = make_action(action_type, UPN)
    ctx, store = make_context(fake, spec, action=action)
    result = await spec.handler(ctx).execute(action)
    assert result.status == "failed" and result.detail["error"] == "privileged_target_refused"
    assert result.detail["reason"] == "directory_role" and result.detail["user"] == {"id": user.id, "upn": UPN}
    assert fake.writes() == [] and store == {}
