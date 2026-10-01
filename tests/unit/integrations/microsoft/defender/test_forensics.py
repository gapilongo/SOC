"""defender.forensics: collect an investigation package, adopt, a running collection, never download it."""

from __future__ import annotations

import httpx
import pytest

from lg_sotf.integrations.microsoft.defender import DEFENDER_FORENSICS
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from tests.fixtures.microsoft import defender_error, make_action
from tests.unit.integrations.microsoft.defender._support import FakeDefender, execute, marker, rerun, verify

SPEC = DEFENDER_FORENSICS
COLLECT_PATH = r"/api/machines/[^/]+/collectInvestigationPackage"


async def test_collect_requests_a_package_and_polls_it() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    action = make_action("collect_forensics", "ws-042")
    result, store = await execute(defender, SPEC, action)
    assert result.status == "succeeded" and result.detail["changed"] is True
    (post,) = defender.writes()
    assert post.url.path == f"/api/machines/{mid}/collectInvestigationPackage"
    assert defender.body(post) == {"Comment": marker(action)}
    assert store == {"machine_id": mid, "requested": True, "machine_action_id": result.detail["machine_action_id"]}
    assert (result.external_ref or {})["reversible"] is False
    plan = result.verify
    assert plan is not None and (plan.state, plan.first_check_s, plan.max_duration_s) == ("pending", 60, 86_400)
    defender.set_status(result.detail["machine_action_id"], "Succeeded")
    checked = await verify(defender, SPEC, rerun(action, result.external_ref or {}, status="succeeded"))
    assert checked.state == "verified"
    assert not any("packageuri" in r.url.path.lower() for r in defender.fake.requests)


async def test_a_pending_collection_of_ours_is_adopted() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")
    action = make_action("collect_forensics", "ws-042")
    ours = defender.action(mid, "CollectInvestigationPackage", "Pending", comment=marker(action))
    result, _ = await execute(defender, SPEC, action)
    assert result.detail["adopted"] is True and result.detail["machine_action_id"] == ours and defender.writes() == []


async def test_400_while_a_collection_is_running_adopts_it() -> None:
    defender = FakeDefender()
    mid = defender.machine("ws-042")

    def running(request: httpx.Request) -> httpx.Response:
        defender.action(mid, "CollectInvestigationPackage", "InProgress")
        return defender_error(400, "BadRequest")

    defender.fail("POST", COLLECT_PATH, running)
    result, _ = await execute(defender, SPEC, make_action("collect_forensics", "ws-042"))
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert result.verify is not None and result.verify.state == "pending"


async def test_400_without_a_running_collection_is_left_to_the_connector() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", COLLECT_PATH, defender_error(400, "BadRequest"))
    with pytest.raises(MicrosoftApiError) as exc:  # the connector records it as failed{bad_request}
        await execute(defender, SPEC, make_action("collect_forensics", "ws-042"))
    assert (exc.value.kind, exc.value.status, exc.value.code) == ("bad_request", 400, "BadRequest")


async def test_forbidden_names_the_permission() -> None:
    defender = FakeDefender()
    defender.machine("ws-042")
    defender.fail("POST", COLLECT_PATH, defender_error(403, "Forbidden"))
    result, _ = await execute(defender, SPEC, make_action("collect_forensics", "ws-042"))
    assert result.detail["error"] == "permission_denied" and "Machine.CollectForensics" in result.detail["hint"]
