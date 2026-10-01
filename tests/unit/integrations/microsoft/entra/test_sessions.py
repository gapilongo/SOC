"""``entra.sessions``: revoke_sessions, its idempotent re-run, lagging verification, guests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Tuple

import httpx

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_SESSIONS
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory, FakeUser, guard_paths

UPN = "alice@contoso.example"


def world(**fields: Any) -> Tuple[FakeMicrosoft, Directory, FakeUser]:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    return fake, directory, directory.add(UPN, **fields)


async def run(fake: FakeMicrosoft, action: ResponseAction) -> Tuple[ConnectorResult, Dict[str, Any]]:
    ctx, store = make_context(fake, ENTRA_SESSIONS, action=action)
    return await ENTRA_SESSIONS.handler(ctx).execute(action), store


async def verify(fake: FakeMicrosoft, action: ResponseAction) -> VerificationResult:
    ctx, _ = make_context(fake, ENTRA_SESSIONS, action=action, read_only=True)
    return await ENTRA_SESSIONS.handler(ctx).verify(action)


def revocations(fake: FakeMicrosoft) -> int:
    return sum(1 for r in fake.writes() if r.url.path.endswith("/revokeSignInSessions"))


async def test_revoke_is_verified_inline() -> None:
    fake, _, alice = world()
    result, store = await run(fake, make_action("revoke_sessions", UPN))
    assert result.status == "succeeded" and result.detail["changed"] is True
    assert "about 1 h" in result.detail["note"] and result.verify is not None and result.verify.state == "verified"
    assert result.external_ref == {"user_id": alice.id, "upn": UPN, "requested": True, "reversible": False}
    assert store == {"user_id": alice.id, "requested": True}
    (post,) = fake.writes()
    assert post.url.path == f"/v1.0/users/{alice.id}/revokeSignInSessions" and post.content == b""
    paths = [f"{r.method} {r.url.path}" for r in fake.api_requests()]
    assert paths[1:4] == guard_paths(alice)
    assert fake.api_requests()[-1].url.params["$select"] == "id,signInSessionsValidFromDateTime"


async def test_rerun_after_the_revocation_took_effect_sends_nothing() -> None:
    fake, _, alice = world(sessions_valid_from=datetime.now(UTC))
    action = make_action("revoke_sessions", UPN, external_ref={"user_id": alice.id, "requested": True}, attempts=2)
    result, _ = await run(fake, action)
    assert result.status == "succeeded" and result.detail["already"] is True and revocations(fake) == 0
    assert result.verify is not None and result.verify.state == "verified"


async def test_a_recent_revocation_by_someone_else_does_not_skip_ours() -> None:
    """An attacker may revoke their own sessions and sign in again: only our own earlier attempt counts."""
    fake, _, _ = world(sessions_valid_from=datetime.now(UTC) - timedelta(seconds=20))
    result, _ = await run(fake, make_action("revoke_sessions", UPN))
    assert result.status == "succeeded" and "already" not in result.detail and revocations(fake) == 1


async def test_lagging_revocation_is_pending_then_verified() -> None:
    fake, directory, alice = world()
    directory.revocation_lag = True
    action = make_action("revoke_sessions", UPN)
    result, _ = await run(fake, action)
    plan = result.verify
    assert result.status == "succeeded" and plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (30, 600)
    executed = make_action("revoke_sessions", UPN, external_ref=result.external_ref, executed_at=action.executed_at)
    assert (await verify(fake, executed)).state == "pending"
    directory.reveal_revocation()
    outcome = await verify(fake, executed)
    assert outcome.state == "verified" and outcome.detail["sessions_valid_from"] is not None


async def test_clock_skew_is_tolerated() -> None:
    fake, _, alice = world()
    alice.sessions_valid_from = datetime.now(UTC) - timedelta(seconds=45)  # Microsoft's clock is behind ours
    executed = make_action("revoke_sessions", UPN, external_ref={"user_id": alice.id})
    assert (await verify(fake, executed)).state == "verified"
    alice.sessions_valid_from = datetime.now(UTC) - timedelta(minutes=5)
    assert (await verify(fake, executed)).state == "pending"


async def test_guests_are_refused() -> None:
    fake, _, _ = world(user_type="Guest")
    result, _ = await run(fake, make_action("revoke_sessions", UPN))
    assert result.status == "failed" and result.detail["error"] == "guest_refused"
    assert "home tenant" in result.detail["hint"] and fake.writes() == []


async def test_any_2xx_is_success_and_403_is_not_retried() -> None:
    fake, directory, alice = world()
    directory.override("POST", f"/v1.0/users/{alice.id}/revokeSignInSessions", httpx.Response(204))
    result, _ = await run(fake, make_action("revoke_sessions", UPN))
    assert result.status == "succeeded"

    fake, directory, alice = world()
    directory.override("POST", f"/v1.0/users/{alice.id}/revokeSignInSessions",
                       graph_error(403, "Authorization_RequestDenied"))
    result, _ = await run(fake, make_action("revoke_sessions", UPN))
    assert result.status == "failed" and result.detail["error"] == "permission_denied" and revocations(fake) == 1


async def test_rehearsal_and_probe_only_read() -> None:
    fake, _, alice = world(user_type="Guest")
    action = make_action("revoke_sessions", UPN)
    ctx, _ = make_context(fake, ENTRA_SESSIONS, action=action, read_only=True)
    report = await ENTRA_SESSIONS.handler(ctx).rehearse(action)
    assert report["would_execute"] == {"method": "POST", "path_template": "/v1.0/users/{id}/revokeSignInSessions"}
    assert report["guard"] == {"refused": "guest_refused"} and report["user"]["user_type"] == "Guest"
    (check,) = await ENTRA_SESSIONS.handler(ctx).probe()
    assert check.status == "ok" and check.permission == "User.Read.All"
    assert fake.writes() == []
