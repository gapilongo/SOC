"""``entra.password``: reset_password never leaks the password, never sends the force flag alone, refuses hybrids."""

from __future__ import annotations

import json
import logging
import string
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx
import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.entra import password
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_PASSWORD
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.services.connectors.base import ConnectorResult
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory, FakeUser

UPN = "alice@contoso.example"


def world(**fields: Any) -> Tuple[FakeMicrosoft, Directory, FakeUser]:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    return fake, directory, directory.add(UPN, **fields)


async def run(
    fake: FakeMicrosoft, action: ResponseAction, options: Optional[Dict[str, Any]] = None
) -> Tuple[ConnectorResult, Dict[str, Any]]:
    ctx, store = make_context(fake, ENTRA_PASSWORD, options=options or {}, action=action)
    return await ENTRA_PASSWORD.handler(ctx).execute(action), store


def sent_passwords(fake: FakeMicrosoft) -> List[str]:
    out: List[str] = []
    for request in fake.writes():
        if request.method == "PATCH":
            profile = json.loads(request.content).get("passwordProfile") or {}
            out.append(profile.get("password"))
    return out


def everything_but_the_patch(fake: FakeMicrosoft) -> str:
    """Every request URL and header, and every body except the password PATCH itself."""
    parts: List[str] = []
    for request in fake.requests:
        parts.append(str(request.url))
        parts.extend(f"{k}: {v}" for k, v in request.headers.items())
        if request.method != "PATCH":
            parts.append(request.content.decode("utf-8", "replace"))
    return "\n".join(parts)


def test_generated_passwords_are_long_random_and_complete() -> None:
    seen = {password.generate_password() for _ in range(200)}
    assert len(seen) == 200
    for value in seen:
        assert len(value) >= 32
        assert any(c in string.ascii_uppercase for c in value) and any(c in string.ascii_lowercase for c in value)
        assert any(c in string.digits for c in value) and any(c in password.SYMBOL_CHARACTERS for c in value)
        assert not any(c.isspace() or c in "'\"\\" for c in value)
    with pytest.raises(ValueError):
        password.generate_password(16)


async def test_reset_sends_a_new_password_with_the_force_flag(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    fake, directory, alice = world()
    result, store = await run(fake, make_action("reset_password", UPN))
    assert result.status == "succeeded" and result.detail["changed"] is True
    assert result.verify is not None and result.verify.state == "verified"
    assert result.verify.detail["force_change"] is True
    (body,) = directory.patches()
    profile = body["passwordProfile"]
    assert profile["forceChangePasswordNextSignIn"] is True and profile["forceChangePasswordNextSignInWithMfa"] is False
    assert len(profile["password"]) >= 32 and set(body) == {"passwordProfile"}
    secret = profile["password"]
    # The password went to Microsoft once, in that PATCH, and nowhere else.
    for place in (json.dumps(result.detail), json.dumps(result.external_ref), json.dumps(result.verify.detail),
                  json.dumps(store), repr(result), caplog.text, everything_but_the_patch(fake)):
        assert secret not in place
    assert store == {"user_id": alice.id, "requested": True}
    assert fake.api_requests()[-1].url.params["$select"] == "id,lastPasswordChangeDateTime,passwordProfile"


async def test_mfa_option_is_sent() -> None:
    fake, directory, _ = world()
    await run(fake, make_action("reset_password", UPN), {"require_mfa_on_change": True})
    (body,) = directory.patches()
    assert body["passwordProfile"]["forceChangePasswordNextSignInWithMfa"] is True


@pytest.mark.parametrize(("code", "error"), [("Request_BadRequest", "bad_request"),
                                              ("FederatedUserPasswordNotAllowed", "federated_user")])
async def test_error_path_keeps_the_code_only_and_no_password(
    code: str, error: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", graph_error(400, code))
    result, _ = await run(fake, make_action("reset_password", UPN))
    (secret,) = sent_passwords(fake)
    assert result.status == "failed" and result.detail["error"] == error and result.detail["ms_code"] == code
    assert "fake error text" not in json.dumps(result.detail)  # Microsoft's message is never kept
    assert secret not in json.dumps(result.detail) and secret not in caplog.text and secret not in repr(result)


async def test_an_escaping_error_carries_no_password_or_request_frames(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", graph_error(503, "ServiceUnavailable"), times=None)
    with pytest.raises(MicrosoftApiError) as exc:
        await run(fake, make_action("reset_password", UPN))
    secrets_sent = sent_passwords(fake)
    assert secrets_sent and exc.value.kind == "server"  # 503 retried with the same body, then given up
    frames = []
    tb = exc.value.__traceback__
    while tb is not None:
        if "/lg_sotf/" in tb.tb_frame.f_code.co_filename:
            frames.append(tb.tb_frame)
        tb = tb.tb_next
    assert frames and all("/http.py" not in f.f_code.co_filename for f in frames)
    for secret in secrets_sent:
        assert secret not in str(exc.value) and secret not in repr(exc.value.args) and secret not in caplog.text
        for frame in frames:
            assert secret not in repr(frame.f_locals)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


async def test_a_network_error_is_never_retried() -> None:
    fake, directory, alice = world()

    def drop(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection reset")

    directory.override("PATCH", f"/v1.0/users/{alice.id}", drop, times=None)
    with pytest.raises(MicrosoftApiError) as exc:
        await run(fake, make_action("reset_password", UPN))
    assert exc.value.ambiguous is True and len(sent_passwords(fake)) == 1  # the re-run reconciles instead


async def test_force_flag_is_never_sent_without_a_password() -> None:
    fake, directory, alice = world()
    await run(fake, make_action("reset_password", UPN))
    alice.last_password_change = datetime.now(UTC)
    await run(fake, make_action("reset_password", UPN, external_ref={"user_id": alice.id, "requested": True}))
    for body in directory.password_bodies:
        assert body["passwordProfile"].get("password")
    assert len(directory.password_bodies) == 1


async def test_rerun_after_the_reset_took_effect_sends_nothing() -> None:
    fake, directory, alice = world(last_password_change=datetime.now(UTC), force_change=True)
    action = make_action("reset_password", UPN, external_ref={"user_id": alice.id, "requested": True}, attempts=2)
    result, _ = await run(fake, action)
    assert result.status == "succeeded" and result.detail["already"] is True and fake.writes() == []
    assert result.verify is not None and result.verify.state == "verified"


async def test_a_recent_change_by_someone_else_does_not_skip_the_reset() -> None:
    """The attacker may have just changed the password: only this action's own earlier attempt counts."""
    fake, directory, _ = world(last_password_change=datetime.now(UTC))
    result, _ = await run(fake, make_action("reset_password", UPN))
    assert result.status == "succeeded" and "already" not in result.detail and len(directory.patches()) == 1


@pytest.mark.parametrize(("fields", "error"), [({"synced": True}, "synced_user_refused"),
                                                ({"user_type": "Guest"}, "guest_refused")])
async def test_synced_users_and_guests_are_refused(fields: Dict[str, Any], error: str) -> None:
    fake, _, _ = world(**fields)
    result, store = await run(fake, make_action("reset_password", UPN))
    assert result.status == "failed" and result.detail["error"] == error and fake.writes() == [] and store == {}
    if error == "synced_user_refused":
        assert "on-premises" in result.detail["hint"]


async def test_verification_waits_for_the_timestamp_and_the_force_flag() -> None:
    fake, directory, alice = world()
    directory.override("PATCH", f"/v1.0/users/{alice.id}", httpx.Response(204))  # accepted, not visible yet
    action = make_action("reset_password", UPN)
    result, _ = await run(fake, action)
    plan = result.verify
    assert result.status == "succeeded" and plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (30, 600)
    executed = make_action("reset_password", UPN, external_ref=result.external_ref, executed_at=action.executed_at)
    ctx, _ = make_context(fake, ENTRA_PASSWORD, action=executed, read_only=True)
    assert (await ENTRA_PASSWORD.handler(ctx).verify(executed)).state == "pending"
    alice.last_password_change, alice.force_change = datetime.now(UTC), False
    assert (await ENTRA_PASSWORD.handler(ctx).verify(executed)).state == "pending"  # the flag must be set
    alice.force_change = True
    outcome = await ENTRA_PASSWORD.handler(ctx).verify(executed)
    assert outcome.state == "verified" and outcome.detail["force_change"] is True


async def test_rehearsal_and_probe_only_read() -> None:
    fake, _, alice = world(synced=True)
    action = make_action("reset_password", UPN)
    ctx, _ = make_context(fake, ENTRA_PASSWORD, action=action, read_only=True)
    report = await ENTRA_PASSWORD.handler(ctx).rehearse(action)
    assert report["guard"] == {"refused": "synced_user_refused"} and report["user"]["synced"] is True
    (check,) = await ENTRA_PASSWORD.handler(ctx).probe()
    assert check.status == "ok" and fake.writes() == []
