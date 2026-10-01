"""``entra.risk``: confirm_compromised (prior state, isProcessing, wrapper parsing, licensing) and dismiss_user_risk."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

import httpx
import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft.entra.capabilities import ENTRA_RISK
from lg_sotf.integrations.microsoft.entra.risk import parse_risky_user
from lg_sotf.services.connectors.base import ConnectorResult, VerificationResult
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action, make_context
from tests.unit.integrations.microsoft.entra._support import Directory, FakeUser

UPN = "alice@contoso.example"
AT_RISK = {"riskState": "atRisk", "riskLevel": "medium", "riskDetail": "none", "isProcessing": False}


def world(risk: Optional[Dict[str, Any]] = None, **fields: Any) -> Tuple[FakeMicrosoft, Directory, FakeUser]:
    fake = FakeMicrosoft()
    directory = Directory(fake)
    user = directory.add(UPN, **fields)
    if risk is not None:
        user.risk = {"id": user.id, **risk}
    return fake, directory, user


async def run(
    fake: FakeMicrosoft, action: ResponseAction, original: Optional[ResponseAction] = None
) -> Tuple[ConnectorResult, Dict[str, Any]]:
    ctx, store = make_context(fake, ENTRA_RISK, action=action, original=original)
    return await ENTRA_RISK.handler(ctx).execute(action), store


async def verify(fake: FakeMicrosoft, action: ResponseAction) -> VerificationResult:
    ctx, _ = make_context(fake, ENTRA_RISK, action=action, read_only=True)
    return await ENTRA_RISK.handler(ctx).verify(action)


def posts(fake: FakeMicrosoft) -> Dict[str, Any]:
    return {r.url.path.rsplit("/", 1)[1]: json.loads(r.content) for r in fake.writes()}


async def test_confirm_saves_the_prior_state_and_is_verified() -> None:
    fake, _, alice = world(AT_RISK)
    result, store = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "succeeded" and result.detail["changed"] is True
    prior = {"riskState": "atRisk", "riskLevel": "medium"}
    assert store == {"user_id": alice.id, "prior": prior, "requested": True}
    assert result.external_ref == {"user_id": alice.id, "upn": UPN, "prior": prior, "requested": True,
                                   "reversible": True}
    assert posts(fake) == {"confirmCompromised": {"userIds": [alice.id]}}
    assert result.verify is not None and result.verify.state == "verified"
    assert result.verify.detail["riskState"] == "confirmedCompromised"
    reads = [r for r in fake.api_requests() if r.url.path == f"/v1.0/identityProtection/riskyUsers/{alice.id}"]
    assert len(reads) == 2 and all(r.headers["Prefer"] == "include-unknown-enum-members" for r in reads)


async def test_no_risk_record_is_a_prior_of_none() -> None:
    fake, _, alice = world()
    result, store = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "succeeded" and store["prior"] == {"riskState": None, "riskLevel": None}


async def test_processing_is_pending_until_identity_protection_finishes() -> None:
    fake, directory, alice = world(AT_RISK)
    directory.risk_processing = True
    result, _ = await run(fake, make_action("confirm_compromised", UPN))
    plan = result.verify
    assert result.status == "succeeded" and plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (60, 1800) and plan.detail["isProcessing"] is True
    executed = make_action("confirm_compromised", UPN, external_ref=result.external_ref)
    assert (await verify(fake, executed)).state == "pending"
    directory.finish_risk_processing()
    outcome = await verify(fake, executed)
    assert outcome.state == "verified" and outcome.detail["riskLevel"] == "high"


async def test_the_documented_value_wrapper_is_parsed() -> None:
    fake, directory, alice = world(AT_RISK)
    directory.wrap_risk = True
    result, store = await run(fake, make_action("confirm_compromised", UPN))
    assert store["prior"] == {"riskState": "atRisk", "riskLevel": "medium"}
    assert result.verify is not None and result.verify.state == "verified"
    user_id = alice.id
    assert parse_risky_user({"value": [{"id": "other", "riskState": "atRisk"}]}, user_id).found is False
    assert parse_risky_user({"value": [{"riskState": "dismissed"}]}, user_id).risk_state == "dismissed"
    assert parse_risky_user({"value": []}, user_id).found is False
    assert parse_risky_user({"id": user_id, "riskState": "<script>"}, user_id).risk_state is None


async def test_already_confirmed_is_not_reversible() -> None:
    fake, _, _ = world({"riskState": "confirmedCompromised", "riskLevel": "high", "isProcessing": False})
    result, store = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert result.external_ref is not None and result.external_ref["reversible"] is False
    assert fake.writes() == [] and store == {}


async def test_rerun_after_our_confirmation_keeps_the_first_prior() -> None:
    fake, _, alice = world({"riskState": "confirmedCompromised", "riskLevel": "high", "isProcessing": False})
    checkpoint = {"user_id": alice.id, "prior": {"riskState": "atRisk", "riskLevel": "low"}, "requested": True}
    result, _ = await run(fake, make_action("confirm_compromised", UPN, external_ref=checkpoint, attempts=2))
    assert result.status == "succeeded" and fake.writes() == []
    assert result.external_ref is not None and result.external_ref["reversible"] is True
    assert result.external_ref["prior"] == {"riskState": "atRisk", "riskLevel": "low"}


@pytest.mark.parametrize(("code", "error"), [
    ("Authentication_RequestFromNonPremiumTenantOrB2CTenant", "not_licensed"),
    ("Forbidden_LicenseRequired", "not_licensed"),
    ("Authorization_RequestDenied", "permission_denied"),
])
async def test_licensing_and_permission_errors(code: str, error: str) -> None:
    fake, directory, alice = world(AT_RISK)
    directory.override("POST", "/v1.0/identityProtection/riskyUsers/confirmCompromised", graph_error(403, code))
    result, _ = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "failed" and result.detail["error"] == error and len(fake.writes()) == 1
    assert "P2" in result.detail["hint"]

    fake, directory, alice = world()
    directory.override("GET", f"/v1.0/identityProtection/riskyUsers/{alice.id}", graph_error(403, code))
    result, _ = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "failed" and result.detail["error"] == error and fake.writes() == []


async def test_probe_reports_not_licensed() -> None:
    fake, directory, _ = world()
    directory.override("GET", "/v1.0/identityProtection/riskyUsers",
                       graph_error(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant"))
    ctx, _ = make_context(fake, ENTRA_RISK, read_only=True)
    (check,) = await ENTRA_RISK.handler(ctx).probe()
    assert check.status == "not_licensed" and check.permission == "IdentityRiskyUser.Read.All"
    directory.override("GET", "/v1.0/identityProtection/riskyUsers", graph_error(403, "Authorization_RequestDenied"))
    (check,) = await ENTRA_RISK.handler(ctx).probe()
    assert check.status == "forbidden"
    (check,) = await ENTRA_RISK.handler(ctx).probe()
    assert check.status == "ok"
    assert fake.writes() == []


def confirmed_original(alice: FakeUser, *, requested: bool = True) -> ResponseAction:
    ref: Dict[str, Any] = {"user_id": alice.id, "prior": {"riskState": "atRisk", "riskLevel": "medium"},
                           "reversible": requested, "capability": "entra.risk"}
    if requested:
        ref["requested"] = True
    return make_action("confirm_compromised", UPN, status="succeeded", external_ref=ref)


async def test_dismiss_is_the_compensating_rollback() -> None:
    fake, _, alice = world({"riskState": "confirmedCompromised", "riskLevel": "high", "isProcessing": False})
    original = confirmed_original(alice)
    rollback = make_action("dismiss_user_risk", UPN, rollback_of=original.id, execution_owner="scheduler")
    result, _ = await run(fake, rollback, original)
    assert result.status == "succeeded" and result.detail["note"] == "the earlier risk state was not restored"
    assert result.detail["prior"] == {"riskState": "atRisk", "riskLevel": "medium"}
    assert posts(fake) == {"dismiss": {"userIds": [alice.id]}}
    assert result.verify is not None and result.verify.state == "verified"
    assert alice.risk is not None and alice.risk["riskState"] == "dismissed"
    executed = make_action("dismiss_user_risk", UPN, rollback_of=original.id, external_ref=result.external_ref)
    assert (await verify(fake, executed)).state == "verified"
    paths = [r.url.path for r in fake.api_requests()]
    assert paths[0] == f"/v1.0/users/{alice.id}" and f"/v1.0/users/{alice.id}/memberOf" in paths  # by id, guarded


async def test_dismiss_is_not_needed_when_the_confirmation_changed_nothing() -> None:
    fake, _, alice = world({"riskState": "confirmedCompromised", "riskLevel": "high"})
    original = confirmed_original(alice, requested=False)
    result, _ = await run(fake, make_action("dismiss_user_risk", UPN, rollback_of=original.id), original)
    assert result.status == "succeeded" and result.detail["error"] == "rollback_not_needed" and fake.requests == []


async def test_dismiss_of_an_already_cleared_risk_sends_nothing() -> None:
    fake, _, alice = world({"riskState": "remediated", "riskLevel": "none", "isProcessing": False})
    original = confirmed_original(alice)
    result, _ = await run(fake, make_action("dismiss_user_risk", UPN, rollback_of=original.id), original)
    assert result.status == "succeeded" and result.detail["already"] is True and fake.writes() == []


async def test_rehearsal_reads_the_risk_without_writing() -> None:
    fake, directory, alice = world(AT_RISK)
    action = make_action("confirm_compromised", UPN)
    ctx, _ = make_context(fake, ENTRA_RISK, action=action, read_only=True)
    report = await ENTRA_RISK.handler(ctx).rehearse(action)
    assert report["guard"] == "passed" and report["risk"]["riskState"] == "atRisk"
    assert report["would_execute"]["path_template"] == "/v1.0/identityProtection/riskyUsers/confirmCompromised"
    directory.override("GET", f"/v1.0/identityProtection/riskyUsers/{alice.id}",
                       graph_error(403, "Forbidden_LicenseRequired"))
    report = await ENTRA_RISK.handler(ctx).rehearse(action)
    assert report["risk_error"] == "not_licensed" and fake.writes() == []


async def test_a_throttled_read_after_the_post_leaves_verification_pending() -> None:
    fake, directory, alice = world(AT_RISK)

    def throttle_second_read(request: httpx.Request) -> httpx.Response:
        return graph_error(429, "TooManyRequests", headers={"Retry-After": "3600"})

    directory.override("GET", f"/v1.0/identityProtection/riskyUsers/{alice.id}",
                       lambda r: httpx.Response(200, json={"id": alice.id, **AT_RISK}), times=1)
    directory.override("GET", f"/v1.0/identityProtection/riskyUsers/{alice.id}", throttle_second_read)
    result, _ = await run(fake, make_action("confirm_compromised", UPN))
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "pending"
    assert result.verify.detail["inline_check"] == "throttled"
