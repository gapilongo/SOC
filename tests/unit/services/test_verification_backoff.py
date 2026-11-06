"""Verification checks: backoff, deadline and every outcome (in-memory ledger)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import pytest

from lg_sotf.db.errors import InvalidTransition
from lg_sotf.db.repos.actions import VerificationWrite
from lg_sotf.domain.connectors import VerificationResult, VerifyPlan
from lg_sotf.integrations.microsoft.auth import MicrosoftAuthError
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.services.response import ResponseService
from lg_sotf.services.verification import VerificationService, classify_error
from lg_sotf.settings import Settings
from tests.fixtures.microsoft import make_action, ms_settings


class Actions:
    def __init__(self, action: Any) -> None:
        self.action = action
        self.writes: List[VerificationWrite] = []
        self.rollback: Any = None

    async def get(self, tenant_id: str, action_id: Any, **_: Any) -> Any:
        return self.action

    async def live_rollback(self, tenant_id: str, action_id: Any, **_: Any) -> Any:
        return self.rollback

    async def record_verification(self, tenant_id: str, action_id: Any, write: VerificationWrite, **_: Any) -> Any:
        if self.action.verification != "pending":
            raise InvalidTransition("verification", action_id, str(self.action.verification), write.state)
        self.writes.append(write)
        update: Dict[str, Any] = {"verification": write.state, "verification_detail": dict(write.detail),
                                  "verify_attempts": self.action.verify_attempts + 1}
        if write.state == "pending":
            update["verify_after"] = write.verify_after
        else:
            update["verified_at"] = datetime.now(UTC)
        self.action = self.action.model_copy(update=update)
        return self.action


class Db:
    @asynccontextmanager
    async def tenant_tx(self, tenant_id: str, **_: Any) -> AsyncIterator[None]:
        yield None


class Responses:
    def __init__(self, action: Any) -> None:
        self.repos = type("Repos", (), {"actions": Actions(action), "db": Db()})()
        self.settings = ms_settings(response={"verify_check_timeout_s": 5.0})
        self.outcomes: List[str] = []
        self.published = 0

    async def record_verification_outcome(self, tenant_id: str, action: Any, *, conn: Any, notify: bool = True) -> None:
        self.outcomes.append(str(action.verification) if notify else f"{action.verification} (quiet)")

    async def publish_action(self, tenant_id: str, action: Any) -> None:
        self.published += 1


class Verifier:
    name = "microsoft"

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    async def verify(self, action: Any) -> VerificationResult:
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class Snapshot:
    def __init__(self, verifier: Optional[Verifier]) -> None:
        self._verifier = verifier

    def verifier(self, action: Any) -> Optional[Verifier]:
        return self._verifier


def pending(**fields: Any) -> Any:
    now = datetime.now(UTC)
    base: Dict[str, Any] = {
        "status": "succeeded", "verification": "pending", "verification_detail": {"first_check_s": 10.0},
        "verify_after": now, "verify_deadline": now + timedelta(minutes=15), "verify_attempts": 0,
    }
    base.update(fields)
    return make_action("isolate_host", "ws-1", **base)


async def run(action: Any, outcome: Any, *, rand: float = 0.5) -> Responses:
    responses = Responses(action)
    service = VerificationService(responses, rand=lambda: rand)  # type: ignore[arg-type]
    verifier = Verifier(outcome) if outcome is not None else None
    await service.check("tenant-a", action.id, snapshot=Snapshot(verifier))  # type: ignore[arg-type]
    return responses


def written(responses: Responses) -> VerificationWrite:
    return responses.repos.actions.writes[-1]  # type: ignore[attr-defined, no-any-return]


@pytest.mark.parametrize(("attempts", "expected"), [(0, 10.0), (1, 20.0), (3, 80.0), (10, 900.0)])
async def test_pending_backoff_doubles_up_to_15_minutes(attempts: int, expected: float) -> None:
    action = pending(verify_attempts=attempts, verify_deadline=datetime.now(UTC) + timedelta(hours=2))
    before = datetime.now(UTC)
    responses = await run(action, VerificationResult("pending", {"status": "InProgress"}))
    write = written(responses)
    assert write.state == "pending" and write.detail["first_check_s"] == 10.0
    assert write.verify_after is not None
    delay = (write.verify_after - before).total_seconds()
    assert expected - 1 <= delay <= expected + 1  # rand 0.5 -> jitter factor 1.0


async def test_jitter_retry_after_and_deadline_clamp() -> None:
    now = datetime.now(UTC)
    low = written(await run(pending(), VerificationResult("pending", {}), rand=0.0))
    high = written(await run(pending(), VerificationResult("pending", {}), rand=1.0))
    assert low.verify_after and high.verify_after
    assert 7 <= (low.verify_after - now).total_seconds() <= 9 and 11 <= (high.verify_after - now).total_seconds() <= 13
    hinted = written(await run(pending(), VerificationResult("pending", {}, retry_after_s=300)))
    assert hinted.verify_after and (hinted.verify_after - now).total_seconds() >= 300 * 0.8 - 1
    near = pending(verify_deadline=now + timedelta(seconds=3))
    clamped = written(await run(near, VerificationResult("pending", {})))
    assert clamped.verify_after == near.verify_deadline


@pytest.mark.parametrize(("status", "effect"), [("executing", "stops"), ("succeeded", "stops"), ("approved", "waits"),
                                              ("awaiting_approval", "checks"), ("proposed", "checks")])
async def test_a_rollback_under_way_ends_or_holds_the_verification_quietly(status: str, effect: str) -> None:
    action = pending()
    responses = Responses(action)
    rollback = make_action("release_host", "ws-1", status=status, rollback_of=action.id, execution_owner="scheduler")
    responses.repos.actions.rollback = rollback  # type: ignore[attr-defined]
    service = VerificationService(responses, rand=lambda: 0.5)  # type: ignore[arg-type]
    # The verifier would see the release: the isolation machine action was cancelled.
    failing = Verifier(VerificationResult("failed", {"reason": "machine_action_cancelled"}))
    before = datetime.now(UTC)
    await service.check("tenant-a", action.id, snapshot=Snapshot(failing))  # type: ignore[arg-type]
    write = written(responses)
    if effect == "stops":
        assert write.state == "inconclusive"
        assert write.detail == {"reason": "rolled_back", "rollback_id": str(rollback.id)}
        assert responses.outcomes == ["inconclusive (quiet)"]
    elif effect == "waits":
        # An approved rollback may still expire or be blocked at its claim: neither checked nor ended, pushed back.
        assert write.state == "pending" and responses.outcomes == []
        assert write.detail == {"first_check_s": 10.0, "reason": "rollback_approved", "rollback_id": str(rollback.id)}
        assert write.verify_after is not None and 9 <= (write.verify_after - before).total_seconds() <= 11
    else:
        assert write.state == "failed" and responses.outcomes == ["failed"]


async def test_an_approved_rollback_at_the_deadline_ends_the_verification() -> None:
    action = pending(verify_deadline=datetime.now(UTC) - timedelta(seconds=1))
    responses = Responses(action)
    rollback = make_action("release_host", "ws-1", status="approved", rollback_of=action.id, execution_owner="scheduler")
    responses.repos.actions.rollback = rollback  # type: ignore[attr-defined]
    service = VerificationService(responses, rand=lambda: 0.5)  # type: ignore[arg-type]
    await service.check("tenant-a", action.id, snapshot=Snapshot(None))  # type: ignore[arg-type]
    write = written(responses)
    assert write.state == "inconclusive" and write.detail["reason"] == "deadline"
    assert write.detail["last"] == {"reason": "rollback_approved", "rollback_id": str(rollback.id)}


async def test_deadline_passed_is_inconclusive() -> None:
    late = pending(verify_deadline=datetime.now(UTC) - timedelta(seconds=1))
    responses = await run(late, VerificationResult("pending", {"status": "InProgress"}))
    write = written(responses)
    assert write.state == "inconclusive" and write.detail["reason"] == "deadline"
    assert responses.outcomes == ["inconclusive"] and responses.published == 1
    # A final answer still wins after the deadline.
    assert written(await run(late, VerificationResult("verified", {}))).state == "verified"


@pytest.mark.parametrize(
    ("outcome", "state", "reason"),
    [
        (VerificationResult("verified", {"accountEnabled": False}), "verified", None),
        (VerificationResult("failed", {"status": "Failed"}), "failed", "contradicted"),
        (VerificationResult("inconclusive", {}), "inconclusive", "unknown"),
        (MicrosoftApiError("forbidden", "x", status=403), "inconclusive", "permission_denied"),
        (MicrosoftAuthError("credentials_invalid"), "inconclusive", "credentials"),
        (MicrosoftAuthError("consent_missing"), "inconclusive", "credentials"),
        (MicrosoftApiError("not_found", "x", status=404), "inconclusive", "not_found"),
        (None, "inconclusive", "integration_unavailable"),
    ],
)
async def test_final_outcomes(outcome: Any, state: str, reason: Optional[str]) -> None:
    responses = await run(pending(), outcome)
    write = written(responses)
    assert write.state == state and write.detail.get("reason") == reason
    assert responses.outcomes == [state]


async def test_missing_microsoft_integration_is_integration_unavailable() -> None:
    responses = await run(pending(connector="microsoft"), None)
    assert written(responses).detail["reason"] == "integration_unavailable"
    webhook = await run(pending(connector="webhook"), None)
    assert written(webhook).detail["reason"] == "no_verifier"


@pytest.mark.parametrize(
    "error",
    [
        MicrosoftApiError("throttled", "x", status=429, retry_after_s=60),
        MicrosoftApiError("server", "x", status=503),
        MicrosoftApiError("network", "x"),
        MicrosoftAuthError("token_unavailable", retryable=True),
        TimeoutError(),
        RuntimeError("bug"),
    ],
)
async def test_transient_failures_back_off(error: BaseException) -> None:
    responses = await run(pending(), error)
    write = written(responses)
    assert write.state == "pending" and "last_error" in write.detail and responses.outcomes == []


def test_classification() -> None:
    assert classify_error(MicrosoftApiError("throttled", "x", retry_after_s=5))[0] == "transient"
    assert classify_error(MicrosoftAuthError("conditional_access_blocked")) == (
        "inconclusive", {"reason": "credentials", "error": "conditional_access_blocked", "aadsts": None}
    )


async def test_settled_verifications_are_left_alone() -> None:
    done = pending(verification="verified")
    responses = await run(done, VerificationResult("failed", {}))
    assert responses.repos.actions.writes == []  # type: ignore[attr-defined]


def test_the_window_starts_when_the_change_succeeds_not_at_the_first_claim(
    make_settings: Callable[..., Settings],
) -> None:
    service = ResponseService.__new__(ResponseService)
    service._settings = make_settings(response={"verify_max_s": 7200})
    # Claimed an hour ago, deferred by throttling, accepted by Microsoft only now.
    executing = make_action("revoke_sessions", "alice@contoso.example", status="executing",
                            executed_at=datetime.now(UTC) - timedelta(hours=1))
    before = datetime.now(UTC)
    write = service._verification_write(executing, VerifyPlan("pending", first_check_s=60, max_duration_s=600))
    assert write.verify_deadline is not None and write.verify_after is not None
    assert write.verify_deadline - before >= timedelta(seconds=599)  # the whole window, not already past
    assert timedelta(seconds=59) <= write.verify_after - before <= timedelta(seconds=61)
    capped = service._verification_write(executing, VerifyPlan("pending", max_duration_s=86_400))
    assert capped.verify_deadline is not None and capped.verify_deadline - before <= timedelta(seconds=7201)
