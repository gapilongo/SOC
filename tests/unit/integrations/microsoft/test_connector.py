"""MicrosoftConnector: rehearsal, live execution, outcome mapping, deferral, rollback, verification, hygiene."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Dict, Iterator

import httpx
import pytest

from lg_sotf.integrations.microsoft.catalog import override_for_tests
from lg_sotf.services.connectors.base import ConnectorResult, LedgerUnavailable
from lg_sotf.services.rollback import RollbackService
from tests.fixtures.microsoft import TOKEN_PATH, FakeMicrosoft, defender_error, make_action, token_error
from tests.unit.integrations.microsoft._support import (
    FAKE_SPECS,
    MACHINE_ID,
    OPERATION_ID,
    build_connector,
    script_account,
    script_isolation,
)

ISO = "defender.fake_isolation"
ACC = "entra.fake_account"


@pytest.fixture(autouse=True)
def fake_catalog() -> Iterator[None]:
    with override_for_tests(FAKE_SPECS):
        yield


def caps(key: str = ISO, *, live: bool = True, enabled: bool = True, **options: Any) -> Dict[str, Any]:
    return {key: {"enabled": enabled, "live": live, "options": options}}


async def test_rehearsal_only_reads() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps(live=False))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "dry_run"
    detail = result.detail
    assert detail["rehearsal"] is True and detail["capability"] == ISO and detail["live"] is False
    assert detail["resolved"] == {"machine_id": MACHINE_ID, "summary": f"would isolate {MACHINE_ID}"}
    assert detail["would_execute"] == "isolate_host" and fake.writes() == [] and h.checkpoints.patches == []


async def test_rehearsal_failure_is_still_a_dry_run() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", defender_error(403, "Forbidden"))
    h = build_connector(fake, caps(live=False))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "dry_run" and result.detail["rehearsal_error"] == "permission_denied"


async def test_live_execution_checkpoints_before_the_write() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps())
    action = make_action("isolate_host", "ws-042")
    result = await h.connector.execute(action)
    assert result.status == "succeeded"
    assert {k: result.detail[k] for k in ("connector", "capability", "integration_id", "live", "changed")} == {
        "connector": "microsoft", "capability": ISO, "integration_id": str(h.integration.id), "live": True,
        "changed": True,
    }
    assert result.detail["summary"].startswith("isolation requested")
    assert h.checkpoints.patches == [{"machine_id": MACHINE_ID, "step": "isolating"}, {"operation_id": OPERATION_ID}]
    (write,) = fake.writes()
    assert write.url.path == f"/api/machines/{MACHINE_ID}/isolate"
    assert json.loads(write.content)["Comment"] == f"LG-SOTF action {action.id}"
    ref = result.external_ref or {}
    assert ref["capability"] == ISO and ref["reversible"] is True and ref["operation_id"] == OPERATION_ID
    assert "rollback_until" in ref
    assert result.verify is not None and result.verify.state == "pending"


async def test_rerun_adopts_the_pending_operation() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps())
    action = make_action("isolate_host", "ws-042", external_ref={"operation_id": OPERATION_ID, "machine_id": MACHINE_ID})
    result = await h.connector.execute(action)
    assert result.status == "succeeded" and fake.writes() == []


async def test_nothing_changed_is_not_reversible() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake, isolated=True)
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert (result.external_ref or {})["reversible"] is False and fake.writes() == []


async def test_disabled_capability_and_unsupported_cloud() -> None:
    fake = FakeMicrosoft()
    h = build_connector(fake, caps(enabled=False, live=False))
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "failed" and result.detail["error"] == "capability_disabled"

    gov = FakeMicrosoft(cloud="usgov_gcc_high")
    h = build_connector(gov, {})
    original = make_action("isolate_host", "ws-042", status="succeeded")
    rollback = make_action("release_host", "ws-042", rollback_of=original.id, execution_owner="scheduler")
    result = await h.connector.execute(rollback)
    assert result.status == "failed" and result.detail["error"] == "unsupported_cloud" and gov.requests == []


async def test_another_tenants_action_is_refused_loudly() -> None:
    fake = FakeMicrosoft()
    h = build_connector(fake, caps())
    with pytest.raises(AssertionError):
        await h.connector.execute(make_action("isolate_host", "ws-042", tenant_id="tenant-b"))
    assert fake.requests == []


async def test_throttling_defers_until_attempts_run_out() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", defender_error(429, "TooManyRequests", headers={"Retry-After": "600"}))
    h = build_connector(fake, caps())
    deferred = await h.connector.execute(make_action("isolate_host", "ws-042", attempts=1))
    assert deferred.status == "deferred" and deferred.retry_after_s == 600.0 and deferred.detail["deferred"] == "throttled"
    exhausted = await h.connector.execute(make_action("isolate_host", "ws-042", attempts=5))
    assert exhausted.status == "failed" and exhausted.detail["error"] == "throttled" and exhausted.detail["retryable"]


async def test_ambiguous_write_is_deferred_for_reconciliation() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)

    def reset(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("connection reset")

    fake.route("POST", "defender", f"/api/machines/{MACHINE_ID}/isolate", reset)
    fake._routes.insert(0, fake._routes.pop())  # the failing POST wins over the scripted one
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "deferred" and result.detail["deferred"] == "outcome_unknown" and result.retry_after_s == 30.0
    assert h.checkpoints.patches == [{"machine_id": MACHINE_ID, "step": "isolating"}]


async def test_a_transient_defender_500_is_retried_and_a_500_on_the_write_is_deferred() -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", defender_error(500, "InternalServerError"), times=1)
    script_isolation(fake)
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "succeeded", result.detail

    fake = FakeMicrosoft()
    fake.route("POST", "defender", f"/api/machines/{MACHINE_ID}/isolate", defender_error(500, "InternalServerError"))
    script_isolation(fake)
    h = build_connector(fake, caps())
    deferred = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert deferred.status == "deferred" and deferred.detail["deferred"] == "outcome_unknown"
    assert deferred.detail["http_status"] == 500 and len(fake.writes()) == 1


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        (defender_error(403, "Forbidden"), "permission_denied"),
        (defender_error(403, "DisabledFeature"), "feature_disabled"),
        (defender_error(404, "ResourceNotFound"), "not_found"),
        (defender_error(400, "InvalidRequestBody"), "bad_request"),
    ],
)
async def test_microsoft_errors_map_to_ledger_codes(reply: httpx.Response, error: str) -> None:
    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", reply)
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "failed" and result.detail["error"] == error
    assert result.detail["http_status"] == reply.status_code and result.detail["ms_code"] and result.detail["request_id"]
    assert result.detail["changed"] is False and "retryable" in result.detail


async def test_token_failures_carry_the_hint() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("invalid_client", aadsts=7000222))
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "failed" and result.detail["error"] == "credentials_invalid"
    assert result.detail["aadsts"] == 7000222 and "expired" in result.detail["hint"] and result.detail["trace_id"]


async def test_invalid_targets_handler_errors_and_lost_checkpoints() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps())
    unsupported = await h.connector.execute(make_action("isolate_host", "10.0.0.5"))
    assert unsupported.detail["error"] == "unsupported_target"

    h.checkpoints.executing = False
    lost = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert lost.status == "failed" and lost.detail["error"] == "lease_lost" and fake.writes() == []

    fake = FakeMicrosoft()
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": [{"no_id": True}]}))
    h = build_connector(fake, caps())
    broken = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert broken.detail["error"] == "connector_exception" and broken.detail["error_type"] == "KeyError"


async def test_rollback_runs_live_with_the_original() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps(live=False))  # stopped being live: undoing our change must still work
    original = make_action("isolate_host", "ws-042", status="succeeded",
                           external_ref={"machine_id": MACHINE_ID, "capability": ISO})
    h.checkpoints.rows[original.id] = original
    rollback = make_action("release_host", "ws-042", rollback_of=original.id, execution_owner="scheduler")
    result = await h.connector.execute(rollback)
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "verified"
    (write,) = fake.writes()
    assert write.url.path == f"/api/machines/{MACHINE_ID}/unisolate"


async def test_verify_reads_only() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake, action_status="Pending")
    h = build_connector(fake, caps())
    action = make_action("isolate_host", "ws-042", status="succeeded", external_ref={"operation_id": OPERATION_ID})
    pending = await h.connector.verify(action)
    assert pending.state == "pending" and pending.retry_after_s == 10 and fake.writes() == []

    done = FakeMicrosoft()
    script_isolation(done, action_status="Failed")
    h = build_connector(done, caps())
    failed = await h.connector.verify(action)
    assert failed.state == "failed" and failed.detail["reason"] == "machine_action_failed"


async def test_graph_capability_and_secret_hygiene() -> None:
    fake = FakeMicrosoft()
    script_account(fake)
    h = build_connector(fake, caps(ACC))
    result: ConnectorResult = await h.connector.execute(make_action("disable_user", "alice@contoso.example"))
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "verified"
    token = fake.api_requests()[0].headers["authorization"].split(" ", 1)[1]
    serialized = json.dumps([result.detail, result.external_ref], default=str)
    assert h.secret["client_secret"] not in serialized and token not in serialized
    assert h.secret["client_secret"] not in repr(h.connector.__dict__)


async def test_probe_all_is_read_only() -> None:
    fake = FakeMicrosoft()
    fake.grant("defender", ["Machine.Isolate", "Machine.Read.All"])
    fake.route("GET", "defender", "/api/machines", httpx.Response(200, json={"value": []}))
    h = build_connector(fake, caps())
    report = await h.connector.probe_all()
    assert report.capabilities[ISO].status == "ok" and fake.writes() == []
    assert {r.url.host for r in fake.requests} <= {"login.microsoftonline.com", "api.security.microsoft.com",
                                                   "graph.microsoft.com"}
    assert all(r.method == "GET" or fake.is_token_request(r) for r in fake.requests)


def test_ids_are_uuids() -> None:
    assert uuid.UUID(str(make_action("isolate_host", "x").id))


# ----------------------------------------------------------------------------- ledger errors and progress


class FlakyCheckpoints:
    """Checkpoints that fail with a database-level error from the ``fail_at``-th write on."""

    def __init__(self, inner: Any, fail_at: int) -> None:
        self.inner = inner
        self.fail_at = fail_at
        self.calls = 0

    async def checkpoint(self, *args: Any, **kwargs: Any) -> bool:
        self.calls += 1
        if self.calls >= self.fail_at:
            raise OSError("connection reset by peer")
        return bool(await self.inner.checkpoint(*args, **kwargs))

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return await self.inner.get(*args, **kwargs)


async def test_a_ledger_error_after_the_write_is_raised_never_recorded_as_the_outcome() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps())
    h.connector._checkpoints = FlakyCheckpoints(h.checkpoints, fail_at=2)  # type: ignore[assignment]
    with pytest.raises(LedgerUnavailable) as exc:
        await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert isinstance(exc.value.__cause__, OSError)
    # The isolation was requested: the row must stay executing so the re-run adopts it.
    assert len(fake.writes()) == 1 and h.checkpoints.patches == [{"machine_id": MACHINE_ID, "step": "isolating"}]


def _started(**ref: Any) -> Dict[str, Any]:
    return {"machine_id": MACHINE_ID, "requested": True, "capability": ISO, **ref}


async def test_a_credential_failure_after_progress_keeps_it_partial_and_reversible() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("invalid_client", aadsts=7000222))
    h = build_connector(fake, caps())
    action = make_action("isolate_host", "ws-042", status="executing", execution_owner="scheduler",
                         connector="microsoft", integration_id=h.integration.id, external_ref=_started())
    result = await h.connector.execute(action)
    assert result.status == "failed" and result.detail["error"] == "credentials_invalid"
    assert result.detail["changed"] is True and result.detail["retryable"] is True and result.detail["partial"] is True
    ref = result.external_ref or {}
    assert ref["partial"] is True and ref["reversible"] is True and ref["rollback_until"] and ref["requested"] is True
    failed = action.model_copy(update={"status": "failed", "result": result.detail, "external_ref": ref})
    rollback = RollbackService(SimpleNamespace(repos=None)).eligibility(  # type: ignore[arg-type]
        failed, None, now=datetime.now(UTC)
    )
    assert rollback.available and rollback.action_type == "release_host"


async def test_a_failure_without_progress_stays_as_it_was() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("invalid_client", aadsts=7000222))
    h = build_connector(fake, caps())
    result = await h.connector.execute(make_action("isolate_host", "ws-042"))
    assert result.status == "failed" and result.external_ref is None and result.detail["changed"] is False
    assert result.detail["retryable"] is False


async def test_a_transient_token_failure_is_deferred_like_throttling() -> None:
    fake = FakeMicrosoft()
    fake.route("POST", "login", TOKEN_PATH, token_error("temporarily_unavailable", status=503))
    h = build_connector(fake, caps())
    deferred = await h.connector.execute(make_action("isolate_host", "ws-042", attempts=1))
    assert deferred.status == "deferred" and deferred.detail["deferred"] == "token_unavailable"
    exhausted = await h.connector.execute(
        make_action("isolate_host", "ws-042", attempts=5, external_ref=_started())
    )
    assert exhausted.status == "failed" and exhausted.detail["error"] == "token_unavailable"
    assert (exhausted.external_ref or {})["partial"] is True and exhausted.detail["retryable"] is True


async def test_a_started_row_is_never_rehearsed_when_its_capability_is_no_longer_live() -> None:
    fake = FakeMicrosoft()
    script_isolation(fake)
    h = build_connector(fake, caps(live=False))
    action = make_action("isolate_host", "ws-042", status="executing", execution_owner="scheduler",
                         connector="microsoft", external_ref=_started(operation_id=OPERATION_ID))
    result = await h.connector.execute(action)
    assert result.status == "failed" and result.detail["error"] == "capability_not_live"
    assert result.detail["retryable"] is True and result.detail["changed"] is True
    assert (result.external_ref or {})["partial"] is True and (result.external_ref or {})["reversible"] is True
    assert fake.requests == []  # not even a rehearsal read
    fresh = await h.connector.execute(make_action("isolate_host", "ws-042", execution_owner="scheduler"))
    assert fresh.status == "dry_run" and fresh.detail["rehearsal"] is True  # nothing started: rehearse as before
