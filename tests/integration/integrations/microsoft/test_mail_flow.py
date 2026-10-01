"""Microsoft 365 mail end to end: the real ledger (Postgres), a fake Exchange behind httpx.MockTransport.

A reported phish is purged from the recipients' mailboxes (approved row,
workflow execution, background verification), rolled back (analyst request,
admin approval, background restore), rehearsed when not live, deferred on
throttling and resumed by the scheduler from its database checkpoint, and
the reporter is notified.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any, Dict, List, Sequence
from uuid import UUID, uuid4

import pytest

from lg_sotf.db.repos import Repositories
from lg_sotf.integrations.microsoft.mail.notify import PROP_ID
from lg_sotf.services.review import ReviewService
from lg_sotf.services.rollback import RollbackService
from tests.fixtures.microsoft import graph_error
from tests.integration.db._support import TENANT_A
from tests.integration.integrations.microsoft.conftest import MicrosoftEnv, MicrosoftEnvFactory
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange, FakeMessage
from tests.unit.integrations.microsoft.mail._scenario import ALICE, BOB, SENDER, SOC, SUBJECT, message_id

pytestmark = pytest.mark.integration


def phish(mid: str, recipients: Sequence[str] = (ALICE, BOB), reporter: str = ALICE) -> Dict[str, Any]:
    """The normalized form of a user-reported phishing email."""
    return {
        "title": f"Reported email: {SUBJECT}",
        "email": {
            "message_id": mid, "from": {"address": SENDER, "domain": "attacker.example"}, "subject": SUBJECT,
            "recipients": list(recipients), "reporter": reporter,
            "date": format_datetime(datetime.now(UTC) - timedelta(hours=2)),
        },
    }


async def reported(env: MicrosoftEnv, mid: str) -> str:
    return await env.alert(title=f"Reported email: {SUBJECT}", normalized=phish(mid))


async def user(repos: Repositories, role: str) -> UUID:
    return (await repos.users.create(TENANT_A, f"{role}-{uuid4().hex[:8]}@example.com", role)).id


async def audit_actions(repos: Repositories, resource_id: Any) -> List[str]:
    page = await repos.audit.list(TENANT_A, resource_id=str(resource_id), limit=100)
    return [e.action for e in reversed(page.items)]


def delivered(exchange: FakeExchange, mid: str) -> Dict[str, FakeMessage]:
    return {address: exchange.mailbox(address).add(mid) for address in (ALICE, BOB)}


def match(mid: str) -> Dict[str, Any]:
    return {"match": {"internet_message_id": mid, "sender": SENDER, "subject": SUBJECT}, "playbook": "phishing"}


async def test_purge_verify_and_roll_back(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"mail.remediate": {"options": {}}})
    exchange = FakeExchange(env.fake)
    mid = message_id()
    copies = delivered(exchange, mid)
    await reported(env, mid)
    action = await env.propose("purge_message", mid, params=match(mid))
    exchange.stale_folder_reads = 1  # the proof right after the change still sees one Inbox copy

    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert (row.connector, row.integration_id, row.execution_owner) == ("microsoft", env.integration.id, "workflow")
    assert row.result is not None and row.result["capability"] == "mail.remediate" and row.result["removed"] == 2
    assert row.external_ref is not None and row.external_ref["reversible"] is True
    assert [s["status"] for s in row.external_ref["steps"]] == ["done", "done"]
    assert row.verification == "pending" and row.verify_after is not None
    for address, message in copies.items():
        assert exchange.mailbox(address).where(message) == "recoverableitemsdeletions"

    await env.make_verifications_due()
    assert await env.run_verify() == 1
    row = await env.get(action)
    assert row.verification == "verified" and row.verified_at is not None
    assert "response_action.verified" in await audit_actions(env.repos, action.id)

    analyst, admin = await user(env.repos, "analyst"), await user(env.repos, "admin")
    rollbacks = RollbackService(env.service)
    eligibility = await rollbacks.eligibility_of(TENANT_A, row)
    assert eligibility.available and eligibility.action_type == "restore_message"
    rollback, _, created = await rollbacks.request(TENANT_A, action.id, user=analyst, role="analyst",
                                                   reason="the sender is a real supplier")
    assert created and (rollback.action_type, rollback.status) == ("restore_message", "awaiting_approval")
    assert await env.run_background() == 0  # nothing moves before an admin approves
    review = ReviewService(env.repos, env.settings, responses=env.service)
    assert await review.approve_actions(TENANT_A, [rollback.id], admin, "admin") == []
    assert await env.run_background() == 1
    done = await env.get(rollback)
    assert done.status == "succeeded" and done.verification == "verified", done.result
    assert done.external_ref is not None and done.external_ref["reversible"] is False
    for address, message in copies.items():
        assert exchange.mailbox(address).where(message) == "inbox"
    restores = [r for r in env.fake.writes() if r.url.path.endswith("/move")]
    assert [json.loads(r.content)["destinationId"] for r in restores] == ["inbox", "inbox"]
    assert exchange.missing_prefer == []
    assert (await rollbacks.eligibility_of(TENANT_A, await env.get(action))).reason == "rollback_exists"


async def test_rehearsal_only_reads(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"mail.remediate": {"options": {}}}, live=False)
    exchange = FakeExchange(env.fake)
    mid = message_id()
    copies = delivered(exchange, mid)
    await reported(env, mid)
    action = await env.propose("purge_message", mid, params=match(mid))
    assert await env.execute(action) == "dry_run"
    row = await env.get(action)
    assert row.result is not None and row.result["rehearsal"] is True and row.result["live"] is False
    assert row.result["resolved"]["found"] == {ALICE: 1, BOB: 1}
    assert row.result["resolved"]["would_execute"] == {"mode": "soft_delete", "mailboxes": 2}
    assert row.verification is None and row.external_ref is None
    assert env.fake.writes() == [] and {r.method for r in env.fake.api_requests()} == {"GET"}
    for address, message in copies.items():
        assert exchange.mailbox(address).where(message) == "inbox"


async def test_throttling_is_deferred_and_resumed_from_the_checkpoint(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"mail.remediate": {"options": {}}})
    exchange = FakeExchange(env.fake)
    mid = message_id()
    copies = delivered(exchange, mid)
    await reported(env, mid)
    exchange.fail("DELETE", rf"/v1\.0/users/{BOB}/messages/.+",
                  graph_error(429, "TooManyRequests", headers={"Retry-After": "600"}))
    action = await env.propose("purge_message", mid, params=match(mid))

    assert await env.execute(action) == "executing"
    row = await env.get(action)
    assert row.execution_owner == "scheduler" and row.lease_until is not None
    assert row.result is not None and row.result["deferred"] == "throttled"
    steps = {s["mailbox"]: s for s in (row.external_ref or {})["steps"]}  # the checkpoints, merged by Postgres
    assert steps[ALICE]["status"] == "done"
    assert steps[BOB] == {"mailbox": BOB, "status": "pending", "items": [{"id": copies[BOB].id, "folder": "inbox"}]}
    assert "response_action.deferred" in await audit_actions(env.repos, action.id)

    await env.expire_leases()
    assert await env.run_background() == 1
    row = await env.get(action)
    assert row.status == "succeeded" and row.result is not None and row.result["counts"]["done"] == 2
    assert len(exchange.calls("DELETE", copies[ALICE].id)) == 1  # never deleted twice
    assert len(exchange.calls("DELETE", copies[BOB].id)) == 2  # throttled once, then applied
    assert exchange.mailbox(BOB).where(copies[BOB]) == "recoverableitemsdeletions"


async def test_notify_the_reporter(microsoft_env: MicrosoftEnvFactory) -> None:
    env = await microsoft_env({"mail.notify": {"options": {"sender_mailbox": SOC}}})
    exchange = FakeExchange(env.fake)
    exchange.mailbox(SOC)
    mid = message_id()
    alert_id = await reported(env, mid)
    action = await env.propose("notify_reporter", f"alert:{alert_id}", params={"reporter": ALICE})
    assert await env.execute(action) == "succeeded"
    row = await env.get(action)
    assert row.verification == "pending" and row.external_ref is not None
    assert row.external_ref["reversible"] is False and row.external_ref["draft_id"]
    (sent,) = exchange.mailbox(SOC).in_folder("sentitems")
    assert sent.to == [ALICE] and sent.props == {PROP_ID: str(action.id)} and sent.body["contentType"] == "Text"
    assert sent.subject == f"Update on the email you reported: {SUBJECT}"
    await env.make_verifications_due()
    assert await env.run_verify() == 1
    assert (await env.get(action)).verification == "verified"
    # A second execution of the same row (a crash before the ledger write) sends nothing more.
    rerun = await env.get(action)
    connector = (await env.service.routing(TENANT_A, (await env.repos.tenants.get(TENANT_A)).settings)).connector_for(
        rerun, sample=False
    )
    again = await connector.execute(rerun)
    assert again.status == "succeeded" and again.detail["already"] is True
    assert len(exchange.mailbox(SOC).in_folder("sentitems")) == 1
