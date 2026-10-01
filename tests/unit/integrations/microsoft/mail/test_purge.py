"""mail.remediate purge_message: recipients, per-mailbox steps, idempotent re-runs, proof, encoding."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

import httpx
import pytest

from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.http import MicrosoftApiError
from lg_sotf.integrations.microsoft.mail import mailboxes
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_REMEDIATE
from lg_sotf.integrations.microsoft.mail.remediate import RemediateHandler
from tests.fixtures.microsoft import graph_error
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange
from tests.unit.integrations.microsoft.mail._scenario import (
    ALICE,
    BOB,
    CAROL,
    SENDER,
    context,
    executed,
    mail_world,
    message_id,
    phish_alert,
    purge_action,
)


def steps_by_mailbox(ref: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {s["mailbox"]: s for s in ref["steps"]}


def delivered(exchange: FakeExchange, mid: str, *addresses: str) -> Dict[str, Any]:
    return {a: exchange.mailbox(a).add(mid) for a in addresses}


async def purge(fake: Any, action: Any, alert: Any, **options: Any) -> Any:
    run = context(fake, MAIL_REMEDIATE, action, options=options, alert=alert)
    run.result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    return run


# ----------------------------------------------------------------------------- happy paths


async def test_soft_delete_removes_the_message_from_every_recipient_mailbox() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE, BOB)
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE, BOB), reporter=ALICE))
    result = run.result
    assert result.status == "succeeded", result.detail
    assert result.detail["changed"] is True and result.detail["removed"] == 2
    assert result.detail["counts"]["done"] == 2 and result.detail["mode"] == "soft_delete"
    assert result.detail["summary"] == "soft-deleted the message in 2 of 2 mailboxes"
    for address, message in copies.items():
        assert exchange.mailbox(address).where(message) == "recoverableitemsdeletions"
    ref = result.external_ref
    assert ref["mode"] == "soft_delete" and ref["internet_message_id"] == mid and ref["reversible"] is True
    until = datetime.fromisoformat(ref["rollback_until"])
    assert timedelta(days=13, hours=23) < until - datetime.now(UTC) <= timedelta(days=14)
    steps = steps_by_mailbox(ref)
    assert steps[ALICE] == {"mailbox": ALICE, "status": "done", "items": [{"id": copies[ALICE].id, "folder": "inbox"}]}
    assert result.verify is not None and result.verify.state == "verified"
    assert result.verify.detail == {"mode": "soft_delete", "mailboxes": 2}
    assert [r.method for r in fake.writes()] == ["DELETE", "DELETE"]
    assert exchange.missing_prefer == [] and fake.unmatched == []


async def test_handles_are_recorded_before_each_mailbox_changes() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB)
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid, (ALICE, BOB)))
    seen: List[Dict[str, Any]] = []
    exchange.on_write = lambda request: seen.append(copy.deepcopy(run.store))
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert result.status == "succeeded"
    # Write-ahead: the mailboxes first (all pending), then each mailbox's handles before its DELETE.
    assert run.checkpoints[0]["steps"] == [{"mailbox": ALICE, "status": "pending"}, {"mailbox": BOB, "status": "pending"}]
    assert run.checkpoints[0]["mode"] == "soft_delete" and "started_at" in run.checkpoints[0]
    for request, state in zip(fake.writes(), seen, strict=True):
        mailbox = request.url.path.split("/")[3]
        step = steps_by_mailbox(state)[mailbox]
        assert step["status"] == "pending" and step["items"][0]["id"] == request.url.path.rsplit("/", 1)[1]


async def test_move_mode_moves_to_deleted_items_and_keeps_the_id() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    projects = exchange.mailbox(BOB).add_folder("Projects")
    alice = exchange.mailbox(ALICE).add(mid)
    bob = exchange.mailbox(BOB).add(mid, folder="Projects")
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE, BOB)), mode="move_to_deleted_items")
    result = run.result
    assert result.status == "succeeded" and result.detail["summary"].startswith("moved to Deleted Items")
    assert exchange.mailbox(ALICE).where(alice) == "deleteditems"
    assert exchange.mailbox(BOB).where(bob) == "deleteditems"
    moves = [json.loads(r.content) for r in fake.writes()]
    assert moves == [{"destinationId": "deleteditems"}, {"destinationId": "deleteditems"}]
    steps = steps_by_mailbox(result.external_ref)
    assert steps[BOB]["items"] == [{"id": bob.id, "folder": projects}]  # immutable id, original folder id
    assert result.verify is not None and result.verify.state == "verified"


async def test_reporter_is_included_and_deduplicated() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB, CAROL)
    alert = phish_alert(mid, (ALICE.upper(), BOB, "not an address"), reporter=CAROL)
    run = await purge(fake, purge_action(mid), alert)
    assert [s["mailbox"] for s in run.result.external_ref["steps"]] == [ALICE, BOB, CAROL]
    assert run.result.detail["invalid_recipients"] == 1
    without = await purge(fake, purge_action(mid), alert, include_reporter=False)
    assert [s["mailbox"] for s in without.result.external_ref["steps"]] == [ALICE, BOB]


async def test_message_trace_finds_every_recipient() -> None:
    fake, exchange = mail_world()
    exchange.trace_page_size = 2
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB, CAROL)
    for address in (ALICE, BOB, CAROL, BOB.upper()):
        exchange.trace(mid, address)
    exchange.trace(message_id(), "dave@contoso.example")  # another message
    received = datetime.now(UTC) - timedelta(hours=3)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (), reporter=None, received_at=received),
                      recipient_source="message_trace")
    assert run.result.status == "succeeded" and run.result.detail["removed"] == 3
    assert [s["mailbox"] for s in run.result.external_ref["steps"]] == [ALICE, BOB, CAROL]
    (text,) = exchange.trace_filters
    start = odata.graph_datetime(received - timedelta(days=1))
    assert text.startswith(f"messageId eq '{mid}' and receivedDateTime ge {start} and receivedDateTime le ")
    first = next(r for r in fake.api_requests() if r.url.path.endswith("/messageTraces"))
    assert first.url.query.endswith(b"&$top=1000")
    assert b"$filter=messageId%20eq%20%27%3C" in first.url.query
    assert len([r for r in fake.api_requests() if r.url.path.endswith("/messageTraces")]) == 2  # nextLink followed


async def test_message_trace_window_never_starts_in_the_future() -> None:
    now = datetime.now(UTC)
    start, end = mailboxes.trace_window(now + timedelta(days=30), now)
    assert start == now - timedelta(days=1) and end == now
    start, end = mailboxes.trace_window(now - timedelta(days=40), now)
    assert end - start == timedelta(days=10)


async def test_message_trace_refuses_messages_older_than_90_days() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    old = datetime.now(UTC) - timedelta(days=95)
    run = await purge(fake, purge_action(mid), phish_alert(mid, received_at=old), recipient_source="message_trace")
    assert run.result.status == "failed" and run.result.detail["error"] == "invalid_target"
    assert "older than 90 days" in run.result.detail["summary"]
    assert fake.api_requests() == [] and run.store == {}


async def test_message_trace_is_refused_outside_the_global_cloud() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    run = context(fake, MAIL_REMEDIATE, purge_action(mid), options={"recipient_source": "message_trace"},
                  alert=phish_alert(mid))
    run.ctx.cloud = type(run.ctx.cloud)(**{**run.ctx.cloud.__dict__, "name": "usgov_gcc_high"})
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(purge_action(mid))
    assert result.status == "failed" and result.detail["error"] == "invalid_options"
    assert fake.api_requests() == []


# ----------------------------------------------------------------------------- what is (not) removed


async def test_a_copy_from_another_sender_is_skipped() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    alice = exchange.mailbox(ALICE).add(mid)
    bob = exchange.mailbox(BOB).add(mid, sender="friend@partner.example")
    run = await purge(fake, purge_action(mid), phish_alert(mid))
    steps = steps_by_mailbox(run.result.external_ref)
    assert steps[BOB] == {"mailbox": BOB, "status": "skipped", "reason": "sender_mismatch"}
    assert exchange.mailbox(BOB).where(bob) == "inbox" and exchange.mailbox(ALICE).where(alice) == "recoverableitemsdeletions"
    assert [r.url.path for r in fake.writes()] == [f"/v1.0/users/{ALICE}/messages/{alice.id}"]


async def test_without_a_known_sender_every_copy_counts() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    exchange.mailbox(BOB).add(mid, sender="friend@partner.example")
    run = await purge(fake, purge_action(mid, sender=None), phish_alert(mid, (BOB,), reporter=None))
    assert run.result.status == "succeeded" and run.result.detail["removed"] == 1


async def test_the_senders_sent_items_copy_is_left_alone() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    internal = "mallory@contoso.example"
    sent = exchange.mailbox(internal).add(mid, folder="sentitems", sender=internal)
    received = exchange.mailbox(ALICE).add(mid, sender=internal)
    action = purge_action(mid, sender=internal)
    run = await purge(fake, action, phish_alert(mid, (ALICE, internal), reporter=None))
    steps = steps_by_mailbox(run.result.external_ref)
    assert steps[internal] == {"mailbox": internal, "status": "skipped", "reason": "sent_items"}
    assert exchange.mailbox(internal).where(sent) == "sentitems"
    assert exchange.mailbox(ALICE).where(received) == "recoverableitemsdeletions"


async def test_too_many_recipients_is_refused_before_any_write() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB, CAROL)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE, BOB, CAROL)), max_mailboxes=2)
    assert run.result.status == "failed"
    assert run.result.detail["error"] == "too_many_recipients" and run.result.detail["count"] == 3
    assert fake.writes() == [] and fake.api_requests() == [] and run.store == {}


async def test_missing_mailboxes_and_messages_are_final() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    exchange.mailbox(ALICE).add(mid)
    exchange.mailbox(BOB)  # the message is not there
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE, BOB, "ghost@contoso.example"), reporter=None))
    result = run.result
    assert result.status == "succeeded" and result.detail["summary"] == "soft-deleted the message in 1 of 3 mailboxes"
    steps = steps_by_mailbox(result.external_ref)
    assert steps[BOB]["status"] == "not_found" and steps["ghost@contoso.example"]["status"] == "mailbox_not_found"
    assert result.detail["counts"] == {"pending": 0, "done": 1, "not_found": 1, "mailbox_not_found": 1, "skipped": 0,
                                       "failed": 0}


async def test_nothing_found_anywhere_is_a_success_that_changed_nothing() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    exchange.mailbox(ALICE)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE,), reporter=None))
    result = run.result
    assert result.status == "succeeded" and result.detail["changed"] is False and result.verify is None
    assert result.external_ref["reversible"] is False and "rollback_until" not in result.external_ref
    assert fake.writes() == []


async def test_an_already_removed_copy_is_not_removed_again() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    message = exchange.mailbox(ALICE).add(mid, folder="deleteditems")
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE,), reporter=None), mode="move_to_deleted_items")
    assert run.result.status == "succeeded" and run.result.detail["already"] is True
    assert steps_by_mailbox(run.result.external_ref)[ALICE]["reason"] == "already_removed"
    assert exchange.mailbox(ALICE).where(message) == "deleteditems" and fake.writes() == []


async def test_no_recipient_at_all_fails_visibly() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    run = await purge(fake, purge_action(mid), phish_alert(mid, (), reporter=None))
    assert run.result.status == "failed" and run.result.detail["error"] == "not_found"
    assert fake.api_requests() == []


# ----------------------------------------------------------------------------- interruptions and re-runs


async def test_partial_failure_then_the_retry_resumes_without_deleting_twice() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE, BOB, CAROL)
    exchange.fail("DELETE", rf"/v1\.0/users/{BOB}/messages/.+", graph_error(403, "ErrorAccessDenied"))
    action = purge_action(mid)
    alert = phish_alert(mid, (ALICE, BOB, CAROL), reporter=None)
    first = await purge(fake, action, alert)
    result = first.result
    assert result.status == "failed" and result.detail["error"] == "partial"
    assert result.detail["retryable"] is True and result.detail["changed"] is True
    assert result.detail["failed_mailboxes"] == [BOB]
    ref = result.external_ref
    assert ref["partial"] is True and ref["reversible"] is True and "rollback_until" in ref
    bob = steps_by_mailbox(ref)[BOB]
    assert bob["status"] == "failed" and bob["error"] == "permission_denied" and bob["ms_code"] == "ErrorAccessDenied"
    assert bob["items"] == [{"id": copies[BOB].id, "folder": "inbox"}]  # kept for the retry

    retried = executed(action, result, status="executing")
    second = await purge(fake, retried, alert)
    assert second.result.status == "succeeded" and second.result.detail["counts"]["done"] == 3
    assert "partial" not in second.result.external_ref
    assert len(exchange.calls("DELETE", copies[ALICE].id)) == 1
    assert len(exchange.calls("DELETE", copies[CAROL].id)) == 1
    assert len(exchange.calls("DELETE", copies[BOB].id)) == 2  # refused once, then done
    assert exchange.mailbox(BOB).where(copies[BOB]) == "recoverableitemsdeletions"


async def test_every_mailbox_failing_is_a_plain_failure() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB)
    exchange.fail("GET", r"/v1\.0/users/[^/]+/messages", graph_error(403, "ErrorAccessDenied"), times=None)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE, BOB), reporter=None))
    detail = run.result.detail
    assert run.result.status == "failed" and detail["error"] == "permission_denied"
    assert detail["retryable"] is False and detail["ms_code"] == "ErrorAccessDenied" and detail["changed"] is False
    assert "Exchange RBAC" in detail["hint"] and run.result.external_ref["reversible"] is False


async def test_throttling_beyond_the_deadline_stops_and_the_rerun_resumes() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE, BOB)
    exchange.fail("DELETE", rf"/v1\.0/users/{BOB}/messages/.+",
                  graph_error(429, "TooManyRequests", headers={"Retry-After": "120"}))
    action = purge_action(mid)
    alert = phish_alert(mid, (ALICE, BOB), reporter=None)
    run = context(fake, MAIL_REMEDIATE, action, alert=alert)
    with pytest.raises(MicrosoftApiError) as exc:
        await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert exc.value.kind == "throttled" and exc.value.retry_after_s == 120
    steps = steps_by_mailbox(run.store)
    assert steps[ALICE]["status"] == "done"
    assert steps[BOB] == {"mailbox": BOB, "status": "pending", "items": [{"id": copies[BOB].id, "folder": "inbox"}]}

    rerun = action.model_copy(update={"external_ref": dict(run.store)})
    second = await purge(fake, rerun, alert)
    assert second.result.status == "succeeded" and second.result.detail["counts"]["done"] == 2
    assert len(exchange.calls("DELETE", copies[ALICE].id)) == 1
    assert len(exchange.calls("DELETE", copies[BOB].id)) == 2  # throttled once, then applied
    assert exchange.calls("GET", "/messageTraces") == []


@pytest.mark.parametrize("recoverable_by_id", [True, False])
async def test_a_delete_applied_but_not_recorded_is_not_repeated(recoverable_by_id: bool) -> None:
    fake, exchange = mail_world(recoverable_by_id=recoverable_by_id)
    mid = message_id()
    message = exchange.mailbox(ALICE).add(mid)
    ref = {
        "mode": "soft_delete", "internet_message_id": mid, "started_at": datetime.now(UTC).isoformat(),
        "steps": [{"mailbox": ALICE, "status": "pending", "items": [{"id": message.id, "folder": "inbox"}]}],
    }
    box = exchange.mailbox(ALICE)
    del box.messages[message.id]
    message.folder = box.folders["recoverableitemsdeletions"]  # the crash came after Microsoft applied it
    box.messages[message.id] = message
    run = await purge(fake, purge_action(mid, external_ref=ref), phish_alert(mid, (ALICE,), reporter=None))
    assert run.result.status == "succeeded" and run.result.detail["counts"]["done"] == 1
    assert fake.writes() == []


async def test_new_mailboxes_are_not_started_close_to_the_deadline() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    recipients = [f"user{i}@contoso.example" for i in range(6)]
    delivered(exchange, mid, *recipients)
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid, recipients, reporter=None))
    loop_time = __import__("asyncio").get_running_loop().time

    def squeeze(_: httpx.Request) -> None:
        run.ctx.deadline = min(run.ctx.deadline, loop_time() + 4.0)

    exchange.on_write = squeeze
    result = await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    counts = result.detail["counts"]
    assert result.status == "failed" and result.detail["error"] == "partial"
    assert counts["done"] == 4 and counts["pending"] == 2 and len(fake.writes()) == 4
    assert result.detail["failed_mailboxes"] == recipients[4:]


async def test_a_mailbox_whose_handles_would_not_fit_fails_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE)
    for _ in range(9):
        exchange.mailbox(BOB).add(mid)
    monkeypatch.setattr(mailboxes, "MAX_STATE_BYTES", 800)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE, BOB), reporter=None))
    steps = steps_by_mailbox(run.result.external_ref)
    assert steps[ALICE]["status"] == "done"
    assert steps[BOB] == {"mailbox": BOB, "status": "failed", "error": "state_limit"}
    assert [r.url.path.rsplit("/", 1)[1] for r in fake.writes()] == [copies[ALICE].id]
    assert run.result.detail["error"] == "partial"


# ----------------------------------------------------------------------------- proof


async def test_proof_waits_when_the_original_folder_still_lists_the_message() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE, BOB)
    exchange.stale_folder_reads = 1  # the Inbox query right after the change still sees ALICE's copy
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE, BOB), reporter=None))
    plan = run.result.verify
    assert run.result.status == "succeeded" and plan is not None and plan.state == "pending"
    assert (plan.first_check_s, plan.max_duration_s) == (120.0, 1800.0)
    assert plan.detail["proven"] == [BOB] and plan.detail["unproven"] == [ALICE]

    row = executed(action, run.result, verification="pending", verification_detail=dict(plan.detail))
    check = context(fake, MAIL_REMEDIATE, row, read_only=True)
    before = len(fake.api_requests())
    verdict = await MAIL_REMEDIATE.handler(check.ctx).verify(row)
    assert verdict.state == "verified" and verdict.detail == {"mode": "soft_delete", "mailboxes": 2}
    checked = {r.url.path.split("/")[3] for r in fake.api_requests()[before:]}
    assert checked == {ALICE}  # BOB was proven by the inline check


async def test_verification_fails_when_the_message_is_back_in_its_folder() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE, BOB)
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE, BOB), reporter=None))
    box = exchange.mailbox(BOB)
    box.messages[copies[BOB].id].folder = box.folders["inbox"]  # the user recovered it
    row = executed(action, run.result, verification="pending", verification_detail={})
    check = context(fake, MAIL_REMEDIATE, row, read_only=True)
    writes = len(fake.writes())
    verdict = await MAIL_REMEDIATE.handler(check.ctx).verify(row)
    assert verdict.state == "failed"
    assert verdict.detail["mailbox"] == BOB and verdict.detail["reason"] == "message_reappeared"
    assert len(fake.writes()) == writes


async def test_verification_stays_pending_while_the_item_is_visible_elsewhere() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE)
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE,), reporter=None))
    box = exchange.mailbox(ALICE)
    box.messages[copies[ALICE].id].folder = box.add_folder("Archive-2026")
    row = executed(action, run.result, verification="pending", verification_detail={})
    verdict = await MAIL_REMEDIATE.handler(context(fake, MAIL_REMEDIATE, row, read_only=True).ctx).verify(row)
    assert verdict.state == "pending" and verdict.detail["unproven"] == [ALICE]


async def test_verification_errors_propagate_to_the_framework() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE)
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE,), reporter=None))
    exchange.fail("GET", rf"/v1\.0/users/{ALICE}/mailFolders/.+", graph_error(403, "ErrorAccessDenied"), times=None)
    row = executed(action, run.result, verification="pending", verification_detail={})
    with pytest.raises(MicrosoftApiError) as exc:
        await MAIL_REMEDIATE.handler(context(fake, MAIL_REMEDIATE, row, read_only=True).ctx).verify(row)
    assert exc.value.kind == "forbidden"


async def test_move_mode_proof_accepts_items_emptied_from_deleted_items() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    copies = delivered(exchange, mid, ALICE)
    action = purge_action(mid)
    run = await purge(fake, action, phish_alert(mid, (ALICE,), reporter=None), mode="move_to_deleted_items")
    box = exchange.mailbox(ALICE)
    box.messages[copies[ALICE].id].folder = box.folders["recoverableitemsdeletions"]  # Deleted Items emptied
    row = executed(action, run.result, verification="pending", verification_detail={})
    verdict = await MAIL_REMEDIATE.handler(context(fake, MAIL_REMEDIATE, row, read_only=True).ctx).verify(row)
    assert verdict.state == "verified"


async def test_a_failing_inline_proof_never_fails_the_purge(monkeypatch: pytest.MonkeyPatch) -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE)

    async def broken(*_: Any) -> str:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(RemediateHandler, "_prove_purge", broken)
    run = await purge(fake, purge_action(mid), phish_alert(mid, (ALICE,), reporter=None))
    assert run.result.status == "succeeded" and run.result.external_ref["reversible"] is True
    assert run.result.verify is not None and run.result.verify.state == "pending"


# ----------------------------------------------------------------------------- untrusted input


@pytest.mark.parametrize(
    ("raw", "encoded"),
    [
        ("<o'brien@x.example>", b"%3Co%27%27brien%40x.example%3E"),
        ("<a+b@x.example>", b"%3Ca%2Bb%40x.example%3E"),
        ("<a#b@x.example>", b"%3Ca%23b%40x.example%3E"),
        ("<a&$top=999@x.example>", b"%3Ca%26%24top%3D999%40x.example%3E"),
        ("<a%27b@x.example>", b"%3Ca%2527b%40x.example%3E"),
        ("a+b@x.example", b"%3Ca%2Bb%40x.example%3E"),  # brackets added
    ],
)
async def test_message_ids_are_encoded_exactly_once(raw: str, encoded: bytes) -> None:
    fake, exchange = mail_world()
    mid = odata.internet_message_id(raw)
    exchange.mailbox(ALICE).add(mid)
    action = purge_action(raw)
    run = await purge(fake, action, phish_alert(mid, (ALICE,), reporter=None))
    assert run.result.status == "succeeded" and run.result.detail["removed"] == 1
    lookup = next(r for r in fake.api_requests() if r.url.path == f"/v1.0/users/{ALICE}/messages")
    assert b"$filter=internetMessageId%20eq%20%27" + encoded + b"%27&" in lookup.url.query
    assert b"$select=id%2CparentFolderId%2CinternetMessageId%2Cfrom%2Csubject%2CreceivedDateTime" in lookup.url.query
    assert lookup.url.raw_path.startswith(b"/v1.0/users/alice%40contoso.example/messages?")


@pytest.mark.parametrize(
    "raw", ["<a b@x.example>", "<a\x00b@x.example>", "<a\r\nb@x.example>", "<no-at-sign>", "<a<b@x.example>", ""]
)
async def test_malformed_message_ids_are_refused_before_any_request(raw: str) -> None:
    fake, exchange = mail_world()
    action = purge_action(raw) if raw else purge_action("placeholder@x.example").model_copy(update={"target": ""})
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert("<x@y.example>"))
    with pytest.raises(odata.InvalidTarget) as exc:
        await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert exc.value.code == "invalid_target" and fake.requests == []


async def test_a_malformed_sender_is_refused() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    action = purge_action(mid, sender="billing@attacker.example' or 1 eq 1")
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid))
    with pytest.raises(odata.InvalidTarget):
        await MAIL_REMEDIATE.handler(run.ctx).execute(action)
    assert fake.requests == []


async def test_mailbox_addresses_from_the_alert_are_validated_before_use() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    exchange.mailbox(ALICE).add(mid)
    alert = phish_alert(mid, (ALICE, "../../admin@contoso.example", "x@contoso.example/messages", "a b@c.example"),
                        reporter=None)
    run = await purge(fake, purge_action(mid), alert)
    assert [s["mailbox"] for s in run.result.external_ref["steps"]] == [ALICE]
    assert run.result.detail["invalid_recipients"] == 3
    assert all(r.url.path.startswith(f"/v1.0/users/{ALICE}/") for r in fake.api_requests())


# ----------------------------------------------------------------------------- rehearsal and probe


async def test_rehearsal_resolves_with_gets_only() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    recipients = [f"user{i}@contoso.example" for i in range(7)]
    delivered(exchange, mid, *recipients[:3])
    for address in recipients[3:6]:
        exchange.mailbox(address)
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, alert=phish_alert(mid, recipients, reporter=None), read_only=True)
    resolved = await MAIL_REMEDIATE.handler(run.ctx).rehearse(action)
    assert resolved["would_execute"] == {"mode": "soft_delete", "mailboxes": 7}
    assert resolved["found"] == {recipients[0]: 1, recipients[1]: 1, recipients[2]: 1, recipients[3]: 0,
                                 recipients[4]: 0}
    assert resolved["summary"] == "would soft-delete the message in 7 mailboxes; found in 3 of the 5 checked"
    assert fake.writes() == [] and run.store == {} and run.checkpoints == []
    assert {r.method for r in fake.api_requests()} == {"GET"}


async def test_rehearsal_reports_a_refusal_without_looking_further() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, options={"max_mailboxes": 1}, alert=phish_alert(mid, (ALICE, BOB)),
                  read_only=True)
    resolved = await MAIL_REMEDIATE.handler(run.ctx).rehearse(action)
    assert resolved["problem"] == "too_many_recipients" and resolved["count"] == 2
    assert fake.api_requests() == []


async def test_probe_reads_the_probe_mailbox_and_message_trace() -> None:
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    run = context(fake, MAIL_REMEDIATE, purge_action(message_id()), read_only=True,
                  options={"probe_mailbox": ALICE, "recipient_source": "message_trace"})
    run.ctx.marker = ""
    checks = await RemediateHandler(run.ctx).probe()
    assert [(c.name, c.status, c.permission) for c in checks] == [
        ("mailbox access", "ok", "Mail.ReadWrite"),
        ("message trace", "ok", "ExchangeMessageTrace.Read.All"),
    ]
    paths = [r.url.path for r in fake.api_requests()]
    assert paths == [f"/v1.0/users/{ALICE}/mailFolders/inbox", "/v1.0/admin/exchange/tracing/messageTraces"]
    assert fake.writes() == []


async def test_probe_reports_refusals_and_missing_setup() -> None:
    fake, exchange = mail_world()
    exchange.mailbox(ALICE)
    exchange.fail("GET", rf"/v1\.0/users/{ALICE}/mailFolders/inbox", graph_error(403, "ErrorAccessDenied"))
    run = context(fake, MAIL_REMEDIATE, purge_action(message_id()), read_only=True, options={"probe_mailbox": ALICE})
    (check,) = await RemediateHandler(run.ctx).probe()
    assert check.status == "forbidden" and "ErrorAccessDenied" in check.detail and len(check.detail) <= 300
    bare = context(fake, MAIL_REMEDIATE, purge_action(message_id()), read_only=True)
    (skipped,) = await RemediateHandler(bare.ctx).probe()
    assert skipped.status == "skipped" and skipped.detail == "set probe_mailbox to test mailbox access"


async def test_the_handler_needs_nothing_but_graph() -> None:
    fake, exchange = mail_world()
    mid = message_id()
    delivered(exchange, mid, ALICE)
    await purge(fake, purge_action(mid), phish_alert(mid, (ALICE,), reporter=None))
    hosts = {r.url.host for r in fake.requests}
    assert hosts == {fake.profile.login_host, fake.profile.graph_host}
    assert SENDER not in json.dumps([r.url.path for r in fake.writes()])
