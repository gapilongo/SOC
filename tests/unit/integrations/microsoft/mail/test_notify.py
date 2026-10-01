"""mail.notify notify_reporter: allowed recipients, the tagged draft, idempotent send, proof, the fixed text."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import pytest

from lg_sotf.db.repos.actions import ResponseAction
from lg_sotf.integrations.microsoft import odata
from lg_sotf.integrations.microsoft.mail import templates
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_NOTIFY
from lg_sotf.integrations.microsoft.mail.notify import PROP_ID, PROPERTY_SET, MailNotifyOptions, NotifyHandler
from tests.fixtures.microsoft import FakeMicrosoft, graph_error, make_action
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange
from tests.unit.integrations.microsoft.mail._scenario import (
    ALICE,
    SOC,
    Run,
    context,
    executed,
    mail_world,
    message_id,
    phish_alert,
)

OPTIONS = {"sender_mailbox": SOC}


def notify_action(reporter: Optional[str] = ALICE, **fields: Any) -> ResponseAction:
    params: Dict[str, Any] = {"playbook": "phishing"}
    if reporter is not None:
        params["reporter"] = reporter
    return make_action("notify_reporter", "alert:alert-1", params=params, **fields)


def world() -> tuple[FakeMicrosoft, FakeExchange]:
    fake, exchange = mail_world()
    exchange.mailbox(SOC)
    return fake, exchange


async def notify(fake: FakeMicrosoft, action: ResponseAction, *, disposition: str = "malicious",
                 subject: str = "Invoice overdue", **options: Any) -> Run:
    run = context(fake, MAIL_NOTIFY, action, options={**OPTIONS, **options},
                  alert=phish_alert(message_id(), subject=subject, disposition=disposition))
    run.result = await MAIL_NOTIFY.handler(run.ctx).execute(action)
    return run


def tag(exchange: FakeExchange, folder: str, action: ResponseAction, **fields: Any) -> Any:
    message = exchange.mailbox(SOC).add(f"<{action.id.hex}@contoso.example>", folder=folder, sender=SOC, **fields)
    message.props = {PROP_ID: str(action.id)}
    return message


async def test_sends_one_tagged_plain_text_reply() -> None:
    fake, exchange = world()
    action = notify_action()
    run = await notify(fake, action)
    result = run.result
    assert result.status == "succeeded" and result.detail == {"summary": "notification sent to the reporter",
                                                              "changed": True}
    create, send = fake.writes()
    assert create.url.path == f"/v1.0/users/{SOC}/messages"
    body = json.loads(create.content)
    assert body["toRecipients"] == [{"emailAddress": {"address": ALICE}}]
    assert body["singleValueExtendedProperties"] == [{"id": PROP_ID, "value": str(action.id)}]
    assert body["subject"] == "Update on the email you reported: Invoice overdue"
    assert body["body"] == {"contentType": "Text", "content": templates.render("malicious", "x")[1]}
    (sent,) = exchange.mailbox(SOC).in_folder("sentitems")
    assert send.url.path == f"/v1.0/users/{SOC}/messages/{run.store['draft_id']}/send"
    assert sent.to == [ALICE] and sent.props == {PROP_ID: str(action.id)}
    assert run.checkpoints == [{"draft_id": run.store["draft_id"], "sender": SOC}]
    assert result.external_ref == {"sender": SOC, "reversible": False, "draft_id": run.store["draft_id"]}
    plan = result.verify
    assert plan is not None and (plan.state, plan.first_check_s, plan.max_duration_s) == ("pending", 60.0, 1800.0)
    assert exchange.missing_prefer == []


async def test_an_already_sent_reply_is_found_by_its_tag() -> None:
    fake, exchange = world()
    action = notify_action()
    tag(exchange, "sentitems", action, sent_at="2026-09-30T08:00:00Z")
    run = await notify(fake, action)
    result = run.result
    assert result.status == "succeeded" and result.detail["already"] is True and result.detail["changed"] is False
    assert result.verify is not None and result.verify.state == "verified"
    assert result.verify.detail == {"sent_at": "2026-09-30T08:00:00Z"}
    assert fake.writes() == []


async def test_a_draft_left_by_a_crash_is_sent_not_duplicated() -> None:
    fake, exchange = world()
    action = notify_action()
    draft_id = tag(exchange, "drafts", action, is_draft=True).id
    rerun = action.model_copy(update={"external_ref": {"draft_id": draft_id, "sender": SOC}})
    run = await notify(fake, rerun)
    assert run.result.status == "succeeded" and run.result.detail["changed"] is True
    assert [r.url.path for r in fake.writes()] == [f"/v1.0/users/{SOC}/messages/{draft_id}/send"]
    assert len(exchange.mailbox(SOC).in_folder("sentitems")) == 1


async def test_an_unrecorded_draft_is_adopted() -> None:
    fake, exchange = world()
    action = notify_action()
    draft_id = tag(exchange, "drafts", action, is_draft=True).id  # created, but the run stopped before recording it
    run = await notify(fake, action)
    assert [r.url.path for r in fake.writes()] == [f"/v1.0/users/{SOC}/messages/{draft_id}/send"]
    assert run.checkpoints == [{"draft_id": draft_id, "sender": SOC}]


async def test_a_recorded_draft_that_was_sent_waits_for_verification() -> None:
    fake, exchange = world()
    action = notify_action()
    rerun = action.model_copy(update={"external_ref": {"draft_id": "AAMkA-gone", "sender": SOC}})
    run = await notify(fake, rerun)
    result = run.result
    assert result.status == "succeeded" and result.verify is not None and result.verify.state == "pending"
    assert result.detail["summary"] == "the notification was sent by an earlier attempt"
    assert fake.writes() == []


async def test_a_reporter_outside_the_allowed_domains_gets_nothing() -> None:
    fake, exchange = world()
    run = await notify(fake, notify_action("someone@elsewhere.example"))
    assert run.result.status == "failed" and run.result.detail["error"] == "recipient_not_allowed"
    assert fake.requests == []
    allowed = await notify(fake, notify_action("someone@elsewhere.example"), recipient_domains=["elsewhere.example"])
    assert allowed.result.status == "succeeded"
    subdomain = await notify(fake, notify_action("someone@eu.elsewhere.example"), recipient_domains=["elsewhere.example"])
    assert subdomain.result.detail["error"] == "recipient_not_allowed"
    idna = await notify(fake, notify_action("someone@xn--bcher-kva.example"), recipient_domains=["Bücher.example"])
    assert idna.result.status == "succeeded"
    invalid = await notify(fake, notify_action(ALICE), recipient_domains=["not a domain"])
    assert invalid.result.detail["error"] == "recipient_not_allowed"  # never falls back to a wider set


async def test_an_unknown_verdict_can_hold_the_reply() -> None:
    fake, exchange = world()
    run = await notify(fake, notify_action(), disposition="unknown", require_known_disposition=True)
    assert run.result.status == "failed" and run.result.detail["error"] == "disposition_unknown"
    assert run.result.detail["retryable"] is True  # Retry sends it once the alert is decided
    assert fake.requests == []
    sent = await notify(fake, notify_action(), disposition="unknown")
    assert sent.result.status == "succeeded"
    body = json.loads(fake.writes()[0].content)["body"]["content"]
    assert body.startswith(templates.PARAGRAPHS["unknown"])


async def test_missing_or_invalid_inputs_fail_before_any_request() -> None:
    fake, exchange = world()
    with pytest.raises(odata.InvalidTarget):
        await notify(fake, notify_action(None))
    with pytest.raises(odata.InvalidTarget):
        await notify(fake, notify_action("alice@contoso.example>, <evil@attacker.example"))
    no_sender = await notify(fake, notify_action(), sender_mailbox="")
    assert no_sender.result.detail["error"] == "invalid_options"
    assert fake.requests == []


async def test_verification_finds_the_sent_reply() -> None:
    fake, exchange = world()
    action = notify_action()
    run = await notify(fake, action)
    row = executed(action, run.result, verification="pending", verification_detail={})
    check = context(fake, MAIL_NOTIFY, row, options=OPTIONS, read_only=True)
    verdict = await MAIL_NOTIFY.handler(check.ctx).verify(row)
    assert verdict.state == "verified" and verdict.detail["sent_at"]
    exchange.mailbox(SOC).messages.clear()
    assert (await MAIL_NOTIFY.handler(check.ctx).verify(row)).state == "pending"


async def test_the_tag_filter_is_encoded_exactly_once() -> None:
    fake, exchange = world()
    action = notify_action()
    await notify(fake, action)
    lookup = fake.api_requests()[0]
    assert lookup.url.path == f"/v1.0/users/{SOC}/mailFolders/sentitems/messages"
    expected = (
        "$filter=singleValueExtendedProperties%2Fany%28ep%3A%20ep%2Fid%20eq%20%27String%20%7B"
        f"{PROPERTY_SET}%7D%20Name%20LGSOTFAction%27%20and%20ep%2Fvalue%20eq%20%27{action.id}%27%29"
    )
    assert lookup.url.query.decode("ascii").startswith(expected + "&$select=id%2CsentDateTime")


async def test_rehearsal_and_probe_only_read() -> None:
    fake, exchange = world()
    action = notify_action()
    run = context(fake, MAIL_NOTIFY, action, options=OPTIONS, read_only=True,
                  alert=phish_alert(message_id(), subject="Pay now https://evil.example/x"))
    resolved = await MAIL_NOTIFY.handler(run.ctx).rehearse(action)
    assert resolved["would_execute"] == {
        "from": SOC, "to": ALICE, "subject": "Update on the email you reported: Pay now hxxps[:]//evil.example/x",
    }
    checks = await NotifyHandler(run.ctx).probe()
    assert [(c.name, c.status, c.permission) for c in checks] == [
        ("sender mailbox", "ok", "Mail.ReadWrite"), ("send mail", "skipped", "Mail.Send"),
    ]
    assert fake.writes() == [] and run.checkpoints == []
    blocked = context(fake, MAIL_NOTIFY, notify_action("x@elsewhere.example"), options=OPTIONS, read_only=True)
    assert (await MAIL_NOTIFY.handler(blocked.ctx).rehearse(notify_action("x@elsewhere.example")))["problem"] == (
        "recipient_not_allowed"
    )


async def test_probe_without_a_sender_mailbox_is_skipped_and_403_is_forbidden() -> None:
    fake, exchange = world()
    bare = context(fake, MAIL_NOTIFY, notify_action(), read_only=True)
    (check,) = await NotifyHandler(bare.ctx).probe()
    assert check.status == "skipped" and fake.requests == []
    exchange.fail("GET", rf"/v1\.0/users/{SOC}/mailFolders/sentitems", graph_error(403, "ErrorAccessDenied"))
    run = context(fake, MAIL_NOTIFY, notify_action(), options=OPTIONS, read_only=True)
    first, _ = await NotifyHandler(run.ctx).probe()
    assert first.status == "forbidden"


def test_options_problems() -> None:
    assert MailNotifyOptions(sender_mailbox=SOC).problems("global") == []
    assert MailNotifyOptions().problems("global") == [
        "sender_mailbox must be the email address of the SOC mailbox the reply is sent from"
    ]
    problems = MailNotifyOptions(sender_mailbox=SOC, recipient_domains=["contoso.example", "not a domain"]).problems(
        "usgov_dod"
    )
    assert problems == ["recipient_domains: 'not a domain' is not a domain name"]


def test_the_property_set_is_stable() -> None:
    # Re-runs and verification find replies by this tag: it must never change between releases.
    assert PROP_ID == f"String {{{PROPERTY_SET}}} Name LGSOTFAction"
    assert str(PROPERTY_SET) == str(__import__("uuid").uuid5(
        __import__("uuid").NAMESPACE_URL, "https://lg-sotf.invalid/microsoft/mail/notify-reporter"
    ))
