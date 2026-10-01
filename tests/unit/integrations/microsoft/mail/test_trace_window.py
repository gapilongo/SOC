"""Message trace windows: anchored on when the report arrived, which the sender of the phish cannot forge.

The email's ``Date`` header comes from the sender. A backdated (or
future-dated) ``Date`` must not move the search away from the real
delivery, and a genuine late report must still be found.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from lg_sotf.integrations.microsoft.alert_view import build_alert_view
from lg_sotf.integrations.microsoft.mail import mailboxes
from lg_sotf.integrations.microsoft.mail.capabilities import MAIL_REMEDIATE
from lg_sotf.services.connectors.base import ConnectorResult
from tests.fixtures.microsoft import FakeMicrosoft
from tests.unit.integrations.microsoft.mail._exchange import FakeExchange
from tests.unit.integrations.microsoft.mail._scenario import (
    ALICE,
    BOB,
    context,
    mail_world,
    message_id,
    phish_alert,
    purge_action,
)

DAY = timedelta(days=1)


def graph_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


async def traced_purge(exchange: FakeExchange, fake: FakeMicrosoft, mid: str, *, date: datetime, reported: datetime,
                       delivered: datetime) -> ConnectorResult:
    for address in (ALICE, BOB):
        exchange.mailbox(address).add(mid)
        exchange.trace(mid, address, received=graph_time(delivered))
    alert = phish_alert(mid, (), reporter=None, received_at=date, ingested_at=reported)
    action = purge_action(mid)
    run = context(fake, MAIL_REMEDIATE, action, options={"recipient_source": "message_trace"}, alert=alert)
    return await MAIL_REMEDIATE.handler(run.ctx).execute(action)


async def test_a_date_backdated_by_a_month_still_finds_the_recipients() -> None:
    fake, exchange = mail_world()
    now = datetime.now(UTC)
    mid = message_id()
    result = await traced_purge(exchange, fake, mid, date=now - 30 * DAY, reported=now - timedelta(minutes=5),
                                delivered=now - timedelta(hours=1))
    assert result.status == "succeeded", result.detail
    assert result.detail["removed"] == 2


async def test_a_date_backdated_beyond_90_days_is_searched_by_the_report_time() -> None:
    fake, exchange = mail_world()
    now = datetime.now(UTC)
    mid = message_id()
    result = await traced_purge(exchange, fake, mid, date=now - 200 * DAY, reported=now, delivered=now - DAY)
    assert result.status == "succeeded" and result.detail["removed"] == 2
    assert len(exchange.trace_filters) == 1  # the Date window is outside the 90 days: not searched


async def test_a_future_date_does_not_hide_a_message_reported_days_later() -> None:
    fake, exchange = mail_world()
    now = datetime.now(UTC)
    mid = message_id()
    result = await traced_purge(exchange, fake, mid, date=now + 30 * DAY, reported=now, delivered=now - 5 * DAY)
    assert result.status == "succeeded" and result.detail["removed"] == 2


async def test_a_genuine_late_report_is_found_through_the_date_window() -> None:
    fake, exchange = mail_world()
    now = datetime.now(UTC)
    mid = message_id()
    result = await traced_purge(exchange, fake, mid, date=now - 20 * DAY, reported=now,
                                delivered=now - 20 * DAY + timedelta(minutes=2))
    assert result.status == "succeeded" and result.detail["removed"] == 2
    assert len(exchange.trace_filters) == 2


def test_windows_cover_the_days_before_the_report_whatever_the_date_says() -> None:
    now = datetime.now(UTC)
    for date in (now - 12 * DAY, now - 30 * DAY, now - 89 * DAY, now + 30 * DAY, now - DAY):
        windows = mailboxes.trace_windows(date, now, now)
        first, last = windows[0]
        assert (first, last) == (now - 9 * DAY, now)
        assert all(end - start <= 10 * DAY and end <= now and start >= now - 90 * DAY for start, end in windows)
    # The Date window is added only when it reaches further back than the report window.
    assert len(mailboxes.trace_windows(now - 12 * DAY, now, now)) == 2
    assert len(mailboxes.trace_windows(now - 3 * DAY, now, now)) == 1
    # A report older than 90 days cannot be traced at all.
    assert mailboxes.trace_windows(now - 100 * DAY, now, now - 95 * DAY) == []
    # Without the report time (no alert row), the Date window alone, as before.
    assert mailboxes.trace_windows(now - 3 * DAY, now) == [(now - 4 * DAY, now)]


def test_the_alert_view_exposes_the_ingestion_time() -> None:
    ingested = datetime.now(UTC) - timedelta(minutes=3)
    row = SimpleNamespace(
        id="alert-1", title="Reported phishing", severity="high", disposition=None, summary={},
        ingested_at=ingested,
        normalized={"email": {"message_id": "<a@b.example>", "date": "Mon, 01 Jan 2024 00:00:00 +0000"}},
    )
    view = build_alert_view(row)  # type: ignore[arg-type]
    assert view.ingested_at == ingested
    assert view.received_at == datetime(2024, 1, 1, tzinfo=UTC)  # the sender's Date, kept as it is
