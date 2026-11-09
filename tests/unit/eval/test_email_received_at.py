"""An email item's report time comes from the message, never the wall clock (issue #346)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, List

import pytest

from lg_sotf.eval import runner
from lg_sotf.eval.dataset import parse_dataset
from lg_sotf.eval.runner import EMAIL_FALLBACK_RECEIVED_AT, email_received_at

REPORT = (
    "From: Reporter <alice@example.com>\nTo: phish-reports@example.com\nSubject: Reported: invoice\n"
    "Date: Mon, 28 Sep 2026 09:30:00 +0200\n\nPlease check.\n"
)


def test_the_report_time_is_its_date_header_in_utc() -> None:
    assert email_received_at(REPORT) == datetime(2026, 9, 28, 7, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    "mime",
    [
        "This is a pasted fragment without headers.",
        "From: a@example.com\nDate: not a date\n\nbody\n",
        "From: a@example.com\nDate: \n\nbody\n",
    ],
)
def test_a_report_without_a_usable_date_gets_the_fixed_fallback(mime: str) -> None:
    assert email_received_at(mime) == EMAIL_FALLBACK_RECEIVED_AT


def test_a_date_without_a_zone_is_read_as_utc() -> None:
    assert email_received_at("Date: Mon, 28 Sep 2026 21:00:00 -0000\n\nx\n") == datetime(2026, 9, 28, 21, tzinfo=UTC)


async def test_the_runner_ingests_an_email_item_at_its_report_time() -> None:
    item = parse_dataset(
        '{"id": "e-1", "source_type": "email", "alert": {"mime": ' + json.dumps(REPORT) + "},"
        ' "expected": {"disposition": "malicious"}}'
    ).items[0]
    seen: List[Any] = []

    class Ingestion:
        async def ingest_email(self, *args: Any, received_at: Any = None, **kwargs: Any) -> None:
            seen.append(received_at)

    r = runner.EvalRunner(tenant_id="t", repos=None, ingestion=Ingestion(), engine=None)  # type: ignore[arg-type]
    await r._ingest(item)
    assert seen == [datetime(2026, 9, 28, 7, 30, tzinfo=UTC)]
