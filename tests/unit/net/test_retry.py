"""Retry-After parsing (delta seconds or HTTP date, capped, non-finite refused) and the shared backoff."""

from __future__ import annotations

import datetime as dt
from typing import Callable

import pytest

from lg_sotf.ingestion.sources.http import SourceHttpClient
from lg_sotf.integrations.http import IntegrationHttp
from lg_sotf.integrations.microsoft.http import MicrosoftHttpFactory
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.net.retry import MAX_RETRY_AFTER_S, exp_backoff, parse_retry_after
from lg_sotf.services.connectors.webhook import WebhookConnector, WebhookTarget
from lg_sotf.settings import Settings


def test_parse_retry_after() -> None:
    now = dt.datetime(2024, 3, 5, 10, 0, 0, tzinfo=dt.UTC)
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after("-3") == 0.0
    assert parse_retry_after("Tue, 05 Mar 2024 10:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None
    # Non-finite and absurd hints never reach a sleep or a retry schedule.
    assert parse_retry_after("inf") is None and parse_retry_after("nan") is None and parse_retry_after("-inf") is None
    assert parse_retry_after("1e12") == 3_600.0 and parse_retry_after("2.5") == 2.5
    assert parse_retry_after("90", cap=10.0) == 10.0


def test_default_cap() -> None:
    assert MAX_RETRY_AFTER_S == 3_600.0


def test_exp_backoff_doubles_up_to_the_cap_with_half_to_full_jitter() -> None:
    low, mid, high = (lambda: 0.0), (lambda: 0.5), (lambda: 1.0)
    assert [exp_backoff(n, 0.5, 8.0, high) for n in range(7)] == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0]
    assert [exp_backoff(n, 1.0, 30.0, low) for n in range(6)] == [0.5, 1.0, 2.0, 4.0, 8.0, 15.0]
    assert exp_backoff(2, 0.5, 10.0, mid) == 1.5
    assert exp_backoff(60, 0.5, 30.0, high) == 30.0


def _reference(attempt: int, base_s: float, max_s: float, r: float) -> float:
    # The formula each client wrote out before F5, kept here verbatim.
    return min(max_s, base_s * (2**attempt)) * (0.5 + r / 2)


@pytest.mark.parametrize("r", [0.0, 0.25, 0.5, 1.0])
async def test_every_client_backoff_is_unchanged(make_settings: Callable[..., Settings], r: float) -> None:
    rand = lambda: r  # noqa: E731
    settings = make_settings()
    source = SourceHttpClient(
        source_type="test", base_url="https://api.example.com", rand=rand, backoff_base_s=1.0, backoff_max_s=20.0
    )
    webhook = WebhookConnector(
        WebhookTarget(url="https://soar.example.com/hook", secret="s" * 32),
        policy=DestinationPolicy(require_https=True),
        rand=rand,
        backoff_base_s=0.25,
        backoff_max_s=3.0,
    )
    try:
        for n in range(8):
            assert source._backoff(n) == _reference(n, 1.0, 20.0, r)
            assert webhook._backoff(n) == _reference(n, 0.25, 3.0, r)
            assert IntegrationHttp(settings, rand=rand)._backoff(n) == _reference(n, 0.5, 8.0, r)
            assert MicrosoftHttpFactory(settings, rand=rand).backoff(n) == _reference(n, 0.5, 8.0, r)
    finally:
        await source.aclose()
