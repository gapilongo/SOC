"""Live ingestion contract: the real Wazuh connector against a Wazuh 4.14 indexer (INT3.1).

The unit tests (tests/unit/ingestion/test_connectors.py) pin the connector's
requests against a fake. These run the same code against the real indexer,
with the index template Wazuh publishes, so they catch what a fake cannot:
how the security plugin answers bad credentials, how ``search_after`` and the
``id`` tie-breaker sort on the real mapping, how range queries parse our
timestamps, and what the template does with malformed documents.

Skipped unless ``LG_SOTF_TEST_WAZUH_ADDRESS`` is set (``make test-wazuh``).
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List

import pytest

from lg_sotf.ingestion.errors import SourceAuthError, UnrecognizedEvent
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.ingestion.normalizers.wazuh import WazuhNormalizer
from lg_sotf.ingestion.sources import PullConnector
from lg_sotf.ingestion.sources.base import iso
from lg_sotf.models.alert import CanonicalAlert
from tests.fixtures.wazuh_lab import SAMPLE_ALERTS, WazuhLab, read_alerts
from tests.live.wazuh._support import AFTER_SAMPLES, BEFORE_SAMPLES, NOW, SKIP_REASON, collect, event_ids, lab_address

pytestmark = [pytest.mark.live, pytest.mark.skipif(lab_address() is None, reason=SKIP_REASON)]

Connect = Callable[..., PullConnector]
SAMPLES = read_alerts(SAMPLE_ALERTS)
IN_ORDER = [a["id"] for a in sorted(SAMPLES, key=lambda a: (a["timestamp"], a["id"]))]
FROM_START = {"v": 1, "since": BEFORE_SAMPLES}


def seed(lab_admin: WazuhLab, index: str, alerts: List[Dict[str, Any]]) -> None:
    indexed, rejected = lab_admin.load(alerts, index)
    assert (indexed, rejected) == (len(alerts), [])


def normalize(event: Dict[str, Any]) -> CanonicalAlert:
    return WazuhNormalizer().normalize(event, NormalizeContext(source_id="src-1", source_type="wazuh", now=NOW))


# -- authentication ------------------------------------------------------------------


async def test_the_reader_authenticates_and_counts_the_alerts(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    conn = wazuh()
    try:
        health = await conn.test()
    finally:
        await conn.aclose()
    assert health.ok and f"{len(SAMPLES)} alerts in {alert_index}" in health.detail


async def test_a_wrong_password_is_an_auth_error(wazuh: Connect, reader: Dict[str, str]) -> None:
    conn = wazuh({"username": reader["username"], "password": "test-only-not-the-password"})
    with pytest.raises(SourceAuthError, match=r"HTTP 401"):
        await conn.test()
    pages, error = await collect(conn, FROM_START)
    assert pages == [] and isinstance(error, SourceAuthError)


async def test_a_user_without_read_access_is_an_auth_error(
    wazuh: Connect, no_access_user: Dict[str, str], lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES[:1])
    pages, error = await collect(wazuh(no_access_user), FROM_START)
    assert pages == [] and isinstance(error, SourceAuthError) and "HTTP 403" in str(error)


async def test_the_reader_sees_only_the_alert_indices(wazuh: Connect, lab_admin: WazuhLab, alert_index: str) -> None:
    # The least-privilege role the connector docs ask for: wazuh-alerts-* only, not the archives.
    archive = alert_index.replace("wazuh-alerts-", "wazuh-archives-")
    try:
        seed(lab_admin, archive, SAMPLES[:1])
        pages, error = await collect(wazuh(index=archive), FROM_START)
    finally:
        lab_admin.delete_index(archive)
    assert pages == [] and isinstance(error, SourceAuthError) and "HTTP 403" in str(error)


# -- pagination and cursor -------------------------------------------------------------


async def test_search_after_pages_through_the_window_in_order(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    pages, error = await collect(wazuh(), FROM_START)
    assert error is None
    # Pages of 2, the last one empty; the two alerts raised in the same millisecond (09:02:10)
    # straddle the first page boundary and are ordered by their id.
    assert [len(p.events) for p in pages] == [2, 2, 2, 2, 2, 2, 0]
    assert event_ids(pages) == IN_ORDER
    assert IN_ORDER[1:3] == ["1762074130.2044", "1762074130.2051"]
    for page in pages[:-1]:
        # The resume point: (epoch millis of the time field, alert id) of the page's last hit.
        after = page.cursor["query"]["after"]
        assert after[1] == page.events[-1]["id"] and isinstance(after[0], int)
        assert page.cursor["since"] == BEFORE_SAMPLES and page.cursor["query"]["until"] == iso(NOW)
    assert pages[-1].cursor == {"v": 1, "since": iso(NOW)}


async def test_a_mid_window_cursor_resumes_without_gaps_or_repeats(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    first, error = await collect(wazuh(), FROM_START, max_pages=2)
    assert error is None
    # The poller stores the cursor after each page; a restart resumes from it with a new connector.
    rest, error = await collect(wazuh(), copy.deepcopy(first[-1].cursor))
    assert error is None
    assert event_ids(first) + event_ids(rest) == IN_ORDER


async def test_a_drained_cursor_returns_only_newer_alerts(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    since = "2026-11-02T09:14:03.500Z"  # exactly the 510 alert: the window's lower bound is exclusive
    pages, error = await collect(wazuh(), {"v": 1, "since": since})
    assert error is None
    assert event_ids(pages) == IN_ORDER[IN_ORDER.index("1762074843.7004") + 1 :]


# -- severity -------------------------------------------------------------------------------


async def test_min_level_filters_on_rule_level_and_levels_map_to_severities(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    pages, error = await collect(wazuh(min_level=7), FROM_START)
    assert error is None
    events = [e for p in pages for e in p.events]
    assert sorted(e["rule"]["level"] for e in events) == [7, 8, 10, 10, 12, 13, 15]
    # Wazuh rule levels on the 0-15 scale: 3-6 low, 7-10 medium, 11-13 high, 14-15 critical.
    severities = {e["rule"]["id"]: normalize(e).severity for e in events}
    assert severities == {
        "550": "medium", "5403": "medium", "5712": "medium", "23505": "medium",
        "87105": "high", "510": "high", "92213": "critical",
    }

    pages, error = await collect(wazuh(), FROM_START)
    low = {e["rule"]["id"]: normalize(e).severity for p in pages for e in p.events if e["rule"]["level"] < 7}
    assert error is None and low == {"5501": "low", "5710": "low", "60122": "low", "31106": "low", "651": "low"}


async def test_indexed_alerts_normalize_with_their_identity_and_entities(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    pages, error = await collect(wazuh(min_level=10), FROM_START)
    assert error is None
    alerts = {a.source_alert_id: a for a in (normalize(e) for p in pages for e in p.events)}
    brute = alerts["1762074420.4120"]
    assert brute.rule_name == "5712: sshd: brute force trying to get access to the system. Non existent user."
    assert iso(brute.occurred_at) == "2026-11-02T09:07:00.004000Z"
    assert "203.0.113.50" in brute.entities.ips and "web-01" in brute.entities.hosts
    assert brute.mitre.techniques == ["T1110"]


# -- empty windows ---------------------------------------------------------------------------


async def test_an_empty_window_yields_one_empty_page_and_moves_the_cursor(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    seed(lab_admin, alert_index, SAMPLES)
    pages, error = await collect(wazuh(), {"v": 1, "since": AFTER_SAMPLES})
    assert error is None
    assert [p.events for p in pages] == [[]] and pages[0].cursor == {"v": 1, "since": iso(NOW)}


async def test_a_pattern_matching_no_index_is_empty_not_an_error(wazuh: Connect) -> None:
    conn = wazuh(index="wazuh-alerts-4.x-lgsotf-none-*")
    try:
        health = await conn.test()
    finally:
        await conn.aclose()
    assert "0 alerts" in health.detail
    pages, error = await collect(wazuh(index="wazuh-alerts-4.x-lgsotf-none-*"), FROM_START)
    assert error is None and [p.events for p in pages] == [[]]


# -- malformed documents ---------------------------------------------------------------------


def _alert(minute: int, **fields: Any) -> Dict[str, Any]:
    base = copy.deepcopy(next(a for a in SAMPLES if a["rule"]["id"] == "5712"))
    base.update(timestamp=f"2026-11-02T09:{minute:02d}:00.000+0000", id=f"1762074000.{minute}")
    base.update(fields)
    return base


async def test_malformed_documents_are_rejected_by_the_template_or_isolated_by_the_normalizer(
    wazuh: Connect, lab_admin: WazuhLab, alert_index: str
) -> None:
    # The Wazuh template refuses documents whose mapped fields have the wrong type, so those never
    # reach the connector.
    unindexable = [_alert(50, rule={"level": "high", "description": "x", "id": "1"}), _alert(51, rule="sshd"),
                   _alert(52, timestamp="yesterday")]
    indexed, rejected = lab_admin.load(unindexable, alert_index)
    assert indexed == 0 and len(rejected) == 3 and set(rejected) <= {"mapper_parsing_exception", "illegal_argument_exception"}

    no_id = _alert(1)
    del no_id["id"]
    no_description = _alert(3, rule={"level": 9, "id": "99999"})
    level_as_text = _alert(4, rule={**_alert(4)["rule"], "level": "12"})  # coerced by the mapping, kept in _source
    seed(lab_admin, alert_index, [_alert(0), no_id, _alert(2), no_description, level_as_text])

    pages, error = await collect(wazuh(), FROM_START)
    # A hit without the `id` tie-breaker sorts with a null key and paging still continues past it.
    assert error is None and [len(p.events) for p in pages] == [2, 2, 1]
    assert pages[0].cursor["query"]["after"][1] is None
    assert event_ids(pages) == ["1762074000.0", None, "1762074000.2", "1762074000.3", "1762074000.4"]

    events = [e for p in pages for e in p.events]
    with pytest.raises(UnrecognizedEvent):
        normalize(events[3])
    assert normalize(events[4]).severity == "high"
    assert [normalize(e).severity for e in events[:3]] == ["medium"] * 3
