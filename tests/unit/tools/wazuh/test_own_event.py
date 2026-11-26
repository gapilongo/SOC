"""Review of PR 443 (AI-E3.3), findings 3 and 7: an alert is never its own evidence, prevalence is taken as
of the alert, and an address is asked for as the detector wrote it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

import pytest

from lg_sotf.eval.tool_fixtures import EventStore
from lg_sotf.tools.registry import ToolParamsInvalid
from lg_sotf.tools.wazuh import templates
from tests.unit.tools.wazuh._support import Investigation, minutes

pytestmark = pytest.mark.unit

AT = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
HOST = "FIN-SRV-02"
RULE = "5710"
HASH = "cd" * 32
WINDOW = {"host": HOST, "at": AT, "before_min": 60, "after_min": 0}


def event(
    n: int, before_s: float = 0, *, rule: str = "100100", level: int = 3, technique: str = "T1059.001",
    group: str = "sysmon", host: str = HOST, sha256: Optional[str] = None,
) -> Dict[str, Any]:
    at = AT - timedelta(seconds=before_s)
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"
    doc: Dict[str, Any] = {
        "id": f"1790000000.{n}", "timestamp": stamp, "agent": {"name": host},
        "rule": {"id": rule, "level": level, "groups": [group], "mitre": {"id": [technique]}},
    }
    if sha256 is not None:
        doc["syscheck"] = {"sha256_after": sha256}
    return doc


def the_alert(n: int = 1) -> Dict[str, Any]:
    """The investigated alert's own event: a level-12 credential-access alert (never-close class)."""
    return event(n, rule=RULE, level=12, technique="T1110", group="authentication_failures")


async def host(documents: List[Dict[str, Any]], **params: Any) -> Any:
    look = Investigation(EventStore(documents), AT + minutes(30))
    result = await look.call("host_activity", **{**WINDOW, **params})
    assert result.outcome != "failed", result.value.error
    return result


async def test_an_alert_alone_on_its_host_shows_nothing() -> None:
    """Without the exclusion the host's hour holds one event, level 12, T1110: the alert itself, which made the
    skill's two malicious indicators true for every alert of a never-close class or a high level."""
    counted = await host([the_alert()])
    assert counted.outcome == "success" and counted.value[0].value.total == 1 and counted.value[0].value.max_level == 12
    alone = await host([the_alert()], exclude_rule_id=RULE)
    assert (alone.outcome, tuple(alone.value), alone.rows) == ("empty", (), 0)
    # Its exact duplicates (the same rule at the same instant, another document id) are the alert too.
    copies = await host([the_alert(1), the_alert(2), the_alert(3)], exclude_rule_id=RULE)
    assert (copies.outcome, tuple(copies.value)) == ("empty", ())
    # Another host's event of the same rule at the same instant is not on this host at all.
    elsewhere = await host([the_alert(), event(9, rule=RULE, host="WS-07")], exclude_rule_id=RULE)
    assert elsewhere.outcome == "empty"


async def test_the_alerts_own_event_is_taken_out_of_every_number_and_the_rest_is_kept() -> None:
    quiet = event(2, 600)  # ten minutes before: level 3, T1059.001
    earlier = event(3, 300, rule=RULE, level=10, technique="T1110", group="authentication_failures")  # same rule, earlier
    result = await host([the_alert(1), the_alert(4), quiet, earlier], exclude_rule_id=RULE)
    (fact,) = result.value
    value = fact.value
    assert value.total == 2 and value.max_level == 10  # the alert's level 12 is gone; the earlier 10 stays
    assert sorted(value.techniques) == ["T1059.001", "T1110"]  # T1110 from the earlier event, not from the alert
    assert {row.group: row.count for row in value.by_group} == {"sysmon": 1, "authentication_failures": 1}
    assert [(e.rule_id, e.level) for e in value.events] == [(RULE, 10), ("100100", 3)]
    assert all(e.at < AT for e in value.events)
    # With only the quiet event beside it, nothing of the alert is left: no technique, no group, no level.
    (left,) = (await host([the_alert(), quiet], exclude_rule_id=RULE)).value
    assert (left.value.total, left.value.max_level, left.value.techniques) == (1, 3, ["T1059.001"])
    assert [row.group for row in left.value.by_group] == ["sysmon"]
    # Another rule's event at the very same instant is somebody else's and is kept.
    twin = event(5, technique="T1486", level=14, group="ransomware")
    (kept,) = (await host([the_alert(), twin], exclude_rule_id=RULE)).value
    assert (kept.value.total, kept.value.max_level, kept.value.techniques) == (1, 14, ["T1486"])


async def test_without_a_rule_the_host_is_read_whole_and_a_malformed_rule_is_refused() -> None:
    (whole,) = (await host([the_alert(), event(2, 600)])).value
    assert whole.value.total == 2 and whole.value.max_level == 12 and "T1110" in whole.value.techniques
    assert templates.own_event(templates.HostActivityParams(**WINDOW)) is None
    look = Investigation(EventStore([the_alert()]), AT + minutes(30))
    for hostile in ("5710 OR 1=1", "", "x" * 33, '5710"}}', "*"):
        with pytest.raises(ToolParamsInvalid, match="exclude_rule_id"):  # never part of a query
            await look.call("host_activity", **WINDOW, exclude_rule_id=hostile)


async def test_the_own_event_query_asks_for_the_alerts_rule_host_and_instant_only() -> None:
    body = templates.own_event(templates.HostActivityParams(**WINDOW, exclude_rule_id=RULE))
    assert body is not None and set(body["aggs"]) == set(templates.host_activity(templates.HostActivityParams(**WINDOW))["aggs"])
    text = str(body["query"])
    assert HOST in text and RULE in text and text.count("2026-11-02T09:00:00") == 2 and "08:00:00" not in text


async def test_prevalence_is_what_was_seen_up_to_the_alert_not_up_to_now() -> None:
    """Asked a day later (a retry, a backlog), the answer is the one of the alert's own moment: what the file
    did afterwards is not evidence about the alert, and two runs of one alert agree."""
    documents = [
        event(1, 86_400, sha256=HASH, host="WS-01"), event(2, 0, sha256=HASH, host=HOST),
        event(3, -3_600, sha256=HASH, host="WS-02"), event(4, -7_200, sha256=HASH, host="WS-03"),
        event(5, 86_400 * 20, host="OLD-01"),  # the index reaches back 20 days
    ]
    look = Investigation(EventStore(documents), AT + timedelta(days=1))
    now = await look.fact("prevalence", kind="sha256", value=HASH, days=7)
    then = await look.fact("prevalence", kind="sha256", value=HASH, days=7, at=AT)
    assert now is not None and then is not None
    assert (now.value.host_count, now.value.window_end) == (4, look.as_of)
    assert (then.value.host_count, then.value.window_end, then.value.window_start) == (2, AT, AT - timedelta(days=7))
    assert then.value.last_seen_at == AT and then.complete is True
    # A time ahead of the index's own clock is not a window that has been read: it ends now.
    ahead = await look.fact("prevalence", kind="sha256", value=HASH, days=7, at=look.as_of + timedelta(days=3))
    assert ahead is not None and ahead.value.window_end == look.as_of
    with pytest.raises(ToolParamsInvalid, match="at: value_error"):  # a time without a zone is no moment
        await look.call("prevalence", kind="sha256", value=HASH, days=7, at=datetime(2026, 11, 2, 9, 0))


def logon(n: int, address: str, before_s: float = 60) -> Dict[str, Any]:
    doc = event(n, before_s, rule="60122", level=5, technique="T1110", group="authentication_failed")
    doc["data"] = {"win": {"system": {"eventID": "4625", "providerName": "Microsoft-Windows-Security-Auditing"},
                           "eventdata": {"targetUserName": f"user{n}", "ipAddress": address, "logonType": "3"}}}
    return doc


LONG, SHORT = "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"


@pytest.mark.parametrize(
    ("asked", "found"),
    [
        (LONG, 5),  # as the detector wrote it, and its canonical form too
        (SHORT, 2),  # the canonical spelling finds what is stored canonically; nothing invents other spellings
        ("10.20.1.83", 1),
    ],
)
async def test_a_source_address_is_asked_for_as_written_and_in_its_canonical_form(asked: str, found: int) -> None:
    """Review finding 7: the view used to rewrite ``2001:0DB8:0000:...`` to ``2001:db8::1`` and the exact-match
    query then found none of the 30 failures the index held under the detector's spelling."""
    documents = [*(logon(n, LONG) for n in range(3)), logon(3, SHORT), logon(4, SHORT), logon(5, "10.20.1.83")]
    look = Investigation(EventStore(documents), AT + minutes(30))
    fact = await look.fact("logon_fanout", pivot="source_ip", value=asked, at=AT, before_min=30)
    assert fact is not None and fact.value.failures == found


def test_only_an_address_has_more_than_one_spelling() -> None:
    assert templates.spellings("source_ip", LONG) == [LONG, SHORT]
    assert templates.spellings("source_ip", SHORT) == [SHORT] and templates.spellings("source_ip", "10.0.0.7") == ["10.0.0.7"]
    assert templates.spellings("target_user", "J.Doe") == ["J.Doe"]
