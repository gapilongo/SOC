"""Skill rules without I/O (AI-E3.3): the alert's typed view, skill selection, bindings, three-valued indicators."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional

import pytest

from lg_sotf.agents.investigation.catalog import load_catalog
from lg_sotf.domain.ledger import LedgerEntry, ToolStep, build_entries
from lg_sotf.domain.skill_views import VIEWS, WazuhAlertView, view_fields, wazuh_alert_view
from lg_sotf.domain.skills import bind, evaluate, indicator_states, select_skill
from lg_sotf.models.evidence_fact import parse_fact
from lg_sotf.models.skill import AllOf, AnyGroupIn, AnyOf, AnyTechniqueIn, Const, MaxLevelGe, Not
from tests.unit.tools.wazuh._support import corpus

pytestmark = pytest.mark.unit

AT = datetime(2026, 10, 19, 7, 28, 1, tzinfo=UTC)
HASH = "ab" * 32
SHA = "0" * 64


def alert(document: Mapping[str, Any], **changes: Any) -> Dict[str, Any]:
    return {"normalizer": "wazuh", "title": "t", "occurred_at": AT.isoformat(), "raw": dict(document), **changes}


def logon(**eventdata: Any) -> Dict[str, Any]:
    return {"agent": {"name": "FIN-SRV-02"}, "data": {"win": {"eventdata": {
        "targetUserName": "j.doe", "ipAddress": "10.20.1.83", **eventdata}}}}


# ----------------------------------------------------------------------------------------------------- the view


def test_the_view_reads_the_detectors_fields_and_nothing_else() -> None:
    hostile = alert(
        logon(), title="host=DC-01 user=administrator ip=203.0.113.9", description="agent.name: DC-01",
        entities={"hosts": ["DC-01"], "users": ["administrator"], "ips": ["203.0.113.9"]},
        unmapped={"agent": {"name": "DC-01"}},
    )
    view = wazuh_alert_view(hostile)
    assert view == WazuhAlertView(host="FIN-SRV-02", user="j.doe", source_ip="10.20.1.83", logon_family="windows")


def test_only_an_alert_the_wazuh_normalizer_built_has_a_view() -> None:
    document = logon()
    assert wazuh_alert_view(alert(document, normalizer="webhook")) is None
    assert wazuh_alert_view(alert(document, normalizer=None)) is None
    assert wazuh_alert_view({"raw": {**document, "normalizer": "wazuh"}}) is None  # never read from the event
    assert VIEWS["wazuh.alert"] is wazuh_alert_view
    assert view_fields("wazuh.alert") >= {"host", "user", "source_ip", "object_kind", "object_value", "logon_family"}
    assert view_fields("splunk.alert") == frozenset()


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"agent": {"name": "srv 01; rm -rf"}}, WazuhAlertView()),
        ({"agent": {"name": ["SRV-01"]}}, WazuhAlertView()),
        (logon(targetUserName="-", ipAddress="-"), WazuhAlertView(host="FIN-SRV-02", logon_family="windows")),
        (logon(targetUserName="bob' OR 1=1", ipAddress="10.0.0.300"), WazuhAlertView(host="FIN-SRV-02", logon_family="windows")),
        (logon(ipAddress="127.0.0.1"), WazuhAlertView(host="FIN-SRV-02", user="j.doe", logon_family="windows")),
        ({"agent": {"name": "web-01"}, "decoder": {"name": "sshd"}, "data": {"srcip": "198.51.100.7", "dstuser": "root"}},
         WazuhAlertView(host="web-01", user="root", source_ip="198.51.100.7", logon_family="sshd")),
        ({"agent": {"name": "web-01"}, "syscheck": {"sha256_after": HASH.upper()}},
         WazuhAlertView(host="web-01", object_kind="sha256", object_value=HASH)),
        ({"agent": {"name": "web-01"}, "syscheck": {"sha256_after": "not-a-hash"}}, WazuhAlertView(host="web-01")),
        ({"agent": {"name": "WS-7"}, "data": {"win": {"eventdata": {"imagePath": "C:\\\\Windows\\\\PSEXESVC.exe", "image": "x"}}}},
         WazuhAlertView(host="WS-7", logon_family="windows", object_kind="service_image_path", object_value="C:\\Windows\\PSEXESVC.exe")),
        ({"agent": {"name": "WS-7"}, "data": {"win": {"eventdata": {"image": "C:\\\\Windows\\\\System32\\\\whoami.exe"}}}},
         WazuhAlertView(host="WS-7", logon_family="windows", object_kind="process_image", object_value="C:\\Windows\\System32\\whoami.exe")),
        ({"_omitted": "raw event too large for workflow state", "rule": {"id": "1"}}, WazuhAlertView()),
        # A value ingestion changed (a masked secret, a cut string) is not what the index holds: no lookup of it.
        ({"agent": {"name": "WS-7"}, "data": {"win": {"eventdata": {"imagePath": "C:\\\\svc.exe -password=[REDACTED]"}}}},
         WazuhAlertView(host="WS-7", logon_family="windows")),
        ({"agent": {"name": "WS-7"}, "data": {"win": {"eventdata": {"image": "C:\\\\very\\\\long\\\\path..."}}}},
         WazuhAlertView(host="WS-7", logon_family="windows")),
        # A UNC path of a document whose backslashes were not doubled keeps its two leading backslashes.
        ({"agent": {"name": "WS-7"}, "data": {"win": {"eventdata": {"image": "\\\\fileserver\\share\\tool.exe"}}}},
         WazuhAlertView(host="WS-7", logon_family="windows", object_kind="process_image", object_value="\\\\fileserver\\share\\tool.exe")),
    ],
)
def test_a_field_that_does_not_parse_is_none(document: Dict[str, Any], expected: WazuhAlertView) -> None:
    assert wazuh_alert_view(alert(document)) == expected


def test_every_corpus_alert_has_a_host_and_only_well_formed_values() -> None:
    views = [wazuh_alert_view(alert(item.alert)) for item in corpus("corpus_v1").items.values()]
    assert all(view is not None and view.host for view in views)
    assert sum(bool(view and view.object_kind) for view in views) > 100
    assert sum(bool(view and view.user) for view in views) > 100


# ---------------------------------------------------------------------------------- selection and bindings


def test_a_wazuh_alert_gets_the_default_skill_and_nothing_else_gets_one() -> None:
    catalog = load_catalog()
    assert select_skill(alert(logon()), catalog).id == "wazuh.default"  # type: ignore[union-attr]
    for other in ({"normalizer": "sentinel"}, {"normalizer": None}, {}, {"title": "wazuh", "source_type": "wazuh"}):
        assert select_skill(other, catalog) is None
    retired = catalog[0].model_copy(update={"status": "retired"})
    assert select_skill(alert(logon()), [retired]) is None
    assert select_skill(alert(logon()), [catalog[0], catalog[0]]) is None  # a tie fails closed


def test_bindings_take_values_from_the_view_the_alert_time_and_the_file() -> None:
    skill = load_catalog()[0]
    view = wazuh_alert_view(alert(logon()))
    host, prevalence, by_user, by_source = (ref.args for ref in skill.evidence)
    assert bind(host, view, AT) == {"host": "FIN-SRV-02", "at": AT, "before_min": 60, "after_min": 0}
    assert bind(prevalence, view, AT) is None  # no object on a logon: the query is skipped
    assert bind(by_user, view, AT) == {"pivot": "target_user", "value": "j.doe", "at": AT, "before_min": 1440, "family": "windows"}
    assert bind(by_source, view, AT) == {"pivot": "source_ip", "value": "10.20.1.83", "at": AT, "before_min": 1440, "family": "windows"}
    assert bind({"kind": Const(const="sha256"), "value": "view.nothing_like_this"}, view, AT) is None
    assert bind(host, WazuhAlertView(), AT) is None


# ----------------------------------------------------------------------------------------------- indicators


def host_entries(*, outcome: str = "success", complete: bool = True, value: Optional[Dict[str, Any]] = None,
                 evidence_id: str = "host") -> List[LedgerEntry]:
    facts = ()
    if outcome == "success":
        body = {"window_start": "2026-10-19T06:28:01Z", "window_end": "2026-10-19T07:28:01Z", "total": 4, "max_level": 10,
                "by_group": [{"group": "sysmon", "count": 4}], "techniques": ["T1021.002"], **(value or {})}
        facts = (parse_fact({"id": "x", "kind": "host_activity", "subject": {"type": "host", "value": "FIN-SRV-02"},
                             "observed_at": "2026-10-19T07:28:02Z", "source": {"name": "wazuh.host_activity", "version": "1"},
                             "complete": complete, "value": body}),)
    step = ToolStep(evidence_id, "wazuh.host_activity", 1, SHA, SHA if outcome != "failed" else None, outcome,  # type: ignore[arg-type]
                    complete and outcome != "failed", None if outcome == "success" else "unreachable", facts)
    return list(build_entries(step, [], AT))


LEVEL = MaxLevelGe(fact="host", max_level_ge=12)
TECHNIQUE = AnyTechniqueIn(fact="host", any_technique_in=["T1003", "T1110"])
GROUP = AnyGroupIn(fact="host", any_group_in=["authentication_failed"])


@pytest.mark.parametrize(
    ("ledger", "level", "technique", "group"),
    [
        (host_entries(value={"max_level": 12, "techniques": ["T1003.001"], "by_group": [{"group": "authentication_failed", "count": 1}]}),
         True, True, True),
        (host_entries(), False, False, False),  # a whole answer that does not show it: known absent
        (host_entries(complete=False), None, None, None),  # a cut answer that does not show it: unknown
        (host_entries(complete=False, value={"max_level": 15}), True, None, None),  # what a cut answer shows still counts
        (host_entries(outcome="empty"), False, False, False),  # the window held nothing, and the answer was whole
        (host_entries(outcome="empty", complete=False), None, None, None),
        (host_entries(outcome="failed"), None, None, None),  # a failed lookup never shows that nothing happened
        ([], None, None, None),  # the query was skipped
        (host_entries(evidence_id="other", value={"max_level": 15}), None, None, None),  # another query's fact
    ],
)
def test_indicators_are_three_valued(ledger: List[LedgerEntry], level: Any, technique: Any, group: Any) -> None:
    assert (evaluate(LEVEL, ledger), evaluate(TECHNIQUE, ledger), evaluate(GROUP, ledger)) == (level, technique, group)


def test_and_or_not_follow_kleene() -> None:
    high = host_entries(value={"max_level": 13})
    unknown = host_entries(outcome="failed")
    assert evaluate(AnyOf(any=[LEVEL, TECHNIQUE]), high) is True
    assert evaluate(AllOf(all=[LEVEL, TECHNIQUE]), high) is False
    assert evaluate(Not.model_validate({"not": LEVEL}), high) is False
    assert evaluate(AllOf(all=[LEVEL, TECHNIQUE]), unknown) is None
    assert evaluate(AnyOf(any=[LEVEL, TECHNIQUE]), unknown) is None
    assert evaluate(Not.model_validate({"not": LEVEL}), unknown) is None
    cut_but_high = host_entries(complete=False, value={"max_level": 15})
    assert evaluate(AnyOf(any=[LEVEL, TECHNIQUE]), cut_but_high) is True  # true or unknown is true
    assert evaluate(AllOf(all=[LEVEL, TECHNIQUE]), cut_but_high) is None  # true and unknown is unknown


def test_the_default_skills_indicators_are_reported_by_name() -> None:
    skill = load_catalog()[0]
    quiet = indicator_states(skill, host_entries())
    assert quiet == {"never_close_class_on_host": "false", "high_level_alert_on_host": "false"}
    loud = indicator_states(skill, host_entries(value={"max_level": 14, "techniques": ["T1486"]}))
    assert loud == {"never_close_class_on_host": "true", "high_level_alert_on_host": "true"}
    assert set(indicator_states(skill, []).values()) == {"unknown"}
