"""Review probes for PR #433 (INT3.4). Each test states the secure expectation; a failure is a finding.

The reviewer's file, unchanged but for two probes. ``p10`` and ``p11`` call ``wazuh.logon_fanout`` with
``outcomes`` and ``logon_types``. The fix removed both parameters (a caller cannot narrow a fan-out at
all), so those calls are now refused before anything is read. As in ``p8``, the refusal is the secure
outcome: each of the two probes accepts it, and keeps its original assertions for a call that is answered.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping

import httpx
import pytest

from lg_sotf.eval.tool_fixtures import EventStore
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.net.egress import DestinationPolicy
from lg_sotf.security.redaction import redact_text
from lg_sotf.tools.registry import ToolParamsInvalid
from lg_sotf.tools.wazuh import templates
from lg_sotf.tools.wazuh.indexer import IndexerClient, IndexerUnavailable
from lg_sotf.tools.wazuh.templates import HostActivityParams
from lg_sotf.tools.wazuh.tools import HOST_ACTIVITY, LOGON_FANOUT
from tests.unit.ingestion._support import public_resolver
from tests.unit.tools._support import Ctx
from tests.unit.tools.wazuh._support import Investigation, minutes, over

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
SYSMON = {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"}


def _doc(n: int, at: datetime, agent: str = "SRV-01", system: Mapping[str, str] = SYSMON, **eventdata: str) -> Dict[str, Any]:
    stamp = at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"
    return {
        "id": f"1790000000.{n}", "timestamp": stamp, "agent": {"name": agent},
        "rule": {"id": "100100", "level": 3, "groups": ["windows"], "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": dict(system), "eventdata": eventdata}},
    }


OLD = _doc(10_000, T0 - timedelta(days=40), agent="OLD-01")


def guid(n: int) -> str:
    return "{" + f"{n:08d}" + "-aaaa-bbbb-cccc-dddddddddddd}"


class Shards:
    """The store as an indexer whose answer carries the given ``_shards`` header."""

    lag = timedelta(0)

    def __init__(self, store: EventStore, as_of: datetime, shards: Mapping[str, int]) -> None:
        self._inner, self._as_of, self._shards = EventStoreBackend(store.as_of(as_of)), as_of, dict(shards)

    def now(self) -> datetime:
        return self._as_of

    async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return {**dict(await self._inner.search(body)), "_shards": self._shards}


async def test_p1_unassigned_shards_are_never_a_complete_answer() -> None:
    """OpenSearch: unallocated shards are neither successful nor failed (successful < total, failed == 0)."""
    store = EventStore([OLD, *(_doc(n, T0 + timedelta(seconds=n)) for n in range(3))])
    backend = Shards(store, T0 + minutes(30), {"total": 5, "successful": 3, "skipped": 0, "failed": 0})
    tools = over(backend)
    nothing = await tools.call(Ctx(), HOST_ACTIVITY, {"host": "QUIET-01", "at": T0, "before_min": 5, "after_min": 5}, agent="a")
    assert (nothing.outcome, nothing.complete) != ("empty", True), "two of five shards were not searched"
    some = await tools.call(Ctx(), HOST_ACTIVITY, {"host": "SRV-01", "at": T0, "before_min": 5, "after_min": 5}, agent="a")
    assert some.complete is False


async def test_p2_an_answer_without_the_asked_aggregation_is_failed() -> None:
    class NoAggs:
        lag = timedelta(0)

        def now(self) -> datetime:
            return T0 + minutes(30)

        async def search(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
            return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {"hits": []}}

    result = await over(NoAggs()).call(
        Ctx(), LOGON_FANOUT, {"pivot": "target_user", "value": "ann", "at": T0, "before_min": 30}, agent="a")
    assert result.outcome == "failed", (result.outcome, result.complete)


async def test_p3_an_ancestor_beyond_the_depth_cap_is_not_a_complete_chain() -> None:
    """winword -> 10 nested cmd -> powershell: the Office ancestor is above the 8 look-ups."""
    docs = [OLD]
    images = ["C:\\\\Office\\\\WINWORD.EXE", *["C:\\\\Windows\\\\cmd.exe"] * 10, "C:\\\\Windows\\\\powershell.exe"]
    for n in range(1, len(images)):
        docs.append(_doc(n, T0 + timedelta(seconds=n), image=images[n], processGuid=guid(n), processId=str(100 + n),
                         parentProcessGuid=guid(n - 1), parentImage=images[n - 1], parentProcessId=str(99 + n)))
    look = Investigation(EventStore(docs), T0 + minutes(30))
    fact = await look.fact("process_lineage", host="SRV-01", process_guid=guid(len(images) - 1), at=T0, after_min=10, depth=8)
    assert fact is not None
    names = [node.image_name for node in fact.value.chain]
    assert "WINWORD.EXE" in names or fact.complete is False, (names, fact.complete)


async def test_p4_a_decoy_process_with_the_same_image_does_not_give_a_complete_chain() -> None:
    """Two powershell.exe in the window: the decoy (from explorer) started first, the alert's (from winword) second."""
    ps = "C:\\\\Windows\\\\powershell.exe"
    docs = [
        OLD,
        _doc(1, T0 - timedelta(seconds=3), image=ps, processGuid=guid(11), parentProcessGuid=guid(10),
             parentImage="C:\\\\Windows\\\\explorer.exe"),
        _doc(2, T0, image=ps, processGuid=guid(21), parentProcessGuid=guid(20), parentImage="C:\\\\Office\\\\WINWORD.EXE"),
    ]
    look = Investigation(EventStore(docs), T0 + minutes(30))
    fact = await look.fact("process_lineage", host="SRV-01", image="C:\\Windows\\powershell.exe", at=T0, after_min=10)
    assert fact is not None
    names = [node.image_name for node in fact.value.chain]
    assert "WINWORD.EXE" in names or fact.complete is False, (names, fact.complete)


async def test_p5_failures_typed_in_another_case_are_counted_for_the_user() -> None:
    """Windows logs TargetUserName as the client typed it; the account is the same one."""
    logon = {"providerName": "Microsoft-Windows-Security-Auditing"}
    docs = [OLD]
    for n in range(20):
        docs.append(_doc(n, T0 - timedelta(minutes=10) + timedelta(seconds=n), system={**logon, "eventID": "4625"},
                         targetUserName="ADMINISTRATOR" if n % 2 else "Administrator", ipAddress="203.0.113.9", logonType="3"))
    docs.append(_doc(99, T0, system={**logon, "eventID": "4624"}, targetUserName="administrator", ipAddress="203.0.113.9",
                     logonType="3"))
    look = Investigation(EventStore(docs), T0 + minutes(30))
    fact = await look.fact("logon_fanout", pivot="target_user", value="administrator", at=T0, before_min=30)
    assert fact is not None
    assert fact.value.failures == 20 or fact.complete is False, (fact.value.failures, fact.value.successes, fact.complete)


async def test_p6_a_logon_event_id_from_another_provider_is_not_a_logon() -> None:
    docs = [OLD, _doc(1, T0 - minutes(1), system={"eventID": "4624", "providerName": "AttackerApp"},
                      targetUserName="ann", ipAddress="10.0.0.5", logonType="2")]
    look = Investigation(EventStore(docs), T0 + minutes(30))
    result = await look.call("logon_fanout", pivot="target_user", value="ann", at=T0, before_min=30)
    assert result.outcome == "empty", [f.value.successes for f in result.value]


def _spray() -> EventStore:
    """20 network failures (4625), 5 Kerberos failures (4771, no logon type), one lockout, then a success."""
    logon = {"providerName": "Microsoft-Windows-Security-Auditing"}
    docs = [OLD]
    for n in range(20):
        docs.append(_doc(n, T0 - minutes(10) + timedelta(seconds=n), system={**logon, "eventID": "4625"},
                         targetUserName="ann", ipAddress="203.0.113.9", logonType="3"))
    for n in range(20, 25):
        docs.append(_doc(n, T0 - minutes(9) + timedelta(seconds=n), system={**logon, "eventID": "4771"},
                         targetUserName="ann", ipAddress="203.0.113.9"))
    docs.append(_doc(30, T0 - minutes(8), system={**logon, "eventID": "4740"}, targetUserName="ann"))
    docs.append(_doc(31, T0, system={**logon, "eventID": "4624"}, targetUserName="ann", ipAddress="203.0.113.9", logonType="10"))
    return EventStore(docs)


async def test_p10_a_fact_read_with_a_filter_does_not_say_zero_for_what_it_did_not_read() -> None:
    """``outcomes`` and ``logon_types`` narrow the search; the fact has no field that says so."""
    look = Investigation(_spray(), T0 + minutes(30))
    base = {"pivot": "target_user", "value": "ann", "at": T0, "before_min": 30}
    everything = await look.fact("logon_fanout", **base)
    assert everything is not None and (everything.value.failures, everything.value.lockouts) == (25, 1)
    try:
        only_success = await look.fact("logon_fanout", **base, outcomes=["success"])
    except ToolParamsInvalid:  # the filter is not a parameter any more: nothing can be read with it
        return
    assert only_success is not None
    told = only_success.value.model_dump()
    assert only_success.value.failures != 0 or only_success.complete is False or "outcomes" in told, (
        only_success.value.failures, only_success.value.lockouts, only_success.complete)


async def test_p11_a_logon_type_filter_does_not_hide_lockouts_and_kerberos_failures() -> None:
    look = Investigation(_spray(), T0 + minutes(30))
    try:
        fact = await look.fact("logon_fanout", pivot="target_user", value="ann", at=T0, before_min=30, logon_types=["10"])
    except ToolParamsInvalid:  # the filter is not a parameter any more: nothing can be read with it
        everything = await look.fact("logon_fanout", pivot="target_user", value="ann", at=T0, before_min=30)
        assert everything is not None and (everything.value.lockouts, everything.value.failures) == (1, 25)
        return
    assert fact is not None
    assert (fact.value.lockouts == 1 and fact.value.failures >= 5) or fact.complete is False, (
        fact.value.failures, fact.value.lockouts, fact.value.successes, fact.complete)


@pytest.mark.parametrize(
    "line",
    [
        "net user backup S3cr3t-Pa55w0rd! /add",
        "psexec \\\\dc01 -u CORP\\admin -p S3cr3t-Pa55w0rd! cmd.exe",
        "mysql -u root -pS3cr3t-Pa55w0rd! prod",
        "curl -u admin:S3cr3t-Pa55w0rd! https://intranet.example/api",
        "schtasks /create /tn x /tr y /ru CORP\\svc /rp S3cr3t-Pa55w0rd!",
        "myapp.exe --password S3cr3t-Pa55w0rd! --run",
        "sqlcmd -S db01 -U sa -P S3cr3t-Pa55w0rd!",
        "wmic /user:admin /password:S3cr3t-Pa55w0rd! process call create x",
        "cmdkey /add:srv /user:admin /pass:S3cr3t-Pa55w0rd!",
        "powershell -c ConvertTo-SecureString 'S3cr3t-Pa55w0rd!' -AsPlainText -Force",
    ],
)
def test_p7_a_password_on_a_command_line_is_masked(line: str) -> None:
    text, masked = redact_text(line)
    assert "S3cr3t-Pa55w0rd!" not in text, (text, masked)


EMPTY = {"timed_out": False, "_shards": {"total": 1, "failed": 0}, "hits": {"hits": []},
         "aggregations": {"total": {"value": 0}, "oldest": {"value": 1.7e12}}}
BODY = templates.host_activity(HostActivityParams(host="SRV-01", at=T0, before_min=5, after_min=5))


def _client(seen: List[httpx.Request], status: int = 200, **overrides: Any) -> IndexerClient:
    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=EMPTY)

    settings: Dict[str, Any] = {
        "base_url": "https://indexer.customer.example:9200", "index": "wazuh-alerts-*", "username": "reader",
        "password": "test-only-pppppppppppp", "policy": DestinationPolicy(require_https=True),
        "transport": httpx.MockTransport(server), "resolver": public_resolver, "now": lambda: T0 + timedelta(hours=1),
    }
    return IndexerClient(**{**settings, **overrides})


@pytest.mark.parametrize(
    "base_url",
    [
        "https://indexer.customer.example:9200/_all/_delete_by_query?q=",
        "https://indexer.customer.example:9200/_msearch?x=",
        "https://indexer.customer.example:9200/other-index/_update_by_query#",
    ],
)
async def test_p8_the_base_url_cannot_choose_the_endpoint(base_url: str) -> None:
    seen: List[httpx.Request] = []
    try:
        client = _client(seen, base_url=base_url)
        await client.search(BODY)
    except Exception:  # noqa: BLE001 - a refusal of any kind is the secure outcome
        return
    assert [request.url.path for request in seen] == ["/wazuh-alerts-*/_search"], [str(r.url) for r in seen]


@pytest.mark.parametrize("status", [204, 206, 301, 302, 304])
async def test_p9_only_a_200_is_an_answer(status: int) -> None:
    seen: List[httpx.Request] = []
    with pytest.raises(IndexerUnavailable):
        await _client(seen, status).search(BODY)
