"""The Wazuh evidence tools against a real Wazuh 4.14 indexer (INT3.4).

The corpus telemetry (``corpus_v1`` and its context events) is indexed with the template Wazuh publishes
for 4.14 and read by the production path: the tool registry, the source resolver
(:class:`lg_sotf.ingestion.wazuh_indexer.WazuhIndexers`), the indexer client with TLS verified against
the lab CA and pinned by the destination policy, as the least-privilege reader. The facts must be the
ones the offline event store gives for the same calls: the templates mean the same thing to OpenSearch as
to the store the unit tests and the evaluation run on.

Skipped unless ``LG_SOTF_TEST_WAZUH_ADDRESS`` is set (``make test-wazuh``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

import pytest

from lg_sotf.eval.dataset import load_dataset
from lg_sotf.eval.tool_fixtures import EventQuery, EventStore, event_time, field_values
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.ingestion.sources import ConnectorDeps, encrypt_source_secret
from lg_sotf.ingestion.wazuh_indexer import WazuhIndexers
from lg_sotf.security.crypto import SecretBox
from lg_sotf.settings import Settings
from lg_sotf.tools.registry import ToolParamsInvalid, ToolRegistry, ToolResult
from lg_sotf.tools.wazuh.tools import Evidence, wazuh_tools
from tests.fixtures.wazuh_lab import INDEX_PREFIX, WazuhLab
from tests.live.wazuh._support import SKIP_REASON, Lab, lab_address
from tests.unit.ingestion._support import make_source
from tests.unit.tools._support import Ctx, registry
from tests.unit.tools.wazuh._support import fake_secret, words

pytestmark = [pytest.mark.live, pytest.mark.skipif(lab_address() is None, reason=SKIP_REASON)]

EVAL = Path(__file__).resolve().parents[2] / "fixtures" / "eval"
ED = "data.win.eventdata."
PSEXESVC = "C:\\Windows\\PSEXESVC.exe"
TYPED = fake_secret(5)  # what a command line carries after a password flag: masked before it reaches a fact
Call = Tuple[str, Dict[str, Any]]
Credentials = Dict[str, str]


@pytest.fixture(scope="module")
def store() -> EventStore:
    return EventStore.load(EVAL / "corpus_v1.jsonl.gz", EVAL / "corpus_v1_events.jsonl.gz")


@pytest.fixture(scope="module")
def items() -> Dict[str, Any]:
    return {item.id: item for item in load_dataset(EVAL / "corpus_v1.jsonl.gz").items}


def everything(store: EventStore) -> List[Dict[str, Any]]:
    return store.as_of(datetime(2100, 1, 1, tzinfo=UTC)).select(EventQuery())


@pytest.fixture
def second_index(lab_admin: WazuhLab) -> Iterator[str]:
    index = f"{INDEX_PREFIX}lgsotf-{uuid.uuid4().hex[:12]}"
    yield index
    lab_admin.delete_index(index)


class Tenant:
    """One tenant's run against the lab: its Wazuh source (index, credentials), resolved as production resolves it."""

    def __init__(
        self, lab: Lab, settings: Settings, index: str, credentials: Credentials, now: datetime, tenant: str = "tenant-a"
    ) -> None:
        with open(lab.ca_file, encoding="utf-8") as fh:
            config = {"base_url": lab.base_url, "ca_cert_pem": fh.read(), "index": index, "max_event_lag_s": 0}
        box = SecretBox.from_settings(settings)
        source = make_source("wazuh", config, tenant_id=tenant, secret_ciphertext=encrypt_source_secret(box, tenant, "src-1", credentials))

        async def alert(tenant_id: str, alert_id: str, **kwargs: Any) -> Any:
            assert (tenant_id, alert_id) == (tenant, "a1")
            return SimpleNamespace(id=alert_id, source_id=source.id)

        async def get_source(tenant_id: str, source_id: str, **kwargs: Any) -> Any:
            assert (tenant_id, source_id) == (tenant, source.id)
            return source

        repos = SimpleNamespace(alerts=SimpleNamespace(get=alert), sources=SimpleNamespace(get=get_source))
        self.ctx = Ctx(tenant_id=tenant, alert_id="a1", repos=repos)
        self.indexers = WazuhIndexers(settings, box, deps=ConnectorDeps(resolver=lab.resolve, now=lambda: now))
        self.tools: ToolRegistry = registry(*wazuh_tools(self.indexers))

    async def call(self, tool: str, params: Mapping[str, Any]) -> ToolResult[Evidence]:
        return await self.tools.call(self.ctx, tool, params, agent="investigation")


def offline(store: EventStore, now: datetime) -> ToolRegistry:
    async def backends(ctx: Any) -> EventStoreBackend:
        return EventStoreBackend(store.as_of(now))

    return registry(*wazuh_tools(backends))


def eventdata(alert: Mapping[str, Any], name: str) -> str:
    found = field_values(alert, ED + name)
    return found[0].replace("\\\\", "\\") if found else ""


def calls_for(item: Any, digest: str) -> List[Call]:
    """What an investigation of ``item`` asks, with every window closed 15 minutes after the alert."""
    alert, at, host = item.alert, event_time(item.alert), str(item.alert["agent"]["name"])
    asked: List[Call] = [
        ("wazuh.host_activity", {"host": host, "at": at, "before_min": 30, "after_min": 15}),
        ("wazuh.host_activity", {"host": "NO-SUCH-HOST", "at": at, "before_min": 30, "after_min": 15}),
        ("wazuh.logon_fanout", {"pivot": "target_host", "value": host, "at": at, "before_min": 15, "after_min": 1}),
        ("wazuh.logon_fanout", {"pivot": "target_host", "value": host, "at": at, "before_min": 1_440, "after_min": 15}),
        # A host or user name typed in another case is the same name (the term's case_insensitive option).
        ("wazuh.logon_fanout", {"pivot": "target_host", "value": host.swapcase(), "at": at, "before_min": 1_440, "after_min": 15}),
        ("wazuh.process_lineage", {"host": host, "image": PSEXESVC, "at": at, "after_min": 15}),
        ("wazuh.prevalence", {"kind": "process_image", "value": PSEXESVC, "days": 30}),
        ("wazuh.prevalence", {"kind": "service_name", "value": "PSEXESVC", "days": 20}),
        ("wazuh.prevalence", {"kind": "sha256", "value": digest, "days": 20}),
        ("wazuh.prevalence", {"kind": "service_name", "value": "*", "days": 30}),
    ]
    user, ip, workstation = (eventdata(alert, name) for name in ("targetUserName", "ipAddress", "workstationName"))
    if ip:
        asked += [("wazuh.logon_fanout", {"pivot": "source_ip", "value": ip, "at": at, "before_min": before, "after_min": 10})
                  for before in (30, 1_440)]
    if user:
        asked += [("wazuh.logon_fanout", {"pivot": "target_user", "value": name, "at": at, "before_min": 1_440, "after_min": 10})
                  for name in (user, user.upper())]
    if workstation:
        asked += [("wazuh.logon_fanout", {"pivot": "source_host", "value": name, "at": at, "before_min": 1_440, "after_min": 10})
                  for name in (workstation, workstation.lower())]
    if eventdata(alert, "imagePath"):
        asked.append(("wazuh.prevalence", {"kind": "service_image_path", "value": eventdata(alert, "imagePath"), "days": 30}))
    if eventdata(alert, "parentProcessGuid"):
        asked.append(("wazuh.process_lineage", {"host": host, "process_guid": eventdata(alert, "parentProcessGuid"), "at": at, "after_min": 15}))
    return asked


async def test_templates_return_the_fixture_facts(
    lab: Lab, lab_admin: WazuhLab, lab_settings: Settings, reader: Credentials, alert_index: str, store: EventStore,
    items: Dict[str, Any],
) -> None:
    docs = everything(store)
    assert lab_admin.load(docs, alert_index) == (len(docs), [])
    digest = next(d["syscheck"]["sha256_after"] for d in docs if d.get("syscheck", {}).get("sha256_after"))
    typo = next(i for i in items.values() if "scenario:noise:logon-typo" in i.tags)
    psexec_child = next(i for i in items.values() if i.alert["rule"]["id"] == "92068")
    chosen = [items["cv1-0021"], items["cv1-0113"], items["cv1-0069"], items["cv1-0057"], typo, psexec_child]
    ssh = next(i for i in items.values() if "invalid_login" in i.alert["rule"]["groups"] and i.alert["decoder"]["name"] == "sshd")
    ssh_logons = [("wazuh.logon_fanout", {"pivot": pivot, "value": value, "at": event_time(ssh.alert), "before_min": 1_440,
                                          "after_min": 10, "family": "sshd"})
                  for pivot, value in (("source_ip", ssh.alert["data"]["srcip"]), ("target_host", ssh.alert["agent"]["name"]))]
    outcomes: Dict[str, int] = {}
    for item in [*chosen, ssh]:
        now = event_time(item.alert) + timedelta(minutes=15)
        tenant, reference = Tenant(lab, lab_settings, alert_index, reader, now), offline(store, now)
        for tool, params in ssh_logons if item is ssh else calls_for(item, digest):
            live = await tenant.call(tool, params)
            expected = await reference.call(Ctx(), tool, params, agent="investigation")
            assert live.value.error is None, (item.id, tool, live.value.error)
            assert (live.outcome, live.complete, live.rows) == (expected.outcome, expected.complete, expected.rows), (item.id, tool, params)
            assert [f.model_dump() for f in live.value] == [f.model_dump() for f in expected.value], (item.id, tool, params)
            outcomes[f"{tool}:{live.outcome}"] = outcomes.get(f"{tool}:{live.outcome}", 0) + 1
        await tenant.indexers.aclose()
    # Every template answered with facts at least once, and with nothing at least once.
    for tool in ("host_activity", "logon_fanout", "process_lineage", "prevalence"):
        assert outcomes.get(f"wazuh.{tool}:success", 0) >= 3, outcomes
    assert outcomes["wazuh.host_activity:empty"] == len(chosen) and outcomes["wazuh.prevalence:empty"] >= len(chosen)


def _busy_host(count: int, at: datetime) -> List[Dict[str, Any]]:
    return [
        {"id": f"1790000000.{n}", "timestamp": f"{at + timedelta(seconds=n):%Y-%m-%dT%H:%M:%S}.000+0000",
         "agent": {"id": "099", "name": "BUSY-01"}, "manager": {"name": "wazuh-manager"},
         "rule": {"id": "100100", "level": 3 + n % 5, "description": "synthetic", "groups": ["windows", f"group_{n % 7}"]},
         "decoder": {"name": "windows_eventchannel"}, "location": "EventChannel",
         "data": {"win": {"system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                          "eventdata": {"image": "C:\\\\x\\\\busy.exe", "commandLine": words("busy.exe", "=".join(["--password", TYPED]))}}}}
        for n in range(count)
    ]


async def test_a_capped_result_is_cut_the_same_way_and_marked(
    lab: Lab, lab_admin: WazuhLab, lab_settings: Settings, reader: Credentials, alert_index: str,
) -> None:
    at = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
    old = {**_busy_host(1, at - timedelta(days=3))[0], "id": "1789000000.1", "agent": {"id": "098", "name": "OLD-01"}}
    # Two quiet events two minutes before, each with a technique: one of a never-close class, one seen once (issue 452).
    quiet = [{**doc, "id": f"1790000001.{n}", "rule": {**doc["rule"], "level": 3, "mitre": {"id": [technique]}}}
             for n, (doc, technique) in enumerate(zip(_busy_host(2, at - timedelta(minutes=2)), ["T1003.001", "T1140"], strict=True))]
    docs = [old, *_busy_host(60, at), *quiet]
    assert lab_admin.load(docs, alert_index) == (len(docs), [])
    now = at + timedelta(minutes=30)
    params = {"host": "BUSY-01", "at": at, "before_min": 5, "after_min": 5}
    tenant = Tenant(lab, lab_settings, alert_index, reader, now)
    live = await tenant.call("wazuh.host_activity", params)
    expected = await offline(EventStore(docs), now).call(Ctx(), "wazuh.host_activity", params, agent="investigation")
    fact = live.value[0]
    assert (live.outcome, live.complete, fact.complete) == ("success", False, False)
    assert (fact.value.total, len(fact.value.events), fact.value.max_level) == (62, 50, 7)
    # More events than a fact lists: a sample, chosen in parts by the indexer's own searches.
    assert [event.listed_for for event in fact.value.events] == [
        "never_close_class", "rare_technique", *["nearest_in_time"] * 10, *["rule_level"] * 38]
    assert fact.value.never_close_class_truncated is False and fact.value.techniques == ["T1003.001", "T1140"]
    assert [event.level for event in fact.value.events[12:22]] == [7] * 10, "the highest levels fill the rest"
    assert TYPED not in fact.model_dump_json() and fact.redactions[0].reason == "secret"
    assert fact.model_dump() == expected.value[0].model_dump()
    await tenant.indexers.aclose()


async def test_a_second_tenants_index_is_never_read(
    lab: Lab, lab_admin: WazuhLab, lab_settings: Settings, reader: Credentials, alert_index: str, second_index: str,
) -> None:
    at = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
    ours, theirs = _busy_host(3, at), [{**doc, "agent": {"id": "200", "name": "THEIR-01"}} for doc in _busy_host(4, at)]
    assert lab_admin.load(ours, alert_index) == (3, []) and lab_admin.load(theirs, second_index) == (4, [])
    now = at + timedelta(minutes=30)
    a = Tenant(lab, lab_settings, alert_index, reader, now, tenant="tenant-a")
    b = Tenant(lab, lab_settings, second_index, reader, now, tenant="tenant-b")
    seen = {"kind": "process_image", "value": "C:\\x\\busy.exe", "days": 7}
    for tenant, own_host, other_host, events in ((a, "BUSY-01", "THEIR-01", 3), (b, "THEIR-01", "BUSY-01", 4)):
        own = await tenant.call("wazuh.prevalence", seen)
        assert (own.outcome, own.value[0].value.host_count, own.value[0].value.event_count) == ("success", 1, events)
        other = await tenant.call("wazuh.host_activity", {"host": other_host, "at": at, "before_min": 5, "after_min": 5})
        assert (other.outcome, tuple(other.value)) == ("empty", ())
        mine = await tenant.call("wazuh.host_activity", {"host": own_host, "at": at, "before_min": 5, "after_min": 5})
        assert mine.outcome == "success" and mine.value[0].value.total == events
        for stray in ({"index": "wazuh-alerts-*"}, {"index": second_index}, {"tenant_id": "tenant-b"}):
            with pytest.raises(ToolParamsInvalid):
                await tenant.call("wazuh.prevalence", {**seen, **stray})
        await tenant.indexers.aclose()


async def test_a_refusing_or_missing_indexer_is_failed_never_empty(
    lab: Lab, lab_admin: WazuhLab, lab_settings: Settings, reader: Credentials, no_access_user: Credentials, alert_index: str,
) -> None:
    at = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
    assert lab_admin.load(_busy_host(2, at), alert_index) == (2, [])
    now = at + timedelta(minutes=30)
    params = {"host": "BUSY-01", "at": at, "before_min": 5, "after_min": 5}

    async def outcome(index: str, credentials: Credentials) -> Tuple[str, Optional[str], bool]:
        tenant = Tenant(lab, lab_settings, index, credentials, now)
        result = await tenant.call("wazuh.host_activity", params)
        await tenant.indexers.aclose()
        return result.outcome, result.value.error, result.complete

    assert await outcome(alert_index, reader) == ("success", None, False)  # nothing older in the index: not covered
    wrong = {"username": reader["username"], "password": "test-only-wrong-" + uuid.uuid4().hex}
    assert await outcome(alert_index, wrong) == ("failed", "credentials_refused", False)
    assert await outcome(alert_index, no_access_user) == ("failed", "credentials_refused", False)
    assert await outcome(".opendistro_security", reader) == ("failed", "source_misconfigured", False)
    missing = await outcome(f"{INDEX_PREFIX}lgsotf-missing-{uuid.uuid4().hex[:8]}", reader)
    assert missing[0] == "failed" and missing[1] in ("index_not_found", "credentials_refused")
    # A pattern that matches no index searched nothing: that is not "nothing found".
    assert await outcome(f"{INDEX_PREFIX}lgsotf-none-{uuid.uuid4().hex[:8]}-*", reader) == ("failed", "index_not_found", False)
    # The source's host resolves to an address where no indexer answers (TEST-NET-1).
    unreachable = Tenant(Lab("192.0.2.1", lab.ca_file), lab_settings, alert_index, reader, now)
    down = await unreachable.call("wazuh.host_activity", params)
    assert (down.outcome, down.complete) == ("failed", False) and down.value.error in ("unreachable", "timeout")
    await unreachable.indexers.aclose()
