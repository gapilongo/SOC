"""The corpus telemetry as the evidence backend of a run (AI-E3.3): chosen by configuration, never silently."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple

import pytest

from lg_sotf.core.workflow import evidence_backends
from lg_sotf.db.errors import NotFound
from lg_sotf.errors import WorkflowError
from lg_sotf.eval.tool_fixtures import event_time, load_documents
from lg_sotf.eval.wazuh_events import MAX_SHIFTED_STORES, TelemetryBackends, telemetry_backends
from lg_sotf.ingestion.wazuh_indexer import WazuhIndexers
from lg_sotf.settings import Settings
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from lg_sotf.tools.wazuh.tools import HOST_ACTIVITY
from tests.unit.tools._support import Ctx
from tests.unit.tools._support import Settings as TenantTools
from tests.unit.tools.wazuh._support import EVAL, FILES, corpus, over

pytestmark = pytest.mark.unit

DATASET, EVENTS, _ = FILES["corpus_v1"]
ITEM = "cv1-0113"


def documents() -> List[Any]:
    return load_documents(EVAL / DATASET, EVAL / EVENTS)


class Alerts:
    """Stored alerts by (tenant, alert): one tenant never reads another's."""

    def __init__(self) -> None:
        self.rows: Dict[Tuple[str, str], Any] = {}
        self.reads: List[Tuple[str, str]] = []

    def add(self, tenant_id: str, alert_id: str, source_alert_id: str, occurred_at: datetime) -> None:
        self.rows[(tenant_id, alert_id)] = SimpleNamespace(source_alert_id=source_alert_id, occurred_at=occurred_at)

    async def get(self, tenant_id: str, alert_id: str, *, conn: Any = None) -> Any:
        self.reads.append((tenant_id, alert_id))
        if (tenant_id, alert_id) not in self.rows:
            raise NotFound("alert", alert_id)
        return self.rows[(tenant_id, alert_id)]


def ctx(alerts: Alerts, tenant_id: str = "t1", alert_id: str = "a1") -> Ctx:
    return Ctx(tenant_id=tenant_id, alert_id=alert_id, repos=SimpleNamespace(alerts=alerts))


async def host_activity(backends: TelemetryBackends, context: Ctx, host: str, at: datetime) -> Any:
    tools = over(await backends(context), settings=TenantTools({"wazuh_indexer": {"enabled": True}}))
    result = await tools.call(context, HOST_ACTIVITY, {"host": host, "at": at, "before_min": 60, "after_min": 0}, agent="t")
    assert result.outcome == "success", result.value.error
    return result.value[0]


async def test_the_store_answers_as_of_the_alerts_own_time() -> None:
    document = corpus("corpus_v1").items[ITEM].alert
    at, alerts = event_time(document), Alerts()
    alerts.add("t1", "a1", str(document["id"]), at)
    backends = TelemetryBackends(documents())

    backend = await backends(ctx(alerts))

    assert backend.now() == at and backend.lag == timedelta(0) and alerts.reads == [("t1", "a1")]
    fact = await host_activity(backends, ctx(alerts), document["agent"]["name"], at)
    assert fact.value.window_end == at and fact.value.total >= 1
    assert max(event.at for event in fact.value.events) <= at  # nothing later than the alert is ever seen


async def test_an_alert_re_sent_at_another_time_takes_its_telemetry_with_it() -> None:
    """Development: the corpus alert arrives now, its id marked ``-<digits>``. The store moves by the same amount."""
    document = corpus("corpus_v1").items[ITEM].alert
    original, now = event_time(document), datetime(2026, 11, 15, 9, 30, 0, 250_000, tzinfo=UTC)
    alerts = Alerts()
    alerts.add("t1", "then", str(document["id"]), original)
    alerts.add("t1", "now", f"{document['id']}-1731663000250", now)
    backends = TelemetryBackends(documents())

    assert (await backends(ctx(alerts, alert_id="now"))).now() == now
    then = await host_activity(backends, ctx(alerts, alert_id="then"), document["agent"]["name"], original)
    moved = await host_activity(backends, ctx(alerts, alert_id="now"), document["agent"]["name"], now)
    assert moved.value.window_end == now and moved.value.total == then.value.total
    assert moved.value.by_group == then.value.by_group and moved.value.techniques == then.value.techniques
    assert [e.at - now for e in moved.value.events] == [e.at - original for e in then.value.events]


async def test_an_alert_the_dataset_does_not_hold_has_no_telemetry_and_no_tenant_reads_anothers() -> None:
    document = corpus("corpus_v1").items[ITEM].alert
    alerts = Alerts()
    alerts.add("t1", "a1", str(document["id"]), event_time(document))
    alerts.add("t1", "unknown", "not-a-corpus-document", event_time(document))
    alerts.add("t1", "lookalike", f"{document['id']}-suffix", event_time(document))
    backends = TelemetryBackends(documents())
    for context in (ctx(alerts, alert_id="unknown"), ctx(alerts, alert_id="lookalike"), ctx(alerts, tenant_id="t2")):
        with pytest.raises(IndexerUnavailable) as refused:
            await backends(context)
        assert refused.value.reason == "no_telemetry"
    assert ("t2", "a1") in alerts.reads and ("t1", "a1") not in alerts.reads  # asked under its own tenant only
    with pytest.raises(IndexerUnavailable) as unset:
        await backends(Ctx(repos=None))
    assert unset.value.reason == "not_configured"


async def test_only_a_few_moved_copies_are_kept() -> None:
    document = corpus("corpus_v1").items[ITEM].alert
    alerts, backends = Alerts(), TelemetryBackends(documents()[:40] + [document])
    for n in range(MAX_SHIFTED_STORES + 5):
        alerts.add("t1", f"a{n}", f"{document['id']}-{n}", event_time(document) + timedelta(days=n + 1))
        await backends(ctx(alerts, alert_id=f"a{n}"))
    assert len(backends._stores) == MAX_SHIFTED_STORES and timedelta(0) in backends._stores


def test_the_backend_is_named_by_the_settings_and_never_guessed(make_settings: Callable[..., Settings]) -> None:
    default = make_settings()
    assert default.investigation.evidence_backend == "indexer" and telemetry_backends(default) is None
    assert isinstance(evidence_backends(default, None, None), WazuhIndexers)
    store = {"evidence_backend": "event_store", "event_store_files": [str(EVAL / DATASET), str(EVAL / EVENTS)]}
    offline = make_settings(investigation=store)
    built = telemetry_backends(offline)
    assert isinstance(built, TelemetryBackends) and len(built) == len(documents()) > 700
    assert evidence_backends(offline, None, built) is built
    # Asked for the event store and not given one: the process does not start (it never falls back to an indexer).
    with pytest.raises(WorkflowError, match="evidence_backend=event_store"):
        evidence_backends(offline, None, None)
    with pytest.raises(OSError):
        telemetry_backends(make_settings(investigation={**store, "event_store_files": ["/nonexistent/corpus.jsonl.gz"]}))
    with pytest.raises(ValueError, match="evaluation and development only"):
        telemetry_backends(make_settings(environment="staging", investigation=store))
