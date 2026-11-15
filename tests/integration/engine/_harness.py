"""Shared by the investigation-harness engine tests: corpus alerts ingested as Wazuh alerts, evidence backends."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.agents.registry import AgentSet
from lg_sotf.db.pool import Database
from lg_sotf.db.repos import Repositories
from lg_sotf.eval.dataset import EvalItem
from lg_sotf.eval.tool_fixtures import load_documents
from lg_sotf.eval.wazuh_events import EventStoreBackend, TelemetryBackends
from lg_sotf.ingestion.service import IngestionService
from lg_sotf.llm.fake import ScriptedChatModel
from lg_sotf.settings import Settings
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from tests.integration.db._support import TENANT_A
from tests.unit.agents._support import factory, scripted
from tests.unit.tools.wazuh._support import EVAL, FILES, corpus

SWITCH_ON = {"tools": {"wazuh_indexer": {"enabled": True}}}
WAZUH_PUSH = "wazuh-push"
#: PsExec from a workstation, then discovery under the service: host activity and prevalence answer.
SERVICE_INSTALL = "cv1-0113"
#: A Windows logon failure that names the account and the source address: host activity and both logon pivots answer.
LOGON = "cv1-0003"


def item(item_id: str = LOGON) -> EvalItem:
    return corpus("corpus_v1").items[item_id]


def telemetry() -> TelemetryBackends:
    """The corpus telemetry as the evidence backend (what ``investigation.evidence_backend: event_store`` builds)."""
    dataset, events, _ = FILES["corpus_v1"]
    return TelemetryBackends(load_documents(EVAL / dataset, EVAL / events))


async def switch_on(repos: Repositories, tenant_id: str = TENANT_A, **investigation: Any) -> None:
    """Turn the harness on for the tenant, with budget overrides when given."""
    patch: Dict[str, Any] = dict(SWITCH_ON)
    if investigation:
        patch["investigation"] = {"budget": investigation}
    await repos.tenants.update_settings(tenant_id, patch)


async def wazuh_alert(
    db: Database, repos: Repositories, settings: Settings, document: Mapping[str, Any], tenant_id: str = TENANT_A
) -> str:
    """``document`` ingested as production ingests a pushed Wazuh alert (the real normalizer); the alert's id."""
    try:
        await repos.sources.get(tenant_id, WAZUH_PUSH)
    except Exception:  # noqa: BLE001 - the source does not exist yet
        await repos.sources.create(tenant_id, "webhook", "Wazuh (push)", source_id=WAZUH_PUSH, config={"format": "wazuh"})
    service = IngestionService(db, settings)
    try:
        result = await service.ingest(tenant_id, WAZUH_PUSH, [dict(document)])
    finally:
        await service.close()
    outcome = result.items[0]
    assert outcome.status == "inserted" and outcome.alert_id is not None, (outcome.status, outcome.reason)
    return outcome.alert_id


def scripted_agents(settings: Settings, evidence: Any, model: Optional[ScriptedChatModel] = None) -> AgentSet:
    """The agents on a scripted model (its ``calls`` show every prompt), with ``evidence`` behind the tools."""
    return AgentSet.build(settings, model_factory=factory(model or scripted()), evidence=evidence)


class Unreachable:
    """An evidence resolver whose indexer never answers."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, ctx: Any) -> Any:
        self.calls += 1
        raise IndexerUnavailable("unreachable")


class Crash(BaseException):
    """The process dying inside a node: nothing between the tool and the engine catches it."""


class Counting:
    """The corpus telemetry, counting the searches of each run and able to die on the nth one."""

    def __init__(self, crash_on_resolve: Optional[int] = None) -> None:
        self._inner = telemetry()
        self.resolved: List[str] = []
        self.crash_on_resolve = crash_on_resolve

    async def __call__(self, ctx: Any) -> EventStoreBackend:
        self.resolved.append(ctx.alert_id)
        if self.crash_on_resolve is not None and len(self.resolved) == self.crash_on_resolve:
            self.crash_on_resolve = None
            raise Crash("the worker died between two tool calls")
        return await self._inner(ctx)


def moved(document: Mapping[str, Any], to: datetime, suffix: str = "-1731600000000") -> Dict[str, Any]:
    """``document`` as the development sender re-sends it: at another time, its id marked with a suffix."""
    stamp = to.strftime("%Y-%m-%dT%H:%M:%S.") + f"{to.microsecond // 1000:03d}"
    return {**document, "timestamp": stamp + "+0000", "@timestamp": stamp + "Z", "id": f"{document['id']}{suffix}"}


def minutes(count: float) -> timedelta:
    return timedelta(minutes=count)
