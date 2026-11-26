"""Shared by the tests of the deep analysis with evidence: a small Wazuh index, the agent on it, a prompt block."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from lg_sotf.agents.analysis.base import AnalysisAgent, AnalysisResult
from lg_sotf.agents.base import AgentContext
from lg_sotf.eval.tool_fixtures import EventStore
from lg_sotf.eval.wazuh_events import EventStoreBackend
from lg_sotf.llm.fake import ScriptedCall, ScriptedChatModel
from lg_sotf.settings import Settings
from lg_sotf.tools.enrichment import EnrichmentService
from lg_sotf.tools.wazuh.indexer import IndexerUnavailable
from tests.unit.agents._support import factory, fake_repos, texts
from tests.unit.agents.investigation._executor import HOSTILE, RUN_ID
from tests.unit.agents.investigation._support import MemoryStore

AT = datetime(2026, 10, 19, 7, 28, 1, tzinfo=UTC)
SWITCH_ON = {"t1": {"tools": {"wazuh_indexer": {"enabled": True}}}}
TRIAGE = {"confidence": 60, "rule_fp": [], "rule_tp": ["failed_logon"]}
CORRELATION = {"score": 40, "related_count": 1}
VERDICT = {"threat_score": 20, "certainty": 80, "verdict": "benign", "conclusion": "A mistyped password.", "recommended_actions": []}


def stamp(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}+0000"


def logon(event_id: str, minutes_before: int, *, user: str = "j.doe", doc_id: str = "1") -> Dict[str, Any]:
    """A Windows logon document (4625 failure, 4624 success) on FIN-SRV-02 from 10.20.1.83."""
    failure = event_id == "4625"
    return {
        "timestamp": stamp(AT - timedelta(minutes=minutes_before)), "id": f"1792394881.{doc_id}",
        "rule": {"id": "60122" if failure else "60106", "level": 5 if failure else 3,
                 "groups": ["windows", "authentication_failed" if failure else "authentication_success"],
                 "mitre": {"id": ["T1531"] if failure else ["T1078"]}},
        "agent": {"name": "FIN-SRV-02"},
        "data": {"win": {"system": {"eventID": event_id, "providerName": "Microsoft-Windows-Security-Auditing"},
                         "eventdata": {"targetUserName": user, "ipAddress": "10.20.1.83", "logonType": "3"}}},
    }


THE_ALERT = logon("4625", 0, doc_id="100")
QUIET = [logon("4624", 30, doc_id="50"), logon("4625", 1, doc_id="99"), THE_ALERT]
# A failed logon for a "user name" the attacker typed: it lands in typed fact fields (a user of an event, a failed user).
POISONED = [*QUIET, logon("4625", 2, user=HOSTILE, doc_id="98")]


def state_alert(document: Mapping[str, Any] = THE_ALERT) -> Dict[str, Any]:
    return {
        "id": "alert-0001", "title": "Logon failure - unknown user or bad password", "severity": "low",
        "category": "authentication_failed", "source_id": "wazuh-push", "occurred_at": AT.isoformat(),
        "normalizer": "wazuh", "entities": {"hosts": ["FIN-SRV-02"], "users": ["j.doe"], "ips": ["10.20.1.83"]},
        "raw": dict(document),
    }


def evidence_of(documents: List[Dict[str, Any]]) -> Any:
    return evidence_of_at(documents, AT)


def evidence_of_at(documents: List[Dict[str, Any]], now: Any) -> Any:
    """The index as it stood at ``now``: at the alert's own time its windows are still open (incomplete facts)."""
    backend = EventStoreBackend(EventStore(documents).as_of(now))

    async def backends(ctx: Any) -> EventStoreBackend:
        return backend

    return backends


async def unreachable(ctx: Any) -> Any:
    raise IndexerUnavailable("unreachable")


async def analyse(
    settings: Settings, model: ScriptedChatModel, evidence: Any, *, tenants: Optional[Dict[str, Any]] = None,
    enrichment: Optional[EnrichmentService] = None, store: Optional[MemoryStore] = None,
) -> AnalysisResult:
    repos = fake_repos(tenant_settings=SWITCH_ON if tenants is None else tenants)
    repos.evidence_facts = store or MemoryStore()
    agent = AnalysisAgent(settings=settings, model_factory=factory(model), evidence=evidence, enrichment=enrichment)
    ctx = AgentContext("t1", "a1", settings, repos=repos, investigation_run_id=RUN_ID)
    return await agent.run(ctx, state_alert(), triage=TRIAGE, correlation=CORRELATION)


def block(call: ScriptedCall, tag: str) -> str:
    """The body of the one ``<tag>`` block of the call."""
    (body,) = re.findall(rf"<{tag}>\n(.*?)\n</{tag}>", "\n".join(texts(call.messages)), re.DOTALL)
    return str(body)
