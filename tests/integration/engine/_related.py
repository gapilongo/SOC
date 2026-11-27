"""Helpers of the related-threat engine tests (AI-E3.16): alerts the fake model closes, other stored alerts in a
given state, and the demo's attack chain."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from uuid import UUID

from lg_sotf.db.repos import Repositories
from lg_sotf.ingestion.normalizers import get_normalizer
from lg_sotf.ingestion.normalizers.base import NormalizeContext
from lg_sotf.llm import fake
from lg_sotf.models.vocabulary import POLICY_APPROVER, REQUESTED_BY
from tests.integration.db._support import TENANT_A, make_alert
from tests.integration.engine._support import analyst

ROUTINE = "Authorized approved expected patch healthcheck, allowlisted and sanctioned"
HOST, USER = "ws-fin-0142", "jsmith"
NOTHING = {"threats": [], "in_progress": [], "model_only": []}
MODEL_CLOSE = ("closed", "benign", "ai_closed:audit_required")
REPO = Path(__file__).resolve().parents[3]
# How the workflow brings an alert to each status (lg_sotf.db.repos.alerts.ALERT_TRANSITIONS).
PATHS: Dict[str, Sequence[str]] = {
    "new": (),
    "queued": ("queued",),
    "processing": ("queued", "processing"),
    "waiting_human": ("queued", "processing", "waiting_human"),
    "waiting_approval": ("queued", "processing", "waiting_approval"),
    "closed": ("queued", "processing", "closed"),
    "failed": ("queued", "failed"),
}
# How the ledger brings a response action to each end (lg_sotf.db.repos.actions.ACTION_TRANSITIONS).
ACTION_PATHS: Dict[str, Sequence[str]] = {
    "awaiting_approval": ("awaiting_approval",),
    "approved": ("approved",),
    "succeeded": ("approved", "executing", "succeeded"),
    "failed": ("approved", "executing", "failed"),
    "dry_run": ("approved", "dry_run"),
    "rejected": ("awaiting_approval", "rejected"),
}


async def tier_on(repos: Repositories, tenant_id: str = TENANT_A) -> None:
    await repos.tenants.update_settings(tenant_id, {"ai_closure": {"tier": "auto_full_audit"}})


async def routine(
    repos: Repositories, name: str, *, tenant_id: str = TENANT_A, severity: str = "low",
    hosts: Sequence[str] = (HOST,), users: Sequence[str] = (), ips: Sequence[str] = (),
) -> str:
    """An alert both tiers of the fake model call benign, with no approved benign evidence: only the models close it."""
    fields: Dict[str, Any] = {
        "title": ROUTINE, "rule_name": "60106: Windows logon success", "description": ROUTINE,
        "entities": {"hosts": list(hosts), "users": list(users), "ips": list(ips)},
        "mitre": {"tactics": ["Initial Access"], "techniques": ["T1078"]},
    }
    return await make_alert(
        repos, tenant_id, source_alert_id=f"e316-{name}", title=ROUTINE, severity=severity, normalized=fields
    )


async def respond(
    repos: Repositories, alert_id: str, approver: Optional[str], end: str, *, tenant_id: str = TENANT_A,
    target: str = "203.0.113.9", rollback_of: Optional[UUID] = None,
) -> UUID:
    """A response action of the alert as the ledger keeps it, brought to ``end`` through the ledger's own state
    machine. ``approver``: ``"person"`` (an analyst approved it), ``"policy"`` (the autonomy policy approved it
    alone) or ``None`` (nobody did: it still waits, or was rejected)."""
    approved_by = await analyst(repos, tenant_id) if approver == "person" else POLICY_APPROVER if approver else None
    action, _ = await repos.actions.propose(
        tenant_id, alert_id, "block_ip", target, "low", requested_by=REQUESTED_BY, rollback_of=rollback_of,
        scope=f"rollback:{rollback_of}:1" if rollback_of else None,
    )
    for step in ACTION_PATHS[end]:
        approval = {"approved_by": approved_by} if step == "approved" else {}
        action = await repos.actions.transition(tenant_id, action.id, step, **approval)  # type: ignore[arg-type]
    return action.id


async def other(
    repos: Repositories, status: str, *, tenant_id: str = TENANT_A, severity: str = "high",
    hosts: Sequence[str] = (HOST,), users: Sequence[str] = (), ips: Sequence[str] = (),
    assessment: Optional[str] = None, verdict: Optional[str] = None, planned: bool = False, case: bool = False,
    true_positive: bool = False, ingested_at: Optional[datetime] = None, idle_minutes: int = 0,
    response: Optional[Tuple[Optional[str], str]] = None,
) -> str:
    """Another stored alert of the tenant, at ``status``, with what the workflow would have kept about it: the
    models' assessments, a response plan (``planned``), an open case of its own (``case``), an analyst's
    ``true_positive`` on its case (``true_positive``; a closed one is closed as the analyst's decision closes
    it), a response action in the ledger (``response``: who approved it and where it ended, :func:`respond`; a
    closed one is closed malicious, as the workflow closes an alert after its response), and how long ago the
    row last changed (``idle_minutes``)."""
    alert_id = await make_alert(
        repos, tenant_id, title="Credential dumping from LSASS", severity=severity, ingested_at=ingested_at,
        normalized={"entities": {"hosts": list(hosts), "users": list(users), "ips": list(ips)}},
    )
    for step in PATHS[status]:
        await repos.alerts.update_status(tenant_id, alert_id, step)
    summary: Dict[str, Any] = {}
    if assessment is not None:
        summary["triage"] = {"threat_assessment": assessment}
    if verdict is not None:
        summary["analysis"] = {"verdict": verdict}
    if planned:  # what the plan_response node keeps when the response policy applied
        summary["response"] = {"threat_type": "credential_theft", "evidence": "llm_only", "awaiting": 1}
    if case or true_positive:
        escalation, _ = await repos.escalations.create_or_attach(tenant_id, alert_id, reason="a model judged it a threat")
        summary["escalation_id"] = escalation.id
        if true_positive:
            await repos.escalations.decide(
                tenant_id, escalation.id, decision="true_positive", decided_by=UUID(await analyst(repos, tenant_id)),
                expected_version=escalation.version,
            )
            if status == "closed":
                summary.update(close_reason="analyst:true_positive", analyst_decision="true_positive")
                await repos.alerts.update(tenant_id, alert_id, disposition="malicious")
    if response is not None:
        await respond(repos, alert_id, *response, tenant_id=tenant_id)
        if status == "closed":
            summary.update(close_reason="policy:response")
            await repos.alerts.update(tenant_id, alert_id, disposition="malicious")
    if summary:
        await repos.alerts.update(tenant_id, alert_id, summary=summary)  # type: ignore[arg-type]
    if idle_minutes:
        async with repos.db.tenant_tx(tenant_id) as conn:
            await conn.execute(
                "UPDATE alerts SET updated_at = now() - make_interval(mins => $3) WHERE tenant_id = $1 AND id = $2",
                tenant_id, alert_id, idle_minutes,
            )
    return alert_id


async def decided(repos: Repositories, alert_id: str, tenant_id: str = TENANT_A) -> Dict[str, Any]:
    events = (await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=100)).items
    return dict([e for e in events if e.node == "decide"][-1].data)


def links(alert: Any) -> List[tuple]:  # type: ignore[type-arg]
    return [(link["threat_alert_id"], link["escalation_id"]) for link in alert.summary.get("linked") or []]


BEACON = "demo-net-001"


def seed_demo() -> Any:
    spec = importlib.util.spec_from_file_location("seed_demo", REPO / "scripts" / "demo" / "seed_demo.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def store_chain(repos: Repositories, seed: Any, tenant_id: str) -> Dict[str, str]:
    """The four alerts of the chain, normalised as the canonical ingest endpoint does, in the demo's order."""
    by_source = {a["source_alert_id"]: a for a in json.loads(seed.DEFAULT_ALERTS.read_text(encoding="utf-8"))["alerts"]}
    ctx = NormalizeContext("demo", "canonical", {}, now=datetime.now(UTC))
    ids: Dict[str, str] = {}
    for step in seed.ATTACK_CHAIN:
        raw = by_source[step]
        normalized = json.loads(get_normalizer("canonical").normalize(raw, ctx).model_dump_json())
        assert "ws-fin-0142.corp.example.com" in normalized["entities"]["hosts"]
        assert normalized["severity"] in ("high", "critical")  # so each step that is judged a threat holds the others
        ids[step] = await make_alert(
            repos, tenant_id, source_id="demo", source_alert_id=f"{step}-qs1", title=normalized["title"],
            severity=normalized["severity"], category=normalized["category"], raw=raw, normalized=normalized,
        )
    return ids


def persuaded(real: Any) -> Any:
    """The fake model, except that it reads the beacon as the real model did in #435: threat score 10, benign,
    with the test-looking names as its false-positive reasons."""
    def analyse(text: str) -> Any:
        if "cdn-sync.updates-cloud.test" not in text.lower():
            return real(text)
        reasons = ("reserved .test domain", "documentation address ranges", "example.com host naming",
                   "vendor is Demo NDR", "regular interval can be synthetic traffic")
        return fake.Signals(threat_score=10, confidence=90, malicious=(), benign=reasons)

    return analyse
