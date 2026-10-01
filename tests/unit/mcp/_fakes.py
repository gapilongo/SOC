"""JSON shaped like the LG-SOTF REST API's responses, for the tester-tool tests (no credential literals)."""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import httpx

from tests.unit.mcp._support import StubApi

TENANT = "qa-01"
KEY_ID = str(uuid.UUID(int=0x51))
INGESTED_AT = "2026-10-01T10:00:00+00:00"


def me(scopes: List[str], *, kind: str = "api_key", tenant: str = TENANT, email: Optional[str] = None) -> Dict[str, Any]:
    return {
        "kind": kind,
        "tenant_id": tenant,
        "home_tenant_id": tenant,
        "auth_method": "api_key" if kind == "api_key" else "password",
        "role": None if kind == "api_key" else "analyst",
        "scopes": scopes,
        "user_id": None,
        "api_key_id": KEY_ID if kind == "api_key" else None,
        "email": email,
        "is_platform_admin": False,
        "expires_at": None,
    }


def alert(
    alert_id: str,
    status: str,
    *,
    disposition: Optional[str] = None,
    summary: Optional[Dict[str, Any]] = None,
    title: str = "Mimikatz execution detected on domain controller",
    ingested_at: str = INGESTED_AT,
    confidence: Optional[float] = 80.0,
) -> Dict[str, Any]:
    return {
        "id": alert_id,
        "tenant_id": TENANT,
        "source_id": f"api:{KEY_ID}",
        "source_alert_id": f"can-{alert_id}",
        "fingerprint": "f" * 64,
        "title": title,
        "severity": "critical",
        "category": "credential_access",
        "status": status,
        "disposition": disposition,
        "confidence": confidence,
        "threat_score": 90.0,
        "priority": 1,
        "assigned_to": None,
        "occurred_at": "2024-03-08T02:14:00+00:00",
        "ingested_at": ingested_at,
        "updated_at": ingested_at,
        "closed_at": None,
        "summary": summary or {},
        "case_key": None,
        "raw": {"title": title},
        "normalized": {"title": title},
    }


def closed_summary(
    *, route: str = "close", code: str = "rule_corroborated_benign", disposition: str = "benign", **extra: Any
) -> Dict[str, Any]:
    return {
        "verdict": disposition,
        "close_reason": "policy:close" if route == "close" else "policy:response",
        "decision": {"route": route, "reason": "low threat corroborated by rules", "disposition": disposition,
                     "code": code},
        "analysis": {"verdict": disposition, "conclusion": "Scheduled backup job.", "reasoning": ["step one"],
                     "recommended_actions": ["none"], "threat_score": 10, "certainty": 70, "stop_reason": "final",
                     "llm_used": True},
        "llm_models": {"analysis": {"provider": "fake", "model": "fake-deep", "tier": "deep"}},
        "llm_usage": {"calls": 2, "input_tokens": 100, "output_tokens": 20, "total_tokens": 120, "cost_usd": 0.0},
        **extra,
    }


def decide_events(route: str, code: str, reason: str = "threat score 90 meets the response policy") -> Dict[str, Any]:
    return {
        "items": [
            {"id": 1, "alert_id": "x", "ts": INGESTED_AT, "node": "triage", "event_type": "node.completed",
             "actor_type": "agent", "actor_id": "triage", "data": {"confidence": 80}},
            {"id": 2, "alert_id": "x", "ts": INGESTED_AT, "node": "decide", "event_type": "node.completed",
             "actor_type": "system", "actor_id": "workflow",
             "data": {"route": route, "reason": reason, "disposition": None, "code": code}},
        ],
        "next_cursor": None,
    }


def action(
    alert_id: str,
    status: str,
    *,
    connector: Optional[str] = None,
    executed_at: Optional[str] = None,
    approved_by: Optional[str] = None,
    verification: Optional[str] = None,
    target: str = "dc-01",
    action_id: Optional[str] = None,
    created_at: str = INGESTED_AT,
    result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": action_id or str(uuid.uuid4()),
        "tenant_id": TENANT,
        "alert_id": alert_id,
        "action_type": "isolate_host",
        "target": target,
        "params": {"reason": "credential theft"},
        "risk_level": "high",
        "status": status,
        "blocked_reason": None,
        "requested_by": "workflow",
        "approved_by": approved_by,
        "approved_at": INGESTED_AT if approved_by else None,
        "executed_at": executed_at,
        "connector": connector,
        "result": result,
        "rollback_of": None,
        "created_at": created_at,
        "updated_at": created_at,
        "execution_owner": "workflow",
        "integration_id": None,
        "external_ref": None,
        "attempts": 1 if executed_at else 0,
        "verification": verification,
        "verification_detail": {"summary": "checked"} if verification else None,
        "verify_deadline": None,
        "verified_at": INGESTED_AT if verification == "verified" else None,
        "rollback": {"available": False, "action_type": None, "risk": None, "until": None, "reason": "not_executed"},
        "rolled_back_by": None,
    }


def escalation(escalation_id: str, alert_id: str, created_at: str) -> Dict[str, Any]:
    return {
        "id": escalation_id, "tenant_id": TENANT, "alert_id": alert_id, "level": "L2", "status": "open",
        "reason": "grey zone", "priority": 2, "summary": {}, "related_alert_ids": [], "assigned_to": None,
        "sla_deadline": None, "decision": None, "decision_notes": None, "approved_actions": [], "decided_by": None,
        "decided_at": None, "claimed_at": None, "version": 0, "created_at": created_at, "updated_at": created_at,
    }


def page(items: List[Dict[str, Any]], next_cursor: Optional[str] = None) -> Dict[str, Any]:
    return {"items": items, "next_cursor": next_cursor}


def ingest_answer(request: httpx.Request, *, rejected: Optional[set] = None) -> httpx.Response:
    """``POST /ingest/alerts``: one inserted alert per event (``alert-<index>``), or rejected."""
    import json

    events = json.loads(request.content)["alerts"]
    items = []
    for index, _event in enumerate(events):
        if rejected and index in rejected:
            items.append({"index": index, "status": "rejected", "alert_id": None, "reason": "canonical alert requires 'severity'"})
        else:
            items.append({"index": index, "status": "inserted", "alert_id": f"alert-{index}", "reason": None})
    inserted = sum(1 for i in items if i["status"] == "inserted")
    return httpx.Response(
        202,
        json={"source_id": f"api:{KEY_ID}", "received": len(events), "inserted": inserted, "duplicates": 0,
              "rejected": len(events) - inserted, "enqueued": inserted, "items": items},
    )


def dataset_item(index: int, *, expected: Optional[Dict[str, Any]] = None, source_type: str = "canonical",
                 split: str = "standard", title: str = "Mimikatz execution detected on domain controller") -> Dict[str, Any]:
    """A line of tests/fixtures/eval/synthetic_v1.jsonl."""
    return {
        "id": f"syn-{index:03d}",
        "source_type": source_type,
        "alert": {"source_alert_id": f"can-{index:03d}", "title": title, "severity": "critical",
                  "occurred_at": "2024-03-08T02:14:00Z", "entities": {"hosts": ["dc-01"]}},
        "expected": expected if expected is not None else {"disposition": "malicious", "escalation": True},
        "split": split,
        "tags": ["synthetic"],
        "notes": "",
    }


def standard_routes(stub: StubApi, scopes: Optional[List[str]] = None) -> None:
    """``/auth/me``, an empty tenant and an ingest endpoint that inserts everything."""
    stub.json("GET /api/v1/auth/me", me(scopes or ["ingest", "read"]))
    stub.json("GET /api/v1/alerts", page([]))
    stub.routes["POST /api/v1/ingest/alerts"] = ingest_answer
