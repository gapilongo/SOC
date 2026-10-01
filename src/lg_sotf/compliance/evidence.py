"""Case evidence packs: one reconstructable, verifiable record of how an alert was handled.

A pack bundles, for one alert of one tenant:

* the alert (normalised form, the raw event redacted once more, the stored
  summary) and its full timeline;
* each agent's reasoning, verdict and confidence, with the provider and
  model it called (``summary.llm_models``; alerts processed before that was
  recorded say so);
* enrichment observations, indicator sightings and correlation;
* escalations (who claimed and decided, when), analyst feedback and the
  response-action ledger (requested by, approved by, executed, blocked
  reason, who executed it and in how many attempts, whether the change was
  verified by re-query, and the rollback lineage);
* a *human oversight* view: which steps were automated, which were decided
  or approved by a person, and where a person overrode the automation;
* the related audit-log entries with their hash-chain values, each entry's
  hash recomputed by the database, and the tenant chain verified from the
  oldest included entry onwards.

The pack is sealed with ``integrity.bundle_sha256`` over its canonical JSON
and, when the install has an indicator HMAC key, an HMAC-SHA256 signature
with a dedicated derived key (see :mod:`lg_sotf.compliance.canonical`).
Lists are capped; ``limits`` records whether anything was left out.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf import __version__
from lg_sotf.compliance import html as h
from lg_sotf.compliance.canonical import jsonable, optional_signing_key, seal
from lg_sotf.db.repos import AlertEvent, Escalation, Feedback, Repositories, ResponseAction
from lg_sotf.db.repos._base import Connection
from lg_sotf.security.redaction import redact
from lg_sotf.settings import Settings

EVIDENCE_FORMAT = "lg-sotf.evidence-pack"
EVIDENCE_VERSION = 1
MAX_TIMELINE_EVENTS = 5_000
MAX_ESCALATIONS = 200
MAX_ACTIONS = 500
MAX_AUDIT_ENTRIES = 2_000
MAX_SIGHTINGS = 1_000
PAGE_SIZE = 200

AGENT_STEPS = ("triage", "correlation", "analysis")
AUTOMATED_NODES = ("gate", "triage", "correlation", "analysis", "decide", "escalate", "plan_response",
                   "execute_actions", "close")
POLICY_APPROVER = "policy:auto"
BENIGN_DECISIONS = frozenset({"false_positive", "benign_positive"})
AI_MALICIOUS = frozenset({"malicious", "suspicious"})


def _obj(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


async def _timeline(repos: Repositories, tenant_id: str, alert_id: str, conn: Connection) -> tuple[List[AlertEvent], bool]:
    events: List[AlertEvent] = []
    cursor: Optional[str] = None
    while len(events) < MAX_TIMELINE_EVENTS:
        page = await repos.alert_events.list_for_alert(tenant_id, alert_id, limit=PAGE_SIZE, cursor=cursor, conn=conn)
        events.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return events[:MAX_TIMELINE_EVENTS], False
    return events[:MAX_TIMELINE_EVENTS], True


async def _escalations(
    repos: Repositories, tenant_id: str, alert_id: str, conn: Connection
) -> tuple[List[Escalation], bool]:
    found: List[Escalation] = []
    cursor: Optional[str] = None
    while len(found) < MAX_ESCALATIONS:
        page = await repos.escalations.list(tenant_id, alert_id=alert_id, limit=PAGE_SIZE, cursor=cursor, conn=conn)
        found.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    truncated = cursor is not None or len(found) > MAX_ESCALATIONS
    return sorted(found[:MAX_ESCALATIONS], key=lambda e: (e.created_at, e.id)), truncated


async def _actions(
    repos: Repositories, tenant_id: str, alert_id: str, conn: Connection
) -> tuple[List[ResponseAction], bool]:
    found: List[ResponseAction] = []
    cursor: Optional[str] = None
    while len(found) < MAX_ACTIONS:
        page = await repos.actions.list(tenant_id, alert_id=alert_id, limit=PAGE_SIZE, cursor=cursor, conn=conn)
        found.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
    truncated = cursor is not None or len(found) > MAX_ACTIONS
    return sorted(found[:MAX_ACTIONS], key=lambda a: (a.created_at, str(a.id))), truncated


async def _audit_entries(
    conn: Connection, tenant_id: str, alert_id: str, escalation_ids: Sequence[str], action_ids: Sequence[str]
) -> tuple[List[Dict[str, Any]], bool]:
    """Audit entries about the alert, its escalations and its actions, oldest first, each hash recomputed."""
    rows = await conn.fetch(
        """
        SELECT tenant_id, id, ts, actor_type, actor_id, action, resource_type, resource_id, details,
               prev_hash, hash,
               audit_entry_hash(tenant_id, id, ts, actor_type, actor_id, action, resource_type,
                                resource_id, details, prev_hash) = hash AS hash_valid
        FROM audit_log
        WHERE tenant_id = $1
          AND ((resource_type = 'alert' AND resource_id = $2)
               OR (resource_type = 'escalation' AND resource_id = ANY($3::text[]))
               OR (resource_type = 'response_action' AND resource_id = ANY($4::text[])))
        ORDER BY id
        LIMIT $5
        """,
        tenant_id,
        alert_id,
        list(escalation_ids),
        list(action_ids),
        MAX_AUDIT_ENTRIES + 1,
    )
    entries = [dict(r) for r in rows]
    return entries[:MAX_AUDIT_ENTRIES], len(entries) > MAX_AUDIT_ENTRIES


def _agents(summary: Mapping[str, Any], events: Sequence[AlertEvent]) -> Dict[str, Any]:
    """Per-step reasoning, verdict and confidence, with the provider/model that step called."""
    models = _obj(summary.get("llm_models"))
    usage_by_agent = _obj(_obj(summary.get("llm_usage")).get("by_agent"))
    completed = {e.node: e for e in events if e.event_type == "node.completed" and e.node}
    out: Dict[str, Any] = {}
    for step in AGENT_STEPS:
        digest = _obj(summary.get(step))
        event = completed.get(step)
        llm_used = digest.get("llm_used")
        model = models.get(step)
        if isinstance(model, Mapping):
            model_info: Dict[str, Any] = {**model, "recorded": True}
        elif llm_used:
            model_info = {"recorded": False, "note": "processed before per-step model recording"}
        else:
            model_info = {"recorded": False, "note": "no model call (rules only)"}
        out[step] = {
            "ran": bool(digest) or event is not None,
            "completed_at": event.ts if event is not None else None,
            "llm_used": llm_used,
            "model": model_info,
            "llm_usage": usage_by_agent.get(step),
            "confidence": digest.get("confidence"),
            "verdict": digest.get("verdict") or digest.get("threat_assessment"),
            "threat_score": digest.get("threat_score"),
            "reasoning": digest.get("reasoning"),
            "conclusion": digest.get("conclusion"),
            "digest": digest,
        }
    out["decision"] = summary.get("decision")
    out["response_plan"] = summary.get("response")
    out["refusals"] = summary.get("llm_refusals") or []
    out["llm_budget_exceeded"] = bool(summary.get("llm_budget_exceeded"))
    return out


def _escalation_view(e: Escalation) -> Dict[str, Any]:
    return {
        "id": e.id,
        "level": e.level,
        "status": e.status,
        "reason": e.reason,
        "priority": e.priority,
        "created_at": e.created_at,
        "sla_deadline": e.sla_deadline,
        "assigned_to": e.assigned_to,
        "claimed_at": e.claimed_at,
        "decision": e.decision,
        "decision_notes": e.decision_notes,
        "approved_actions": e.approved_actions,
        "decided_by": e.decided_by,
        "decided_at": e.decided_at,
        "related_alert_ids": e.related_alert_ids,
        "summary": e.summary,
    }


def _action_view(a: ResponseAction, rolled_back_by: Optional[Any] = None) -> Dict[str, Any]:
    result, _ = redact(a.result) if a.result is not None else (None, 0)
    params, _ = redact(a.params)
    verification_detail, _ = redact(a.verification_detail) if a.verification_detail is not None else (None, 0)
    return {
        "id": a.id,
        "action_type": a.action_type,
        "target": a.target,
        "risk_level": a.risk_level,
        "status": a.status,
        "blocked_reason": a.blocked_reason,
        "requested_by": a.requested_by,
        "approved_by": a.approved_by,
        "approved_at": a.approved_at,
        "executed_at": a.executed_at,
        "connector": a.connector,
        "execution_owner": a.execution_owner,
        "attempts": a.attempts,
        "params": params,
        "result": result,
        "verification": a.verification,
        "verified_at": a.verified_at,
        "verification_detail": verification_detail,
        "rollback_of": a.rollback_of,
        "rolled_back_by": rolled_back_by,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
    }


def _rollback_links(actions: Sequence[ResponseAction]) -> Dict[Any, Any]:
    """Original action id -> the most recent rollback row of it among ``actions``."""
    links: Dict[Any, Any] = {}
    for a in sorted(actions, key=lambda x: (x.created_at, str(x.id))):
        if a.rollback_of is not None:
            links[a.rollback_of] = a.id
    return links


def _feedback_view(f: Feedback) -> Dict[str, Any]:
    return {
        "id": f.id,
        "escalation_id": f.escalation_id,
        "user_id": f.user_id,
        "decision": f.decision,
        "confidence": f.confidence,
        "notes": f.notes,
        "triage_correct": f.triage_correct,
        "correlation_helpful": f.correlation_helpful,
        "analysis_accurate": f.analysis_accurate,
        "review_duration_s": f.review_duration_s,
        "created_at": f.created_at,
    }


def human_oversight(
    summary: Mapping[str, Any],
    events: Sequence[AlertEvent],
    escalations: Sequence[Escalation],
    actions: Sequence[ResponseAction],
    feedback: Sequence[Feedback],
    audit: Sequence[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    """Which steps ran automatically, which a person decided or approved, and where a person overrode the automation.

    Rollback requests and retries (from the ``audit`` entries of the
    actions) are human steps; a rollback also counts as an override of the
    action it undoes.
    """
    steps: List[Dict[str, Any]] = []
    overrides: List[Dict[str, Any]] = []
    by_id = {str(a.id): a for a in actions}
    for entry in audit:
        action = by_id.get(str(entry.get("resource_id")))
        if entry.get("resource_type") != "response_action" or action is None:
            continue
        details = entry.get("details") if isinstance(entry.get("details"), Mapping) else {}
        if entry.get("action") == "response_action.rollback_requested":
            steps.append(
                {"at": entry.get("ts"), "step": f"rollback_requested:{action.action_type}", "mode": "human",
                 "actor": entry.get("actor_id"), "detail": (details or {}).get("reason")}
            )
            overrides.append(
                {"at": entry.get("ts"), "kind": "action_rolled_back", "actor": entry.get("actor_id"),
                 "detail": f"rollback of {action.action_type} on {action.target} requested"}
            )
        elif entry.get("action") == "response_action.retry_requested":
            steps.append(
                {"at": entry.get("ts"), "step": f"retry_requested:{action.action_type}", "mode": "human",
                 "actor": entry.get("actor_id"), "detail": (details or {}).get("reason")}
            )
    for e in events:
        if e.event_type == "node.completed" and e.node in AUTOMATED_NODES:
            steps.append({"at": e.ts, "step": e.node, "mode": "automated", "actor": e.actor_id, "detail": None})
        elif e.actor_type == "user":
            steps.append({"at": e.ts, "step": e.event_type, "mode": "human", "actor": e.actor_id, "detail": None})
    analysis = _obj(summary.get("analysis"))
    ai_verdict = analysis.get("verdict")
    for esc in escalations:
        steps.append(
            {"at": esc.created_at, "step": "escalated", "mode": "automated", "actor": "workflow",
             "detail": f"{esc.level}: {esc.reason}"}
        )
        if esc.claimed_at is not None and esc.assigned_to is not None:
            steps.append(
                {"at": esc.claimed_at, "step": "escalation_claimed", "mode": "human", "actor": esc.assigned_to,
                 "detail": esc.id}
            )
        if esc.decided_at is not None and esc.decision:
            steps.append(
                {"at": esc.decided_at, "step": "analyst_decision", "mode": "human", "actor": esc.decided_by,
                 "detail": esc.decision}
            )
            contradicts = (esc.decision in BENIGN_DECISIONS and ai_verdict in AI_MALICIOUS) or (
                esc.decision == "true_positive" and ai_verdict == "benign"
            )
            if contradicts:
                overrides.append(
                    {"at": esc.decided_at, "kind": "verdict_overridden", "actor": esc.decided_by,
                     "detail": f"automated verdict {ai_verdict!s} -> analyst decision {esc.decision}"}
                )
    for a in actions:
        if a.approved_by and a.status != "rejected":
            human = a.approved_by != POLICY_APPROVER
            steps.append(
                {"at": a.approved_at or a.updated_at, "step": f"action_approved:{a.action_type}",
                 "mode": "human" if human else "automated", "actor": a.approved_by, "detail": a.target}
            )
        if a.status == "rejected":
            steps.append(
                {"at": a.updated_at, "step": f"action_rejected:{a.action_type}", "mode": "human",
                 "actor": a.approved_by, "detail": a.target}
            )
            overrides.append(
                {"at": a.updated_at, "kind": "action_rejected", "actor": a.approved_by,
                 "detail": f"{a.action_type} on {a.target} proposed by {a.requested_by or 'workflow'} was rejected"}
            )
        if a.status == "blocked":
            steps.append(
                {"at": a.updated_at, "step": f"action_blocked:{a.action_type}", "mode": "automated",
                 "actor": "guardrails", "detail": a.blocked_reason}
            )
        if a.executed_at is not None:
            steps.append(
                {"at": a.executed_at, "step": f"action_executed:{a.action_type}", "mode": "automated",
                 "actor": a.connector, "detail": a.status}
            )
    for f in feedback:
        for field, label in (
            ("triage_correct", "triage"),
            ("correlation_helpful", "correlation"),
            ("analysis_accurate", "analysis"),
        ):
            if getattr(f, field) is False:
                overrides.append(
                    {"at": f.created_at, "kind": "agent_output_disputed", "actor": f.user_id,
                     "detail": f"analyst feedback: {label} output judged wrong or unhelpful"}
                )
    steps.sort(key=lambda s: (str(jsonable(s["at"])), s["step"]))
    overrides.sort(key=lambda s: str(jsonable(s["at"])))
    human_steps = [s for s in steps if s["mode"] == "human"]
    close_reason = summary.get("close_reason")
    return {
        "summary": {
            "automated_steps": len(steps) - len(human_steps),
            "human_steps": len(human_steps),
            "human_decisions": sum(1 for s in human_steps if s["step"] == "analyst_decision"),
            "human_action_approvals": sum(1 for s in human_steps if str(s["step"]).startswith("action_approved")),
            "overrides": len(overrides),
            "closed_without_human": close_reason is not None and not human_steps,
            "close_reason": close_reason,
            "suppressed_by": summary.get("suppressed_by"),
        },
        "steps": steps,
        "overrides": overrides,
    }


async def build_evidence_pack(
    repos: Repositories,
    settings: Settings,
    tenant_id: str,
    alert_id: str,
    *,
    generated_by: Mapping[str, Any],
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Assemble and seal the evidence pack (raises ``NotFound`` for an unknown alert)."""
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        events, events_truncated = await _timeline(repos, tenant_id, alert_id, conn)
        escalations, escalations_truncated = await _escalations(repos, tenant_id, alert_id, conn)
        actions, actions_truncated = await _actions(repos, tenant_id, alert_id, conn)
        feedback = await repos.feedback.list_for_alert(tenant_id, alert_id, conn=conn)
        sightings = await repos.indicators.sightings_for_alert(tenant_id, alert_id, conn=conn)
        audit, audit_truncated = await _audit_entries(
            conn, tenant_id, alert_id, [e.id for e in escalations], [str(a.id) for a in actions]
        )
    chain_since = audit[0]["ts"] if audit else None
    chain = await repos.audit.verify_chain(tenant_id, chain_since) if audit else None
    summary = _obj(alert.summary)
    rollbacks = _rollback_links(actions)
    raw_redacted, raw_redactions = redact(alert.raw)
    analysis = _obj(summary.get("analysis"))
    pack: Dict[str, Any] = {
        "format": EVIDENCE_FORMAT,
        "version": EVIDENCE_VERSION,
        "generated_at": now or datetime.now(UTC),
        "generated_by": dict(generated_by),
        "lg_sotf_version": __version__,
        "tenant_id": tenant_id,
        "alert": {
            "id": alert.id,
            "source_id": alert.source_id,
            "source_alert_id": alert.source_alert_id,
            "fingerprint": alert.fingerprint,
            "case_key": alert.case_key,
            "title": alert.title,
            "severity": alert.severity,
            "category": alert.category,
            "status": alert.status,
            "disposition": alert.disposition,
            "confidence": alert.confidence,
            "threat_score": alert.threat_score,
            "priority": alert.priority,
            "assigned_to": alert.assigned_to,
            "occurred_at": alert.occurred_at,
            "ingested_at": alert.ingested_at,
            "updated_at": alert.updated_at,
            "closed_at": alert.closed_at,
            "normalized": alert.normalized,
            "raw_redacted": raw_redacted,
            "raw_redactions": raw_redactions,
            "summary": summary,
        },
        "timeline": [
            {"id": e.id, "ts": e.ts, "node": e.node, "event_type": e.event_type, "actor_type": e.actor_type,
             "actor_id": e.actor_id, "data": e.data}
            for e in events
        ],
        "agents": _agents(summary, events),
        "enrichment": {
            "observations": analysis.get("tools") or [],
            "threat_indicators": analysis.get("threat_indicators") or [],
            "history": analysis.get("history") or [],
            "indicator_sightings": [
                {"indicator_type": s.indicator_type, "value_display": s.value_display, "value_hash": s.value_hash,
                 "seen_at": s.seen_at}
                for s in sightings[:MAX_SIGHTINGS]
            ],
        },
        "correlation": {
            "digest": summary.get("correlation"),
            "escalation_related_alert_ids": sorted({i for e in escalations for i in e.related_alert_ids}),
        },
        "escalations": [_escalation_view(e) for e in escalations],
        "feedback": [_feedback_view(f) for f in feedback],
        "actions": [_action_view(a, rollbacks.get(a.id)) for a in actions],
        "human_oversight": human_oversight(summary, events, escalations, actions, feedback, audit),
        "audit": {
            "entries": audit,
            "chain_verification": {
                "scope": "tenant chain from the oldest included entry to the newest entry",
                "since": chain_since,
                "ok": chain.ok if chain is not None else None,
                "first_bad_id": chain.first_bad_id if chain is not None else None,
            },
            "included_entry_hashes_valid": all(e["hash_valid"] for e in audit),
        },
        "limits": {
            "timeline_truncated": events_truncated,
            "escalations_truncated": escalations_truncated,
            "actions_truncated": actions_truncated,
            "audit_truncated": audit_truncated,
            "sightings_truncated": len(sightings) > MAX_SIGHTINGS,
        },
    }
    document = jsonable(pack)
    return seal(document, optional_signing_key(settings))


# ------------------------------------------------------------------ HTML


def _step_rows(steps: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [{**s, "mode": "HUMAN" if s.get("mode") == "human" else "automated"} for s in steps]


def render_evidence_html(pack: Mapping[str, Any]) -> str:
    """The pack as a standalone, print-friendly HTML document (every value escaped)."""
    alert = _obj(pack.get("alert"))
    integrity = _obj(pack.get("integrity"))
    signature = _obj(integrity.get("signature"))
    oversight = _obj(pack.get("human_oversight"))
    osum = _obj(oversight.get("summary"))
    agents = _obj(pack.get("agents"))
    audit = _obj(pack.get("audit"))
    chain = _obj(audit.get("chain_verification"))
    limits = _obj(pack.get("limits"))
    body: List[str] = [
        f'<div class="notice">{h.esc(h.UNTRUSTED_NOTICE)}</div>',
        h.kv_table(
            [
                ("Alert id", alert.get("id")),
                ("Tenant", pack.get("tenant_id")),
                ("Title (untrusted)", alert.get("title")),
                ("Severity / status / disposition",
                 f"{alert.get('severity')} / {alert.get('status')} / {alert.get('disposition') or '-'}"),
                ("Confidence / threat score", f"{alert.get('confidence')} / {alert.get('threat_score')}"),
                ("Occurred / ingested / closed",
                 f"{alert.get('occurred_at')} / {alert.get('ingested_at')} / {alert.get('closed_at') or '-'}"),
                ("Source", f"{alert.get('source_id')} ({alert.get('source_alert_id')})"),
                ("Generated", f"{pack.get('generated_at')} by {_obj(pack.get('generated_by')).get('actor_id')}"),
                ("LG-SOTF version", pack.get("lg_sotf_version")),
            ]
        ),
    ]
    overrides = oversight.get("overrides") or []
    body.append(
        h.section(
            "Human oversight",
            h.kv_table(
                [
                    ("Automated steps", osum.get("automated_steps")),
                    ("Steps taken by a person", osum.get("human_steps")),
                    ("Analyst decisions", osum.get("human_decisions")),
                    ("Human action approvals", osum.get("human_action_approvals")),
                    ("Overrides of the automation", osum.get("overrides")),
                    ("Closed without human involvement", osum.get("closed_without_human")),
                    ("Close reason", osum.get("close_reason")),
                ]
            ),
            "<h3>Steps</h3>",
            h.table(
                [("at", "When"), ("step", "Step"), ("mode", "Mode"), ("actor", "Actor"), ("detail", "Detail")],
                _step_rows(oversight.get("steps") or []),
            ),
            "<h3>Overrides</h3>",
            h.table([("at", "When"), ("kind", "Kind"), ("actor", "Actor"), ("detail", "Detail")], overrides,
                    empty="No human override of the automation was recorded."),
            anchor="oversight",
        )
    )
    agent_parts: List[str] = []
    for step in AGENT_STEPS:
        info = _obj(agents.get(step))
        model = _obj(info.get("model"))
        model_text = (
            f"{model.get('provider')} / {model.get('model')} ({model.get('tier')} tier)"
            if model.get("recorded")
            else model.get("note")
        )
        agent_parts.append(f"<h3>{h.esc(step.title())}</h3>")
        agent_parts.append(
            h.kv_table(
                [
                    ("Ran", info.get("ran")),
                    ("Completed at", info.get("completed_at")),
                    ("LLM used", info.get("llm_used")),
                    ("Provider / model", model_text),
                    ("Verdict", info.get("verdict")),
                    ("Confidence", info.get("confidence")),
                    ("Threat score", info.get("threat_score")),
                    ("Conclusion (model output, untrusted)", info.get("conclusion")),
                    ("Reasoning (model output, untrusted)", info.get("reasoning")),
                ]
            )
        )
    agent_parts.append("<h3>Routing decision</h3>" + h.pre(agents.get("decision") or {}))
    body.append(h.section("Agent reasoning and verdicts", *agent_parts, anchor="agents"))
    enrichment = _obj(pack.get("enrichment"))
    body.append(
        h.section(
            "Enrichment and correlation",
            "<h3>Observations</h3>",
            h.pre(enrichment.get("observations") or []),
            "<h3>Indicator sightings</h3>",
            h.table(
                [("indicator_type", "Type"), ("value_display", "Value (display)"), ("seen_at", "Seen")],
                enrichment.get("indicator_sightings") or [],
            ),
            "<h3>Correlation</h3>",
            h.pre(pack.get("correlation") or {}),
        )
    )
    body.append(
        h.section(
            "Escalations",
            h.table(
                [("id", "Id"), ("level", "Level"), ("status", "Status"), ("reason", "Reason"),
                 ("created_at", "Created"), ("assigned_to", "Claimed by"), ("claimed_at", "Claimed"),
                 ("decision", "Decision"), ("decided_by", "Decided by"), ("decided_at", "Decided"),
                 ("decision_notes", "Notes")],
                pack.get("escalations") or [],
            ),
        )
    )
    body.append(
        h.section(
            "Analyst feedback",
            h.table(
                [("created_at", "When"), ("user_id", "Analyst"), ("decision", "Decision"),
                 ("triage_correct", "Triage correct"), ("correlation_helpful", "Correlation helpful"),
                 ("analysis_accurate", "Analysis accurate"), ("notes", "Notes")],
                pack.get("feedback") or [],
            ),
        )
    )
    body.append(
        h.section(
            "Response ledger",
            h.table(
                [("action_type", "Action"), ("target", "Target"), ("risk_level", "Risk"), ("status", "Status"),
                 ("requested_by", "Requested by"), ("approved_by", "Approved by"), ("approved_at", "Approved"),
                 ("executed_at", "Executed"), ("connector", "Connector"), ("verification", "Verification"),
                 ("verified_at", "Verified"), ("rollback_of", "Rolls back"), ("blocked_reason", "Blocked reason")],
                pack.get("actions") or [],
            ),
        )
    )
    body.append(
        h.section(
            "Timeline",
            h.table(
                [("ts", "When"), ("event_type", "Event"), ("node", "Node"), ("actor_type", "Actor type"),
                 ("actor_id", "Actor"), ("data", "Data")],
                pack.get("timeline") or [],
            ),
        )
    )
    chain_ok = chain.get("ok")
    chain_text = "not checked (no related entries)" if chain_ok is None else ("VALID" if chain_ok else "BROKEN")
    body.append(
        h.section(
            "Audit trail",
            h.kv_table(
                [
                    ("Chain verification", f"{chain_text} (from {chain.get('since') or '-'})"),
                    ("First bad entry", chain.get("first_bad_id")),
                    ("Included entries' hashes recomputed and valid", audit.get("included_entry_hashes_valid")),
                ]
            ),
            h.table(
                [("id", "Id"), ("ts", "When"), ("actor_type", "Actor type"), ("actor_id", "Actor"),
                 ("action", "Action"), ("resource_type", "Resource"), ("resource_id", "Resource id"),
                 ("prev_hash", "Previous hash"), ("hash", "Hash"), ("hash_valid", "Hash valid")],
                audit.get("entries") or [],
            ),
        )
    )
    body.append(
        h.section(
            "Alert data (untrusted)",
            "<h3>Normalised</h3>",
            h.pre(alert.get("normalized") or {}),
            f"<h3>Raw event (redacted; {h.esc(alert.get('raw_redactions'))} redactions)</h3>",
            h.pre(alert.get("raw_redacted") or {}),
        )
    )
    body.append(
        h.section(
            "Integrity",
            h.kv_table(
                [
                    ("bundle_sha256", integrity.get("bundle_sha256")),
                    ("Canonicalisation", integrity.get("canonicalization")),
                    ("Signature", f"{signature.get('alg')} key {signature.get('key_id')}" if signature else "unsigned"),
                    ("Truncated lists", ", ".join(k for k, v in limits.items() if v) or "none"),
                ]
            ),
            h.paragraph(
                "The digest and signature cover the JSON bundle, not this HTML rendering. Verify the JSON with "
                "`lg-sotf evidence-verify <file>` (see docs/compliance.md)."
            ),
        )
    )
    return h.document(
        f"Case evidence pack: alert {alert.get('id')}",
        body,
        subtitle="LG-SOTF case record for review, audit and incident reporting.",
    )


__all__ = [
    "EVIDENCE_FORMAT",
    "EVIDENCE_VERSION",
    "build_evidence_pack",
    "human_oversight",
    "render_evidence_html",
]
