"""The evidence pack as a standalone, print-friendly HTML document.

Renders a sealed pack built by :func:`lg_sotf.compliance.evidence.build_evidence_pack`
(every value escaped by :mod:`lg_sotf.compliance.html`). It reads only the pack
mapping: no database access (import-linter contract ``evidence-html-no-db``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from lg_sotf.compliance import html as h

AGENT_STEPS = ("triage", "correlation", "analysis")


def _obj(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


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


__all__ = ["AGENT_STEPS", "render_evidence_html"]
