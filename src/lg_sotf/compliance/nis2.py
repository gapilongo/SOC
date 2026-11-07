"""NIS2 Article 23 incident-report drafts, prefilled deterministically from case data.

NIS2 (Directive (EU) 2022/2555) Article 23(4) asks an essential or important
entity to send its CSIRT or competent authority, for a *significant*
incident:

* an **early warning** without undue delay and within 24 hours of becoming
  aware, indicating whether the incident is suspected of being caused by
  unlawful or malicious acts and whether it could have a cross-border
  impact;
* an **incident notification** within 72 hours, updating the early warning
  with an initial assessment (severity and impact) and, where available,
  indicators of compromise;
* a **final report** within one month of the notification: a detailed
  description (severity and impact), the type of threat or root cause,
  applied and ongoing mitigation measures, and any cross-border impact.

This module builds a *draft* for each stage. Every field says where its
value came from: ``case_data`` (derived deterministically from the alert,
its analysis, escalations and response ledger), ``requires_human`` (a
legal or business judgement LG-SOTF cannot make — the value is left empty
or only hinted) or ``ai_drafted``. An optional narrative from the
configured model is built through the untrusted-data boundary
(:func:`lg_sotf.llm.build_prompt`) and labelled "AI-drafted — review
required". LG-SOTF never submits anything to a CSIRT or authority: a person
completes, checks and submits the report through the national channel.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, cast

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import BaseModel, ConfigDict

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.compliance import html as h
from lg_sotf.compliance.canonical import jsonable
from lg_sotf.db.repos import Alert, AlertEvent, Escalation, Repositories, ResponseAction
from lg_sotf.llm import (
    USE_DEFAULT,
    BudgetLimit,
    LLMBudgetExceeded,
    LLMError,
    LLMRefusal,
    TokenBudget,
    ainvoke_structured,
    build_prompt,
    get_chat_model,
)
from lg_sotf.llm.client import Tier
from lg_sotf.llm.provenance import model_provenance
from lg_sotf.llm.schema import clipped_str
from lg_sotf.observability.logging import get_logger
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.core.state import AlertSummary

log = get_logger(__name__)

Stage = Literal["early_warning", "notification", "final"]
Source = Literal["case_data", "requires_human", "ai_drafted"]
STAGES: Sequence[str] = ("early_warning", "notification", "final")

DISCLAIMER = (
    "Draft for a human to complete and submit. LG-SOTF does not submit reports to CSIRTs or competent "
    "authorities, and it does not decide whether an incident is significant under NIS2 Article 23(3)."
)
AI_LABEL = "AI-drafted — review required"
STAGE_TITLES = {
    "early_warning": "NIS2 early warning (Art. 23(4)(a))",
    "notification": "NIS2 incident notification (Art. 23(4)(b))",
    "final": "NIS2 final report (Art. 23(4)(d))",
}
DEADLINES = {
    "early_warning": "without undue delay and in any event within 24 hours of becoming aware of the significant incident",
    "notification": "without undue delay and in any event within 72 hours of becoming aware of the significant incident",
    "final": "no later than one month after the incident notification",
}
MAX_IOCS = 50
MAX_ASSETS = 25
MAX_VALUE_CHARS = 4_000
# Longest field or narrative value stored in a draft's timeline event.
MAX_EVENT_VALUE_CHARS = 4_000
IOC_KINDS = {"ips": "ip", "domains": "domain", "urls": "url", "hashes": "hash", "emails": "email"}
ASSET_KINDS = ("hosts", "users")
DONE_STATUSES = frozenset({"succeeded", "dry_run"})
PENDING_STATUSES = frozenset({"proposed", "awaiting_approval", "approved", "executing"})


@dataclass(frozen=True)
class DraftField:
    key: str
    label: str
    value: Optional[str]
    source: Source
    required: bool = True
    help: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "source": self.source,
            "required": self.required,
            "help": self.help,
        }


@dataclass(frozen=True)
class CaseData:
    """What the draft is built from (already read in the caller's tenant transaction)."""

    alert: Alert
    escalations: Sequence[Escalation]
    actions: Sequence[ResponseAction]
    indicator_displays: Sequence[str] = ()


MAX_CASE_ESCALATIONS = 50
MAX_CASE_ACTIONS = 200


async def load_case(repos: Repositories, tenant_id: str, alert_id: str) -> CaseData:
    """Read the alert, its escalations, actions and indicator sightings (``NotFound`` for an unknown alert)."""
    async with repos.db.tenant_tx(tenant_id, readonly=True) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        escalations = await repos.escalations.list(
            tenant_id, alert_id=alert_id, include_attached=True, limit=MAX_CASE_ESCALATIONS, conn=conn
        )
        actions = await repos.actions.list(tenant_id, alert_id=alert_id, limit=MAX_CASE_ACTIONS, conn=conn)
        sightings = await repos.indicators.sightings_for_alert(tenant_id, alert_id, conn=conn)
    displays = [f"{s.indicator_type}: {s.value_display}" for s in sightings if s.value_display][:MAX_IOCS]
    return CaseData(
        alert=alert,
        escalations=sorted(escalations.items, key=lambda e: (e.created_at, e.id)),
        actions=sorted(actions.items, key=lambda a: (a.created_at, str(a.id))),
        indicator_displays=displays,
    )


def _obj(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _summary(alert: Alert) -> AlertSummary:
    """The alert's summary document (empty when malformed); its values are read defensively."""
    return cast("AlertSummary", _obj(alert.summary))


def _strings(value: Any, limit: int) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out: List[str] = []
    for item in value:
        if isinstance(item, Mapping):
            item = item.get("value", item.get("name", item.get("id")))
        if isinstance(item, (str, int)) and not isinstance(item, bool):
            text = str(item).strip()
            if text and text not in out:
                out.append(text[:300])
        if len(out) >= limit:
            break
    return out


def _clip(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    return text if len(text) <= MAX_VALUE_CHARS else text[: MAX_VALUE_CHARS - 3] + "..."


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(UTC).isoformat() if value is not None else None


def _decided(escalations: Sequence[Escalation]) -> Optional[Escalation]:
    decided = [e for e in escalations if e.decided_at is not None and e.decision]
    return max(decided, key=lambda e: e.decided_at or datetime.min.replace(tzinfo=UTC)) if decided else None


def _mitre(normalized: Mapping[str, Any]) -> tuple[List[str], List[str]]:
    mitre = _obj(normalized.get("mitre"))
    return _strings(mitre.get("tactics"), 20), _strings(mitre.get("techniques"), 30)


def _malicious_assessment(case: CaseData) -> str:
    alert = case.alert
    summary = _summary(alert)
    analysis = _obj(summary.get("analysis"))
    decided = _decided(case.escalations)
    parts: List[str] = []
    if decided is not None:
        verdict = {
            "true_positive": "confirmed as a true positive (malicious activity)",
            "false_positive": "judged a false positive",
            "benign_positive": "judged benign (expected activity)",
            "needs_more_info": "still under investigation",
        }.get(str(decided.decision), str(decided.decision))
        parts.append(f"Analyst decision: {verdict} at {_iso(decided.decided_at)}.")
    if analysis.get("verdict"):
        parts.append(
            f"Automated analysis verdict: {analysis.get('verdict')} "
            f"(threat score {analysis.get('threat_score')}, certainty {analysis.get('certainty')})."
        )
    if alert.disposition:
        parts.append(f"Case disposition: {alert.disposition}.")
    tactics, techniques = _mitre(_obj(alert.normalized))
    if tactics or techniques:
        parts.append(f"MITRE ATT&CK: {', '.join([*tactics, *techniques])}.")
    if not parts:
        parts.append("No verdict recorded yet.")
    parts.append("Confirm whether unlawful or malicious acts are suspected before submitting.")
    return " ".join(parts)


def _assets(normalized: Mapping[str, Any]) -> Dict[str, List[str]]:
    entities = _obj(normalized.get("entities"))
    return {kind: _strings(entities.get(kind), MAX_ASSETS) for kind in ASSET_KINDS}


def _asset_text(normalized: Mapping[str, Any]) -> str:
    assets = _assets(normalized)
    lines = [f"{kind}: {', '.join(values)}" for kind, values in assets.items() if values]
    return "; ".join(lines) if lines else "No affected hosts or accounts were extracted from the alert."


def _iocs(case: CaseData) -> List[str]:
    entities = _obj(_obj(case.alert.normalized).get("entities"))
    out: List[str] = []
    for kind, label in IOC_KINDS.items():
        for value in _strings(entities.get(kind), MAX_IOCS):
            item = f"{label}: {value}"
            if item not in out:
                out.append(item)
    for display in case.indicator_displays:
        if display and len(out) < MAX_IOCS and display not in out:
            out.append(display)
    return out[:MAX_IOCS]


def _severity_text(case: CaseData) -> str:
    alert = case.alert
    return (
        f"Alert severity {alert.severity}; threat score {alert.threat_score if alert.threat_score is not None else '-'}; "
        f"confidence {alert.confidence if alert.confidence is not None else '-'}; "
        f"disposition {alert.disposition or 'undecided'}."
    )


def _actions_text(actions: Iterable[ResponseAction], statuses: frozenset[str]) -> Optional[str]:
    lines = [
        f"{a.action_type} on {a.target} ({a.status}{', dry run' if a.status == 'dry_run' else ''})"
        for a in actions
        if a.status in statuses
    ]
    return "; ".join(lines[:30]) if lines else None


def _threat_type(case: CaseData) -> Optional[str]:
    summary = _summary(case.alert)
    triage = _obj(summary.get("triage"))
    response = _obj(summary.get("response"))
    tactics, techniques = _mitre(_obj(case.alert.normalized))
    parts: List[str] = []
    if response.get("threat_type"):
        parts.append(f"Likely threat type: {response.get('threat_type')}.")
    categories = _strings(triage.get("threat_categories"), 10)
    if categories:
        parts.append(f"Triage categories: {', '.join(categories)}.")
    if case.alert.category:
        parts.append(f"Alert category: {case.alert.category}.")
    if tactics or techniques:
        parts.append(f"MITRE ATT&CK: {', '.join([*tactics, *techniques])}.")
    return " ".join(parts) if parts else None


def _timeline_text(case: CaseData) -> str:
    alert = case.alert
    parts = [f"First observed {_iso(alert.occurred_at)}; ingested {_iso(alert.ingested_at)}."]
    for esc in case.escalations:
        parts.append(f"Escalated ({esc.level}) {_iso(esc.created_at)}: {esc.reason}.")
        if esc.decided_at is not None:
            parts.append(f"Analyst decision {esc.decision} at {_iso(esc.decided_at)}.")
    executed = [a for a in case.actions if a.executed_at is not None]
    for a in executed[:10]:
        parts.append(f"{a.action_type} on {a.target} {a.status} at {_iso(a.executed_at)}.")
    if alert.closed_at is not None:
        parts.append(f"Case closed {_iso(alert.closed_at)}.")
    return " ".join(parts)


def _common_fields(case: CaseData) -> List[DraftField]:
    alert = case.alert
    first_escalation = min((e.created_at for e in case.escalations), default=None)
    return [
        DraftField("reporting_entity", "Reporting entity (name, sector, contact point)", None, "requires_human",
                   help="Your organisation's identification as registered with the competent authority."),
        DraftField("recipient", "CSIRT or competent authority", None, "requires_human",
                   help="The national CSIRT or authority you report to, and its reporting channel."),
        DraftField("significance", "Why the incident is significant (Art. 23(3))", None, "requires_human",
                   help="Severe operational disruption or financial loss, or considerable damage to others. "
                        "LG-SOTF does not make this determination."),
        DraftField("internal_reference", "Internal reference", f"LG-SOTF alert {alert.id}"
                   + (f" (case {alert.case_key})" if alert.case_key else ""), "case_data", required=False),
        DraftField("detection_time", "Detected (first observed / ingested)",
                   f"{_iso(alert.occurred_at)} / {_iso(alert.ingested_at)}", "case_data"),
        DraftField("awareness_time", "When the entity became aware", None, "requires_human",
                   help="The 24 h / 72 h deadlines run from awareness. "
                        + (f"First escalation to an analyst: {_iso(first_escalation)}." if first_escalation
                           else "No escalation was recorded.")),
    ]


def build_draft_fields(case: CaseData, stage: str) -> List[DraftField]:
    """The stage's fields in submission order (deterministic for the same case data)."""
    if stage not in STAGES:
        raise ValueError(f"unknown NIS2 report stage: {stage!r}")
    alert = case.alert
    normalized = _obj(alert.normalized)
    analysis = _obj(_summary(alert).get("analysis"))
    cross_border = DraftField(
        "cross_border_impact", "Cross-border impact", None, "requires_human",
        help="Whether other Member States are or could be affected. Affected assets from the case: "
             + _asset_text(normalized),
    )
    fields = _common_fields(case)
    summary_line = f"{alert.title} (severity {alert.severity}{', category ' + alert.category if alert.category else ''})"
    if stage == "early_warning":
        fields += [
            DraftField("incident_summary", "Short description", _clip(summary_line), "case_data"),
            DraftField("suspected_malicious", "Suspected unlawful or malicious act", _clip(_malicious_assessment(case)),
                       "case_data", help="Prefilled from the case; confirm before submitting."),
            cross_border,
            DraftField("assistance_requested", "Assistance requested from the CSIRT", None, "requires_human",
                       required=False),
        ]
    elif stage == "notification":
        iocs = _iocs(case)
        fields += [
            DraftField("suspected_malicious", "Suspected unlawful or malicious act (update)",
                       _clip(_malicious_assessment(case)), "case_data"),
            cross_border,
            DraftField("initial_assessment", "Initial assessment",
                       _clip(" ".join(p for p in (summary_line + ".", str(analysis.get("conclusion") or "")) if p)),
                       "case_data", help="From the automated analysis and analyst decisions; edit as needed."),
            DraftField("severity", "Severity", _severity_text(case), "case_data"),
            DraftField("impact", "Impact (affected assets, services, users)", _clip(_asset_text(normalized)),
                       "case_data", help="Add business impact: affected services, number of users, duration."),
            DraftField("indicators_of_compromise", "Indicators of compromise",
                       "\n".join(iocs) if iocs else None, "case_data" if iocs else "requires_human",
                       required=False, help="Where available (Art. 23(4)(b))."),
            DraftField("actions_taken", "Response actions taken so far",
                       _actions_text(case.actions, DONE_STATUSES | PENDING_STATUSES), "case_data", required=False),
        ]
    else:
        fields += [
            DraftField("detailed_description", "Detailed description (including severity and impact)",
                       _clip(f"{summary_line}. {_timeline_text(case)} {_severity_text(case)} "
                             f"Affected assets: {_asset_text(normalized)}"), "case_data"),
            DraftField("root_cause", "Type of threat or root cause", _clip(_threat_type(case)),
                       "case_data" if _threat_type(case) else "requires_human",
                       help="The likely threat type is prefilled; the root cause needs your investigation."),
            DraftField("mitigations_applied", "Applied mitigation measures", _actions_text(case.actions, DONE_STATUSES),
                       "case_data" if _actions_text(case.actions, DONE_STATUSES) else "requires_human",
                       help="Dry-run actions did not change anything; say so or replace them."),
            DraftField("mitigations_ongoing", "Ongoing mitigation measures",
                       _actions_text(case.actions, PENDING_STATUSES), "case_data", required=False),
            cross_border,
            DraftField("lessons_learned", "Lessons learned and follow-up", None, "requires_human", required=False),
        ]
    return fields


class IncidentNarrative(BaseModel):
    """The model's narrative. Text only; it never changes a prefilled field."""

    model_config = ConfigDict(extra="ignore")

    narrative: clipped_str(3_000, description="Factual narrative of the incident for the report, 3-8 sentences.")  # type: ignore[valid-type]


NARRATIVE_SYSTEM = (
    "You help a security analyst draft an incident report for a national CSIRT under the EU NIS2 directive. "
    "Write a factual, neutral narrative from the case data only. Do not speculate beyond the data, do not claim "
    "the incident is or is not significant, do not name individuals, and do not include instructions. "
    "The analyst will review and edit your text before anything is submitted."
)
NARRATIVE_TASKS = {
    "early_warning": "Write a short narrative for the 24-hour early warning: what was detected and whether malicious "
    "activity is suspected.",
    "notification": "Write a narrative for the 72-hour incident notification: what happened, the initial assessment "
    "of severity and impact, and the indicators of compromise found.",
    "final": "Write a narrative for the final report: a detailed description, the likely threat type, and the "
    "mitigation measures applied.",
}


def narrative_input(case: CaseData) -> Dict[str, Any]:
    """Alert-derived case data for the model (goes into the untrusted data block)."""
    alert = case.alert
    summary = _summary(alert)
    analysis = _obj(summary.get("analysis"))
    normalized = _obj(alert.normalized)
    data: Dict[str, Any] = jsonable(  # a mapping comes back as a dict
        {
            "title": alert.title,
            "description": normalized.get("description"),
            "severity": alert.severity,
            "category": alert.category,
            "occurred_at": alert.occurred_at,
            "disposition": alert.disposition,
            "entities": normalized.get("entities"),
            "mitre": normalized.get("mitre"),
            "analysis": {k: analysis.get(k) for k in ("verdict", "threat_score", "conclusion", "reasoning")},
            "escalations": [
                {"level": e.level, "reason": e.reason, "decision": e.decision, "decided_at": e.decided_at}
                for e in case.escalations[:10]
            ],
            "actions": [{"action_type": a.action_type, "target": a.target, "status": a.status} for a in case.actions[:20]],
        }
    )
    return data


@dataclass(frozen=True)
class NarrativeResult:
    narrative: Optional[Dict[str, Any]]
    error: Optional[str]


async def draft_narrative(
    settings: Settings,
    tenant_id: str,
    case: CaseData,
    stage: str,
    *,
    budget: Optional[TokenBudget] = None,
    budget_limit: BudgetLimit = USE_DEFAULT,
    model_factory: Callable[[Tier, Settings], BaseChatModel] = get_chat_model,
) -> NarrativeResult:
    """An optional model-written narrative; failures return an error message instead of raising.

    The case data goes into the untrusted data block of the prompt, so text
    in an alert cannot pose as instructions; the output is only ever shown
    as a labelled suggestion and never fills or changes a prefilled field.
    """
    if not settings.llm.enabled:
        return NarrativeResult(None, "no LLM is configured")
    tier: Tier = "fast"
    try:
        model = model_factory(tier, settings)
        prompt = build_prompt(NARRATIVE_SYSTEM, NARRATIVE_TASKS[stage], narrative_input(case), settings=settings)
        result = await ainvoke_structured(
            model,
            IncidentNarrative,
            prompt.messages,
            agent="nis2_report",
            tier=tier,
            tenant_id=tenant_id,
            settings=settings,
            budget=budget,
            budget_limit=budget_limit,
        )
    except LLMBudgetExceeded:
        return NarrativeResult(None, "the tenant's daily LLM token budget is exhausted")
    except LLMRefusal:
        return NarrativeResult(None, "the model declined to write a narrative")
    except LLMError as exc:
        log.warning("nis2.narrative_unusable", error_type=type(exc).__name__)
        return NarrativeResult(None, "the model's answer could not be used")
    except Exception as exc:  # noqa: BLE001 - provider/transport errors must not fail the deterministic draft
        log.warning("nis2.narrative_failed", error_type=type(exc).__name__)
        return NarrativeResult(None, "the model could not be reached")
    provenance = model_provenance(model, tier)
    return NarrativeResult(
        {
            "text": str(result.narrative).strip(),
            "label": AI_LABEL,
            "provider": provenance["provider"],
            "model": provenance["model"],
        },
        None,
    )


def render_draft_html(
    *,
    alert_id: str,
    stage: str,
    fields: Sequence[Mapping[str, Any]],
    generated_at: str,
    ai_narrative: Optional[Mapping[str, Any]],
) -> str:
    """The draft as a standalone HTML document with the disclaimer and field provenance."""
    rows: List[str] = []
    for f in fields:
        source = f.get("source")
        tag = {
            "case_data": h.badge("from case data"),
            "requires_human": h.badge("to be completed by you", "human"),
            "ai_drafted": h.badge(AI_LABEL, "ai"),
        }.get(str(source), "")
        value = f.get("value")
        shown = h.esc(value) if value else '<span class="muted">— to be completed —</span>'
        help_text = f'<br><span class="muted">{h.esc(f.get("help"))}</span>' if f.get("help") else ""
        required = " *" if f.get("required") else ""
        rows.append(
            f'<tr><th align="left" bgcolor="#eeeeee">{h.esc(f.get("label"))}{required}</th>'
            f'<td style="white-space: pre-wrap">{shown}{help_text}</td><td>{tag}</td></tr>'
        )
    body = [
        f'<div class="danger"><strong>DRAFT.</strong> {h.esc(DISCLAIMER)}</div>',
        h.kv_table(
            [
                ("Stage", STAGE_TITLES.get(stage, stage)),
                ("Deadline", DEADLINES.get(stage)),
                ("Case", f"LG-SOTF alert {alert_id}"),
                ("Draft generated", generated_at),
            ]
        ),
        f'<div class="notice">{h.esc(h.UNTRUSTED_NOTICE)}</div>',
        '<table border="1" cellpadding="4" cellspacing="0" width="100%">'
        '<tr><th align="left" bgcolor="#eeeeee">Field (* required)</th><th align="left" bgcolor="#eeeeee">Value</th>'
        '<th align="left" bgcolor="#eeeeee">Source</th></tr>' + "".join(rows) + "</table>",
    ]
    if ai_narrative:
        body.append(
            h.section(
                "Narrative",
                f"<p>{h.badge(AI_LABEL, 'ai')} <span class=\"muted\">{h.esc(ai_narrative.get('provider'))} / "
                f"{h.esc(ai_narrative.get('model'))}</span></p>",
                h.pre(str(ai_narrative.get("text") or "")),
            )
        )
    return h.document(STAGE_TITLES.get(stage, "NIS2 report draft") + " — DRAFT", body,
                      subtitle="Prepared with LG-SOTF from case data. Complete, review and submit it yourself.")


# --------------------------------------------------------------- storing a draft


def _event_value(value: Optional[str]) -> Optional[str]:
    if value is None or len(value) <= MAX_EVENT_VALUE_CHARS:
        return value
    return value[:MAX_EVENT_VALUE_CHARS]


async def record_draft(
    repos: Repositories,
    audit: AuditLogger,
    tenant_id: str,
    actor: Actor,
    alert_id: str,
    *,
    stage: str,
    fields: List[Dict[str, Any]],
    narrative: Optional[Dict[str, Any]],
    author: str,
    timeline_actor: Actor,
) -> AlertEvent:
    """Store a draft as an ``incident_report_draft`` timeline event; audited ``alert.incident_report_drafted``.

    The event keeps each field's key, source and value (values clipped) and
    the SHA-256 of the whole draft, so a submitted report can be matched to it.
    """
    draft = {"stage": stage, "fields": fields, "ai_narrative": narrative}
    draft_sha256 = hashlib.sha256(
        json.dumps(draft, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    async with repos.db.tenant_tx(tenant_id) as conn:
        event = await repos.alert_events.append(
            tenant_id,
            alert_id,
            "incident_report_draft",
            actor_type=timeline_actor.type,
            actor_id=timeline_actor.id,
            data={
                "stage": stage,
                "framework": "NIS2 Art. 23",
                "status": "draft_not_submitted",
                "author": author,
                "draft_sha256": draft_sha256,
                "fields": [
                    {"key": f["key"], "source": f["source"], "value": _event_value(f["value"])} for f in fields
                ],
                "ai_narrative": {**narrative, "text": _event_value(narrative["text"])} if narrative else None,
            },
            conn=conn,
        )
        await audit.record(
            tenant_id,
            "alert.incident_report_drafted",
            "alert",
            alert_id,
            actor_type=actor.type,
            actor_id=actor.id,
            details={
                "stage": stage,
                "event_id": event.id,
                "draft_sha256": draft_sha256,
                "ai_narrative": narrative is not None,
            },
            conn=conn,
        )
    return event


__all__ = [
    "AI_LABEL",
    "DEADLINES",
    "DISCLAIMER",
    "STAGES",
    "CaseData",
    "DraftField",
    "IncidentNarrative",
    "NARRATIVE_SYSTEM",
    "NarrativeResult",
    "NARRATIVE_TASKS",
    "build_draft_fields",
    "draft_narrative",
    "load_case",
    "narrative_input",
    "record_draft",
    "render_draft_html",
]
