"""The scenario of the console v2 prototype's case screen, as today's workflow would store it.

``docs/design/console-v2`` draws CASE-2291 at Northwind Logistics: nine
alerts on one host and one user in 20 hours. This fixture holds the rows
today's platform would have for it: the escalation of the Word alert
(:mod:`tests.fixtures.investigation`), two alerts attached to it that wait
for a person, one still being investigated, two alerts the AI closed on the
model's word that the safety net linked and left closed, and three more
closed alerts that show the other ways an alert closes (an analyst on
another case, a suppression rule, an earlier analyst verdict). Seven
response actions are on the ledger. Everything is invented and synthetic.

:func:`open_case` and :func:`decided_case` are the facts; the frontend's
test fixture (``src/lg_front/src/test/caseReadModels.ts``) is the backend's
own assembly of them (:func:`frontend_fixture`), and
``tests/unit/domain/test_case.py`` fails when the two drift apart.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence
from uuid import UUID

from lg_sotf.domain import closure
from lg_sotf.domain.case import AuditFacts, CaseEscalation, CaseEvent, CaseFacts, MemberFacts, assemble
from lg_sotf.domain.case.model import CaseAction
from lg_sotf.domain.investigation import AlertFacts
from lg_sotf.domain.investigation.model import ProposedActionGuardrail
from tests.fixtures import investigation as prototype

NOW = datetime(2026, 11, 14, 10, 4, 12, tzinfo=UTC)
CASE_ID = "esc-2291"
TENANT = "northwind"
THREAT = "alr-48213"
OPENED_AT = datetime(2026, 11, 14, 9, 44, 35, tzinfo=UTC)
CLAIMED_AT = datetime(2026, 11, 14, 9, 52, 10, tzinfo=UTC)
INES = "5b0c7a52-6f0e-4c58-9d0e-1f2a3b4c5d6e"
EMAILS = {INES: "ines.moreau@brightwater.example"}
TODAY = datetime(2026, 11, 14, tzinfo=UTC)
#: The guardrail check of an action that waits: checked now, against the tenant's policy, and passed.
PASSED = ProposedActionGuardrail(verdict="passed")


def at(clock: str, day: datetime = TODAY) -> datetime:
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    return day + timedelta(hours=hours, minutes=minutes, seconds=seconds)


def node(ts: datetime, name: str, **data: Any) -> CaseEvent:
    return CaseEvent(ts=ts, event_type="node.completed", node=name, data=data, actor_type="system", actor_id="workflow")


def event(ts: datetime, kind: str, user: Optional[str] = None, **data: Any) -> CaseEvent:
    return CaseEvent(ts=ts, event_type=kind, data=data, actor_type="user" if user else "agent", actor_id=user or "workflow")


def member(
    alert_id: str, title: str, severity: str, occurred: datetime, status: str, summary: Dict[str, Any], *,
    entities: Optional[Dict[str, List[str]]] = None, events: Sequence[CaseEvent] = (), closed: Optional[datetime] = None,
    disposition: Optional[str] = None, audit: Optional[AuditFacts] = None, hidden: bool = False,
) -> MemberFacts:
    return MemberFacts(
        alert=AlertFacts(
            id=alert_id, tenant_id=TENANT, status=status, severity=severity, summary=summary, view={},
            ingested_at=occurred + timedelta(seconds=4), closed_at=closed,
        ),
        title=title,
        occurred_at=occurred,
        disposition=disposition,
        entities=entities if entities is not None else {"hosts": [prototype.HOST]},
        events=list(events),
        audit=audit,
        hidden=hidden,
    )


def _threat() -> MemberFacts:
    occurred = prototype.OCCURRED_AT
    events = [
        CaseEvent(ts=prototype.INGESTED_AT + offset, event_type="node.completed", node=name, data=data,
                  actor_type=actor, actor_id="workflow")
        for offset, name, actor, data in prototype.node_events()
    ]
    events.append(node(at("09:44:35"), "plan_response", auto=0, awaiting=4, blocked=1, done=0))
    return replace(
        member(THREAT, prototype.TITLE, "high", occurred, "waiting_human", prototype.summary(), events=events),
        alert=AlertFacts(id=THREAT, tenant_id=TENANT, status="waiting_human", severity="high",
                         summary=prototype.summary(), view={}, ingested_at=prototype.INGESTED_AT),
        entities=prototype.normalized()["entities"],
    )


def _model_closed(alert_id: str, title: str, severity: str, clock: str, *, users: Sequence[str] = (),
                  audit: Optional[AuditFacts] = None) -> MemberFacts:
    occurred = at(clock)
    closed = occurred + timedelta(seconds=6)
    summary = {
        "close_reason": closure.MODEL_CLOSE_REASON,
        "decision": {"route": "close", "code": "model_closed", "autonomy_tier": "auto_full_audit"},
        "linked": [{"threat_alert_id": THREAT, "escalation_id": CASE_ID, "at": OPENED_AT.isoformat()}],
    }
    events = [
        node(occurred + timedelta(seconds=5), "decide", route="close", code="model_closed", autonomy_tier="auto_full_audit"),
        node(closed, "close", disposition="benign", close_reason=closure.MODEL_CLOSE_REASON),
        event(OPENED_AT, "alert.linked", reason="related_threat", threat_alert_id=THREAT, escalation_id=CASE_ID),
    ]
    return member(alert_id, title, severity, occurred, "closed", summary, events=events, closed=closed,
                  disposition="benign", audit=audit,
                  entities={"hosts": [prototype.HOST], "users": list(users)})


def members() -> List[MemberFacts]:
    """The nine alerts of the case, the alert it was opened for first."""
    yesterday = TODAY - timedelta(days=1)
    logon = at("16:20:00", yesterday)
    return [
        _threat(),
        member(
            "alr-47702", "Failed logon burst: 6 failures in 2 minutes", "low", logon, "closed",
            {"close_reason": "analyst:benign_positive", "analyst_decision": "benign_positive"},
            entities={"users": [prototype.USER]}, closed=at("16:41:00", yesterday), disposition="benign",
            events=[
                node(logon + timedelta(seconds=40), "escalate", level="L1", priority=3),
                event(at("16:41:00", yesterday), "analyst.decision", INES, decision="benign_positive", escalation_id="esc-2207"),
                node(at("16:41:02", yesterday), "close", disposition="benign", close_reason="analyst:benign_positive"),
            ],
        ),
        _model_closed(
            "alr-48190", "Package installed: Adobe Acrobat Reader update 24.004", "info", "09:14:07",
            audit=AuditFacts(label="benign", agreement=True, labelled_at=at("09:58:40")),
        ),
        _model_closed("alr-48212", "Outlook opened a Word attachment from the internet zone", "low", "09:41:49",
                      users=[prototype.USER]),
        member(
            "alr-48219", "LSASS memory read by rundll32 via comsvcs.dll MiniDump", "critical", at("09:43:58"),
            "waiting_human", {"analysis": {"verdict": "malicious"}, "decision": {"code": "high_risk"}},
            events=[node(at("09:44:36"), "escalate", level="L2", priority=9)],
        ),
        member(
            "alr-48214", "Periodic HTTPS beacon to a newly registered domain", "high", at("09:44:02"),
            "waiting_approval", {"analysis": {"verdict": "malicious"}, "decision": {"code": "high_risk"}},
            entities={"hosts": [prototype.HOST], "domains": [prototype.DOMAIN]},
            events=[node(at("09:44:40"), "plan_response", auto=0, awaiting=2, blocked=0, done=0)],
        ),
        member(
            "alr-48226", "Microsoft Defender signature update completed", "info", at("09:47:30"), "closed",
            {"close_reason": "suppression_rule",
             "suppressed_by": {"rule_id": "sup-014", "name": "Defender definition updates"}},
            closed=at("09:47:35"), disposition="benign",
            events=[node(at("09:47:35"), "gate", suppressed=True)],
        ),
        member(
            "alr-48231", "PowerShell listed every user in Active Directory (Get-ADUser)", "medium", at("09:51:16"),
            "closed",
            {"close_reason": "verdict_cache",
             "suppressed_by": {"source_alert_id": "alr-46011", "decision": "benign_positive"}},
            closed=at("09:51:21"), disposition="benign",
            events=[node(at("09:51:21"), "gate", suppressed=True, verdict_cache=True)],
        ),
        member(
            "alr-48247", 'Scheduled task "OneDriveSync" created by powershell.exe', "medium", at("10:01:44"),
            "processing", {},
        ),
    ]


def action(n: int, alert_id: str, action_type: str, target: str, risk: str, status: str, *,
           reversible: Optional[bool] = True, inverse: Optional[str] = None, note: Optional[str] = None,
           guardrail: Optional[ProposedActionGuardrail] = PASSED) -> CaseAction:
    return CaseAction(
        action_id=UUID(int=0x48213000 + n), action_type=action_type, target=target, risk=risk, status=status,
        reversible=reversible, inverse_action=inverse, irreversible_note=note, guardrail=guardrail,
        alert_id=alert_id, created_at=OPENED_AT + timedelta(seconds=n),
    )


def actions() -> List[CaseAction]:
    blocked = ProposedActionGuardrail(
        verdict="blocked", code="autonomy_disabled",
        reason="The tenant's autonomy policy disables actions of this risk.",
    )
    return [
        action(1, THREAT, "isolate_host", prototype.HOST, "high", "awaiting_approval", inverse="release_host"),
        action(2, THREAT, "block_domain", prototype.DOMAIN, "medium", "awaiting_approval", inverse="unblock_domain"),
        action(3, THREAT, "block_ip", prototype.ADDRESS, "low", "awaiting_approval", inverse="unblock_ip"),
        action(4, THREAT, "reset_password", f"{prototype.USER}@northwind.example", "critical", "blocked",
               reversible=False, note="A reset password cannot be restored.", guardrail=blocked),
        action(5, THREAT, "quarantine_file", "Invoice_INV-20931.docm", "medium", "dry_run", inverse="release_file"),
        action(6, "alr-48214", "block_url", prototype.SCRIPT_URL, "medium", "succeeded", inverse="unblock_url", guardrail=None),
        action(7, "alr-48214", "revoke_sessions", f"{prototype.USER}@northwind.example", "medium", "failed",
               reversible=False, note="Revoked sessions cannot be restored.", guardrail=None),
    ]


def escalation(**changes: Any) -> CaseEscalation:
    values: Dict[str, Any] = {
        "id": CASE_ID, "tenant_id": TENANT, "alert_id": THREAT, "status": "claimed", "version": 3,
        "created_at": OPENED_AT, "summary": prototype.escalation_summary(), "sla_deadline": at("10:08:12"),
        "assigned_to": INES, "claimed_at": CLAIMED_AT,
    }
    return CaseEscalation(**{**values, **changes})


def open_case() -> CaseFacts:
    """The case as the prototype draws it: claimed, waiting for its decision."""
    found = members()
    return CaseFacts(escalation=escalation(), now=NOW, members=found, total_alerts=len(found), emails=EMAILS,
                     actions=actions())


def decided_case() -> CaseFacts:
    """The same case after the analyst's true positive: the linked alerts are reopened (the case is decided, so a
    new run reviews each), and the alert the case was opened for is closed by the analyst."""
    decided_at = at("10:09:30")
    decided = escalation(status="decided", decision="true_positive", decided_by=INES, decided_at=decided_at,
                         decision_notes="The dump is visible in the process tree. Isolating the host.", version=4)
    marker = {"reason": "related_threat", "threat_alert_id": THREAT, "escalation_id": CASE_ID, "mode": "requeued"}
    out: List[MemberFacts] = []
    for m in members():
        if m.alert.id == THREAT:
            summary = {**m.alert.summary, "close_reason": "analyst:true_positive", "analyst_decision": "true_positive"}
            out.append(replace(
                m, disposition="malicious",
                alert=replace(m.alert, status="closed", summary=summary, closed_at=decided_at + timedelta(seconds=20)),
                events=[*m.events, event(decided_at, "analyst.decision", INES, decision="true_positive", escalation_id=CASE_ID),
                        node(decided_at + timedelta(seconds=20), "close", disposition="malicious",
                             close_reason="analyst:true_positive")],
            ))
        elif "linked" in m.alert.summary:
            summary = {**m.alert.summary, "reopened": marker, "close_reason": "reopened:related_threat"}
            out.append(replace(
                m, disposition=None,
                alert=replace(m.alert, status="queued", summary=summary, closed_at=None),
                events=[*m.events, event(decided_at + timedelta(seconds=1), "alert.reopened", INES, **marker)],
            ))
        else:
            out.append(m)
    return CaseFacts(escalation=decided, now=at("10:12:00"), members=out, total_alerts=len(out), emails=EMAILS,
                     actions=actions())


FRONTEND_HEADER = """/**
 * Case read models as `GET /cases/{id}` returns them, for the case page's tests and screenshots: the
 * console v2 prototype's case (nine alerts on one host, claimed and waiting for its decision), and the
 * same case after the analyst's true positive.
 *
 * Generated from the backend's own assembly (`lg_sotf.domain.case.assemble` over
 * `tests/fixtures/case.py`, printed by `python -m tests.fixtures.case`), then committed: they are what
 * the API serialises, not a hand-written guess, and `CaseOut` holds them to the OpenAPI schema
 * (contract.check.ts). `tests/unit/domain/test_case.py` fails when this file drifts from the backend.
 * Synthetic data only.
 */

import type { CaseOut } from '../modules/soc/api/types';
"""


def frontend_fixture() -> str:
    """The frontend's ``caseReadModels.ts``: the two cases as the API would serialise them."""
    parts = [FRONTEND_HEADER]
    for name, facts in (("OPEN_CASE", open_case()), ("DECIDED_CASE", decided_case())):
        body = json.dumps(assemble(facts).model_dump(mode="json"), indent=2, ensure_ascii=False)
        parts.append(f"export const {name}: CaseOut = {body};\n")
    return "\n".join(parts)


if __name__ == "__main__":
    print(frontend_fixture(), end="")
