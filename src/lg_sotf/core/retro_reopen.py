"""The safety net of decision policy v3 (FIX-3): a related threat reopens the alerts the models closed alone.

At the autonomy tier ``auto_full_audit`` the models close every alert the
deep tier judged benign (:mod:`lg_sotf.domain.closure`); the forward gates of
FIX-1 and FIX-2 (thresholds, campaign check) are gone. Instead, when an alert
becomes a threat:

* the workflow plans a response for it, or closes it malicious;
* it is escalated with a model verdict of malicious or suspicious (the deep
  tier's ``malicious``, the fast tier's ``suspicious``, ``likely_threat`` or
  ``confirmed_threat``);
* an analyst decides ``true_positive`` on it;
* a blind audit labels it ``malicious``;

:func:`reopen_related_model_closes` reopens every alert of the same tenant
that the models closed alone (close reason ``ai_closed:*``) in the previous
:data:`REOPEN_WINDOW`, and that shares a host, user or IP with it. Each one
is **folded** into the threat's open escalation: attached to it as a
related alert and set to ``waiting_human`` under that case, with no new run
and no new escalation, so the analyst sees one case holding the related
alerts; the analyst's decision on the case settles it
(:func:`settle_folded`). Only when there is no open case (a response plan
without an escalation, or a case already decided) is it queued for a new
run instead, marked ``reopened`` so the policy never closes it on the
models' word again. Either way it is audited ``alert.reopened`` (reason
``related_threat``), with an ``alert.reopened`` event on its timeline. A single attack step the model
misjudged therefore resurfaces as soon as the attack shows itself anywhere.

It is idempotent (an alert already reopened is no longer closed, so it is
not selected again) and tenant-scoped (every query runs in the tenant's
transaction). The callers count a failure in
``lgsotf_retro_reopen_failures_total`` and log it as an error; it never
fails the threat's own decision.

IPs are matched whatever their role in the alert (source or destination):
the canonical alert does not keep the role, and a wider match only reopens
more.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, List, Mapping, Optional, Sequence

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.models.vocabulary import BENIGN_DECISIONS
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import RETRO_REOPEN_FAILURES, RETRO_REOPENED

log = get_logger(__name__)

REOPEN_WINDOW = timedelta(hours=24)
REOPEN_REASON = "related_threat"
REOPEN_ACTION = "alert.reopened"
#: The close reason a reopened alert carries until it closes again (it no longer reads ``ai_closed:*``).
REOPENED_CLOSE_REASON = "reopened:related_threat"
#: How a reopened alert came back: folded into the threat's open case, or queued for its own review run.
FOLDED, REQUEUED = "folded", "requeued"
ACTIVE_ESCALATION_STATUSES = frozenset({"open", "claimed"})
MAX_REOPEN = 200
MAX_ENTITY_VALUES = 50
#: The model verdicts that make an escalated alert a threat for the safety net.
THREAT_ASSESSMENTS = frozenset({"suspicious", "likely_threat", "confirmed_threat"})


def judged_threat(triage: Mapping[str, Any], analysis: Mapping[str, Any]) -> bool:
    """Whether a model judged the alert malicious or suspicious (the escalation path of the safety net)."""
    return analysis.get("verdict") == "malicious" or triage.get("threat_assessment") in THREAT_ASSESSMENTS


def _values(entities: Any, kind: str) -> List[str]:
    values = entities.get(kind) if isinstance(entities, Mapping) else None
    if not isinstance(values, list):
        return []
    return [v for v in values[:MAX_ENTITY_VALUES] if isinstance(v, str) and v]


def _closed_by_models(alert: Any) -> bool:
    summary = alert.summary if isinstance(alert.summary, Mapping) else {}
    reason = summary.get("close_reason")
    return alert.status == "closed" and isinstance(reason, str) and reason.startswith("ai_closed:")


async def reopen_related_model_closes(
    repos: Repositories,
    tenant_id: str,
    threat: Any,
    *,
    actor: Actor,
    escalation_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> List[str]:
    """Reopen the model-closed alerts related to ``threat`` (a stored alert); the ids reopened (see the module docs).

    Raises on a database error: the caller counts it (:func:`reopen_counted`).
    """
    now = now or datetime.now(UTC)
    entities = threat.entities if isinstance(threat.entities, Mapping) else {}
    candidates = await repos.alerts.model_closed_sharing_entities(
        tenant_id,
        hosts=_values(entities, "hosts"),
        users=_values(entities, "users"),
        ips=_values(entities, "ips"),
        since=now - REOPEN_WINDOW,
        exclude_alert_id=threat.id,
        limit=MAX_REOPEN,
    )
    reopened: List[str] = []
    for alert_id in candidates:
        if await _reopen_one(repos, tenant_id, alert_id, threat_id=threat.id, actor=actor, escalation_id=escalation_id):
            reopened.append(alert_id)
    return reopened


async def _active_escalation(repos: Repositories, tenant_id: str, escalation_id: Optional[str], conn: Any) -> Any:
    if escalation_id is None:
        return None
    try:
        escalation = await repos.escalations.get(tenant_id, escalation_id, conn=conn)
    except NotFound:
        return None
    return escalation if escalation.status in ACTIVE_ESCALATION_STATUSES else None


async def _reopen_one(
    repos: Repositories, tenant_id: str, alert_id: str, *, threat_id: str, actor: Actor, escalation_id: Optional[str]
) -> bool:
    async with repos.db.tenant_tx(tenant_id) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        if not _closed_by_models(alert):
            return False  # reopened already, or closed again by a person: nothing to do
        escalation = await _active_escalation(repos, tenant_id, escalation_id, conn)
        marker = {
            "reason": REOPEN_REASON, "threat_alert_id": threat_id, "escalation_id": escalation_id,
            "mode": FOLDED if escalation is not None else REQUEUED,
        }
        if escalation is not None:
            # Folded into the threat's case: one escalation holds the related alerts, no new run, no new case.
            deadline = escalation.sla_deadline or datetime.now(UTC) + REOPEN_WINDOW
            await repos.escalations.attach(
                tenant_id, escalation.id, alert_id, priority=escalation.priority, level=escalation.level,
                sla_deadline=deadline, conn=conn,
            )
            await repos.alerts.update_status(tenant_id, alert_id, "waiting_human", conn=conn)
            summary = {"reopened": marker, "close_reason": REOPENED_CLOSE_REASON, "escalation_id": escalation.id,
                       "escalation_attached": True}
        else:
            # No open case to fold into (a plan without an escalation, a decided one): a new run reviews it.
            run = await repos.runs.upsert_queued(tenant_id, alert_id, requeue_terminal=True, conn=conn)
            if run.status != "queued":
                raise InvalidTransition("workflow run", alert_id, run.status, "queued")
            await repos.alerts.update_status(tenant_id, alert_id, "queued", conn=conn)
            summary = {"reopened": marker, "close_reason": REOPENED_CLOSE_REASON}
        await repos.alerts.update(tenant_id, alert_id, disposition=None, summary=summary, conn=conn)  # type: ignore[arg-type]
        await repos.alert_events.append(
            tenant_id, alert_id, REOPEN_ACTION, node="retro_reopen", actor_type=actor.type, actor_id=actor.id,
            data=dict(marker), conn=conn,
        )
        await AuditLogger(repos).record(
            tenant_id, REOPEN_ACTION, "alert", alert_id, actor_type=actor.type, actor_id=actor.id,
            details=dict(marker), conn=conn,
        )
    return True


async def settle_folded(
    repos: Repositories, tenant_id: str, alert_id: str, *, escalation_id: str, decision: str, decided_by: str
) -> bool:
    """Apply the analyst's decision on the case to an alert folded into it (it has no run waiting): close it
    ``malicious`` on ``true_positive``, ``benign`` on a benign decision; ``needs_more_info`` leaves it open.
    Returns whether the alert was folded into this escalation."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
        marker = alert.summary.get("reopened") if isinstance(alert.summary, Mapping) else None
        folded = (
            alert.status == "waiting_human" and isinstance(marker, Mapping) and marker.get("mode") == FOLDED
            and alert.summary.get("escalation_id") == escalation_id
        )
        if not folded:
            return False
        if decision == "true_positive":
            disposition = "malicious"
        elif decision in BENIGN_DECISIONS:
            disposition = "benign"
        else:
            return True
        await repos.alerts.update_status(tenant_id, alert_id, "processing", conn=conn)
        await repos.alerts.update(
            tenant_id, alert_id, disposition=disposition,
            summary={"close_reason": f"analyst:{decision}", "analyst_decision": decision}, conn=conn,
        )
        await repos.alerts.update_status(tenant_id, alert_id, "closed", conn=conn)
        await repos.alert_events.append(
            tenant_id, alert_id, "analyst.decision", node="await_analyst", actor_type="user", actor_id=decided_by,
            data={"decision": decision, "escalation_id": escalation_id, "folded": True}, conn=conn,
        )
    return True


async def reopen_counted(
    repos: Repositories,
    tenant_id: str,
    threat: Any,
    *,
    actor: Actor,
    path: str,
    escalation_id: Optional[str] = None,
) -> Sequence[str]:
    """:func:`reopen_related_model_closes` for a threat path: a failure is counted and logged as an error, never
    raised (the threat's own decision stands); returns the ids reopened."""
    try:
        reopened = await reopen_related_model_closes(
            repos, tenant_id, threat, actor=actor, escalation_id=escalation_id
        )
    except Exception as exc:  # noqa: BLE001 - counted and logged as an error: an alerting rule can page on it
        RETRO_REOPEN_FAILURES.labels(path=path).inc()
        log_failure(log, "retro_reopen.failed", exc, level="error", alert_id=getattr(threat, "id", None),
                    path=path, error_type=type(exc).__name__)
        return []
    if reopened:
        RETRO_REOPENED.labels(path=path).inc(len(reopened))
        log.info("retro_reopen.reopened", alert_id=threat.id, path=path, count=len(reopened))
    return reopened
