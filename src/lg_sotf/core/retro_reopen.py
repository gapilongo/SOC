"""The safety net of decision policy v3 (FIX-3, AI-E3.15, AI-E3.16): what a related threat does to the alerts
the models closed alone, and what an open one does to a close that is being decided.

At the autonomy tier ``auto_full_audit`` the models close every alert the
deep tier judged benign (:mod:`lg_sotf.domain.closure`); the forward gates of
FIX-1 and FIX-2 (thresholds, campaign check) are gone. Two alerts **relate**
when they share a host or a user by relation key
(:func:`lg_sotf.domain.related.relation_keys`: short host name, bare account
name; never an IP address alone, never an account every host has). A threat
only a model stands behind links; a stronger signal acts. The stronger signal
is one predicate, :func:`lg_sotf.domain.related.hold_grade`, in both
directions: the alert is high or critical and a model judged it a threat, or
a person confirmed it. A response that only waits for an approval is still
the model's word: it links.

Backward: the threat comes after the close
------------------------------------------

When an alert becomes a threat, the safety net looks up the alerts of the
same tenant that the models closed alone (close reason ``ai_closed:*``) in
the previous :data:`REOPEN_WINDOW` and that relate to it.

**A model judged the threat, below hold grade**
(:func:`link_related_model_closes`): a low or medium alert that is escalated
after a model judged it a threat (the deep tier's ``malicious``, the fast
tier's ``likely_threat`` or ``confirmed_threat``; never ``suspicious``,
#352), or that gets a response plan the workflow only proposes (it waits
for a person's approval), or that the workflow closes malicious after a
response it only simulated in the tenant's dry-run mode.

A model's judgement on such an alert is not a confirmation (AI-E3.15: on
dev, one benign alert a model misjudged undid thirteen correct closes). Each
related alert is **linked** and stays closed: it is attached to the threat's
open escalation as a related alert when there is one, so the analyst sees it
in the case; it gets an entry in its summary's ``linked`` list (threat
alert, case, time) and is audited ``alert.linked`` (reason
``related_threat``), with an ``alert.linked`` event on its timeline. Its
status, disposition and close reason do not change, no run starts, and a
decision on the case never settles it
(:func:`lg_sotf.services.folded.settle_folded`): it stays closed by the
models, marked for audit. The threat keeps the ids it linked
(``linked_alert_ids`` in its summary). Each call links the related closes the
threat has not linked yet, newest first and at most :data:`MAX_REOPEN`, so
the calls of one run (response plan, escalation, close) reach older ones.

**The threat reaches hold grade or is confirmed**
(:func:`reopen_related_model_closes`):

* it is escalated or gets a response plan while it is high or critical and
  a model judged it a threat (AI-E3.16: the forward check would have held
  these closes, had the threat been looked at first);
* an analyst decides ``true_positive`` on it (the API, then the response
  plan and the malicious close of the run that decision resumes);
* an analyst approves a response action for it;
* a blind audit labels it ``malicious``;
* the workflow carries out a response action for it (``succeeded``), alone
  under the tenant's autonomy policy: once the platform has acted on a
  threat, the related alerts do not stay closed. A ``dry_run`` is a
  simulation and confirms nothing.

Each related alert is reopened, and so is every alert linked earlier to the
threat or attached to its case, however long ago it closed. Each one is
**folded** into the threat's open escalation: attached to it as a
related alert and set to ``waiting_human`` under that case, with no new run
and no new escalation, so the analyst sees one case holding the related
alerts; the analyst's decision on the case settles it
(:func:`lg_sotf.services.folded.settle_folded`), and a later case of the
threat takes it over when the first one asked for more information
(:func:`refold`). Only when there is no open case (a response plan
without an escalation, or a case already decided) is it queued for a new
run instead, marked ``reopened`` so the policy never closes it on the
models' word again. Either way it is audited ``alert.reopened`` (reason
``related_threat``), with an ``alert.reopened`` event on its timeline. A
single attack step the model misjudged therefore resurfaces as soon as a
serious step of the attack is seen anywhere on its host or user.

Both are idempotent (an alert already reopened is no longer closed, so it is
not selected again; an alert already linked to the threat is linked again
only to show it in a new case) and tenant-scoped (every query runs in the
tenant's transaction). The callers count a failure in
``lgsotf_retro_reopen_failures_total`` and log it as an error; it never
fails the threat's own decision. A shadow run runs neither: the call is
recorded in the run's sink (:func:`reopen_counted`, the one entry point of
both, is an egress boundary).

The closed alerts are read as a bounded candidate set (tenant, closed by the
models, closed in the window, newest first, at most
:data:`MAX_CLOSED_CANDIDATES`) and compared by relation key here. Past that
limit the newest ones are compared, the older ones are not, and the failure
counter and an error log say so (path ``candidates``).

Forward: the threat is there before the close
---------------------------------------------

When ``decide`` runs for an alert at the tier, :func:`related_open` reads
what the database holds about the tenant's other alerts and gives each
related one its role (:func:`lg_sotf.domain.related.classify`):

* **hold**: a hold-grade alert that is open (up to seven days from its
  ingestion), or one a person confirmed and that closed in the last 24
  hours. The model-led close is withheld and the alert goes to an analyst
  through the ordinary escalation path (:mod:`lg_sotf.domain.closure`).
* **in progress**: a high or critical alert on the same host that is being
  processed and changed in the last 15 minutes. Also withheld.
* **model only**: any other open alert of the last 24 hours that a model
  judged a threat or planned a response for, also while that response
  waits for an approval. It holds nothing: the alert
  closes on the models' word and is linked to that alert's case at once,
  through :func:`link_related_model_closes` (path ``forward``).

The candidates are read by tenant, state and time, newest first, at most
:data:`MAX_RELATED_CANDIDATES`. Past that limit, or when the read fails,
the check fails closed without failing the run: the digest says
``unchecked`` and the alert goes to an analyst (:func:`related_open_counted`).
A ``failed`` alert never holds. An alert that is only queued has not been
looked at; if it reaches hold grade later, the backward net reopens the
close.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.state import RelatedOpenDigest
from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.domain.related import (
    HOLD_WINDOW,
    LINK_WINDOW,
    MODEL_THREATS,
    RelatedFacts,
    related_digest,
    relation_keys,
)
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import RETRO_LINKED, RETRO_REOPEN_FAILURES, RETRO_REOPENED
from lg_sotf.security.shadow import egress, sink
from lg_sotf.services.folded import FOLDED, REQUEUED, closed_by_models, folded_into

log = get_logger(__name__)

REOPEN_WINDOW = LINK_WINDOW
REOPEN_REASON = "related_threat"
REOPEN_ACTION = "alert.reopened"
LINK_ACTION = "alert.linked"
#: The newest links one alert's summary keeps (one per threat).
MAX_LINKS = 20
#: The newest alerts a threat remembers it linked (``linked_alert_ids``).
MAX_LINKED_IDS = 1_000
#: The close reason a reopened alert carries until it closes again (it no longer reads ``ai_closed:*``).
REOPENED_CLOSE_REASON = "reopened:related_threat"
ACTIVE_ESCALATION_STATUSES = frozenset({"open", "claimed"})
MAX_REOPEN = 200
#: The alerts the models closed in the window that one call of the safety net compares with a threat.
MAX_CLOSED_CANDIDATES = 20_000
#: The open threats (and serious alerts in progress) of a tenant that one decision compares with its alert. With
#: more than that the check is not complete, so it fails closed (``unchecked``).
MAX_RELATED_CANDIDATES = 2_000
#: Why a related-alert check did not complete (the digest's ``unchecked``).
READ_FAILED, TOO_MANY = "read_failed", "too_many_candidates"


def _listed(summary: Any, key: str) -> List[Any]:
    value = summary.get(key) if isinstance(summary, Mapping) else None
    return list(value) if isinstance(value, list) else []


def _linked_ids(threat: Any) -> List[str]:
    """The alerts ``threat`` (a stored alert) linked so far."""
    return [a for a in _listed(threat.summary, "linked_alert_ids") if isinstance(a, str)]


async def _related(repos: Repositories, tenant_id: str, threat: Any, now: datetime, *, unlinked: bool = False) -> List[str]:
    """Ids of the alerts the models closed alone in the window that relate to ``threat`` (a shared host or user by
    relation key), newest first, at most :data:`MAX_REOPEN`; ``unlinked``: only those the threat has not linked
    yet. Past :data:`MAX_CLOSED_CANDIDATES` closed alerts the older ones are not compared: counted and logged."""
    keys = relation_keys(threat.entities)
    if not keys:
        return []
    closed = await repos.alerts.model_closed_candidates(
        tenant_id, since=now - REOPEN_WINDOW, exclude_alert_id=threat.id, not_linked_to=unlinked,
        limit=MAX_CLOSED_CANDIDATES + 1,
    )
    if len(closed) > MAX_CLOSED_CANDIDATES:
        RETRO_REOPEN_FAILURES.labels(path="candidates").inc()
        log.error("retro_reopen.too_many_candidates", alert_id=threat.id, limit=MAX_CLOSED_CANDIDATES)
    related = [c.id for c in closed[:MAX_CLOSED_CANDIDATES] if keys & relation_keys(c.entities)]
    return related[:MAX_REOPEN]


async def related_open(
    repos: Repositories, tenant_id: str, alert_id: str, *, now: Optional[datetime] = None
) -> RelatedOpenDigest:
    """What the database holds, at this moment, about the alerts related to this one: the ids of the ones that
    hold a model-led close back (``threats``), of the high or critical alerts in progress on its hosts
    (``in_progress``) and of the threats only a model stands behind (``model_only``: the close is linked to their
    case); see the module docs. ``{"unchecked": "too_many_candidates"}`` when the tenant has more open threats
    than one decision compares. Read in the tenant's transaction; raises on a database error
    (:func:`related_open_counted` turns that into an unchecked digest)."""
    now = now or datetime.now(UTC)
    alert = await repos.alerts.get(tenant_id, alert_id)
    if not relation_keys(alert.entities):
        return {"threats": [], "in_progress": [], "model_only": []}
    rows = await repos.alerts.related_candidates(
        tenant_id, exclude_alert_id=alert_id, open_since=now - HOLD_WINDOW, closed_since=now - LINK_WINDOW,
        threat_assessments=sorted(MODEL_THREATS), limit=MAX_RELATED_CANDIDATES + 1,
    )
    if len(rows) > MAX_RELATED_CANDIDATES:
        return {"unchecked": TOO_MANY}
    others = [
        RelatedFacts(
            id=r.id, status=r.status, severity=r.severity, entities=r.entities, threat_assessment=r.threat_assessment,
            verdict=r.verdict, planned=r.planned, confirmed=r.confirmed, ingested_at=r.ingested_at,
            changed_at=r.changed_at,
        )
        for r in rows
    ]
    digest = related_digest(alert.entities, others, now)
    return {"threats": digest["threats"], "in_progress": digest["in_progress"], "model_only": digest["model_only"]}


async def related_open_counted(repos: Repositories, tenant_id: str, alert_id: str) -> RelatedOpenDigest:
    """:func:`related_open` for the ``decide`` step: it never raises. A read that fails is counted
    (``lgsotf_retro_reopen_failures_total``, path ``related_open``), logged as an error and answered
    ``{"unchecked": "read_failed"}``: the alert goes to an analyst, and the run goes on."""
    try:
        digest = await related_open(repos, tenant_id, alert_id)
    except Exception as exc:  # noqa: BLE001 - fail closed without failing the run: counted, logged, escalated
        RETRO_REOPEN_FAILURES.labels(path="related_open").inc()
        log_failure(log, "related_open.failed", exc, level="error", alert_id=alert_id, error_type=type(exc).__name__)
        return {"unchecked": READ_FAILED}
    if "unchecked" in digest:
        RETRO_REOPEN_FAILURES.labels(path="related_open").inc()
        log.error("related_open.too_many_candidates", alert_id=alert_id, limit=MAX_RELATED_CANDIDATES)
    return digest


def forward_links(summary: Any) -> List[str]:
    """The open threats only a model stands behind that the decision recorded for an alert (its summary's
    ``related_open.model_only``): once the models close the alert, it is linked to each one's case."""
    related = summary.get("related_open") if isinstance(summary, Mapping) else None
    return [threat for threat in _listed(related, "model_only") if isinstance(threat, str)]


async def link_related_model_closes(
    repos: Repositories,
    tenant_id: str,
    threat: Any,
    *,
    actor: Actor,
    escalation_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> List[str]:
    """Link the model-closed alerts related to ``threat`` (a stored alert) to its open case: they stay closed. The
    ids of the alerts linked to this threat for the first time (see the module docs).

    Raises on a database error: the caller counts it (:func:`reopen_counted`).
    """
    now = now or datetime.now(UTC)
    related = await _related(repos, tenant_id, threat, now, unlinked=True)
    # Kept on the threat first: a confirmation reopens them whenever it comes, even if a link below fails.
    async with repos.db.tenant_tx(tenant_id) as conn:
        known = _linked_ids(await repos.alerts.get_locked(tenant_id, threat.id, conn=conn))
        ids = list(dict.fromkeys([*known, *related]))[-MAX_LINKED_IDS:]
        if ids != known:
            await repos.alerts.update(tenant_id, threat.id, summary={"linked_alert_ids": ids}, conn=conn)
    # The ones linked earlier that the threat's open case does not show yet (it opened after the link) join it.
    case = await _active_escalation(repos, tenant_id, escalation_id, None)
    shown = set(case.related_alert_ids) if case is not None else set(known)
    linked: List[str] = []
    for alert_id in dict.fromkeys([*related, *[a for a in known if a not in shown][:MAX_REOPEN]]):
        try:
            if await _link_one(repos, tenant_id, alert_id, threat_id=threat.id, actor=actor,
                               escalation_id=escalation_id, now=now):
                linked.append(alert_id)
        except NotFound:
            continue  # the retention purge removed it since
    return linked


async def _link_one(
    repos: Repositories, tenant_id: str, alert_id: str, *, threat_id: str, actor: Actor,
    escalation_id: Optional[str], now: datetime,
) -> bool:
    """Link one alert; whether this is its first link to the threat (a link into a new case of the same threat is
    written and audited, and not counted again). The row is locked: two threats linking it at once both land."""
    async with repos.db.tenant_tx(tenant_id) as conn:
        alert = await repos.alerts.get_locked(tenant_id, alert_id, conn=conn)
        if not closed_by_models(alert):
            return False  # reopened, or closed again by a person, meanwhile
        # Shown in the threat's case when it is open; nothing else about the alert changes.
        case = escalation_id if await _attach(repos, tenant_id, escalation_id, alert_id, conn) else None
        links: List[Dict[str, Optional[str]]] = [
            dict(m) for m in _listed(alert.summary, "linked") if isinstance(m, Mapping)
        ]
        prior = next((m for m in links if m.get("threat_alert_id") == threat_id), None)
        if prior is not None and case in (None, prior.get("escalation_id")):
            return False  # linked to this threat already, and no new case to show it in
        marker = {"threat_alert_id": threat_id, "escalation_id": case, "at": now.isoformat()}
        links = [*(m for m in links if m is not prior), marker][-MAX_LINKS:]
        await repos.alerts.update(tenant_id, alert_id, summary={"linked": links}, conn=conn)
        details = {"reason": REOPEN_REASON, **marker}
        await repos.alert_events.append(
            tenant_id, alert_id, LINK_ACTION, node="retro_reopen", actor_type=actor.type, actor_id=actor.id,
            data=dict(details), conn=conn,
        )
        await AuditLogger(repos).record(
            tenant_id, LINK_ACTION, "alert", alert_id, actor_type=actor.type, actor_id=actor.id,
            details=dict(details), conn=conn,
        )
    return prior is None


async def reopen_related_model_closes(
    repos: Repositories,
    tenant_id: str,
    threat: Any,
    *,
    actor: Actor,
    escalation_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> List[str]:
    """Reopen the model-closed alerts related to ``threat`` (a stored alert), those linked to it or into its case
    earlier included; the ids reopened (see the module docs).

    Raises on a database error: the caller counts it (:func:`reopen_counted`).
    """
    now = now or datetime.now(UTC)
    related = await _related(repos, tenant_id, threat, now)
    # Linked earlier, by this threat or into its case: they reopen too, however long ago they closed.
    linked = _linked_ids(threat) + await _case_alerts(repos, tenant_id, escalation_id)
    reopened: List[str] = []
    for alert_id in dict.fromkeys([*related, *linked]):
        try:
            if alert_id != threat.id and await _reopen_one(
                repos, tenant_id, alert_id, threat_id=threat.id, actor=actor, escalation_id=escalation_id
            ):
                reopened.append(alert_id)
        except NotFound:
            continue  # a linked alert the retention purge removed since
    return reopened


async def _case_alerts(repos: Repositories, tenant_id: str, escalation_id: Optional[str]) -> List[str]:
    """The alerts attached to the case, whatever its status: the ones linked into it are among them."""
    if escalation_id is None:
        return []
    try:
        return list((await repos.escalations.get(tenant_id, escalation_id)).related_alert_ids)
    except NotFound:
        return []


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
        if not closed_by_models(alert):
            return False  # reopened already, or closed again by a person: nothing to do
        # Folded into the threat's case when it is still open: one escalation holds the related alerts, no new run.
        folded = await _attach(repos, tenant_id, escalation_id, alert_id, conn)
        marker = {
            "reason": REOPEN_REASON, "threat_alert_id": threat_id, "escalation_id": escalation_id,
            "mode": FOLDED if folded else REQUEUED,
        }
        if folded:
            await repos.alerts.update_status(tenant_id, alert_id, "waiting_human", conn=conn)
            summary = {"reopened": marker, "close_reason": REOPENED_CLOSE_REASON, "escalation_id": escalation_id,
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


async def refold(repos: Repositories, tenant_id: str, threat_id: str, escalation_id: str) -> List[str]:
    """Move the alerts folded for ``threat_id`` into a case that is no longer open (decided ``needs_more_info``)
    onto the threat's new case ``escalation_id``; the ids moved. Called whenever the threat escalates."""
    moved: List[str] = []
    for alert_id in await repos.alerts.folded_for_threat(tenant_id, threat_id, exclude_escalation_id=escalation_id):
        async with repos.db.tenant_tx(tenant_id) as conn:
            alert = await repos.alerts.get(tenant_id, alert_id, conn=conn)
            current = folded_into(alert)
            if current is None or current == escalation_id or await _active_escalation(repos, tenant_id, current, conn):
                continue
            if not await _attach(repos, tenant_id, escalation_id, alert_id, conn):
                continue
            marker = {**(alert.summary.get("reopened") or {}), "escalation_id": escalation_id}
            await repos.alerts.update(tenant_id, alert_id, summary={"reopened": marker, "escalation_id": escalation_id},
                                      conn=conn)
            moved.append(alert_id)
    return moved


async def _attach(repos: Repositories, tenant_id: str, escalation_id: Optional[str], alert_id: str, conn: Any) -> bool:
    """Attach ``alert_id`` to the escalation if it is still open (the attach is guarded in SQL against a case
    decided meanwhile); whether it is attached now (an alert linked into that case earlier already is)."""
    escalation = await _active_escalation(repos, tenant_id, escalation_id, conn)
    if escalation is None:
        return False
    if alert_id in escalation.related_alert_ids:
        return True
    deadline = escalation.sla_deadline or datetime.now(UTC) + REOPEN_WINDOW
    attached = await repos.escalations.attach(
        tenant_id, escalation.id, alert_id, priority=escalation.priority, level=escalation.level,
        sla_deadline=deadline, conn=conn,
    )
    return attached is not None


# A shadow run records that the safety net would have run: it links and reopens nothing and counts no failure.
@egress("retro_reopen", sink(lambda a: [], detail=lambda a: {"path": a["path"]}))
async def reopen_counted(
    repos: Repositories,
    tenant_id: str,
    threat: Any,
    *,
    actor: Actor,
    path: str,
    confirmed: bool,
    escalation_id: Optional[str] = None,
) -> Sequence[str]:
    """The safety net for a threat path. ``confirmed`` says what stands behind the threat: a person's decision,
    an executed response or hold grade (the related model closes reopen, :func:`reopen_related_model_closes`), or
    only a model's judgement below hold grade (they are linked and stay closed,
    :func:`link_related_model_closes`). A failure is counted and logged as an error, never raised (the threat's
    own decision stands); returns the ids reopened (none when linking)."""
    act = reopen_related_model_closes if confirmed else link_related_model_closes
    try:
        ids = await act(repos, tenant_id, threat, actor=actor, escalation_id=escalation_id)
    except Exception as exc:  # noqa: BLE001 - counted and logged as an error: an alerting rule can page on it
        RETRO_REOPEN_FAILURES.labels(path=path).inc()
        log_failure(log, "retro_reopen.failed", exc, level="error", alert_id=getattr(threat, "id", None),
                    path=path, error_type=type(exc).__name__)
        return []
    if ids:
        (RETRO_REOPENED if confirmed else RETRO_LINKED).labels(path=path).inc(len(ids))
        log.info("retro_reopen.reopened" if confirmed else "retro_reopen.linked", alert_id=threat.id, path=path,
                 count=len(ids))
    return ids if confirmed else []


async def enqueue_requeued(repos: Repositories, queue: Any, tenant_id: str, alert_ids: Sequence[str]) -> int:
    """After the reopen committed: a run message for each alert it requeued (folded ones have no run to start), the
    same producer ingestion and the API use. A failure is logged, not raised: the orphan sweep is the backstop.
    Returns the number enqueued."""
    if queue is None:
        return 0
    enqueued = 0
    for alert_id in alert_ids:
        try:
            alert = await repos.alerts.get(tenant_id, alert_id)
            if alert.status != "queued":
                continue
            await queue.enqueue_process(tenant_id, alert_id, alert.severity)
            enqueued += 1
        except Exception as exc:  # noqa: BLE001 - the run is queued in the database; the orphan sweep dispatches it
            log_failure(log, "retro_reopen.enqueue_failed", exc, alert_id=alert_id, error_type=type(exc).__name__)
    return enqueued
