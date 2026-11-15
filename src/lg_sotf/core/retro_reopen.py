"""The safety net of decision policy v3 (FIX-3, AI-E3.15): a related threat a model judged links the alerts the
models closed alone to its case, and one a person confirmed reopens them.

At the autonomy tier ``auto_full_audit`` the models close every alert the
deep tier judged benign (:mod:`lg_sotf.domain.closure`); the forward gates of
FIX-1 and FIX-2 (thresholds, campaign check) are gone. Instead, when an alert
becomes a threat, the safety net looks up the alerts of the same tenant that
the models closed alone (close reason ``ai_closed:*``) in the previous
:data:`REOPEN_WINDOW` and that share a host, user or IP with it.

**A model judged the threat** (:func:`link_related_model_closes`):

* the workflow plans a response for it, or closes it malicious, with no
  analyst ``true_positive`` and no response action that really ran behind
  it (a response it only proposes, or only simulates in the tenant's
  dry-run mode);
* it is escalated and a model judged it a threat (the deep tier's
  ``malicious``, the fast tier's ``likely_threat`` or ``confirmed_threat``).
  The fast tier's ``suspicious`` is a doubt, not a threat: it does not block
  a model close, so it does not touch one either (#352).

A model's judgement is not a confirmation (AI-E3.15: on dev, one benign alert
a model misjudged undid thirteen correct closes). Each related alert is
**linked** and stays closed: it is attached to the threat's open escalation
as a related alert when there is one, so the analyst sees it in the case; it
gets an entry in its summary's ``linked`` list (threat alert, case, time) and
is audited ``alert.linked`` (reason ``related_threat``), with an
``alert.linked`` event on its timeline. Its status, disposition and close
reason do not change, no run starts, and a decision on the case never
settles it (:func:`lg_sotf.services.folded.settle_folded`): it stays closed
by the models, marked for audit. The threat keeps the ids it linked
(``linked_alert_ids`` in its summary). Each call links the related closes
the threat has not linked yet, newest first and at most :data:`MAX_REOPEN`,
so the calls of one run (response plan, escalation, close) reach older ones.

**The threat is confirmed** (:func:`reopen_related_model_closes`), by a
person or by the platform acting on it:

* an analyst decides ``true_positive`` on it (the API, then the response
  plan and the malicious close of the run that decision resumes);
* an analyst approves a response action for it;
* a blind audit labels it ``malicious``;
* the workflow carries out a response action for it (``succeeded``), alone
  under the tenant's autonomy policy: once the platform has acted on a
  threat, the related alerts do not stay closed. A response it only
  proposes confirms nothing, and neither does a ``dry_run``: a simulation
  is not an act.

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
``related_threat``), with an ``alert.reopened`` event on its timeline. A single attack step the model
misjudged therefore resurfaces as soon as the attack is confirmed anywhere.

Both are idempotent (an alert already reopened is no longer closed, so it is
not selected again; an alert already linked to the threat is linked again
only to show it in a new case) and tenant-scoped (every query runs in the
tenant's transaction). The callers count a failure in
``lgsotf_retro_reopen_failures_total`` and log it as an error; it never
fails the threat's own decision. A shadow run runs neither: the call is
recorded in the run's sink (:func:`reopen_counted`, the one entry point of
both, is an egress boundary).

IPs are matched whatever their role in the alert (source or destination):
the canonical alert does not keep the role, and a wider match only links or
reopens more.

**The other order of arrival** (:func:`related_open`, AI-E3.16): the threat
is there before the close. When ``decide`` runs for an alert at the tier, it
reads the tenant's alerts of the same window that share a host or user with
it and are not closed. The same distinction applies forward: a threat only a
model stands behind links, a stronger signal acts.

* **Hold** (:mod:`lg_sotf.domain.closure`): the close is withheld when the
  related open alert waits for a response approval, is high or critical and
  judged a threat by a model, or was confirmed by a person (an analyst's
  ``true_positive``, a blind-audit ``malicious`` label); also while a high
  or critical alert on the same host is being processed. The held alert
  joins the threat's open case as an attached alert, so the analyst gets
  one case; it escalates on its own only when the threat has no open case.
* **Link forward** (:func:`forward_links`): any other related open alert a
  model judged a threat, or planned a response for, holds nothing. The
  alert closes on the models' word and is linked to that threat's case at
  once, through :func:`link_related_model_closes` (path ``forward``). A
  later confirmation of the threat reopens it like any linked alert.

IPs are left out here, and so are the accounts every host has of its own
(:data:`BUILT_IN_ACCOUNTS`): a shared proxy, resolver or NAT address, or
``root`` on two servers, would relate unrelated alerts, and the safety net
above still links by them. An alert that is only queued has not been looked
at; if it becomes a threat it arrives after the close, which the safety net
covers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Sequence

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.core.state import RelatedOpenDigest
from lg_sotf.db.errors import InvalidTransition, NotFound
from lg_sotf.db.repos import Repositories
from lg_sotf.observability.logging import get_logger, log_failure
from lg_sotf.observability.metrics import RETRO_LINKED, RETRO_REOPEN_FAILURES, RETRO_REOPENED
from lg_sotf.security.shadow import egress, sink
from lg_sotf.services.folded import FOLDED, REQUEUED, closed_by_models, folded_into

log = get_logger(__name__)

REOPEN_WINDOW = timedelta(hours=24)
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
MAX_ENTITY_VALUES = 50
#: The related open alerts a decision records: the ones that hold the close back first, then the ones it links to.
MAX_RELATED_OPEN = 10
#: Accounts every host has of its own: two alerts that share only one of them are not about the same user, so it
#: holds no close back (:func:`related_open`). The safety net still links by them: a link changes no decision.
BUILT_IN_ACCOUNTS = frozenset({"root", "system", "local service", "network service"})
#: The fast-tier verdicts that make an escalated alert a threat for the safety net: the same ones that block a
#: model close. ``suspicious`` is absent on purpose (#352).
THREAT_ASSESSMENTS = frozenset({"likely_threat", "confirmed_threat"})


def judged_threat(triage: Mapping[str, Any], analysis: Mapping[str, Any]) -> bool:
    """Whether a model judged the alert a threat (the escalation path of the safety net); ``suspicious`` is not one."""
    return analysis.get("verdict") == "malicious" or triage.get("threat_assessment") in THREAT_ASSESSMENTS


def _values(entities: Any, kind: str) -> List[str]:
    values = entities.get(kind) if isinstance(entities, Mapping) else None
    if not isinstance(values, list):
        return []
    return [v for v in values[:MAX_ENTITY_VALUES] if isinstance(v, str) and v]


def _listed(summary: Any, key: str) -> List[Any]:
    value = summary.get(key) if isinstance(summary, Mapping) else None
    return list(value) if isinstance(value, list) else []


def _linked_ids(threat: Any) -> List[str]:
    """The alerts ``threat`` (a stored alert) linked so far."""
    return [a for a in _listed(threat.summary, "linked_alert_ids") if isinstance(a, str)]


async def _related(repos: Repositories, tenant_id: str, threat: Any, now: datetime, *, unlinked: bool = False) -> List[str]:
    """Ids of the alerts the models closed alone in the window that share a host, user or IP with ``threat``,
    newest first, at most :data:`MAX_REOPEN`; ``unlinked``: only those the threat has not linked yet."""
    entities = threat.entities if isinstance(threat.entities, Mapping) else {}
    return await repos.alerts.model_closed_sharing_entities(
        tenant_id,
        hosts=_values(entities, "hosts"),
        users=_values(entities, "users"),
        ips=_values(entities, "ips"),
        since=now - REOPEN_WINDOW,
        exclude_alert_id=threat.id,
        not_linked_to=unlinked,
        limit=MAX_REOPEN,
    )


def _built_in(user: str) -> bool:
    """A built-in account of the host itself, with or without its authority prefix (``NT AUTHORITY\\SYSTEM``)."""
    return user.rsplit("\\", 1)[-1].strip().lower() in BUILT_IN_ACCOUNTS


async def related_open(
    repos: Repositories, tenant_id: str, alert_id: str, *, now: Optional[datetime] = None
) -> RelatedOpenDigest:
    """What the database holds, at this moment, about the open threats on the alert's hosts and users: the ids of
    the ones that hold a model-led close back (``threats``), of the high or critical alerts in progress on its
    hosts (``in_progress``) and of the threats only a model stands behind (``model_only``: the close is linked
    to their case), at most :data:`MAX_RELATED_OPEN` in all (see the module docs). Read in the tenant's
    transaction; raises on a database error, so a failed read never closes an alert."""
    alert = await repos.alerts.get(tenant_id, alert_id)
    entities = alert.entities if isinstance(alert.entities, Mapping) else {}
    found = await repos.alerts.open_threats_sharing_entities(
        tenant_id,
        hosts=_values(entities, "hosts"),
        users=[user for user in _values(entities, "users") if not _built_in(user)],
        since=(now or datetime.now(UTC)) - REOPEN_WINDOW,
        exclude_alert_id=alert_id,
        threat_assessments=sorted(THREAT_ASSESSMENTS),
        limit=MAX_RELATED_OPEN,
    )
    return {
        "threats": [other.id for other in found if other.kind == "hold"],
        "in_progress": [other.id for other in found if other.kind == "in_progress"],
        "model_only": [other.id for other in found if other.kind == "model_only"],
    }


def forward_links(summary: Any) -> List[str]:
    """The open threats only a model stands behind that the decision recorded for an alert (its summary's
    ``related_open.model_only``): once the models close the alert, it is linked to each one's case."""
    related = summary.get("related_open") if isinstance(summary, Mapping) else None
    return [threat for threat in _listed(related, "model_only") if isinstance(threat, str)]


def holders(summary: Any) -> List[str]:
    """The open threats that held the alert's model-led close back (``related_open.threats``)."""
    related = summary.get("related_open") if isinstance(summary, Mapping) else None
    return [threat for threat in _listed(related, "threats") if isinstance(threat, str)]


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
    """The safety net for a threat path. ``confirmed`` says what stands behind the threat: a person's decision
    or an executed response (the related model closes reopen, :func:`reopen_related_model_closes`) or only a
    model (they are linked and stay closed, :func:`link_related_model_closes`). A failure is counted and logged as
    an error, never raised (the threat's own decision stands); returns the ids reopened (none when linking)."""
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
