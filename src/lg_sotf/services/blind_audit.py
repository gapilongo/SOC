"""Blind audit of auto-closed alerts (PRD-10.2): sampling runs, the blind queue, labels and the estimate.

Sampling (:meth:`BlindAuditService.sample`) draws a uniform sample of the
alerts automation closed in a window (:mod:`lg_sotf.domain.blind_audit`
defines the frame and the draw) with a seed the server chooses, and records
the run, its seed and its frame. Windows of one tenant follow each other
without gaps or overlap: a run starts where the last one ended (the first
run anywhere), so every alert is in one frame at most and the report lists
any uncovered time; the check and the run are serialised per tenant by an
advisory lock. A window ends 5 minutes before the database's clock. Runs
start from the scheduler (the tenant setting ``blind_audit``, week by week),
from ``lg-sotf audit-sample`` or from ``POST /blind-audit/runs``; a dry run
(:meth:`BlindAuditService.dry_run`) takes the caller's seed and records
nothing.

Tenant setting ``blind_audit`` (all optional)::

    {"enabled": false,        # the weekly scheduled run
     "sample_rate": 0.02,     # share of the frame drawn
     "min_per_week": 5}       # at least this many per 7 days of window (all of a smaller frame)

Labelling (:meth:`BlindAuditService.label`): the analyst's label
(``malicious``, ``benign``, ``unsure``) is recorded once, with the agreement
with the AI class the item had when it was sampled. Only then does the
service return the AI's verdict, confidence, routing and reasoning
(:class:`~lg_sotf.db.repos.blind_audit.Reveal`); the queue and an unlabelled
item never carry them, and until the label exists the alert's AI side is
hidden everywhere else too (the alert routes, its timeline and evidence
pack, MCP, live updates; :mod:`lg_sotf.domain.blind_audit` ``HIDDEN``). A
``malicious`` label opens a normal escalation for the alert, in the label's
transaction, and both are audited. Deciding that escalation re-queues the
alert (:meth:`BlindAuditService.requeue_after_decision`): its new run starts
at the analyst's decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import TYPE_CHECKING, Any, List, Mapping, Optional, Sequence, Set, Tuple
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db import Connection, locks
from lg_sotf.db.errors import Conflict, InvalidTransition
from lg_sotf.db.pagination import Page
from lg_sotf.db.repos.blind_audit import (
    BlindAuditItem,
    BlindAuditRun,
    BlindAuditRunSummary,
    OrganisationLabels,
    Reveal,
)
from lg_sotf.domain import blind_audit as sampling
from lg_sotf.domain.blind_audit import BlindAuditEstimate, LabelCounts
from lg_sotf.domain.rates import RateInterval
from lg_sotf.observability.logging import get_logger
from lg_sotf.services import alerts as alert_changes
from lg_sotf.services.reporting import ReportWindow

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories
    from lg_sotf.db.repos.escalations import Escalation
    from lg_sotf.services.escalation import EscalationService

log = get_logger(__name__)

SETTING = "blind_audit"
# alerts.summary key: the blind-audit escalation a run of the alert starts at (see requeue_after_decision).
BLIND_AUDIT_REVIEW_KEY = "blind_audit_review"
DEFAULT_SAMPLE_RATE = 0.02
DEFAULT_MIN_PER_WEEK = 5
MAX_MIN_PER_WEEK = 500
DEFAULT_WINDOW = timedelta(days=7)
MAX_WINDOW = timedelta(days=366)
MAX_NOTES_CHARS = 4_000


class SamplingError(ValueError):
    """A sampling request that cannot run (the message is safe to show); ``code``: ``invalid_window``,
    ``window_not_contiguous``, ``window_already_sampled``, ``seed_needs_dry_run`` or ``invalid_seed``."""

    def __init__(self, message: str, code: str = "invalid_window") -> None:
        super().__init__(message)
        self.code = code


class BlindAuditPolicy(BaseModel):
    """Tenant setting ``blind_audit`` (see the module docstring)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(default=False, strict=True)
    sample_rate: float = Field(default=DEFAULT_SAMPLE_RATE, gt=0, le=1)
    min_per_week: int = Field(default=DEFAULT_MIN_PER_WEEK, ge=0, le=MAX_MIN_PER_WEEK, strict=True)


def resolve_blind_audit_policy(tenant_settings: Optional[Mapping[str, Any]]) -> BlindAuditPolicy:
    """The tenant's policy; a missing or invalid section gives the defaults (sampling off)."""
    section = (tenant_settings or {}).get(SETTING)
    if not isinstance(section, Mapping):
        return BlindAuditPolicy()
    try:
        return BlindAuditPolicy.model_validate(dict(section))
    except ValidationError:
        log.warning("blind_audit.invalid_tenant_policy")
        return BlindAuditPolicy()


def week_window(now: datetime) -> Tuple[datetime, datetime]:
    """The last complete ISO week before ``now``: Monday 00:00 UTC to the next Monday."""
    today = now.astimezone(UTC).date()
    end = datetime.combine(today - timedelta(days=today.weekday()), time.min, tzinfo=UTC)
    return end - timedelta(days=7), end


def next_monday(after: datetime) -> datetime:
    """The first Monday 00:00 UTC strictly after ``after``."""
    day = after.astimezone(UTC).date()
    return datetime.combine(day + timedelta(days=7 - day.weekday()), time.min, tzinfo=UTC)


@dataclass(frozen=True)
class SampleRequest:
    """A sampling run: the window and the size rule (``None`` fields take the tenant's policy or defaults).

    ``seed`` is for dry runs only: a recorded run's seed is always the server's (``seed_source``).
    """

    since: Optional[datetime] = None
    until: Optional[datetime] = None
    seed: Optional[int] = None
    sample_rate: Optional[float] = None
    min_per_week: Optional[int] = None
    size: Optional[int] = None


class BlindAuditDraw(BaseModel):
    """A dry run: what a run over this window and seed draws, recorded nowhere."""

    window_start: datetime
    window_end: datetime
    seed: int
    frame_size: int
    sample_size: int
    alert_ids: List[str]


@dataclass(frozen=True)
class _Plan:
    since: datetime
    until: datetime
    rate: Optional[float]
    minimum: int


@dataclass(frozen=True)
class LabelResult:
    item: BlindAuditItem
    reveal: Reveal
    escalation: Optional[Escalation]
    escalation_created: bool


class BlindAuditStratum(BaseModel):
    """One run as a stratum of the estimate, with its own rate and 95% Wilson interval."""

    run_id: UUID
    window_start: datetime
    window_end: datetime
    frame_size: int
    sampled: int
    labelled: int
    pending: int
    malicious: int
    benign: int
    unsure: int
    complete: bool
    false_negative_rate: RateInterval


class UncoveredSpan(BaseModel):
    """Time in the report's window that no run sampled: alerts closed then are in no frame."""

    start: datetime = Field(serialization_alias="from")
    end: datetime = Field(serialization_alias="to")

    model_config = ConfigDict(populate_by_name=True)


class BlindAuditReport(BaseModel):
    """``GET /reports/blind-audit``: the production false-negative estimate over the runs of a window."""

    start: date = Field(serialization_alias="from")
    end: date = Field(serialization_alias="to")
    generated_at: datetime
    estimate: BlindAuditEstimate
    strata: List[BlindAuditStratum]
    runs: List[BlindAuditRunSummary]
    uncovered: List[UncoveredSpan]
    labels_by_organisation: List[OrganisationLabels]
    notes: List[str]

    model_config = ConfigDict(populate_by_name=True)


REPORT_NOTES = (
    "Each run draws a uniform random sample, with a seed the server chose and recorded, from the alerts "
    "automation closed in its window without a person involved and without a malicious verdict (its frame). "
    "Runs follow each other without gaps; time no run covered is listed as uncovered.",
    "From the moment an alert is sampled until it is labelled, everyone in the tenant (admins included) is "
    "kept from its verdict: the alert routes and MCP withhold its disposition, scores, summary and findings; "
    "its timeline shows only ingestion and notes; its escalations and response actions are not served and "
    "audit details about it are redacted; its evidence pack withholds all of these; live updates carry no "
    "data; it cannot be reprocessed; and it is left out of the value, detection and dashboard figures and of "
    "other alerts' correlation digests. Before it was sampled its verdict was visible like any alert's (in "
    "the console, live updates and exports taken then), and comparing exports taken before and after a run "
    "reveals the dispositions of the sampled alerts in aggregate.",
    "The false-negative rate is stratified: each run's rate (malicious over malicious and benign labels) is "
    "weighted by its frame, so runs that drew different shares are not mixed up. The 95% interval is Wilson's "
    "on Kish's effective sample size; each run also shows its own Wilson interval.",
    "Unsure and pending samples are left out of the rate. The worst case counts them as malicious; the "
    "estimate is marked incomplete until every sample of every run is labelled.",
)

SETTLE_LAG = timedelta(minutes=5)
MAX_CATCH_UP_WEEKS = 60


class BlindAuditService:
    def __init__(self, repos: Repositories, escalations: Optional[EscalationService] = None) -> None:
        self._repos = repos
        self._escalations = escalations
        self._audit = AuditLogger(repos)

    async def policy(self, tenant_id: str) -> BlindAuditPolicy:
        tenant = await self._repos.tenants.get(tenant_id)
        return resolve_blind_audit_policy(tenant.settings)

    # ------------------------------------------------------------------ sampling

    async def _plan(
        self, conn: Connection, tenant_id: str, request: SampleRequest, now: Optional[datetime], *, contiguous: bool
    ) -> _Plan:
        """The window and size rule. Windows end ``SETTLE_LAG`` before the database's clock (a close still
        committing is not missed); a recorded run starts exactly where the tenant's last run ended."""
        if any(bound is not None and bound.tzinfo is None for bound in (request.since, request.until)):
            raise SamplingError("the window bounds must carry a time zone")
        db_now = await self._repos.blind_audit.db_now(tenant_id, conn=conn)
        limit = min(now or db_now, db_now) - SETTLE_LAG
        until = min(request.until or limit, limit)
        latest = await self._repos.blind_audit.latest_window_end(tenant_id, conn=conn)
        if contiguous and latest is not None:
            if request.since is not None and request.since != latest:
                raise SamplingError(
                    f"runs follow each other without gaps: this run starts where the last one ended ({latest.isoformat()})",
                    "window_not_contiguous",
                )
            since = latest
        else:
            since = request.since or (latest if latest is not None and latest < until else until - DEFAULT_WINDOW)
        if until <= since:
            raise SamplingError("nothing to sample yet: the window must end after it starts, 5 minutes before now")
        if until - since > MAX_WINDOW:
            raise SamplingError(f"a sampling window spans at most {MAX_WINDOW.days} days")
        policy = await self.policy(tenant_id)
        rate = None if request.size is not None else (request.sample_rate or policy.sample_rate)
        minimum = 0 if request.size is not None else (
            policy.min_per_week if request.min_per_week is None else request.min_per_week
        )
        return _Plan(since, until, rate, minimum)

    @staticmethod
    def _size(plan: _Plan, frame_size: int, fixed: Optional[int]) -> int:
        days = (plan.until - plan.since).total_seconds() / 86_400
        return sampling.sample_size(frame_size, rate=plan.rate, min_per_week=plan.minimum, days=days, fixed=fixed)

    async def sample(
        self, tenant_id: str, request: SampleRequest, *, trigger: str, actor: Actor, now: Optional[datetime] = None
    ) -> BlindAuditRun:
        """Draw and record one run with a server seed (``SamplingError`` for an invalid or non-contiguous window)."""
        if request.seed is not None:
            raise SamplingError("a caller's seed is for dry runs only; a recorded run uses a server seed", "seed_needs_dry_run")
        seed = sampling.new_seed()
        repo = self._repos.blind_audit
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.BLIND_AUDIT_SAMPLING, tenant_id)
            plan = await self._plan(conn, tenant_id, request, now, contiguous=True)
            if await repo.overlaps(tenant_id, plan.since, plan.until, conn=conn):
                raise SamplingError("another run already sampled part of this window", "window_already_sampled")
            frame_size, ranked = await repo.frame(
                tenant_id, plan.since, plan.until, seed=seed, limit=sampling.MAX_SAMPLE_PER_RUN, conn=conn
            )
            items = [(a.alert_id, a.rank, sampling.ai_class(a.disposition)) for a in ranked[: self._size(plan, frame_size, request.size)]]
            run = await repo.create_run(
                tenant_id, since=plan.since, until=plan.until, seed=seed, sample_rate=plan.rate,
                min_sample=plan.minimum, fixed_size=request.size, frame_size=frame_size, items=items,
                trigger=trigger, created_by=actor.id, conn=conn,
            )
            await self._audit.record(
                tenant_id, "blind_audit.sampled", "blind_audit_run", str(run.id),
                actor_type=actor.type, actor_id=actor.id,
                details={
                    "trigger": trigger, "window_start": plan.since.isoformat(), "window_end": plan.until.isoformat(),
                    "seed": str(seed), "seed_source": run.seed_source, "frame_size": frame_size,
                    "sample_size": len(items),
                },
                conn=conn,
            )
        log.info("blind_audit.sampled", trigger=trigger, frame_size=frame_size, sample_size=len(items))
        return run

    async def dry_run(self, tenant_id: str, request: SampleRequest, *, now: Optional[datetime] = None) -> BlindAuditDraw:
        """What a run over this window and seed draws, recorded nowhere (the seed may be the caller's).

        Alerts an earlier run sampled stay in the frame, so a recorded run's window and seed re-draw its sample.
        """
        seed = sampling.new_seed() if request.seed is None else request.seed
        if not 0 <= seed <= sampling.MAX_SEED:
            raise SamplingError(f"the seed must be a whole number from 0 to {sampling.MAX_SEED}", "invalid_seed")
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            plan = await self._plan(conn, tenant_id, request, now, contiguous=False)
            frame_size, ranked = await self._repos.blind_audit.frame(
                tenant_id, plan.since, plan.until, seed=seed, limit=sampling.MAX_SAMPLE_PER_RUN,
                include_sampled=True, conn=conn,
            )
        drawn = ranked[: self._size(plan, frame_size, request.size)]
        return BlindAuditDraw(
            window_start=plan.since, window_end=plan.until, seed=seed, frame_size=frame_size,
            sample_size=len(drawn), alert_ids=[a.alert_id for a in drawn],
        )

    async def sample_due(self, tenant_id: str, *, now: Optional[datetime] = None) -> List[BlindAuditRun]:
        """The scheduled runs: week by week from where the last run ended (the last complete week for a first run)."""
        now = now or datetime.now(UTC)
        if not (await self.policy(tenant_id)).enabled:
            return []
        latest = await self._repos.blind_audit.latest_window_end(tenant_id)
        since = latest if latest is not None else week_window(now)[0]
        runs: List[BlindAuditRun] = []
        for _ in range(MAX_CATCH_UP_WEEKS):
            end = next_monday(since)
            if end > now - SETTLE_LAG:
                break
            request = SampleRequest(since=since, until=end)
            try:
                run = await self.sample(tenant_id, request, trigger="schedule", actor=Actor("system", "scheduler"), now=now)
            except SamplingError as exc:
                log.info("blind_audit.schedule_skipped", reason=str(exc))
                break
            runs.append(run)
            since = end
        return runs

    # ------------------------------------------------------------------- reading

    async def queue(
        self, tenant_id: str, *, labelled: bool, limit: int, cursor: Optional[str]
    ) -> Page[BlindAuditItem]:
        return await self._repos.blind_audit.list_items(tenant_id, labelled=labelled, limit=limit, cursor=cursor)

    async def item(self, tenant_id: str, item_id: UUID) -> Tuple[BlindAuditItem, Optional[Reveal]]:
        """The item, and the AI's side only once it is labelled."""
        async with self._repos.db.tenant_tx(tenant_id, readonly=True) as conn:
            item = await self._repos.blind_audit.get_item(tenant_id, item_id, conn=conn)
            reveal = None if item.label is None else await self._repos.blind_audit.reveal(tenant_id, item_id, conn=conn)
        return item, reveal

    async def runs(self, tenant_id: str, *, limit: int, cursor: Optional[str]) -> Page[BlindAuditRunSummary]:
        return await self._repos.blind_audit.list_runs(tenant_id, limit=limit, cursor=cursor)

    async def hidden_alert_ids(self, tenant_id: str, alert_ids: Sequence[str]) -> Set[str]:
        """The alerts whose AI side stays hidden: they wait for a blind-audit label."""
        return await self._repos.blind_audit.pending_alert_ids(tenant_id, alert_ids)

    # ------------------------------------------------------------------ labelling

    async def label(
        self,
        tenant_id: str,
        item_id: UUID,
        label: str,
        *,
        notes: Optional[str],
        actor: Actor,
        user_id: Optional[UUID],
        organisation: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> LabelResult:
        """Record the label once (``Conflict`` when the item has one), then reveal the AI's side.

        ``malicious`` opens (or joins) the alert's active escalation in the same transaction.
        ``organisation``: the MSSP organisation of a delegated labeller (``None`` for the tenant's own people).
        """
        now = now or datetime.now(UTC)
        notes = (notes or "").strip()[:MAX_NOTES_CHARS] or None
        repo = self._repos.blind_audit
        escalation: Optional[Escalation] = None
        created = False
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            item = await repo.get_item(tenant_id, item_id, for_update=True, conn=conn)
            if item.label is not None:
                raise Conflict("the item is already labelled")
            ai = (await repo.reveal(tenant_id, item_id, conn=conn)).ai_class
            agreed = sampling.agreement(label, ai)
            if label == "malicious":
                escalation, created = await self._open_escalation(conn, tenant_id, item, notes, actor, now)
            await repo.label(
                tenant_id, item_id, label=label, notes=notes, agreement=agreed, labelled_by=user_id,
                labelled_by_actor=actor.id or actor.type, escalation_id=escalation.id if escalation else None,
                labelled_by_org=organisation, now=now, conn=conn,
            )
            await self._audit.record(
                tenant_id, "blind_audit.labelled", "blind_audit_item", str(item_id),
                actor_type=actor.type, actor_id=actor.id,
                details={
                    "alert_id": item.alert_id, "run_id": str(item.run_id), "label": label, "ai_class": ai,
                    "agreement": agreed, "escalation_id": escalation.id if escalation else None,
                    "escalation_created": created, "organisation": organisation,
                },
                conn=conn,
            )
            labelled = await repo.get_item(tenant_id, item_id, conn=conn)
            reveal = await repo.reveal(tenant_id, item_id, conn=conn)
        if created and escalation is not None and self._escalations is not None:
            await self._escalations.announce_after_commit(escalation)
        log.info("blind_audit.labelled", label=label, agreement=agreed, escalation_created=created)
        return LabelResult(labelled, reveal, escalation, created)

    async def _open_escalation(
        self, conn: Any, tenant_id: str, item: BlindAuditItem, notes: Optional[str], actor: Actor, now: datetime
    ) -> Tuple[Escalation, bool]:
        if self._escalations is None:
            raise RuntimeError("labelling an item malicious needs the escalation service")
        alert = await self._repos.alerts.get(tenant_id, item.alert_id, conn=conn)
        escalation, created = await self._escalations.open_for_audit(
            conn, alert, item_id=str(item.id), notes=notes, actor=actor, now=now
        )
        # A run of this alert (the re-triage below, or a reprocess) starts at the analyst's decision on it.
        await self._repos.alerts.update(
            tenant_id, alert.id, summary={"blind_audit_review": escalation.id}, conn=conn
        )
        return escalation, created

    async def requeue_after_decision(
        self, tenant_id: str, escalation: Escalation, actor: Actor
    ) -> Optional[str]:
        """Re-triage: a decided blind-audit escalation of an alert whose run has ended queues the alert again
        (the reprocess path). The new run starts at the analyst's decision, so it sets the disposition and
        ``analyst_decision`` and plans a response where the policy allows. Returns the alert's severity to
        enqueue, or ``None`` when nothing is queued (another escalation, or a run that is not finished)."""
        routing = escalation.summary.get("routing") if isinstance(escalation.summary, Mapping) else None
        if escalation.status != "decided" or not isinstance(routing, Mapping) or routing.get("code") != "blind_audit":
            return None
        alert = await self._repos.alerts.get(tenant_id, escalation.alert_id)
        # Closed by automation, the decision not applied yet (a finished re-triage run has applied it).
        if alert.status != "closed" or alert.summary.get("analyst_decision") is not None:
            return None
        try:
            queued = await alert_changes.request_reprocess(
                self._repos, self._audit, tenant_id, actor, alert.id, summary={"blind_audit_review": escalation.id}
            )
        except InvalidTransition:
            log.info("blind_audit.requeue_skipped")
            return None
        return queued.severity

    # ------------------------------------------------------------------- estimate

    async def report(self, tenant_id: str, window: ReportWindow) -> BlindAuditReport:
        repo = self._repos.blind_audit
        runs = await repo.runs_in_window(tenant_id, window.since, window.until)
        by_org = await repo.labels_by_organisation(tenant_id, [r.id for r in runs])
        db_now = await repo.db_now(tenant_id)
        strata = [
            sampling.Stratum(frame_size=r.frame_size, counts=LabelCounts(
                sampled=r.sampled, malicious=r.malicious, benign=r.benign, unsure=r.unsure, agreed=r.agreed
            ))
            for r in runs
        ]
        return BlindAuditReport(
            start=window.start,
            end=window.end,
            generated_at=datetime.now(UTC),
            estimate=sampling.estimate(strata),
            strata=[_stratum_out(r, s) for r, s in zip(runs, strata, strict=True)],
            runs=runs,
            uncovered=uncovered_spans(window.since, min(window.until, db_now - SETTLE_LAG), runs),
            labels_by_organisation=by_org,
            notes=list(REPORT_NOTES),
        )


def _stratum_out(run: BlindAuditRunSummary, stratum: sampling.Stratum) -> BlindAuditStratum:
    c = stratum.counts
    return BlindAuditStratum(
        run_id=run.id, window_start=run.window_start, window_end=run.window_end, frame_size=run.frame_size,
        sampled=c.sampled, labelled=c.labelled, pending=c.pending, malicious=c.malicious, benign=c.benign,
        unsure=c.unsure, complete=c.pending == 0, false_negative_rate=sampling.run_rate(c),
    )


def uncovered_spans(since: datetime, until: datetime, runs: Sequence[BlindAuditRunSummary]) -> List[UncoveredSpan]:
    """The parts of ``[since, until)`` no run's window covers."""
    gaps: List[UncoveredSpan] = []
    cursor = since
    for run in sorted(runs, key=lambda r: r.window_start):
        if run.window_start > cursor and cursor < until:
            gaps.append(UncoveredSpan(start=cursor, end=min(run.window_start, until)))
        cursor = max(cursor, run.window_end)
    if cursor < until:
        gaps.append(UncoveredSpan(start=cursor, end=until))
    return gaps
