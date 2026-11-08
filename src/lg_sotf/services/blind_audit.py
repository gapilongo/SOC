"""Blind audit of auto-closed alerts (PRD-10.2): sampling runs, the blind queue, labels and the estimate.

Sampling (:meth:`BlindAuditService.sample`) draws a uniform, seeded sample of
the alerts automation closed in a window (:mod:`lg_sotf.domain.blind_audit`
defines the frame and the draw) and records the run, its seed and its frame.
Windows of one tenant never overlap, so every alert is in one frame at most;
the check and the run are serialised per tenant by an advisory lock. Runs
start from the scheduler (the tenant setting ``blind_audit``, every complete
week), from ``lg-sotf audit-sample`` or from ``POST /blind-audit/runs``.

Tenant setting ``blind_audit`` (all optional)::

    {"enabled": false,        # the weekly scheduled run
     "sample_rate": 0.02,     # share of the frame drawn
     "min_per_week": 5}       # at least this many per 7 days of window (all of a smaller frame)

Labelling (:meth:`BlindAuditService.label`): the analyst's label
(``malicious``, ``benign``, ``unsure``) is recorded once, with the agreement
with the AI class the item had when it was sampled. Only then does the
service return the AI's verdict, confidence, routing and reasoning
(:class:`~lg_sotf.db.repos.blind_audit.Reveal`); the queue and an unlabelled
item never carry them. A ``malicious`` label opens a normal escalation for
the alert (re-triage by the review queue), in the label's transaction, and
both are audited.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import TYPE_CHECKING, Any, List, Mapping, Optional, Tuple
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lg_sotf.audit.logger import Actor, AuditLogger
from lg_sotf.db import locks
from lg_sotf.db.errors import Conflict
from lg_sotf.db.pagination import Page
from lg_sotf.db.repos.blind_audit import BlindAuditItem, BlindAuditRun, BlindAuditRunSummary, Reveal
from lg_sotf.domain import blind_audit as sampling
from lg_sotf.domain.blind_audit import BlindAuditEstimate, LabelCounts
from lg_sotf.observability.logging import get_logger
from lg_sotf.services.reporting import ReportWindow

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories
    from lg_sotf.db.repos.escalations import Escalation
    from lg_sotf.services.escalation import EscalationService

log = get_logger(__name__)

SETTING = "blind_audit"
DEFAULT_SAMPLE_RATE = 0.02
DEFAULT_MIN_PER_WEEK = 5
MAX_MIN_PER_WEEK = 500
DEFAULT_WINDOW = timedelta(days=7)
MAX_WINDOW = timedelta(days=366)
MAX_NOTES_CHARS = 4_000


class SamplingError(ValueError):
    """A sampling request that cannot run (the message is safe to show); ``code``: ``invalid_window`` or
    ``window_already_sampled``."""

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


@dataclass(frozen=True)
class SampleRequest:
    """A sampling run: the window and the size rule (``None`` fields take the tenant's policy or defaults)."""

    since: Optional[datetime] = None
    until: Optional[datetime] = None
    seed: Optional[int] = None
    sample_rate: Optional[float] = None
    min_per_week: Optional[int] = None
    size: Optional[int] = None


@dataclass(frozen=True)
class LabelResult:
    item: BlindAuditItem
    reveal: Reveal
    escalation: Optional[Escalation]
    escalation_created: bool


class BlindAuditReport(BaseModel):
    """``GET /reports/blind-audit``: the production false-negative estimate over the runs of a window."""

    start: date = Field(serialization_alias="from")
    end: date = Field(serialization_alias="to")
    generated_at: datetime
    estimate: BlindAuditEstimate
    runs: List[BlindAuditRunSummary]
    notes: List[str]

    model_config = ConfigDict(populate_by_name=True)


REPORT_NOTES = (
    "Each run draws a uniform random sample, with a recorded seed, from the alerts automation closed in its "
    "window without a person involved and without a malicious verdict (its frame). Analysts label each sample "
    "without seeing the AI's verdict, confidence, routing or reasoning.",
    "The false-negative rate is malicious labels over malicious and benign labels, with its 95% Wilson "
    "interval; unsure labels are counted but left out. The estimated missed threats scale the rate and its "
    "interval to the frames of the runs.",
    "Runs are counted when their window starts in the report's window. Pooling runs is exact when they drew "
    "the same share of their frame; samples still waiting for a label are left out until they are labelled.",
)


def _window(request: SampleRequest, latest_end: Optional[datetime], now: datetime) -> Tuple[datetime, datetime]:
    if any(bound is not None and bound.tzinfo is None for bound in (request.since, request.until)):
        raise SamplingError("the window bounds must carry a time zone")
    until = min(request.until or now, now)
    since = request.since or (latest_end if latest_end is not None and latest_end < until else until - DEFAULT_WINDOW)
    if until <= since:
        raise SamplingError("the window must end after it starts (and cannot end in the future)")
    if until - since > MAX_WINDOW:
        raise SamplingError(f"a sampling window spans at most {MAX_WINDOW.days} days")
    return since, until


class BlindAuditService:
    def __init__(self, repos: Repositories, escalations: Optional[EscalationService] = None) -> None:
        self._repos = repos
        self._escalations = escalations
        self._audit = AuditLogger(repos)

    async def policy(self, tenant_id: str) -> BlindAuditPolicy:
        tenant = await self._repos.tenants.get(tenant_id)
        return resolve_blind_audit_policy(tenant.settings)

    # ------------------------------------------------------------------ sampling

    async def sample(
        self, tenant_id: str, request: SampleRequest, *, trigger: str, actor: Actor, now: Optional[datetime] = None
    ) -> BlindAuditRun:
        """Draw and record one run (``SamplingError`` when the window is invalid or already sampled)."""
        now = now or datetime.now(UTC)
        policy = await self.policy(tenant_id)
        rate = None if request.size is not None else (request.sample_rate or policy.sample_rate)
        minimum = 0 if request.size is not None else (
            policy.min_per_week if request.min_per_week is None else request.min_per_week
        )
        seed = sampling.new_seed() if request.seed is None else request.seed
        if not 0 <= seed <= sampling.MAX_SEED:
            raise SamplingError(f"the seed must be a whole number from 0 to {sampling.MAX_SEED}", "invalid_seed")
        repo = self._repos.blind_audit
        async with self._repos.db.tenant_tx(tenant_id) as conn:
            await locks.tenant_xact_lock(conn, locks.BLIND_AUDIT_SAMPLING, tenant_id)
            since, until = _window(request, await repo.latest_window_end(tenant_id, conn=conn), now)
            if await repo.overlaps(tenant_id, since, until, conn=conn):
                raise SamplingError(
                    "another run already sampled part of this window; pick a window after it", "window_already_sampled"
                )
            frame_size, ranked = await repo.frame(
                tenant_id, since, until, seed=seed, limit=sampling.MAX_SAMPLE_PER_RUN, conn=conn
            )
            k = sampling.sample_size(
                frame_size, rate=rate, min_per_week=minimum, days=(until - since).total_seconds() / 86_400,
                fixed=request.size,
            )
            items = [(a.alert_id, a.rank, sampling.ai_class(a.disposition)) for a in ranked[:k]]
            run = await repo.create_run(
                tenant_id, since=since, until=until, seed=seed, sample_rate=rate, min_sample=minimum,
                fixed_size=request.size, frame_size=frame_size, items=items, trigger=trigger,
                created_by=actor.id, conn=conn,
            )
            await self._audit.record(
                tenant_id, "blind_audit.sampled", "blind_audit_run", str(run.id),
                actor_type=actor.type, actor_id=actor.id,
                details={
                    "trigger": trigger, "window_start": since.isoformat(), "window_end": until.isoformat(),
                    "seed": str(seed), "frame_size": frame_size, "sample_size": len(items),
                },
                conn=conn,
            )
        log.info("blind_audit.sampled", trigger=trigger, frame_size=frame_size, sample_size=len(items))
        return run

    async def sample_due(self, tenant_id: str, *, now: Optional[datetime] = None) -> Optional[BlindAuditRun]:
        """The scheduled run: the last complete week, from where earlier runs ended (``None`` when nothing is due)."""
        now = now or datetime.now(UTC)
        if not (await self.policy(tenant_id)).enabled:
            return None
        week_start, week_end = week_window(now)
        latest = await self._repos.blind_audit.latest_window_end(tenant_id)
        since = max(week_start, latest) if latest is not None else week_start
        if since >= week_end:
            return None
        try:
            return await self.sample(
                tenant_id, SampleRequest(since=since, until=week_end), trigger="schedule",
                actor=Actor("system", "scheduler"), now=now,
            )
        except SamplingError as exc:  # a run overlapping the week's middle: that part is already sampled
            log.info("blind_audit.schedule_skipped", reason=str(exc))
            return None

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
        now: Optional[datetime] = None,
    ) -> LabelResult:
        """Record the label once (``Conflict`` when the item has one), then reveal the AI's side.

        ``malicious`` opens (or joins) the alert's active escalation in the same transaction.
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
                now=now, conn=conn,
            )
            await self._audit.record(
                tenant_id, "blind_audit.labelled", "blind_audit_item", str(item_id),
                actor_type=actor.type, actor_id=actor.id,
                details={
                    "alert_id": item.alert_id, "run_id": str(item.run_id), "label": label, "ai_class": ai,
                    "agreement": agreed, "escalation_id": escalation.id if escalation else None,
                    "escalation_created": created,
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
        return await self._escalations.open_for_audit(conn, alert, item_id=str(item.id), notes=notes, actor=actor, now=now)

    # ------------------------------------------------------------------- estimate

    async def report(self, tenant_id: str, window: ReportWindow) -> BlindAuditReport:
        runs = await self._repos.blind_audit.runs_in_window(tenant_id, window.since, window.until)
        counts = sampling.total(
            [LabelCounts(sampled=r.sampled, malicious=r.malicious, benign=r.benign, unsure=r.unsure, agreed=r.agreed)
             for r in runs]
        )
        return BlindAuditReport(
            start=window.start,
            end=window.end,
            generated_at=datetime.now(UTC),
            estimate=sampling.estimate(sum(r.frame_size for r in runs), counts),
            runs=runs,
            notes=list(REPORT_NOTES),
        )

