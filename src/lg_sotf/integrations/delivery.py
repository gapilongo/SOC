"""Outbox delivery and ticket sync: the scheduler's integration jobs.

Why the scheduler (and not the workers): the outbox spans tenants and the
scheduler already runs the cross-tenant sweeps as the schema owner
(``system_tx``), while workers use the runtime role, which RLS confines to
one tenant per transaction. The scheduler is leader-elected, so one process
delivers at a time and the per-integration rate limits can live in memory;
claims still use ``FOR UPDATE SKIP LOCKED`` so a leader handover (or an
operator running a second delivery loop) never sends a row twice
concurrently. Delivery never competes with alert processing for worker
slots, and a slow receiver cannot hold a workflow run.

One pass (:meth:`OutboxDelivery.run_once`):

1. claim up to ``integrations.batch_size`` due rows (``pending``/``failed``
   with ``next_attempt_at <= now()``), counting the attempt and moving
   ``next_attempt_at`` one lease ahead (a crashed delivery is retried when
   the lease ends: delivery is at-least-once, receivers deduplicate on the
   event id);
2. deliver them, ``integrations.delivery_concurrency`` at a time, each
   integration within its rate limit (``config.rate_limit_per_minute``, a
   token bucket; a row over the limit is deferred without using an attempt);
3. record the outcome: ``sent``; ``failed`` with exponential backoff and
   jitter (``integrations.backoff_base_s`` doubling up to
   ``backoff_max_s``, at least the receiver's ``Retry-After``); ``dead``
   after ``integrations.max_attempts`` attempts, on a permanent error (a 4xx
   other than 408/425/429, a refused destination), for a disabled
   integration, or when the event is older than
   ``integrations.max_age_hours``.

``last_error`` is redacted and truncated; it never contains a webhook URL
or credentials.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID

from prometheus_client import Counter

from lg_sotf.db.errors import NotFound
from lg_sotf.db.repos.integrations import Integration, OutboxEntry
from lg_sotf.integrations.channels import SmtpFactory, send_notification
from lg_sotf.integrations.config import IntegrationConfigError, decrypt_secret, rate_limit_per_minute
from lg_sotf.integrations.events import ui_base_url
from lg_sotf.integrations.http import DeliveryError, IntegrationHttp
from lg_sotf.integrations.ticketing import DeliveryDeferred, TicketService
from lg_sotf.observability.logging import bound_context, get_logger
from lg_sotf.observability.metrics import REGISTRY
from lg_sotf.security.crypto import SecretBox
from lg_sotf.security.hashing import SecurityConfigError
from lg_sotf.security.redaction import redact_text
from lg_sotf.settings import Settings

if TYPE_CHECKING:
    from lg_sotf.db.repos import Repositories

log = get_logger(__name__)

DELIVERIES = Counter(
    "lgsotf_integration_deliveries_total",
    "Integration outbox delivery attempts, by integration kind and outcome (sent, retry, dead, deferred).",
    ["kind", "outcome"],
    registry=REGISTRY,
)
TICKET_SYNCS = Counter(
    "lgsotf_ticket_syncs_total",
    "Linked ticket status polls, by ticketing system and outcome (ok, resolved, error).",
    ["system", "outcome"],
    registry=REGISTRY,
)

CLAIM_LEASE_S = 300.0
SYNC_ACTOR = "scheduler"
MAX_SYNC_TOTAL = 1_000


def backoff_s(attempts: int, *, base_s: float, max_s: float, rand: Callable[[], float] = random.random) -> float:
    """Delay before the next attempt after ``attempts`` attempts: ``base * 2**(attempts-1)`` capped, jitter +-20%."""
    raw = min(max_s, base_s * (2 ** max(0, attempts - 1)))
    return max(1.0, raw * (0.8 + 0.4 * rand()))


def safe_error(exc: BaseException) -> str:
    text, _ = redact_text(" ".join(str(exc).split()))
    return (f"{type(exc).__name__}: {text}" if text else type(exc).__name__)[:1_000]


class RateLimiter:
    """Token bucket per integration: ``per_minute`` tokens, refilled continuously, burst of one minute's worth."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: Dict[UUID, Tuple[float, float]] = {}

    def acquire(self, key: UUID, per_minute: int) -> float:
        """0 when a token was taken, else the seconds until one is available."""
        now = self._clock()
        rate = per_minute / 60.0
        tokens, last = self._buckets.get(key, (float(per_minute), now))
        tokens = min(float(per_minute), tokens + (now - last) * rate)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return 0.0
        self._buckets[key] = (tokens, now)
        return (1.0 - tokens) / rate


@dataclass(frozen=True)
class Outcome:
    status: str
    retry_in_s: Optional[float] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    refund: bool = False
    metric: str = "sent"


class OutboxDelivery:
    def __init__(
        self,
        repos: Repositories,
        settings: Settings,
        *,
        http: Optional[IntegrationHttp] = None,
        secret_box: Optional[SecretBox] = None,
        tickets: Optional[TicketService] = None,
        smtp_factory: Optional[SmtpFactory] = None,
        limiter: Optional[RateLimiter] = None,
        rand: Callable[[], float] = random.random,
    ) -> None:
        self._repos = repos
        self._settings = settings
        self._cfg = settings.integrations
        self._http = http or IntegrationHttp(settings)
        self._box = secret_box
        if self._box is None and settings.security.encryption_keys is not None:
            try:
                self._box = SecretBox.from_settings(settings)
            except SecurityConfigError:
                self._box = None
        self._tickets = tickets or TicketService(repos, settings, http=self._http, secret_box=self._box)
        self._smtp_factory = smtp_factory
        self._limiter = limiter or RateLimiter()
        self._rand = rand
        self._base_url = ui_base_url(settings)

    @property
    def tickets(self) -> TicketService:
        return self._tickets

    async def run_once(self) -> int:
        """Claim and deliver one batch; returns how many rows were claimed."""
        entries = await self._repos.integrations.claim_due_all_tenants(limit=self._cfg.batch_size, lease_s=CLAIM_LEASE_S)
        if not entries:
            return 0
        integrations = await self._integrations(entries)
        slots = asyncio.Semaphore(self._cfg.delivery_concurrency)

        async def one(entry: OutboxEntry) -> None:
            async with slots:
                await self._process(entry, integrations.get((entry.tenant_id, entry.integration_id)))

        await asyncio.gather(*(one(e) for e in entries))
        return len(entries)

    async def _integrations(self, entries: List[OutboxEntry]) -> Dict[Tuple[str, UUID], Optional[Integration]]:
        found: Dict[Tuple[str, UUID], Optional[Integration]] = {}
        for key in {(e.tenant_id, e.integration_id) for e in entries}:
            try:
                found[key] = await self._repos.integrations.get(*key)
            except NotFound:
                found[key] = None
        return found

    async def _process(self, entry: OutboxEntry, integration: Optional[Integration]) -> None:
        with bound_context(tenant_id=entry.tenant_id, alert_id=entry.alert_id):
            kind = integration.kind if integration is not None else "unknown"
            try:
                outcome = await self.deliver(entry, integration)
            except Exception as exc:  # noqa: BLE001 - an unexpected failure is retried like a transient one
                log.warning("integrations.delivery_crashed", kind=kind, error_type=type(exc).__name__)
                outcome = self._failure(entry, safe_error(exc), retryable=True)
            try:
                recorded = await self._repos.integrations.record_outcome(
                    entry.tenant_id,
                    entry.id,
                    claimed_attempts=entry.attempts,
                    status=outcome.status,
                    retry_in_s=outcome.retry_in_s,
                    error=outcome.error,
                    result=outcome.result,
                    refund_attempt=outcome.refund,
                )
            except Exception as exc:  # noqa: BLE001 - the claim lease expires and the row is retried
                log.error("integrations.outcome_not_recorded", kind=kind, error_type=type(exc).__name__)
                return
            DELIVERIES.labels(kind=kind, outcome=outcome.metric).inc()
            if not recorded:
                log.warning("integrations.outcome_superseded", kind=kind)
            elif outcome.status == "dead":
                log.warning("integrations.delivery_dead", kind=kind, event_type=entry.event_type, attempts=entry.attempts)
            elif outcome.status == "failed":
                log.info("integrations.delivery_retry", kind=kind, attempts=entry.attempts)

    def _failure(self, entry: OutboxEntry, error: str, *, retryable: bool, retry_after: Optional[float] = None) -> Outcome:
        if not retryable or entry.attempts >= self._cfg.max_attempts:
            return Outcome("dead", error=error, metric="dead")
        delay = backoff_s(entry.attempts, base_s=self._cfg.backoff_base_s, max_s=self._cfg.backoff_max_s, rand=self._rand)
        if retry_after is not None:
            delay = max(delay, min(retry_after, self._cfg.backoff_max_s))
        return Outcome("failed", retry_in_s=delay, error=error, metric="retry")

    async def deliver(self, entry: OutboxEntry, integration: Optional[Integration]) -> Outcome:
        """Deliver one claimed row and say what to record (never raises for delivery errors)."""
        if integration is None or not integration.enabled:
            return Outcome("dead", error="integration disabled or deleted", metric="dead")
        if datetime.now(UTC) - entry.created_at > timedelta(hours=self._cfg.max_age_hours):
            return Outcome("dead", error="expired: not delivered within integrations.max_age_hours", metric="dead")
        wait = self._limiter.acquire(integration.id, rate_limit_per_minute(integration.kind, integration.config))
        if wait > 0:
            return Outcome(entry.status, retry_in_s=max(1.0, wait), refund=True, metric="deferred",
                           error=entry.last_error)
        try:
            result = await self._send(entry, integration)
        except DeliveryDeferred as deferred:
            return Outcome(entry.status, retry_in_s=deferred.delay_s, refund=True, metric="deferred", error=str(deferred))
        except DeliveryError as exc:
            return self._failure(entry, safe_error(exc), retryable=exc.retryable, retry_after=exc.retry_after)
        except IntegrationConfigError as exc:
            # The admin may fix the configuration: keep retrying until the attempts run out.
            return self._failure(entry, safe_error(exc), retryable=True)
        return Outcome("sent", result=result)

    async def _send(self, entry: OutboxEntry, integration: Integration) -> Dict[str, Any]:
        payload = entry.payload
        if entry.operation in ("notify", "test"):
            secret = decrypt_secret(self._box, integration.tenant_id, integration.id, integration.secret_ciphertext)
            return await send_notification(
                integration.kind,
                http=self._http,
                settings=self._settings,
                payload=payload,
                base_url=self._base_url,
                config=integration.config,
                secret=secret,
                delivery_id=str(entry.id),
                smtp_factory=self._smtp_factory,
            )
        if entry.operation == "ticket_create":
            if not entry.alert_id:
                raise DeliveryError("the event has no alert", retryable=False, code="no_alert")
            ticket, created = await self._tickets.ensure_ticket(
                integration, payload, alert_id=entry.alert_id, escalation_id=entry.escalation_id
            )
            return {"ticket": ticket.external_key, "url": ticket.external_url, "created": created}
        if entry.operation == "ticket_update":
            if not entry.escalation_id:
                raise DeliveryError("the event has no escalation", retryable=False, code="no_escalation")
            return await self._tickets.sync_decision(integration, payload, escalation_id=entry.escalation_id)
        raise DeliveryError(f"unknown operation {entry.operation!r}", retryable=False, code="unsupported")

    async def purge(self) -> int:
        """Delete sent/dead rows older than ``integrations.outbox_retention_days`` (bounded batch)."""
        cutoff = datetime.now(UTC) - timedelta(days=self._cfg.outbox_retention_days)
        return await self._repos.integrations.purge_finished_all_tenants(older_than=cutoff)


async def sync_tickets(
    repos: Repositories, settings: Settings, tickets: TicketService, events: Any = None
) -> int:
    """Poll linked open tickets; a ticket resolved or closed externally adds an alert timeline note.

    Bounded: at most ``integrations.ticket_sync_batch_per_tenant`` tickets per
    tenant per pass, least recently synced first. The escalation is never
    decided from the ticket's state. Returns how many tickets were polled.
    """
    cfg = settings.integrations
    due = await repos.integrations.tickets_due_for_sync_all_tenants(
        min_age_s=cfg.ticket_sync_interval_s / 2, per_tenant=cfg.ticket_sync_batch_per_tenant, limit=MAX_SYNC_TOTAL
    )
    cache: Dict[Tuple[str, UUID], Optional[Integration]] = {}
    for ticket in due:
        key = (ticket.tenant_id, ticket.integration_id)
        if key not in cache:
            try:
                cache[key] = await repos.integrations.get(*key)
            except NotFound:
                cache[key] = None
        integration = cache[key]
        if integration is None:
            continue
        with bound_context(tenant_id=ticket.tenant_id, alert_id=ticket.alert_id):
            try:
                state = await tickets.client(integration).state(ticket)
            except (DeliveryError, IntegrationConfigError) as exc:
                TICKET_SYNCS.labels(system=ticket.system, outcome="error").inc()
                await repos.integrations.record_sync(ticket.tenant_id, ticket.id, sync_error=safe_error(exc))
                continue
            except Exception as exc:  # noqa: BLE001 - one ticket must not stop the pass
                TICKET_SYNCS.labels(system=ticket.system, outcome="error").inc()
                log.warning("integrations.ticket_sync_failed", error_type=type(exc).__name__)
                continue
            newly_resolved = state.resolved and not ticket.resolved
            async with repos.db.tenant_tx(ticket.tenant_id) as conn:
                await repos.integrations.record_sync(
                    ticket.tenant_id,
                    ticket.id,
                    external_status=state.status,
                    resolved=state.resolved,
                    resolved_by=state.resolved_by,
                    conn=conn,
                )
                if newly_resolved:
                    who = state.resolved_by or "someone outside LG-SOTF"
                    await repos.alert_events.append(
                        ticket.tenant_id,
                        ticket.alert_id,
                        "ticket.resolved_externally",
                        actor_type="system",
                        actor_id=f"integration:{integration.id}",
                        data={
                            "system": ticket.system,
                            "ticket": ticket.external_key,
                            "url": ticket.external_url,
                            "status": state.status,
                            "resolved_by": state.resolved_by,
                            "escalation_id": ticket.escalation_id,
                            "note": f"Ticket {ticket.external_key} {state.status.lower()} by {who}. "
                            "The escalation is not decided by this; an analyst decides it in LG-SOTF.",
                        },
                        conn=conn,
                    )
            TICKET_SYNCS.labels(system=ticket.system, outcome="resolved" if newly_resolved else "ok").inc()
            if newly_resolved and events is not None:
                try:
                    from lg_sotf.core.events import make_event

                    await events.publish(
                        ticket.tenant_id,
                        make_event("alert.updated", ticket.tenant_id, ticket.alert_id,
                                   {"ticket": ticket.external_key, "ticket_status": state.status}),
                    )
                except Exception as exc:  # noqa: BLE001 - live UI events are best effort
                    log.warning("integrations.ticket_event_failed", error_type=type(exc).__name__)
    return len(due)
