# 0012. Drive workflow runs from a Redis Streams queue with a dead-letter stream, and derive it from PostgreSQL

* Status: accepted (recorded after the fact; the design dates from 1.0)
* Date: 2026-11-06
* Roadmap step: Q5 ([refactor roadmap](../design/refactor-roadmap.md), Phase 8)

## Context and problem

Every alert becomes a workflow run that may take seconds (LLM calls) or wait
days for an analyst. Runs must survive a worker crash, a rolling upgrade and
a Redis restart; a run must never execute twice at the same time (it would
propose or execute the same response action twice); a poison alert must not
block the others; and one tenant's burst must not starve the rest. Redis is
already required for rate limits, budgets, caches and the event bus.

## Decision

* **Two streams and one group.** `{prefix}:q:alerts:high` (critical and high
  severity) and `{prefix}:q:alerts:normal`, consumer group `workers`; workers
  read `high` first. A message is `tenant_id`, `alert_id`, `kind`
  (`process` | `resume`), `payload`, `enqueued_at`
  (`lg_sotf.queue.producer.WorkQueue`).
* **At-least-once delivery.** `XREADGROUP`; `XACK` and `XDEL` once the run's
  outcome is committed. An entry left pending is reclaimed with `XAUTOCLAIM`
  after `worker.visibility_timeout_s`, or at once when its consumer's
  liveness key (TTL one run lease) has expired, so a killed worker's backlog
  is recovered within about one lease.
* **PostgreSQL decides who runs.** `workflow_runs` holds the status, the
  attempt counter and a lease that the worker heartbeats; only the holder of
  a live lease executes a run, so a duplicate delivery is skipped, never run
  twice. The retry budget lives on `workflow_runs.attempt`, not on delivery
  counts.
* **Dead letters.** Past `worker.max_deliveries` attempts the message is
  copied to `{prefix}:q:alerts:dlq`, the run is marked `dead_lettered`, the
  alert `failed`, and the entry acked; `lg-sotf dlq list` and `lg-sotf dlq requeue` inspect and replay them.
* **Redis is derived state.** Every queue entry can be rebuilt from
  `workflow_runs`: the scheduler re-enqueues runs left `queued` or `failed`
  without a message (`runtime/orphans.py`), resumes whose decision was
  recorded but never enqueued (`runtime/resumes.py`) and alerts stored but
  never dispatched. Losing Redis loses time, not work.
* **Events are best effort.** Status changes are published on
  `{prefix}:events:{tenant_id}` (pub/sub) for the WebSocket; a lost event
  costs a UI refresh, never a decision.

## Consequences

* Workers scale horizontally with no coordinator; the per-tenant concurrency
  cap and deferral keep one tenant from monopolising them
  (`runtime/worker.py`).
* Every handler must be idempotent: a message can arrive twice, after a
  crash, or after its run already finished.
* Pub/sub channels ignore Redis database indexes, so everything that shares a
  Redis (installs, or parallel test workers) must use its own
  `redis.key_prefix`.
* Tests: `tests/integration/queue`, `tests/integration/runtime` and the e2e
  crash and recovery tests (`test_worker_crash.py`, `test_recovery.py`,
  `test_api_stack.py`).

## Alternatives considered

* **A PostgreSQL queue (`SELECT ... FOR UPDATE SKIP LOCKED`).** One fewer
  moving part, but long-polling workers hold connections from the pool the
  API needs, and Redis is required anyway.
* **RabbitMQ, Kafka or Celery.** A new service to run, secure and back up for
  a few hundred messages a minute; ownership would still have to be decided
  in PostgreSQL to avoid double execution.
* **Exactly-once delivery from the queue.** Not available from any of these
  without the same database lease, so the lease is the single source of truth.
