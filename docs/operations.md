# Operations runbook

Day-2 procedures for LG-SOTF. Deployment and sizing are in
`docs/deployment.md`; the system contract is `docs/architecture.md`.

Conventions below: `NS=lg-sotf`, release `lg-sotf`. Operator commands run the
same image as the application, for example:

```sh
# Kubernetes: run a one-off command with the scheduler's configuration (owner DB access)
kubectl -n $NS exec deploy/lg-sotf-scheduler -- lg-sotf dlq list
# Compose
docker compose -f docker/docker-compose.yml run --rm --no-deps scheduler dlq list
```

Commands that change runs or tenants (`enqueue`, `dlq requeue`, `create-admin`,
`create-tenant`) use the
schema-owner connection, so run them from the scheduler (or a pod with the owner
secret), not from the API or worker.

## 1. Health at a glance

| Check | Healthy |
|---|---|
| `kubectl -n $NS get pods` | all Running/Ready; migrate Job Completed |
| API `GET /readyz` | `{"status":"ok","checks":{"database":"ok","redis":"ok"}}` |
| Worker / scheduler `:9100/readyz` | same shape |
| Scheduler logs | exactly one replica logged `scheduler.leadership_acquired` most recently |
| `lgsotf_queue_depth{stream="dlq"}` | 0 or stable |
| `lgsotf_queue_pending` | bounded, not growing |
| `lgsotf_escalations_open` | within analyst capacity |

`/healthz` is liveness only (the process loop answers); `/readyz` pings
PostgreSQL and Redis. A pod that is live but not ready has a dependency problem,
not a code problem.

After an upgrade or an infrastructure change, run the customer-path smoke
test against the environment (docs/deployment.md, "End-to-end smoke test"):
`python scripts/smoke_stack.py --base-url https://<api> flow` with a
dedicated admin in `SMOKE_ADMIN_EMAIL`/`SMOKE_ADMIN_PASSWORD`. It creates a
few synthetic alerts, an API key and a webhook source in that tenant; use a
staging tenant.

The tenant's audit trail is available to admins at `GET /api/v1/audit`
(filters `action`, `resource_type`, `resource_id`, `actor_id`, `from`/`to`)
and its hash chain is checked with `GET /api/v1/audit/verify`; include both
in incident evidence.

## 2. Scaling

* **API**: HPA on CPU (`api.autoscaling`). Manual: `kubectl -n $NS scale deploy/lg-sotf-api --replicas=N` (only when the HPA is disabled).
* **Workers**: KEDA on consumer-group lag (`worker.keda`), or CPU HPA. Manual
  scale for an incident backlog:
  `kubectl -n $NS scale deploy/lg-sotf-worker --replicas=N` (with KEDA, raise
  `worker.keda.maxReplicaCount` / lower `lagCount` instead; KEDA overrides manual
  scaling). Before scaling out, check the LLM provider limits: more replicas
  multiply concurrent LLM calls (`docs/deployment.md`, Sizing) and the DB
  connection budget.
* **Scheduler**: keep 2 replicas. Never scale it for throughput; only the leader works.
* **Backlog triage**: `high` (critical/high severity) is always read before
  `normal`. A growing `normal` backlog with a flat `high` backlog is expected
  under load.

## 3. Dead-letter queue (DLQ)

A queue entry is dead-lettered after `worker.max_deliveries` failed deliveries:
it is copied to `<prefix>:q:alerts:dlq`, the run is marked `dead_lettered`, and
the original entry is acknowledged.

```sh
lg-sotf dlq list                 # oldest first: entry id, tenant, alert, kind, failed_at, reason
lg-sotf dlq list --json --limit 200 > dlq.jsonl
lg-sotf dlq requeue <entry-id> [<entry-id> ...]
```

Procedure:

1. List and group by `reason`. Reasons are sanitized error classes/messages, not
   raw alert data.
2. Find the cause in worker logs: filter JSON logs by `alert_id` / `tenant_id`
   (both are bound on every worker log line) and events `worker.run_failed`,
   `worker.message_failed`, `worker.message_dead_lettered`.
3. Fix the cause first (provider outage, bad source mapping, bug fix deployed,
   budget raised). Requeueing into the same failure only refills the DLQ.
4. `lg-sotf dlq requeue <ids>`. It resets the run to `queued` and re-enqueues
   it; a `resume` letter (analyst decision/approval) is replayed after the run
   is restarted from its checkpoint, so decisions are not lost. The command
   exits non-zero and lists any entry it could not requeue.
5. Watch `lgsotf_runs_total{outcome="dead_lettered"}` stay flat.

A single alert can also be forced through again:
`lg-sotf enqueue --tenant <t> --alert <id> [--force]` (`--force` reprocesses a
finished run). For a run waiting on a decision or approval that was already
committed but never reached it (the resume message was lost),
`lg-sotf enqueue --tenant <t> --alert <id> --resume` rebuilds the resume from
the escalation row or the action ledger; the scheduler does the same on its
own (see below). Both are audited as `alert.reprocess_requested`.

## 4. Stuck runs

Symptoms: alerts stay `processing`/`queued`; `lgsotf_queue_pending` grows;
worker `/healthz` fails (liveness restarts the pod).

Built-in recovery (scheduler leader):

* `stale_runs`: a run whose worker lease (`workflow_runs.lease_expires_at`) has
  expired is requeued; runs out of attempts are failed/dead-lettered.
* `orphaned_runs`: runs left `queued`/`failed` without a queue message (Redis
  data loss, crash between commit and enqueue) are re-enqueued. The same job
  dispatches alerts left `new` with no run for more than 5 minutes (a crash
  between insert and dispatch; polled pages already commit their runs with
  the page), and rebuilds lost resumes: a run `waiting_human` whose
  escalation is `decided`, or `waiting_approval` with approved actions or
  none awaiting approval, for longer than `worker.visibility_timeout_s`, gets
  its resume re-enqueued from PostgreSQL (log `resume.recovered`).
* Resumes that reach a run which is not waiting yet (still running, or
  requeued after a crash) are retried with a short backoff (1 s doubling to
  30 s) instead of idling until the visibility timeout; a stale run whose
  alert is still waiting goes back to that waiting status.
* Dead consumers: once a crashed worker's entries are claimed and it has
  been idle for a while, it is removed from the consumer group
  (`queue.dead_consumer_removed`).
* Dead workers: each worker keeps a liveness key
  (`{prefix}:q:consumers:<consumer>:alive`) refreshed every third of its run
  lease (60 s) and deleted on a clean stop. Once a worker's key has expired
  (killed, OOM, node lost), live workers claim the stream entries it held
  (`XCLAIM`, log `queue.claimed_from_dead_consumer`) within about one lease
  plus a few seconds; with the stale-run sweep, a crash is recovered in
  roughly `2 x lease + stale_run_sweep_interval_s`, not the visibility
  timeout. A worker that restarts under the same consumer name first sends
  its predecessor's pending entries back to the stream
  (`queue.own_pending_requeued`). The run lease stays the authority: a
  claimed entry whose run is still leased by a live worker is not executed.
  During a rolling upgrade from a version without liveness keys, new workers
  treat old workers as dead and may claim their not-yet-started entries;
  this is safe (the lease decides) but can log `worker.run_not_claimable`.
* Pending entries of live workers not acknowledged within
  `worker.visibility_timeout_s` are reclaimed by other workers (`XAUTOCLAIM`).

Manual steps:

1. Confirm the scheduler has a leader (logs `leader.acquired`); with no leader,
   none of the sweeps run. Check the owner DB credentials and that the
   scheduler pods are Ready.
2. Look for runs waiting on a node timeout (`worker.node_timeout_s`,
   `analysis_timeout_s`, `run_timeout_s`): `lgsotf_node_seconds` p99 close to
   the timeout usually means the LLM provider is slow or rate limiting.
3. Inspect in SQL (owner connection):
   ```sql
   SELECT tenant_id, alert_id, status, attempt, worker_id, lease_expires_at, updated_at, last_error
   FROM workflow_runs
   WHERE status IN ('queued','running') AND updated_at < now() - interval '30 minutes'
   ORDER BY updated_at LIMIT 50;
   ```
4. For an individual run: `lg-sotf enqueue --tenant <t> --alert <id>`.
   Runs in `waiting_human` / `waiting_approval` are **not** stuck; they wait
   for an analyst decision or action approval (see SLA below).

## 5. SLA sweeps and escalations

The scheduler's `sla` job runs every `scheduler.sla_sweep_interval_s`
(default 60 s): escalations past `sla_deadline` move up a level (L1 -> L2 -> L3)
and at the top level expire. Expiry never strands an alert: a decision on an
expired escalation is still accepted and audited with `after_sla_expiry`.

* Alert when `lgsotf_escalations_open` grows for more than an hour or when
  many escalations reach L3 (analyst capacity problem, not a platform fault).
* If SLA changes stop entirely, the scheduler has no leader or the `sla` job is
  failing (logs `scheduler.job_failed` with `job=sla`).

## 6. Retention and partitions

The `maintenance` job (every `scheduler.maintenance_interval_s`, default 1 h):

* creates the next two monthly partitions of `alert_events` and `audit_log`;
* purges data older than `retention.*_days` (alerts 90, events 90, audit 365,
  indicators 30, LLM usage 400, checkpoints 30 days), dropping whole expired
  partitions where possible.

Checks: the current and next month partitions exist
(`SELECT inhrelid::regclass FROM pg_inherits WHERE inhparent = 'alert_events'::regclass;`).
If partitions are missing, inserts fall into the default partition and still
succeed, but retention becomes slower; confirm the scheduler leader is healthy.
A tenant may override `alerts_days` and `indicators_days` in
`tenants.settings.retention` (set by an operator in the database; the
`/tenant/settings` API does not edit them); `alert_events` and `audit_log`
follow the install setting because whole monthly partitions are dropped. Changing retention
takes effect at the next maintenance run.

## 7. Key rotation

Rotate on schedule (for example yearly) and immediately on suspected exposure.
Update the Secret, then roll the pods:
`kubectl -n $NS rollout restart deploy/lg-sotf-api deploy/lg-sotf-worker deploy/lg-sotf-scheduler`.

### Fernet encryption keys (`LG_SOTF_SECURITY__ENCRYPTION_KEYS`)

Comma-separated list: the **first** key encrypts, **all** keys decrypt.
The API, the worker and the scheduler check every key at startup and refuse
to start if one is not a valid Fernet key, so a bad value stops the rollout
at the first pod (ADR-0006).

1. Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
2. Prepend it: `NEW,OLD`. Roll all pods. New writes use the new key; old
   ciphertexts still decrypt.
3. Re-encrypt stored values (source credentials, tenant webhook secrets,
   tenant enrichment keys) under the new key by re-saving them through the
   admin API (`PATCH /api/v1/sources/{id}` with the credentials, tenant
   settings for webhook secrets). TOTP MFA secrets re-encrypt themselves on
   their next successful use; users who have not signed in with a code by
   step 4 need an MFA reset (docs/identity.md). The library primitive is
   `SecretBox.rotate()`; there is no bulk re-encryption command yet.
4. Only after every value is re-encrypted, remove `OLD` and roll again. A value
   still encrypted with a removed key cannot be decrypted (the source reports a
   configuration error and must be re-entered).

### JWT signing secret (`LG_SOTF_AUTH__JWT_SECRET`)

Single HS256 key. Replacing it invalidates access tokens immediately (they live
`auth.access_token_ttl_s`, default 15 min). Refresh tokens are opaque and
stored hashed in the database, so browsers obtain a new access token on the
next refresh; users are not logged out. On suspected compromise also revoke
refresh tokens (users re-login):
`UPDATE refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL;` (owner connection).
Roll the API pods together (`rollout restart`); during the rollout, requests
with a token signed by the other key get 401 and the client refreshes.

### Indicator HMAC key (`LG_SOTF_SECURITY__INDICATOR_HMAC_KEY`)

Indicator sightings are stored as HMAC-SHA256 of the value. A new key means new
alerts no longer correlate with sightings recorded under the old key, until
those age out (`retention.indicators_days`, default 30). Rotate only on
compromise, and expect reduced correlation for that window.

### Other secrets

* `LG_SOTF_API__METRICS_TOKEN`: update the Secret; the ServiceMonitor reads the
  same key; roll the API.
* Database passwords: `ALTER ROLE lgsotf_app PASSWORD '...'` (and the owner),
  update the Secrets, roll pods. With two roles, rotate one at a time.
* `LG_SOTF_RESPONSE__WEBHOOK_SECRET` / per-tenant webhook secrets: coordinate
  with the SOAR, which verifies the HMAC signature.
* LLM API keys: create the new key at the provider, update the Secret, roll
  workers, revoke the old key.

## 8. Incident checklist

1. **Scope**: which component (api/worker/scheduler), which tenants, since when
   (dashboards below, `kubectl get events`).
2. **Dependencies**: `/readyz` on each role; PostgreSQL (connections,
   `max_connections`, locks, disk), Redis (memory, `maxmemory` evictions,
   persistence), LLM provider status and 429/5xx rates
   (`lgsotf_llm_calls_total{outcome!="success"}`).
3. **Contain**:
   * Stop automated response everywhere: set `settings.response.dry_run=true`
     (or `LG_SOTF_RESPONSE__DRY_RUN=true`) and roll workers.
   * LLM misbehaving or over budget: switch the tier model, lower
     `llm.daily_token_budget_per_tenant` (agents fall back to rules), or
     disable LLM calls with `llm.enabled=false`.
   * Suspend a tenant (`tenants.status = 'suspended'`) if one tenant's traffic
     is the cause.
4. **Security incident** (credential leak, suspicious access): rotate the
   affected keys (section 7), revoke API keys (`/api/v1/api-keys`) and refresh
   tokens, export the tamper-evident `audit_log` for the period (hash chain per
   tenant) before retention can remove it.
5. **Recover**: requeue the DLQ after the fix (section 3); verify the scheduler
   sweeps drain `queued` runs; check escalations that expired during the
   incident.
6. **Review**: timeline, customer impact per tenant, follow-up actions; add a
   test for the bug that caused it.

## 9. Observability

Logs are JSON on stderr with `request_id`, `tenant_id`, `alert_id`,
`thread_id`, `node` context. There is no tracing
([ADR-0008](adr/0008-remove-tracing.md)): `observability.otlp_endpoint` is
ignored, and each process logs `observability.otlp_endpoint_deprecated` at
startup while it is set; remove it from your configuration. Metrics are Prometheus: API `/metrics` (bearer
`api.metrics_token`), worker and scheduler `:9100/metrics`
(`serviceMonitor.enabled=true` wires all three).

### Dashboards to create

| Dashboard | Panels (PromQL sketches) |
|---|---|
| Overview | request rate and 5xx ratio `sum(rate(lgsotf_http_requests_total{status=~"5.."}[5m])) / sum(rate(lgsotf_http_requests_total[5m]))`; p95 latency `histogram_quantile(0.95, sum by (le, route) (rate(lgsotf_http_request_seconds_bucket[5m])))`; pod restarts |
| Pipeline | `lgsotf_queue_depth` and `lgsotf_queue_pending` by stream; `sum by (outcome) (rate(lgsotf_runs_total[5m]))`; node p90 `histogram_quantile(0.9, sum by (le, node) (rate(lgsotf_node_seconds_bucket[15m])))`; worker replicas; transactions retried after a migration `increase(lgsotf_db_stale_statement_retries_total[1h])` (expected only around an upgrade) |
| LLM | calls by model/agent/outcome; tokens `sum by (model, kind) (rate(lgsotf_llm_tokens_total[1h]))`; spend `sum by (model) (increase(lgsotf_llm_cost_usd_total[1d]))`; refusals and skipped calls by reason |
| Analysts | `lgsotf_escalations_open`; actions by status `sum by (status) (rate(lgsotf_actions_total[1h]))` |
| Ingestion | `lgsotf_ingest_events_total`, `lgsotf_source_polls_total` by outcome, `lgsotf_source_poll_seconds` |

### Alerts to create

| Alert | Condition (starting point) | Severity |
|---|---|---|
| API down | no ready API pods for 2 m, or `/readyz` failing | page |
| High API error rate | 5xx ratio > 2 % for 10 m | page |
| Queue backlog growing | `sum(lgsotf_queue_depth{stream!="dlq"})` increasing for 30 m and workers at max | page |
| High-priority backlog | `lgsotf_queue_depth{stream="high"} > 50` for 15 m | page |
| Dead letters | `increase(lgsotf_queue_depth{stream="dlq"}[15m]) > 0` | ticket (page if > 20) |
| Run failures | `rate(lgsotf_runs_total{outcome=~"failed|dead_lettered"}[15m]) / rate(lgsotf_runs_total[15m]) > 0.05` | page |
| No scheduler leader | no scheduler pod logged leadership in 5 m, or `lgsotf_queue_depth` stops updating | page |
| LLM errors | `rate(lgsotf_llm_calls_total{outcome=~"error|invalid_output"}[10m]) / rate(lgsotf_llm_calls_total[10m]) > 0.1` | page |
| LLM spend | daily `increase(lgsotf_llm_cost_usd_total[1d])` above budget | ticket |
| Escalation backlog | `lgsotf_escalations_open` above analyst capacity for 1 h | ticket |
| Source polling failing | `increase(lgsotf_source_polls_total{outcome="error"}[30m]) > 0` for a source type | ticket |
| Pod restarts / OOM | `kube_pod_container_status_restarts_total` increase, `OOMKilled` | ticket |
| Certificates | TLS certificate expiry < 14 days | ticket |

Tune thresholds to your volume after a week of baseline data. Metric labels are
deliberately low cardinality (never tenant or alert ids); per-tenant views come
from the API (`/api/v1/dashboard/summary`, `/api/v1/usage/llm`) and logs.
