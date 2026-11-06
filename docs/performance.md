# Performance and sizing

This page reports how LG-SOTF behaves under load, where it stops scaling,
and how to size a deployment. Every number comes from
`scripts/load_test.py` driving the real processes (`lg-sotf api`,
`lg-sotf scheduler`, N × `lg-sotf worker`) through the public API. The
measurement date was 2026-09-29, on the code at commit `ebbc6b5`.

**Summary.**

* **No alert was lost and no run failed.** In the main scenario, 13,795
  alerts were ingested in 7 minutes, including bursts of up to 200/s. All
  of them settled, with no failed run, no retry, nothing in the dead-letter
  queue and no worker restart.
* **Default workers are slow because of configuration, not CPU.** With the
  defaults and one tenant, a worker finishes about **1.45 alerts/s** when
  an LLM call takes 2 s. That is about 125,000 alerts/day. The worker uses
  17% of one core. The limit is the per-tenant cap of 8 runs in flight per
  worker (half of `worker.concurrency`). Behind it are the per-process LLM
  slots (`llm.fast.max_concurrency` 16, `llm.deep.max_concurrency` 8).
  With those caps raised, one worker process reaches **~10 alerts/s**
  (~860,000/day) before it runs out of CPU (~85 ms of CPU per alert).
* **The deep model's latency sets the capacity.** With a 2 s fast tier and
  a 14 s deep tier, a default worker settles about 0.67 alerts/s
  (58,000/day). The limit is the 8 deep-model slots per process.
* **One API process accepts about 70 single-alert requests/s.** Above that
  it collapses: latency grows to 7–24 s, it accepts fewer requests per
  second, and it answers 503 when the 10-connection pool runs out. When
  senders batch 50 alerts per request, the same process accepts
  **~700 alerts/s**.
* **Queries slow down as the database grows.** With 114,000 alerts, the
  dashboard for a long window takes 0.5–0.9 s. Alert-list filters that
  match few rows scan the whole index (250 ms). Both costs grow linearly
  with alert volume.
* **Checkpoints are the largest growth factor.** The LangGraph checkpoint
  tables take about **44 KB per alert**. That is about 4.4 GB/day at
  100,000 alerts/day.

## After the fix release

The results below were measured on commit `ebbc6b5`. The bottlenecks they
found (B1–B10 under *Bottlenecks and fixes*) were then fixed; re-running the
relevant parts of `scripts/load_test.py` on the same host gives:

| Measurement | Before | After |
|---|---|---|
| Drain 400 alerts, 1 worker, defaults, 2 s per call (`--mode drain --backlog 400 --workers 1`) | 270 s, 1.48 alerts/s, 8 runs in flight | **128 s, 2.97 alerts/s**, 16 runs in flight |
| Stream `XADD` per alert during that drain (fair-share requeue churn) | ~30 | **1** |
| Single-alert ingest at 100/s, one API process (`--phases r75:75:20,r100:100:20,r150:150:20 --batch 1`) | 46/s accepted, p50 8.7 s, 503 `PoolExhausted` | **100/s accepted, p50 15 ms, p95 24 ms** |
| Single-alert ingest at 150/s | 66/s accepted, p50 6.6 s | **150/s accepted, p50 21 ms, p95 53 ms** |

What changed:

* B1: `worker.per_tenant_concurrency` applies only while other tenants have
  work in the same worker; a tenant alone uses every slot.
* B2: a worker whose whole batch belongs to tenants at their cap waits for a
  run to finish instead of re-queueing the batch in a loop.
* B3: `llm.<tier>.max_concurrency` defaults to `worker.concurrency`; slot
  waits are exported as `lgsotf_llm_slot_wait_seconds{tier}`.
* B4: dispatch is batched (three statements per request, one pipelined
  `XADD` round trip), and `api.max_inflight_ingest` (64) refuses overload at
  once with `503` + `Retry-After` instead of queueing on the pool (a
  backlog sender at ~100 req/s saw 19 of 400 requests refused this way).
* B5: WebSocket buffers are configurable (`api.ws_subscriber_buffer`) and
  events are no longer deep-copied per subscriber.
* B6: escalation grouping looks up related alerts before it takes the
  per-tenant lock.
* B7/B8: migration 0003 adds `ix_alerts_status_severity`,
  `ix_alerts_disposition`, `ix_alerts_tenant_closed`,
  `ix_escalations_claimed` and `ix_workflow_runs_active`; the dashboard
  counts only unfinished runs.
* B9: a completed run keeps only its final checkpoint (runs still waiting
  on an analyst keep theirs until they finish; about 42 KB per waiting
  alert in the drain above).
* B10: a worker's pool grows with `worker.concurrency`
  (`max(pool_max, concurrency / 2)`), and docs/deployment.md gives the
  `max_connections` budget.

The sizing table below still uses the pre-fix defaults; with the fixes the
"per tenant 16" column is what the defaults now give a single tenant, and
the deep-slot limit applies only when `llm.deep.max_concurrency` is set.
Not re-measured: the 100k-alert main scenario and query timings at
millions of alerts (see *Caveats*).

## Methodology

### Test bed

| | |
|---|---|
| Host | one VM, 4 vCPU, 15 GB RAM. The load generator, the API, the scheduler, the workers, PostgreSQL and Redis all ran on it |
| PostgreSQL | 16, stock Ubuntu configuration (`max_connections=100`, `shared_buffers=128MB`). Local TCP with TLS (the default `sslmode=prefer`) |
| Redis | 7, stock configuration |
| Application | `environment=development`, one role for the whole install, default settings unless a run says otherwise |
| LLM | `provider=fake` with an injected latency per structured call: uniform `lo:hi` seconds, separately for the fast and deep tiers |

Everything shares four cores. The absolute ceilings measured here (API
requests/s, worker alerts/s per process) are therefore conservative. The
ratios and the bottlenecks carry over to larger hosts.

A second, independent compose stack started on the same host at 16:16.
The last two ingest-ceiling runs overlapped with its start, and it was
mostly idle. The main scenario and the capacity runs finished before it
started.

### Latency injection

`scripts/load_test.py` writes a `sitecustomize.py` into its work directory
and puts it on the workers' `PYTHONPATH`. Before each structured call to
`FakeChatModel`, it sleeps for a time drawn uniformly from the tier's
range (`LOADTEST_LLM_LATENCY=fast=1:3,deep=8:20`). The workers therefore
wait on the model the way they do on a hosted model. The application code
is unchanged: every LLM call passes through `ainvoke_structured`, the
per-tier slots (`llm_slot`), usage metering and budgets, as in
production.

The fake model escalates most alerts. In these tests 77–80% of alerts
ended `waiting_human`, 15–20% `waiting_approval` and 3% `closed`. On
average an alert needed **2.64 LLM calls**: 1.0 triage (fast), 0.97
correlation (fast) and 0.77 analysis (deep). A real model closes more
noise at triage, so it makes fewer calls per alert. The sizing below
takes the calls per alert as a parameter.

### Load

* **Seed.** 100,000 alerts spread over the last 30 days: 86% closed, 8%
  waiting for a human, 2% waiting for an approval, 4% failed and
  dead-lettered. Each has a workflow run. About 20,000 escalations
  (open, or decided with claim times), 300,000 indicator sightings and 30
  days of LLM usage rows are seeded too. Row sizes are close to those of
  real processed alerts (`summary` about 1.6 KB compressed, against
  2.2 KB for processed alerts). Seeding takes 38 s.
* **Ingest.** `POST /api/v1/ingest/alerts` with an `ingest` API key,
  sent open-loop at a fixed rate (requests are sent on schedule even
  when earlier ones have not returned), with at most 512 requests in
  flight. By default there is one alert per request, the worst case and
  what most webhook senders do. The mix is 55% benign-looking, 30%
  suspicious and 15% malicious, with random hosts, users, IPs and
  domains. 20% of alerts share one "hot" IP (a proxy or DNS server).
* **Readers.** Four viewer accounts, one request per second each, in
  rotation:
  * `GET /dashboard/summary`, both the cached 24 h window and a random
    window of 25 h to 90 days (a cache miss);
  * `GET /alerts` first page, the next page by cursor,
    `status=waiting_human`, `severity=critical&severity=high`, and a
    `q=` title search.
* **Live clients.** Twenty WebSocket clients on `/ws`.
* **Measurements.** Every 2 s the sampler records:
  * stream depth, pending entries and lag of both work streams, and the
    DLQ depth;
  * Redis `used_memory`, clients and command counts;
  * `pg_stat_activity` per application name and state. The workers'
    LangGraph checkpointer pools are named `ckpt-workerN` through
    `PGAPPNAME`;
  * RSS and CPU of every process, host CPU, PostgreSQL CPU, and the
    load generator's own CPU and event-loop lag;
  * the status of every ingested alert.

  At the end the script also collects:
  * the workers' and the API's Prometheus metrics (node timings, HTTP
    timings);
  * warnings and errors from every log;
  * `EXPLAIN ANALYZE` of the dashboard, alert-list and correlation
    queries under the tenant's RLS scope, before and after the load;
  * the time from ingestion to settling for each alert (from
    `alerts.ingested_at` to the run's completion or wait).
* **Profiles.** `py-spy` was attached to the API during single-alert
  ingestion and to a CPU-bound worker. It is not part of the script.

### Reproducing

```sh
source /home/user/venv/bin/activate
# main scenario (about 45 minutes): 100k seed, 4 workers, 1-3 s per LLM call,
# 10/50/200 alerts/s bursts, then 30 alerts/s for 5 minutes, then wait until every alert settles
python scripts/load_test.py --reset \
  --database-url postgresql://soc:soc_dev_password@127.0.0.1:5432/soc_test_e \
  --redis-url redis://127.0.0.1:6379/5 --settle-timeout 3600

# capacity of N workers: queue a backlog, measure how fast it drains
python scripts/load_test.py --reset --seed 0 --mode drain --backlog 800 --workers 4
# ... with the concurrency caps raised
python scripts/load_test.py --reset --seed 0 --mode drain --backlog 1200 --workers 1 \
  --worker-concurrency 64 --per-tenant-concurrency 64 \
  --env LG_SOTF_LLM__FAST__MAX_CONCURRENCY=64 --env LG_SOTF_LLM__DEEP__MAX_CONCURRENCY=64
# ingest ceiling with batched senders
python scripts/load_test.py --reset --seed 0 --workers 1 --batch 50 \
  --phases b300:300:20,b500:500:20,b700:700:20 --settle-timeout 0
```

`--reset` drops the database's `public` schema and flushes the Redis
database. The script refuses a database whose name does not contain
`test`, `load` or `perf`. See `--help` for every option. The JSON report
(`--out`) holds all the numbers, including the 2-second timeline.

## Results

### 1. Main scenario: 4 workers, 1–3 s per LLM call, 100k seeded alerts

| Phase | Offered | Achieved | Ingest latency p50 / p95 / p99 | Errors |
|---|---|---|---|---|
| burst 10/s × 30 s | 300 | 10.0/s | 20 / 51 / 154 ms | 0 |
| burst 50/s × 30 s | 1,500 | 50.0/s | 25 / 84 / 135 ms | 0 |
| burst 200/s × 15 s | 3,000 | **67/s** | **7.5 / 14.4 / 18.1 s** | 4 connection resets (0.13%) |
| sustained 30/s × 300 s | 9,000 | 30.0/s | 21 / 60 / 118 ms | 1 connection reset |

In the 200/s burst the API saturated: it accepted 67 alerts/s, the
server-side mean was about 2.9 s, and clients waited 7–18 s. During that
phase the load generator also lagged (event-loop stalls up to 4.5 s).
The client-side percentiles of that phase are therefore upper bounds,
but the server-side means and the separate ingest-ceiling runs (§3)
confirm the saturation.

End to end:

* **Settled:** 13,795 of 13,795. No failed or dead-lettered run, one
  attempt per run, DLQ always empty.
* **Throughput:** 5.3–7.2 alerts/s for the 4 workers (430 completions per
  minute while high-severity alerts were draining, 315 per minute
  afterwards). The workers split the work evenly: 3,445 / 3,465 / 3,437 /
  3,448 runs.
* **Backlog:** peaked at **10,869 entries** when ingestion stopped (7 min).
  Draining it took another 34 minutes.
* **Time from ingestion to settling:** p50 954 s, p95 2,149 s, max
  2,444 s. It is set by the backlog, because the offered rate (30/s
  sustained) is 5× the capacity. Alerts in the high-priority stream
  (high and critical) went first: those that ended `waiting_approval`
  had a median of 12 s. Normal-stream alerts waited up to 40 minutes.
* **Node time per run:**

  | Node | Mean time | Comment |
  |---|---|---|
  | triage | 1.82 s | about one model call |
  | correlation | 2.03 s | about one model call |
  | analysis | 2.08 s | about one model call |
  | escalate | 66 ms | 16–20 ms in the smaller runs; see B6 |
  | gate | 8 ms | |
  | plan_response | 69 ms | |

* **Memory:**
  * workers: RSS 169 → 194 MB, growth in the second half of the run
    0.07–0.17 MB/min over 13,800 runs. No leak.
  * API: RSS 110 → 144 MB after the burst, then flat.
  * scheduler: RSS 125 → 129 MB.
  * Redis: 1.8 MB idle, **3.5 MB** at the 10,869-entry backlog (acked
    entries are deleted), about 170 bytes per queued entry.
* **PostgreSQL:**
  * **connections:** at most **40** on this database (51 on the server).
    By pool: API up to 14 (pool size 10); workers at most 5 each on the
    asyncpg pool and 1 each on the checkpointer pool; scheduler 5 plus
    the leader lock.
  * **longest statement:** 0.5 s.
  * **PostgreSQL CPU:** peak 1.6 cores.
* **Redis commands:** 408,758 `XADD` for 13,795 alerts, i.e. **30 per
  alert**. This is the fair-share deferral churn described in B2. Redis
  CPU peaked at 0.11 cores.
* **Storage written:**

  | Table | Rows | Size | Per alert |
  |---|---|---|---|
  | checkpoints | 106,463 | | 7.7 |
  | checkpoint_writes | 645,901 | | 47 |
  | checkpoint_blobs | 260,352 | | 19 |
  | all checkpoint tables | | **607 MB** | **44 KB** |
  | alert_events | 87,885 | | 6.4 |
  | escalations | 2,735 | | |

  Related alerts attached to open escalations.

Readers during the run (114,000 alerts in the tenant):

| Request | p50 | p95 | p99 |
|---|---|---|---|
| `GET /alerts` (first page) | 15 ms | 40 ms | 114 ms |
| `GET /alerts` (next page, cursor) | 15 ms | 35 ms | 60 ms |
| `GET /alerts?status=waiting_human` | 20 ms | 44 ms | 100 ms |
| `GET /alerts?severity=critical&severity=high` | 16 ms | 36 ms | 64 ms |
| `GET /alerts?q=beacon` (30-day window) | 20 ms | 136 ms | 225 ms |
| `GET /dashboard/summary` (24 h, cached 15 s) | 9 ms | 183 ms | 273 ms |
| `GET /dashboard/summary` (25 h–90 d, cache miss) | **485 ms** | **704 ms** | **886 ms** |

The maximum of every reader was 3–11 s, all of it during the 200/s
burst, when the API was saturated.

WebSocket:

* **Volume:** 3.2 million events, about **12 events per alert per
  client**: 7.7 `alert.updated`, 2 `alert.created` (dispatch), plus
  escalation and action events.
* **Delivery delay:** p50 3.6 ms, p95 21 ms.
* **Disconnects:** all 20 clients were disconnected with **1013** (the
  API log shows `events.subscriber_lagged`) during the 200/s burst, and
  reconnected.

### 2. Worker capacity (drain a backlog; 1–3 s per call unless stated)

| Workers | Settings | Backlog | Drain time | Alerts/s total | Per worker | Worker CPU | Alerts/day per worker |
|---|---|---|---|---|---|---|---|
| 1 | defaults (concurrency 16, per tenant 8) | 400 | 270 s | 1.48 | 1.48 | 16% | 128,000 |
| 2 | defaults | 600 | 204 s | 2.94 | 1.47 | 16% | 127,000 |
| 4 | defaults | 800 | 140 s | 5.7 | 1.43 | 16% | 124,000 |
| 1 | per tenant 16 | 400 | 130 s | 3.1 | 3.1 | 27% | 266,000 |
| 1 | concurrency 64, per tenant 64, LLM slots default (16/8) | 800 | 173 s | 4.6 | 4.6 | 40% | 400,000 |
| 1 | concurrency 64, per tenant 64, **LLM slots 64/64** | 1,200 | 120 s | **10.0** | 10.0 | 83% | **864,000** |
| 1 | concurrency 128, per tenant 128, LLM slots 128/128 | 2,000 | 198 s | 10.1 | 10.1 | 87% | 873,000 |
| 2 | per tenant 16, **deep tier 8–20 s** | 400 | 301 s | 1.33 | 0.67 | 7% | 58,000 |

These runs used no seed (an empty database), and their mean run time
matches the model below:

* 5.15 s per run at 1–3 s per call;
* 22–24 s per run with an 8–20 s deep tier, where the analysis node
  took 23.3 s on average for about one 14 s call (see B3).

### 3. API ingest ceiling (one `lg-sotf api` process, readers off)

| Sender | Offered | Accepted | Latency p50 / p95 / p99 | Errors |
|---|---|---|---|---|
| 1 alert per request | 75/s | 74/s | 23 / 310 / 660 ms | 0 |
| 1 alert per request | 100/s | **46/s** | 8.7 / 18.4 / 22.5 s | 4 × 503 `PoolExhausted`, 2 resets |
| 1 alert per request | 150/s | **66/s** | 6.6 / 11.7 / 15.8 s | 8 resets |
| 50 alerts per request | 300/s | 300/s | 162 / 380 / 490 ms | 0 |
| 50 alerts per request | 500/s | 498/s | 307 / 529 / 807 ms | 0 |
| 50 alerts per request | 700/s | 683/s | 1.19 / 1.60 / 1.74 s | 0 |
| 50 alerts per request | 1,000/s | < 700/s | 6.8 / 11.4 / 12.5 s | 0 |

Notes on these runs:

* `py-spy` was attached during the 100/s phase. The 150/s phase ran
  without it.
* Single-alert ingestion costs about **7.5 ms of API CPU per request**
  (0.75 cores at 100 requests/s).
* At 500–700 alerts/s all five WebSocket clients were disconnected
  repeatedly (55 closes with code 1013). The load generator's loop lag
  stayed under 33 ms, so the lag was on the server.

### 4. Database queries at volume (EXPLAIN ANALYZE, tenant RLS scope)

Measured after the main scenario: 114,000 alerts, 114,000 runs, about
23,000 escalations. Times are for three executions.

| Query (code) | Time | Plan |
|---|---|---|
| dashboard counts, 24 h (`AlertsRepo.dashboard_counts`) | 22–70 ms | index scan, 17,000 rows |
| dashboard counts, 30 d | 147–158 ms | **seq scan** of all alerts |
| MTTA/MTTR, 30 d (`AlertsRepo.response_times`) | 141–152 ms | **seq scans** of `escalations` (no index on `claimed_at`) and of `alerts` |
| runs by status (`RunsRepo.counts_by_status`) | 36–50 ms | index-only scan of **every run ever**, whatever the dashboard window |
| open escalations | 6–8 ms | index |
| alert list, first page | 0.2–0.4 ms | index |
| alert list, `status=waiting_human` | 0.2–0.4 ms | index |
| alert list, `disposition=inconclusive` | 16–31 ms | walks `ix_alerts_ingested`, filters 14,600 rows |
| alert list, `severity=critical AND status IN (waiting_human, failed)` (no match) | **253–271 ms** | walks **all 113,795 rows** of `ix_alerts_ingested` |
| title search `q=`, 30-day window | 70–91 ms | seq scan of the window (38,000 rows) |
| correlation `related_alerts` for the hot indicator (60 min window, 2,731 sightings) | < 10 ms for the application query | index |

Before the load (100,000 seeded alerts) the same queries were about 20%
faster. All of them grow linearly with the tenant's alert count (or the
window). At 100,000 alerts/day with the default 90-day retention (9
million alerts), the extrapolated times are:

* the no-match filter above: about 20 s, close to
  `statement_timeout` = 30 s;
* the 30-day dashboard: about 4 s;
* runs by status: about 3 s on every dashboard cache miss.

## Bottlenecks and fixes

Ordered by impact on a customer deployment.

**B1. Single-tenant installs run at half the configured concurrency.**
`Worker._try_reserve_tenant` (`src/lg_sotf/runtime/worker.py`) caps runs
per tenant per process at `worker.per_tenant_concurrency` (8). The
default `worker.concurrency` is 16. A single-organisation install (the
`default` tenant) therefore never uses 8 of its 16 slots.

* **Evidence:** 1.48 alerts/s at the defaults, 3.1 alerts/s with
  `per_tenant_concurrency=16` (2.1×). Worker CPU was 16%.
* **Fix:** default `per_tenant_concurrency` to `concurrency`, or derive
  it from the number of active tenants, so the cap only applies when
  other tenants are waiting. Document the cap in the sizing section of
  the deployment guide.

**B2. Fair-share deferral churns Redis and reorders the queue.** A worker
reads up to `free` messages. When the tenant is at its cap,
`Worker._defer` → `StreamConsumer.requeue` puts each of them back at the
tail: one `XADD` + `XACK` + `XDEL` in a `MULTI`. The loop sleeps
`_DEFER_BACKOFF_S` (0.25 s) only when every message was deferred.

* **Evidence:** 408,758 `XADD` for 13,795 alerts, i.e. 30 requeues per
  alert. That is about 170 `XADD`/s plus the same number of `XACK`,
  `XDEL`, `MULTI` and `EXEC` for as long as a backlog exists.
* **Effects:**
  * wasted worker CPU;
  * arrival order within a stream is lost: a deferred alert goes behind
    newer ones;
  * `StreamConsumer._reclaim` issues `XAUTOCLAIM` on both streams at every
    read (108,000 calls).
* **Fix:** stop reading while a tenant is at its cap. For example, keep
  a per-tenant local queue, or read with `COUNT` equal to the free
  per-tenant capacity, and back off on `_wait_for_free_slot` instead of
  requeueing. Where fair share across tenants matters, prefer per-tenant
  streams (or Redis consumer-group sharding) over requeue-to-tail.

**B3. The per-process LLM slots are smaller than the worker concurrency.**
`llm_slot` (`src/lg_sotf/llm/client.py`) allows 16 fast and 8 deep calls
in flight per process, while `worker.concurrency` is 16. Runs above the
slots queue inside the node, and the wait counts against
`worker.node_timeout_s` (180 s) and `worker.analysis_timeout_s`.

* **Evidence at 1–3 s per call:** with concurrency 64 and the default
  slots, triage took 5.8 s and correlation 5.6 s per node for a 2 s
  call, at 4.6 alerts/s. With 64 slots the same worker settled 10
  alerts/s.
* **Evidence with an 8–20 s deep tier and per tenant 16:** the analysis
  node averaged 23.3 s for about one 14 s call. Throughput was 0.67
  alerts/s per worker, exactly the 8 deep slots divided by the deep
  seconds per alert.
* **Fix:**
  * size the slots from the concurrency (for example default
    `max_concurrency = worker.concurrency`);
  * log or record slot wait time as its own metric, for example
    `lgsotf_llm_slot_wait_seconds{tier}`;
  * treat the slots as a guard for provider rate limits (requests per
    minute and tokens per minute), preferably shared across processes
    (a Redis token bucket), not as a per-process throughput limit.

**B4. The API saturates at about 70 single-alert requests/s and then
collapses.**

* **Causes:**
  * `lg-sotf api` (`src/lg_sotf/cli.py`) runs one uvicorn process and
    has no `--workers` option.
  * Each single-alert request spends about 7.5 ms of CPU. The profile
    shows no single hotspot: FastAPI/Starlette middleware about a third,
    and normalisation, redaction and logging about a quarter.
  * Each request takes a pool connection 4–5 times in separate
    transactions: API-key lookup, `sources.get`, the insert transaction,
    and the `dispatch_new_alerts` transaction. The dispatch transaction
    also makes two round trips per alert (`upsert_queued` +
    `update_status`), followed by one `XADD` and one `PUBLISH` per
    alert.
* **Evidence:** beyond about 75 requests/s, hundreds of requests queue
  on the 10-connection pool. Acceptance fell to 46–66/s, latency rose to
  7–24 s, and `PoolExhausted` produced 503s after the 10 s acquire
  timeout.
* **Fixes:**
  * **admission control:** a bounded semaphore on the ingest routes that
    answers 429 or 503 with `Retry-After` at once instead of queueing
    unbounded work;
  * **batch dispatch:** one `INSERT … ON CONFLICT` for all runs and one
    `UPDATE … WHERE id = ANY(…)`, a pipelined `XADD`/`PUBLISH`, and one
    connection for the whole request;
  * **an `--workers` option**, or document running several API replicas
    (the Helm HPA already scales them);
  * **tell integrators to batch.** 50 alerts per request gives about
    700 alerts/s per process.

  The ingest rate limit (`api.ingest_rate_limit_per_minute`, 6,000
  requests/min) counts requests, not alerts. It would allow 100
  single-alert requests/s, more than one process can serve.

**B5. WebSocket subscribers are disconnected when the API is busy.**
Each subscriber has a 256-event buffer (`DEFAULT_SUBSCRIBER_BUFFER`,
`src/lg_sotf/queue/events.py`). Every event is deep-copied per subscriber
in `_Hub._dispatch`. Every API replica pattern-subscribes to all tenants'
events. About 12 events per alert reach every client of a tenant.

* **Evidence:** during ingest bursts the API event loop cannot forward
  fast enough. The buffer overflows and the client is closed with 1013:
  20 of 20 clients at 200 alerts/s, and 55 closes for 5 clients at
  500–700 alerts/s while the load generator itself had no lag. The UI
  then re-reads state through the REST API, which adds load at the worst
  time.
* **Fix:**
  * coalesce `alert.updated` events per alert (for example 1 per 500 ms)
    and share one immutable serialized payload across subscribers
    instead of `deepcopy`;
  * subscribe per tenant channel only for tenants with connected
    clients;
  * make the buffer configurable.

**B6. Escalation grouping is serialized per tenant.**
`EscalationService.open_or_attach` (`src/lg_sotf/services/escalation.py`)
takes `pg_advisory_xact_lock(locks.ESCALATION_GROUP, hashtext(tenant_id))`
and then runs `sightings_for_alert`, `related_alerts` (limit 100 over the
60-minute window) and `_FIND_PARENT_SQL` inside that lock. It also writes
the audit record, which takes the tenant's audit-chain lock.

* **Evidence:** the `escalate` node went from 16–20 ms in the small runs
  to **66 ms** with 4 workers, 32 runs in flight and 2,700 escalations.
  At about 80% escalation, one tenant cannot escalate faster than about
  1 / (time the lock is held), whatever the number of workers. At 66 ms
  that is roughly 15–40 escalations/s.
* **Fix:**
  * compute the related alerts before taking the lock (they are only
    candidates);
  * lock per case key or fingerprint rather than per tenant;
  * keep only the parent lookup and attach step under the lock.

**B7. Dashboard queries scan the whole history.** `_compute`
(`src/lg_sotf/api/routers/dashboard.py`) runs five queries per cache miss:

* `RunsRepo.counts_by_status` counts every run the tenant ever had (no
  window);
* `AlertsRepo.response_times` seq-scans `escalations` (no index on
  `claimed_at`) and alerts closed in the window;
* `dashboard_counts` seq-scans for windows longer than a few days.

**Evidence:** uncached dashboard p50 485 ms, p95 704 ms at 114,000
alerts. It grows linearly, to seconds at millions of alerts. The cache
key includes `window_hours`, so every distinct window is a miss.

**Fix:**

* restrict run counts to non-terminal statuses (`queued`, `running`,
  `waiting_*`) using a partial index;
* add `escalations (tenant_id, claimed_at)` and
  `alerts (tenant_id, closed_at) WHERE status = 'closed'` (the existing
  `ix_alerts_closed_at` has no `tenant_id`);
* maintain an hourly roll-up table (tenant, hour, status, severity,
  disposition, count) updated by the scheduler or by triggers, and read
  long windows from it;
* restrict `window_hours` to a few presets so the cache is effective.

**B8. Alert-list filters that match few rows walk the whole index.**
`AlertsRepo.list` orders by `(ingested_at, id)`. With several filters,
PostgreSQL picks `ix_alerts_ingested` and filters row by row.

* **Evidence:** 253–271 ms for `severity=critical` together with
  `status=waiting_human,failed` with no match (all 113,795 index rows
  read), and 16–31 ms for `disposition=inconclusive`. There is no
  `disposition` index. Extrapolated, a common analyst filter would come
  close to the 30 s `statement_timeout` at 9 million alerts.
* **Fix:**
  * add composite indexes for the filters the UI offers, for example
    `(tenant_id, status, severity, ingested_at DESC, id DESC)` and
    `(tenant_id, disposition, ingested_at DESC, id DESC)`;
  * or bound unfiltered-order scans by a default time window, as `q`
    already is;
  * consider a per-request `statement_timeout` well below 30 s for list
    endpoints.

**B9. Checkpoint storage grows about 44 KB per alert.** `durability="sync"`
(`WorkflowEngine._invoke`) writes about 7.7 checkpoints, 47 writes and
19 blobs per alert: 607 MB for 13,800 alerts. At 100,000 alerts/day that
is about 4.4 GB/day. With `retention.checkpoints_days=30` it reaches
about 130 GB before retention catches up. Waiting runs, most runs with
the fake model, keep their checkpoints until they are decided.
Checkpoint I/O is also about a quarter of a CPU-bound worker's busy
time in the profile (`AsyncPostgresSaver.aput_writes` and `aput`).

**Fix:**

* delete a thread's checkpoints except the last one when a run completes;
* use `durability="exit"` for nodes that do not need a checkpoint
  between them (the side-effecting nodes are already idempotent);
* shorten the default retention and document the storage in the
  deployment guide.

**B10. The pool sizes are small compared with high worker concurrency.**
Each worker has a 10-connection asyncpg pool (`database.pool_max`) and a
checkpointer pool of `min(pool_max, concurrency)` (`WorkflowEngine.create`).
With concurrency 64 the worker used all 10 asyncpg connections and
queued on them. No `PoolExhausted` occurred in the worker runs.

**Fix:**

* derive the pool sizes from `worker.concurrency` (for example half of
  the concurrency, capped);
* document `max_connections` ≥ API replicas × `pool_max` + workers ×
  (`pool_max` + checkpointer pool) + scheduler (6) + the migrate job,
  or put PgBouncer in transaction mode in front (the checkpointer
  already uses `prepare_threshold=0`).

What held up under load:

* no alert was lost or ran twice;
* no run timed out, and no worker or scheduler warning or error was
  logged;
* the DLQ stayed empty;
* high-priority alerts were served first;
* Redis memory stayed trivial;
* no process leaked memory over 40 minutes and 13,800 runs;
* the readers' first-page and cursor queries stayed under 50 ms at
  p95 at 114,000 alerts;
* WebSocket delivery was fast (p95 21 ms) while the API was not
  saturated.

## Sizing guidance

A worker's throughput is the smallest of four limits:

```
runs in flight   C = min(worker.concurrency, worker.per_tenant_concurrency × busy tenants)
run time         T ≈ n_fast × L_fast + n_deep × L_deep + 0.5 s        (no slot wait)
LLM slot limits  S_fast / (n_fast × L_fast)   and   S_deep / (n_deep × L_deep)
CPU limit        ≈ 10 alerts/s per worker process (one core; about 85 ms of CPU per alert)

alerts/s per worker = min(C / T, fast slot limit, deep slot limit, CPU limit)
alerts/day per worker = 86,400 × alerts/s per worker
```

The terms are:

* `n_fast`, `n_deep`: model calls per alert. Measured here: 1.97 fast and
  0.77 deep. Measure yours with `/usage/llm` calls divided by the number
  of alerts.
* `L_fast`, `L_deep`: mean seconds per call.
* `S_fast`, `S_deep`: `llm.fast.max_concurrency` (16) and
  `llm.deep.max_concurrency` (8).

The table gives alerts/day **per worker process**. The first two rows
were measured. The others come from the formula, with the measured call
mix (1.97 fast and 0.77 deep calls per alert) and a CPU limit of about
10/s per process:

| LLM latency (fast / deep) | Defaults, one tenant (C=8, slots 16/8) | per tenant 16 (C=16, slots 16/8) | Tuned (C=64, slots 64/64, pool 20) |
|---|---|---|---|
| 2 s / 2 s | **125,000** (measured; the formula gives 116,000) | **266,000** (measured; the formula gives 231,000) | **860,000** (measured, CPU bound) |
| 2 s / 14 s | 45,000 | **58,000** (measured; the formula gives 64,000) | 363,000 |
| 2 s / 30 s | 25,000 | 30,000 | 201,000 |
| 5 s / 30 s | 21,000 | 30,000 | 165,000 |

How to use it:

1. **Pick the worker count** from your peak sustained rate, not the daily
   mean. Alerts arrive in bursts, so leave 2× headroom: a backlog of
   B alerts drains at (capacity − arrival rate). In the main scenario
   the 4 default workers (5.7/s) needed 41 minutes to settle a 7-minute
   burst.
2. **For one organisation**, set `worker.per_tenant_concurrency` equal to
   `worker.concurrency` (B1).
3. **When raising `worker.concurrency`**, raise `llm.fast.max_concurrency`
   and `llm.deep.max_concurrency` to match (B3), and
   `database.pool_max` to about concurrency/2. Keep an eye on the
   provider's rate limits. For example, 30 alerts/s × 2.64 calls is
   about 80 requests/s, or 4,800 per minute, across all workers.
4. **Worker memory and CPU:** about 200 MB RSS per worker process
   (stable), one core at 10 alerts/s. Plan one vCPU per worker process
   that you run near its CPU limit. Workers waiting on a slow model use
   little CPU (7–17%), so several workers can share a core.
5. **API replicas:** one per 50–60 single-alert requests/s at peak, or
   one per 500 alerts/s for senders that batch 50. Add replicas for
   WebSocket fan-out when many analysts stay connected (B5).
6. **PostgreSQL:**
   * *connections:* `max_connections` ≥ API replicas × `pool_max` +
     workers × (`pool_max` + the checkpointer pool) + 10. The defaults
     used up to 40 connections for 4 workers + 1 API + scheduler; the
     worst case at the defaults is 20 per worker.
   * *storage per alert:* about 4–5 KB in `alerts` (raw, normalized and
     summary included), about 1 KB of events and sightings, and
     **about 44 KB of checkpoints**.
   * *CPU:* about 1.6 cores at 6 alerts/s with readers.
7. **Redis:** memory is negligible (about 170 bytes per queued alert).
   CPU stayed below 0.11 cores even with the B2 churn.

For example, at **1 million alerts/day** (11.6/s average, about 30/s at
peak) with a 2 s fast tier and a 14 s deep tier, on the tuned
configuration:

* about 10 worker processes at 363,000/day each (4.2/s), 42/s in total,
  which covers the 30/s peak with no backlog;
* 3 API replicas, or 1–2 if senders batch;
* PostgreSQL with 4–8 vCPU, `max_connections` ≈ 400 (or PgBouncer), and
  storage for about 45 GB/day of checkpoints until B9 is fixed;
* a provider quota of about 1,850 requests per minute on average
  (11.6/s × 2.64 calls) and about 4,800 at peak.

## Caveats

* The fake model escalates most alerts, so these runs exercise the most
  expensive path: escalations, grouping and plans. A real model that
  closes more noise at triage makes fewer calls per alert and writes
  fewer escalations. Plug your own call mix into the formula.
* Real provider SDKs add CPU per call (HTTPS, JSON parsing, larger
  prompts). Expect the ~10 alerts/s CPU limit per process to be lower
  with `anthropic`.
* Everything ran on one 4-vCPU host, with the load generator competing
  for the same cores. At the highest ingest rates the load generator
  itself lagged (reported in each report as `loadgen_loop_lag_ms`);
  those client-side percentiles are upper bounds.
* One tenant was used throughout. With several busy tenants the
  per-tenant cap (B1) matters less, and the per-tenant locks (B6) are
  spread across tenants.
