# LG-SOTF Architecture

LG-SOTF is a multi-tenant AI triage and investigation platform for security
alerts. It ingests alerts from SIEM/EDR/cloud sources, triages and investigates
them with a LangGraph multi-agent workflow, escalates uncertain cases to
analysts, and proposes (or, where a tenant allows it, executes) response
actions under explicit guardrails.

This document is the contract every module is built against. When code and
this document disagree, fix one of them in the same change.

## 1. Processes

One container image, four process roles, selected by `lg-sotf <role>`:

| Role | Command | Scales | Responsibility |
|---|---|---|---|
| API | `lg-sotf api` | horizontally (HPA on CPU/RPS) | REST + WebSocket, auth, tenant scoping, enqueues work. Never runs a workflow in-process. |
| Worker | `lg-sotf worker` | horizontally (KEDA on queue lag) | Consumes the alert queue, runs the LangGraph workflow with a Postgres checkpointer, resumes interrupted runs. |
| Scheduler | `lg-sotf scheduler` | 2 replicas, one active (leader lease) | Polls pull-based sources and enqueues alerts, sweeps SLAs and stale runs, retention and partition maintenance, exports queue gauges, delivers the integrations outbox and polls linked tickets. |
| Migrate | `lg-sotf migrate` | one-shot job | Alembic `upgrade head`, LangGraph checkpointer `setup()`, bootstrap tenant/admin. |

Supporting services: PostgreSQL 15+ (system of record, checkpoints, RLS
tenancy) and Redis 7+ (work queue via Streams, pub/sub event fan-out, rate
limits, short-lived caches). Redis holds nothing that cannot be rebuilt from
Postgres except in-flight queue entries, which are re-derivable from
`workflow_runs`.

## 2. Package layout

Packages belong to layers and imports point down only
([ADR-0001](adr/0001-layering.md); enforced by import-linter, `make
import-lint`). What each package owns is in the
[refactor roadmap](design/refactor-roadmap.md), section 1.2.

| Layer (top to bottom) | Packages (`src/lg_sotf/`) | Owns |
|---|---|---|
| Entrypoints | `cli.py`, `__main__.py` | `lg-sotf` commands: api, worker, scheduler, migrate, create-admin, create-tenant, reset-mfa, dlq, eval, eval-scorecard, tenant-export, tenant-erase, evidence-verify, mcp, version |
| Interfaces | `api` \| `mcp` \| `eval` | FastAPI app, auth, routers, WebSocket; the stdio MCP server; the evaluation harness |
| Process roles | `runtime` | worker, leader-elected scheduler, health server, sweeps, shutdown |
| Workflow engine | `core` | graph, nodes, `WorkflowEngine`, retry policy |
| Application | `services` \| `compliance` \| `onboarding` \| `agents` \| `ingestion` | escalation, review, response, reporting; evidence, NIS2, export; onboarding; triage, correlation and analysis agents; sources and normalizers |
| Adapters | `integrations` \| `tools` \| `llm` \| `queue` | notifications, ticketing, Microsoft clients; enrichment; model clients; Redis Streams |
| Audit | `audit` | `AuditLogger`, the only writer of `audit_log` |
| Persistence | `db` | pool, tenancy (RLS), repositories (all SQL), the tenant-scoped LangGraph checkpointer, migrations, locks |
| Domain (no I/O) | `domain` | routing, phishing and suppression policy, URL facts, indicator extraction; the event publisher and connector ports |
| Value types | `models` | canonical alert and domain vocabulary |
| Network kernel | `net` | SSRF egress policy (`net/egress.py`), TLS verification and the shared context cache (`net/tls.py`), Retry-After (`net/retry.py`) |
| Kernel | `errors` : `observability` : `security` : `settings` | root errors; logging, metrics; crypto, hashing, redaction, webhook signing; typed settings |

Some modules still sit in the wrong layer (for example the action catalog
in `services/response.py`); `pyproject.toml` lists each such import as an
exact exception tied to the roadmap step that moves it.

Removed: `Backup/`, `test.html`, `app_initializer.py` (replaced by
`runtime/`), `storage/postgres.py` DDL at startup (replaced by migrations),
the `ConfigManager` facade and `utils/llm.py` shim (agents read `Settings`
through `BaseAgent.get_config`), the unused tool orchestrator, empty
placeholder modules, per-process in-memory queues and dedup.

## 3. Configuration

`lg_sotf.settings.get_settings()` returns a cached `Settings`. Environment
variables use `LG_SOTF_<SECTION>__<KEY>` (e.g. `LG_SOTF_DATABASE__URL`,
`LG_SOTF_LLM__FAST__MODEL`). Standard variables are honoured as fallbacks:
`DATABASE_URL`, `REDIS_URL`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GOOGLE_API_KEY`. An optional YAML file (`LG_SOTF_CONFIG_FILE`) supplies
lower-precedence values and may reference `${VAR}` / `${VAR:-default}`.

Every process calls `settings.assert_safe()` at startup; in `staging` and
`production` it refuses to start with missing secrets, a fake LLM, wildcard
CORS, insecure cookies, or the development database password.

No module reads `os.environ` or YAML directly except `settings.py`. Agents
read their section of `settings.agents` through `BaseAgent.get_config`.
`DATABASE_URL` and `REDIS_URL` apply only when nothing else (init arguments,
`LG_SOTF_*` variables, `.env`, YAML) sets the URL.

## 4. Tenancy

Every tenant-owned table has `tenant_id TEXT NOT NULL REFERENCES tenants(id)`
and a row-level-security policy:

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON <t>
  USING (tenant_id = current_setting('app.tenant_id', true) OR (SELECT lgsotf_rls_bypass()))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR (SELECT lgsotf_rls_bypass()));
```

`lgsotf_rls_bypass()` is true only when `app.bypass_rls = 'on'` **and** the
session user is a member of the role that owns the schema, so setting the GUC
from a runtime session does nothing.

One table has a second, read-only policy. `tenant_grants` (migration 0012)
holds the delegated access a customer tenant gives an MSSP organisation; its
rows belong to the customer (`tenant_id`), which alone writes them, and the
organisation reads its own grants from its home tenant:

```sql
CREATE POLICY org_read ON tenant_grants FOR SELECT
  USING (organisation_id = current_setting('app.tenant_id', true) OR (SELECT lgsotf_rls_bypass()));
```

Permissive policies combine per command, so the organisation can `SELECT`
its grants but never insert, extend or revoke one, and no third tenant sees
them. An organisation is keyed by its home tenant id (`organisations`), and
its staff are users of that tenant listed in `organisation_members`.

Two database roles:

* **Owner** (`database.migration_url`): runs `lg-sotf migrate` and the
  scheduler (partition DDL, retention, cross-tenant sweeps via `system_tx`).
* **Runtime** (`database.url`, role named by `database.runtime_role`): used by
  the API and workers; no ownership, no `BYPASSRLS`; privileges granted by
  `lg-sotf migrate`. Pre-tenant credential lookups (user by email, refresh
  token by hash, API key by id) go through `SECURITY DEFINER` functions.

Single-role installs (development) use the owner role everywhere.

Application code never issues tenant queries outside a scoped transaction:

```python
async with db.tenant_tx(tenant_id) as conn:  # SET LOCAL app.tenant_id
    ...
async with db.system_tx() as conn:  # SET LOCAL app.bypass_rls = 'on' (scheduler/migrate only)
    ...
```

Repositories additionally filter by `tenant_id` explicitly (defence in depth).
Redis keys are `"{prefix}:t:{tenant_id}:..."`. LangGraph thread IDs are
`"{tenant_id}:{alert_id}"`. A single-organisation install is the `default`
tenant created by `lg-sotf migrate`.

## 5. Data model (PostgreSQL)

All timestamps are `TIMESTAMPTZ`, all IDs are `TEXT` unless stated. Monthly
range partitioning (by `ts`/`created_at`) is used for the append-only,
high-volume tables `alert_events` and `audit_log`; the scheduler creates the
next two partitions ahead and drops expired ones.

| Table | Purpose / key columns |
|---|---|
| `tenants` | `id` PK, `name`, `status` (active/suspended), `settings JSONB` (autonomy policy, LLM budget, retention overrides, protected assets), timestamps |
| `users` | `id UUID` PK, `tenant_id`, `email` (unique per tenant, lowercase), `password_hash` (argon2id, null for SSO-only), `role` (`admin`/`analyst`/`viewer`), `is_platform_admin`, `is_active`, `failed_logins`, `locked_until`, `last_login_at` |
| `refresh_tokens` | `id UUID` PK, `user_id`, `tenant_id`, `token_hash` (sha256), `expires_at`, `revoked_at`, `replaced_by` (rotation) |
| `api_keys` | `id UUID` PK, `tenant_id`, `name`, `prefix` (first 8 chars, shown in UI), `key_hash` (sha256), `scopes TEXT[]` (`ingest`, `read`, `write`), `created_by`, `last_used_at`, `revoked_at` |
| `sources` | PK (`tenant_id`, `id`) — ids are unique per tenant, `type` (splunk/qradar/sentinel/wazuh/crowdstrike/guardduty/webhook/file), `name`, `enabled`, `config JSONB` (non-secret), `secret_ciphertext` (Fernet), `poll_interval_s`, `cursor JSONB`, `last_polled_at`, `last_error`, `health` |
| `alerts` | PK (`tenant_id`, `id`); `source_id`, `source_alert_id`, `fingerprint`, `title`, `severity` (info/low/medium/high/critical), `category`, `status` (see §6), `disposition` (malicious/benign/inconclusive, null until decided), `confidence`, `threat_score`, `priority`, `assigned_to`, `occurred_at`, `ingested_at`, `updated_at`, `closed_at`, `raw JSONB` (original, size-capped), `normalized JSONB` (canonical model), `summary JSONB` (verdict, indicators, correlations digest, recommended actions, reasoning digest, LLM usage), `case_key`. UNIQUE (`tenant_id`, `source_id`, `source_alert_id`). Indexes: (`tenant_id`, `ingested_at DESC`, `id`), (`tenant_id`, `status`, `ingested_at DESC`), (`tenant_id`, `severity`, `ingested_at DESC`), (`tenant_id`, `fingerprint`, `ingested_at DESC`) |
| `alert_events` | partitioned; `tenant_id`, `alert_id`, `ts`, `node`, `event_type`, `actor_type` (system/user/agent), `actor_id`, `data JSONB`. Timeline for the UI and audit of agent decisions |
| `workflow_runs` | PK (`tenant_id`, `alert_id`); `thread_id` UNIQUE, `status` (queued/running/waiting_human/waiting_approval/completed/failed/dead_lettered), `attempt`, `worker_id`, `lease_expires_at`, `last_error`, `created_at`, `updated_at`, `completed_at`, `graph_version` (the graph its checkpointed thread started on; NULL = no thread yet, or one started before graph versions, which ran graph 1) |
| `escalations` | `id` PK, `tenant_id`, `alert_id`, `thread_id`, `level` (L1/L2/L3), `status` (open/claimed/decided/expired/cancelled), `reason`, `priority`, `summary JSONB`, `related_alert_ids TEXT[]`, `assigned_to`, `sla_deadline`, `decision` (true_positive/false_positive/benign_positive/needs_more_info), `decision_notes`, `approved_actions TEXT[]`, `decided_by`, `decided_at`, `version INT` (optimistic lock). Partial unique index: one open/claimed escalation per (`tenant_id`, `alert_id`) |
| `analyst_feedback` | `id` PK, `tenant_id`, `escalation_id`, `alert_id`, `user_id`, `decision`, `confidence`, `notes`, `triage_correct`, `correlation_helpful`, `analysis_accurate`, `review_duration_s`, `created_at` |
| `response_actions` | Action ledger. `id UUID` PK, `tenant_id`, `alert_id`, `action_type`, `target`, `risk_level`, `idempotency_key` (UNIQUE per tenant = sha256(tenant, alert, action_type, target)), `status` (proposed/awaiting_approval/approved/rejected/executing/succeeded/failed/dry_run/blocked), `blocked_reason`, `requested_by`, `approved_by`, `approved_at`, `executed_at`, `connector`, `result JSONB`, `rollback_of` |
| `suppression_rules` | `id` PK, `tenant_id`, `name`, `match JSONB` (field → value/regex/cidr predicates), `disposition` (benign), `created_by`, `source_feedback_id`, `expires_at`, `hit_count`, `last_hit_at`, `enabled` |
| `indicator_sightings` | `tenant_id`, `indicator_type`, `value_hash` (HMAC-SHA256 with per-install key), `value_display` (truncated, redacted), `alert_id`, `seen_at`. Index (`tenant_id`, `indicator_type`, `value_hash`, `seen_at DESC`). Correlation reads this instead of scanning JSONB |
| `llm_usage_daily` | PK (`tenant_id`, `day`, `model`, `agent`); `calls`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `cost_usd NUMERIC(12,6)`, `refusals`, `errors` (UPSERT) |
| `integrations` | `id UUID` PK, `tenant_id`, `kind` (slack/teams/email/webhook/jira/servicenow), `name`, `enabled`, `config JSONB` (non-secret), `secret_ciphertext` (Fernet), `events TEXT[]`, `min_severity` (docs/integrations.md) |
| `notification_outbox` | `id UUID` PK, `tenant_id`, `integration_id`, `event_id`, `event_type`, `operation` (notify/ticket_create/ticket_update/test), `dedupe_key` (UNIQUE per integration), `payload JSONB` (lg-sotf.event.v1 summary), `status` (pending/sent/failed/dead), `attempts`, `next_attempt_at`, `last_error`, `result`. Written in the transaction of the change it announces; delivered by the scheduler |
| `external_tickets` | `id UUID` PK, `tenant_id`, `integration_id`, `alert_id`, `escalation_id` (UNIQUE per integration), `action_id`, `system`, `external_key`, `external_url`, `external_status`, `resolved`, `resolved_by`, `last_synced_at` |
| `investigation_steps` | Investigation trace, append-only. `id UUID` PK, `tenant_id`, `alert_id` (cascades with the alert), `run_id`, `step_index` (UNIQUE per run), `agent`, `kind` (llm/tool), `prompt_name`, `prompt_hash`, `provider`, `model`, `tool`, `input_hash`, `output_hash` (SHA-256), `result_digest JSONB` (redacted, size-capped), `outcome`, `error_type`, token counts, `latency_ms`, `started_at`. Index (`tenant_id`, `kind`, `input_hash`) for record/replay (docs/compliance.md) |
| `audit_log` | partitioned; `tenant_id`, `id BIGSERIAL`, `ts`, `actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`, `details JSONB`, `prev_hash`, `hash` (sha256 chain per tenant). UPDATE/DELETE blocked by trigger unless `app.bypass_rls='on'` (retention) |

LangGraph checkpoint tables are created by `AsyncPostgresSaver.setup()` in
`lg-sotf migrate`, which then puts them under the tenant RLS policy (keyed on
`split_part(thread_id, ':', 1)`); the worker's checkpointer
(`db/checkpointer.py`) sets `app.tenant_id` from the thread id before each
statement. The retention job removes them for threads whose run is
completed and older than `retention.checkpoints_days`, and with their alert
when the alert itself expires.

## 6. Alert lifecycle

`status` values (the only ones code may write):

`new` → `queued` → `processing` → one of
`waiting_human` | `waiting_approval` | `closed` | `failed`;
`waiting_human` → `processing` (resumed) ; `waiting_approval` → `processing`.

`disposition` is set when a verdict exists: `malicious`, `benign`,
`inconclusive`. Suppressed alerts are `closed` + `benign` with
`summary.suppressed_by` set; duplicates are never inserted (unique key).

## 7. Queue (Redis Streams)

* Streams: `{prefix}:q:alerts:high` (critical/high severity) and
  `{prefix}:q:alerts:normal`; consumer group `workers`. Workers read `high`
  first, then `normal`.
* Message fields: `tenant_id`, `alert_id`, `kind` (`process` | `resume`),
  `payload` (JSON; for `resume`: `{"type": "analyst_decision"|"approval", ...}`),
  `enqueued_at`.
* Producer API (`lg_sotf.queue.producer.WorkQueue`):
  `enqueue_process(tenant_id, alert_id, severity)`,
  `enqueue_resume(tenant_id, alert_id, payload)`.
* Consumer: `XREADGROUP` with `block_ms`; on success `XACK` + `XDEL`; on
  exception the entry stays pending and is reclaimed by `XAUTOCLAIM` after
  `worker.visibility_timeout_s`. Each worker refreshes a liveness key
  `{prefix}:q:consumers:{consumer}:alive` (TTL = run lease); entries pending
  for a consumer whose key has expired are claimed by live workers at once
  (`XCLAIM`), so a killed worker's backlog is recovered within about one
  lease. The `workflow_runs` lease, not queue ownership, prevents double
  execution. Deliveries > `worker.max_deliveries` → copied
  to `{prefix}:q:alerts:dlq`, run marked `dead_lettered`, acked.
* Idempotency: the worker checks `workflow_runs` before running; a completed
  run is acked and skipped; an interrupted/partial run resumes from its
  checkpoint (`ainvoke(None, config)`); `resume` messages use
  `Command(resume=payload)`.
* Events: `lg_sotf.queue.events.EventBus.publish(tenant_id, event)` →
  Redis pub/sub channel `{prefix}:events:{tenant_id}`; API WebSocket
  connections subscribe per tenant. Event shape:
  `{"type": "alert.updated"|"alert.created"|"escalation.created"|"escalation.updated"|"action.updated", "tenant_id", "alert_id", "data": {...}, "ts"}`.

## 8. Workflow

Graph (compiled once per worker process with `AsyncPostgresSaver`,
`durability="sync"`, thread id `{tenant_id}:{alert_id}`):

```
START → gate → triage → correlation → analysis → decide
gate:        suppression rules / verdict cache (same or lower severity than the
             analyst decided; never for critical or LLM-normalised alerts) →
             close (benign) | triage
triage:      rules + fast-tier LLM → close (obvious FP) | correlation
correlation: indicator sightings + optional LLM → analysis | decide
analysis:    ReAct with deep-tier LLM, bounded steps, early stop
decide:      policy routing → escalate | plan_response | close
escalate:    create/attach escalation (idempotent) → await_analyst
await_analyst: interrupt({"escalation_id": ...}) → route on decision:
             true_positive → plan_response ; false_positive/benign → close ;
             needs_more_info → analysis (max once)
plan_response: build actions, write ledger (idempotent), apply guardrails →
             execute_actions (auto-allowed) and/or await_approval
await_approval: interrupt({"action_ids": [...]}) → execute_actions | close
execute_actions: run every approved action through connectors (idempotent via
             ledger), again until a pass finds none approved → await_approval
             (actions still awaiting) | close | escalate (policy response
             with a failed or no completed action)
close:       write final alert row + summary + events
```

Rules:

* `WorkflowState` holds identifiers, the canonical alert (size-capped), scores,
  and small digests. Large artifacts (tool outputs, full reasoning) go to
  `alerts.summary` / `alert_events`, not graph state. Accumulating lists are
  capped.
* Agents are stateless singletons: no per-alert data on `self`. No locks
  around agent execution. Concurrency is bounded by the worker semaphore and
  per-model LLM semaphores.
* Every node has a timeout (`worker.node_timeout_s`, analysis
  `worker.analysis_timeout_s`) and a LangGraph `RetryPolicy` for transient
  errors. A node that still fails raises; the worker records `failed`, the
  message is retried by the queue and eventually dead-lettered. Failures are
  never converted into default scores that drive routing.
* LLM output alone can never auto-close a high/critical alert or authorise a
  containment action. Routing to `close` from LLM evidence requires rule
  corroboration or analyst decision; containment requires tenant autonomy
  policy `auto` for that risk level *and* guardrails passing.
  (Clarification: "auto-close" here means closing as benign. The decision to
  plan a response is taken from the threat score; rule corroboration gates
  automatic *containment*, not planning or non-containment actions such as
  `create_ticket`, which run under autonomy `auto` on any evidence. A
  policy response whose actions complete closes the alert as malicious at
  any severity.)
* Side-effecting nodes (`escalate`, `plan_response`, `execute_actions`) are
  idempotent because nodes may re-run on resume.
* The graph is versioned (`core/graph.py`: `GRAPH_VERSION`,
  `GRAPH_BUILDERS`). A change that could break a run checkpointed on the
  previous graph (nodes, edges, state schema, interrupt payloads) bumps
  `GRAPH_VERSION` and keeps the previous builder. Each worker compiles every
  kept graph; a fresh thread starts on the current one after its version is
  stamped on `workflow_runs.graph_version`, and a run with a checkpoint
  continues and resumes on the graph it started on, so runs waiting for an
  analyst drain on graph N-1 after an upgrade. A run on a version the worker
  does not have fails with `UnknownGraphVersion` (logged
  `workflow.unknown_graph_version`) before anything is written, is retried,
  and is dead-lettered like any failing run; it never runs on another graph.
  Drop a builder only when no run that can still resume is on its version.
* A model refusal at any stage escalates with reason `model_refused`; no
  actions are planned from a refused analysis.
* Related alerts (shared key entities or fingerprint within the grouping
  window) attach to one open escalation; one analyst decision resumes the
  parent and every attached run. A benign/false-positive decision is only
  inherited by attached alerts whose own evidence does not contradict it;
  otherwise the attached alert is detached into its own escalation.
* A decision on an SLA-expired escalation is still accepted (audited with
  `after_sla_expiry`), so expiry never strands an alert.
* Approvals are per action; unmentioned actions stay pending unless the
  request sets `reject_remaining`. An approval commits whenever the analyst
  makes it, also while the run is not waiting: `execute_actions` treats
  every `approved` action of the alert as pending work and runs it exactly
  once (the ledger transition `approved → executing` decides the owner), and
  the run closes only when nothing is `approved` or `awaiting_approval`.
* Dry-run execution completes a response: when the policy chose the
  response and its actions ran as `dry_run` (the tenant's or install's
  dry-run mode) or `succeeded`, the alert closes with disposition
  `malicious` and `summary.dry_run` records whether it was a dry run. Only a
  `failed` action, or no completed action at all (all blocked/rejected),
  sends a policy-chosen response to an analyst.

## 9. LLM layer (`lg_sotf.llm`)

* `get_chat_model(tier: "fast"|"deep")` → configured LangChain chat model
  (timeout, max_retries, max_tokens) for the configured provider; `fake`
  returns a deterministic schema-valid model for tests/dev.
* `build_messages(system, task, untrusted: dict)` → `[SystemMessage(system +
  task, cache_control when enabled), HumanMessage("<alert_data>…</alert_data>")]`.
  Untrusted data is compact JSON, per-field and total size capped, and
  explicitly labelled as data, never instructions.
* `ainvoke_structured(model, schema, messages, agent=...)` → validated
  Pydantic object; uses `with_structured_output(method="json_schema")` where
  supported; handles `stop_reason == "refusal"` (raises `LLMRefusal`),
  validation failures (raises `LLMOutputError`), records usage.
* Usage metering: token counts and cost per call → Prometheus counters
  (labels: `model`, `agent`, `outcome`) and `llm_usage_daily` UPSERT (batched).
  Per-tenant daily token budget: when exceeded, agents fall back to rules and
  mark `summary.llm_budget_exceeded`.
* Per-model concurrency semaphores (`llm.<tier>.max_concurrency`, default
  `worker.concurrency`; waits exported as `lgsotf_llm_slot_wait_seconds`).

## 10. API

Base path `/api/v1`. JSON. Errors: `{"error": {"code", "message", "request_id"}}`.

Authentication (`lg_sotf.api.auth`):

* Local users: `POST /auth/login` (email, password, tenant optional) → access
  JWT (HS256, `access_token_ttl_s`) in body + rotating refresh token in an
  `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`.
  `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`.
* OIDC: if `auth.oidc_issuer` is set, bearer JWTs from that issuer are
  verified against its JWKS (cached); tenant and role come from configured
  claims.
* API keys: `Authorization: Bearer lgk_<id>_<secret>` or `X-API-Key`; scopes
  `ingest`, `read`, `write`.
* Principal: `{user_id|api_key_id, tenant_id, role, scopes, is_platform_admin}`.
  Platform admins may act on another tenant with `X-Tenant-ID`.
* Roles: `viewer` (read), `analyst` (read, claim/decide escalations, approve
  low/medium actions, notes), `admin` (everything in tenant incl. users, API
  keys, sources, suppressions, settings, high-risk approvals).

Endpoints:

| Method | Path | Auth |
|---|---|---|
| GET | `/healthz` (liveness, no deps), `/readyz` (db+redis ping), `/metrics` (Prometheus; token or network-restricted) | none / none / metrics token |
| POST | `/auth/login`, `/auth/refresh`, `/auth/logout`; GET `/auth/me` | public / cookie / cookie / bearer |
| POST | `/ingest/alerts` (batch ≤ `api.max_ingest_batch`, 202 + per-item result) | api key `ingest` |
| POST | `/ingest/webhook/{source_id}` (vendor-native payload, normalized server-side) | api key `ingest` |
| GET | `/alerts` (filters: status, severity, disposition, source_id, q, from, to; keyset pagination `cursor`, `limit` ≤ 200; `q` is a title search limited to a `from`/`to` window of at most 93 days, default 30) | viewer |
| GET | `/alerts/{id}`, `/alerts/{id}/events` | viewer |
| POST | `/alerts/{id}/reprocess` (admin), `/alerts/{id}/notes` (analyst) | |
| GET | `/escalations` (filters, pagination), `/escalations/{id}` | viewer |
| POST | `/escalations/{id}/claim`, `/escalations/{id}/decision` (body includes `version`; 409 on conflict) → enqueue resume | analyst |
| GET | `/actions` (ledger, filters) | viewer |
| POST | `/actions/{id}/approve`, `/actions/{id}/reject` → enqueue resume | analyst (low/medium) / admin (high) |
| GET/POST/PATCH/DELETE | `/sources`, `/sources/{id}/test` | admin |
| GET/POST/PATCH/DELETE | `/suppressions` | analyst create, admin manage |
| GET/POST/PATCH/DELETE | `/users`, `/api-keys` | admin |
| GET/PATCH | `/tenant/settings` (autonomy policy, protected assets, LLM budget) | admin |
| DELETE | `/tenant/verdict-cache` (clear cached analyst-benign verdicts) | admin |
| GET | `/dashboard/summary` (counts by status/severity/disposition, MTTA/MTTR, queue depth, LLM cost; cached 15 s per tenant) | viewer |
| GET | `/usage/llm` (daily usage/cost) | admin |
| GET | `/audit` (hash-chained audit log; filters, keyset pagination), `/audit/verify` (recompute the tenant's chain) | admin |
| POST | `/platform/tenants` (provision a tenant, optionally with its first admin; audited in the new and the home tenant) | platform admin |
| WS | `/ws?token=<access token>` → tenant event stream | viewer |

Middleware: request id, structured access log, security headers, CORS
allowlist, body size limits, Redis fixed-window rate limits per principal
(stricter on login and ingest), error envelope.

## 11. Response guardrails

For each proposed action: resolve risk level → tenant autonomy policy
(`auto`/`approval`/`disabled`) → guardrails (protected assets and CIDRs,
never private/loopback/own ranges for IP blocks unless allowed, target
syntax validation, per-tenant hourly cap) → ledger row with idempotency key.
Connectors: `dry_run` (default; records what would happen), `webhook`
(HMAC-signed POST to the tenant's SOAR, e.g. Tracecat/Shuffle/Tines),
`microsoft` (direct Microsoft 365 mail, Entra ID and Defender for Endpoint
actions with verification and rollback; docs/microsoft.md) and ticketing
(Jira/ServiceNow `create_ticket`). `services/connectors/routing.py` picks the
connector per action. Global `response.dry_run=true` forces dry-run
everywhere. Every transition is written to `audit_log`.

## 12. Ingestion

* Canonical model `lg_sotf.models.alert.CanonicalAlert` — a subset of OCSF
  Detection Finding (class_uid 2004): `source_id`, `source_alert_id`, `title`,
  `description`, `severity`, `category`, `occurred_at` (UTC), `entities`
  (hosts, users, ips, domains, urls, hashes, processes), `mitre` (tactics,
  techniques), `raw` (original), `unmapped`.
* Deterministic per-source normalizers; LLM normalization is an optional
  fallback for unknown formats (off by default).
* `IngestionService.ingest(tenant_id, source_id, events) -> IngestResult`:
  redact secrets, normalize, compute `fingerprint`, insert with
  `ON CONFLICT DO NOTHING`, return new alert ids; callers enqueue them.
* Pull sources: scheduler (leader) polls due sources, uses persisted
  `cursor` (source event time/ID watermark, advanced only after insert commit,
  with overlap window), reuses one HTTP client per source, verifies TLS by
  default, refreshes OAuth tokens, backs off on errors, never drops a page.

### Outbound HTTP (all stacks)

Pull sources are one of seven outbound HTTP stacks. They share two pieces
from `lg_sotf.net.http`: `read_capped` (every body is read up to a byte cap,
`ResponseTooLarge` past it, a non-encoded `Content-Length` over the cap
refused before any byte is read) and `guarded_client` (the client of the
tenant-controlled stacks: `GuardedTransport` checks and pins every request to
an address the egress policy allows, redirects are never followed, timeout
and `User-Agent` always set). TLS contexts come from `lg_sotf.net.tls`
(`PROCESS_TLS`: one default, one per distinct CA). `Retry-After` is read with
`lg_sotf.net.retry.parse_retry_after` (seconds or HTTP date). Ruff (`TID251`)
refuses `httpx.AsyncHTTPTransport` outside `lg_sotf/net/`.

Everything else is per stack, on purpose:

| Stack | Destination check | Retries | Idempotency | `Retry-After` | Connection lifetime | Body cap |
|---|---|---|---|---|---|---|
| Pull sources (`ingestion/sources/http.py`) | `guarded_client`, policy from `IngestionOptions` | `ingestion.http_max_retries` (4): network errors, 429, 5xx; backoff 0.5-30 s with jitter | no distinction: every request (queries, searches sent as POST, the OAuth token request, the M365 message move) is retried alike; a 401 refreshes the token once | waited up to `ingestion.http_max_retry_after_s` (120 s); longer ends the poll with `SourceRateLimited` | one pooled client per source instance | 64 MiB |
| Integrations (`integrations/http.py`: Slack, Teams, email webhooks, Jira, ServiceNow) | `guarded_client`, `egress_policy` | per call (`retries`, default 0; the outbox schedules later attempts): network errors, 408, 425, 429, 500, 502, 503, 504; backoff 0.5-8 s | `idempotent=False` (ticket create, comment) retries only when the request never reached the server (connect or pool errors) or on 429 | waited when at most 15 s; longer is raised on `DeliveryError.retry_after` (capped at 3600 s) for the outbox | one client per `request()` call | 256 KiB |
| Response webhooks (`services/connectors/webhook.py`) | `guarded_client`, `egress_policy` | 3: network errors, 429, 5xx; backoff 0.5-10 s; all within a deadline of a third of `worker.node_timeout_s` (at most 60 s) | every attempt carries the same `Idempotency-Key` (the action id); the receiver deduplicates | waited up to 15 s; longer fails the action | one client per `execute()` (all its attempts) | 64 KiB |
| Microsoft Graph and Defender (`integrations/microsoft/http.py`) | `guarded_client`, `egress_policy(require_https=True)`, fixed cloud hosts | `response.microsoft_retries` (3); backoff 0.5-8 s | 429 and 503 always; network errors, 500, 502, 504 and Graph `Directory_ConcurrencyViolation` only when idempotent (GET, DELETE); otherwise `ambiguous=True` for the handler to reconcile | waited unless longer than the time left, then `throttled` with `retry_after_s` | one client per attempt (a fresh connection after a 503) | 1 MiB (4 MiB per page, 64 KiB for tokens) |
| Enrichment providers (`tools/enrichment/http.py`) | none: fixed vendor base URLs, `https` in staging and production | none in the request | GET only | read on 429 and 503 and returned; the enrichment service backs off per tenant and provider (60 s when absent) | one pooled client per provider instance | 2 MiB |
| MCP API client (`mcp/client.py`) | URL shape only: the operator's own API, `http` for loopback only; `trust_env=False` | `mcp.max_retries` (2) for GET: transport errors, 429, 502, 503, 504; backoff 0.5 s doubling | writes are never retried | waited, capped at 10 s | one pooled client per MCP server | `mcp.max_response_bytes` (4 MiB) |
| OIDC discovery and JWKS (`api/auth/oidc.py`) | none: the configured issuer | none; an unknown `kid` refetches at most every 30 s | GET only | not read | one pooled client per verifier | 256 KiB |

## 13. Observability

* Logs: JSON (structlog) with `request_id`, `tenant_id`, `alert_id`,
  `thread_id`, `node` bound in context vars. No secrets or raw alert bodies at
  INFO.
* Metrics (Prometheus, low-cardinality labels only — never alert/tenant ids):
  `lgsotf_http_requests_total{route,method,status}`,
  `lgsotf_http_request_seconds`, `lgsotf_queue_depth{stream}`,
  `lgsotf_queue_pending{stream}`, `lgsotf_runs_total{outcome}`,
  `lgsotf_node_seconds{node}`, `lgsotf_llm_calls_total{model,agent,outcome}`,
  `lgsotf_llm_tokens_total{model,kind}`, `lgsotf_llm_cost_usd_total{model}`,
  `lgsotf_escalations_open`, `lgsotf_actions_total{action_type,status}`,
  `lgsotf_llm_slot_wait_seconds{tier}`,
  `lgsotf_integration_deliveries_total{kind,outcome}`, `lgsotf_ticket_syncs_total{system,outcome}`.
* No OpenTelemetry tracing: the unused exporter was removed
  ([ADR-0008](adr/0008-remove-tracing.md), which also lists how to add tracing
  back). `observability.otlp_endpoint` is ignored and logs a warning. The
  LLM and tool calls of each investigation are recorded in Postgres instead
  (`investigation_steps`, shown in evidence packs; docs/compliance.md).

## 14. Testing conventions

See [testing.md](testing.md): the unit, deploy and integration tiers, the
test services (`make test-services`), `_support.py` helpers, the fake LLM,
clocks, timeouts, isolation rules and the flaky-test policy. Every bug fix and
every guardrail has a test.

## 15. Evaluation harness (`lg_sotf.eval`)

* `lg-sotf eval --dataset <jsonl> --report <json> [--thresholds <yaml>] [--baseline <json>]`
  ingests each labelled item with `IngestionService.ingest` and runs it with
  `WorkflowEngine.run` in a fresh tenant (`eval-<timestamp>-<random>`,
  created with the schema-owner connection). The queue is bypassed; every
  other component is the production one.
* A run that reaches an analyst or approval interrupt is left waiting and
  recorded as `review="unreviewed"` (plus an `eval.review_not_performed`
  alert event). The harness never resumes a run with a synthetic decision and
  never approves an action.
* Metrics are pure functions of the per-item results
  (`lg_sotf.eval.metrics`); the headline is the malicious false-negative rate
  (expected-malicious alerts closed as benign without a human). The gate
  compares the JSON report with a thresholds file and optionally a baseline
  report; exit code 1 means a violation, 2 that the run could not start.
* `environment=production` is refused; point the settings at a dedicated
  evaluation database. See `docs/evaluation.md`.
* `lg-sotf eval-scorecard <report.json>... --output <md>` turns the reports
  of one model configuration into a scorecard (`lg_sotf.eval.scorecard`,
  pure file processing: no database or model). See `docs/scorecards/`.
* Clarifications (behaviour since the eval review): by default each split
  runs in its own fresh tenant (`<base>-<n>-<split>`, `--isolate splits`;
  `--isolate none` keeps one tenant). Database reachability, the migrated
  schema, Redis and the report paths are checked before any tenant is
  created; those failures, a baseline from a different dataset or selection,
  and a run in which every item errored all exit with code 2.
