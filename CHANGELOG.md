# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

A ground-up rebuild of the proof of concept into a multi-tenant platform
that can be operated in production. Nothing of the 0.1 runtime is
compatible: configuration, storage, APIs and deployment all changed. There is
no automated migration from 0.1 data.

### Added

- **Process model**: one container image with `lg-sotf api`, `worker`,
  `scheduler` and `migrate` roles, plus operator commands (`create-tenant`,
  `create-admin`, `enqueue`, `dlq list|requeue`, `version`, `eval`).
- **Typed settings** (`lg_sotf.settings`): environment variables
  `LG_SOTF_<SECTION>__<KEY>`, optional `.env` and YAML with `${VAR}`
  expansion; startup safety checks refuse unsafe staging/production
  configuration (missing or published secrets, fake model, wildcard CORS,
  insecure cookies, development database password).
- **PostgreSQL system of record** with Alembic migrations: tenants, users,
  sessions, API keys, sources, alerts, alert timeline, workflow runs,
  escalations, analyst feedback, response action ledger, suppression rules,
  indicator sightings, daily LLM usage, audit log; monthly partitions for
  the timeline and audit log; retention jobs.
- **Tenant isolation** with row-level security on every tenant table, a
  non-owner runtime role, `SECURITY DEFINER` credential lookups, and
  tenant-scoped Redis keys, checkpoints and caches.
- **Durable runtime**: Redis Streams work queue (high/normal priority),
  consumer groups, dead-letter queue, worker leases and liveness keys,
  recovery of crashed workers, stale and orphaned run sweeps, a
  leader-elected scheduler, graceful drain.
- **Checkpointed workflow engine** (LangGraph with the Postgres
  checkpointer): gate (suppression rules, verdict cache), triage,
  correlation, analysis, policy decision, escalation with analyst interrupt,
  response planning, approval interrupt, execution, close; per-node timeouts
  and retry policies; idempotent side effects.
- **Ingestion service** with deterministic normalizers for Splunk,
  CrowdStrike, Microsoft Sentinel, Wazuh, AWS GuardDuty, IBM QRadar,
  canonical and generic field-mapped webhooks; pull connectors for Splunk,
  QRadar, Sentinel, Wazuh indexer and CrowdStrike Falcon with persisted
  cursors; secret redaction, size caps, fingerprints and deduplication;
  optional LLM normalisation fallback; outbound destination policy.
- **LLM layer**: provider factory (Anthropic by default, OpenAI and Gemini
  as extras, deterministic fake model), untrusted-data prompt boundary,
  structured output with refusal handling, prompt caching, per-model
  concurrency limits, usage and cost metering, per-tenant daily token
  budgets.
- **Agents** hardened against prompt injection: rule/LLM triage with
  injection detection, indicator-based correlation, analysis with tenant
  history and optional VirusTotal/AbuseIPDB enrichment; rule corroboration
  required for automatic benign closes and automatic containment; high and
  critical alerts are never closed as benign by automation; refusals
  escalate.
- **Human review**: escalation levels, SLAs and level-up sweeps, grouping of
  related alerts, claim and decision with optimistic locking, feedback,
  suppression suggestions.
- **Response automation** under per-tenant autonomy policy, protected
  assets, allowed actions, hourly caps and blast-radius limits; dry-run by
  default; HMAC-signed webhook connector for SOAR platforms; per-action
  approvals.
- **REST and WebSocket API** (`/api/v1`): local login with rotating refresh
  cookies, OIDC, scoped API keys, RBAC (viewer, analyst, admin, platform
  admin), ingestion, alerts, escalations, actions, sources, suppressions,
  users, API keys, tenant settings, dashboard, LLM usage, audit log and
  verification, tenant provisioning, live events; rate limits, body limits,
  security headers, OpenAPI.
- **Hash-chained, append-only audit log** per tenant.
- **Observability**: JSON logs with request/tenant/alert context and
  redaction, Prometheus metrics, OpenTelemetry tracing, health servers for
  workers and scheduler.
- **Deployment**: hardened multi-stage Dockerfile (non-root, read-only root
  filesystem), Docker Compose stack and production override with two
  database roles, Helm chart (HPA, KEDA, PDBs, NetworkPolicies,
  ServiceMonitors, migrate hook), secret generator, end-to-end stack smoke
  test, CI (lint, types, tests on PostgreSQL and Redis, dependency and
  secret scanning, image build, Helm validation).
- **Evaluation harness** (`lg-sotf eval`, `lg_sotf.eval`): labelled JSONL
  datasets in canonical or vendor formats, runs through the real ingestion
  and workflow without inventing analyst decisions, metrics (malicious
  false-negative rate, benign auto-close, escalation and inconclusive rates,
  precision/recall/F1, Cohen's kappa, cost, latency), JSON and Markdown
  reports, thresholds and baseline regression gate (baselines must match
  the dataset and selection); one fresh tenant per split so split metrics
  are independent; database, schema, Redis and report-path checks before
  any item runs; a 64-item synthetic dataset with an adversarial
  prompt-injection split; CI smoke evaluation; analyst-feedback export (one
  item per alert, final decision) for real data.
- **Documentation**: architecture contract, API, configuration reference
  generated from the code, deployment, operations runbook, security model,
  user guide, evaluation guide.

### Changed

- The analyst web application in `src/lg_front` is rebuilt as a client of
  the new API (see its README).
- Configuration moved from `ConfigManager` YAML files to typed settings;
  `ConfigManager` remains as a thin read-only facade for agents.

### Removed

- The proof-of-concept runtime (`app_initializer`, in-process queues and
  deduplication, schema creation at startup), empty placeholder modules and
  documentation, and dead files (`Backup/`, `test.html`,
  `test_claude_simple.py`, `test_claude_workflow.py`, `setup_api_key.sh`).

### Security

- See [docs/security.md](docs/security.md) for the threat model and
  controls, and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Before 0.2.0

Proof of concept: a single-process LangGraph workflow demonstrating
LLM-assisted alert triage. Not supported.
