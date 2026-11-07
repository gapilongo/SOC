# LG-SOTF

[![CI](https://github.com/gapilongo/SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/gapilongo/SOC/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

LG-SOTF is a multi-tenant AI triage platform for security alerts. It ingests
alerts from your SIEM, EDR and cloud detectors, investigates each one with a
LangGraph workflow of rule-based and LLM agents, closes obvious noise,
escalates everything uncertain or dangerous to your analysts with a written
assessment, and proposes response actions that run only under your policy,
guardrails and approvals.

It is built to be operated: durable queue-based workers with checkpointed
workflows, PostgreSQL row-level security per tenant, an audited decision
trail, metered LLM cost, Prometheus metrics, a Helm chart, and an evaluation
harness that measures what the platform would miss before you change a model
or a threshold.

**Your data, your model.** LG-SOTF runs entirely on your infrastructure,
including air-gapped networks, with Anthropic, OpenAI, Gemini or a model you
host yourself (Ollama, vLLM, any OpenAI-compatible server). It measures its
own accuracy against your analysts' decisions, and every case exports as a
verifiable evidence pack.

## How it works

```mermaid
flowchart LR
    subgraph Sources
      PULL[Splunk, QRadar, Sentinel,<br/>Wazuh, CrowdStrike]
      PUSH[Webhooks, GuardDuty,<br/>canonical API]
    end
    subgraph LG-SOTF
      SCH[Scheduler<br/>leader-elected] -->|poll with cursor| PULL
      API[API<br/>REST + WebSocket]
      Q[(Redis Streams<br/>work queue)]
      PG[(PostgreSQL<br/>RLS per tenant,<br/>checkpoints, audit)]
      W[Workers<br/>LangGraph engine]
      PUSH -->|API key| API
      SCH -->|ingest + enqueue| Q
      API -->|ingest + enqueue| Q
      Q --> W
      W --> PG
      API --> PG
    end
    W -->|redacted alert data| LLM[LLM provider<br/>Claude by default]
    W -->|indicators, opt-in| TI[Threat intel<br/>VirusTotal, AbuseIPDB]
    W -->|HMAC-signed actions| SOAR[Your SOAR<br/>Tracecat, Shuffle, Tines ...]
    AN[Analysts and admins<br/>web app or API] --> API
```

Each alert runs through one workflow, checkpointed in PostgreSQL so a crashed
worker resumes where it stopped:

```mermaid
flowchart LR
    G[gate<br/>suppression rules,<br/>verdict cache] --> T[triage<br/>rules + fast model]
    T -->|obvious noise, low/medium only| C[close]
    T --> CO[correlation<br/>shared indicators, bursts]
    CO --> A[analysis<br/>rules, history, threat intel,<br/>deep model]
    CO --> D
    A --> D[decide<br/>routing policy]
    D -->|uncertain, high severity,<br/>model refused| E[escalate<br/>analyst decision]
    D -->|high threat score| P[plan response<br/>autonomy + guardrails]
    D -->|low threat, rules agree,<br/>low/medium only| C
    E --> P
    E --> C
    P -->|approval needed, incl. containment<br/>on model-only evidence| AP[await approval]
    AP --> X[execute via connector]
    P -->|autonomy auto| X
    X -->|actions completed:<br/>closed as malicious| C
    G --> C
```

## What's new in 1.2

* **MCP for testers and analysts**: from Claude Code, send test alerts, wait
  for triage, read verdicts, reasoning and proposed actions, and score a run;
  decisions stay in the web app or Slack ([docs](docs/mcp.md),
  [design](docs/design/mcp-architecture.md)).

## What's new in 1.1

* **Actions that really happen, and are proven**: approved actions run
  directly in Microsoft 365 (purge and restore phishing emails, notify the
  reporter), Entra ID (disable, revoke sessions, reset password, confirm
  compromised) and Defender for Endpoint (isolate, block IP/domain/URL/file,
  collect forensics). Each action is re-checked against Microsoft, can be
  rolled back under the same approvals, and is routed per action type, so the
  rest can still go to your SOAR ([docs](docs/microsoft.md)).
* **SOAR templates**: a reference receiver and an n8n workflow for the
  signed webhook ([docs](docs/soar-playbooks.md)).

## What's new in 1.0

* **Phishing triage**: user-reported emails from a Microsoft 365 reporting
  mailbox, any IMAP mailbox (Google Workspace included) or
  `POST /api/v1/ingest/email`; authentication results, lookalike domains,
  display-name impersonation, deceptive links and risky attachments; purge
  message, block sender and notify reporter actions ([docs](docs/phishing.md)).
* **Integrations**: Slack, Microsoft Teams, email and signed-webhook
  notifications; approve or reject actions from Slack; one Jira or
  ServiceNow ticket per escalation, kept in sync ([docs](docs/integrations.md)).
* **Self-hosted models and air-gapped installs**: Ollama/vLLM providers with
  schema-constrained output and repair, zero-cost metering, a "Test model"
  button, an Ollama compose overlay and verified offline bundles
  ([local LLMs](docs/local-llm.md), [air-gapped](docs/air-gapped.md)).
* **Proof of value**: reports for alerts handled without a human, analyst
  hours saved, time to verdict, AI-versus-analyst accuracy (false-negative
  rate first), noisy detection rules, a printable monthly report, and
  `lg-sotf eval --from-history` to try a model on your own decided alerts
  ([docs](docs/reporting.md)).
* **MSSP console**: every tenant's activity, SLA risk and quota usage;
  suspend and reactivate; daily alert, source and user quotas; monthly usage
  export for invoicing; tenant profiles; a tenant switcher
  ([docs](docs/mssp.md)).
* **Identity**: TOTP MFA with recovery codes (required for platform admins
  in staging and production, optional per tenant), OIDC group-to-role
  mapping and just-in-time provisioning ([docs](docs/identity.md)).
* **Compliance**: signed case evidence packs with the human-oversight trail
  and audit-chain proof, NIS2 incident report drafts, GDPR tenant export and
  erasure ([docs](docs/compliance.md)).
* **MCP server**: `lg-sotf mcp` lets analysts work with LG-SOTF from Claude
  or any MCP client ([docs](docs/mcp.md)).
* **Quick start**: `make quickstart` goes from clone to triaged demo alerts
  and prints the measured time to first verdict ([docs](docs/quickstart.md));
  a first-run setup wizard takes a new install's admin to the first triaged
  sample alert, and new tenants get a getting-started checklist and one-click
  sample alerts ([docs](docs/onboarding.md)).

## Features

**Ingestion**
* Pull connectors for Splunk (search jobs), IBM QRadar (offenses), Microsoft
  Sentinel (Log Analytics), Wazuh indexer and CrowdStrike Falcon (Alerts
  API v2), with persisted cursors, overlap windows, retries and an outbound
  destination policy (no SSRF into your network).
* Push ingestion: canonical alerts (`POST /api/v1/ingest/alerts`) and
  vendor-native webhooks (Splunk, CrowdStrike, Sentinel, Wazuh, GuardDuty via
  EventBridge, QRadar, or any JSON with a field map).
* Deterministic normalisation to one canonical alert model (a subset of OCSF
  Detection Finding) with entities and MITRE ATT&CK; secret redaction before
  anything is stored or sent to a model; deduplication by source alert id.

**Triage and investigation**
* Triage, correlation and analysis agents combining deterministic rules with
  a fast and a deep model tier (Anthropic Claude by default; OpenAI and
  Google Gemini as optional extras; a deterministic offline model for tests
  and demos).
* Correlation across the tenant's alerts by HMAC-hashed indicators; tenant
  alert history and optional threat-intelligence lookups (VirusTotal,
  AbuseIPDB) as evidence.
* Safety policy in code: automation never closes a high or critical alert
  as benign (only an analyst decision, an admin-enabled suppression rule or
  an analyst-confirmed verdict can); a low/medium benign close needs rule
  corroboration, not just the model; containment on model-only evidence
  always waits for approval; model refusals and suspected prompt injection
  go to a human. A response the policy started closes the alert as
  malicious once its actions complete (for example a ticket created under
  autonomy `auto`), whatever the severity.

**Human review**
* Escalations with levels, SLAs, escalation of overdue cases, grouping of
  related alerts into one case, claim/decide with optimistic locking, and
  decisions `true_positive`, `false_positive`, `benign_positive`,
  `needs_more_info` that resume the waiting workflows.
* Analyst feedback capture, suppression rules (analyst proposals enabled by
  admins) and suggestions from false-positive decisions.

**Response**
* A catalogue of containment and notification actions (block IP, domain or
  URL, isolate host, terminate process, quarantine file, disable user, reset
  password, revoke sessions, collect forensics, create ticket, notify),
  planned into an idempotent action ledger.
* Per-tenant autonomy per risk level, protected assets, allowed actions,
  hourly caps and blast-radius limits, re-checked right before execution.
* Dry-run by default; HMAC-signed webhooks to your SOAR for real execution.
  Direct Microsoft 365, Entra ID and Defender for Endpoint execution with
  verification and rollback; other vendors through your SOAR.

**Platform**
* Multi-tenant: PostgreSQL row-level security with a separate non-owner
  runtime role, tenant-scoped Redis keys and checkpoints, platform-admin
  cross-tenant access that is audited.
* Authentication: local accounts (argon2id, lockout, rotating refresh
  tokens), OIDC single sign-on, scoped API keys; roles viewer, analyst,
  admin.
* Append-only, hash-chained audit log per tenant with an API to verify it.
* LLM usage and cost metering per tenant, model and agent; per-tenant daily
  token budgets with rule-only fallback.
* Operations: API, worker, scheduler and migrate roles in one image;
  Redis Streams queue with dead-letter queue and CLI; crash recovery via
  leases and checkpoints; retention and partition maintenance; Prometheus
  metrics, JSON logs; Docker Compose and a Helm chart
  (HPA, KEDA, PDBs, NetworkPolicies, ServiceMonitors).
* Evaluation harness (`lg-sotf eval`) with a synthetic labelled dataset,
  adversarial prompt-injection cases, metrics and a CI regression gate.
* Analyst web application (`src/lg_front`, React and TypeScript, a client
  of the public API only): a live Overview that puts the analyst's own work
  first, an alert queue with filters and a side panel per alert, an
  escalation queue with a decision page per escalation, approvals,
  suppressions, reports and tenant administration, in a dark (default),
  light or system theme. Served by a non-root nginx container under a
  strict Content-Security-Policy. Access tokens are kept in memory only.
  Shipped in the compose stack (`PROFILES=frontend`) and the Helm chart
  (`frontend.enabled`).

### Not in this release

No direct response integrations beyond Microsoft (other vendors go through
your SOAR; tickets and notifications are native), no native SAML
(use an OIDC broker such as Keycloak or Entra ID), no WebAuthn/passkeys, no
billing or self-service sign-up, no model fine-tuning or automatic threshold
learning, and no published accuracy figures on real customer data: the
accuracy report and `lg-sotf eval --from-history` measure it on yours.

## Product tour

A 75-second walkthrough. Captions explain each step: sign-in, the Overview
(your work first, then the window's figures), sending sample alerts, the
Alerts queue and one alert in its side panel, the Escalations queue and a
decision page, Approvals, integrations, tenant settings and the audit log. It
ends on the Overview in the light theme.

![Product tour: LG-SOTF from sign-in to the light theme](docs/media/tour.gif)

[Download the full-quality video (MP4, 1.6 MB)](docs/media/tour.mp4?raw=true). GitHub
plays the GIF above inline but only offers the MP4 as a download. The tour runs against the
same demo stack as the screenshots below: synthetic alerts and the offline
stand-in model. To record it again after a UI change, run
`scripts/record_tour.mjs`, then `scripts/make_tour_media.sh`. Both scripts
explain their usage at the top.

## Screenshots

Taken by the browser end-to-end suite (`scripts/e2e_ui_stack.sh`) against
the compose stack running the offline demo model: the alerts are the suite's
synthetic test alerts, and texts such as "fake conclusion" come from the
deterministic stand-in model, not from Claude.

| | |
|---|---|
| ![Overview](docs/screenshots/02-overview.png) | ![Overview in the light theme](docs/screenshots/02-overview-light.png) |
| Overview: what needs you now, then the last 24 hours; updated live over the WebSocket | The same page in the light theme (dark, light or system, switched in the header) |
| ![Alert in the side panel](docs/screenshots/04-alert-timeline.png) | ![Escalation queue](docs/screenshots/05-escalations.png) |
| Alerts queue with one alert open in the side panel: entities and workflow timeline | Escalation queue in SLA order, to claim one by one or in bulk |
| ![Escalation decision page](docs/screenshots/06-decision.png) | ![Approvals](docs/screenshots/07-approvals.png) |
| Decision page: the investigation next to the analyst's decision form | Approvals: response actions waiting for a human, with guardrails and blast radius |

More pages (sign-in, the alert queue, decided escalations, the actions
ledger, suppressions, sources, users and API keys, tenant settings, LLM usage
and the audit log) are in [docs/screenshots](docs/screenshots).

## Quickstart (Docker Compose)

The fastest path is one command: `make quickstart` (or
`scripts/quickstart.sh`) builds and starts the stack with the offline model,
seeds 16 demo alerts and prints the web UI address and the measured time to
the first verdict; `make quickstart OLLAMA=<model>` uses a local model. See
[docs/quickstart.md](docs/quickstart.md). The manual steps follow.

Requirements: Docker with Compose v2, GNU make, Python 3 (for the secret
generator), `curl`.

### 1. Offline demo with the fake model (no API key)

```sh
git clone https://github.com/gapilongo/SOC.git && cd SOC
make env                     # .env from .env.example plus fresh random secrets
echo 'LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=admin@example.com' >> .env
make up                      # builds the image; starts postgres, redis, migrate, api, worker, scheduler
curl -s localhost:8000/readyz
grep '^LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD=' .env   # the generated admin password
```

The default `LG_SOTF_LLM__PROVIDER=fake` is a deterministic keyword
heuristic that runs offline. It exercises the whole pipeline but is not a
detection model; staging and production refuse it.

Send an alert and review it through the API:

```sh
API=http://localhost:8000/api/v1
TOKEN=$(curl -s -X POST $API/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"<password from .env>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# An API key for senders (shown once)
KEY=$(curl -s -X POST $API/api-keys -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"quickstart","scopes":["ingest"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')

# Ingest a canonical alert
curl -s -X POST $API/ingest/alerts -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '[{"source_alert_id":"demo-1","title":"Mimikatz credential dumping on dc-01","severity":"high",
        "occurred_at":"2026-01-15T10:00:00Z","entities":{"hosts":["dc-01"],"users":["tadmin"]}}]'

# A few seconds later: the alert waits for an analyst, with an escalation
curl -s "$API/alerts?limit=5" -H "Authorization: Bearer $TOKEN"
curl -s "$API/escalations?status=open" -H "Authorization: Bearer $TOKEN"
# Claim (version from the escalation), decide, then approve proposed actions:
#   POST $API/escalations/<id>/claim     {"version": <v>}
#   POST $API/escalations/<id>/decision  {"version": <v+1>, "decision": "true_positive", "notes": "..."}
#   GET  $API/actions?status=awaiting_approval
#   POST $API/actions/<id>/approve       {"reject_remaining": true}
```

With the default `response.dry_run=true`, approved actions are recorded as
`dry_run` and nothing leaves the platform. Interactive API docs are at
`http://localhost:8000/docs`.

The analyst web app runs as a separate container (nginx serving the static
app and proxying `/api` to the api service). Start it with the rest of the
stack and sign in as `admin@example.com`:

```sh
make up PROFILES=frontend    # also builds and starts the web UI
```

Open **http://localhost:3000** (use `localhost`, not `127.0.0.1`: live
updates are accepted only from origins listed in `api.cors_origins`, and the
development configuration lists `http://localhost:3000`). The UI opens on
the Overview (your unassigned and overdue escalations, what you hold, the
approvals you can act on, then the window's figures); the sidebar leads to
the alert queue, escalations to claim and decide, approvals, suppressions
and reports. Admins also see Getting started, Sources, Integrations, Users
and API keys, Tenant settings, LLM usage and the Audit log. The header's
theme switch picks dark, light or the system setting.

Stop with `make down` (keeps data) or `make clean-volumes` (deletes it).
If you started the UI, pass the profile again (`make down PROFILES=frontend`):
without it the UI container keeps running and the stack's network cannot be
removed.

### 2. Real triage with Claude

Add your Anthropic API key to `.env` and restart:

```sh
cat >> .env <<'EOF'
LG_SOTF_LLM__PROVIDER=anthropic
ANTHROPIC_API_KEY=<your key>
EOF
make up
```

The fast tier (triage, correlation) defaults to `claude-haiku-4-5` and the
deep tier (analysis) to `claude-opus-5-5`; change them with
`LG_SOTF_LLM__FAST__MODEL` / `LG_SOTF_LLM__DEEP__MODEL` (set the tier's other
keys too, see docs/configuration.md). Every call is metered: see
`GET /api/v1/usage/llm` and set `LG_SOTF_LLM__DAILY_TOKEN_BUDGET_PER_TENANT` to
cap spend.

### Production

Use the production compose override (two database roles, mandatory secrets)
or the Helm chart in `deploy/helm/lg-sotf`, with TLS in front of the API,
OIDC for analysts, and secrets from your secret store. Follow
[docs/deployment.md](docs/deployment.md). Before promoting an image, run
`make smoke`: it builds the image, starts its own throwaway stack, exercises
ingestion, triage and the API end to end, and tears the stack down. To check
a running deployment instead, run `scripts/smoke_stack.py --base-url ...
flow` with an admin's credentials (docs/deployment.md). For hosted dev and
uat environments (GitHub Actions to a free Oracle Cloud VM, HTTPS by Caddy,
automatic rollback) follow [docs/cicd.md](docs/cicd.md). Processes refuse to
start in `staging`/`production` with missing or placeholder secrets, the fake
model, wildcard CORS or insecure cookies.

## Configuration

All settings come from `LG_SOTF_<SECTION>__<KEY>` environment variables, an
optional `.env`, and an optional YAML file named by `LG_SOTF_CONFIG_FILE`.
Standard `DATABASE_URL`, `REDIS_URL` and `ANTHROPIC_API_KEY` are honoured.
The main groups:

| Section | What it controls |
|---|---|
| `database`, `redis` | Connections, pool sizes, TLS, the runtime and owner database roles |
| `llm` | Provider, fast and deep tier models, timeouts, concurrency, prompt size limits, budgets, prices |
| `auth` | JWT, session lifetimes, lockout, OIDC, bootstrap tenant and admin |
| `api` | Bind address, CORS, body limits, rate limits, metrics token, trusted proxies |
| `worker`, `scheduler` | Concurrency, timeouts, retries, dead-lettering, sweep intervals, leader lease |
| `response` | Dry-run switch, default autonomy, install-wide action cap and SOAR webhook |
| `retention` | Days to keep alerts, events, audit log, indicators, usage, checkpoints |
| `security` | Fernet encryption keys and the indicator HMAC key |
| `routing`, `ingestion`, `agents`, `tools` | Policy thresholds, ingestion limits, escalation defaults, enrichment providers |

Every setting, its environment variable and default is listed in
[docs/configuration.md](docs/configuration.md) (generated from the code).
Tenant policy (autonomy, protected assets, connector, review SLAs,
enrichment keys, token budget) is set per tenant through
`/api/v1/tenant/settings`.

## Security model in brief

* **Tenant isolation** in the database (row-level security, non-owner
  runtime role, `SECURITY DEFINER` credential lookups), in Redis keys, in
  workflow checkpoints and in caches.
* **Least authority for automation**: the model's opinion alone never closes
  a high or critical alert as benign and never triggers containment without
  approval; response actions
  pass autonomy policy and guardrails twice and default to dry run.
* **Prompt-injection defences**: alert data is redacted, size-capped,
  escaped and delimited as untrusted data; output is schema-validated;
  steering text is detected and treated as evidence of malice; an
  adversarial evaluation split is gated in CI.
* **Secrets** only from the environment, encrypted at rest where stored,
  write-only through the API; startup refuses unsafe production
  configuration.
* **Accountability**: every decision, approval and administrative change is
  in a hash-chained, append-only audit log.

Personal data in alerts (names, addresses, hosts) is not pseudonymised and is
sent to the configured model provider when the LLM is enabled. Read
[docs/security.md](docs/security.md) for the threat model and data handling,
and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Measuring quality

```sh
lg-sotf eval --dataset tests/fixtures/eval/synthetic_v1.jsonl --report ~/lg-sotf-eval/smoke.json \
             --thresholds tests/fixtures/eval/smoke_thresholds.yaml
```

The harness runs labelled alerts through the real ingestion and workflow in
fresh tenants (one per split, so split metrics are independent), never
invents analyst decisions, and reports the malicious
false-negative rate (threats closed without a human), benign auto-close rate,
escalation and inconclusive rates, per-class precision/recall/F1, Cohen's
kappa, cost and latency, with a regression gate for CI. The shipped dataset
is synthetic and the CI run uses the fake model, so those numbers check
plumbing and policy, not detection quality; export your analysts' decisions
to evaluate a real model ([docs/evaluation.md](docs/evaluation.md)).

## Development

```sh
python3.11 -m venv .venv && . .venv/bin/activate
make dev                     # pinned dependencies + editable install
make lint                    # ruff + mypy
make test                    # unit tests; integration tests need the variables below
export LG_SOTF_TEST_DATABASE_URL=postgresql://soc:<password>@127.0.0.1:5432/soc_test
export LG_SOTF_TEST_REDIS_URL=redis://127.0.0.1:6379/5
make test
```

Integration tests reset the database named in `LG_SOTF_TEST_DATABASE_URL`
(its name must contain `test`). LLM paths are tested with the fake provider;
no test needs network access. See [CONTRIBUTING.md](CONTRIBUTING.md).

The web app has its own unit tests (`npm run test:ci` in `src/lg_front`).
The browser end-to-end suite drives the real UI in Chromium against the
production-like compose stack (build, start, test, tear down):

```sh
(cd src/lg_front && npm ci && npx playwright install chromium)
scripts/e2e_ui_stack.sh      # --no-build to reuse images, --keep to leave the stack up
```

It signs in, provisions an analyst, a viewer and an ingest API key through
the UI, checks that the Overview updates live when alerts arrive, filters
and pages the alert list, opens a timeline, claims and decides an escalation,
approves a response until the alert closes, checks role gating, signs out,
and asserts that no token is kept in browser storage or written to the
container logs and that no page violates the Content-Security-Policy.

## Documentation

| | |
|---|---|
| [User guide](docs/user-guide.md) | Analyst and admin workflows |
| [Architecture](docs/architecture.md) | The system contract |
| [API](docs/api.md) | Authentication, roles, endpoints, events |
| [Configuration](docs/configuration.md) | Every setting |
| [Deployment](docs/deployment.md) | Image, Compose, Helm, PostgreSQL roles, TLS, sizing, upgrades, backups |
| [CI/CD](docs/cicd.md) | Multi-arch images on GHCR, dev and uat on an Oracle Cloud Always Free VM, promotion, rollback, backups |
| [Self-hosting on a PC](docs/self-hosting-pc.md) | Dev and uat on your own Windows PC (WSL2, Tailscale Funnel), no cloud account |
| [Operations](docs/operations.md) | Runbooks, key rotation, incidents, dashboards and alerts |
| [Security](docs/security.md) | Threat model and controls |
| [Evaluation](docs/evaluation.md) | The evaluation harness |
| [Quickstart](docs/quickstart.md) | One-command demo with measured time to first verdict |
| [Phishing](docs/phishing.md) | Reported-email triage, mailbox sources |
| [Integrations](docs/integrations.md) | Slack, Teams, email, webhooks, Jira, ServiceNow |
| [Reporting](docs/reporting.md) | Value, accuracy and detection reports, backtest |
| [MSSP operations](docs/mssp.md) | Console, suspension, quotas, usage metering |
| [Onboarding](docs/onboarding.md) | First-run setup wizard, getting-started checklist, sample alerts |
| [Identity](docs/identity.md) | MFA, OIDC role mapping and provisioning |
| [Compliance](docs/compliance.md) | Evidence packs, NIS2 drafts, tenant export and erasure |
| [Local LLMs](docs/local-llm.md) / [Air-gapped](docs/air-gapped.md) | Self-hosted models and offline installs |
| [MCP server](docs/mcp.md) | Using LG-SOTF from Claude or another MCP client |
| [Changelog](CHANGELOG.md) | Release notes |

## License

Released under the [MIT License](LICENSE). Contributions are accepted under
the same license ([CONTRIBUTING.md](CONTRIBUTING.md)).
