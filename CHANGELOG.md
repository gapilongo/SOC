# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OpenAI-compatible cloud APIs that refuse OpenAI's tool calling, such as
  DeepSeek's V4 thinking models, now work with the `openai` provider: set
  `llm.base_url` and `llm.structured_output: json_mode` (deploy variable
  `LLM_STRUCTURED_OUTPUT`). Replies are parsed as JSON with one repair attempt
  and metered under the provider's own model name. OpenAI itself, with no
  `llm.base_url`, keeps tool calling.
- DeepSeek prices in the built-in price table: `deepseek-flash` (and its
  retired name `deepseek-v4-flash`) and `deepseek-v4-pro`, at DeepSeek's
  published rates, including the cache-hit price. Prices can now have peak
  windows: a DeepSeek call between 01:00-04:00 or 06:00-10:00 UTC on a weekday
  costs twice the off-peak rate. Before this, DeepSeek usage showed as $0 and
  logged `llm.price_unknown`.
- `GET /auth/me` now returns `tenant_name`, the display name of the tenant
  the request acts on.
- `GET /dashboard/summary` now describes the escalation and approval queues:
  `overdue_escalations`, `unassigned_escalations`, `unassigned_breaching`,
  `next_sla_deadline` (the earliest deadline still ahead),
  `open_escalations_by_severity`, `pending_approvals_total` and
  `pending_approvals_by_risk`, plus two figures for the caller:
  `pending_approvals` (the pending actions your role may approve) and
  `my_claimed` (active escalations assigned to you). `llm_model` names the
  model that writes the analysis verdicts. The caller's figures are never
  served from another caller's cache.
- `GET /escalations` can sort by SLA with `order=sla_deadline`: soonest
  deadline first, so overdue escalations come first and those without a
  deadline last. New filters: `assigned_to=none` (unassigned), `overdue=true`
  and `decided_by` (a user id or `me`).
- Escalations now carry `assigned_to_email` and `decided_by_email`, and a
  digest of their alert: `rule` (the detection rule, else the title),
  `source_id`, `source_name`, `alert_severity` and `entities_preview` (the
  first user, host, IP and so on, with a count per kind). `ai_reason` is the
  first sentence of the analysis conclusion and `ai_reason_source` says
  whether the model or the rules wrote it. `routing` gives the routing code
  that opened the escalation, the confidence, and the review band when a
  band decided it (the grey zone). Escalations opened before this release
  have no `routing` or `ai_reason_source`.
- Alerts now carry `source_name` and `entities_preview`, and the alert list
  takes `closed_from` and `closed_to` to list alerts closed in a window. The
  new `GET /alerts/counts` returns the alert count per status for the list
  views in one call (cached 15 seconds); closed alerts are counted only
  inside a window, today (UTC) by default.
- Response actions now carry `blast_radius` (what kind of target the action
  changes, the hosts it is scoped to and, while it waits for approval, the
  hourly limits it will be checked against), `reversible` and
  `irreversible_note`. Actions waiting for approval carry `guardrail`: the
  verdict of the guardrails checked again now against the tenant's current
  policy, with the reason, and why a human must approve. Blocked actions
  carry the guardrail that blocked them.
- Alert details now list `findings`: each evidence lookup of the analysis
  agent with its source (the provider) and `checked_at`, the time the
  platform received the result. Analyses recorded before this release have
  no `checked_at`.
- `GET /escalations/groups` groups the open and claimed escalations by
  their alert's source and detection rule ("Unusual sign-in pattern ×38"),
  largest group first, with the number unassigned and overdue, the earliest
  deadline, the confidence range and the count per severity. `GET
  /escalations` takes `source_id` and `rule` to list one group.
- Bulk triage: `POST /escalations/bulk/claim` claims up to 50 escalations
  and `POST /escalations/bulk/close` closes up to 50 as false positive (or
  benign positive) with one note. Each escalation is claimed or decided
  exactly as with the single-escalation endpoints (same permissions, version
  check, audit entry and notifications), and the response reports each one:
  one that fails (not found, changed since you read it, already decided)
  does not stop the others. With `propose_suppression`, a bulk close also
  proposes one disabled suppression rule from the escalations it closed.
- `POST /escalations/bulk/propose-suppression` proposes one disabled
  suppression rule from up to 50 escalations an analyst decided false
  positive or benign positive. It is all or nothing: if one escalation is
  not found, or has no such decision, nothing is created. The rule matches
  those alerts' detections (fingerprints) and sources, up to the most severe
  of their severities; an admin enables it.
- `GET /escalations/{id}/response-preview` shows the response plan a
  true-positive decision would produce, without running or recording
  anything: for each action its risk, whether it can be rolled back, the
  connector that would run it, the guardrail verdict, whether it would run
  automatically or wait for approval, and whether your role may pre-approve
  it (high and critical risk need an admin).

### Changed

- Building the web app from source (`src/lg_front`) now needs Node.js
  22.12 or later; Node 20 is no longer supported. The frontend image
  already built on Node 22, so container deployments are unaffected.
- The command line now applies the API's password policy to the
  passwords it sets (`lg-sotf create-admin`, `lg-sotf create-tenant
  --admin-email` and the bootstrap admin that `lg-sotf migrate` creates
  from `auth.bootstrap_admin_password`): besides at least
  `auth.password_min_length` characters, a password must have at most
  1,024 characters and at least 4 different characters, or the command
  fails with "password is too repetitive" or "password must be at most
  1024 characters". Before, the CLI checked only the minimum length.
  Generated bootstrap passwords already comply.
- The worker and the scheduler now refuse to start when
  `security.encryption_keys` is set but holds a key that is not a valid
  Fernet key, as the API already did: `lg-sotf worker` and
  `lg-sotf scheduler` exit with the configuration error. Before, they ran
  without a key, and every action, notification, ticket and source poll that
  needed a stored credential failed later. Unset keys still start every role.
  Each process now builds its key set once at startup and passes it to the
  components that decrypt credentials (ADR-0006).
- Roles are now listed from least to most privileged (`viewer`, `analyst`,
  `admin`) everywhere: in the choices of `lg-sotf create-admin --role` and
  in the "expected one of" message when a user is created or updated with
  an unknown role. Before, these two listed `admin, analyst, viewer`. The
  roles themselves and the `admin` default are unchanged.
- Web UI: an error on one page no longer replaces the whole app. Each page
  has its own error screen, and the sidebar and header stay usable. When a
  new version has been deployed and an old page bundle can no longer be
  loaded, the page says "A new version is available" and offers a reload.
- Web UI: the LLM usage page checks the date window (start before end,
  within the allowed range) before it sends the request, with the same
  message as the reports page.
- Web UI: while the phone menu is open, keyboard focus stays inside it, and
  Escape closes it.

### Fixed

- The account menu button in the web app now includes the initials it
  shows in its accessible name ("Account: <email>, <role>, initials MR"),
  so speech-input users can activate it by saying what they see (WCAG
  2.5.3 Label in Name).
- An LLM call that failed unexpectedly no longer leaves its token estimate
  counted against the tenant's daily LLM budget. Each call reserves an
  estimate first and settles it with the tokens actually used, but an
  error while preparing the call or while reading or recording the
  model's answer skipped that step, so the whole estimate stayed counted
  until the end of the UTC day. Every outcome now settles the
  reservation, including a call cancelled by a node timeout, which counts
  the tokens of the attempts already answered.
- Web UI: `/account` (account security) is no longer reachable by typing
  the URL while a platform admin acts on another tenant. The account menu
  already hid it in that case.
- Web UI: an integration of a kind this version does not know is listed
  with its own name and cannot be edited, instead of opening the Slack
  form. Tenant quotas the API does not report show "-" in the quota
  dialog, which no longer writes the text "undefined".
- A worker could hang on graceful shutdown until it was killed. It
  cancelled its liveness and usage-flush loops only once, and a cancel can
  be swallowed inside a Redis command on Python 3.11, leaving those loops
  running forever. Shutdown now cancels them repeatedly until they stop,
  like the worker's other background tasks. This was the cause of the
  occasionally flaky `test_worker_restart_mid_processing_loses_no_alert`.

- `GET /users` now lists every account of the tenant. Before, it stopped
  at the first 1,000 accounts by email and left the rest out without
  saying so. The response format and order (by email) are unchanged.
- Web UI: the Actions page now explains the `internal_sender`,
  `invalid_email`, `invalid_message`, `rejected_by_reviewer` and
  `rejected_with_remaining` block reasons instead of showing the raw codes.
  A test now fails when the backend adds a guardrail reason that the web app
  cannot describe, or when the web app's source-type, integration-kind or
  ticketing-kind lists drift from the backend.
- Web UI: a successful API answer that is not JSON, such as the app's own
  `index.html` served by a misrouted proxy or a cut-off body, now shows an
  error card ("The API response could not be read") with the request id.
  Before, the page showed a raw `SyntaxError`. Empty answers and downloads
  are read as before.
- Web UI: Jira and ServiceNow ticket links now show on the Escalations page
  when more than one page of escalations is loaded. Before, the page asked
  for the tickets of up to 200 escalations in one request whose address was
  about 10 KB long. The proxy refuses addresses over 8 KB, so the links
  silently disappeared. The page now asks in batches of 50, still for the
  first 200 escalations.
- A change is no longer left in place when its audit log entry cannot be
  written. Before, the change was saved first and the entry written
  afterwards, so a failed write answered 500 but the change stayed, with no
  trace in the audit log. Now the change and its entry are saved together:
  either both are there or neither is, and the request can simply be
  retried. This covers MFA enrollment, disabling MFA, new recovery codes,
  using a recovery code, the role update of a single sign-on account,
  creating, updating and deleting alert sources, suppression rules and
  integrations, integration connection tests, creating users and API keys,
  revoking API keys, the getting-started checklist steps, and, on the
  command line, `create-admin`, the bootstrap admin of `migrate`, `enqueue`
  and `dlq requeue`.
- The scheduler's SLA escalation and expiry entries are now redacted and
  logged like every other audit entry.
- Provisioning a tenant (`POST /platform/tenants`) no longer leaves a
  half-created tenant behind. Before, if creating the first admin or an
  audit entry failed, the tenant already existed without its admin, and
  retrying answered 409 "already exists". Now the tenant, its settings, its
  first admin and its audit entries are saved together, so a failure leaves
  nothing behind and a retry succeeds. `lg-sotf create-tenant` now does the
  same: a failed run leaves no tenant, so running it again works instead of
  reporting that the tenant already exists. Changing a tenant's name, status or
  quotas is also saved together with the platform admin's audit entry.
- Notifications, ticketing requests and response-action webhooks no longer
  build a new TLS context for every request. Each request used to load the CA
  bundle again, synchronously on the event loop, blocking other work in the
  API and the workers while it did. One context per process is now reused for
  default verification, and one per distinct `ca_cert_pem` (up to 256), so an
  integration with its own CA still trusts only that CA.
- Sign-out could leave the session alive. The web app showed the sign-in
  page before `POST /auth/logout` had finished; reloading at that moment
  aborted the logout request, and the reload's `POST /auth/refresh` rotated
  the refresh cookie before the logout revoked it. The API revoked only the
  token presented at logout, so the rotated cookie stayed valid and the
  reload signed the user back in. Now the web app reports signed out only
  after the API answers (at most 5 seconds), starts no refresh meanwhile, and
  sends the logout with `keepalive` so a navigation cannot abort it. Logout
  also revokes every token the presented one was rotated into.

## [1.2.3] - 2026-11-05

### Fixed

- Evidence packs and NIS2 incident drafts for an alert that was attached to
  another alert's escalation now include that escalation, its decision and
  its audit entries. Before, they matched only escalations whose primary
  alert was the one exported, so the pack for an attached alert omitted the
  decision that closed it.
- The GDPR tenant export now includes `indicator_sightings.jsonl`: the
  indicator values seen on each alert as displayed (IP addresses, email
  addresses, user and host names). The manifest's `excluded` list now names
  workflow run bookkeeping as well, and a test fails when a new
  tenant-scoped table is neither exported nor listed as excluded.
- `DATABASE_URL` and `REDIS_URL` are now true fallbacks. Before, an exported
  `DATABASE_URL` or `REDIS_URL` overrode the URL from init arguments, the
  YAML config file and `.env`, contrary to the documented precedence.

- Web UI: **Load more** on a list no longer loses the page it is loading
  when a live update arrives at the same time. The live refresh cancelled the
  in-flight request and refetched only the pages already shown; it now waits
  for the page to arrive. This was also the cause of an intermittent e2e
  failure.
- A `Retry-After` header of `inf`, `nan` or a very large number no longer
  reaches retry sleeps or schedules: non-finite values are ignored and every
  hint is capped at one hour. Enrichment now uses the same parser as the
  other HTTP clients (it also accepts fractional seconds).

### Changed

- `make lint` type-checks the same packages as CI (adds `integrations` and
  `mcp`); a test keeps the two lists in step.
- API-key authentication uses the shared `verify_api_key` helper instead of
  an inline comparison (same constant-time check).
- `docs/architecture.md` package layout, connector list and tracing note
  match the code; `docs/operations.md` no longer says traces are exported
  (the exporter is configured, but no spans are created yet).

### Removed

- Dead code with no production callers: the `ConfigManager` facade
  (`lg_sotf.core.config`) and `lg_sotf.utils.llm`, the unused tool
  orchestrator layer (`lg_sotf.tools.base`, `cache`, `orchestrator`), the
  legacy `AgentRegistry` and unused `BaseAgent` methods, seven unused
  exception classes, the duplicate `lg_sotf.main` entry module (use
  `lg-sotf` or `python -m lg_sotf`), and small unused helpers.
- The unused `aiohttp` and `aiofiles` runtime dependencies (and aiohttp's
  dependency stack) from the package and the container image.
- 22 empty legacy test files and packages and unreferenced alert fixtures.
- Web UI: unused exports and live-event state that re-rendered consumers on
  every event.

## [1.2.2] - 2026-11-05

### Fixed

- Lookalike-domain detection now catches brand domains spelled with a
  Cyrillic `і`, Greek `ι` or dotless `ı` in place of `i` (for example
  `mіcrosoft`). The comparison folded those letters to `i` but folded ASCII
  `i` to `l`, so the two spellings never matched.
- `lg-sotf dlq requeue` now really starts a dead letter with
  a fresh delivery count. The copy kept the exhausted `retries` counter, so
  a requeued resume could be dead-lettered again on its first failure.
- Jira and ServiceNow ticket creation and comments are no longer resent
  after a read timeout or a 5xx answer, which could open a duplicate
  ticket or post a comment twice. They are still retried when the request
  never reached the server (connection refused or timed out, HTTP 429);
  otherwise the error goes to the caller, whose retry looks for the ticket
  first.
- Alerts normalized by the LLM fallback now carry the `secrets_redacted`
  flag when redaction replaced values in them.
- Splunk sources reject an invalid `max_event_lag_s` or `search_timeout_s`
  (null, text, negative, NaN, infinite or out of range) with a field-named
  config error. Before, null failed with an HTTP 500 and NaN made the job
  wait loop poll forever. Values must now be numbers: 0 to 30 days for the
  lag, 1 to 3600 seconds for the search timeout.

### Changed

- The reference configs (`configs/*.yaml`) carry only keys the code reads.
  Keys under `tools.virustotal` were misnamed and ignored: they are now
  `timeout_s` and `requests_per_minute`. In `development.yaml` VirusTotal
  sat under `tools.intel` and its key was never used. `ingestion.
  llm_normalization` is now the real switch, `ingestion.llm_fallback`.
  Obsolete blocks that looked like controls but did nothing are removed:
  `agents.response` (`dry_run_mode`, `auto_approve_*`; the real switch is
  `response.dry_run`), `agents.ingestion`, `agents.human_loop`, and the
  `tools` retry and cache keys. A new test fails when a reference config
  sets a key in `agents`, `routing`, `tools` or `ingestion` that nothing
  reads.

### Security

- Pinned dependencies updated for published advisories: aiohttp 3.14.4,
  certifi 2026.10.18, langgraph-checkpoint-postgres 3.1.3 (with
  langgraph-checkpoint 4.3.0), langgraph-sdk 0.4.6, OpenTelemetry
  1.45.1 / 0.66b1 and pyasn1 0.6.5.

## [1.2.1] - 2026-10-01

### Fixed

- A model call that fails fast with a transient provider error (HTTP 429,
  5xx such as Gemini's "503 high demand", or a refused connection) is now
  retried twice within the call (about 2 s and 6 s apart). Before, the
  analysis step's retry budget allowed a single attempt, so such an error
  failed the run and the alert waited about 20 minutes for redelivery.
  Timeouts are still left to the node policy.

## [1.2.0] - 2026-10-01

MCP for testers and analysts: Phases 0 and 0.5 of the approved MCP
architecture (`docs/design/mcp-architecture.md`). Security first: MCP reads,
does safe writes and proposes; it never approves, rejects, rolls back or
retries actions, decides escalations, or changes settings, sources,
integrations, users, keys or MFA.

### Added

- Seven new `lg-sotf mcp` tools: `whoami`, `get_verdict`, `list_actions`,
  `get_action`, `ingest_test_alerts`, `wait_for_verdict` and `get_test_run`.
  From Claude Code, a tester on a dry-run dev or UAT install can send up to 25
  canonical test alerts with expected labels, wait for triage, read verdicts,
  routes, reasoning and proposed actions, and score the run (accuracy, route
  and escalation accuracy, mismatches, contamination). Analysts gain read
  access to verdicts and the response-action ledger.
- `LG_SOTF_MCP__API_KEY_FILE`: the key is read from an owner-only file and
  never sits in the launching shell.
- `examples/mcp/.mcp.json`: a committable Claude Code entry (docker, image
  `v1.2.0`, key file mounted read-only, no URL or credential).
- `docs/mcp.md`: the tester workflow, the QA-tenant runbook and the security
  model; `docs/design/mcp-architecture.md`: the full design and its phases.
- Web app: "Connect an AI client" help on the API keys card.

### Changed

- Every MCP tool result strips invisible, bidi and control characters, and
  escapes `>` as well as `<` inside the untrusted-data block.
- `add_note` is annotated as destructive, so clients ask before calling it.
- One malformed message no longer ends the stdio session; a long
  `wait_for_verdict` no longer blocks other requests and stops when cancelled.

### Upgrade notes for 1.2

- Test alerts sent through MCP are triaged like real ones in this release.
  Use them only on an install with `response.dry_run=true` (the default) and
  in QA tenants without integrations, as the runbook in `docs/mcp.md` says.
  Server-side rehearsal routing for MCP-ingested alerts comes in Phase 1a.

## [1.1.0] - 2026-10-01

Approved response actions now run directly in the customer's Microsoft
environment, and LG-SOTF proves they happened.

### Added

- **Microsoft direct response** (`docs/microsoft.md`): a `microsoft`
  integration per tenant (its own app registration, client secret or
  certificate, write-only and encrypted; global, US Government, GCC High,
  DoD and China clouds with fixed Microsoft hosts, never a tenant-supplied
  URL). A connection test reports token, permissions and readiness per
  capability, including Exchange RBAC for Applications setups.
- **Per-action routing**: each action type goes to the Microsoft connector,
  the SOAR webhook, ticketing or dry run (`GET /tenant/response/routes`); the
  dry-run kill switches always win, and a tenant dry run makes Microsoft
  rehearse an action without changing anything.
- **Microsoft 365 mail** (`docs/microsoft-mail.md`): `purge_message` finds the
  reported message by Internet Message-ID in each recipient mailbox (from the
  alert or message trace) and removes it; `restore_message` rolls it back;
  `notify_reporter` sends a fixed update from the SOC mailbox.
  `block_sender` stays on the SOAR webhook (no Microsoft API exists).
- **Entra ID** (`docs/microsoft-entra.md`): `disable_user` (rollback
  `enable_user`), `revoke_sessions`, `reset_password` (random, never stored,
  change forced at next sign-in) and `confirm_compromised` (rollback
  `dismiss_user_risk`). A guard refuses privileged targets and protected
  assets, including aliases and object ids.
- **Defender for Endpoint** (`docs/microsoft-defender.md`): `isolate_host`
  (rollback release), IP/domain/URL and file indicators with expiry (rollback
  deletes only LG-SOTF's indicators), stop-and-quarantine, and investigation
  package collection.
- **Verification**: executed actions are re-checked against Microsoft until
  proven or failed (`action.verification_failed` event, a badge in the UI,
  `POST /actions/{id}/verify`).
- **Rollback and retry**: `POST /actions/{id}/rollback` records an inverse
  action under the same approvals; `POST /actions/{id}/retry` resumes failed
  or partial Microsoft actions. Approvals that arrive after the alert's
  workflow ended run in a background job; approvals older than
  `response.approval_ttl_s` expire.
- **SOAR templates** (`docs/soar-playbooks.md`): a dependency-free reference
  receiver (`examples/soar/receiver`) and an importable n8n workflow, plus
  recipes for Tines, Shuffle and Tracecat.

### Fixed

- Phishing: a link's visible text is no longer a block target. Only real link
  targets, the sender infrastructure and reply-to domains can be blocked.

### Upgrade notes for 1.1

- Migration `0009` adds ledger columns for routing, verification and rollback
  and builds its indexes concurrently. Its downgrade is refused while a
  Microsoft integration exists.
- Stranded approvals from 1.0 older than `response.approval_ttl_s` are
  blocked as `approval_expired` instead of executed.
- Nothing runs against Microsoft until a tenant adds a Microsoft integration,
  enables capabilities and turns dry run off. Live behaviour was tested
  against faithful API fakes, not a real tenant: validate in a lab tenant
  first (see the open items in `docs/microsoft.md`).
- CI now lints, type-checks and scans `examples/` and type-checks
  `src/lg_sotf/integrations`.

## [1.0.0] - 2026-09-30

The first commercial release: the multi-tenant platform rebuild (tracked as
0.2.0, never released on its own) plus the Release 1 product features below.

### Added in 1.0

- **Phishing triage** (`docs/phishing.md`): user-reported email ingestion
  from `POST /api/v1/ingest/email`, a Microsoft 365 reporting mailbox
  (`m365_mailbox` source, Graph) and any IMAPS mailbox (`imap` source);
  a hardened MIME parser (nothing rendered, attachments hashed not stored,
  explicit caps); phishing signals in triage and analysis (SPF/DKIM/DMARC,
  reply-to and return-path mismatch, display-name impersonation, lookalike
  and punycode domains, deceptive links, risky attachments); actions
  `purge_message`, `block_sender`, `notify_reporter`; tenant settings
  `phishing`; a 39-item synthetic phishing evaluation set.
- **Integrations hub** (`docs/integrations.md`): Slack, Microsoft Teams
  (Workflows), SMTP email and HMAC-signed webhook (`lg-sotf.event.v1`)
  notifications for escalations, SLA breaches, pending approvals, action
  outcomes and critical alerts, through a transactional outbox with retries,
  backoff, dead-lettering and a delivery log; Jira (Cloud and Data Center)
  and ServiceNow tickets, one per escalation, with decision comments and
  external-resolution notes; `create_ticket` executes through them; Slack
  interactive approve/reject under the web app's authorization rules.
- **Self-hosted models** (`docs/local-llm.md`, `docs/air-gapped.md`):
  `ollama` and `openai_compatible` providers, plain HTTP only for private
  hosts, `llm.structured_output` with one schema-guided repair, local usage
  metered at zero cost, `POST /api/v1/tenant/llm/test` and a "Test model"
  button, `docker/docker-compose.ollama.yml`, and verified air-gap
  bundle/load scripts; Gemini list prices.
- **Quick start** (`docs/quickstart.md`): `make quickstart` /
  `scripts/quickstart.sh` with 16 synthetic demo alerts and the measured time
  to first verdict (2 min 13 s on the reference run, 2.1 s after ingest).
- **Reports** (`docs/reporting.md`): value (handled without a human, analyst
  hours saved via `reporting.minutes_per_alert`, time to verdict, MTTA/MTTR,
  SLA breaches, cost per alert), accuracy against analyst decisions
  (false-negative rate headline, confusion matrix, confidence ranges,
  per-model breakdown), detection tuning with one-click suppression
  proposals, a printable monthly report, CSV exports, dashboard value tiles,
  and `lg-sotf eval --from-history` (side-effect-free backtest).
- **MSSP operations** (`docs/mssp.md`, `docs/onboarding.md`): MSSP console
  with per-tenant activity, SLA risk and quota usage; suspend and reactivate
  (ingest, API keys, sessions and workers honour it, queued work is kept);
  daily alert, source and user quotas; `usage_daily` metering and monthly
  usage export; tenant profiles and policy copy; a tenant switcher;
  per-tenant retention within install bounds; a getting-started checklist
  with one-click sample alerts.
- **Identity** (`docs/identity.md`): TOTP MFA for local accounts with
  recovery codes, admin and CLI reset (`lg-sotf reset-mfa`), a tenant
  `security.require_mfa` policy and `auth.require_mfa_for_platform_admins`;
  OIDC role mapping from group claims and just-in-time provisioning.
- **Compliance** (`docs/compliance.md`): signed case evidence packs
  (`GET /alerts/{id}/evidence`, `lg-sotf evidence-verify`) with per-step
  model provenance, the human-oversight trail and audit-chain proof; NIS2
  incident report drafts for each Article 23 stage; streamed tenant data
  export and erasure (`lg-sotf tenant-export`, `tenant-erase`).
- **MCP server** (`docs/mcp.md`): `lg-sotf mcp`, a stdio Model Context
  Protocol server over the REST API with a scoped API key.

### Upgrade notes for 1.0

- Migrations `0004` to `0008` run with the `migrate` role as usual.
- Platform admins must enrol an authenticator app at their next sign-in in
  staging and production. Set
  `LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false` to postpone it.
- The scheduler now also delivers notifications and syncs tickets; it must
  keep running (one leader) for integrations to work.
- Response execution stays in dry run by default.

### Fixed in 1.0

- Gemini "503 high demand" and "429 resource exhausted" errors are now retried
  like other providers' transient errors, instead of failing the run until
  the message is redelivered (found in the Dev smoke test).

### Platform rebuild (previously 0.2.0)

A ground-up rebuild of the proof of concept into a multi-tenant platform
that can be operated in production. Nothing of the 0.1 runtime is
compatible: configuration, storage, APIs and deployment all changed. There is
no automated migration from 0.1 data.

#### Added

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

#### Changed

- The analyst web application in `src/lg_front` is rebuilt as a client of
  the new API (see its README).
- Configuration moved from `ConfigManager` YAML files to typed settings;
  `ConfigManager` remains as a thin read-only facade for agents.

#### Removed

- The proof-of-concept runtime (`app_initializer`, in-process queues and
  deduplication, schema creation at startup), empty placeholder modules and
  documentation, and dead files (`Backup/`, `test.html`,
  `test_claude_simple.py`, `test_claude_workflow.py`, `setup_api_key.sh`).

#### Security

- See [docs/security.md](docs/security.md) for the threat model and
  controls, and [SECURITY.md](SECURITY.md) for vulnerability reporting.
- Release hardening from the final review: login attempts are counted
  before the password check (lockout holds under concurrency); SSO is
  blocked by a disabled local account even without `email_verified`; open
  WebSockets re-check logout, deactivation and suspension and are capped per
  principal and tenant; LangGraph checkpoint tables are under tenant RLS;
  CLI-created accounts and reprocessing are audited; tenant-less login is
  resolved by password; response targets exclude parent processes and a
  built-in list of critical processes, and are scoped to the alert's hosts;
  containment on rule evidence applies only to corroborated targets;
  verdict-cache hits are severity-bound and invalidated by true positives;
  LLM-normalised alerts are never closed automatically; more command-line
  credential forms are redacted; URL guardrails canonicalise hosts;
  cookie endpoints check `Origin`; the compose stack trusts only its own
  proxy's `X-Forwarded-For`; the runtime image carries no pip or setuid
  binaries; Helm refuses enrichment keys in values.

#### Fixed

- Worker runs could wedge when a cancellation was swallowed inside redis-py
  on Python 3.11; cancelled polls, lost resume messages and stale resumes are
  recovered from PostgreSQL; ledger transitions and their audit entries are
  atomic; retention removes checkpoints with their alert and expires failed
  alerts; the token budget survives a Redis restart; dead consumers leave the
  group; settings PATCHes no longer lose concurrent updates.
- A worker killed after a graph step's writes were saved but before that
  step's checkpoint (seen right after `__start__`) no longer leaves its alert
  stuck in `processing` with the run marked `completed`: the retry continues
  the thread from the saved writes.
- Throughput: single-tenant workers use their full concurrency, LLM slots
  follow `worker.concurrency`, dispatch is batched with ingest admission
  control, and new indexes serve the dashboard and alert-list filters (see
  docs/performance.md).

## Before 0.2.0

Proof of concept: a single-process LangGraph workflow demonstrating
LLM-assisted alert triage. Not supported.
