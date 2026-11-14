# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- An investigation trace. Every model call and every threat-intelligence or
  history lookup of an alert's investigation is now stored, in order, with
  the prompt and model (or tool), token counts, latency, outcome and the
  SHA-256 of what went in and came out, plus a redacted, size-capped digest
  of the result. Evidence packs show the steps in a new **Investigation
  trace** section (HTML) and under `investigation` (JSON). The trace is kept
  and deleted with its alert, and is part of the tenant data export. Database
  migration 0011 adds the `investigation_steps` table.

- A proof-of-value install profile: `scripts/pov.sh --siem-host HOST` (or
  `make pov SIEM=HOST`) starts a stack that can only read. Every response
  action is blocked or recorded as dry run, whatever a tenant admin sets; pull
  sources that mark or move mailbox messages are refused; and outbound
  connections go only to the SIEM host(s) and the model endpoint (local Ollama
  by default, or an EU-hosted endpoint; DeepSeek is refused). It ends with the
  next steps: connect a source, then `scripts/pov.sh --backtest 90`. Helm
  users layer `deploy/helm/lg-sotf/values-pov.yaml`. See docs/pov.md.
- Two install-level settings: `ingestion.allowed_destination_hosts`, an egress
  allow-list for sources, integrations, response webhooks, Microsoft Graph,
  enrichment providers and the LLM endpoint (unset by default, so nothing
  changes for existing installs), and `ingestion.read_only_sources`, which
  refuses the `m365_mailbox` and `imap` sources.
- `lg-sotf eval-scorecard` turns the JSON reports of `lg-sotf eval` (one per
  dataset, same model) into a one-page scorecard in Markdown and JSON: the
  malicious false-negative rate first, with counts and a 95% Wilson interval,
  then auto-close precision, escalation rate, per-class precision and recall,
  cost and latency per item, the model and prompt version, and the
  limitations. DeepSeek scorecards are marked internal only. The first
  baseline, a local `qwen2.5:7b` on Ollama over the synthetic and phishing
  sets, is in `docs/scorecards/`.
- A first-run setup wizard for the install's admin (the platform admin
  `lg-sotf migrate` creates). Until setup is done the Overview invites them to
  it; five steps confirm the account, name the organisation and the first
  tenant, pick a language-model profile (an EU-hosted Mistral profile is
  preselected, local Ollama or your own model server are offered; the wizard
  shows the settings that select it and tests the model configured now), send
  the sample alerts and wait for the first verdict. Finishing lands on the
  Overview with a link to start a proof of value (a placeholder page until the
  proof-of-value run ships). The wizard never changes the running model,
  which stays install configuration. API: `GET` and `PUT /onboarding/setup`,
  `POST /onboarding/setup/complete`, audited as `onboarding.setup_saved` and
  `onboarding.setup_completed`.
- `GET /onboarding/status` now returns `first_verdict`: an alert, samples
  included, is closed or waits for an analyst or an approval (the moment
  `make quickstart` measures).
- An install rehearsal test drives the setup from an empty database to the
  first triaged alert and records the time against a 30-minute budget
  (`tests/integration/e2e/test_first_run.py`; the browser twin is
  `src/lg_front/e2e/wizard.spec.ts`).
- Every model call now records which prompt version it sent. Each prompt has
  a name (such as `triage.assess`) and a short hash of its text and output
  schema, so a changed hash means the model was asked something different.
  The alert's model provenance, evidence packs (JSON and HTML), the
  `llm.call` log event and evaluation reports (a new "Models and prompts"
  section) show the prompt name and hash next to the provider and model.
- Runs waiting for an analyst or an approval now survive upgrades that change
  the workflow graph. Each run records the graph version it started on
  (`workflow_runs.graph_version`, migration 0010), and workers keep the
  previous graph next to the current one, so a waiting run resumes and is
  decided on the graph it started on. A run on a graph version the worker
  does not have fails with `UnknownGraphVersion` and is retried, then
  dead-lettered; it is never run on a different graph.
- Every change is now tested against a real upgrade before it merges. A CI
  job (`scripts/ci/upgrade_rehearsal.sh`) runs the previous release on a
  fresh database until some alerts wait for an analyst and one waits for an
  approval, migrates the database with the new release as the schema owner,
  and decides every waiting alert through the new release's API. The build
  fails if any of those runs fails, is dead-lettered or stays open, or if the
  upgrade changes the runtime database role's privileges.
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
- The Wazuh connector is now tested against a real Wazuh 4.14 indexer, not
  only a fake: `make test-wazuh-up` starts a Wazuh indexer lab with the alert
  index template Wazuh publishes and sample 4.14 alerts, and `make
  test-wazuh` runs live contract tests for authentication, paging and
  resuming, severity mapping, empty windows and malformed documents. CI runs
  them in a new, non-blocking job. More alerts can be loaded into the lab
  with `python -m tests.fixtures.wazuh_lab load` (docs/testing.md).

- Telemetry for the evaluation corpus (AI-E1.10). An investigation needs
  what surrounds an alert, and `corpus_v1` held alerts only.
  - `corpus_v1_events.jsonl.gz`: 291 context events around the corpus alerts
    of the Windows logon-failure and service-install families (the logon
    before a service install, the success after a typo, retry cadences,
    PsExec process trees, the fleet's updater installs). `corpus_v1.jsonl.gz`
    itself is unchanged.
  - `corpus_skills_v1.jsonl.gz`: 196 labelled alerts of those two families
    (63 and 60 attacks, 73 benign) with their own context events. 28 are
    context-abuse attacks that sit inside what the tenant declared: a spray
    from the admin workstation, PsExec by an admin account followed by
    discovery, an "updater" service outside the patch window, a service
    account used interactively.
  - Gold evidence for both (`*_gold.json`): per item, the benign hypothesis
    the telemetry supports, the malicious indicators and never-close
    conditions of ADR 0014 that are true, and the documents they rest on.
  - `lg_sotf.eval.tool_fixtures.EventStore`: an in-memory store of a
    dataset's alerts and events that answers indexer-style queries as of a
    moment, so a replayed investigation never sees the future.
  - `scripts/load_corpus_telemetry.py`: loads the telemetry around chosen
    corpus items into a lab's Wazuh indexer with timestamps moved to the
    present, idempotently. The indexer URL and credentials come from the
    environment and are never printed, and the script refuses a host that
    was not passed with `--host`. See `docs/evaluation.md` ("Corpus
    telemetry, gold evidence and the skills corpus").

- Evaluation cassettes: `lg-sotf eval --cassettes DIR --cassette-mode record`
  writes each item's tool observations (reputation, history, enrichment
  providers) and model replies to one JSON Lines file per item. The default
  `replay` mode runs the dataset again from them with no network call and the
  same verdicts; `replay-tools` replays the tools and calls the configured
  model, to compare a new model or prompt on the same observations. A call
  the cassette does not hold fails the item (`CassetteMiss`) instead of going
  out. Cassettes for the first synthetic and phishing items are committed;
  `make eval-cassettes` records them again.

- Shadow mode, part one: system code can run a candidate pipeline (another
  model, prompt or graph) on a real alert beside the production run. The
  shadow run records what it would have done (notifications, escalation,
  response plan, alert changes, live UI events) in the new `shadow_effects`
  table instead of doing it. Migration `0013` creates the table; it is in the
  tenant data export and follows alert retention. No API endpoint exposes
  shadow runs yet.

- Shadow agreement report: `lg-sotf shadow-run --tenant T --candidate profile.yaml --window 7d`
  replays a tenant's recently decided alerts through a candidate model
  profile in shadow mode and reports how often it takes the same route as
  production (overall and per route, with n and a 95% confidence interval),
  a confusion matrix, the alerts the candidate would have closed where
  production escalated (listed first), escalate and plan_response
  differences, candidate failures, new escalations, different response
  plans, and the cost and latency difference per alert. A candidate run that
  fails, or whose model answers are unusable so the rules decide, counts as a
  disagreement and is listed; the report says when there is not enough to
  judge the candidate on. Platform admins can also read the report at
  `GET /api/v1/platform/shadow/reports/{id}` (beta). Migration `0015` adds
  the `shadow_verdicts` table (append-only, tenant row-level security,
  deleted with its alert, in the tenant data export, not in the evidence
  pack).

- New settings `database.shadow_url` (the shadow role's login),
  `database.shadow_role` (the role `lg-sotf migrate` grants `SELECT` on the
  tenant tables, except the credential tables, and nothing else) and
  `database.shadow_pool_max`. Without `database.shadow_url` shadow runs
  refuse to start; they never fall back to the runtime role. `lg-sotf
  migrate` refuses a shadow role that could write or bypass tenant
  isolation, and changes nothing in that case: it reports the role and the
  fix after the schema upgrade, which stays in place. `database.shadow_url`
  accepts the same URL forms as `database.url` (`postgresql+asyncpg://`,
  `postgresql+psycopg://`).
- Production compose: set `LGSOTF_SHADOW_PASSWORD` before the first start
  to create `lgsotf_shadow`, grant it and give its login to the worker.
  Helm: the new `secrets.shadowSecret` (key `LG_SOTF_DATABASE__SHADOW_URL`,
  loaded into the worker only) and `settings.database.shadow_role`. For an
  existing database, create the role by hand (docs/deployment.md, section 4).
- New setting `security.shadow_candidate_llm_hosts`: the LLM hosts a shadow
  candidate profile may call besides production's own. It is read from the
  production settings only; a candidate profile cannot extend it.
  `lg-sotf shadow-run` refuses a candidate on any other host before reading
  any alert, and stores the candidate's host (never its key) on each
  verdict row and in the report (`candidate_host`; migration `0017`).
- Each `lg-sotf shadow-run` is audited in the tenant
  (`tenant.shadow_replayed`) and in the platform tenant
  (`platform.tenant_shadow_replayed`), with the report id, candidate label
  and host, window and number of alerts.

- Every rate in the evaluation reports, the scorecard and the Reports pages
  now comes with its sample size and a 95% Wilson interval, for example
  `25.0% (1 of 4; 95% CI 4.6% to 69.9%)`, so a rate over a handful of alerts
  no longer reads like a firm number. Eval reports carry `metrics.intervals`,
  which the gate can check (for example
  `intervals.malicious_false_negative_rate.ci_high`). The `/reports/*`
  responses add a `<rate>_ci` field next to each rate, with `rate`, `n`,
  `ci_low` and `ci_high`, and the CSV exports add `_n`, `_ci_low` and
  `_ci_high` columns at the end. Existing fields and columns are unchanged.
  A sample too small to read is shown everywhere as "Not enough data (n=…)".

- An attack-emulation ground-truth corpus, `corpus_v1`
  (`tests/fixtures/eval/corpus_v1.jsonl.gz`): 520 labelled Wazuh 4.14
  alerts, 208 malicious and 312 benign (a 40/60 split). The malicious alerts
  come from Atomic Red Team tests chained into Caldera-style campaigns
  (Office macro to credential theft, PsExec to ransomware, SSH brute force to
  persistence, web exploitation to a web shell, Kerberoasting, UAC bypass
  and WMI persistence, a Linux cryptominer, password spraying and more); the
  benign ones are routine noise (admin logins, patching, backups, monitoring)
  and look-alikes that trip the same rules (an authorised scanner, IT using
  PsExec, Ansible editing root's crontab, updaters dropping executables).
  Every alert names its ATT&CK technique and, where one exists, its Atomic
  Red Team test. Alerts use the real rule ids, levels, groups and MITRE
  mappings of the Wazuh v4.14.8 ruleset. A seeded generator
  (`python -m tests.fixtures.attack_corpus`) rebuilds the file byte for byte.
- CI replays the corpus through the real pipeline from committed cassettes
  (fake model, no network) and gates it with
  `tests/fixtures/eval/corpus_v1_thresholds.yaml`: no malicious alert closed
  by automation in any log source. The Wazuh live tests load it into a 4.14
  indexer and read it back through the real Wazuh connector.
- `lg-sotf eval --dataset` reads gzip-compressed datasets (`.jsonl.gz`), and
  cassette replays read gzip-compressed cassettes (`<item>.jsonl.gz`).

- An adversarial evaluation corpus, `tests/fixtures/eval/adversarial_v2.jsonl`:
  91 synthetic alerts that try to steer the model through log fields
  (persona and instruction hijacks in user names, command lines, URLs,
  user-agents, email subjects and bodies), through threat-intelligence and
  history answers, by asking for a response or a close, and with encoding
  tricks (Base64, look-alike letters, zero-width and other invisible
  characters, instructions split across fields), plus benign look-alikes
  such as the security team's own test strings. Its gate runs in CI with
  the fake model: no malicious alert of the adversarial split may be closed
  by automation and no benign one may be routed to a response.
- Evaluation items can now carry a `family`, an `injection` spec (what the
  injected text asks for) and `tool_fixtures` (canned threat-intelligence
  and history answers, used only by `lg-sotf eval`). Reports add a
  per-family table with each rate's sample size and 95% interval, and three
  rates: `malicious_auto_close_rate`, `benign_escalation_rate` (false
  escalations) and `injection_followed_rate` (how often the model did what
  injected text asked). Thresholds can check `families.<name>.<metric>`.
  Reports of datasets without families are unchanged apart from the three
  new rates.

- `docs/ai-system-card.md`, the AI system card for compliance and security
  reviewers: intended and out-of-scope uses, the model profiles and where
  each one runs, every kind of model call and the read-only tools, what the
  AI decides and what people decide (routing, autonomy, approvals, the kill
  switches), the safety invariants, the evaluation evidence with its
  intervals and known gaps, logging and traceability, data handling and
  retention, and the human oversight design. It maps the system to the EU AI
  Act (risk-classification reasoning with its caveats, Articles 4, 12 to 15,
  26 and 50) and to NIS2 Art. 21(2) and Implementing Regulation 2024/2690.
  It is not legal advice.
- `python scripts/export_invariants.py` now also writes the invariants table
  of the system card, and CI fails when the card is stale, misses an offered
  model profile or a model call, or presents DeepSeek as supported.

- Tenant setting `triage.known_scanners`: host names, IP addresses or CIDR
  ranges of your own vulnerability scanners. An alert whose host or IP
  entities include one gets the `known_scanner` false-positive signal.
- Triage recognises the EICAR anti-virus test file by hash: an alert whose
  only file hashes are EICAR's gets the `eicar_test_file` false-positive
  signal.

- Release trains. Every Thursday, the head of `main` becomes a partner
  release candidate `vX.Y.Z-rc.N`, and the `:partner` image tags move to it.
  From Actions > *Release train*, a candidate is promoted to the stable
  `vX.Y.Z` and, if chosen, to the LTS channel (git tag `lts-X.Y`, image tags
  `:lts` and `:lts-X.Y`). A commit is tagged only when its CI passed,
  including the N-1 upgrade rehearsal and the install rehearsal, and when
  its images pass the same signature and provenance checks as a deploy.
  Channel tags only ever move to verified digests. Releases with a Security
  changelog entry say so in their GitHub release title. See
  docs/releases.md for the channels, cadence, support windows and backports,
  and for how to pin and verify a release.

- A CI gate, `eval-gate`: every pull request runs the synthetic and phishing
  evaluation sets with the offline fake model and compares the result with a
  committed baseline (`tests/fixtures/eval/baselines/`). One more missed
  attack, or one fewer benign alert closed, than the baseline fails the
  build, and the log names every item that ended differently. The job calls
  no model and reads no secret. `make eval-gate` runs it locally;
  `make eval-baselines` records the baselines again after an intended change.
- A nightly evaluation with a real model: both sets run through one pinned
  model and the scorecard is kept as a workflow artifact for 90 days. The
  model is set with repository variables and one secret
  (`EVAL_LLM_PROVIDER`, `EVAL_LLM_BASE_URL`, `EVAL_LLM_FAST_MODEL`,
  `EVAL_LLM_DEEP_MODEL`, `EVAL_LLM_API_KEY`); the job is skipped until they
  are set. Only a model hosted in the EU or run locally is accepted, and
  only with exact model names. See "Evaluation gate in CI" in
  docs/evaluation.md.

- API stability tiers. Every operation in the OpenAPI document now carries
  `x-stability`: `stable` (ingest, alerts, escalation review, actions,
  sources, suppressions, users, API keys, audit, auth and the health probes),
  `beta` (platform administration, tenant settings, reports, integrations,
  compliance exports, triage groups and bulk actions, MFA, usage, metrics) or
  `internal` (the dashboard summary and onboarding screens). A stable
  operation is deprecated for at least 6 months, and over two minor releases,
  before it is removed or changed incompatibly. See "Stability and
  deprecation" in docs/api.md.
- A deprecated route answers with `Deprecation` (RFC 9745), `Sunset`
  (RFC 8594) and `Link: <...>; rel="deprecation"` headers on every response,
  errors included, and is marked `deprecated: true` with an `x-sunset` date
  in the OpenAPI document. Browsers can read the three headers (CORS). No
  route is deprecated yet.
- A CI gate, `api-compat`: a pinned, checksum-verified oasdiff compares
  `docs/openapi.json` with the base branch's and fails on a breaking change
  to a stable operation, including a removal before its sunset or a move from
  stable to beta. Changes to beta and internal operations are reported only.

- MSSP organisation model, part 1 (schema): a tenant can be an MSSP
  *organisation* with named staff members, and a customer tenant can give an
  organisation (or one of its members) a role in it, with a reason and an
  expiry of at most a year. Grants belong to the customer: only the customer
  can create or revoke them, the organisation can only read its own, and no
  other tenant sees them (row-level security). Tenant exports include them
  (`tenant_grants.jsonl`, `organisations.jsonl`,
  `organisation_members.jsonl`).
- MSSP organisation model, part 2 (reading under grants): a member of an
  organisation acts in a customer tenant by sending `X-Tenant-ID` with their
  own sign-in, when the customer granted the organisation access. Every read
  route serves the customer's data under the grant's role (capped at the
  member's own role) and answers 403 without a live grant; revoking a grant
  takes effect on the next request, and each request is recorded in the
  customer's audit log (`grant.tenant_access`). New endpoints:
  `PUT /platform/organisations/{tenant_id}`, `/organisation/members`,
  `GET /organisation/grants`, and `GET`/`POST /tenant/grants` with
  `POST /tenant/grants/{id}/revoke` for the customer's admins. Giving and
  revoking a grant is audited in both the customer's and the organisation's
  chain. `GET /auth/me` returns `grant_id`. See docs/mssp.md.
- MSSP organisation model, part 3 (writing and deciding under grants): an
  MSSP analyst acting under a grant can now decide escalations (one at a
  time or with bulk close) and approve, reject, roll back, retry and verify
  actions, within the grant's role. Every audit entry written under a grant
  is recorded in both chains: the customer's, naming the organisation and
  grant, and the organisation's as `delegated.<action>` with the customer
  entry's id and hash. Claiming an escalation and creating or changing
  users, MFA, API keys and grants stay refused under a grant. A platform
  admin's tenant switch still cannot claim or decide.
- MSSP organisation model, part 4 (live updates, automation and MCP under
  grants): `/ws?tenant=<customer>` streams a granted customer's events and
  closes when the grant is revoked or expires; an organisation's API key
  acts under a grant to the whole organisation with its scopes capped by the
  grant's role (never `ingest`); `LG_SOTF_MCP__TENANT_ID` pins the MCP server
  to one customer tenant. A generated cross-tenant leak suite covers every
  API operation, MCP tool and the WebSocket channel.

- A per-tenant autonomy tier for closing alerts on the models' word,
  `ai_closure.tier` in the tenant settings: `off` (the default) or
  `auto_full_audit`. At `auto_full_audit`, an info, low or medium alert
  closes as benign when both model tiers call it benign: the fast tier with
  a threat likelihood of at most 8 and the deep tier with a certainty of at
  least 85 (install settings `routing.model_close_max_likelihood` and
  `routing.model_close_min_certainty`). Such a close has the decision code
  `model_closed` and the close reason `ai_closed:audit_required`, so an
  analyst can find and audit every one. Only a tenant admin can change the
  tier, never under an MSSP grant, and the audit event records the tier set.

- Retro-reopen, the safety net that replaces the forward gates. When an
  alert becomes a threat (a response plan or a malicious close, an
  escalation whose model verdict is malicious or suspicious, an analyst
  `true_positive`, a blind-audit `malicious` label), every alert the models
  closed alone in the previous 24 hours that shares a host, user or IP with
  it is reopened. When the threat has an open escalation, the alert is
  folded into it: attached as a related alert and set to `waiting_human`
  under that one case (no new run, no new escalation), and the analyst's
  decision on the case settles it. Without an open case it is queued for its
  own review run instead. Either way it is audited `alert.reopened` (reason
  `related_threat`) and its summary records it under `reopened`.
  Failures are counted in `lgsotf_retro_reopen_failures_total`; reopened
  alerts in `lgsotf_retro_reopened_total`.

- `docs/microsoft-skus.md`, the Microsoft SKU coverage matrix: every
  Microsoft Graph, Defender for Endpoint and Log Analytics API LG-SOTF calls,
  with the licence it needs on Microsoft 365 Business Premium, E3 and E5 (and
  the add-on that unlocks it), the application permission it is granted, the
  Microsoft Learn page that states the requirement, and a lab-evidence column
  (pending until the Microsoft lab tenant exists). It also rates the planned
  evidence APIs (sign-in logs, risk detections, Defender alerts and
  incidents, advanced hunting) and lists the open questions the lab tenant
  must settle. A deploy test fails when the code calls a Microsoft API path
  the matrix does not list, or the matrix lists one the code no longer calls.

- The evidence-fact schema v1, a published contract for the typed
  observations investigation tools return (IP, domain, URL and file
  reputation, process lineage, sign-in history, related alerts), which
  verdicts will cite by id. It is a JSON Schema 2020-12 file with a SemVer
  version, `schemas/evidence-fact/v1.json`, with an example per kind, and CI
  refuses a change that is not matched by the right version bump. See
  docs/evidence-facts.md.

- Evidence-fact schema 1.1.0, a backward-compatible minor version of
  `schemas/evidence-fact/v1.json`: every 1.0 fact is still valid. It adds
  the facts the Wazuh evidence tools will return (`host_activity`: what a
  host did around an alert; `logon_fanout`: how many accounts, sources and
  hosts a logon pattern touched; `prevalence`: how widely a file, an image, a
  service or a command is seen), the processes a process started
  (`children` on `process_lineage`), and `complete`, which is false when the
  source cut a result or its time window had not closed, so that "nothing
  was found" is never read from a partial answer. Every list holds at most
  50 items and every text field has a maximum length. Published now; the tools
  that produce these facts come in a later release. See
  docs/evidence-facts.md.

- Blind audit of auto-closed alerts: a uniform random sample of the alerts
  automation closed goes to analysts with the AI verdict hidden, so the
  production false-negative rate can be measured without bias. Analysts
  label each sample malicious, benign or unsure on the new Blind audit page
  (keys M, B, U and N); only then is the AI's verdict, confidence, routing
  and reasoning shown, with the agreement. A malicious label opens a normal
  escalation for the alert; deciding it re-triages the alert with the
  analyst's decision.
- From the moment an alert is sampled until it is labelled, its verdict is
  withheld from everyone in the tenant: the alert routes and MCP (alerts
  carry `hidden_for_blind_audit`), its timeline (ingestion and notes only),
  its escalations, response actions and audit details, its evidence pack
  and live updates; it cannot be reprocessed, and it is left out of the
  value, detection and dashboard figures and of other alerts' correlation.
  Blindness starts at sampling: earlier views and exports showed the verdict
  like any alert's.
- Samples are drawn every week when the tenant setting `blind_audit` is on
  (2% of auto-closed alerts, at least 5 a week by default; off until
  enabled), on demand with `lg-sotf audit-sample --tenant T` (also the
  proof-of-value random sample, for example `--size 200`), or from the
  Blind audit page. Runs follow each other without gaps, end 5 minutes
  before now, and use a seed the server picks and records; a dry run
  (`--dry-run`) re-draws a run with a given seed and records nothing.
- Reports > Blind audit and `GET /api/v1/reports/blind-audit` show the
  false-negative rate among auto-closed alerts, stratified over the
  sampling runs, with its 95% interval and sample size, the estimated
  number of missed threats, a worst case counting unsure and unlabelled
  samples as malicious, an "incomplete" mark until every sample is
  labelled, uncovered time, labels by organisation for MSSP grants, and
  "Not enough data (n=…)" below 30 labels. New beta endpoints under
  `/api/v1/blind-audit`.

- Proof-of-value runs, started without the command line. An admin opens
  **Proof of value** > *New proof of value* (a three-step wizard: the days of
  history to replay, the days of shadow period, review and start) or calls
  `POST /api/v1/pov/runs` (beta). The scheduler then runs the backtest over
  the alerts analysts decided in the history window and stores its result on
  the run (alerts replayed, confirmed threats, how many the triage would have
  closed, with sample sizes and intervals); the shadow period that follows
  links the tenant's reports over its dates. `GET /api/v1/pov/runs` and
  `GET /api/v1/pov/runs/{id}` show the status; `POST
  /api/v1/pov/runs/{id}/cancel` ends a run early. A run only reads: it
  changes no alert, creates no escalation, response action or notification,
  and its backtest runs in read-only transactions. One run in progress per
  tenant, at most 3 created in 24 hours, 500 alerts per backtest. The
  first-run setup now ends on the wizard, and the Reports page opens on the
  dates of a `?from=&to=` link. Migration `0019` adds the `pov_runs` table
  (tenant row-level security, in the tenant data export and erasure; the API
  role cannot write a run's backtest status or result). See docs/pov.md.

- Guided Wazuh setup: Sources > Connect Wazuh step by step checks a Wazuh
  connection before the source is saved and says what to change. For the
  indexer it checks, in order, the settings, that the install may reach the
  host and the indexer answers, the TLS certificate, the sign-in, the
  permission on the alerts index, the index itself and the clocks. A failed
  check names what is missing, for example the index pattern and the
  permission `indices:data/read/search`, the CA certificate, or the host to
  add to the PoV allow-list. For alerts pushed by the Wazuh manager it checks
  the push source and that the API key has the `ingest` scope. API:
  `POST /onboarding/connectors/wazuh/check` (the tenant's own admins, 20 runs
  per tenant per minute), audited as `source.setup_checked`. See
  docs/onboarding.md.

- The console has the shell of the console v2 design (PRD-2.12): the frame
  every page lives in.
  - **The rail.** Pages are in five groups: Work, Detect and respond, Assure,
    Configure and Platform. The Queue is where work waits: the older
    Escalations list left the rail (its address `/escalations` still works,
    and the decision page leads back to the queue unless you came from that
    list). Three entries have the design's names and open the same pages as
    before: "AI usage and cost" (LLM usage), "People and keys" (Users and
    API keys) and "Tenants" (MSSP console). Counts are plain numbers next to a page's name,
    the signed-in person is at the bottom (account security, row density and
    sign out are in their menu), and on a narrow screen the rail opens from
    the menu button.
  - **The tenant is part of the address.** A platform admin chooses the
    tenant to work in with the control at the left of the top bar, and the
    address becomes `/s/<tenant>/...`. A reload, a new tab and a shared link
    now open the same tenant; before, they fell back to the home tenant
    without saying so. Someone who has one tenant and opens another
    tenant's address is told so and shown nothing under it.
  - **Search and commands.** One field in the top bar, also opened with
    Ctrl+K (Cmd+K) or `/`, finds pages, alerts by title, and (for a platform
    admin) tenants. Each alert says which tenant it is in. `>` lists
    commands. A command that changes something never runs from the field:
    it opens the page where the act is confirmed. The `/` key can be
    switched off with the command "Single-key shortcuts": the same switch,
    kept per user, as on the investigation view.
  - **Notifications.** The bell lists only what needs an act now:
    escalations past their deadline, a deadline in the next 15 minutes,
    actions waiting for your approval and, for admins, a source the API
    reports as failing or degraded. Each line names the tenant and opens the
    page where the act happens.
  - **Brand.** The console's name, logo and one accent colour come from one
    `brand` object in the runtime configuration (`/config.js`). The accent
    is checked for contrast before it is used; one that fails is refused
    with the failing pair named, and the product's colours stay. Without a
    brand the console shows the product's own.
  - **A service that is not licensed.** A service module can declare a group
    of its own in the rail. Where the licence does not include it, a
    platform admin sees the group locked and labelled "Not licensed", with a
    page that says so; a customer tenant's users do not see it. No second
    service is shipped yet.

- Investigation view: every alert now opens on a full page
  (`/alerts/<id>`, "Open full page" in the alert's side panel) that explains
  the AI's decision in the same order for every alert. First the outcome in
  one of four categories tied to what happens next (closed by AI; closed by
  AI, sampled for audit; needs your decision: likely malicious; needs your
  decision: unsure), the verdict as a sentence, and why the alert is with a
  person or why it was closed. Then the alert's description and its
  entities; the claims of the analysis, each beside what the lookup it names
  returned, with the provider's verdict highlighted; what is not established,
  in three kinds (checked and found nothing, not checked, could not check
  for this customer); the steps of the investigation in plain words; and the
  proposed response with the exact target of every action.
- The page keeps three voices apart: what a tool returned (monospace on a
  recessed surface, with its outcome), what the model wrote, and what a
  check, the policy or a person decided. A claim that names no lookup, or
  only a lookup that returned nothing, is marked **Unsupported**: nothing
  found is never counted as proof.
- A decision bar stays at the bottom of the page: `T`, `B` or `F` chooses the
  verdict, the bar says what that verdict sets in motion (which ticked
  actions run, how many wait for approval) before anything is recorded, and
  `Ctrl+Enter` records it and opens the next escalation. The rules are those
  of the decision page: a claim first, a note for a true positive, and your
  verdict and note are kept when someone else changed the escalation.
  Single-key shortcuts act only outside text fields and can be switched off
  in the bar.
- **Hide the verdict** (`V`) withholds the verdict, the claims and the
  model's assessment so you can judge from the evidence first; an alert in a
  blind-audit sample always opens this way.

Not shown yet, and said so on the page instead of being filled in: the
track record of each outcome (how often analysts confirmed it), the hash of
each observation, how many hosts or users an action reaches, and the
"needs more information" verdict in the decision bar.

- Decision bar: **Needs more** (`N`) records `needs_more_info`. The bar says
  what that does today before you record it: no verdict is recorded, the
  analysis runs again and reads your note (once per alert by default), then
  the alert comes back to an analyst as a new escalation, and no response
  action runs. The bar asks for the note.
- Decision bar: switching single-key shortcuts off (or on) is now kept for
  you on this browser, with your other display preferences, instead of
  lasting for the tab.
- Investigation view: an entity chip (host, user, address, domain, hash)
  opens the alert list searched for that value. The search is the list's
  title search over the last 30 days; the API has no entity filter yet.

- Break-glass access for platform operators: `POST /api/v1/auth/break-glass`
  opens a platform-admin API session from a sealed credential when nobody
  can sign in the normal way. It is off by default. An operator turns it on
  by setting `LG_SOTF_AUTH__BREAK_GLASS_CREDENTIAL_HASH` (the hash printed
  by the new `lg-sotf break-glass-credential` command); it also needs SMTP
  (`integrations.smtp_host`, `smtp_from`) and `integrations.enabled`, so the
  alert can be mailed. While off, the route is not mounted.
- `docs/runbooks/break-glass.md`: when to use break-glass, the procedure,
  what to do when the alert is unexpected, how to rotate the credential
  after use, and a drill checklist with what to record.

- `lg-sotf verify-invariants` checks this install's safety invariants,
  read-only, in a synthetic dry-run tenant: forced row-level security on
  every tenant table, a runtime role that cannot bypass it, an append-only
  audit log, the response kill switch, the routing policy for high-severity
  alerts, log redaction and evidence-pack sealing. It exits 1 when a check
  fails; `--json` prints the results as JSON.
- `docs/invariants.md` lists the twelve safety invariants, each with its
  rationale, owner, threat-model rows and the tests that prove it. CI fails
  when a named test is missing or an enforced invariant's test is skipped.

- Tool registry (`lg_sotf.tools.registry`, AI-E2.1): every lookup the
  analysis agent makes is now a declared tool called through one registry.
  A tool does not load without a read-only risk class (there is no write
  class), a strict and bounded parameter model, row, time and window caps and
  a declared egress. Every call validates its parameters first, enforces the
  caps, holds the tool to the egress it declared and is recorded in the
  trace.
  - The VirusTotal and AbuseIPDB lookups (`reputation.<provider>`) and the
    alert-history lookup (`platform.history`) run through it. Recorded
    cassettes replay unchanged.
  - Every tool result carries a typed outcome: `success`, `empty` (the query
    ran and matched nothing) or `failed` (refused, timed out, raised, over
    the row cap, or no answer from the source). A failed call can no longer
    be mistaken for "no rows". `complete` is false when a result holds as
    many rows as its cap.
  - The investigation trace stores the same outcome for the step. Migration
    0018 adds `empty` and `failed` to `investigation_steps.outcome`. A
    history lookup that finds no earlier alert is now stored as `empty`, not
    `success`.
  - Every tool result carries the SHA-256 of its input and of its output:
    the hashes of its stored trace step. The output hash no longer changes
    when the same answer comes from the cache.
  - New pending invariants, numbered as ADR-0014 numbers them: INV-14,
    "Evidence tools are read-only, templated and capped", which the Wazuh
    query templates (INT3.4) complete; and INV-13, "Autonomy is earned per
    skill and tenant and lost on any miss", registered as a placeholder that
    AI-E3.10 delivers.

- `lg-sotf eval --oracle propose|accept`: a measurement mode in which two
  simulated analysts, taking turns, decide every escalation at once from the dataset's
  labels (`false_positive` for benign, `true_positive` for malicious;
  response actions are rejected), through the same decision path as the API,
  with items in event-time order. It shows how much the verdict cache, the
  tenant's entity history and suppression rules could close with perfect,
  instant analysts. `accept` also enables the suppression rules the
  decisions suggest. Each item's status still records what automation did
  before the oracle acted.
- Every evaluation report and scorecard now leads with two numbers: the
  benign closure rate (with n and a 95% interval) and malicious auto-close
  (with n and an exact one-sided 95% upper bound). A table attributes each
  automatic close to rules, the model, history, the verdict cache, a
  suppression rule or a completed response, and every malicious alert closed
  by any of them is listed by id.
- Datasets can declare the tenant's context (`_meta.tenant_context`): IT
  admin accounts and groups, helpdesk accounts, automation accounts and
  hosts, jump hosts, patch windows and the authorised scanner. The
  attack-emulation corpus declares its estate's. Nothing applies it yet;
  reports show how many benign alerts it covers ("closable with context")
  and how many attacks it covers too.
- A loader for the public AIT Alert Data Set (2.29 million Wazuh alerts, CC
  BY 4.0): `python -m tests.fixtures.aitads fetch DIR` and `build DIR --out
  FILE` sample `aitads_v1` (5,000 alerts per scenario, stratified by attack
  phase, seeded). Labels come from the dataset's attack-phase times; see
  `docs/evaluation.md#ait-ads` for what they can and cannot say.

- The web app has a **Queue** page (`/queue`, beside Escalations in the
  menu): one dense list of what needs a person, soonest deadline first, built
  from the console v2 design (`docs/design/console-v2/`).
  - **More on one screen:** 22 rows at 1440 by 900 in the default density
    (25 in Dense), against 6 to 7 on the Escalations page. Three row
    densities (Dense, Compact, Two lines), remembered per user.
  - **Each row** shows the deadline (overdue and under ten minutes are marked
    in words), the severity as bars and a word, what the item is and why it
    needs a person, and what the analysis made of it so far.
  - **Views** are tabs with counts: Needs a person, Mine, Unassigned,
    Deadline under 15 min, Likely malicious. "Save view" keeps the current
    view, filters and density under a name, per user in the browser.
  - **Preview:** the highlighted row opens beside the list, which stays in
    view.
  - **Keyboard:** `J` and `K` move, `Enter` opens the item, `Space` shows or
    hides the preview, `X` selects, `C` claims.
  - **Bulk:** selected rows can be claimed together. Deciding several at once
    is offered only for look-alike alerts, which the API does not group yet,
    so the Look-alikes view stays hidden until it does.
  - The queue shows the tenant you are acting on. The Escalations page is
    unchanged.

- `GET /api/v1/alerts/{id}/investigation` (beta): one read model that
  explains the AI's decision on an alert, for the console's new
  investigation view. It only reads stored data: it calls no model and
  writes nothing.
  - **Outcome:** one of four categories tied to what happens next (closed
    by the AI on evidence; closed on the model's word and sampled for
    audit; needs your decision, likely malicious; needs review, not proven
    either way), the reason in plain words, why the AI may not close the
    alert on its own, and who or what closed it (the AI, a suppression
    rule, a cached analyst verdict or an analyst).
  - **Summary, claims and observations:** the conclusion, marked as written
    by the model or by the rules; each claim with what it points to and
    the lookups it rests on; each lookup with a typed outcome (`success`,
    `empty`, `failed`), a bounded excerpt and, where the trace store has
    the call, its input and output hashes.
  - **What is not established:** checked and found nothing; not checked;
    could not be checked for this customer. An empty or failed lookup never
    backs a claim.
  - **Steps, track record and response:** what the investigation did in
    plain words; how often people confirmed this outcome category for the
    tenant over 90 days, as counts, with a rate only from 30 verdicts on;
    and the proposed actions with their exact targets.
  - `pending_harness` names the fields that stay empty until the
    investigation harness fills them (highlight ranges, the model's
    citations, the checker's verdicts), so the view can say so.
  - Text an attacker can shape (claim texts, targets, excerpt lines) is
    returned as data, cut to a stated length, and never put into a
    sentence. An alert that waits for its blind-audit label shows nothing
    of the AI's side.

- Scorecard v2 (`docs/scorecards/v2/deepseek-v4/`): DeepSeek V4, whose
  weights are released under MIT (`deepseek-flash` fast tier,
  `deepseek-v4-pro` deep tier), on the 520-alert attack-emulation corpus.
  It was measured through DeepSeek's hosted API on synthetic alerts only; a
  client self-hosts the same weights, and customer data never goes to the
  hosted API.
  - **Misses:** 0 of 208 malicious alerts closed without a human (95% CI 0.0%
    to 1.8%), in every log source and campaign.
  - **Closes:** 0 of 312 benign alerts closed by automation. 33 benign
    alerts were given a response plan, and none of their actions ran.
  - **Cost:** $1.47 for the run.
  - **RUN.md** traces which routing gate held each benign alert and lists the
    changes to test next.

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
- The OpenAPI document (`/api/v1/openapi.json`, `docs/openapi.json`) now
  lists the allowed values of every response field drawn from a vocabulary,
  such as alert `status` and `severity`, escalation `level`, action
  `status`, `risk_level` and `action_type`, user `role` and API key
  `scopes`, as an `enum`. Responses are unchanged, and clients must still
  accept values they do not know: a newer release can add one (ADR-0009).
  The evidence pack, `GET /readyz`, `GET /tenant/response/routes` and
  `GET /integrations/microsoft/catalog` now publish the shape of their JSON
  body, and the tenant export is documented as a ZIP only.
- An action whose stored `verification` state the API process does not
  know is now returned as is, instead of failing the request with a 500.
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

- The pipeline metrics (`lgsotf_node_seconds`, `lgsotf_llm_calls_total`,
  `lgsotf_llm_tokens_total`, `lgsotf_llm_cost_usd_total`,
  `lgsotf_llm_refusals_total`, `lgsotf_llm_skipped_total`,
  `lgsotf_enrichment_lookups_total`, `lgsotf_llm_slot_wait_seconds`) have a new `mode` label (`live` or
  `shadow`). Add `mode="live"` to your alerts and dashboards; the examples in
  `docs/operations.md` do.

- The attack-emulation corpus declares its authorised vulnerability scanner,
  as a tenant would (`_meta.tenant_settings`, `triage.known_scanners`).
- Evaluation reports record, per item, what the routing decision read
  (`decision_inputs`: the confidence, the triage, correlation and analysis
  scores and the verdict).

- The adversarial corpus v2 gates the `title-camouflage` family: its three
  items moved from the reported-only `known-gap` split to the `adversarial`
  split, and the corpus lists its own scanner.

- The adversarial corpus v2 has a seventh gated family, `activity-camouflage`
  (6 malicious items): attacks whose detection rule name holds a word for
  the detected activity, such as `scheduled-task-update` or
  `scheduled-backup-deleted`.

- CI now also rehearses the upgrade from the latest LTS release, when that
  is not the previous release: `scripts/ci/upgrade_rehearsal.sh --from lts`.
  The upgrade rehearsal's previous release is the latest `v*` tag, which can
  now be a release candidate.
- *Release images* and *Deploy* accept release-candidate tags
  (`vX.Y.Z-rc.N`). Their GitHub releases are created as pre-releases.

- The web console is now built from service modules (ARCH-E10.1,
  [ADR 0015](docs/adr/0015-frontend-module-model.md)). It is still one build
  and one image, and it works as before; the change is in how it is put
  together, so that a second service can be added without editing the first.
  - Each service is a folder under `src/lg_front/src/modules/` with a typed
    manifest (pages and their access rules, navigation, counts, live events,
    extension contributions). The security operations pages are the first
    module. Adding a service is its folder and one line in
    `src/app/modules.ts`; a test registers an example module that way and
    checks that the route, the sidebar, the access guard, live updates and a
    cross-link all follow.
  - Each module has its own API slice, and its cached data is kept under its
    own name, so one service cannot refresh or clear another's by accident.
  - Services link to each other through named extension points. The tenant
    switcher and the "acting on another tenant" banner use them, and are now
    loaded only for platform admins, which makes the first page load a little
    smaller for everyone else.
  - A lint rule keeps a module from reaching into another module's files and
    keeps the shell from naming a service.
  - Tabs, timelines and entity lists are one shared component each. What you
    may notice: the Reports and MSSP console tabs look like the Alerts view
    tabs and answer to Home and End; on the decision page the Entities tab
    says "IP addresses" where it said "Ips".

- The regression checks of `smoke_thresholds.yaml` and
  `phishing_smoke_thresholds.yaml` are exact for the benign auto-close rate
  (`max_decrease: 0`, was 0.05). They apply only when a run is compared with
  a baseline.

- Every info, low and medium alert now goes through analysis. Before, a
  strong correlation (or a low confidence) sent it straight to the decision
  on a correlation-raised confidence, which could plan a response or hold a
  benign alert in the grey zone without any analysis.
- Correlation is evidence, not a score boost: related alerts, bursts and
  alert rates go to the analysis model and into the alert summary, but they
  no longer raise the alert's confidence. A response plan therefore needs
  the analysis threat score (or trusted triage evidence), never correlation
  alone.
- The grey zone (30 to 70) is tested on the analysis threat score, not on
  the confidence from before the analysis. Escalations record that score
  next to the review band.
- A low-threat benign verdict now closes an alert with approved benign
  evidence, the false-positive signals triage takes only from what an
  attacker cannot write: the detection rule's name, the EICAR test file, a
  test-environment source, a scanner you listed in `triage.known_scanners`
  or an authenticated internal sender. The rules' threat score no longer
  has to be below 30, which no Wazuh alert could reach.

- Model-led closure (`ai_closure.tier = auto_full_audit`) can now close
  routine Wazuh noise that ships without an ATT&CK mapping. A reviewed,
  versioned catalogue of noise families, keyed by vendor and detection rule
  id, lifts the "no ATT&CK mapping" block for: package installs and updates
  (dpkg 2901, 2902; yum 2932, 2933), Windows software installs (60612),
  Defender scan and signature status (62107, 62108, 62130) and a single web
  4xx (31101). It lifts nothing else: the tier, severity, both model tiers
  benign at the install thresholds, steering text, a recent true positive
  and a campaign in progress still block. Such a close's decision reason
  names the family and the catalogue version.
- Alerts now record the format whose normalizer built them
  (`normalized.normalizer`: `wazuh`, `canonical`, `webhook`, `llm`, ...).
  Models never see it. Alerts stored before this release have none, so the
  catalogue does not apply to them.
- The campaign check is unchanged (FIX-1). A check that lets one detection
  rule repeat without blocking was deferred.

- Decision policy v3: at the autonomy tier `auto_full_audit`, every alert
  the deep analysis judges benign closes on the models' word, at any
  certainty and below the response policy's threat score, for info, low,
  medium and high severity, unless the fast tier called it a likely or
  confirmed threat. The likelihood and certainty thresholds
  (`routing.model_close_max_likelihood`, `routing.model_close_min_certainty`),
  the campaign check and the block on alerts without an ATT&CK mapping are
  removed. The tier stays per tenant and `off` by default.
- What still never closes on the models' word: critical alerts; credential
  access (by ATT&CK, T1531, or the vendor's authentication-failure rules);
  a Wazuh alert whose rule cannot be read; log clearing, tampering,
  ransomware and named persistence; steering text; a recent true positive on
  its entities; an alert a model normalised; an alert the safety net
  reopened.

- The theme follows the system setting until you choose one; before, dark
  was the default. The control in the top bar steps System, Light, Dark.
- The top bar no longer repeats the page's name; the browser tab names the
  page and the console.
- "Operate" and "Report" in the navigation are now "Work", "Detect and
  respond" and "Assure". No page moved to another address.

- Decision page: the expected response plan is shown under the
  investigation instead of inside the decision form, so "Record decision"
  stays in view. The form says how many actions are pre-approved.

- Investigation view (`/alerts/<id>`): the page now reads the investigation
  read model (`GET /alerts/{id}/investigation`) instead of rebuilding it in
  the browser, so it shows what the API knows:
  - the **track record** of the alert's outcome, as counted squares ("Analysts
    confirmed 31 of 34 alerts sent to a person as likely malicious"), a bar
    above 60 alerts, and the words "too few for a rate" under 30. Never a
    percentage;
  - **why the AI may not close the alert on its own** (the closure policy's
    blockers), and for an alert the AI closed on evidence, the approved
    benign signals the rules found;
  - who or what closed an alert, with the rule's name, the analyst's
    decision, the earlier alert a cached verdict came from, and the time;
  - claims in the model's own words, and claims the rules derive from a
    lookup, marked as the rules';
  - each observation with its sources, its verdict and, where the trace
    store has the call, its hash;
  - the response as it stands: what a true positive would propose now, or
    the actions on the ledger with their status.
  "Not yet available" is now said only for what the read model lists as
  pending, in its own words. The "Reach" column is gone until the API
  returns a reach.
- An API that does not serve the read model yet (it answers 404) still
  gets the page: it is built from the alert, its escalation, its timeline
  and the response preview, as before.

- The per-tenant tool switch fails closed. A third-party lookup runs only
  when `tools.<provider>` is absent from the tenant's settings or its
  `enabled` is absent or exactly `true`. A value such as `"false"` or `0`, a
  setting that is not a mapping, or settings that cannot be read keep the
  lookup off. Before, only `enabled: false` switched it off.
- An HTTP 404 from AbuseIPDB is now an error, not "unknown address" (AbuseIPDB
  answers 200 for an address it does not know). A VirusTotal answer without
  analysis statistics is now an error, not a verdict with zero detections.

- The safety net of AI closure no longer reopens AI-closed alerts on a
  model's word. When a model judges a related alert a threat (an escalation
  it judged a threat, a response the workflow only proposes or, in dry-run
  mode, only simulates), the AI-closed
  alerts sharing a host, user or address in the last 24 hours are **linked**
  to that threat's case: listed in the case as related alerts, marked
  `linked` and audited `alert.linked`. They stay closed, a benign decision
  on the case leaves them closed by AI and due for audit, and their evidence
  pack and NIS2 draft show no analyst decision. When the threat is
  confirmed, they are **reopened** as before, including the ones linked
  earlier, however long ago they closed. A confirmation is an analyst true
  positive, an analyst's own approval of a response action (console or
  Slack), a blind-audit malicious label, or a response action that really
  ran when the workflow carried it out alone under your autonomy policy:
  once the platform has acted on a threat, the related alerts do not stay
  closed. A dry run is a simulation and confirms nothing. On a realistic
  alert mix, 18 of 24 reopens came from a model's
  unconfirmed judgement, 13 of them from one benign alert (#369).
- New metric `lgsotf_retro_linked_total` (by `path`) counts the linked
  alerts; `lgsotf_retro_reopened_total` counts confirmed reopens only, with
  the new paths `approval` and `response`.

- Pull requests now add a changelog fragment in `changelog.d/` instead of
  editing `CHANGELOG.md`, so parallel pull requests no longer conflict.
  `python scripts/changelog.py fold` moves the fragments into the changelog at
  release time; `check` validates them.

- The whole console takes the look of the console v2 design
  (`docs/design/console-v2`), on every page at once:
  - **A flat sheet.** Content sits on the page and hairlines carry the
    structure; sections have a title over a rule and no box. The dark theme
    is graphite, not black. Corners are 3 px on controls and 2 px on tags.
  - **Denser lists.** A row is 28 px by default (it was 44 px) and 44 px with
    "Comfortable rows" (it was 56 px), so the alert list shows about half as
    many rows again on a screen. Buttons and fields are 28 px high, 24 px
    inside a table row, and still grow to 44 px on touch screens.
  - **Severity is four bars and the word**, critical and high in bold; it was
    a coloured square. A state is a mark whose shape says what kind it is
    (waiting, waiting for approval, running, done, failed) and the state in
    words; it was a grey pill with a coloured dot.
  - **Labels read as sentences.** A status such as `waiting_human` reads
    "Waiting human", not "Waiting Human", and a label such as "Needs your
    input" keeps its own capitals. The words are written by the app, not
    title-cased by the stylesheet, so a screen reader and a copy get the same
    text as the screen.
  - **Column headings and section labels** are small monospace capitals; what
    a tool returned (JSON, an observation) is monospace on a recessed surface
    with a double rule on its left.
  - Segmented choices and pressed toggles are inverted (dark on light, light
    on dark); the selected tab is underlined in the text colour; notices sit
    on a tint; toasts appear at the bottom centre.
- **The theme follows your system setting by default.** It was dark by
  default. Your own choice (System, Light or Dark, in the header) is
  remembered as before, so nothing changes for anyone who already chose one.
- The accent, link, focus and selection colours are now read from one brand
  block of the design tokens; their default values are unchanged.
- For developers of the web app: `src/lg_front/src/theme/tokens.css` now holds the type scale, the radii,
  the control heights and the row densities next to the colours, and
  `npm run lint` refuses a raw hex colour or an arbitrary size utility
  (`h-[34px]`, `text-[13.5px]`, `rounded-[3px]`) in the web app. Two files of
  the layout shell are exempt from the size rule until the new shell
  replaces them.

- The Overview follows the console v2 design: flat, with rules instead of
  cards, and in a new order.
  - **Needs you now** comes first, one line and one action each: what you
    hold and its first deadline, the response actions your role may approve,
    what nobody has claimed, and the sampled AI closes waiting for a
    blind-audit label. An item opens its investigation view.
  - **Closed without a person** says in one sentence how many of the
    window's finished alerts no person touched and how many reached one,
    with a bar and the table it is drawn from.
  - **How the AI's closes are verified** shows the blind audit of the last
    30 days: closes eligible, sampled, labelled, and labelled malicious by
    an analyst who could not see the AI's verdict, with the missed-threat
    rate and its 95% interval once the sample carries one.
  - Then the next deadlines and, for admins, platform health.
- Every figure still says what it counts and over which window, and a share,
  a rate or a mean over too few observations is withheld in words. A figure
  the API does not report yet (who or what closed each alert, planted
  attacks, the safety net) reads "not measured yet" and shows no number.
- The severity strips and the six window tiles are gone from the Overview;
  alerts by status moved into platform health. Switching the window keeps
  the page on screen while the new figures load.
- On a phone the Overview's tables become stacked records, so nothing
  scrolls sideways.

- `lg-sotf eval-scorecard` marks a DeepSeek scorecard internal-only only
  when one of its datasets is not synthetic. A run on synthetic data only is
  publishable. Real alerts must still never go to DeepSeek's hosted API.

### Deprecated

- `observability.otlp_endpoint` (`LG_SOTF_OBSERVABILITY__OTLP_ENDPOINT`) is
  ignored. It is still accepted, so existing configurations load, and every
  process logs `observability.otlp_endpoint_deprecated` at startup while it
  is set. Remove it; a later release drops the setting.

### Removed

- OpenTelemetry tracing. The exporter it configured never sent anything: no
  code created spans. The OpenTelemetry SDK and OTLP exporter (and their
  protobuf dependencies) are no longer installed; `opentelemetry-api` stays,
  as a dependency of FastAPI and the Anthropic client. `configs/*.yaml`, the
  production compose file, `.env.example` and the Helm example no longer
  mention an OTLP endpoint. Logs and Prometheus metrics are unchanged.
  `docs/adr/0008-remove-tracing.md` records the decision and how tracing
  would be added back.

- The `--i-understand-no-shadow-role` option of `lg-sotf shadow-run`: the
  command now always needs the shadow database role, in every environment.

### Fixed

- On a phone, the language-model test results under Tenant settings scroll
  sideways and can now be reached with the keyboard too.
- Backtests (`lg-sotf eval --from-history`) start each replay from the same
  initial state as the workflow. A tenant `llm_daily_token_budget` stored as
  `true` or `false` is now ignored by the backtest too (the install default
  applies), as the workflow already did; the backtest used to carry the bool
  into the replayed state.
- The account menu button in the web app now includes the initials it
  shows in its accessible name ("Account: <email>, <role>, initials MR"),
  so speech-input users can activate it by saying what they see (WCAG
  2.5.3 Label in Name).
- `lg-sotf mcp` now honours every form of `Retry-After` the LG-SOTF API (or a
  proxy in front of it) can send when it retries a read: fractional seconds
  (`1.5`) and HTTP dates, as well as whole seconds. Before, only whole seconds
  were understood and anything else fell back to the exponential backoff.
  The wait is still at most 10 seconds; a negative value means retry now.
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

- Shadow runs no longer slow down production triage. Their LLM calls now use
  slots of their own, one per model tier and worker process by default
  (`llm.fast.shadow_max_concurrency`, `llm.deep.shadow_max_concurrency`), so
  a live call never waits for a shadow call and can no longer time out
  behind one.

- A run no longer fails when an upgrade migrates the database while it is in
  flight. A migration that changes a table made the running workers'
  prepared statements on it stale, and the first transaction to use one
  failed with `InvalidCachedStatementError`; the message then waited for the
  visibility timeout (20 minutes by default) before another try. The worker's
  transactions on runs are now run again once, in a new transaction for the
  same tenant, and the run finishes normally. Each retry logs
  `db.stale_statement_retry` and counts in the new
  `lgsotf_db_stale_statement_retries_total` metric.

- The "LLM errors" and "Run failures" alerts in the operations guide now sum
  both sides of their ratio before dividing. The old expressions divided each
  error series by itself, so the ratio was 1 as soon as one call or run
  failed, and the alert paged on a single error. If you copied either
  expression into your Prometheus rules, replace it.

- Decision page: every action in the expected response plan of a true
  positive now names its exact target (the process, host, user or address,
  as the API gives it), next to its risk and whether it can be undone, as
  the Approvals page does. Before, the list showed only the action's
  description, so two actions of one type ("Terminate a process through
  EDR") could not be told apart and an analyst could pre-approve an action
  without seeing what it acts on.
- An action the plan sends without a target can no longer be pre-approved
  from the decision page: its checkbox is disabled, it says why, and it is
  left for the Approvals page.

- Claiming an escalation whose SLA has expired now works. Before, every
  click answered "Someone else changed this escalation first" and nothing
  changed. The escalation stays expired, so the missed SLA is kept in the
  queue and in reports, and you become its owner. The audit entry records
  the claim as late (`after_sla_expiry`). As with a claimed escalation,
  only an admin can take it over from its owner.
- A claim on an escalation that is already decided or closed now says so
  ("This escalation is already decided or closed") instead of reporting a
  change by someone else. The API answers `409 invalid_transition` for it,
  whatever the version sent; a stale version on an active escalation is
  still `409 conflict`.
- Repeating an action that fails the same way no longer stacks identical
  notifications: the newest replaces the one on screen.

- An evaluation no longer depends on the hour it runs. An email item used to
  be stamped with the time it was ingested, which became the alert's
  `occurred_at`, and triage adds rule confidence to alerts outside
  06:00-18:00 UTC. A run in the evening built different triage prompts than
  a run in the morning, so the committed `phishing_v1` cassettes stopped
  replaying after 18:00 UTC (#346). The evaluation runner now ingests each
  report at its own `Date` header, or at a fixed noon when it has none.
  Production still stamps a pushed report with the time it arrives.

- An alert retro-reopen requeues (a related response plan with no open case
  to fold it into) now gets its run message as soon as the reopen commits,
  so a worker reviews it at once instead of after the orphan sweep
  (2 x `worker.visibility_timeout_s`), which stays the backstop (#350).

- The safety net of AI closure no longer treats a merely *suspicious* alert
  as a threat. An escalation reopens the related AI-closed alerts only when
  a model judged it a threat (deep verdict malicious, or fast tier
  likely_threat or confirmed_threat), next to the unchanged paths: a
  response plan, an analyst true positive and a blind-audit malicious label.
  On a realistic alert mix this had reopened 23 of 40 AI closes without a
  single real attack behind them (#352).

### Security

- Published images are signed. Each `ghcr.io/gapilongo/lg-sotf` and
  `lg-sotf-frontend` digest now carries a keyless cosign signature and a SLSA
  build-provenance attestation, both from the `Release images` workflow on
  `main`. The deploy workflow verifies both before it deploys, and stops if
  either check fails. This means the workflow can no longer deploy images
  built before this change; roll back to those on the VM instead. To verify
  an image yourself, including on an air-gapped host, see `docs/security.md`
  (section 9) and `docs/air-gapped.md`.
- Failure logs never carry the exception message (ADR-0005). An unhandled
  API error (`api.unhandled_error`) is no longer logged with a traceback,
  which quoted the message of the exception and of every exception chained
  to it, and the source line of every frame. The record keeps `error_type`
  and now carries `error` (the same type name), `stack` (the innermost 15
  frames as `module:lineno in func`, one per line, without source text)
  and `cause_types`. The workflow, worker, scheduler, services, integrations, MCP,
  eval, ingestion, queue, LLM and other API failure logs, which already
  logged only the type, gain the same three fields; their event names and
  existing fields are unchanged. To find where a 500 came from, search
  `event=api.unhandled_error` and read `stack` instead of a `Traceback`.
- Error text that is stored or shown is now redacted before it is cut to
  length: a run's and a source's `last_error`, an outbox delivery's and a
  ticket sync's error, a ticketing receiver's error body, the ticket
  connector's `detail`, eval and backtest item errors, and the MCP server's
  messages for errors the LG-SOTF API returned. Before, run errors and
  receiver error bodies were cut first, so a token straddling the cut could
  slip past the redaction patterns; eval and backtest errors and ticket
  details were cut and never redacted; and the MCP client did not redact the
  API's error messages at all. Each limit now covers the whole text,
  including the error type name (300 characters for runs, sources, eval and
  MCP, 1,000 for deliveries and ticket syncs).
- OIDC sign-in now reads the identity provider's discovery and key (JWKS)
  documents up to their 256 KiB limit and stops there. Before, the API
  downloaded the whole response into memory and only then checked its size,
  so a broken or hostile identity provider could make it hold an arbitrarily
  large body. A document over the limit is refused as before, now without
  being downloaded.

- Cassettes are redacted with the trace digest's rules before they are
  written, so no credential reaches a cassette file.

- A shadow run cannot cause an effect outside the platform. Every egress
  path (HTTP clients, so Slack, webhooks, tickets and Microsoft; mail; the
  notification outbox; response connectors; WebSocket events; the work
  queue) refuses or records the call in shadow mode, and every database
  transaction it opens is read only, with no way to commit, notify or keep
  session state. Its Redis client sends reads only. An architecture test
  finds the egress call sites in the source and fails on any that is not
  covered.
- A shadow run never bills the tenant or spends its LLM token budget, never
  calls a threat-intelligence provider (it reads the lookup cache only, so
  its verdicts can see fewer threat-intelligence answers), and never moves
  production metrics.

- `lg-sotf shadow-run` reads only through the SELECT-only shadow database
  role (`database.shadow_url`, AI-E1.5c) and refuses to run without it. Reading
  a shadow report is audited as `platform.shadow_report_viewed` in the
  platform admin's home tenant.
- A candidate profile expands `${VAR}` only in `llm.api_key`, and only from a
  `CANDIDATE_` variable, so it cannot send a process secret to an endpoint
  of its choice. A candidate on another provider or `base_url` never gets
  production's LLM API key, by inheritance or by name.

- Shadow runs now read the database only as a dedicated SELECT-only role,
  `lgsotf_shadow`, from a connection pool of their own. A statement that
  slips past the shadow statement guard, for example a `COMMIT` hidden
  behind a comment marker inside a string literal, now fails at the database
  for lack of privilege instead of writing. The guard stays as a second line
  of defence.
- A shadow run of an alert a model judges a threat no longer tries to reopen
  the related alerts the models closed. The attempt changed nothing (the
  database refused it), but it was counted in
  `lgsotf_retro_reopen_failures_total` and logged as an error, which could
  page the operator. The shadow run now records that the reopen would have
  run, and reopens and enqueues nothing.

- `lg-sotf shadow-run` now refuses to start when `database.shadow_url` is
  set but unusable: a role that may write, or a login that fails. Before,
  it audited the replay, retried the login for every alert and printed a
  report with no agreement. A database or shadow-role failure during a
  replay now stops it.
- A role is also refused as the shadow role when it holds an `INSERT` or
  `UPDATE` grant on a single column, or is a member of any other role.
- A candidate profile can no longer set `llm.<tier>.shadow_max_concurrency`:
  the shadow slots are always production's.

- Triage no longer reads benign words ("test", "update", "maintenance",
  "scheduled" ...) from alert titles. Integrations build titles from the
  names of the objects involved, and an attacker who named a scheduled task
  "Windows Update Test" could get a malicious alert closed on the rules
  alone. False-positive evidence now comes only from the detection rule's
  name (with quoted values and every attacker-named value masked out), EICAR
  hashes, the tenant's known scanners and the source id. Alerts whose only
  benign evidence was in the title now reach the model and, when needed, an
  analyst.

- Rule-name words that name the activity a rule detects (`scheduled`,
  `update`, `backup`, `scan`, `monitoring`) are no longer false-positive
  evidence on their own: a new scheduled task is persistence and a disabled
  monitor is defence evasion. They count only with a trusted qualifier: a
  word of benign intent in the same rule name (`test`, `selftest`,
  `maintenance`, `health_check`), a test-like source id or, for `scan`, one
  of your `triage.known_scanners` among the alert's entities. Before this
  change, an info alert from a rule such as `scheduled-task-update` could
  close on the rules alone. Alerts whose only benign evidence was an
  activity word now reach the model and, when needed, an analyst; if your
  scanners raise `scan` alerts that used to close, list them in
  `triage.known_scanners`.

- MSSP grants, after an independent security review: nothing created or
  changed under a grant outlives it or acts as a customer user. Under a grant,
  integrations (all kinds), sources and tenant settings can no longer be
  created or changed, and a Slack app recorded as written under a grant never
  approves or rejects. Suppression rules written under a grant name it and
  expire with it. A grant row can only be revoked, once, and nothing the
  organisation does deletes it; an unknown organisation id is accepted like a
  known one; a tenant can give at most 10 grants a minute. An organisation's
  API key uses a grant only when the customer set `allow_api_keys` and while
  the member who created it is still a member. A delegated WebSocket closes
  when the organisation's own tenant is suspended. Reads under a grant are now
  recorded in the organisation's chain too (`delegated.grant.tenant_access`),
  and `GET /audit` under a grant hides the customer's grant register and
  other organisations' details. `GET /organisation/grants` and
  `/organisation/members` are for members (and the home tenant's admins).
- MSSP grants, second review round: revoking a grant ends the suppression
  rules written under it, and the suppression gate ignores rules of a grant
  that is no longer live. An organisation's API key stops when its creator's
  account is disabled and acts no further than the creator's own role.
  Under a grant, sources and suppression rules can no longer be deleted, and
  only rules created under a grant can be changed. `GET /organisation/grants`
  answers for organisations only and no longer shows the customer's reason.
  Audit entries cut for a caller under a grant carry `redacted: true`.

- Even at `auto_full_audit`, the models never close alone: a high or
  critical alert; credential access, log clearing, security-tool tampering
  or ransomware behaviour; persistence through an object the attacker
  creates and names (scheduled tasks, services, autostart entries, WMI
  subscriptions, accounts); an alert whose detection rule maps it to no
  ATT&CK tactic or technique; an alert with text written to steer a model;
  an alert whose entities have an analyst-confirmed malicious history, a
  related alert closed as malicious or rule evidence of a threat. A verdict
  the rules produced because a model was not consulted never counts. With
  the tier `off`, nothing closes on the models' word alone.
- Nor while a campaign may be in progress: a burst of related alerts, a
  related alert a model judged malicious or suspicious, or one still waiting
  for an analyst or an approval. These are counted over every related alert,
  not only the ten shown to the correlation model. A related alert the models
  closed alone is shown to later models as `ai_closed_unaudited`, never as
  `benign`, so one persuaded close cannot vouch for the next.
- Approved benign evidence no longer closes an alert past text written to
  steer a model, analyst-confirmed malicious history, rule evidence of a
  threat or a related alert closed as malicious. A declared scanner or a
  test source never closes credential access, log clearing, tampering,
  ransomware or named persistence.
- `triage.known_scanners` now counts only when the scanner is the source of
  the activity (a source address or host field of the event, such as
  `srcip` or the Windows logon source), never when it is the host or address
  the activity reached. An attack on your scanner is still an attack. If
  your scanner alerts carry the scanner only as an entity, they now go to
  the model and, when needed, an analyst.
- ATT&CK tactics are matched whatever their spelling, so Sentinel's
  `CredentialAccess` is a never-close class like Wazuh's `Credential Access`.

- Authentication failures never close on the models' word, whatever ATT&CK
  technique the vendor gave them: a Wazuh rule in the groups
  `authentication_failed`, `authentication_failures`, `invalid_login` or
  `login_denied`, the rules 6250 (Asterisk) and 44733 (FortiAuthenticator),
  and ATT&CK T1531, where Wazuh maps its Windows logon failures. Before,
  25 stock Wazuh rules of that kind (logon failures, a failed logon from a
  malicious IP, a possible replay attack) were closable.
- The catalogue reads only the rule id of the vendor's own event, and only
  on an alert the Wazuh normalizer built, never the title, description or
  rule-name text: a custom rule that copies a stock description, a forged
  rule-name prefix or a canonical push of a Wazuh document stays unmapped.
- The workflow state keeps the vendor rule (`raw.rule`: id, level,
  description, groups, ATT&CK) when an oversized raw event is dropped. A
  Wazuh alert whose rule cannot be read, or whose groups list had to be cut,
  never closes on the models' word.

- The guided checks never return, log or audit the entered password, user
  name or API key, and an unknown API key, a mistyped one and another
  tenant's key get the same answer. The indexer is reached through the
  install's destination policy, and a refused destination keeps its single
  generic message.

- Builds now verify every input. Every Python requirements file is
  hash-locked for all platforms and installed with `pip install
  --require-hashes` in the image build, CI and `make dev`; re-lock with
  `make lock`. Every base image is pinned by digest, including the
  Dockerfiles' `# syntax=` line and the PostgreSQL, Redis and Caddy defaults
  in the compose files. `PYTHON_BASE_IMAGE`, `NODE_IMAGE` and `NGINX_IMAGE`
  now default to the pinned images; set them only to use a mirror. The
  frontend runs on `nginx-unprivileged:1.30-alpine-slim`. The old
  `1.28-alpine` tag no longer receives updates and carried fixable critical
  CVEs.
- CI now scans both images with Trivy and fails on any critical or high CVE
  that has a fix. Reviewed exceptions live in `.trivyignore`, and each one
  expires within 90 days. `pip-audit` now also checks the build and CI tool
  locks. See `docs/security.md`, section 9.
- Every release now carries CycloneDX SBOMs as assets: the Python lock, the
  frontend's production npm packages, and both images for amd64 and arm64,
  made from the release digests. It also carries an OpenVEX document
  (`security/vex.json`) that lists the CVEs scanners report in the images
  but that do not affect LG-SOTF, with the reason for each. Every asset is
  validated against its schema (here and on every change in CI) and has a
  build-provenance attestation; `docs/security.md` (section 9) shows how to
  download and verify them and how to use the VEX document with Grype or
  Trivy. If the GitHub release does not exist when the tag is pushed, it is
  created with generated notes.

- A dependency policy, `docs/dependency-policy.md`. A new Python, npm,
  image or action dependency must pass an admission checklist: need,
  licence allowlist, maintenance, size and transitive dependencies,
  security history, and hash-locking with `make lock`. The pull request
  template now has a "New dependency" checkbox for it. Vulnerable
  dependencies are patched within these times: critical 7 days, high 14,
  medium 30, low the next minor release. Advisories are triaged within 2
  business days. Dependabot now runs every Monday for every ecosystem, so
  merged updates ship on Thursday's partner train. It labels its pull
  requests and groups minor and patch updates of Python and production npm
  packages. The dependency files and the Dependabot configuration need the
  code owner's review.

- Every break-glass sign-in is audited (`auth.break_glass_used`: account,
  source address, reason) and mailed to every active platform admin of the
  install. Both are written before the session is issued; if either fails,
  the sign-in fails.
- A break-glass session lasts `auth.break_glass_ttl_s` (10 minutes by
  default, at most 15) and has no refresh token. It never acts under an
  MSSP grant, and every audit entry it writes carries
  `auth_method: break_glass`. Failed attempts are audited
  (`auth.break_glass_failed`) and rate-limited per client address.
- An alert that cannot be mailed is retried; one that is given up is logged
  as an error and counted in `lgsotf_security_alerts_undelivered_total`.
- Upgrade notes: database migration `0020` (run `lg-sotf migrate` before
  starting the new version), and upgrade the scheduler together with the
  API, because an older scheduler cannot read the new `email` outbox rows.

- The verdict cache could close a malicious alert at the gate because it
  matched alerts by fingerprint alone (rule, hosts, users, IPs, hashes,
  domains). On one host, a ransomware `PSEXESVC` service matched an Edge
  update service an analyst had closed as benign, and a web shell's `ps`
  running as uid 33 matched monitoring's `ps` running as root. The cache now
  uses a verdict key: the fingerprint plus the process image, command line,
  service name and image path, user/uid, parent process, the objects an
  attacker creates (scheduled tasks, registry keys, target files, Sysmon WMI
  subscriptions) and the request context (URLs, user agents, O365 operations
  and parameters, queries, process-access rights), compared in full: nothing
  is masked or truncated.
- Alerts with no process, command, service or created object, alerts in a
  never-close class (credential access, log clearing, tampering, ransomware,
  persistence through named objects) and alerts normalised by a model never
  close from the cache and get no suggested rule; request context alone (a
  user agent, a URL, an O365 operation) is never enough. Model-normalised
  alerts also skip suppression rules.
- A cached verdict now closes an alert only after two different analysts
  decided it benign within 7 days, at the alert's severity or higher. One
  analyst's decisions, including a bulk close, count once. It is never used
  for critical alerts, nor within 7 days of a confirmed threat on that key or
  on any alert with the same fingerprint.
- Suppression rules suggested from false-positive decisions (one decision, or
  a batch of escalations) match the alert's verdict key instead of its
  fingerprint, so enabling one no longer suppresses a different service or
  command on the same host. With the analyst oracle on corpus_v1, enabling
  every suggestion closed 4 attacks before this change and none after.
- When a threat is confirmed on an alert (an analyst `true_positive`, a
  blind-audit malicious label, a planned response or a malicious close),
  every enabled suppression rule that would close that alert is disabled and
  recorded as `suppression.revoked` in the audit log. A failure is logged as
  an error and counted in `lgsotf_revocation_failures_total`.
- Migration 0016 disables every enabled suggested rule that matches a
  fingerprint alone (audited `suppression.revoked`, reason
  `fingerprint_suggestion`), and the gate ignores such rules even if they are
  enabled again. Replace them with rules on `verdict_key`.
- A benign decision on a grouped escalation now closes an attached alert only
  when it has the same verdict key as the reviewed alert; otherwise the
  attached alert gets its own escalation, as before.
- Cached verdicts written before this change are no longer read, so repeats
  are investigated until two analysts have decided them again. They expire
  within 7 days; `DELETE /tenant/verdict-cache` removes them now.

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
