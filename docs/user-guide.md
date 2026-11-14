# User guide

How analysts and administrators work with LG-SOTF day to day. Everything
here is available through the REST API (`/api/v1`, reference in
`docs/api.md`, interactive schema at `/docs` when `api.docs_enabled`); the
web application in `src/lg_front` is a client of the same API. Operators
installing and running the platform should read `docs/deployment.md` and
`docs/operations.md`.

## Concepts

| Term | Meaning |
|---|---|
| Tenant | One customer organisation. Users, sources, alerts and policy belong to exactly one tenant; tenants never see each other's data. |
| Source | Where alerts come from: a pull connector (Splunk, QRadar, Microsoft Sentinel, Wazuh indexer, CrowdStrike Falcon) the scheduler polls, a push source (`webhook`, `guardduty`) that senders post to, or the canonical ingest endpoint. |
| Alert | One detection, normalised to the canonical model (title, severity, category, entities, MITRE ATT&CK), with the original event kept. |
| Run | The workflow processing one alert: gate (suppression rules, verdict cache), triage, correlation, analysis, decision, then close, escalate or plan a response. |
| Disposition | The outcome: `malicious`, `benign` or `inconclusive`. |
| Escalation | A request for an analyst decision on an alert (levels L1-L3, SLA deadline). Related alerts are grouped into one escalation. |
| Action | A proposed response (block an address, isolate a host, disable an account, open a ticket ...) in the action ledger, with a risk level, a status and an audit trail. |

Alert status moves `new` -> `queued` -> `processing` -> `closed`, or pauses
at `waiting_human` (an escalation is open) or `waiting_approval` (actions
need approval); `failed` means processing failed and will be retried or
dead-lettered (operators handle those).

## Roles

| Role | Can |
|---|---|
| Viewer | Read alerts, timelines, escalations, actions, suppression rules and the Overview (the dashboard summary). |
| Analyst | Everything a viewer can, plus add notes, propose suppression rules, claim and decide escalations, approve or reject low and medium risk actions. |
| Admin | Everything in the tenant: users, API keys, sources, tenant settings (response policy, protected assets, review policy, enrichment, LLM budget), suppression management, reprocessing, LLM usage, audit log, high and critical risk approvals. |

Platform admins (an operator-level flag) can additionally create tenants and
act on another tenant with the `X-Tenant-ID` header; such access is recorded
in that tenant's audit log, and decisions stay with the tenant's members. The
web app's MSSP console and header tenant switcher build on this
(docs/mssp.md). New tenant admins find a getting-started checklist and
sample alerts under Getting started (docs/onboarding.md).

## Signing in

* **Password**: `POST /api/v1/auth/login` with email and password (and
  `tenant` if your email exists in several tenants). You get a 15-minute
  access token and a refresh cookie; `POST /auth/refresh` renews the token,
  `POST /auth/logout` ends the session. Ten failed attempts lock the account
  for 15 minutes (install defaults).
* **Two-step verification**: with MFA on (or required by your tenant), the
  password is followed by a code from your authenticator app or a recovery
  code. Set it up, renew recovery codes or turn it off under **Account
  security**; an admin can reset it for a lost device (**Users and API
  keys, Reset MFA**). See [identity.md](identity.md).
* **Single sign-on**: if your organisation configured OIDC, sign in with your
  identity provider; your tenant and role come from token claims. To claim
  and decide escalations you also need a user record in the tenant (an admin
  creates it without a password, or the install provisions it on your first
  sign-in when just-in-time provisioning is on).

## Analyst workflows

### 1. Watch the queue

* `GET /dashboard/summary?window_hours=24`: counts by status, severity and
  disposition, open escalations, mean time to acknowledge and to resolve,
  queue depth, LLM tokens and cost.
* `GET /escalations?status=open` (and `claimed`): the work waiting for
  people, newest first; each escalation carries the level, SLA
  deadline, reason code (`grey_zone`, `false_positive_review`, `high_risk`,
  `model_refused`, `response_review`, ...), a summary (verdict, threat score,
  conclusion, recommended actions) and the ids of attached related alerts.
* `GET /alerts` with filters `status`, `severity`, `disposition`,
  `source_id`, `from`/`to` and `q` (title search) for everything else.
* Live updates: connect to `/api/v1/ws?token=<access token>` to receive
  `alert.*`, `escalation.*` and `action.updated` events for your tenant.
  After a reconnect, re-read from the REST API (delivery is at most once).

### 2. Investigate an alert

* `GET /alerts/{id}`: the canonical alert, the original event (secrets
  redacted), and the summary: triage indicators and confidence, correlation
  (related alerts, shared indicators), the analysis conclusion and threat
  score, recommended actions, LLM usage and, for closed alerts, the verdict
  and close reason.
* `GET /alerts/{id}/events`: the timeline: every node the run passed, agent
  digests, escalation and decision events, action updates, notes.
* `POST /alerts/{id}/notes`: add a note for colleagues (stored on the
  timeline).

Read the summary critically: the analysis states whether its evidence came
from threat intelligence and alert history or only from the model, and
alerts where text in the alert tried to steer the model carry a
`prompt_injection_suspected` indicator.

### 3. Decide an escalation

In the web app the **Queue** page lists what waits for a person in one dense
list, soonest deadline first: the deadline (overdue and under ten minutes are
marked), the severity, what the item is and why it needs you, and what the
analysis made of it so far. It works from the keyboard: `J` and `K` (or the
arrow keys) move, `Enter` opens the item, `Space` shows or hides the preview
beside the list, `X` selects a row and `C` claims it (or the selected rows).
The tabs are views with their counts (Needs a person, Mine, Unassigned,
Deadline under 15 min, Likely malicious); "Save view" keeps the current view,
filters and row density under a name. Row density (Dense, Compact, Two
lines) and saved views are remembered per user in the browser. The queue
shows the tenant you are acting on. The **Escalations** page remains, with
grouping by rule and bulk close.

1. **Claim** it so colleagues know you are on it:
   `POST /escalations/{id}/claim` with the escalation's current `version`.
   A `409 conflict` means someone else changed it; re-read and retry.
2. **Decide**: `POST /escalations/{id}/decision` with `version` and one of:
   * `true_positive`: it is malicious. The run continues to response
     planning. You may pre-approve low and medium risk actions in
     `approved_actions` (for example `"block_ip"` or
     `"block_ip:203.0.113.7"`); high and critical risk actions still need an
     admin's approval.
   * `false_positive` (the detection was wrong) or `benign_positive` (the
     detection was right but the activity is legitimate): the alert closes
     as benign, and the verdict is cached. Once two different analysts have
     made such decisions within 7 days on the same detection and behaviour
     (same rule and entities, and the same process, command line, service,
     user and parent process), its repeats at that severity or lower close
     automatically, never for critical alerts, and not for 7 days after a
     threat is confirmed on that detection. With
     `suggest_suppression: true` a false-positive decision also creates a
     disabled suppression rule suggestion for an admin to review. It matches
     the same detection with the same behaviour (`verdict_key`), at the
     decided severity or lower.
   * `needs_more_info`: the analysis runs again with your notes, once; after
     that the case comes back to you.
   Add `notes` and optional `feedback` (`confidence`, `triage_correct`,
   `correlation_helpful`, `analysis_accurate`). Feedback feeds the
   evaluation harness (docs/evaluation.md) and helps tune the platform.
3. **Grouped alerts**: the decision also resumes every alert attached to the
   escalation. A benign decision closes an attached alert only if it is the
   same detection and not more severe; otherwise that alert gets its own
   escalation. Pre-approved actions apply only to the alert you reviewed.

Claims and decisions after the SLA deadline are still accepted (and marked
as late in the audit log); an expired escalation never strands an alert.
A claimed expired escalation stays in the Expired view, now with you as
its owner.

### 4. Approve or reject response actions

`GET /actions?status=awaiting_approval` lists pending actions with their
type, target, risk level and, in `params.explanation`, why the plan chose
it. Then per action:

* `POST /actions/{id}/approve`: analysts may approve low and medium risk,
  admins also high and critical, unless the tenant's autonomy policy
  disables that risk level. The other pending actions of the alert stay
  pending; send `{"reject_remaining": true}` to reject them in the same step.
* `POST /actions/{id}/reject`.

Approved actions are checked against the guardrails again right before they
run. With the default dry-run mode they are recorded as `dry_run` and nothing
is sent; with the webhook connector the tenant's SOAR receives a signed
request and the result is stored on the action. An action that a guardrail
blocks (`blocked`, with a reason such as `protected_asset` or
`non_public_ip`) can never be approved. Executed actions can be verified by
re-query, retried and rolled back (docs/microsoft.md).

### 5. Reduce noise with suppression rules

`POST /suppressions` proposes a rule (field predicates: exact values, regular
expressions, CIDR ranges, with an optional expiry). Rules proposed by
analysts are stored disabled; an admin enables them. Matching alerts are
closed as benign at the gate with `suppressed_by` recorded. Rules that
would match everything are refused.

### 6. Export evidence and draft incident reports

In an alert's drawer, **Evidence and reporting** downloads the case evidence
pack (JSON, or HTML to print to PDF): the alert, its timeline, each agent's
reasoning and model, escalations, feedback, the response ledger, what was
automated and what a person decided, and the related audit entries, with a
digest and signature. **Draft NIS2 report** prepares the early warning,
notification or final report from the case; fields you must complete are
marked, and any model-written narrative is labelled "AI-drafted — review
required". LG-SOTF never submits a report. See [compliance.md](compliance.md);
to use LG-SOTF from Claude or another MCP client, see [mcp.md](mcp.md).

### 7. Label blind-audit samples

**Blind audit** (analysts and admins) lists a random sample of alerts that
automation closed, to measure how many real threats it lets through. Each
sample shows the alert's source, times, entities and event, but not the
AI's verdict: label it **Malicious**, **Benign** or **Unsure** from the
evidence alone (keys M, B and U), with an optional note. The AI's verdict,
confidence, routing and reasoning appear only after you label, with whether
you agree; press N for the next sample. Until a sample is labelled, its
alert shows "Verdict hidden for a blind audit" everywhere else too, for
everyone. A malicious label opens a normal escalation for the alert; deciding
it in the queue re-triages the alert with your decision (its disposition, and
a response where the policy allows). The results are under Reports > Blind
audit.

## Administrator workflows

### Users and access

* `POST /users` (email, role, optional password; omit it for SSO-only
  users), `PATCH /users/{id}` (role, active flag, password),
  `DELETE /users/{id}`. You cannot demote or deactivate yourself or remove
  the tenant's last active admin. Password changes and deactivation end the
  user's sessions.
* `POST /api-keys` with a name and scopes (`ingest` for senders, `read` for
  reporting tools, `write` for notes and suppression proposals). The key is
  shown once; store it in the sender's secret store. `DELETE /api-keys/{id}`
  revokes it.

### Connect alert sources

* **Push, canonical**: give the sender an `ingest` API key; it posts
  canonical alerts to `POST /ingest/alerts` (batches up to 500).
* **Push, vendor format**: `POST /sources` with type `webhook` and
  `config.format` set to `splunk`, `crowdstrike`, `sentinel`, `wazuh`,
  `guardduty` or `qradar`, or `generic` with a `field_map` (dot-paths from
  the payload to canonical fields, optional `severity_map`). Senders post
  native payloads to `POST /ingest/webhook/{source_id}`. AWS GuardDuty uses
  a `guardduty` source fed by an EventBridge rule and API destination.
* **Pull**: `POST /sources` with type `splunk`, `qradar`, `sentinel`,
  `wazuh` or `crowdstrike`, its `config` (base URL and query options) and its
  credentials in `secret` (encrypted, never shown again). The scheduler polls
  every `poll_interval_s` with a persisted cursor; `POST /sources/{id}/test`
  checks connectivity; `GET /sources` shows health and the last error.
  Connector configuration keys are documented in
  `lg_sotf.ingestion.sources`.
* **Wazuh, step by step**: Sources > Connect Wazuh step by step checks the
  indexer connection (or the manager's push) before the source is saved and
  says what to change for each failed check. See
  [onboarding.md](onboarding.md#guided-wazuh-setup).

Every ingest call answers per event (`inserted`, `duplicate`, `rejected` with
a reason). Duplicates (same source and source alert id) are never processed
twice.

### Notify channels and open tickets

Under **Integrations**, send escalations, SLA breaches, pending approvals and
action outcomes to Slack, Microsoft Teams (Workflows), email or a signed
webhook, and open a Jira or ServiceNow ticket for each escalation. Choose the
events and the minimum severity, use **Test**, and check the **Log** for
failed deliveries. Linked tickets appear in the alert drawer and on the
escalation decision page. See [integrations.md](integrations.md) for each tool's setup.

### Set the response policy

`PATCH /tenant/settings` (merge patch; `GET` shows the current values with
secrets replaced by `*_configured` flags):

* `autonomy`: per action risk level `auto`, `approval` or `disabled`.
  Defaults: approval for low, medium and high, disabled for critical. With
  `auto`, containment actions (block, isolate, disable, quarantine,
  terminate, reset, revoke) run automatically only when rule evidence
  corroborates the threat; on model-only evidence they always wait for
  approval. Non-containment actions (ticket, notification, forensics
  collection) at an `auto` level run without approval, and when every
  planned action has completed the alert closes as malicious, whatever its
  severity. Keep low risk at `approval` if every closure should involve a
  person.
* `protected_assets`: `hosts` (wildcards allowed), `users`, `cidrs`,
  `domains`, `processes` (wildcards allowed) and `hashes` that no action may
  ever target, whatever the spelling. Critical operating-system and
  security-agent processes (`lsass.exe`, `csrss.exe`, `winlogon.exe`,
  `services.exe`, `svchost.exe`, `explorer.exe`, `systemd`, `sshd`, EDR
  agents ...) are never terminated, whatever the tenant configured.
  Parent/grandparent processes and their hashes are never response
  targets, and `terminate_process`/`quarantine_file` carry the alert's
  hosts in `params.scope.hosts` of the signed webhook body.
* `response`: `connector` (`dry_run` or `webhook`), `webhook_url` and
  `webhook_secret` (your SOAR: Tracecat, Shuffle, Tines, n8n or any HTTPS
  receiver that verifies the HMAC signature; templates and recipes in
  [soar-playbooks.md](soar-playbooks.md)), `dry_run`, `allowed_actions`,
  `allow_internal_ip_blocks`, `max_actions_per_hour`, `blast_radius` (per
  action type per hour).
* `review`: SLA minutes per level, level thresholds, minimum level per
  severity, grouping (window, by fingerprint and by shared indicators),
  suppression suggestions.
* `tools`: enrichment provider keys (`virustotal`, `abuseipdb`) and whether
  the tenant uses them, plus `internal_domains` that are never sent to a
  provider.
* `llm_daily_token_budget`: daily token limit for the tenant; when reached,
  agents fall back to rules until the next day.

Action types: `block_ip`, `block_domain`, `block_url` and
`terminate_process` (medium risk), `quarantine_file`, `collect_forensics`,
`create_ticket`, `send_alert` (low), `isolate_host` and `revoke_sessions`
(high), `disable_user` and `reset_password` (critical).

Recommended rollout: keep `connector: dry_run` for the first weeks, review
what the platform would have done in the action ledger, then switch to the
webhook connector with `approval` everywhere, and only then consider `auto`
for low risk actions.

### Manage suppression rules

`GET /suppressions` lists rules with hit counts; `PATCH` enables, disables or
edits them; `DELETE` removes them. Review suggestions created from analysts'
false-positive decisions regularly and set expiry dates on broad rules. When
an analyst confirms a threat (`true_positive`) on an alert, the platform
disables every enabled rule that would have closed that alert and records
`suppression.revoked` in the audit log; re-enable a rule only after checking
it.

### Reprocess, usage and audit

* `POST /alerts/{id}/reprocess` re-runs a finished alert (after a policy or
  source mapping change).
* `GET /usage/llm?from=&to=` shows daily calls, tokens and cost per model
  and agent.
* `GET /audit` lists the tenant's audit trail (logins, user and key changes,
  sources, settings, suppression rules, claims, decisions, approvals,
  response execution, platform-admin access); `GET /audit/verify` checks the
  hash chain. Export it for incident evidence.

### Measure quality

Run the evaluation harness on your analysts' decisions before changing
models, routing thresholds or autonomy (docs/evaluation.md). Watch the
malicious false-negative rate (threats closed without a human) first, then
the benign auto-close rate (analyst time saved).

### Run a proof of value

**Proof of value** (admins) measures the triage on your own alerts before
you rely on it. *New proof of value* opens a three-step wizard: name the
run and choose how many days of history to replay (the backtest), choose
the length of the shadow period on live alerts, review and start. The
server then runs the backtest by itself; nothing is typed on a command
line. The page shows the backtest's result (alerts replayed, confirmed
threats, how many of them the triage would have closed, with the sample
size and interval) and links the reports over the shadow period. A run
only reads: it changes no alert, takes no response action and notifies
nobody. One run at a time per tenant; *Stop this run* ends it early. See
docs/pov.md.

### Reports

**Reports** (every role) shows, for a date range: *Value* (alerts handled
without a human, estimated analyst hours saved, time to verdict, MTTA/MTTR,
SLA breaches, LLM cost per alert), *Accuracy* (the AI verdict against your
analysts' decisions, with the false-negative rate first and an explicit
"insufficient data" warning below 30 decisions) and *Detections* (noisy
rules with a tune-or-suppress suggestion; analysts can *Propose
suppression*, which creates a disabled rule for an admin to enable) and
*Blind audit* (the false-negative rate among auto-closed alerts, from
analysts' blind labels of a random sample, with its interval and sample
size; stratified over the sampling runs, with a worst case and an
"incomplete" mark until every sample is labelled). Admins turn on the weekly
sample with the tenant setting `blind_audit` (`{"enabled": true}`), draw one
now on the Blind audit page, or run `lg-sotf audit-sample --tenant <id>
[--size 200]` (a proof-of-value random sample; runs follow each other
without gaps and use a seed the server picks).
*Export CSV* downloads the value series or the detections table; *Open
monthly report* shows a printable page for the month. Admins set the
minutes an analyst spends per alert under Tenant settings > Reporting. To
try another model on your own decided alerts before switching, run
`lg-sotf eval --from-history --tenant <id> --days 30` (read-only). Every
definition and limit: docs/reporting.md.
