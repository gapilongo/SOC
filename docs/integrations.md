# Integrations: notifications, ChatOps and ticketing

LG-SOTF can tell analysts about escalations, approvals and action outcomes
where they already work (Slack, Microsoft Teams, email, or any system that
accepts a signed webhook), and can open and keep in sync a Jira or ServiceNow
ticket for every escalation. Admins configure integrations per tenant under
**Integrations** in the web app or through `/api/v1/integrations`.

Everything sent is a **summary**: the alert's title, severity, status,
verdict, confidence, threat score and at most five redacted values per entity
kind (never command lines), the escalation or action it concerns, and a link
to the alert in LG-SOTF. The raw alert never leaves the platform.

## Events

| Event | Raised when | Where it is raised |
|---|---|---|
| `escalation.created` | the workflow opens an escalation (also a detached one) | `EscalationService.open_or_attach` / `open_detached` |
| `escalation.sla_breached` | the scheduler's SLA sweep raises the level (L1 -> L2 -> L3) or expires an L3 escalation | `Scheduler._handle_breach` |
| `escalation.decided` | an analyst records a decision | `ReviewService.decide`, `EscalationService.close_after_resume` |
| `action.awaiting_approval` | a planned response action needs an approval | `ResponseService` ledger transitions |
| `action.executed` | an action succeeded, or ran as a dry run (`action.dry_run: true`) | `ResponseService` ledger transitions |
| `action.failed` | an action failed | `ResponseService` ledger transitions |
| `action.verification_failed` | a re-check contradicts an executed action or cannot prove it (`action.verification: {outcome, reason}`; docs/microsoft.md) | `VerificationService` |
| `alert.critical_received` | a critical alert is dispatched to the workers (once per alert) | `dispatch_new_alerts` |

Each integration subscribes to a list of events and a **minimum severity**
(the alert's severity; action events use the severity of the alert they act
on). Ticketing integrations accept only `escalation.created` (open a ticket)
and `escalation.decided` (comment and optionally resolve); they may also set
`config.min_level` (`L1`/`L2`/`L3`) to open tickets only from that level.

Onboarding sample alerts (source `demo:samples`) never raise events, and a
`create_ticket` action on one runs as a dry run, so trying the product
never pages anyone or opens a real ticket.

### Reliable delivery (outbox)

Events are written to `notification_outbox` **in the same database
transaction** as the change they announce: if the escalation, decision or
ledger transition rolls back, so does the event, and a committed change
cannot lose its event. One row is written per matching integration; a
`dedupe_key` (for example `escalation.created:<escalation id>`) makes this
idempotent when a workflow node runs again after a resume.

The **scheduler** delivers the outbox (job `notifications`, every
`scheduler.tick_s`). It was chosen over the workers because the outbox spans
tenants and only the scheduler runs as the schema owner that may read across
tenants (`system_tx`); the workers' runtime role is confined to one tenant by
RLS. It is leader-elected, so per-integration rate limits live in memory, and
delivery never takes a workflow slot. Claims still use `FOR UPDATE SKIP
LOCKED`, so a leader handover cannot send a row twice concurrently.

* A claim counts the attempt and leases the row for five minutes; an attempt
  whose outcome is never recorded (crash) is retried after the lease.
  Delivery is **at least once**: receivers deduplicate on the event `id`.
* Failures are retried with exponential backoff and jitter
  (`integrations.backoff_base_s`, doubling, capped at
  `integrations.backoff_max_s`; a receiver's `Retry-After` is honoured).
* A row becomes `dead` after `integrations.max_attempts` attempts, on a
  permanent error (a 4xx other than 408/425/429, a refused destination, a
  redirect), when the integration is disabled or deleted (or the tenant
  deleted), or when it is older than `integrations.max_age_hours`.
* A suspended tenant's rows wait: they keep their status and are looked at
  again every five minutes without using an attempt (metric outcome
  `deferred`), so reactivating the tenant delivers what is still within
  `integrations.max_age_hours`; older rows become `dead`.
* Rate limits: `config.rate_limit_per_minute` per integration (defaults:
  Slack 60, Teams 30, email 30, webhook 120, Jira and ServiceNow 60). A row
  over the limit waits without using an attempt.
* `last_error` is redacted and truncated; it never contains a webhook URL or
  credentials. Sent and dead rows are deleted after
  `integrations.outbox_retention_days` (job `outbox_purge`).

The admin page shows each integration's delivery log (also
`GET /api/v1/integrations/{id}/deliveries`). Metrics:
`lgsotf_integration_deliveries_total{kind,outcome}` (`sent`, `retry`,
`dead`, `deferred`) and `lgsotf_ticket_syncs_total{system,outcome}`.

## Security

* Credentials (webhook URLs, which embed a token for Slack and Teams, API
  tokens, passwords, signing secrets) are **write-only**: encrypted with
  `security.encryption_keys`, bound to the tenant and the integration id, and
  never returned (the API reports `secrets: {field: configured}`). On update,
  `secret` is a merge patch: a value replaces that field, `null` removes it.
* A stored credential never follows a new destination: an update that
  changes where or as whom it is used (Jira `base_url`, `deployment`,
  `email`; ServiceNow `instance_url`, `username`; webhook `url`; any
  `ca_cert_pem`) must carry that credential again (`secret.api_token`,
  `secret.password`, `secret.signing_secret`), otherwise it is refused with
  422 `invalid_integration`. Slack and Teams webhook URLs are the credential
  themselves.
* Every outbound HTTP request goes through the destination policy used by
  the pull sources: `https` only in staging and production, loopback,
  link-local and cloud metadata addresses always refused, private ranges only
  when `ingestion.allow_private_destinations` is set, the connection pinned to
  the checked address, redirects not followed, timeouts
  (`integrations.http_timeout_s`) and a 256 KiB response cap. On-prem Jira,
  ServiceNow or webhook receivers with a private CA can set
  `config.ca_cert_pem`.
* Every create, update, delete and test is written to the audit log
  (`integration.*`), as are tickets opened or linked
  (`integration.ticket_created` / `integration.ticket_linked`).
* Untrusted text is escaped per channel (Slack `mrkdwn`, Adaptive Card
  markdown, HTML), so an alert title cannot mention `@channel` or inject a
  link. The UI renders ticket links only for `http(s)` URLs.

## Setup per tool

The base URL of links in notifications is `api.public_url` (the UI and API
share a host in the shipped deployments); set `integrations.ui_base_url` if
the web app is served elsewhere.

### Slack

1. Create a Slack app for your workspace (api.slack.com/apps), enable
   **Incoming Webhooks** and add a webhook for the SOC channel.
2. In LG-SOTF, add a **Slack** integration and paste the webhook URL
   (`https://hooks.slack.com/services/...`; other hosts are refused) as the
   credential. Pick the events and the minimum severity, then **Test**.

Messages use Block Kit: a header with the event and alert title, fields for
severity, verdict, confidence, threat score, escalation level or action, the
capped entities, and an **Open in LG-SOTF** button.

**Interactive approvals (optional).** Approve and Reject buttons on
`action.awaiting_approval` messages:

1. In the Slack app, enable **Interactivity** and set the Request URL shown
   in the integration form (after saving with *Approve and reject actions
   from Slack* ticked):
   `https://<api host>/api/v1/integrations/slack/interactions?tenant=<tenant>&integration=<integration id>`.
2. Add the bot token scope `users:read.email`, install the app, and enter the
   app's **Signing secret** and **Bot User OAuth Token** as credentials.
3. Every click is verified with the signing secret (`v0` HMAC-SHA256,
   timestamps older than five minutes and replayed signatures refused). The
   Slack user is mapped to an LG-SOTF user of the tenant by the email Slack
   reports as **confirmed**; the user must be an active analyst or admin.
   The decision goes through the same service and rules as the web app:
   analysts approve low and medium risk, admins also high and critical,
   nobody what the tenant's autonomy policy disables. Each verified click is
   audited (`integration.slack_interaction`); a second click changes nothing.
   The clicking user gets an ephemeral reply with the outcome.
4. A click from Slack involves no LG-SOTF sign-in, so two sign-in rules are
   checked for the mapped user before it decides anything (approve or
   reject):
   * **MFA policy.** When MFA is required for the account (the tenant's
     `security.require_mfa`, or a platform admin under
     `auth.require_mfa_for_platform_admins`) and it has not enrolled, the
     click is refused (outcome `mfa_required`); the user is told to enroll
     in the web app first.
   * **Recent SSO sign-in.** An account provisioned by OIDC (single sign-on)
     must have signed in to LG-SOTF within
     `integrations.slack_sso_max_age_hours` (install setting, default 12);
     otherwise the click is refused (outcome `sso_login_required`). An
     identity disabled at the IdP therefore stops approving from Slack at
     most that long after its last use of the web app. Every accepted OIDC
     token refreshes the account's last sign-in (at most every five
     minutes).

### Microsoft Teams

Office 365 connectors (incoming webhooks at `outlook.office.com/webhook` or
`*.webhook.office.com`) are **retired by Microsoft and not supported**. Use
Teams **Workflows** (Power Automate):

1. In the channel, open *Workflows* and create a flow from the template
   **Post to a channel when a webhook request is received**.
2. Copy the flow's HTTP URL and add a **Microsoft Teams** integration with it
   as the credential (the URL contains a signature; treat it as a secret).

Messages are Adaptive Cards (version 1.4) with the same facts as Slack and an
*Open in LG-SOTF* action.

### Email

The SMTP server is an install setting; recipients are per integration.

```yaml
integrations:
  smtp_host: smtp.example.com
  smtp_port: 587            # 465 with smtp_security: tls
  smtp_security: starttls   # starttls | tls | none (refused in staging/production)
  smtp_username: lgsotf
  smtp_password: ${SMTP_PASSWORD}
  smtp_from: soc-alerts@example.com
```

Certificates are always verified. Messages have a plain-text part and a
simple HTML part (every value escaped), `Auto-Submitted: auto-generated`.

### Generic webhook

Each event is `POST`ed as JSON (`application/json`) with the schema
`lg-sotf.event.v1`:

```json
{
  "schema": "lg-sotf.event.v1",
  "id": "5b0e...-uuid",
  "event": "escalation.created",
  "occurred_at": "2026-09-30T12:00:00+00:00",
  "tenant_id": "acme",
  "severity": "high",
  "alert": {"id": "...", "title": "...", "severity": "high", "status": "waiting_human",
            "verdict": "malicious", "confidence": 72.0, "threat_score": 81.0,
            "category": "malware", "source_id": "splunk-prod",
            "entities": {"hosts": ["ws-042"], "ips": ["185.220.101.44"]}},
  "escalation": {"id": "...", "level": "L2", "priority": 8, "status": "open", "reason": "...",
                 "decision": null, "sla_deadline": "2026-09-30T13:00:00+00:00", "attached_alerts": 0},
  "action": null,
  "links": {"alert": "https://soc.example.com/alerts?alert=...", "escalations": "https://soc.example.com/escalations"}
}
```

Keys are stable; new keys may be added. Headers use the signing scheme of
the response webhook connector:

| Header | Value |
|---|---|
| `X-LGSOTF-Signature` | `v1=<hex>`: HMAC-SHA256 of `"<timestamp>.<raw body>"` with the integration's signing secret |
| `X-LGSOTF-Timestamp` | Unix time of this attempt (every retry is signed afresh) |
| `X-LGSOTF-Event` | the event type |
| `Idempotency-Key` | the event `id` (identical on every retry) |
| `X-LGSOTF-Delivery` | the outbox row id |

Verify with a constant-time comparison and reject timestamps older than five
minutes (`lg_sotf.security.signing.verify_signature` is a
reference implementation), then deduplicate on the signed body's `id`.
Answer with a 2xx; 429 and 5xx are retried.

### Jira

* **Jira Cloud**: an Atlassian account for LG-SOTF (a bot account is best)
  with *Browse projects*, *Create issues*, *Add comments* and *Transition
  issues* in the target project. Create an API token at
  id.atlassian.com/manage-profile/security/api-tokens. Configure `base_url`
  (`https://<site>.atlassian.net`), `email` (the account's email),
  `project_key` and optionally `issue_type` (default `Task`), `labels`,
  `priority_map` (`{"critical": "Highest"}`), `min_level`, and
  `resolve_transition` (a transition name or id, e.g. `Done`). REST API v3
  is used, with Atlassian Document Format descriptions.
* **Jira Data Center** (optional): set `deployment: datacenter` and use a
  personal access token as the credential (REST API v2, bearer auth).

**Test** checks the credentials and the project without creating an issue.

### ServiceNow

Create an integration user (*Web service access only*) with the `itil` role,
or a custom role with read/create/write ACLs on `incident`. Configure
`instance_url` (`https://<instance>.service-now.com`), `username`, the
password as credential, and optionally `assignment_group`, `caller_id`,
`category`, `min_level`, `comment_field` (`work_notes` by default, or
`comments`), `resolve_on_decision` with `resolve_state` (default `6`,
Resolved) and `close_code` (default `Solution provided`). Incidents are
created with the Table API; `urgency`/`impact` follow the alert severity.

## Ticket lifecycle

* **Opening.** On `escalation.created` (when the integration subscribes and
  the severity and level match), and for the `create_ticket` response action.
  At most one ticket per escalation and integration: if the alert already has
  a ticket (opened by `create_ticket`), the escalation reuses and links it.
  Each ticket carries a correlation token (the Jira label or ServiceNow
  `correlation_id` `lgsotf-<hash of tenant and escalation>`); the client
  searches for it before creating, so a retry after a crash never opens a
  duplicate. The alert timeline shows *Opened jira ticket SOC-7*.
* **`create_ticket` action.** When the tenant has an enabled ticketing
  integration with `response_actions: true` (the default) and response
  execution is live (neither `response.dry_run` nor the tenant's dry-run
  switch is on), `create_ticket` opens the ticket through it (ledger
  `connector: ticketing`, `result.ticket`). Otherwise it keeps the tenant's
  connector (dry run or SOAR webhook) as before.
* **Decision.** On `escalation.decided` the ticket gets a comment with the
  decision and a link; for `true_positive`, `false_positive` and
  `benign_positive` the configured resolve transition (Jira) or resolved
  state (ServiceNow) is applied. A decision delivered before the ticket
  exists waits for it.
* **External changes.** The scheduler (job `ticket_sync`, every
  `integrations.ticket_sync_interval_s`) polls linked open tickets, at most
  `integrations.ticket_sync_batch_per_tenant` per tenant per pass, least
  recently synced first, and stores the external status. When a ticket is
  resolved or closed outside LG-SOTF, the alert timeline gets a note (*Ticket
  SOC-7 done by Jo Analyst*). **The escalation is never decided from ticket
  state**: an analyst decides it in LG-SOTF.

Ticket links appear in the alert drawer and on the escalation cards
(`GET /api/v1/tickets?alert_id=` or `?escalation_id=`, viewer role).

## API

| Method | Path | Access |
|---|---|---|
| GET, POST | `/integrations` | admin |
| GET, PATCH, DELETE | `/integrations/{id}` | admin |
| POST | `/integrations/{id}/test` (sends a test message; ticketing kinds check credentials and project) | admin |
| GET | `/integrations/{id}/deliveries?status=&limit=` (newest first, at most 200) | admin |
| GET | `/tickets?alert_id=` or `?escalation_id=...` (repeatable, at most 200) | viewer / `read` |
| POST | `/integrations/slack/interactions?tenant=&integration=` | Slack signing secret |
| GET | `/integrations/microsoft/catalog` (the `microsoft` kind is the direct response connector: docs/microsoft.md) | admin |

Invalid configuration answers `422 invalid_integration`; a tenant may have at
most 50 integrations.

## Limitations

* Delivery is at least once: a crash between a send and its recorded outcome
  can repeat a message or a ticket comment (never a ticket: creation searches
  first).
* An escalation opened while its alert's `create_ticket` action is creating a
  ticket at the same moment can end up with two tickets.
* Deleting an integration deletes its delivery log and ticket links (the
  tickets stay in Jira/ServiceNow); disable it instead to keep them.
* Jira's "resolved by" is the author of the last status change in the issue's
  changelog (falling back to the assignee).
