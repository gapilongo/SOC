# Microsoft direct response, verification and rollback

LG-SOTF 1.1 can execute approved response actions directly in the
customer's Microsoft tenant (Microsoft 365 mail through Microsoft Graph,
Microsoft Entra ID, and Microsoft Defender for Endpoint), prove by
re-query that each change is in effect, and roll changes back. This page
describes the framework shared by all Microsoft capabilities. The
capabilities themselves are documented per package:

* [Microsoft 365 mail](microsoft-mail.md): `mail.remediate`, `mail.notify`
* [Microsoft Entra ID](microsoft-entra.md): `entra.account`, `entra.sessions`, `entra.password`, `entra.risk`
* [Microsoft Defender for Endpoint](microsoft-defender.md): `defender.isolation`, `defender.indicators`,
  `defender.file_indicators`, `defender.stop_quarantine`, `defender.forensics`

The direct connector is only another executor of an approved ledger row.
Planning, guardrails, protected assets, autonomy, approvals, the hourly cap,
blast radius, the audit trail and integration events work exactly as for
the SOAR webhook (see [user guide](user-guide.md) and
[security](security.md)).

## 1. Overview and the four live switches

Nothing reaches Microsoft by default. A write needs all four of:

| Switch | Where | Default |
|---|---|---|
| Install kill switch | `response.dry_run` (setting, `LG_SOTF_RESPONSE__DRY_RUN`) | `true` |
| Tenant kill switch | tenant settings `response.dry_run` | on for tenants created from a `profile` (copied with `copy_settings_from`); **off when unset** (tenants created with `lg-sotf create-tenant`, or with `POST /platform/tenants` without a profile or source tenant); a malformed value counts as on |
| The Microsoft integration | Integrations page, **Microsoft 365 (direct response)**, enabled | none configured |
| The capability | the capability card: **Enabled** and **Live** | off |

An enabled capability that is not live *rehearses*: it resolves the targets
with read-only calls (GET only; a write is refused before it is sent) and
records the action as `dry_run` with `result.rehearsal: true`,
`result.resolved` (what it found) and `result.would_execute`. Going live
asks for a confirmation.

The kill switches always win, also for rollbacks and retries. The
**Response routing** section of the tenant settings shows the effective
state ("Dry run is on" when either switch forces it). Onboarding sample
alerts never reach Microsoft or a ticketing system: an action of a sample
alert that would go to either is a dry run (a sample's webhook actions
still reach the SOAR, as in 1.0).

## 2. App registration

Use **one single-tenant app registration per customer directory**, created
in that directory (Entra admin center > App registrations > New
registration, "Accounts in this organizational directory only").

1. **Credential.** A certificate is recommended (Microsoft: "Don't use
   password credentials"). Create an RSA key of at least 2048 bits and a
   certificate (a self-signed one is accepted), upload the certificate
   (`.cer`/`.pem`) under *Certificates & secrets*, and give LG-SOTF the
   certificate PEM (config) and the unencrypted PKCS#8 or PKCS#1 private
   key PEM (write-only secret). A client secret is allowed; paste its
   *value*, not its id.
2. **API permissions.** Add the *application* permissions listed by each
   capability you will enable (the Integrations page shows them per
   capability, and the package pages list them with their purpose):
   Microsoft Graph permissions under *Microsoft Graph*, Defender for
   Endpoint permissions under *APIs my organization uses > WindowsDefenderATP*.
   Some capabilities also need an Entra directory role on the app's service
   principal or an Exchange RBAC for Applications role; tokens do not show
   those, so the connection test reports them as `unknown` with guidance.
3. **Admin consent.** Select *Grant admin consent for <tenant>* after every
   permission change ("Every time you add a permission, you must select
   Grant admin consent for it to take effect"). An app-only token may be
   issued without a `roles` claim when consent is missing, so a missing
   consent often shows up as `403` on the first API call.
4. In LG-SOTF: the directory (tenant) id and the application (client) id
   as GUIDs (`common`, `organizations`, `consumers` and domain names are
   refused), the cloud, the credential, and optionally the Defender API
   region.

At most one Microsoft integration exists per tenant (a second one is
`409 integration_exists`). Changing the cloud, the directory, the app, the
credential type or the certificate requires the credential again in the
same request, so a stored credential is never sent to another directory.

## 3. Clouds and hosts

Hosts are fixed per cloud in the code; no configuration field holds a URL.

| Cloud | Sign-in | Microsoft Graph | Defender for Endpoint |
|---|---|---|---|
| `global` (commercial, and GCC, which uses the worldwide endpoints) | `login.microsoftonline.com` | `graph.microsoft.com` | `api.security.microsoft.com`, or `{us,eu,uk,au,swa,ina,aea}.api.security.microsoft.com`; token scope `https://api.securitycenter.microsoft.com/.default` |
| `usgov_gcc_high` | `login.microsoftonline.us` | `graph.microsoft.us` | not supported in 1.1 |
| `usgov_dod` | `login.microsoftonline.us` | `dod-graph.microsoft.us` | not supported in 1.1 |

The Defender token uses the legacy audience `api.securitycenter.microsoft.com`:
Microsoft notes that some Defender for Endpoint APIs refuse tokens for the
newer resource with `403` even on `api.security.microsoft.com`. The China
cloud and Defender on the US Government clouds are not supported (no
documented token scope).

## 4. Routing

Each action is routed on its own; the first match wins:

| # | Rule | Route (`source`) |
|---|---|---|
| 1 | install `response.dry_run` | dry run (`kill_switch`) |
| 2 | tenant `response.dry_run` true or malformed | dry run (`tenant_dry_run`) |
| 3 | an onboarding sample alert whose route would be `microsoft` or `ticketing` | dry run (`sample`) |
| 4 | a pinned row (a re-run of an executing row, a rollback, a retry, a scheduler row with a connector) | its recorded connector (`pinned`); a `microsoft` row needs its pinned integration to exist and be enabled |
| 5 | tenant `response.routes[action_type]` | that connector (`explicit`) |
| 6 | `create_ticket` with an enabled ticketing integration for response actions | `ticketing` |
| 7 | an enabled capability of the enabled Microsoft integration executes the type | `microsoft` (`capability`) |
| 8 | otherwise | the tenant default: `response.connector`, else the install webhook, else dry run (`default`) |

A configuration problem never falls back silently: the action fails with
`connector_misconfigured` and the reason (for example an explicit
`microsoft` route with no enabled capability for the type, a pinned
integration that was deleted, or undecryptable credentials).

`response.routes` (tenant settings, at most 64 entries) overrides rules 6
to 8 per type with `dry_run`, `webhook`, `ticketing` (only for
`create_ticket`) or `microsoft` (only for types a capability executes).
`GET /api/v1/tenant/response/routes` and the **Response routing** table in
tenant settings show every type's current route and why.

Examples:

* Isolate hosts in Defender but keep blocking IPs through the SOAR:
  enable `defender.isolation` only; `block_ip` keeps the default webhook.
* Keep `disable_user` in the SOAR although `entra.account` is enabled:
  `{"response": {"routes": {"disable_user": "webhook"}}}`.
* Rehearse everything first: enable the capabilities without **Live**,
  turn the tenant dry run off, and review the `dry_run` rows'
  `result.resolved`.

## 5. Rehearsal and Live

| Capability state | What an approved action does |
|---|---|
| not enabled | not routed to Microsoft (rule 7 does not match) |
| enabled | rehearsal: GET-only resolution, recorded `dry_run` with `rehearsal: true` |
| enabled and live | executes; `succeeded`, `failed` or, when it cannot finish now, `executing` handed to the scheduler |

A rollback of an action is executed even when its capability is no longer
live (undoing our own change must stay possible), but never while a kill
switch is on.

Handlers read before they write and tag what they create with the marker
`LG-SOTF action <uuid>`. Before each non-idempotent write they checkpoint
their progress into the row (`external_ref`), so a re-run after a crash
adopts a pending operation or an existing object instead of acting twice.
Every result carries `connector`, `capability`, `integration_id`, `live`,
`summary`, `changed` (and `already` when nothing needed changing); failures
also `error`, `http_status`, `ms_code`, `request_id`, `retryable` and
`hint`. Microsoft's free-text error messages are never stored.

## 6. Verification

`succeeded` means Microsoft accepted the change. **Verification** is a
separate axis that proves it by re-query:

| State | Proves |
|---|---|
| `pending` | not decided yet; checked again with backoff |
| `verified` | a re-read shows the change in effect (for example the account is disabled, the isolation machine action completed) |
| `failed` | the observed state contradicts the change (the machine action ended `Failed`/`TimeOut`/`Cancelled`, a synced user was re-enabled) |
| `inconclusive` | the check could not be completed: `deadline`, `permission_denied` (403 on the read), `credentials`, `integration_unavailable`, `no_verifier`; or `rolled_back`: a rollback of the action is executing or succeeded, so the change is being undone on purpose (audited, no alert or event). While the rollback is only approved (it may still expire or be blocked), the verification stays `pending` (`rollback_approved`) and is checked again later |
| (none) | not applicable: dry runs, webhook and ticketing actions, failed actions |

A synchronous write that an inline re-read disproves is recorded as
`failed` with `error: "not_verified"`, not as `succeeded` plus a failed
verification.

The scheduler job `verify_actions` runs every `response.verify_interval_s`
(15 s), claims due checks, runs `response.verify_concurrency` (4) at once,
each within `response.verify_check_timeout_s` (30 s). A pending check is
repeated after `max(retry_after, min(900 s, first_check * 2^attempts))`
with 0.8-1.2 jitter, never past the deadline: the capability's window
from the moment Microsoft accepted the change (also after deferrals), at
most `response.verify_max_s` (4 days). Throttling, Microsoft server and network
errors are retried the same way. Verification only reads, so the dry-run
switches do not stop it.

A final outcome is audited (`response_action.verified`,
`.verification_failed`, `.verification_inconclusive`), added to the alert
timeline (`action.verified`, `action.verification_failed`), and failed or
inconclusive outcomes raise the integration event
`action.verification_failed` (Slack, Teams, email, webhook). `POST
/api/v1/actions/{id}/verify` (the **Re-check** button) re-opens a finished
verification for one more hour of checks (not within 5 minutes of the last
change: `429`).

## 7. Rollback

A rollback is a new ledger row of the inverse type (`rollback_of` set),
with the same alert and target, pinned to the original's connector and
integration, and always executed by the scheduler. It follows the normal
rules: guardrails with the restorative exemptions (a protected asset, a
non-public IP or an internal sender does not block undoing our own
change), autonomy for the inverse's own risk, and approval by role (the
requester's approval counts when their role may approve that risk;
otherwise an admin approves it, from the UI or Slack).

| Original | Inverse | Webhook | Microsoft |
|---|---|---|---|
| `isolate_host` | `release_host` (high) | yes | `defender.isolation` |
| `block_ip` / `block_domain` / `block_url` | `unblock_ip` / `unblock_domain` / `unblock_url` (medium) | yes | `defender.indicators` |
| `quarantine_file` | `unblock_file` (medium) | yes | `defender.file_indicators` (not `defender.stop_quarantine`: irreversible) |
| `block_sender` | `unblock_sender` (medium) | yes | no direct capability |
| `disable_user` | `enable_user` (critical) | yes | `entra.account` |
| `purge_message` | `restore_message` (high) | yes | `mail.remediate` |
| `confirm_compromised` | `dismiss_user_risk` (high) | yes | `entra.risk` (compensating) |
| `revoke_sessions`, `reset_password`, `collect_forensics`, `notify_reporter`, `terminate_process` | none | no | no |

Irreversible notes: revoked sessions do not revoke access tokens already
issued (they stay valid until they expire, about 1 h); a reset password
cannot be restored; collected evidence and sent notifications cannot be
recalled; a terminated process is not restarted.

A rollback is available when the original `succeeded` (or failed with
`external_ref.partial`), is not itself a rollback, its type has an inverse,
the connector supports it (the webhook always; Microsoft when
`external_ref.reversible` and before `external_ref.rollback_until`) and no
live rollback exists. Otherwise the API answers `409 rollback_unavailable`
with the reason: `not_executed`, `is_rollback`, `irreversible`,
`nothing_changed`, `window_expired`, `rollback_exists`,
`connector_unsupported`, `integration_gone` (the Microsoft integration that
executed the action was deleted: a rollback is pinned to it, and a
re-created integration is a different one, so undo the change in
Microsoft).

**Webhook contract.** The signed response webhook body
(`lg-sotf.response-action.v1`) has a top-level `rollback_of`: `null`, or the
id of the action being rolled back. A rollback's `action.type` is the
inverse type and `action.params.rollback` holds `{of, reason,
requested_by}`; the receiver undoes what it did for the original action id.

## 8. Background execution, late approvals, TTL, retry

Each ledger row has an **execution owner**. The alert's workflow run owns
the rows it planned (`workflow`); the scheduler (`scheduler`) owns
rollbacks, retries, and rows handed to it. A row is handed off, never back:

* an approval that arrives after the alert's run ended (checked under a
  lock on the run, so a concurrent reprocess cannot execute it twice);
* a Microsoft call that could not finish now (`deferred`: throttled, a
  token endpoint that is briefly unavailable, a write whose outcome is
  unknown after a network or server error, the workflow step's budget
  running out mid-call, or too little of it left to start); the row stays
  `executing` and is re-run after the `Retry-After` (at least 30 s). A
  database error while the call checkpoints is never recorded as the
  outcome either: the row stays `executing` and is run again;
* a Microsoft row left `executing` by a run that ended (after a grace of the
  execution budget plus 60 s); other connectors' orphans are still failed
  with `orphaned_execution`;
* an `approved` workflow row whose run ended: approved at or after the run's
  end, it is handed off (`late_approval`); approved while the run was
  active, the run superseded it and it is blocked (`approval_superseded`).
  The approval TTL applies here too: a late approval older than
  `response.approval_ttl_s` is blocked (`approval_expired`) instead of
  being handed off.

**Upgrading from 1.0.** 1.0 never executed an approval that arrived after
the alert's run had ended. The first `response_background` pass after the
upgrade hands such rows to the scheduler only when they were approved
within `response.approval_ttl_s` (24 h); older ones are blocked with
`approval_expired` and never executed. Review recent approved actions of
closed or false-positive alerts before upgrading if 24 h is too long for
you (lower `response.approval_ttl_s` for the upgrade).

The scheduler job `response_background` (every
`response.background_interval_s`, 5 s) expires scheduler approvals older
than `response.approval_ttl_s` (24 h; `approval_expired`), settles stranded
approvals, then claims due rows (leased for `response.background_deadline_s`
+ 60 s, at most two per tenant and `response.background_concurrency` at
once). Approved rows go through the normal execution claim (guardrails,
caps, blast radius); executing rows whose lease ended are re-run with their
pinned connector, and fail with `attempts_exhausted` after
`response.max_execution_attempts` (5).

**A started row is never recorded as "nothing ran".** When a row's
checkpoints show that an earlier attempt got as far as a write (a re-run,
or a retry), turning a kill switch on holds it (`deferred`, `halted`, run
again every 5 minutes; after its attempts it fails with `halted`), a
disabled or deleted integration fails it with `connector_misconfigured`,
and a capability that is no longer live fails it with
`capability_not_live`, instead of recording `dry_run`. These failures, and
any other failure after progress, are `retryable` and keep what was done
(`external_ref.partial`, reversible per the capability), so **Retry** and
**Roll back** stay available. A row that had not started yet is still
recorded `dry_run` (rehearsed when the capability is not live).

**Retry.** `POST /api/v1/actions/{id}/retry` (the **Retry** button) runs a
failed Microsoft action again when its failure is retryable (or `partial`),
your role may approve its risk and no rollback of it exists (`409
retry_unavailable`, reason `rollback_exists`: the retry would redo what the
rollback undoes). Guardrails and caps are checked again
first (`409 guardrail_blocked` / `cap_reached` leave the row unchanged);
the scheduler executes it.

## 9. Connection test

**Test** on the integration (`POST /api/v1/integrations/{id}/test`) sends
token requests and GET requests only:

* a fresh token for Microsoft Graph (always) and Defender (when an enabled
  capability needs it), with the permissions in each token's `roles` claim;
* for every capability, each permission: `granted` or `missing` from the
  token, `unknown` for directory roles and Exchange RBAC (never in tokens).
  A mailbox permission meant to be granted through Exchange RBAC for
  Applications is `unknown` when the token lacks it, and `granted` with a
  warning when it was consented tenant-wide (which overrides the scope). A
  permission needed only with some options (`recipient_source=message_trace`)
  is required exactly when those options are set;
* the read-only probes of every enabled capability.

A capability is `ok` when its probes pass and no required token-visible
permission is missing, and `unverified` when the only evidence is unknown.
It is also `unverified`, with guidance, whenever a required mailbox
permission is not in the token: it can only come from Exchange RBAC for
Applications, which the test cannot see, and a passing read probe does not
prove a write role. Check those grants with
`Test-ServicePrincipalAuthorization` ([mail](microsoft-mail.md)).
Otherwise the status is `missing_permission`, `not_licensed`,
`unsupported_cloud`, `error` or `not_enabled`. The report (never a token)
is stored with the test delivery and audited as `integration.tested`.

## 10. Troubleshooting

Token failures are classified by the OAuth `error` field only; AADSTS
numbers only choose the hint (Microsoft: never branch on them).

| OAuth `error` | Ledger error | Typical AADSTS | What to check |
|---|---|---|---|
| `invalid_client`, `invalid_grant` | `credentials_invalid` | 7000215 (wrong secret), 7000222 (expired secret), 700027 (assertion signature / certificate not registered), 700024 (assertion time range, clock), 50012 | the secret value, the certificate uploaded to the app, this server's clock |
| `unauthorized_client`, `invalid_resource` | `app_not_in_tenant` | 700016, 7000229, 90002 | the directory id, the cloud, admin consent in that directory |
| `invalid_scope` | `consent_missing` | 65001, 90094, 650056 | grant admin consent after adding permissions |
| `interaction_required` | `conditional_access_blocked` | 53003, 530032 | Conditional Access for workload identities |
| `temporarily_unavailable`, HTTP 429/5xx | `token_unavailable` (retryable) | 50196, 90055 | throttling; retried |

API failures map to `permission_denied` (403; `feature_disabled` for
Defender `DisabledFeature`, `not_licensed` for licence errors), `not_found`,
`bad_request`, `throttled`, `ms_server_error`, `network_error`, `deadline`.
Target problems are `invalid_target` or `unsupported_target` (for example a
`DOMAIN\user` account Graph cannot resolve, a private IP for a Defender
indicator, a SHA-512 hash). The package pages list their own outcome codes.

Requests retry 429 and 503 always, network errors, 500, 502, 504 and Graph
`Directory_ConcurrencyViolation` only when idempotent (GET, DELETE, or a
write the handler declared idempotent), at most `response.microsoft_retries`
times, honouring `Retry-After` and never sleeping past the call's deadline.
A network error, 500, 502 or 504 on any other write leaves its outcome
unknown: the action is deferred and the scheduler's re-run reconciles.
Defender calls are limited client-side to 60 per minute per integration.

## 11. Security model

* **Fixed hosts.** No configuration field holds a URL; hosts come from the
  cloud table in the code, and every request still goes through the
  destination policy (https only, the resolved address checked and pinned,
  no redirects followed, bounded response bodies, per-attempt timeouts).
* **Secrets.** The client secret or private key is encrypted with the
  install's keys, bound to the tenant and integration id, write-only in the
  API, and never in a result, `external_ref`, outbox payload, evidence pack,
  export or log. Tokens live in process memory only, keyed by tenant,
  integration, credential fingerprint, cloud, directory, client and API.
* **Tenant isolation.** A connector is built from the tenant's own
  integration (row-level security) and refuses an action of another tenant
  (an assertion, never a ledger result); ledger rows can only pin an
  integration of their own tenant (a composite foreign key).
* **Untrusted targets.** Alert data (UPNs, host names, Message-IDs,
  indicators) is validated per kind and encoded once, through one module:
  OData string literals double quotes, filter fields come from an allowlist,
  path segments are percent-encoded and never `.` or `..`.
* **Guardrails.** Direct actions pass the same guardrails, protected
  assets, autonomy, approvals, hourly cap and blast radius as webhook
  actions. Rollbacks skip only the restorative exemptions listed above.
  A handler that resolves a target to another identity (an Entra alias or
  object id to a user) checks that identity against the protected assets
  again before any write (`protected_asset`).
* **Audit.** Configuration changes (with the capabilities enabled,
  disabled, made live or not live, their options and whether the credential
  was rotated), every execution, deferral, hand-off, verification outcome,
  re-check, retry and rollback request are audited.

## 12. Capability documentation

* [Microsoft 365 mail](microsoft-mail.md)
* [Microsoft Entra ID](microsoft-entra.md)
* [Microsoft Defender for Endpoint](microsoft-defender.md)
* [Microsoft SKU coverage matrix](microsoft-skus.md): every Microsoft API
  LG-SOTF calls, with the licence it needs on Business Premium, E3 and E5,
  its permission and the Microsoft Learn source

Each page has the same sections: Overview, Actions and Microsoft calls,
Permissions and setup, Verification, Rollback, Limits and licensing,
Troubleshooting. The API endpoint `GET /api/v1/integrations/microsoft/catalog`
lists the installed capabilities with their actions, permissions, options
schema and clouds.

## 13. Limitations and follow-ups

* Not supported in 1.1: the China cloud; Defender for Endpoint on the US
  Government clouds; GCC tenants whose Defender for Endpoint runs on
  `api-gcc`.
* `block_sender` has no direct capability (there is no Tenant Allow/Block
  List API); it stays with the webhook or dry run.
* Not implemented: `permanentDelete`, `analyzedEmails/remediate`, in-place
  archive mailboxes (reported `not_found`), PIM-eligible roles (not seen by
  the privileged-target guard), device disable, on-premises AD actions,
  rollback of a rollback, fetching the investigation package.
* Follow-up: the `m365_mailbox` and `sentinel` ingestion sources still
  accept tenant-supplied `authority_url` and `graph_url`
  (`src/lg_sotf/ingestion/sources/m365.py`, `sentinel.py`), which conflicts
  with the fixed-host rule of the response connector.
* Open questions to settle in a lab tenant before general availability:
  whether `/messages` excludes Recoverable Items and whether immutable ids
  survive a delete; whether filtering sent items on
  `singleValueExtendedProperties` works app-only; whether app-only
  `revokeSignInSessions` needs a directory role for limited-admin targets;
  which permission reads `ownedObjects` and administrative-unit membership
  (the guard fails closed until settled); whether `computerDnsName eq` is
  case-sensitive, what a duplicate isolation returns and the indicator
  upsert key; whether MC1220762 spares the machines, machine actions and
  indicators APIs; PS256 acceptance per cloud.
