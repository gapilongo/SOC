# Running LG-SOTF as an MSSP

One installation serves many customers. Each customer is a *tenant*: its
alerts, users, API keys, settings and audit log are isolated by PostgreSQL
row-level security. Operators of the installation are *platform admins*
(`users.is_platform_admin`, granted with `lg-sotf create-admin
--platform-admin` or by another platform admin). This page covers what they
can do across tenants.

Everything here needs a platform admin signed in with a local password
(OIDC identities never carry the platform-admin flag). Tenant admins and API
keys get `403`.

## The MSSP console

In the web app, **MSSP console** (`/platform`) has four tabs:

* **Tenants**: every tenant with its status, alerts in the last 24 hours,
  alerts today against the daily quota, last ingest time, open and overdue
  escalations, SLA breaches in the last 24 hours, LLM cost this month, and
  users and sources against their quotas. From a row: **Open** switches the
  tenant context, **Quotas** edits the quotas, **Suspend** / **Reactivate**
  (with a confirmation) changes the status. Your own home tenant cannot be
  suspended.
* **Escalation queue**: open and claimed escalations of every tenant, the
  soonest SLA deadline first. Opening one switches to its tenant and shows
  its escalation queue. Under a platform admin's tenant switch, claims,
  decisions and approvals are refused, because they belong to the
  customer's analysts; an MSSP analyst the customer granted access to
  decides there under the grant (see [Delegated access](#delegated-access-organisations-and-grants)).
* **Usage**: invoicing figures per tenant for a month, with CSV export.
* **Create tenant**: id, name, optional first admin, and the initial
  settings (see [Templates](#templates)).

The header's tenant switcher lists every tenant (search by name or id). While
you act on another tenant, an amber banner says so, every request carries
`X-Tenant-ID` and is written to that tenant's audit log
(`platform_admin.tenant_access`), and live updates are off. **Return to ...**
goes back to your home tenant.

## Delegated access (organisations and grants)

MSSP analysts do not need an account in every customer tenant. Their
company is an *organisation*: a tenant of its own (its *home tenant*) whose
staff accounts may act in customer tenants that granted it access.

1. A platform admin makes the MSSP's tenant an organisation:
   `PUT /platform/organisations/{tenant_id}` with `{"name": ...}`.
2. An admin of that tenant lists the staff who may use its grants:
   `PUT /organisation/members/{user_id}` (an account of the home tenant),
   `DELETE /organisation/members/{user_id}`, `GET /organisation/members`.
3. A customer's admin gives the organisation a role in their tenant:
   `POST /tenant/grants` with `organisation_id`, `role`, `reason` and
   `expires_at` (at most 365 days ahead), and optionally `user_id` to grant
   one member only. `GET /tenant/grants` lists every grant the tenant gave,
   revoked and expired ones included; `POST /tenant/grants/{id}/revoke`
   ends one.
4. A member sees where they may act (`GET /organisation/grants`) and acts
   there by sending `X-Tenant-ID: <customer>` with their own sign-in.

Under a grant the member has the grant's role, never more than their own
role in the home tenant, and no platform-admin powers (a platform admin who
is also a member and holds a grant acts under the grant). With the analyst
role they decide escalations and approve, reject, roll back, retry and
verify actions within the role's approval authority, and write what the role
allows (notes, suppression rules; settings, sources and integrations with an
admin grant). Two things are never available under a grant: claiming an
escalation (it assigns it to an account of the customer; decide without
claiming) and anything that creates or changes credentials that would
outlive the grant (users, MFA resets, API keys, grants). Rows written under a
grant leave the customer's user columns empty (`decided_by`, `created_by`):
the member's account belongs to the organisation's tenant, and the audit log
names them.

Every audit entry written under a grant is recorded in both chains, in the
same transaction: in the customer's, with `delegation` (the organisation and
the grant) in its details, and in the organisation's as
`delegated.<action>` (for example `delegated.escalation.decided`) with the
customer, the grant, and the customer entry's id and hash, but never its
details. Either side can show the other's entry exists and is unchanged. The grant is read
on every request: a revoked or expired grant, a removed member or a
suspended customer gets 403 on the next request. Every request is written to
the customer's audit log (`grant.tenant_access`, with the grant and the
organisation). Giving and revoking a grant is recorded in both chains: the
customer's (`grant.created`, `grant.revoked`) and the organisation's
(`grant.received`, `grant.revoked`).

Live updates, automation and MCP work under grants too:

* **WebSocket**: `GET /ws?token=...&tenant=<customer>` streams the customer
  tenant's events to a member holding a grant (browsers cannot set
  `X-Tenant-ID` on a socket). The grant is re-checked every
  `api.ws_revalidate_s`; a revoked or expired grant closes the socket with
  1008. Nobody else may name another tenant, platform admins included.
* **API keys**: an API key of the organisation's home tenant acts under a
  grant to the whole organisation (never one given to a single member) with
  `X-Tenant-ID`. Its scopes are capped by the grant's role: `read` for a
  viewer grant, `read` and `write` for analyst and admin grants, never
  `ingest`. Keys still never decide, approve or administer.
* **MCP**: `LG_SOTF_MCP__TENANT_ID` pins `lg-sotf mcp` to one customer: every
  call carries `X-Tenant-ID`. It is configuration, not a tool argument, so
  nothing the model reads (an alert, a note) can point the server at another
  tenant. Run one MCP server per customer.

`tests/integration/api/test_cross_tenant_leak.py` checks the boundary on
every release: every operation of the API contract, every MCP tool and the
WebSocket channel, called by organisation members and keys with and without
a grant and by another customer, never return a victim tenant's data or
change its rows.

Grants belong to the customer. Only the customer's own admin accounts give,
list and revoke them: never someone acting under a grant, and a platform
admin's `X-Tenant-ID` may list them but not give or revoke one. Row-level
security enforces the same split: the organisation can read its own grants
and nothing else, and cannot create, extend or revoke one.

The platform admin's tenant override (below) is unchanged and stays
separate: it is not expressed as a grant, it keeps the admin's own role, and
it still cannot claim or decide.

## API

| Method | Path | What |
|---|---|---|
| POST | `/api/v1/platform/tenants` | Provision a tenant: `id`, `name`, optional `admin_email`/`admin_password`, and either `profile` or `copy_settings_from`. |
| GET | `/api/v1/platform/tenants?status=active\|suspended` | Every tenant with `quotas`, `quota_usage` and `stats`. |
| PATCH | `/api/v1/platform/tenants/{id}` | `name`, `status` (`active`/`suspended`), `quotas` (only the keys present change; `null` = unlimited). |
| GET | `/api/v1/platform/escalations?tenant_id=&limit=&cursor=` | Open and claimed escalations of every tenant, soonest SLA first, keyset-paginated (`limit` <= 200). Each item has `overdue`. |
| GET | `/api/v1/platform/usage?month=YYYY-MM&format=json\|csv` | Per-tenant usage for a UTC month (default: the current one). |

Platform endpoints act across tenants: send them without `X-Tenant-ID` (the
web app does). Every call is audited in your home tenant
(`platform.tenants_listed`, `platform.escalations_listed`,
`platform.usage_exported`, `platform.tenant_created`,
`platform.tenant_updated`); changes are also audited in the tenant concerned
(`tenant.created`, `tenant.updated`, `tenant.suspended`,
`tenant.reactivated`), and a settings copy in the source tenant
(`platform.settings_copied`).

Provisioning is atomic. `POST /platform/tenants` and `lg-sotf create-tenant`
run the same code (`services.tenancy.provision_tenant`): the tenant row, its
seeded settings, its first admin and every audit entry (in the new tenant,
your home tenant and a copied tenant) are saved in one database
transaction. If any part fails, for example the admin account or an audit
entry, nothing is saved and the request answers 500 (the command exits with
an error); send it again. Two requests for the same id at the same time
create the tenant once; the other gets `409 conflict`. A `PATCH` is saved
together with its audit entries in the same way.

`stats` fields: `alerts_24h`, `alerts_today` (UTC day, what the quota
counts), `last_ingest_at` (sample alerts excluded), `open_escalations`,
`overdue_escalations` (past their SLA deadline now), `sla_breaches_24h` (SLA
escalations and expiries recorded by the scheduler), `llm_cost_mtd_usd`,
`llm_tokens_mtd`, `users` (active accounts), `sources`.

The API runs as the least-privilege runtime database role, which cannot read
across tenants. The cross-tenant figures come from four `SECURITY DEFINER`
functions (`lgsotf_platform_tenants`, `lgsotf_platform_tenant_stats`,
`lgsotf_platform_escalations`, `lgsotf_platform_usage`, migration 0004) that
return aggregates only; each figure is an index range scan within one
tenant. `lg-sotf migrate` grants them to `database.runtime_role`.

## Suspension

`PATCH /platform/tenants/{id}` with `{"status": "suspended"}`:

| Path | Effect while suspended |
|---|---|
| Sign-in, refresh | `403 tenant_suspended`; access tokens already issued are refused on their next request. |
| API keys (read, write, ingest) | `403 tenant_suspended`; pushes to `/ingest/*` are refused. |
| Pull sources | Not polled; their cursors stay where they were. |
| Queued work | Workers acknowledge the tenant's queue messages without claiming the run: queued runs stay `queued`, waiting runs keep waiting, and analyst decisions already recorded stay on their escalation. |
| Recovery sweeps | Skip the tenant (orphaned, stranded and lost-resume sweeps). |
| Escalation SLAs | Frozen: the SLA sweep skips the tenant, so nothing is escalated or expired while nobody can work it. |
| Integration deliveries | Held (retried every five minutes); delivered after reactivation if still within `integrations.max_age_hours`. |
| Live WebSockets | Closed at the next revalidation. |
| Platform admins | Can still act on the tenant with `X-Tenant-ID` (to investigate or export). |

Nothing is deleted. Reactivating (`{"status": "active"}`) re-enqueues the
tenant's queued runs at once (up to 10,000; the orphan sweep picks up any
remainder), the resume sweep re-sends recorded decisions, and every open or
claimed escalation gets a fresh SLA deadline of *now + its level's SLA*
(`review.sla_minutes`; a deadline already later than that is kept). The
number of escalations moved is recorded as `sla_deadlines_reset` in the
`tenant.reactivated` audit entry. Restarting the clock (rather than adding
the suspended time back) is deliberate: it needs no record of when the
suspension started, and it gives the returning team a full SLA window
instead of a queue of escalations that breach on the next sweep. Each API
process caches tenant status for 15 seconds and each worker for 15 seconds,
so other processes follow a status change within that time.

Queued work is left queued rather than failed so a suspension for
non-payment or a contract pause is reversible without re-ingesting.
Retention still applies to a suspended tenant.

## Quotas

| Quota | Counts | Over the limit |
|---|---|---|
| `max_alerts_per_day` | Alerts stored today (UTC), from `usage_daily` | `POST /ingest/*` gets `429 quota_exceeded` with `Retry-After` (seconds to 00:00 UTC). The first refusal of the day is audited once as `tenant.quota_exceeded`; later ones are only counted (`alerts_rejected_quota`). Pull sources are not polled until the next UTC day, so nothing is lost. |
| `max_sources` | Registered sources | `POST /sources` gets `409 quota_exceeded`. |
| `max_users` | Active user accounts | Creating an active user, or reactivating one, gets `409 quota_exceeded`. Inactive accounts do not count. |

Quotas are `null` (unlimited) by default and only platform admins can set
them; they are columns of `tenants`, not tenant settings, so tenant admins
cannot change them through `/tenant/settings`. The daily alert check runs
before a request is processed, so a request that starts under the quota is
accepted whole: the day can end above the quota by at most the batches in
flight at that moment (`api.max_ingest_batch` each). Source and user checks
lock the tenant row with the insert, so concurrent requests cannot pass
them. Built-in sample alerts are never counted or refused.

## Usage metering

`usage_daily` (one row per tenant and UTC day, row-level security like every
tenant table) holds:

* `alerts_ingested`: alerts stored, counted in the transaction that inserts
  them. Duplicates (the same `source_alert_id` delivered again) and rejected
  events are not counted.
* `alerts_processed`: alerts whose automated triage finished (the run
  completed or reached a human), counted once per triage in the transaction
  that records the run's result. Resumes after an analyst decision are not
  counted again; a reprocessed alert counts again (it is triaged again).
* `alerts_rejected_quota`, `quota_exceeded_at`.

Why a counter table rather than counting `alerts`: alerts are purged by
retention, which tenant admins can now shorten (down to
`retention.tenant_min_days`), so last month's invoice would change once its
alerts expire; and a stored alert says nothing about deliveries refused by the
quota. The counters are kept for `retention.usage_days` (default 400 days),
independently of alert retention.

`GET /platform/usage` returns, per tenant: `alerts_ingested`,
`alerts_processed`, `alerts_rejected_quota`, `llm_calls`,
`llm_input_tokens`, `llm_output_tokens`, `llm_cost_usd` (from
`llm_usage_daily`), `active_users` (distinct accounts of the tenant, or SSO
subjects, that appear as actors in its audit log during the month: sign-ins,
decisions, changes; users who only read over SSO are not visible there),
`users` and `sources` (current counts), plus `totals`. `format=csv` returns
the same rows as `text/csv` (`lg-sotf-usage-YYYY-MM.csv`); text cells that a
spreadsheet would run as a formula are prefixed with `'`.

## Templates

`POST /platform/tenants` accepts one of:

* `profile`:

  | Profile | Autonomy (low / medium / high / critical) | Max actions per hour | Review SLA L1/L2/L3 (minutes) |
  |---|---|---|---|
  | `conservative` | approval / approval / disabled / disabled | 10 | 30 / 60 / 120 |
  | `balanced` | auto / approval / approval / disabled | 25 | 30 / 60 / 120 |
  | `autonomous` | auto / auto / approval / approval | 50 | 15 / 30 / 60 |

  Every profile keeps `response.dry_run: true`: actions are recorded, never
  executed, until the tenant configures its connector and switches dry run
  off. `conservative` also sets `security.require_mfa: true`: local
  accounts enrol a TOTP factor at their first sign-in (SSO users get MFA
  from their IdP). `balanced` and `autonomous` leave MFA to the tenant
  admin, as a plain new tenant does.
* `copy_settings_from: <tenant id>`: copies the policy of an existing
  tenant: `autonomy`, `review`, `llm_daily_token_budget`, `retention`,
  `security.require_mfa`, `reporting` (minutes per alert),
  `response.dry_run`, `allowed_actions`, `max_actions_per_hour`,
  `blast_radius`, `autonomy`, `allow_internal_ip_blocks`, and which
  enrichment tools are enabled. Never copied: secrets (webhook secret, tool
  API keys, any `*_ciphertext`), destinations (connector, webhook URL, CA
  certificate) and anything that describes the source customer (protected
  assets, `protected_cidrs`, `tools.internal_domains`, and the `phishing`
  section: protected brands, executives, trusted mail servers). Copying those
  would send one customer's response actions to another customer's endpoint
  or leak its asset and staff names.

The response lists the seeded keys (`settings_keys`); the audit entries name
the profile or source tenant.

## Operational notes

* Suspension and quota changes take effect immediately in the API process
  that served the `PATCH` and within 15 seconds elsewhere.
* The tenant list is fetched when the switcher opens and on the console's
  Tenants tab (every 60 seconds while visible); each fetch is one audited
  call.
* Retention bounds for tenant overrides are install settings:
  `retention.tenant_min_days` (default 7) and `retention.tenant_max_days`
  (default 730). Stored overrides outside the bounds are clamped when the
  purge runs.
