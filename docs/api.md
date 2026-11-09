# LG-SOTF HTTP and WebSocket API

This page summarises authentication, authorisation and the endpoints of the
API process (`lg-sotf api`). The OpenAPI document is the source of truth for
request and response schemas: it is served at `/api/v1/openapi.json`, with
interactive docs at `/docs`, when `api.docs_enabled` is true (disable it in
production if the schema should not be public).

The API authenticates callers, scopes every query to the caller's tenant
(PostgreSQL row-level security plus explicit `tenant_id` filters) and
enqueues work for the workers. It never runs a workflow itself.

## Conventions

* Base path `/api/v1`; JSON request and response bodies.
* Errors always have the shape
  `{"error": {"code": "...", "message": "...", "request_id": "..."}}`;
  validation errors (422) add `details`. Stack traces and internal messages
  are never returned.

  | Status | Typical `code` | When |
  |---|---|---|
  | 400 | `invalid_request`, `invalid_cursor`, `invalid_value`, `invalid_json`, `batch_too_large`, `search_window_too_large` | malformed input |
  | 401 | `unauthorized`, `invalid_credentials`, `invalid_session` | missing, invalid, expired or revoked credentials |
  | 403 | `forbidden`, `tenant_suspended` | role, scope or tenant does not allow the call; the tenant is suspended |
  | 404 | `not_found`, `source_not_found` | the object does not exist in the caller's tenant |
  | 409 | `conflict`, `invalid_transition`, `already_in_state`, `last_admin`, `run_active`, `source_disabled`, `quota_exceeded` | stale `version`, duplicate, illegal state change, source or user quota reached |
  | 413 | `payload_too_large` | body over the size limit |
  | 422 | `validation_error`, `invalid_settings`, `invalid_source`, `invalid_rule`, `invalid_integration`, `weak_password` | schema or policy validation failed |
  | 429 | `rate_limited`, `quota_exceeded` | rate limit hit, or the tenant's daily alert quota is used up; see `Retry-After` |
  | 503 | `service_unavailable`, `encryption_unavailable` | a dependency is down or not configured |

* Every response carries `X-Request-ID` (the caller's value when it matches
  `[A-Za-z0-9._:-]{8,128}`, otherwise a generated id), which is also in the
  error body and in the server logs.
* Lists that can grow without bound (`/alerts`, `/alerts/{id}/events`,
  `/escalations`, `/actions`) use keyset pagination: pass the returned
  `next_cursor` as `cursor`; `limit` is at most 200. Cursors are opaque.
* Multi-valued filters repeat the parameter: `?status=queued&status=failed`.
* Timestamps are ISO 8601; query timestamps without an offset are UTC.

## Stability and deprecation

Every operation in the OpenAPI document carries `x-stability`. Build
integrations on `stable` operations. The MCP server (docs/mcp.md) and the
WebSocket events are outside this document and versioned separately.

| Tier | Promise | Operations |
|---|---|---|
| `stable` | No breaking change without a deprecation period first (below). New optional fields, parameters, enum values and operations may appear at any time: ignore what you do not know (tolerant reader, ADR-0009). | `/auth` (login, refresh, logout, me), `/ingest/*`, `/alerts`, `/escalations` (list, read, claim, decision, response preview), `/actions`, `/sources`, `/suppressions`, `/users`, `/api-keys`, `/audit`, `/healthz`, `/readyz` |
| `beta` | May change in a minor release; breaking changes are listed in the changelog. | `/auth/mfa`, `/escalations/groups` and `/escalations/bulk/*`, `/tenant/*`, `/usage/llm`, `/platform/*`, `/alerts/{id}/evidence`, `/alerts/{id}/incident-report`, `/integrations/*`, `/tickets`, `/reports/*`, `/metrics` |
| `internal` | Screens of the bundled UI; may change or disappear in any release. | `/dashboard/summary`, `/onboarding/*` |

A breaking change is one that can make a working client fail: removing an
operation, a response field or an enum value of a request; adding a required
parameter or request field; narrowing a type or a limit. CI compares each
change's `docs/openapi.json` with the base branch's using oasdiff and fails
on a breaking change to a `stable` operation (`scripts/ci/check_api_compat.py`).
Moving an operation from `stable` to `beta` or `internal` counts as removing it.

**Deprecation window.** A stable operation is deprecated at least 6 months
(180 days), and over at least two minor releases, before it is removed or
changed incompatibly. The changelog announces the deprecation under
`Deprecated`. For the whole window the operation keeps working and every
response from it, errors included, carries:

| Header | Example | Meaning |
|---|---|---|
| `Deprecation` (RFC 9745) | `Deprecation: @1794182400` | Deprecated since this time (Unix seconds; here 2026-11-09 00:00 UTC). |
| `Sunset` (RFC 8594) | `Sunset: Mon, 10 May 2027 00:00:00 GMT` | It may be removed from this time on. |
| `Link` | `Link: <https://github.com/gapilongo/SOC/blob/main/docs/api.md#stability-and-deprecation>; rel="deprecation"; type="text/html"` | What replaces it and how to migrate. |

In the OpenAPI document the operation has `deprecated: true`, `x-sunset`
(the date), `x-deprecated-since` and `externalDocs` (the same link). The
three headers are exposed to browsers through CORS. To find deprecated calls
before the sunset, log or alert on any response with a `Deprecation` header.
Beta operations are deprecated the same way when practical, with no minimum
window. No operation is deprecated today.

In code a route is deprecated with `lg_sotf.api.stability.route_contract`:

```python
@router.get("/old", **route_contract(deprecation=Deprecation(since=date(2026, 11, 9), sunset=date(2027, 5, 10))))
```

A router's tier is set where it is mounted (`api_routers` in
`lg_sotf/api/app.py`); `route_contract(stability=...)` overrides it for one
route. A unit test fails if any operation has no tier.

## Authentication

Three kinds of credentials are accepted. All of them resolve to a
*principal*: `{user_id | api_key_id, tenant_id, role, scopes, is_platform_admin}`.

### Local users (password)

* `POST /auth/login` with `{"email", "password", "tenant"?}` returns
  `{"access_token", "token_type": "bearer", "expires_in", "user"}` and sets
  the refresh cookie `lgsotf_refresh` (`HttpOnly; Secure; SameSite=Strict;
  Path=/api/v1/auth`, lifetime `auth.refresh_token_ttl_s`).
* With TOTP MFA enabled for the account (or required by
  `security.require_mfa` / `auth.require_mfa_for_platform_admins`) the right
  password returns `{"mfa_required": true, "mfa_token", "expires_in",
  "enrollment_required", "methods"}` instead, and no cookie. The
  `mfa_token` is not a session: `POST /auth/mfa/verify` with it and a TOTP
  or recovery code returns the normal login response; with
  `enrollment_required` it permits only `/auth/mfa/enroll` and
  `/auth/mfa/confirm`. Wrong codes count toward the lockout. See
  [identity.md](identity.md).
* The access token is an HS256 JWT (`iss`, `aud`, `exp`, `iat`, `jti`, `sub`
  = user id, `tenant`, `role`), valid for `auth.access_token_ttl_s`. Send it
  as `Authorization: Bearer <token>`. The user row is re-read on every
  request, so deactivating a user or changing a role takes effect at once.
* `POST /auth/refresh` (cookie) rotates the refresh token and returns a new
  access token. Presenting an already-rotated refresh token is treated as
  theft: every refresh token of that user is revoked, the attempt is written
  to the audit log, and the caller must sign in again.
* `POST /auth/logout` revokes the refresh token and, when the request also
  carries the access token, blocks that token until it expires.
* `GET /auth/me` returns the current principal.
* Unknown emails, wrong passwords and disabled, locked or SSO-only accounts
  all get the same `401 invalid_credentials` after the same amount of
  argon2 work. After `auth.max_login_attempts` consecutive failures an
  account is locked for `auth.lockout_minutes` (even the right password
  fails meanwhile). Each attempt is counted before the password is checked,
  so concurrent requests cannot run more than `auth.max_login_attempts`
  checks per lockout window. Without `tenant`, an email registered in
  several tenants is resolved by the password (each account keeps its own
  lockout count); when the password matches in more than one tenant the
  answer is `401 tenant_required` and the client must pass `tenant`.
* The API creates users implicitly only through OIDC just-in-time
  provisioning (`auth.oidc_jit_provisioning`, off by default). The first admin comes from
  `lg-sotf migrate` (`auth.bootstrap_admin_*`) or `lg-sotf create-admin`;
  further users are created through `/users`.

### OIDC (single sign-on)

When `auth.oidc_issuer` is set, bearer tokens from that issuer are accepted:

* signature verified against the issuer's JWKS (`auth.oidc_jwks_url`, or
  the `jwks_uri` of the issuer's discovery document), cached for 10 minutes
  and refetched when a token names an unknown `kid` (key rotation);
* only `RS256` and `ES256`, with the key type matching the algorithm;
* `iss` must equal `auth.oidc_issuer`, `aud` must equal
  `auth.oidc_audience` (required), `exp`/`iat` are checked;
* the tenant comes from the `auth.oidc_tenant_claim` claim (default
  `tenant_id`, falling back to `auth.oidc_default_tenant`), the role from
  `auth.oidc_role_claim` (a string or a list) mapped through
  `auth.oidc_role_map` (without a map the values must be role names); the
  highest mapped role wins, `auth.oidc_default_role` applies when nothing
  maps, otherwise 403;
* with `auth.oidc_jit_provisioning`, a verified identity without a local
  account gets one (no password, linked by the IdP subject; audited as
  `user.provisioned`), whose stored role follows the mapping on later
  sign-ins (`user.role_synced`);
* when the token's email (`auth.oidc_email_claim`) is verified by the IdP
  (the `auth.oidc_email_verified_claim` claim, default `email_verified`, is
  `true`) and a local user with that email exists in
  that tenant, the principal is linked to it. A disabled local account with
  the token's email blocks the SSO login whether or not the email is
  verified; an unverified or missing `email_verified` never links. OIDC never grants platform-admin rights, even when linked to a
  platform-admin account: platform admins sign in with local login. Claiming and deciding escalations and approving
  actions are attributed to a person and need such a provisioned account;
  create SSO-only users with `POST /users` without a password, or turn on
  just-in-time provisioning.

### API keys

* Format `lgk_<32 hex id>_<secret>`, sent as `X-API-Key: <key>` or
  `Authorization: Bearer <key>`. Only a SHA-256 hash is stored; the key is
  shown once, in the `POST /api-keys` response.
* Scopes: `ingest` (the ingest endpoints), `read` (the viewer `GET`
  endpoints), `write` (notes and creating suppression rules). API keys can
  never use administrative endpoints or decide escalations and approvals.

### Tenants and platform admins

A principal acts on its own tenant. Two kinds of caller may send
`X-Tenant-ID: <tenant>` to act on another tenant, and every such request is
recorded in that tenant's audit log:

* a member of an MSSP organisation that holds a live grant to that tenant
  (`grant.tenant_access`): the caller has the grant's role, capped at their
  own role, and no platform-admin powers (see docs/mssp.md, "Delegated
  access"); `GET /auth/me` returns the `grant_id`. They may decide
  escalations and approve actions, but not claim, and not create or change
  users, API keys or grants. Every audit entry they cause is also recorded
  in their organisation's chain (`delegated.<action>`). An API key of the
  organisation acts under a grant to the whole organisation, with `read`
  (viewer grant) or `read` and `write` (analyst or admin grant) at most. On
  the WebSocket the customer is named with `?tenant=<id>`;
* otherwise a platform admin (`users.is_platform_admin`), with their own
  role (`platform_admin.tenant_access`).

Anyone else sending a different `X-Tenant-ID` gets 403. Requests of a suspended tenant's users and API keys
get `403 tenant_suspended` (see docs/mssp.md). Under an
override, rows the admin creates (suppression rules, API keys) carry no
`created_by` (the admin's account belongs to the home tenant; the audit log
names the actor), and claiming, deciding escalations and approving or
rejecting actions are refused with 403: those decisions belong to members of
the tenant. Only a platform admin can modify or delete a platform-admin
account; a tenant admin gets 403.

## Roles

| Role | May |
|---|---|
| `viewer` | read alerts, timelines, escalations, actions, suppressions, dashboard |
| `analyst` | viewer + notes, create suppression rules, claim and decide escalations, approve/reject low and medium risk actions |
| `admin` | everything in the tenant: users, API keys, sources, suppression management, tenant settings, reprocessing, LLM usage, high and critical risk approvals |

The tenant's autonomy policy can disable approval of a risk level entirely.

## Endpoints

| Method | Path | Access |
|---|---|---|
| GET | `/healthz` (liveness), `/readyz` (database and Redis) | none |
| GET | `/metrics` (Prometheus) | `Authorization: Bearer <api.metrics_token>` when configured |
| POST | `/auth/login` | public |
| POST | `/auth/refresh`, `/auth/logout` | refresh cookie |
| GET | `/auth/me` | any principal |
| POST | `/auth/mfa/verify` | MFA challenge token (body) |
| POST | `/auth/mfa/enroll`, `/auth/mfa/confirm` | own account (local session), or the enrollment challenge token (body) |
| GET | `/auth/mfa`; POST `/auth/mfa/disable`, `/auth/mfa/recovery-codes` | own account (local session) |
| POST | `/ingest/alerts` | API key `ingest` |
| POST | `/ingest/webhook/{source_id}` | API key `ingest` |
| POST | `/ingest/email` (raw `message/rfc822`, optional `?reporter=`) | API key `ingest` |
| GET | `/alerts`, `/alerts/counts`, `/alerts/{id}`, `/alerts/{id}/events` | viewer / `read` |
| POST | `/alerts/{id}/notes` | analyst / `write` |
| POST | `/alerts/{id}/reprocess` | admin |
| GET | `/escalations`, `/escalations/{id}`, `/escalations/groups`, `/escalations/{id}/response-preview` | viewer / `read` |
| POST | `/escalations/{id}/claim`, `/escalations/{id}/decision`, `/escalations/bulk/claim`, `/escalations/bulk/close` | analyst (user account) |
| POST | `/escalations/bulk/propose-suppression` (creates a disabled rule) | analyst / `write` |
| GET | `/actions`, `/actions/{id}` | viewer / `read` |
| POST | `/actions/{id}/approve`, `/actions/{id}/reject` | analyst (low/medium), admin (high/critical) |
| POST | `/actions/{id}/rollback` `{reason, approve?}` (201; 409 `rollback_unavailable` with `details[0].reason`), `/actions/{id}/retry` `{reason}` (failed Microsoft actions without a rollback; 409 `retry_unavailable`/`guardrail_blocked`/`cap_reached`), `/actions/{id}/verify` (409 not applicable, 429 within 5 minutes); docs/microsoft.md | analyst (user account); retry: the role that may approve the action's risk |
| GET, POST | `/sources`; GET, PATCH, DELETE `/sources/{id}`; POST `/sources/{id}/test` | admin |
| GET | `/suppressions`, `/suppressions/{id}` | viewer / `read` |
| POST | `/suppressions` | analyst / `write` |
| PATCH, DELETE | `/suppressions/{id}` | admin |
| GET, POST | `/users`; GET, PATCH, DELETE `/users/{id}` | admin |
| POST | `/users/{id}/mfa/reset` (remove MFA, end sessions; audited) | admin (platform admin for platform-admin accounts) |
| GET, POST | `/api-keys`; DELETE `/api-keys/{id}` | admin |
| GET, PATCH | `/tenant/settings` | admin |
| GET | `/onboarding/status`; POST `/onboarding/sample-alerts`, `/onboarding/autonomy-reviewed`, `/onboarding/dismiss` (docs/onboarding.md) | admin |
| GET, PUT | `/onboarding/setup`; POST `/onboarding/setup/complete`: the first-run setup wizard (docs/onboarding.md) | platform admin, own account, home tenant |
| POST, GET | `/platform/tenants`; PATCH `/platform/tenants/{id}`; GET `/platform/escalations`, `/platform/usage` (docs/mssp.md), `/platform/shadow/reports/{id}` (docs/evaluation.md) | platform admin |
| DELETE | `/tenant/verdict-cache` (forget the tenant's cached analyst-benign verdicts; audited) | admin |
| POST | `/tenant/llm/test` (probe the fast and deep model tiers; 6 per tenant per minute; audited) | admin |
| GET | `/tenant/response/routes` (`{dry_run_forced, routes: {action_type: {connector, source, capability, live, problem}}}`) | admin |
| GET | `/dashboard/summary` | viewer / `read` |
| GET | `/usage/llm` | admin |
| GET | `/reports/value`, `/reports/accuracy`, `/reports/detections`, `/reports/monthly` (docs/reporting.md) | viewer / `read` |
| POST | `/reports/detections/propose-suppression` (creates a disabled rule) | analyst / `write` |
| GET | `/reports/blind-audit` (production false-negative estimate from blind audits) | viewer / `read` |
| GET | `/blind-audit/items`, `/blind-audit/items/{id}` (the blind queue: no AI verdict before the label) | analyst (user accounts) |
| POST | `/blind-audit/items/{id}/label` (`malicious`, `benign`, `unsure`; once; reveals the AI verdict) | analyst (user accounts) |
| GET | `/blind-audit/runs` (sampling runs: window, seed, frame, counts) | viewer / `read` |
| POST | `/blind-audit/runs` (draw a sample now, server seed; `dry_run` records nothing) | admin, not under an MSSP grant |
| GET | `/audit`, `/audit/verify` | admin |
| GET | `/alerts/{id}/evidence?format=json\|html` (case evidence pack; audited) | viewer / `read` |
| POST | `/alerts/{id}/incident-report` (NIS2 draft; stored on the timeline) | analyst / `write` |
| GET | `/platform/tenants/{id}/erasure`; POST `/platform/tenants/{id}/export`; DELETE `/platform/tenants/{id}` | platform admin |
| GET, POST | `/integrations`; GET, PATCH, DELETE `/integrations/{id}`; POST `/integrations/{id}/test`; GET `/integrations/{id}/deliveries` | admin |
| GET | `/integrations/microsoft/catalog` (Microsoft capabilities, clouds and Defender regions; docs/microsoft.md) | admin |
| GET | `/tickets?alert_id=` or `?escalation_id=` (linked Jira/ServiceNow tickets) | viewer / `read` |
| POST | `/integrations/slack/interactions?tenant=&integration=` (Slack Interactivity; Slack signing secret, no bearer token) | Slack signature |
| WS | `/ws?token=<access token>` | viewer |

`/healthz`, `/readyz` and `/ws` are also served under `/api/v1`.
`/metrics` is served at the root only, so an ingress that routes `/api`
publicly never exposes it; set `api.metrics_token` (an empty value refuses every scrape) or keep the root path
network-restricted. `/readyz` reports 503 only when the database is unreachable or
Redis fails; a database whose pool is fully busy counts as ready.

### Ingestion

* `POST /ingest/alerts` takes canonical alerts (see
  `lg_sotf.ingestion.normalizers.canonical`) as a JSON array or as
  `{"alerts": [...]}`, at most `api.max_ingest_batch` per request and
  `api.max_ingest_body_bytes` per body. They are stored under the source id
  `api:<api key id>`.
* `POST /ingest/webhook/{source_id}` takes a vendor-native JSON object (or an
  array of them) for a push source (`webhook`, `guardduty`) registered in
  the key's tenant; the source's configuration picks the normalizer.
* `POST /ingest/email` takes one raw email (`Content-Type: message/rfc822` or
  `application/octet-stream`, at most `ingestion.email.max_message_bytes`,
  10 MB by default), usually a user's report with the suspicious message
  attached; `?reporter=<address>` names the reporting user. It is parsed
  server-side and stored under `email:<api key id>`, deduplicated on the
  reported message's Message-ID plus the reporter. See `docs/phishing.md`.
* All three answer `202` with one result per submitted event, in order:
  `{"index", "status": "inserted"|"duplicate"|"rejected", "alert_id", "reason"}`,
  plus totals and the number of alerts queued for the workers. Duplicates
  (same source and source alert id) are never inserted twice.

### Alerts

`GET /alerts` filters: `status`, `severity`, `disposition`, `source_id`,
`from`/`to` (ingestion time), `closed_from`/`closed_to` (closing time; only
closed alerts match), `q` (title substring). A `q` search is limited
to a window of at most 93 days (default: the 30 days before `to`); a wider
window is a `400 search_window_too_large`. Notes are stored as `note`
events on the alert timeline. `reprocess` requeues a finished alert (409
while its run is active).

Every alert carries `source_name` (null once the source is deleted) and
`entities_preview`: `{"items": [{"kind", "value"}], "counts": {kind: n}}`,
the first value of up to three entity kinds (users, hosts, IPs, e-mails,
domains, URLs, processes, hashes, in that order) and how many values each
kind present has; null without entities. `GET /alerts/{id}` also lists
`findings`: one entry per provider result of the analysis agent's lookups,
`{origin: "threat_intel"|"history", kind, target, source, status, verdict,
checked_at, cached, data}`; `checked_at` is when the platform received the
result (null for analyses recorded before it was stored).

`GET /alerts/counts?closed_from=&closed_to=` returns `{by_status,
closed_from, closed_to, generated_at}`: the number of alerts in every status,
all-time except `closed`, which counts alerts closed in the window (default:
from today 00:00 UTC, no end). It is cached for 15 seconds per tenant and
window.

### Escalations and actions

* `GET /escalations` filters: `status`, `level`, `assigned_to` (a user id,
  `me`, or `none` for unassigned), `decided_by` (a user id or `me`),
  `overdue=true` (active escalations past their deadline) and `alert_id`.
  `order=created_at` (default) lists newest first; `order=sla_deadline`
  lists the soonest deadline first, so overdue escalations come first and
  escalations without a deadline last. Both are keyset-paginated.
* Every escalation carries `assigned_to_email`, `decided_by_email`, and a
  digest of its alert: `alert_severity`, `rule` (the detection rule name,
  else the title), `source_id`, `source_name` and `entities_preview` (as on
  alerts). `ai_reason` is the first sentence of the analysis conclusion,
  `ai_reason_source` `model` or `rules` (who wrote it). `routing` is
  `{code, confidence, band}`: the routing code that opened the escalation
  (`grey_zone`, `false_positive_review`, `inconclusive`, `model_refused`,
  `llm_normalized`, `analyst_request`, `response_review`, `group_review`,
  `blind_audit`)
  and, for `grey_zone` when the confidence was inside it, the band
  (`{min, max}`, `routing.correlation_grey_zone_min`..`_max`). Escalations
  opened before this was recorded have `routing` and `ai_reason_source`
  null.
* `GET /escalations/groups?assigned_to=&min_size=2&limit=50` groups the open
  and claimed escalations by their alert's `source_id` and `rule`, largest
  first (at most 100 groups; `truncated` says more matched): `{source_id,
  source_name, rule, size, unassigned, overdue, earliest_sla_deadline,
  min_confidence, max_confidence, by_severity, escalation_ids}` (up to 10
  ids, soonest deadline first). `GET /escalations?source_id=&rule=` lists a
  group's escalations.
* Bulk triage takes at most 50 escalations, each once (422 otherwise).
  `POST /escalations/bulk/claim` `{"items": [{"escalation_id", "version"}]}`
  and `POST /escalations/bulk/close` `{"items", "notes", "decision"?:
  "false_positive"|"benign_positive", "propose_suppression"?}` run the
  single-escalation claim or decision for each item, in order, each in its
  own transaction and audited the same way, and answer 200 with per-item
  results: `{results: [{escalation_id, ok, escalation, error: {status,
  code, message}, resumes_enqueued, resumes_failed}], succeeded, failed,
  suppression, suppression_created}`. An item's `error` is what the
  single endpoint would have answered (404 `not_found`, 409 `conflict` for
  a stale version, 409 `invalid_transition`, 403 `forbidden`); the other
  items still go through and committed items stay committed. With
  `propose_suppression`, one disabled rule is proposed from the closed
  escalations (no per-escalation suggestion is made).
* `POST /escalations/bulk/propose-suppression` `{"escalation_ids", "name"?}`
  is all or nothing: 404 when an escalation is not found, 422
  `not_confirmed_benign` (`details` lists them) when one has no
  `false_positive` or `benign_positive` decision. Otherwise one disabled rule
  matching the alerts' fingerprints and sources, up to the most severe of
  their severities: 201 `{suppression, created: true, escalation_ids}`, or
  200 with the unexpired rule that already has the same match.
* `GET /escalations/{id}/response-preview` computes the plan a
  `true_positive` decision would produce, without writing anything or
  calling a connector: `{escalation_id, alert_id, generated_at,
  threat_type, evidence: "analyst", dry_run_forced, actions: [{action_type,
  target, description, risk, reversible, inverse_action, irreversible_note,
  connector: {name, source, live, ready}, guardrail: {verdict, code,
  reason}, autonomy, without_preapproval: "automatic"|"awaiting_approval"|
  "blocked", can_preapprove, role_lock: null|"admin"|"disabled",
  approval_entry}]}`. `can_preapprove` and `role_lock` are for the caller's
  role; `approval_entry` is the `approved_actions` entry for that action.
  The final plan is computed from the alert as it is when the decision is
  recorded.
* Claim and decision bodies carry the escalation's `version`; a stale
  version is `409 conflict` (re-read and retry). A claim or decision on a
  decided or cancelled escalation is `409 invalid_transition`, whatever the
  version: retrying cannot help. Claims and decisions on escalations whose
  SLA expired are accepted and audited with `after_sla_expiry`; a claimed
  expired escalation keeps the status `expired` and gets the assignee.
* `POST /escalations/{id}/decision`:
  `{"decision": "true_positive"|"false_positive"|"benign_positive"|"needs_more_info",
  "version", "notes"?, "approved_actions"?, "feedback"?, "suggest_suppression"?}`.
  The decision resumes the escalation's alert and every alert attached to
  it; the response lists them and how many resume messages were queued.
* Approvals are per action: `POST /actions/{id}/approve` approves that
  action only; the alert's other pending actions stay pending unless the
  body sets `{"reject_remaining": true}`. The approver's role comes from the
  principal, never from the request.
* `GET /actions` also filters on `verification` (`pending`, `verified`,
  `failed`, `inconclusive`). Every action carries `execution_owner`,
  `integration_id`, `external_ref`, `attempts`, `verification` (with
  `verification_detail`, `verify_deadline`, `verified_at`), `rollback`
  (eligibility: `available`, `action_type`, `risk`, `until`, `reason`) and
  `rolled_back_by`; see docs/microsoft.md.
* Every action also carries `reversible` (its type has an inverse),
  `irreversible_note`, and `blast_radius`: `{target_kind, scope_hosts}`
  and, while it awaits approval, the limits it will be checked against when
  it executes: `hourly_limit` and `executed_last_hour` for its type,
  `tenant_hourly_cap` and `tenant_executed_last_hour`. An action awaiting
  approval carries `guardrail` `{verdict: "passed"|"blocked", evaluated:
  "now", code, reason, approval_reason}`, the guardrails checked again
  against the tenant's current policy (`approval_reason` is why a human
  must approve, e.g. `admin_approval_required`, `llm_only_evidence`); a
  blocked action carries the recorded one (`evaluated: "recorded"`).
* A response the policy chose on its own (no analyst `true_positive`
  decision) closes the alert only when an action really `succeeded` through
  a connector. When every approved action ran as `dry_run` (the default),
  the alert is escalated again (L3, "automatic response left the threat
  without a human or a completed action") and closes after that decision.

### Sources

Source credentials are write-only: send them in `secret` (an object) on
create or update; they are encrypted with the install's keys, bound to the
tenant and source, and responses only show `has_secret`. `"secret": null`
removes them. Configuration keys that look like credentials are refused in
`config`. A source is validated (configuration, required credentials and
the outbound destination policy) before it is saved; `POST
/sources/{id}/test` checks connectivity without ingesting.

### Suppression rules

Analysts (and `write` API keys) create rules; admins update, enable/disable
and delete them. Only admins create rules that are active immediately: a rule
created by an analyst or an API key is stored with `enabled: false` whatever
the request says, and takes effect once an admin enables it (`PATCH
{"enabled": true}`). Rules suggested from false-positive decisions are also
created disabled, and match only the decided alert's severity and below
(`{"severity": {"in": [...]}}`), never a more severe alert of the same
detection. A rule whose every predicate matches any alert (all
severities, a `.*` regex, a `/0` network) is refused with 422
`invalid_rule`.

### Users and API keys

Passwords must have at least `auth.password_min_length` characters, at most
1,024, and at least 4 different characters (the CLI applies the same rules). Admins
cannot change their own role or active status, delete themselves, or remove
the tenant's last active admin; only platform admins grant the platform-admin
flag. Password changes and deactivation revoke the user's refresh tokens.
Password hashes and API key hashes are never returned.

### Tenant settings

`GET /tenant/settings` returns the settings with secrets replaced by
`<name>_configured: true`. `PATCH` is a merge patch (`null` removes a key)
over: `autonomy`, `protected_assets` (`hosts`, `users`, `domains`, `cidrs`,
`processes`, `hashes`), `protected_cidrs`, `response`
(connector, webhook URL, `webhook_secret`, guardrail limits),
`llm_daily_token_budget`, `review` (SLA and grouping policy), `tools`
(`<provider>.api_key`, `<provider>.enabled`, `internal_domains`),
`retention` (`alerts_days`, `indicators_days`, merged key by key, within the
install's `retention.tenant_min_days`..`tenant_max_days`, which responses
return as `retention_limits`), `security` (`require_mfa`: force TOTP MFA
for local accounts), `reporting` (`minutes_per_alert`, 1-480, default 15:
the value report's hours-saved estimate), `blind_audit` (`enabled`,
default false; `sample_rate`, default 0.02; `min_per_week`, default 5: the
weekly blind-audit sample, docs/reporting.md), `phishing` (`protected_brands`,
`executives`, `trusted_authserv_ids`; see `docs/phishing.md`) and `triage`
(`known_scanners`: up to 256 host names, IP addresses or CIDR ranges of the
tenant's own vulnerability scanners; an alert whose activity comes from one
(a source address or host field of the event, never a victim or destination)
gets the `known_scanner` false-positive signal; the section is
replaced whole) and `ai_closure` (`tier`: `off`, the default, or
`auto_full_audit`, which lets both model tiers close a low or medium alert
on their own under the conditions of `docs/architecture.md`, decision policy
v2; such closes carry the close reason `ai_closed:audit_required`; the
section is replaced whole, and the audit event records the tier set; a new
tenant never copies it from a template). Secrets
(`response.webhook_secret`, `tools.<provider>.api_key`) are encrypted before
they are stored and cannot be read back; ciphertext fields cannot be written
directly. Invalid settings are refused with `422 invalid_settings` listing
every problem. Concurrent `PATCH` requests are serialised on the tenant row,
so edits of different sub-keys of one section never overwrite each other.

### Model test

`POST /tenant/llm/test` sends one tiny structured request (no alert data) to
each model tier through the same path as triage and returns
`{provider, enabled, ok, tiers: [{tier, model, ok, latency_ms,
structured_output, error_code, error}]}`. `error_code` is one of
`disabled`, `unavailable` (configuration), `timeout` (60 s per tier),
`connection`, `http_error`, `refusal`, `invalid_output` or `error`; `error` is
a message written by the server with a hint (never the provider's response
text, URL or key). The calls are metered to the tenant as agent `llm_test`
and every test writes a `tenant.llm_tested` audit entry. More than 6 tests per
tenant per minute answer `429`.

### Integrations

Notification channels (Slack, Teams, email, signed webhook) and ticketing
(Jira, ServiceNow); see `docs/integrations.md`. Credentials are write-only
(`secrets: {field: configured}` in responses; `secret` on update is a merge
patch). Invalid configuration is `422 invalid_integration`. `POST
/integrations/{id}/test` sends a test message (ticketing: checks credentials
and project) and logs it in the delivery log.

### Dashboard and usage

`GET /dashboard/summary?window_hours=24` returns counts by status, severity
and disposition, MTTA/MTTR, open escalations, unfinished workflow runs by
status (the tenant's queue depth; completed and dead-lettered runs are not
counted) and LLM tokens and cost; it is cached for 15 seconds
per tenant and window. It also carries `handled_without_human`,
`needed_human`, `handled_without_human_rate` and `analyst_hours_saved`
(definitions in docs/reporting.md). The escalation queue figures count
active escalations: `overdue_escalations`, `unassigned_escalations`,
`unassigned_breaching`, `next_sla_deadline` (the earliest deadline still
ahead) and `open_escalations_by_severity` (by the alert's severity); the
approval queue figures are `pending_approvals_total` and
`pending_approvals_by_risk`. `pending_approvals` (what the caller's role may
approve under the tenant's autonomy policy) and `my_claimed` (active
escalations assigned to the caller) are computed for each request, never
cached. `llm_model` is the model of the deep tier, which writes the analysis
verdicts (null when LLM use is off). `GET /usage/llm?from=&to=` returns daily
usage rows (at most 400 days).

### Reports

`/reports/value`, `/reports/accuracy` and `/reports/detections` take
`from`/`to` (UTC dates, at most 366 days, default the last 30; `400
invalid_window` otherwise) and are cached for 60 seconds per tenant and
window; value and detections also answer `format=csv`.
`/reports/monthly?month=YYYY-MM` returns a self-contained HTML report (its
own Content-Security-Policy allows only its inline stylesheet, by hash) or
`format=json`. `POST /reports/detections/propose-suppression` with
`{"source_id", "rule_field": "rule_name"|"title", "rule", "from"?, "to"?}`
creates a disabled suppression suggestion (201; 200 with the existing rule
when an identical unexpired one exists; `422 no_confirmed_benign` without
an analyst-confirmed benign alert of that detection in the window). Metric
definitions: docs/reporting.md.

### Blind audit (beta)

`GET /blind-audit/items?status=pending|labelled` lists sampled auto-closed
alerts (pending oldest first, labelled newest first; keyset `cursor`).
Items carry the alert as its source sent it (`alert`: title, severity,
source, category, times, `entities_preview`; `raw` and `normalized` on
`GET /blind-audit/items/{id}`) and never the AI's disposition, confidence,
scores, routing, summary or reasoning: `reveal` is `null` until the item
is labelled. `POST /blind-audit/items/{id}/label` with `{"label":
"malicious"|"benign"|"unsure", "notes"?}` records the label once (`409`
after) and returns `{item, escalation_id, escalation_created}` with
`item.reveal` (`ai_class`, `agreement`, `disposition`, `confidence`,
`threat_score`, `close_reason`, `routing_code`, `conclusion`); a malicious
label opens an escalation (routing code `blind_audit`); deciding it
re-queues an alert whose run has ended, and the new run starts at that
decision. These need an analyst or admin signed in as themselves (no API
keys, no platform override; MSSP staff under a grant may label, attributed
to their organisation). `POST /blind-audit/runs` (the tenant's own admins,
`ADMIN_NOT_UNDER_GRANT`) takes `to` (default and at most 5 minutes ago),
`sample_rate`, `min_per_week` or `size`, and `from` only for the tenant's
first run (a run starts where the last one ended: `409
window_not_contiguous` otherwise); the seed is the server's (`seed_source`).
With `"dry_run": true` it returns `{window_start, window_end, seed,
frame_size, sample_size, alert_ids}` (200) and records nothing; only a dry
run takes `seed` (`400 seed_needs_dry_run` otherwise). `GET
/reports/blind-audit?from=&to=` returns the stratified estimate
(docs/reporting.md, "Blind audit").

While an alert waits for its blind-audit label, its AI side is withheld
from every caller: `GET /alerts` and `GET /alerts/{id}` return
`hidden_for_blind_audit: true`, `disposition`, `confidence`, `threat_score`
and `priority` null, `summary` `{"hidden_for_blind_audit": true}` and no
`findings`, and a `disposition` filter leaves it out; `GET
/alerts/{id}/events` returns only `ingested` and `note` events; its
escalations and response actions are `404` (`GET /escalations/{id}`,
`/escalations/{id}/response-preview`, `/actions/{id}`) and left out of `GET
/escalations` and `GET /actions`; `GET /audit` entries about it carry
`details` `{"hidden_for_blind_audit": true}` and `redacted: true`; the
evidence pack withholds every section that names the verdict; WebSocket
events carry no data; `POST /alerts/{id}/reprocess` is `409
hidden_for_blind_audit`; `GET /dashboard/summary` counts leave it out; and
other alerts' `summary.correlation` no longer lists it in
`related_alert_ids` or counts it in `related_dispositions`.

### Audit log

`GET /audit` lists the tenant's audit entries newest first (keyset
pagination with `cursor`, `limit` at most 200) with exact filters `action`,
`resource_type`, `resource_id`, `actor_id` and a `from`/`to` time window.
Each entry carries its `prev_hash` and `hash` (a SHA-256 chain per tenant).
`GET /audit/verify?from=` recomputes the chain and answers
`{"ok": true}` or `{"ok": false, "first_bad_id": <id>}`. Entries record who
did what (logins, user and API key changes, sources, settings, suppression
rules, claims, decisions, approvals and response execution, platform-admin
`X-Tenant-ID` access); they never contain secrets or raw alert bodies.

### Compliance

`GET /alerts/{id}/evidence` returns the alert's evidence pack (JSON, or
printable HTML with `format=html`) sealed with `integrity.bundle_sha256` and
an HMAC signature; the export is audited and the digest is repeated in the
`X-Evidence-Bundle-SHA256` header. `POST /alerts/{id}/incident-report` with
`{"stage": "early_warning"|"notification"|"final", "include_ai_narrative"}`
drafts a NIS2 Article 23 report (201; a draft only, never submitted).
Platform admins export a tenant (`POST /platform/tenants/{id}/export`,
streamed ZIP of JSONL files without secrets) and erase a *suspended* tenant
(`DELETE /platform/tenants/{id}` with `{"confirm": "<id>"}`; 409
`tenant_not_suspended`/`erasure_blocked`, 422 `confirmation_mismatch`); the
audit log is retained. See [compliance.md](compliance.md).

### Live events (WebSocket)

Connect to `/ws?token=<access token>` (API keys are not accepted in URLs;
browser connections must come from an allowed CORS origin). After a
`{"type": "hello"}` message the socket receives the tenant's events
(`alert.created`, `alert.updated`, `escalation.created`,
`escalation.updated`, `action.updated`) and periodic `{"type": "ping"}`.
Add `&tenant=<id>` to stream a customer tenant under an MSSP grant; a
revoked or expired grant closes the socket with 1008.
Delivery is at-most-once: after a reconnect, re-read state from the REST
API. The server closes the socket with code 4401 when the token expires or
is revoked by a logout (reconnect with a fresh token), 1013 when the client
falls behind, the server is at capacity or the principal
(`api.ws_max_per_principal`, default 5) or tenant (`api.ws_max_per_tenant`,
default 100) already holds its share of sockets, and 1008 on policy
violations, including a disabled or deleted account or a suspended tenant.
An open socket re-checks its token, account and tenant every
`api.ws_revalidate_s` (default 15 s).

## Limits and hardening

* Request bodies are limited to `api.max_body_bytes` (ingest:
  `api.max_ingest_body_bytes`), enforced while the body streams in, so
  chunked uploads cannot exceed it.
* Fixed-window rate limits in Redis, per minute: `api.rate_limit_per_minute`
  per principal, `api.ingest_rate_limit_per_minute` per API key on the
  ingest endpoints, `api.login_rate_limit_per_minute` per (client address,
  email) on login with a per-address cap of ten times that on *failed*
  logins (users signing in correctly through one proxy address are never
  refused because of each other), and per refresh
  token on refresh/logout. Failed authentications are counted per address:
  once an address is over its budget, further *failing* requests get 429
  instead of 401, and a credential that keeps failing is refused before it
  is checked; credentials that verify are never throttled by other clients'
  failures. Client addresses come from `X-Forwarded-For` only for proxies in
  the server's `forwarded_allow_ips`; set it to the ingress controller's
  addresses, otherwise every client shares the ingress address. Limited requests get `429` with `Retry-After`. If
  Redis is unreachable, limits are not enforced (account lockout still
  applies).
* CORS allows only `api.cors_origins`, with credentials; a `*` entry is
  ignored.
* The cookie endpoints (`POST /auth/refresh`, `/auth/logout`) refuse a
  browser request whose `Origin` is not the API's own host, `api.public_url`
  or an `api.cors_origins` entry, and any `Sec-Fetch-Site: cross-site`
  request (`403`): `SameSite=Strict` does not stop a sibling subdomain.
* Ingest requests in flight per API process are capped at
  `api.max_inflight_ingest` (64); more get `503 overloaded` with
  `Retry-After: 1` at once instead of queueing on the database pool. One
  process sustains roughly 70 single-alert requests per second; send batches
  (about 50 alerts per request gives roughly ten times the throughput) or run
  more API replicas.
* Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, a restrictive `Content-Security-Policy` (`frame-ancestors 'none'`),
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and, over HTTPS,
  `Strict-Transport-Security`. Run behind a TLS-terminating proxy listed in
  `api.forwarded_allow_ips` so the scheme and client address are correct.
* Access logs are structured JSON (method, route template, status,
  duration, client address, tenant, principal, request id); they never
  contain bodies, query strings or credentials.
