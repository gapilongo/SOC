# SOAR playbooks: run LG-SOTF actions in your own SOAR

This guide is for teams that already run a SOAR (Tines, Shuffle, Tracecat,
n8n, or their own automation) and want LG-SOTF's approved response actions to
run there. LG-SOTF's **webhook connector** sends one HMAC-signed `POST` per
approved action; your SOAR verifies it, performs the action with its own
vendor integrations, and answers with the outcome, which LG-SOTF records on
the action ledger.

The repository ships ready-made starting points under `examples/soar/`:

| Path | What it is |
|---|---|
| `examples/soar/receiver/lgsotf_receiver.py` | Reference receiver in Python (standard library only, 3.10+): signature and timestamp checks, deduplication in SQLite, dispatch by action type, the response contract, HTTPS, a gateway mode that forwards verified actions to another SOAR, and a `send-test` command that posts a signed test action |
| `examples/soar/receiver/lgsotf_handlers.py` | One handler stub per action type, with example vendor calls. Every stub answers `rejected` / `not_implemented` until you connect it |
| `examples/soar/n8n/lg-sotf-response.json` | Importable n8n workflow: webhook, signature check, one branch per action type with a placeholder HTTP Request node, response |
| `examples/soar/n8n/build_workflow.py`, `examples/soar/n8n/code/` | The workflow's generator and the source of its Code nodes, for maintainers: edit them and regenerate the JSON |

The wire format is defined in `lg_sotf.services.connectors.webhook` and its
signature in `lg_sotf.security.signing`; the tests in `tests/unit/examples/`
sign requests with that code, so the templates cannot silently drift from it.

## Go live in an afternoon

1. **Pick a receiver.** n8n: import the workflow ([n8n](#n8n)). Tines: verify
   natively ([Tines](#tines)). Shuffle, Tracecat or any SOAR that cannot check
   an HMAC over the raw body: put the reference receiver in front of it in
   gateway mode ([Shuffle](#shuffle), [Tracecat](#tracecat)). No SOAR: fill in
   the reference receiver's handlers ([Reference receiver](#reference-receiver)).
2. **Create the shared secret** (at least 16 bytes; use 32 random bytes):
   `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Store it
   in your secret manager, the receiver's configuration and LG-SOTF. Never
   put it in a workflow export, a URL or a ticket.
3. **Expose the receiver over HTTPS** at an address LG-SOTF can reach
   ([network rules](#install-prerequisites-operator)).
4. **Test the receiver** before LG-SOTF uses it:
   `LGSOTF_WEBHOOK_SECRET=... python3 examples/soar/receiver/lgsotf_receiver.py send-test --url https://soar.example.com/...`
   posts one signed `send_alert` action and prints the answer. A forged
   request must get `401`: run it once more with a different secret.
5. **Point LG-SOTF at it** ([tenant settings](#tenant-settings-admin)) with
   `approval` autonomy for every risk level you allow and a short
   `allowed_actions` list, approve a first real action, and check the ledger
   entry and your SOAR's run.
6. **Widen step by step**: more action types, then `auto` for low risk only
   where rule evidence is strong (see the rollout in `docs/user-guide.md`).

## The request

`POST <webhook_url>` with `Content-Type: application/json` and
`User-Agent: lg-sotf-response/1`.

| Header | Value |
|---|---|
| `X-LGSOTF-Timestamp` | Unix time in seconds when this attempt was signed. Every retry is signed again when it is sent. |
| `X-LGSOTF-Signature` | `v1=` followed by the lower-case hex HMAC-SHA256 of `"<timestamp>.<raw body>"`, keyed with the shared secret. |
| `Idempotency-Key` | The action id: the same value as the signed body field `action.id`. It is identical on every retry and every re-execution. It is **not** signed. |
| `X-LGSOTF-Event` | `response_action.execute` |
| `X-LGSOTF-Delivery` | A UUID per execution, for your logs. Retries of one execution share it. |

The body is canonical JSON (UTF-8, sorted keys, compact separators). Schema
`lg-sotf.response-action.v1`: keys are stable, new keys may be added, so
ignore keys you do not know.

```json
{
  "schema": "lg-sotf.response-action.v1",
  "event": "response_action.execute",
  "sent_at": "2026-09-29T12:00:00+00:00",
  "tenant_id": "acme",
  "action": {
    "id": "<action id, a UUID>",
    "idempotency_key": "<sha256 hex>",
    "type": "isolate_host",
    "target": "ws-042",
    "target_type": "host",
    "risk_level": "high",
    "params": {"playbook": "malware", "evidence": "rules", "explanation": "approved: ..."},
    "requested_by": "agent:workflow",
    "approved_by": "<user id> | policy:auto",
    "approved_at": "2026-09-29T11:59:00+00:00"
  },
  "alert": {"id": "<alert id>", "severity": "high", "title": "C2 beacon from ws-042"},
  "rollback_of": null
}
```

| Field | Meaning |
|---|---|
| `sent_at` | When this execution started (the same on its retries). |
| `tenant_id` | The LG-SOTF tenant. A receiver on an install-wide webhook serves several tenants: check it. |
| `action.id` | The ledger action id. **Deduplicate on it.** |
| `action.idempotency_key` | Identifies the planned action (tenant, alert, type, target). |
| `action.type`, `action.target`, `action.target_type` | What to do and to what. Target kinds: `ip`, `domain`, `url`, `hash`, `user`, `host`, `process`, `email`, `message`, `alert` (`alert:<id>`). |
| `action.risk_level` | `low`, `medium`, `high` or `critical`. |
| `action.params.scope.hosts` | `terminate_process` and `quarantine_file` only: the hosts the alert concerns. Act on these hosts only; an empty list means no host is known, so do not act fleet-wide. |
| `action.params.match` | `purge_message` only: `internet_message_id`, and `sender` and `subject` when known. Match all of them: a Message-ID is chosen by the sender. |
| `action.params.reporter` | `notify_reporter` only: the address to notify. |
| `action.params.playbook`, `evidence`, `explanation`, `approval_reason` | Why LG-SOTF planned and approved the action: useful in tickets and logs. |
| `approved_by` | The approving user's id, or `policy:auto` for an automatic approval under the tenant's autonomy policy. |
| `rollback_of` | `null`, or for a rollback the id of the action it undoes ([Rollbacks](#rollbacks)). |
| `action.params.rollback` | Rollbacks only: `of` (the same id), `reason` and `requested_by`. |

### Verifying the signature

A request is authentic when all of these hold. Check them **before** parsing
or acting on the body.

1. `X-LGSOTF-Timestamp` is a decimal integer and at most **300 seconds** from
   your clock, in either direction (keep the receiver on NTP).
2. `X-LGSOTF-Signature` equals `v1=` + hex HMAC-SHA256(secret, timestamp +
   `"."` + raw body), compared in **constant time**. Use the raw bytes as
   received: a body that was parsed and serialised again no longer matches.
3. If `Idempotency-Key` is present, it equals the signed `action.id`.
   Otherwise a captured request could be replayed inside the window under a
   new key.

```python
expected = "v1=" + hmac.new(secret, timestamp.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
authentic = hmac.compare_digest(expected, signature) and abs(time.time() - int(timestamp)) <= 300
```

```javascript
const expected = 'v1=' + crypto.createHmac('sha256', secret).update(timestamp + '.').update(rawBody).digest('hex');
const authentic = expected.length === signature.length
  && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))
  && Math.abs(Date.now() / 1000 - Number(timestamp)) <= 300;
```

Answer every failed check with the same `401`, so the sender learns nothing
about which check failed. To rotate the secret, have the receiver accept the
old and the new secret (the reference receiver reads
`LGSOTF_WEBHOOK_SECRET_PREVIOUS`), change it in LG-SOTF, then remove the old one.

## The response contract

| Your answer | What LG-SOTF records |
|---|---|
| `2xx` with a JSON object whose `status` is `failed`, `error` or `rejected` (any case) | `failed` (`error: receiver_reported_failure`), not retried |
| any other `2xx` (JSON or not) | `succeeded` |
| `429` or `5xx` | retried with exponential backoff and jitter, at most 3 retries; a `Retry-After` of up to 15 s is honoured, a longer one fails the action at once |
| a network error or timeout | retried like a `5xx` |
| a redirect (`3xx`) | `failed` (`unexpected_redirect`): redirects are never followed |
| any other status (`401`, `404`, `409`, `422` ...) | `failed`, not retried |

The JSON object in a `2xx` answer is stored on the ledger row after
redaction (values under keys that look like secrets, such as `token` or
`api_key`, are replaced by `[REDACTED]`); more than 2,000 characters are stored as
`{"_truncated": true}` and more than 64 KiB fail the action. The templates
answer:

```json
{"status": "succeeded", "action_id": "5f0c...", "action_type": "isolate_host", "reference": "<vendor job or rule id>", "detail": {"http_status": 201}}
{"status": "failed", "action_id": "5f0c...", "action_type": "isolate_host", "error": "vendor_error", "message": "EDR answered 403"}
{"status": "rejected", "action_id": "5f0c...", "action_type": "release_host", "error": "not_implemented"}
```

Use `succeeded` when the change was made or was already in place, `failed`
when it was attempted and did not happen, and `rejected` when it was not
attempted (not implemented, not allowed on this receiver, unknown action
type). Never answer `succeeded` for an action type you do not handle.

**Timing.** Each attempt times out after `response.webhook_timeout_s`
(15 s by default). All attempts of one execution share a deadline of a third
of `worker.node_timeout_s`, at most 60 s; when it passes, the action is
`failed` with `error: deadline` and its outcome is unknown. Answer within a
few seconds: start long jobs (a forensic package, a mailbox-wide purge),
return once the vendor accepted them, and put the vendor's job id in
`reference`.

**Performed or accepted.** A `2xx` means "performed or accepted". A SOAR that
answers as soon as it has queued the run (Shuffle, Tracecat's default
webhook, a Tines webhook without an Exit response) makes the ledger say
`succeeded` before anything happened, and failures then show only in the
SOAR. Prefer answering after the vendor call, as the n8n workflow, the
reference receiver and a response-enabled Tines story do.

## Idempotency

LG-SOTF delivers **at least once**. The same action arrives again when a
retry follows a lost answer (same body, new timestamp and signature), and when
a worker died during the call and the action is executed again (new
`sent_at`, new `X-LGSOTF-Delivery`, same `action.id`). Therefore:

* Deduplicate on the **signed** `action.id`. The `Idempotency-Key` header is a
  copy for platforms that deduplicate on headers; if you use it, check it
  against `action.id` as above.
* Answer a repeated id with the **original answer** (status and body), and
  never act twice. The reference receiver adds `Idempotent-Replayed: true` to
  such answers.
* While the first request for an id is still running, answer `503` with a
  short `Retry-After` (at most 15 s): LG-SOTF retries and then gets the stored
  answer.
* A request with a known id but a different tenant, type or target is not a
  retry: refuse it (the reference receiver answers `409`).
* Keep answers for days, not minutes (the reference receiver: 30 days; the
  n8n workflow: 7 days). An action LG-SOTF recorded as `failed` with
  `error: orphaned_execution` or `deadline` has an unknown outcome: look its
  id up in the receiver's store (`sqlite3 lgsotf-receiver.sqlite3 "select
  state, reply from lgsotf_actions where action_id = '<id>'"`) before acting
  by hand.
* Make the vendor side idempotent too: look for an existing indicator, block
  rule or pending machine action before creating one, and treat "already
  isolated" or "already disabled" as `succeeded`.

## Set up the webhook connector in LG-SOTF

### Install prerequisites (operator)

* `LG_SOTF_RESPONSE__DRY_RUN=false`. The install-wide default is `true`:
  every action is recorded as `dry_run` and nothing is sent anywhere,
  whatever the tenants configure.
* The destination is checked before every call: `https` only in staging and
  production; loopback, link-local and cloud-metadata addresses are always
  refused; private (RFC 1918 / ULA) addresses only when the install sets
  `ingestion.allow_private_destinations: true`. A refused destination fails
  the action with `error: destination_refused`.
* TLS certificates are always verified. For a private CA, the tenant stores
  its certificate in `response.ca_cert_pem`; with `tls_verify: false` every
  action fails with the reason.
* Optional install-wide webhook: `response.webhook_url` and
  `response.webhook_secret` serve every tenant that selects the webhook
  connector without its own URL. They all share that secret, so the receiver
  must check `tenant_id` (the reference receiver's `--tenants`).

### Tenant settings (admin)

In the web app, **Tenant settings > Response**: connector **webhook (SOAR)**,
the **Webhook URL**, the **Webhook signing secret** (write-only: it is
encrypted with the tenant's key and never shown again), and leave **Dry run**
on until the receiver passed its test. Through the API, once it has:

```http
PATCH /api/v1/tenant/settings
Content-Type: application/json

{"response": {"connector": "webhook",
              "webhook_url": "https://soar.example.com/lgsotf/actions",
              "webhook_secret": "<the shared secret>",
              "allowed_actions": ["send_alert", "create_ticket", "block_ip"],
              "dry_run": false},
 "autonomy": {"low": "approval", "medium": "approval", "high": "approval", "critical": "disabled"}}
```

`GET /api/v1/tenant/settings` then shows `webhook_secret_configured: true`
instead of the secret. The webhook URL is not a secret field: every tenant
admin can read it, so a URL that embeds a token is only as private as the
admin role. The guardrails (protected assets, internal IP addresses,
critical processes, internal senders), approvals, autonomy, the hourly cap
and the per-action blast-radius limits all apply before anything is sent; a
blocked action never reaches the SOAR.

## Recipes

### Reference receiver

Copy `examples/soar/receiver/` to the host, fill in the handlers you need in
`lgsotf_handlers.py` (each returns `Outcome.succeeded(reference=...)`,
`Outcome.failed(error, message)`, or raises `RetryLater()` only when the
vendor surely did nothing), then:

```sh
export LGSOTF_WEBHOOK_SECRET=...          # from your secret manager
python3 lgsotf_receiver.py serve --host 0.0.0.0 --port 8443 \
    --tls-cert /etc/lgsotf/server.crt --tls-key /etc/lgsotf/server.key \
    --db /var/lib/lgsotf/receiver.sqlite3 --tenants acme
```

The webhook URL is `https://<host>:8443/lgsotf/actions` (`--path` changes
it); `GET /healthz` answers `{"status": "ok"}`. Without `--tls-cert` it
serves plain HTTP on `127.0.0.1` for a TLS-terminating reverse proxy in
front. Handlers run in a thread per request while LG-SOTF waits. Several
processes may share one `--db` file.

**Gateway mode.** With `LGSOTF_FORWARD_URL` set, the receiver verifies and
deduplicates, then posts each verified action (the same JSON payload, plus
`Idempotency-Key`) to that URL, with the headers in `LGSOTF_FORWARD_HEADERS`
(a JSON object, for the SOAR's own webhook authentication). `https` is
required unless `LGSOTF_FORWARD_ALLOW_HTTP=1`. The SOAR's `2xx` becomes
`succeeded` (its `execution_id`, `wf_exec_id` or `id` becomes `reference`), a
JSON `status` of `failed`/`error`/`rejected` becomes `failed`, `429` and `503`
are retried, anything else fails.

### n8n

1. **Import** `examples/soar/n8n/lg-sotf-response.json` (Workflows > Import
   from file).
2. **Secret.** Create the n8n variable `LGSOTF_WEBHOOK_SECRET` (plans with
   Variables), or set it as an environment variable of n8n and allow
   expressions to read it with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` (this
   exposes every environment variable to workflow editors: prefer the
   variable). Without a secret of at least 16 bytes, every execution fails
   with an error and LG-SOTF records the action as failed.
3. **Self-hosted n8n**: allow the Code node to load `crypto` with
   `NODE_FUNCTION_ALLOW_BUILTIN=crypto` (on the task runners too, when they
   run separately). n8n Cloud allows it already.
4. **Actions.** For each action type you handle, open its
   `TODO <action>: ...` HTTP Request node, set the vendor URL, credential and
   body (the node notes name an example call), and **enable** it. Disabled
   placeholders answer `rejected` / `not_implemented`. Action types without a
   branch go to **Unsupported action type** and are answered `rejected`.
   Keep each call's timeout at 10 s or less.
5. **Activate** the workflow and use its production URL
   (`https://<n8n>/webhook/lg-sotf-response`) as the tenant's webhook URL. Test
   with `send-test` first.

The **Verify LG-SOTF signature** node checks the three conditions above on
the raw body (the Webhook node's **Raw Body** option must stay on) and
answers repeated action ids from the workflow's static data; **Build LG-SOTF
result** turns the vendor's HTTP status into the response contract (`2xx`:
`succeeded`, anything else: `failed`) and stores it. Static data is saved only
by production executions of the active workflow and is not a lock: keep the
vendor calls short so a retry never overlaps the first run. For several
LG-SOTF tenants, duplicate the workflow with its own path and secret
variable.

### Tines

Tines can verify the request itself:

1. A **Webhook** action with `capture_raw_body` and `include_headers` on.
   Tines turns header names to lower case with underscores:
   `x_lgsotf_timestamp`, `x_lgsotf_signature`, `idempotency_key`.
2. Store the secret as a Tines **credential** (for example
   `lgsotf_webhook_secret`).
3. A **Trigger** that continues only when the signature matches, compared in
   constant time on the raw body (here the webhook action is named `webhook`):

   ```text
   CONST_EQUALS("v1=" & HMAC_SHA256(webhook.headers.x_lgsotf_timestamp & "." & webhook.raw_body,
                                    CREDENTIAL.lgsotf_webhook_secret),
                webhook.headers.x_lgsotf_signature)
   ```

   plus the 300-second window against `UNIX_TIMESTAMP()`, and
   `idempotency_key` equal to `body.action.id` when present. Adjust the path
   of the raw body to what your webhook's events show.
4. Deduplicate on `body.action.id` (an **Event Transform** in `deduplicate`
   mode with `path` `<<body.action.id>>` and a `period` of several days), then
   branch on `body.action.type`.
5. For the ledger to show real outcomes, enable API responses on the webhook
   and end each branch with an **Exit** action answering
   `{"status": "succeeded" | "failed", "action_id": ..., "reference": ...}`
   within LG-SOTF's 15-second timeout. Set the webhook's own `response` to
   `{"status": "rejected", "error": "not_answered"}`: a request that no Exit
   action answers (a forged one, a deduplicated repeat) is then recorded as
   failed, never as a false success. Without API responses, LG-SOTF records
   the webhook's immediate answer (accepted).

The formula functions (`HMAC_SHA256`, `CONST_EQUALS`, `UNIX_TIMESTAMP`) and
option names are those of Tines' current documentation: check them in your
tenant. If the raw body is not available to you, use the gateway pattern
below.

### Shuffle

Shuffle's webhook trigger can require fixed headers but cannot check an HMAC
over the raw body, so run the reference receiver as a gateway in front of it:

1. In the workflow's **Webhook** trigger, add a required header in its
   **Authentication** field, for example `x-lgsotf-gateway: <random token>`,
   and start the trigger.
2. Run the receiver with `LGSOTF_FORWARD_URL` set to the webhook URI Shuffle
   shows for the trigger and
   `LGSOTF_FORWARD_HEADERS='{"x-lgsotf-gateway": "<random token>"}'`.
3. In the workflow, the execution argument is the verified payload: branch on
   `$exec.action.type` and use `$exec.action.target`.

Shuffle answers once the execution is queued, so the ledger records
`succeeded` (accepted); follow failures in Shuffle.

### Tracecat

Tracecat webhooks have a secret URL, an optional `x-tracecat-api-key` header,
method and IP allowlists, but no HMAC check of the sender, so use the gateway:

1. Turn the workflow's webhook on, and generate an API key for it.
2. Run the receiver with `LGSOTF_FORWARD_URL=<the webhook URL>` and
   `LGSOTF_FORWARD_HEADERS='{"x-tracecat-api-key": "<key>"}'`, and restrict
   the webhook's IP allowlist to the receiver.
3. In the workflow, `${{ TRIGGER.action.type }}` and
   `${{ TRIGGER.action.target }}` carry the verified action.

The default webhook answers with the execution ids (`wf_exec_id` becomes the
ledger `reference`) before the workflow runs; Tracecat's synchronous webhook
variant can return the workflow's result instead (see Tracecat's webhook
documentation), in which case return `{"status": ...}` as above.

## Action types and example vendor calls

The calls below are well-known **examples to verify** against your vendor's
current API documentation and licence; grant each integration only the
permissions it needs. Targets were validated by LG-SOTF's guardrails but come
from alert data: URL-encode them in paths, escape them in query languages
(OData: double single quotes, `'` becomes `''`), and never pass them to a
shell.

| Action | Target | Default risk | Example vendor calls |
|---|---|---|---|
| `block_ip` | `ip` | medium | Defender for Endpoint `POST /api/indicators` (`indicatorType: IpAddress`, `action: Block`); PAN-OS XML API `type=user-id` tag registration for a dynamic address group; Cloudflare `POST /zones/{zone_id}/firewall/access_rules/rules` (`mode: block`) |
| `block_domain` | `domain` | medium | Defender for Endpoint indicator `DomainName` / `Block`; Cisco Umbrella `POST /policies/v2/destinationlists/{id}/destinations` |
| `block_url` | `url` | medium | Defender for Endpoint indicator `Url` / `Block`; Zscaler ZIA `PUT /api/v1/urlCategories/{id}?action=ADD_TO_LIST`, then `POST /api/v1/status/activate` |
| `isolate_host` | `host` | high | Resolve the host to exactly one device first. Defender for Endpoint `POST /api/machines/{id}/isolate`; CrowdStrike `POST /devices/entities/devices-actions/v2?action_name=contain`; SentinelOne `POST /web/api/v2.1/agents/actions/disconnect` |
| `terminate_process` | `process` | medium | On `params.scope.hosts` only. CrowdStrike Real Time Response session, then `kill <pid>` |
| `quarantine_file` | `hash` | low | On `params.scope.hosts`: Defender for Endpoint `POST /api/machines/{id}/StopAndQuarantineFile` (SHA-1). Tenant-wide: Defender indicator `FileSha256` / `BlockAndRemediate`; CrowdStrike `POST /iocs/entities/indicators/v1` (`action: prevent`) |
| `disable_user` | `user` | critical | Microsoft Graph `PATCH /v1.0/users/{id}` with `{"accountEnabled": false}`; Okta `POST /api/v1/users/{id}/lifecycle/suspend`; Google Workspace Directory API `users.update` with `suspended: true`; Active Directory `Disable-ADAccount` from a runner |
| `reset_password` | `user` | critical | Okta `POST /api/v1/users/{id}/lifecycle/expire_password`; Active Directory `Set-ADUser -ChangePasswordAtLogon $true`; Microsoft Graph `passwordProfile` update (cloud-only accounts). Never log or return a generated password |
| `revoke_sessions` | `user` | high | Microsoft Graph `POST /v1.0/users/{id}/revokeSignInSessions`; Okta `DELETE /api/v1/users/{id}/sessions`; Google Workspace `users.signOut` |
| `collect_forensics` | `host` | low | Defender for Endpoint `POST /api/machines/{id}/collectInvestigationPackage`; return the machine action id |
| `create_ticket` | `alert` | low | Only reaches the SOAR when the tenant has no ticketing integration in LG-SOTF (`docs/integrations.md`). Jira `POST /rest/api/3/issue`; ServiceNow `POST /api/now/table/incident` |
| `send_alert` | `alert` | low | Slack `chat.postMessage`; PagerDuty Events API v2 `POST /v2/enqueue`; a Teams Workflows webhook |
| `block_sender` | `email` | medium | Microsoft 365 has no Graph API for the Tenant Allow/Block List: Exchange Online PowerShell `New-TenantAllowBlockListItems -ListType Sender -Block -Entries <address>` (with `-ExpirationDate` or `-NoExpiration`) from an automation runner |
| `purge_message` | `message` | high | Match `params.match` in full. Microsoft Graph per mailbox: `GET /v1.0/users/{id}/messages?$filter=internetMessageId eq '<id>'`, check sender and subject, then move to Deleted Items or delete; Gmail API `users.messages.list` with `rfc822msgid:<id>`, then `users.messages.trash` |
| `notify_reporter` | `alert` | low | Microsoft Graph `POST /v1.0/users/{mailbox}/sendMail` from a shared mailbox the application is restricted to; any SMTP relay |
| `confirm_compromised` | `user` | high | Microsoft Graph `POST /v1.0/identityProtection/riskyUsers/confirmCompromised` with `{"userIds": ["<object id>"]}` (Entra ID P2) |

Defender for Endpoint paths are relative to its API host
(`https://api.security.microsoft.com`). Microsoft Graph calls need
application permissions such as `User.EnableDisableAccount.All`,
`User.RevokeSessions.All`, `Mail.ReadWrite` or `Mail.Send`; scope mailbox
permissions with Exchange Online RBAC for Applications rather than granting
them for every mailbox. Default risks are the catalog's; the tenant's
autonomy policy decides which need an approval.

### Rollbacks

An analyst can roll back an action your receiver executed. LG-SOTF then
sends a new action of the inverse type, with the same target and
`rollback_of` set to the original action's id. It has its own `action.id`,
is signed, approved (under the inverse's own risk) and deduplicated like any
other action, and is never sent while a dry-run switch is on. Undo what you
did for the original id (the `reference` you answered then), and answer
`succeeded` when it is already undone. Nothing is undone until you add the
handler: the templates answer `rejected` / `not_implemented`, which LG-SOTF
records as a failed rollback.

| Action | Undoes | Target | Default risk | Example vendor calls |
|---|---|---|---|---|
| `release_host` | `isolate_host` | `host` | high | Defender for Endpoint `POST /api/machines/{id}/unisolate`; CrowdStrike `POST /devices/entities/devices-actions/v2?action_name=lift_containment` |
| `unblock_ip` | `block_ip` | `ip` | medium | Delete the rule or indicator you created, for example Defender for Endpoint `DELETE /api/indicators/{id}` |
| `unblock_domain` | `block_domain` | `domain` | medium | Defender for Endpoint `DELETE /api/indicators/{id}`; remove it from the Umbrella destination list |
| `unblock_url` | `block_url` | `url` | medium | Defender for Endpoint `DELETE /api/indicators/{id}`; Zscaler ZIA `PUT /api/v1/urlCategories/{id}?action=REMOVE_FROM_LIST`, then activate |
| `unblock_file` | `quarantine_file` | `hash` | medium | Defender for Endpoint `DELETE /api/indicators/{id}` of the file indicator. A file stopped and quarantined per host has no documented undo call: answer `failed` |
| `unblock_sender` | `block_sender` | `email` | medium | Exchange Online PowerShell `Remove-TenantAllowBlockListItems -ListType Sender -Entries <address>` from a runner |
| `enable_user` | `disable_user` | `user` | critical | Microsoft Graph `PATCH /v1.0/users/{id}` with `{"accountEnabled": true}`; Okta `POST /api/v1/users/{id}/lifecycle/unsuspend` |
| `restore_message` | `purge_message` | `message` | high | Move back exactly the items the purge removed, to their original folders: Microsoft Graph `POST /v1.0/users/{id}/messages/{item id}/move`. Keep the item ids when you purge |
| `dismiss_user_risk` | `confirm_compromised` | `user` | high | Microsoft Graph `POST /v1.0/identityProtection/riskyUsers/dismiss` with `{"userIds": ["<object id>"]}` |

`revoke_sessions`, `reset_password`, `collect_forensics`, `notify_reporter`
and `terminate_process` have no rollback. LG-SOTF never plans a rollback on
its own: only an analyst's rollback request creates one (docs/microsoft.md,
section Rollback).

## Coexisting with the direct Microsoft connectors

LG-SOTF 1.1 can also execute actions directly in Microsoft 365 (mail through
Microsoft Graph), Entra ID and Defender for Endpoint, and then verify and
roll them back. The SOAR keeps working next to them; the split is **per
action type**:

* An action type you enable on the tenant's Microsoft connector runs there.
  Every other action type keeps going to the tenant's connector, the webhook
  to your SOAR. A typical split:

  | Usually direct (Microsoft) | Stays on the SOAR |
  |---|---|
  | `isolate_host`, `collect_forensics`, indicator-based `block_ip` / `block_domain` / `block_url` / `quarantine_file` (Defender for Endpoint); `disable_user`, `revoke_sessions`, `reset_password`, `confirm_compromised` (Entra ID); `purge_message`, `notify_reporter` (Exchange Online) | `block_sender` (no Microsoft API for the Tenant Allow/Block List), `terminate_process`, `send_alert`, `create_ticket` without a ticketing integration, and any control outside Microsoft (perimeter firewall, proxy, another EDR or IdP) |

  The Microsoft connector documentation lists its exact capabilities,
  permissions and options.
* The dry-run switches (install and tenant) win over every route: nothing is
  sent to Microsoft or to the SOAR while they are on.
* Routing never falls back silently: when an action routed to Microsoft
  cannot run there (for example its credential is missing or cannot be
  decrypted), it fails on the ledger with the reason. It is not sent to the
  SOAR instead.
* An action is always finished by the connector that started it: an
  interrupted execution is re-run on the same connector, so moving an action
  type from the SOAR to a direct connector never executes an in-flight action
  twice.
* Do not automate the same action type in both places. Once an action type
  runs directly, keep its SOAR branch only for re-runs and rollbacks of
  actions the SOAR executed earlier, and make sure no SOAR automation of its
  own acts on LG-SOTF alerts for that action type.
* Post-action verification applies to the direct connectors. For actions
  executed by the SOAR, the ledger records what your receiver reports: report
  `failed` honestly.
* Rollback requests for an action executed by the SOAR go to the SOAR, as
  actions of their own type (for example `release_host` for `isolate_host`)
  whose top-level `rollback_of` holds the original action id
  ([Rollbacks](#rollbacks)). They are signed, approved and deduplicated like
  any other action. Until you add handlers for them, the templates answer
  `rejected` / `not_implemented`, which LG-SOTF records as a failed rollback:
  nothing is undone silently.

## Receiver security checklist

* Verify the signature, the window and the `Idempotency-Key` on the raw body
  before anything else; answer `401` without details.
* HTTPS with a certificate LG-SOTF can verify; restrict the source addresses
  to LG-SOTF's egress where you can.
* Keep the secret in a secret store; never log it, the signature, or whole
  request bodies at `INFO`.
* Deduplicate on `action.id`, keep answers for days, and make vendor calls
  idempotent.
* Check `tenant_id` when a receiver serves more than one tenant.
* Honour `params.scope.hosts` and `params.match`; resolve names to exactly
  one object and refuse ambiguous matches.
* Validate and encode targets before they reach URLs, OData or other query
  languages, and never a shell.
* Give vendor integrations least privilege, and keep response JSON free of
  secrets (it is stored on the ledger).
* Answer `rejected` for anything you do not handle; never `succeeded`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every request gets `401` | Different secrets on the two sides; the body is parsed and re-serialised before verification (a proxy or framework rewriting JSON); the receiver's clock is off by more than 5 minutes |
| Ledger `failed`, `error: destination_refused` | `http` URL in staging or production, a private address without `ingestion.allow_private_destinations`, or a loopback/link-local address |
| Ledger `failed`, `error: unexpected_redirect` | The URL redirects (missing path, `http` to `https`): use the final URL |
| Ledger `failed`, `error: deadline` or `network_error` | The receiver is slow or unreachable; the outcome is unknown: check the receiver's store before acting by hand |
| Ledger `failed`, `http_status: 409` | The same action id arrived with another target: investigate, this is not a retry |
| n8n: `access to env vars denied` or the secret error | Use the n8n variable, or set `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` |
| n8n: `Cannot find module 'crypto'` / module disallowed | Set `NODE_FUNCTION_ALLOW_BUILTIN=crypto` on n8n and its task runners |
| n8n: `No raw body` | Turn the **Raw Body** option of the LG-SOTF webhook node back on |
| n8n: repeated action ids are executed again | Static data is kept only for production executions of the active workflow |
| Ledger `succeeded` but nothing happened | The SOAR answered before running (accepted): see "Performed or accepted" |
