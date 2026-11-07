# Compliance tooling

LG-SOTF keeps a reconstructable record of every alert it handles and a
hash-chained audit log of every security-relevant action. The features on
this page turn those records into artefacts that regulated teams are asked
for:

* **case evidence packs**: one verifiable bundle per alert, with a human
  oversight view;
* **NIS2 incident-report drafts** for the 24-hour, 72-hour and final
  reports;
* **tenant data export and erasure** for GDPR requests and customer offboarding;
* **model provenance**: which provider, model and prompt version informed each workflow step.

These features *help you with* record keeping, incident reporting and data
subject requests. They do not make an installation compliant on their own,
and nothing here is legal advice. Whether an incident is significant,
whether and when to notify, and what to tell an authority remain decisions
for your organisation.

## Case evidence packs

`GET /api/v1/alerts/{id}/evidence?format=json|html` (role `viewer`, or an
API key with `read`) returns one bundle for the alert. In the UI, open an
alert and use **Evidence and reporting → Download JSON / Download HTML /
Open HTML**.

| Section | Contents |
|---|---|
| `alert` | The alert row: normalised form, the raw event redacted once more for credentials (`raw_redacted`, with the count of redactions), and the stored `summary` |
| `timeline` | Every timeline event (up to 5,000), oldest first |
| `agents` | Per step (`triage`, `correlation`, `analysis`): whether it ran and when, verdict, confidence, threat score, reasoning and conclusion, token usage, and the **provider, model and prompt version** it called; plus the routing decision, the response plan, model refusals and whether the LLM budget ran out |
| `enrichment` | Threat-intelligence and history observations, threat indicators, indicator sightings (display value and keyed hash) |
| `correlation` | The correlation digest and the alerts grouped with this one |
| `escalations` | Level, reason, SLA, who claimed it and when, the decision, who decided and when, notes, pre-approved actions |
| `feedback` | Analyst feedback on the agents' output |
| `actions` | The response ledger: requested by, approved by and when, executed when and through which connector, `blocked_reason`, parameters and result (redacted) |
| `human_oversight` | Which steps were automated and which were taken by a person, and every override (see below) |
| `audit` | The related audit-log entries (about the alert, its escalations and its actions) with `prev_hash`, `hash` and `hash_valid`, and a verification of the tenant's chain from the oldest included entry to the newest |
| `limits` | Whether any list was capped |
| `integrity` | `bundle_sha256` and the signature (see *Verifying a pack*) |

Each export is itself audited (`alert.evidence_exported`, with the bundle
digest in `details.bundle_sha256`). The response carries the digest in
`X-Evidence-Bundle-SHA256` and the audit entry id in `X-Audit-Entry-Id`.

The HTML form is a single self-contained file (no scripts, no external
resources, every value escaped) laid out for print-to-PDF. It shows the same
content; the digest and signature cover the JSON bundle, so keep the JSON
next to any PDF you file.

### Human oversight

The `human_oversight` section classifies what happened:

* **automated**: workflow nodes (gate, triage, correlation, analysis,
  decide, escalate, plan response, execute, close), escalation creation,
  actions approved by policy (`approved_by: policy:auto`), guardrail blocks
  and connector executions;
* **human**: claiming and deciding an escalation, approving or rejecting an
  action, notes and incident-report drafts written by a user;
* **overrides**: an analyst decision that contradicts the automated verdict
  (for example `false_positive` on an alert the analysis called
  `malicious`), a rejected action that the workflow proposed, and analyst
  feedback marking an agent's output as wrong.

The summary says how many steps of each kind there were and whether the
alert was closed without any human involvement.

### Model provenance

Every agent records the provider, model and tier it called, and the name
and hash of the prompt it sent, in `alerts.summary.llm_models`
(`{"triage": {"provider": "anthropic", "model": "claude-haiku-4-5", "tier":
"fast", "prompt_name": "triage.assess", "prompt_hash": "3f9c..."}, ...}`).
Evidence packs show it per step. Alerts processed before model recording show
`recorded: false` with the note "processed before per-step model recording";
alerts processed before prompt versions were recorded show the model with
the prompt "not recorded"; steps that made no model call say "rules only".

Prompts are named templates in the code (`lg_sotf.llm.registry`). The hash
is the first 16 hex characters of a SHA-256 over everything fixed that the
model is sent for that template: the system prompt and task, the shared
guard against instructions in alert data, the preambles of the data blocks
and the output schema. The same hash means the model received the same
instructions; any wording or schema change gives a new hash. Every model
call also logs `prompt_name` and `prompt_hash` with the model in its
`llm.call` event.

### Verifying a pack

`integrity.bundle_sha256` is the SHA-256 of the pack's canonical form: the
JSON document **without** its `integrity` member, with object keys sorted,
no insignificant whitespace, UTF-8, non-ASCII characters unescaped. In
Python:

```python
import hashlib, json

pack = json.load(open("evidence-<alert>.json", encoding="utf-8"))
body = {k: v for k, v in pack.items() if k != "integrity"}
canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == pack["integrity"]["bundle_sha256"]
```

Anyone can recompute a digest, so a matching digest alone only shows the
file is internally consistent. Two things tie it to your installation:

* **The signature.** `integrity.signature` is `HMAC-SHA256` over the same
  canonical bytes with a dedicated signing key derived from the install
  secret: `HKDF-SHA256(ikm = security.indicator_hmac_key, salt = none, info =
  "lg-sotf/evidence-signing/v1", length = 32)`. The key never leaves the
  server and is not the indicator key itself. `signature.key_id` identifies
  it (a truncated digest of the key). Verify with the same settings as the
  server:

  ```sh
  lg-sotf evidence-verify evidence-<alert>.json
  # bundle_sha256: 3f1c... (matches)
  # signature: valid
  ```

  Exit code 0 means the digest matches and the signature is valid; 1 means
  it does not, the pack was signed with another key, or the pack is unsigned
  (accept unsigned packs with `--allow-unsigned`). Installs without
  `security.indicator_hmac_key` (development only; production requires it)
  produce unsigned packs.
* **The audit log.** The export's audit entry records the digest, and the
  entry is part of the tenant's hash chain (`GET /api/v1/audit/verify`). A
  reviewer can compare the file's digest with the entry.

The signature is symmetric: whoever verifies it holds the install secret. It
proves the pack came from your installation to you and your auditors with
access to the install; it is not a public-key signature for third parties.

The `audit` section is verified at export time: `hash_valid` is the database
recomputing each included entry's hash, and `chain_verification.ok` covers
every entry of the tenant from the oldest included one onwards. A tampered
entry shows `hash_valid: false` and `ok: false` with `first_bad_id`.

## NIS2 incident-report drafts

`POST /api/v1/alerts/{id}/incident-report` (role `analyst`, or an API key
with `write`) with `{"stage": "early_warning" | "notification" | "final",
"include_ai_narrative": true}` returns a draft for one reporting stage of
NIS2 (Directive (EU) 2022/2555) Article 23(4). In the UI: open an alert,
**Draft NIS2 report**, pick the stage.

| Stage | Deadline | Fields |
|---|---|---|
| `early_warning` (Art. 23(4)(a)) | within 24 hours of becoming aware | short description; whether unlawful or malicious acts are suspected (prefilled from the analyst decision, automated verdict, disposition and MITRE mapping); cross-border impact; assistance requested |
| `notification` (Art. 23(4)(b)) | within 72 hours of becoming aware | the early-warning update; initial assessment; severity; impact (affected hosts and accounts); indicators of compromise (from the alert's entities and indicator sightings); response actions so far |
| `final` (Art. 23(4)(d)) | one month after the notification | detailed description with timeline, severity and impact; type of threat or root cause (likely threat type, triage categories, MITRE); applied and ongoing mitigation measures (from the response ledger; dry runs are marked); cross-border impact; lessons learned |

Every stage also has the reporting entity, the recipient CSIRT or authority,
why the incident is significant (Art. 23(3)), the detection time and the
awareness time. Each field says where its value came from:

* `case_data`: derived deterministically from the case (the same case gives
  the same draft);
* `requires_human`: a legal or business judgement LG-SOTF cannot make
  (significance, awareness time, cross-border impact, the reporting entity);
  left empty, sometimes with a hint;
* `ai_drafted`: model output.

With `include_ai_narrative` and a configured LLM, the fast-tier model writes
a short narrative from the case data. The case data goes into the prompt's
untrusted-data block, like every other model call, so text inside an alert
cannot pose as instructions; the narrative never fills or changes a field
and is labelled **"AI-drafted — review required"**. If no model is
configured, the budget is spent or the call fails, the draft is returned
without it and `ai_narrative_error` says why.

Every draft is stored as an `incident_report_draft` event on the alert's
timeline (with the field values, the narrative and a digest) and audited as
`alert.incident_report_drafted`. The response includes a standalone HTML
rendering.

**LG-SOTF does not submit reports.** A draft is a starting point for a
person to complete, check and submit through your national CSIRT's or
competent authority's channel. LG-SOTF does not decide whether an incident
is significant.

## Tenant data export (GDPR access and portability)

Platform admins export all of a tenant's data:

* API: `POST /api/v1/platform/tenants/{id}/export`, answered with a streamed
  `application/zip`;
* UI: **Platform → Tenant data → Export tenant data**;
* CLI (large tenants, no HTTP timeouts): `lg-sotf tenant-export --tenant <id>
  --output <file.zip>`. The file is created with mode 0600 and never
  overwritten without `--force`.

The archive holds JSON Lines files, one object per row: `users.jsonl`,
`api_keys.jsonl`, `sources.jsonl`, `alerts.jsonl`, `alert_events.jsonl`,
`escalations.jsonl`, `feedback.jsonl`, `actions.jsonl`, `suppressions.jsonl`,
`integrations.jsonl`, `notification_outbox.jsonl` (delivery summaries),
`external_tickets.jsonl`, `usage_daily.jsonl`, `llm_usage_daily.jsonl`,
`audit_log.jsonl` and `indicator_sightings.jsonl` (the indicator values seen on
each alert, as displayed: IP addresses, email addresses, user and host names),
plus `tenant.json` (name, status, settings) and `manifest.json` (row count and
SHA-256 of every file, who exported and when, and what is excluded).

Not exported, and named in the manifest's `excluded` list: authentication
secrets (`user_mfa`, `refresh_tokens`), workflow run bookkeeping
(`workflow_runs`) and LangGraph checkpoints, queue entries and caches. A test
fails when a new tenant-scoped table is neither exported nor listed as
excluded.

Secrets are never exported:

* users come from a column allow-list: no password hash, no lockout
  counters, and nothing added later such as MFA secrets;
* API keys without their hash; sources and integrations without their
  encrypted credentials (`has_secret: true` instead);
* tenant settings with every `*_ciphertext` value replaced by
  `*_configured: true`;
* source and integration configuration, settings and action parameters and
  results also go through the credential redactor.

Rows are read in keyset-ordered batches, each in its own short transaction,
and compressed as they stream, so memory use does not grow with the tenant.
Each export is audited in the tenant's chain (`tenant.data_exported`) and in
the admin's home tenant (`platform.tenant_exported`). The archive contains
personal data (user emails, analyst notes, alert content): store and
transfer it accordingly.

## Tenant erasure (GDPR erasure, offboarding)

Erasure permanently deletes a tenant's data:

* API: `DELETE /api/v1/platform/tenants/{id}` with `{"confirm": "<id>"}`;
  `GET /api/v1/platform/tenants/{id}/erasure` says whether it can run now
  and why not;
* UI: **Platform → Tenant data → Erase tenant**, enabled only for a
  suspended tenant, after typing the tenant id;
* CLI: `lg-sotf tenant-erase --tenant <id> --confirm <id>` (asks again
  unless `--yes`).

It is refused unless the tenant is **suspended** (suspension stops sign-ins,
API keys and the UI for that tenant; export first), the confirmation equals
the tenant id, no workflow run of the tenant is running, and (API) the
tenant is not the platform admin's own home tenant.

What is deleted: every row of the tenant in every table with a `tenant_id`
(alerts, timeline events, workflow runs, escalations, feedback, response
actions, suppression rules, indicator sightings, LLM usage, sources, API
keys, users and their refresh tokens, and tables added by later releases),
the LangGraph checkpoints of the tenant's threads, the tenant's Redis keys
(`{prefix}:t:{tenant}:*`, found with `SCAN`) and its entries in the work and
dead-letter streams. The database side runs in bounded batches, children
first (the order follows the schema's foreign keys, so deleting a batch
never cascades to further rows), each in its own transaction, through the `lgsotf_erase_tenant_batch`
function (the API's least-privilege database role cannot delete these rows
directly). An interrupted erasure can be run again and continues.

What is kept: the tenant's **audit log**, and the `tenants` row as a
tombstone (id, name, status) whose settings are replaced by `{"erased_at":
...}`, because the audit rows reference it. The erasure is recorded in the
tenant's own chain (`tenant.erased`, with counts) and in the admin's home
tenant (`platform.tenant_erasure_started`, `platform.tenant_erased`); from
the CLI, in the bootstrap tenant.

### Why the audit log is retained

The audit log is append-only by design: database triggers refuse `UPDATE`,
`DELETE` and `TRUNCATE` on `audit_log` for every role except the schema
owner running retention, and each entry's hash covers the previous one. An
erasure that could delete a tenant's audit entries would need exactly the
capability the design withholds from the API, and it would let whoever
triggers it remove the record of what they did. So erasure keeps the audit
rows. Deleting them per tenant is not configurable, because that would
weaken the immutability guarantee for everyone.

The legal basis to document for the retained entries is usually:

* **legal obligation** (GDPR Art. 6(1)(c) and 17(3)(b)) where you must keep
  security and incident records, for example under NIS2 Articles 21 and 23
  or sector rules;
* **legitimate interest** (Art. 6(1)(f)) and the **establishment, exercise
  or defence of legal claims** (Art. 17(3)(e)): proving who did what, when,
  on which case, including the erasure itself.

Minimisation: entries record actions, resource ids and actor ids (UUIDs of
accounts that erasure deletes), not alert bodies or secrets; accounts
created with the CLI record their email in `user.created`. Retained entries
still expire: the scheduler drops whole monthly partitions older than
`retention.audit_days` (default 365). That setting is install-wide; lower it
if your retention policy requires a shorter period.

## EU AI Act: human oversight and record keeping

Whether the AI Act treats your deployment as high-risk depends on how you
use LG-SOTF (for example, as a safety component in the operation of
critical digital infrastructure) and is your assessment to make. Whatever
the classification, where you want to meet the Act's expectations for
oversight and logging, or a customer asks for them, these features help:

| Expectation | How LG-SOTF helps |
|---|---|
| Human oversight (Art. 14): people can understand the output, decide not to use it, override or reverse it, and stop the system | Uncertain or high-impact cases go to an analyst (escalations with SLAs); containment needs a policy you set per risk level and guardrails, and by default a human approval; LLM output alone never closes a high/critical alert or authorises containment; analysts' decisions override verdicts; `needs_more_info` sends a case back; the dry-run connector and `response.dry_run` stop real actions; the evidence pack's **human oversight** section shows, per case, what was automated, what a person decided and every override |
| Record keeping and logs (Art. 12, deployers keep logs, Art. 26(6)) | Per-alert timeline of every node, decision and action; hash-chained audit log with verification; the model and provider per step; evidence packs export all of it with a digest and signature; `retention.*` settings control how long each kind of record is kept |
| Transparency to users (Art. 13) and AI-generated content | The UI and evidence packs show reasoning, confidence, whether a model was used and which one, and model refusals; NIS2 narratives are labelled "AI-drafted — review required" |
| Monitoring and accuracy (Art. 26(5), Art. 15) | Analyst feedback per case, the evaluation harness (`lg-sotf eval`, see [evaluation.md](evaluation.md)) with a false-negative gate, LLM usage and cost per tenant |
| Robustness against manipulation (Art. 15(5)) | Alert content reaches models only inside a delimited, size-capped untrusted-data block; rules must corroborate automated closes and containment; MCP tool results are marked as untrusted |

## Related

* [api.md](api.md): endpoint reference and roles;
* [mcp.md](mcp.md): driving LG-SOTF from Claude or another MCP client
  (the `get_evidence_pack` tool);
* [security.md](security.md): tenant isolation, secrets, audit log.
