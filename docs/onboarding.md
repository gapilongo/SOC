# First-run onboarding

A new tenant's admin lands on a dashboard with nothing in it. The
getting-started checklist walks them to their first triaged alert, and
built-in sample alerts let them see the triage before any source is
connected.

## Getting started page and banner

Admins see **Getting started** in the navigation and, on the dashboard, a
banner with their progress, the next steps, a **Send sample alerts** button
and a dismiss button. The banner disappears when it is dismissed or every
step is done; the page stays available.

| Step | Done when | Link |
|---|---|---|
| `source_connected` | A source is registered, or an alert from a real source (not the samples) has arrived | `/sources` |
| `notifications_configured` | The tenant has an enabled Slack, Teams, email or webhook integration (ticketing integrations do not count) | `/integrations` |
| `teammate_invited` | The tenant has more than one user account | `/users` |
| `autonomy_reviewed` | An admin saved the autonomy or response settings, or chose **Mark reviewed** | `/settings` |
| `first_alert_triaged` | An alert (sample alerts included) has a disposition or is closed | `/alerts` |

The state is computed by the API from the tenant's own data on every request
(one read-only transaction); only `autonomy_reviewed_at`, `dismissed_at` and
`samples_sent_at` are stored, in `tenants.onboarding`. The notifications
step depends on the optional integrations feature: when the `integrations`
table does not exist, or the runtime role cannot read it, the step is
reported as `available: false`, hidden in the UI and not counted.

## API (tenant admins)

| Method | Path | What |
|---|---|---|
| GET | `/api/v1/onboarding/status` | `steps` (`id`, `done`, `available`), `completed`, `total`, `complete`, `dismissed`, `dismissed_at`, `samples_sent`. |
| POST | `/api/v1/onboarding/sample-alerts` | Ingest the sample set and queue it for triage. Returns `inserted`, `duplicates`, `enqueued`, `alert_ids`. |
| POST | `/api/v1/onboarding/autonomy-reviewed` | Mark the autonomy policy reviewed without changing it. |
| POST | `/api/v1/onboarding/dismiss` | Hide the dashboard banner for the tenant. |

Analysts, viewers and API keys get `403`. The three `POST`s are audited
(`onboarding.sample_alerts_sent`, `onboarding.autonomy_reviewed`,
`onboarding.dismissed`).

## Sample alerts

`src/lg_sotf/onboarding/samples.py` defines five canonical-format alerts:

1. multiple failed VPN logins followed by a success (high);
2. the EICAR anti-virus test file quarantined (low);
3. periodic beaconing to a newly registered domain (high);
4. an encoded PowerShell command started by an Office document (critical;
   the encoded text decodes to `Write-Output 'sample'`);
5. a port scan from the IT vulnerability scanner (low).

They go through the normal ingestion service (redaction, normalisation,
fingerprinting, deduplication) and dispatch, so the workers triage them like
any alert. Safety and bookkeeping:

* Every indicator is reserved for documentation: `example.com`/`.net`/`.org`
  and the `.example` TLD (RFC 2606/6761), TEST-NET addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 5737) and the
  EICAR test-file hashes. Enrichment lookups on them are harmless.
* They are stored under the reserved source id `demo:samples` (it cannot be
  registered as a source or pushed to) and carry the `sample` flag in
  `normalized.flags`.
* Idempotent: the set has fixed `source_alert_id`s, so sending it again
  stores nothing new (`inserted: 0`, `duplicates: 5`).
* Not metered: they are left out of `usage_daily` (invoicing) and of the
  daily alert quota, and do not count as a connected source. Their LLM calls
  are real and appear in the LLM usage like any other.
* They age out with the tenant's normal alert retention; delete them sooner
  by shortening retention or leave them as a reference.

## Per-tenant retention

Admins can set, under **Tenant settings > Data retention** or with `PATCH
/api/v1/tenant/settings`:

```json
{"retention": {"alerts_days": 30, "indicators_days": 14}}
```

Keys merge one by one; `null` removes an override (back to the install
default). Values must be whole days within `retention.tenant_min_days` ..
`retention.tenant_max_days` (install settings, default 7 .. 730); anything
else is refused with `422 invalid_settings`. `GET /tenant/settings` returns
the bounds and the install defaults as `retention_limits`. Alert timelines,
the audit log, LLM usage and checkpoints follow the install settings only.
