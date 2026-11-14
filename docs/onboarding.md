# First-run onboarding

A new install's admin goes through the setup wizard; a new tenant's admin
lands on an empty Overview. The getting-started checklist walks them to their
first triaged alert, and built-in sample alerts let them see the triage before
any source is connected.

## First-run setup wizard

The admin that `lg-sotf migrate` creates from `auth.bootstrap_admin_email`
and `auth.bootstrap_admin_password` is a platform admin of the bootstrap
tenant (`auth.bootstrap_tenant_id`). Until they finish or skip setup, their
Overview shows **Finish setting up LG-SOTF** with a **Start setup** link to
`/setup` (also linked from Getting started). The wizard has five steps:

1. **Your account**: the signed-in email, the role and whether two-step
   sign-in is on (required for platform admins in production), and a reminder
   to remove the bootstrap password from the env file: it is only read when the
   first account is created.
2. **Organisation**: the organisation's name and the first tenant's display
   name (the tenant id does not change).
3. **Language model**: where triage sends alert data. The model is install
   configuration (`llm.*`, read at start-up), so the wizard does not change
   it: it shows the model configured now and where it runs, lets the admin
   pick a profile, shows the settings that select that profile, and tests the
   configured model with the same probe as **Tenant settings > Language
   model**. The profiles, EU or local first:

   | Profile | Where | Settings |
   |---|---|---|
   | `mistral_eu` (preselected) | EU (Mistral's API) | `openai` provider, `llm.base_url` `https://api.mistral.ai/v1`, an API key, `mistral-small-latest` / `mistral-medium-latest` |
   | `ollama_local` | this server | `ollama` provider, the Ollama overlay (`make quickstart OLLAMA=qwen3:8b`), `qwen3:8b` |
   | `self_hosted` | your network | `openai_compatible` provider and your server's `llm.base_url` (vLLM, llama.cpp) |
   | `anthropic` | outside the EU | `anthropic` provider and an API key |

   The configured model is labelled `eu`, `local`, `us` (a cloud API without
   `llm.base_url`), `offline` (the fake demo model), `cn` (hosted in China,
   flagged) or `unknown` (a gateway or a public server whose region is not
   known). A model hosted in China is never offered. When the configured model
   is EU or local and matches a profile, that profile is preselected.
4. **Sample alerts**: sends the sample set (below) and waits until the first
   one has a verdict: it is closed, or waits for an analyst or an approval.
5. **Finish**: a summary; **Finish setup** lands on the Overview with a
   **Start a proof of value** link (`/pov`, a placeholder until the
   proof-of-value run ships).

**Skip setup** marks setup done without the remaining steps. Every step can be
run again later from `/setup`.

The organisation, the picked profile and `setup_completed_at` are stored in
`tenants.onboarding`; the tenant name is the tenant's own `name`. Saving
(`onboarding.setup_saved`, with the changed values) and finishing or skipping
(`onboarding.setup_completed`, with `skipped`) are audited in the tenant.

### Time to the first triaged alert

`tests/integration/e2e/test_first_run.py` rehearses a fresh install: from an
empty database it runs `migrate`, signs in as the bootstrap admin, makes the
wizard's API calls, lets a real worker triage the sample alerts and fails if
the first verdict takes more than 30 minutes. It writes the timings to
`$LG_SOTF_REHEARSAL_REPORT` (JSON; default: the test's temporary directory)
and to the JUnit property `time_to_first_triage_s`. The Playwright spec
`src/lg_front/e2e/wizard.spec.ts` clicks through the same steps on a phone-sized
screen against the compose stack, checks every step with axe in both themes
and records the same time.

## Getting started page and banner

Admins see **Getting started** in the navigation and, on the Overview, a
banner with their progress, the next steps, a **Send sample alerts** button
and a dismiss button. The banner disappears when it is dismissed or every
step is done; the page stays available.

| Step | Done when | Link |
|---|---|---|
| `source_connected` | A source is registered, or an alert from a real source (not the samples) has arrived | `/sources`, `/sources/wazuh` (guided) |
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

## Guided Wazuh setup

**Sources > Connect Wazuh step by step** (`/sources/wazuh`, also linked from
the checklist and from the last step of the setup wizard) checks a Wazuh
connection before anything is saved. The admin enters the indexer URL, the
index pattern, a read-only indexer user and, for a private CA, its
certificate, then chooses **Run checks**. The platform builds the connector
the poller uses, applies the install's destination policy and sends one
read-only search (the newest alert and the indexer's clock). The answer is
shown as seven checks, in the order a connection is made. The first failure
says what to change; the checks after it are skipped until it is fixed:

| Check | Fails when | The message names |
|---|---|---|
| Connection settings | The URL, index pattern, time field or CA text is malformed; plain `http` in production | The setting |
| Indexer reachable | The host is not on the install's allow-list or has a refused address; the name does not resolve; nothing answers; the server is not an indexer (the dashboard on 443, the manager API on 55000) | The host and port, `ingestion.allowed_destination_hosts` and `scripts/pov.sh --allow-host` |
| TLS certificate | The certificate is signed by a CA the server does not trust, names another host or has expired | The CA certificate field, the host name |
| Sign-in | The indexer answers `401` | Which kind of account is needed (an indexer user, not a dashboard or manager API account) |
| Permission to read the alerts index | The indexer answers `403` | The index pattern and the missing permission (`indices:data/read/search`; the fix is the index permission `read` on the pattern) |
| Alerts index | The pattern matches no index, the index does not exist, shards fail, or the time field is not a date there | The index pattern, the time field |
| Clocks agree | The indexer's clock is more than 120 seconds from the server's, or the newest alert is dated in the future (the Wazuh manager's clock runs ahead) | The size and direction of the difference; the fix is NTP |

One attempt is made, without retries, so an unreachable host answers within
the connect timeout. Once every check passes, **Save source** creates the
`wazuh` source with the values that were checked; editing a value discards
the result.

**Push from the manager** covers the other way in: the Wazuh manager posts
alerts to `POST /api/v1/ingest/webhook/<source id>` with an API key. The
page creates the push source (a `webhook` source with `config.format:
wazuh`, id `wazuh-push` by default) and checks two things: that the source
exists, is enabled and takes the Wazuh format, and that the key the manager
sends is an active key of this tenant with the `ingest` scope. A missing
scope is named with the scopes the key has. A mistyped key, a deleted one
and another tenant's key get the same answer.

Messages never contain the password, the user name, the API key, a response
body or an exception text. The entered credentials are used for the check
only; they are stored (encrypted) when the source is saved, as for any
source. Each run is audited as `source.setup_checked` with the ids of the
failed checks, without the URL.

## API (tenant admins)

| Method | Path | What |
|---|---|---|
| GET | `/api/v1/onboarding/status` | `steps` (`id`, `done`, `available`), `completed`, `total`, `complete`, `dismissed`, `dismissed_at`, `samples_sent`, `first_verdict` (an alert, samples included, is closed or waits for an analyst or an approval). |
| POST | `/api/v1/onboarding/sample-alerts` | Ingest the sample set and queue it for triage. Returns `inserted`, `duplicates`, `enqueued`, `alert_ids`. |
| POST | `/api/v1/onboarding/autonomy-reviewed` | Mark the autonomy policy reviewed without changing it. |
| POST | `/api/v1/onboarding/dismiss` | Hide the Overview banner for the tenant. |

Setup wizard (a platform admin's own account in their home tenant; anyone
else, an `X-Tenant-ID` override and API keys get `403`):

| Method | Path | What |
|---|---|---|
| GET | `/api/v1/onboarding/setup` | `completed`, `completed_at`, `tenant_id`, `tenant_name`, `organisation`, `llm_profile`, `default_llm_profile`, `configured_llm` (`provider`, `enabled`, `fast_model`, `deep_model`, `residency`, `profile`) and `llm_profiles` (`id`, `label`, `residency`, `description`, `provider`, models, `env`). |
| PUT | `/api/v1/onboarding/setup` | `{"organisation", "tenant_name", "llm_profile"}` (names 1-200 characters on one line; `llm_profile` one of the profile ids or `null`). |
| POST | `/api/v1/onboarding/setup/complete` | `{"skipped": false}`; the first completion time is kept. |

Guided source setup (the tenant's own admins; refused under a grant, like
creating a source; 20 runs per tenant per minute):

| Method | Path | What |
|---|---|---|
| POST | `/api/v1/onboarding/connectors/wazuh/check` | `{"pull": {"config": {"base_url", "index", "time_field", "ca_cert_pem"}, "secret": {"username", "password"}}}` and/or `{"push": {"source_id", "api_key"}}`. Returns `ok` (no check failed and at least one passed) and `checks`: `id`, `title`, `status` (`passed`, `failed`, `skipped`), `message` and, on a failed check, `fix`. Nothing is stored. |

Analysts, viewers and API keys get `403` on the checklist endpoints. The three `POST`s are audited
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
