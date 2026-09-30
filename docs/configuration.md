# Configuration reference

All configuration is read by `lg_sotf.settings.Settings`; no other module reads
the environment or configuration files. Every process role (`api`, `worker`,
`scheduler`, `migrate` and the operator commands) uses the same settings.

## Sources and precedence

Highest first:

1. Environment variables `LG_SOTF_<SECTION>__<KEY>` (double underscore between
   levels): `LG_SOTF_DATABASE__URL`, `LG_SOTF_LLM__FAST__MODEL`. Lists and
   mappings are JSON: `LG_SOTF_API__CORS_ORIGINS='["https://soc.example.com"]'`.
   Keys of the free-form mappings (`agents`, `routing`, `tools`, `ingestion`)
   can also be set one at a time: `LG_SOTF_ROUTING__RESPONSE_THRESHOLD=85`.
2. A `.env` file in the working directory (development convenience; the
   production compose override and the Helm chart do not use it).
3. The YAML file named by `LG_SOTF_CONFIG_FILE` (the Helm chart renders
   `values.settings` into one). Values may reference the environment as
   `${VAR}` or `${VAR:-default}`; keys whose reference expands to nothing fall
   back to the default.
4. Built-in defaults (the tables below).

Standard variables are honoured as fallbacks when the `LG_SOTF_` form is not
set: `DATABASE_URL`, `REDIS_URL`, and the provider key of the configured LLM
provider (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`).
`LG_SOTF_ENV` is a legacy alias of `LG_SOTF_ENVIRONMENT`.

Reference files: `.env.example` (annotated, with secret generation
instructions), `configs/development.yaml`, `configs/staging.yaml`,
`configs/production.yaml`, and `deploy/helm/lg-sotf/values.yaml` (`settings`
mirrors this reference).

## Production safety checks

With `environment` set to `staging` or `production`, every process calls
`Settings.assert_safe()` at startup and refuses to start when:

* `auth.jwt_secret` is missing or shorter than 32 bytes;
* `security.encryption_keys` or `security.indicator_hmac_key` is missing;
* `llm.provider` is `fake` without `llm.allow_fake`, or a cloud provider has no
  API key (`ollama` and `openai_compatible` need none), or `llm.base_url`
  breaks the endpoint policy (docs/local-llm.md);
* `api.cors_origins` contains `*`, or `auth.cookie_secure` is false;
* `database.url` contains the development password;
* any secret still has a value published in this repository (the placeholders
  in `configs/development.yaml` and `.env.example`,
  `lg_sotf.security.insecure`).

Generate real secrets with `python scripts/generate_secrets.py` (or `make
secrets`). Never put secrets in the YAML file or in Helm `values.settings`;
use environment variables from a secret store (see docs/deployment.md).

## Tenant settings are separate

Per-tenant policy (response autonomy, protected assets, allowed actions,
blast-radius limits, connector choice, review SLAs and grouping, enrichment
opt-in, LLM daily token budget) lives in the database (`tenants.settings`)
and is edited by tenant admins through `GET/PATCH /api/v1/tenant/settings`
(docs/api.md). The install settings below provide defaults and hard limits
for those tenant settings. Data retention is an install setting
(`retention.*` below); the API cannot change it per tenant.

## Settings reference

This section is generated from the code by `python docs/tools/settings_reference.py --write`;
`tests/unit/eval/test_configuration_docs.py` fails when a setting is missing or
the section is stale. Defaults shown are the code defaults, not the values in
the example files.

<!-- BEGIN GENERATED SETTINGS REFERENCE (docs/tools/settings_reference.py) -->

### Top level

Top-level settings.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `environment` | `LG_SOTF_ENVIRONMENT` | `development` \| `test` \| `staging` \| `production` | `development` | `development`, `test`, `staging` or `production`. Staging and production run the startup safety checks (`Settings.assert_safe`). `LG_SOTF_ENV` is accepted as a legacy alias. |
| `config_file` | `LG_SOTF_CONFIG_FILE` | string (optional) | unset | Optional YAML file with lower precedence than environment variables and `.env`; may reference `${VAR}` and `${VAR:-default}`. |
| `agents` | `LG_SOTF_AGENTS` | mapping | `{}` | Free-form per-agent tuning, keyed by agent name (`triage`, `correlation`, `analysis`, `human_loop`). `human_loop` holds install defaults of the escalation policy (`sla_minutes`, `level_thresholds`, `min_level`, `grouping`, `suggest_suppressions`; see `lg_sotf.services.escalation`). |
| `routing` | `LG_SOTF_ROUTING` | mapping | `{}` | See the routing table below. |
| `tools` | `LG_SOTF_TOOLS` | mapping | `{}` | Enrichment providers (`virustotal`, `abuseipdb`, `http`) with install keys and `share_with_tenants`, plus `internal_domains`, `cache` and `lookup_timeout_s` (see `lg_sotf.tools.enrichment.service`). Nothing is sent to a provider without a key and consent. |
| `ingestion` | `LG_SOTF_INGESTION` | mapping | `{}` | See the ingestion table below. |

### `database`

PostgreSQL connections (asyncpg pool; the worker's LangGraph checkpointer opens its own pool).

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `database.url` | `LG_SOTF_DATABASE__URL` | secret | `postgresql://soc:soc_dev_password@localhost:5432/soc` | Runtime DSN (API, worker). In production a non-owner role without `BYPASSRLS`. `DATABASE_URL` is honoured when this is unset. The default is the development stack's credential and is refused in staging/production. |
| `database.migration_url` | `LG_SOTF_DATABASE__MIGRATION_URL` | secret (optional) | unset | Schema-owner DSN for `lg-sotf migrate`, the scheduler and operator commands. Defaults to `database.url` (single-role installs). |
| `database.runtime_role` | `LG_SOTF_DATABASE__RUNTIME_ROLE` | string (optional) | unset | Login role that `lg-sotf migrate` grants runtime privileges to (two-role installs). |
| `database.pool_min` | `LG_SOTF_DATABASE__POOL_MIN` | integer | `2` | Minimum connections per process pool. |
| `database.pool_max` | `LG_SOTF_DATABASE__POOL_MAX` | integer | `10` | Maximum connections per process pool; size PostgreSQL `max_connections` from it (see docs/deployment.md). |
| `database.command_timeout_s` | `LG_SOTF_DATABASE__COMMAND_TIMEOUT_S` | number | `30.0` | Client-side timeout for one database command. |
| `database.statement_timeout_ms` | `LG_SOTF_DATABASE__STATEMENT_TIMEOUT_MS` | integer | `30000` | Server-side `statement_timeout` set on every pooled connection. |
| `database.ssl_mode` | `LG_SOTF_DATABASE__SSL_MODE` | `disable` \| `prefer` \| `require` \| `verify-ca` \| `verify-full` (optional) | unset | libpq-style TLS mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`. Use `verify-full` in production. |
| `database.ssl_root_cert` | `LG_SOTF_DATABASE__SSL_ROOT_CERT` | string (optional) | unset | CA bundle path for `verify-ca` / `verify-full`. |

### `redis`

Redis: work queue (Streams), event fan-out (pub/sub), rate limits, caches.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `redis.url` | `LG_SOTF_REDIS__URL` | secret | `redis://localhost:6379/0` | Redis URL (`rediss://` for TLS). `REDIS_URL` is honoured when this is unset. |
| `redis.max_connections` | `LG_SOTF_REDIS__MAX_CONNECTIONS` | integer | `64` | Connection pool size per process. |
| `redis.key_prefix` | `LG_SOTF_REDIS__KEY_PREFIX` | string | `lgsotf` | Prefix of every key, stream and channel; lets several installs share one Redis. |
| `redis.socket_timeout_s` | `LG_SOTF_REDIS__SOCKET_TIMEOUT_S` | number | `10.0` | Socket timeout for Redis commands. |

### `llm`

Language model provider, tiers, prompt limits, budgets and pricing.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `llm.enabled` | `LG_SOTF_LLM__ENABLED` | boolean | `true` | Master switch. When false, agents run on rules only and nothing is sent to a model. |
| `llm.provider` | `LG_SOTF_LLM__PROVIDER` | `anthropic` \| `openai` \| `gemini` \| `ollama` \| `openai_compatible` \| `fake` | `anthropic` | `anthropic` (default), `openai`, `gemini` (optional extras), the self-hosted `ollama` and `openai_compatible` (vLLM, llama.cpp, LM Studio, ...; API key optional, metered as `local/<model>` at zero cost; see docs/local-llm.md) or `fake` (deterministic offline heuristic for tests and demos; refused in staging/production unless `llm.allow_fake`). |
| `llm.api_key` | `LG_SOTF_LLM__API_KEY` | secret (optional) | unset | Provider API key (optional for `ollama` and `openai_compatible`). Falls back to `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or `GOOGLE_API_KEY` for the chosen provider. |
| `llm.base_url` | `LG_SOTF_LLM__BASE_URL` | string (optional) | unset | Custom API endpoint (gateway, proxy or self-hosted server). Required for `openai_compatible`; `ollama` defaults to `http://ollama:11434/v1`. `http://` only to loopback, private (RFC 1918, CGNAT, ULA), docker service or `*.internal` hosts; metadata and link-local addresses and credentials in the URL are refused. When set, Anthropic server-side refusal fallbacks are not requested. |
| `llm.structured_output` | `LG_SOTF_LLM__STRUCTURED_OUTPUT` | `auto` \| `json_schema` \| `json_mode` \| `function_calling` | `auto` | How `ollama` and `openai_compatible` return structured output: `json_schema` (`auto`; the schema as `response_format` and in the prompt), `json_mode` (`response_format: json_object`) or `function_calling`. JSON replies get one validation-and-repair retry. Cloud providers always use their native method. |
| `llm.refusal_fallback` | `LG_SOTF_LLM__REFUSAL_FALLBACK` | boolean | `true` | Anthropic only: ask the API to retry a refused request on a fallback model (server-side fallback beta). A refusal that remains still escalates the alert. |
| `llm.prices` | `LG_SOTF_LLM__PRICES` | mapping | `{}` | Price overrides per model id, merged over the built-in table: `{model: {input, output, cache_write, cache_read}}` in USD per million tokens (cache prices default to 1.25x and 0.1x input). Unknown models are metered at zero cost with a warning. |
| `llm.allow_fake` | `LG_SOTF_LLM__ALLOW_FAKE` | boolean | `false` | Allow `provider=fake` in staging/production (demos only). |
| `llm.max_input_chars` | `LG_SOTF_LLM__MAX_INPUT_CHARS` | integer | `24000` | Total size budget of the untrusted alert data in one prompt; the largest subtrees are shrunk first. |
| `llm.max_field_chars` | `LG_SOTF_LLM__MAX_FIELD_CHARS` | integer | `2000` | Cap on every string in prompt data. |
| `llm.max_list_items` | `LG_SOTF_LLM__MAX_LIST_ITEMS` | integer | `50` | Cap on every list in prompt data. |
| `llm.prompt_caching` | `LG_SOTF_LLM__PROMPT_CACHING` | boolean | `true` | Mark stable prompt prefixes for provider prompt caching (Anthropic). |
| `llm.daily_token_budget_per_tenant` | `LG_SOTF_LLM__DAILY_TOKEN_BUDGET_PER_TENANT` | integer (optional) | unset | Default daily token budget per tenant (tenants may override with `llm_daily_token_budget`). When exhausted, agents fall back to rules and the alert summary records `llm_budget_exceeded`. Unset means unlimited. |

### `llm.fast`

Fast tier: triage, correlation and ingestion fallback calls. Setting one key of the tier keeps the defaults of the others.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `llm.fast.model` | `LG_SOTF_LLM__FAST__MODEL` | string | `claude-haiku-4-5` | Model id of the tier. |
| `llm.fast.max_tokens` | `LG_SOTF_LLM__FAST__MAX_TOKENS` | integer | `2048` | Maximum output tokens per call. |
| `llm.fast.temperature` | `LG_SOTF_LLM__FAST__TEMPERATURE` | number (optional) | `0.0` | Sampling temperature; omitted automatically for models that do not accept it. |
| `llm.fast.effort` | `LG_SOTF_LLM__FAST__EFFORT` | `low` \| `medium` \| `high` \| `xhigh` \| `max` (optional) | unset | Optional effort level (`low`, `medium`, `high`, `xhigh`, `max`) for models that support it. |
| `llm.fast.timeout_s` | `LG_SOTF_LLM__FAST__TIMEOUT_S` | number | `60.0` | Per-call timeout. |
| `llm.fast.max_retries` | `LG_SOTF_LLM__FAST__MAX_RETRIES` | integer | `2` | Client retries for transient provider errors. |
| `llm.fast.max_concurrency` | `LG_SOTF_LLM__FAST__MAX_CONCURRENCY` | integer (optional) | unset | Concurrent calls of this tier per process; unset = `worker.concurrency`. Set it only to respect a provider rate limit (waits show in `lgsotf_llm_slot_wait_seconds`). |

### `llm.deep`

Deep tier: the analysis agent's investigation. Setting one key of the tier keeps the defaults of the others.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `llm.deep.model` | `LG_SOTF_LLM__DEEP__MODEL` | string | `claude-opus-5-5` | Model id of the tier. |
| `llm.deep.max_tokens` | `LG_SOTF_LLM__DEEP__MAX_TOKENS` | integer | `16000` | Maximum output tokens per call (models that always think bill thinking as output; leave room). |
| `llm.deep.temperature` | `LG_SOTF_LLM__DEEP__TEMPERATURE` | number (optional) | `0.0` | Sampling temperature; omitted automatically for models that do not accept it. |
| `llm.deep.effort` | `LG_SOTF_LLM__DEEP__EFFORT` | `low` \| `medium` \| `high` \| `xhigh` \| `max` (optional) | unset | Optional effort level (`low`, `medium`, `high`, `xhigh`, `max`) for models that support it. |
| `llm.deep.timeout_s` | `LG_SOTF_LLM__DEEP__TIMEOUT_S` | number | `300.0` | Per-call timeout. |
| `llm.deep.max_retries` | `LG_SOTF_LLM__DEEP__MAX_RETRIES` | integer | `2` | Client retries for transient provider errors. |
| `llm.deep.max_concurrency` | `LG_SOTF_LLM__DEEP__MAX_CONCURRENCY` | integer (optional) | unset | Concurrent calls of this tier per process; unset = `worker.concurrency`. Set it only to respect a provider rate limit (waits show in `lgsotf_llm_slot_wait_seconds`). |

### `auth`

Local accounts, sessions, OIDC single sign-on and the bootstrap tenant/admin.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `auth.jwt_secret` | `LG_SOTF_AUTH__JWT_SECRET` | secret (optional) | unset | HS256 signing key for access tokens; at least 32 bytes. Required in staging/production. |
| `auth.jwt_issuer` | `LG_SOTF_AUTH__JWT_ISSUER` | string | `lg-sotf` | `iss` claim of issued access tokens. |
| `auth.jwt_audience` | `LG_SOTF_AUTH__JWT_AUDIENCE` | string | `lg-sotf-api` | `aud` claim of issued access tokens. |
| `auth.access_token_ttl_s` | `LG_SOTF_AUTH__ACCESS_TOKEN_TTL_S` | integer | `900` | Access token lifetime. |
| `auth.refresh_token_ttl_s` | `LG_SOTF_AUTH__REFRESH_TOKEN_TTL_S` | integer | `1209600` | Refresh token (cookie) lifetime. |
| `auth.cookie_secure` | `LG_SOTF_AUTH__COOKIE_SECURE` | boolean | `true` | Send the refresh cookie over HTTPS only. Must stay true in staging/production. |
| `auth.cookie_domain` | `LG_SOTF_AUTH__COOKIE_DOMAIN` | string (optional) | unset | Optional `Domain` attribute of the refresh cookie. |
| `auth.password_min_length` | `LG_SOTF_AUTH__PASSWORD_MIN_LENGTH` | integer | `12` | Minimum password length for local accounts. |
| `auth.max_login_attempts` | `LG_SOTF_AUTH__MAX_LOGIN_ATTEMPTS` | integer | `10` | Consecutive failed logins before the account is locked. |
| `auth.lockout_minutes` | `LG_SOTF_AUTH__LOCKOUT_MINUTES` | integer | `15` | Lock duration after too many failed logins. |
| `auth.oidc_issuer` | `LG_SOTF_AUTH__OIDC_ISSUER` | string (optional) | unset | Enables OIDC bearer tokens from this issuer (verified against its JWKS). |
| `auth.oidc_audience` | `LG_SOTF_AUTH__OIDC_AUDIENCE` | string (optional) | unset | Expected `aud` of OIDC tokens. |
| `auth.oidc_jwks_url` | `LG_SOTF_AUTH__OIDC_JWKS_URL` | string (optional) | unset | JWKS URL; discovered from the issuer when unset. |
| `auth.oidc_tenant_claim` | `LG_SOTF_AUTH__OIDC_TENANT_CLAIM` | string | `tenant_id` | Claim holding the tenant id. |
| `auth.oidc_role_claim` | `LG_SOTF_AUTH__OIDC_ROLE_CLAIM` | string | `roles` | Claim holding the role(s) (`admin`, `analyst`, `viewer`). |
| `auth.oidc_email_claim` | `LG_SOTF_AUTH__OIDC_EMAIL_CLAIM` | string | `email` | Claim holding the user's email. |
| `auth.oidc_email_verified_claim` | `LG_SOTF_AUTH__OIDC_EMAIL_VERIFIED_CLAIM` | string | `email_verified` | Claim that must be true before the email is trusted. |
| `auth.oidc_default_tenant` | `LG_SOTF_AUTH__OIDC_DEFAULT_TENANT` | string (optional) | unset | Tenant for tokens without a tenant claim (single-organisation installs). |
| `auth.bootstrap_admin_email` | `LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL` | string (optional) | unset | `lg-sotf migrate` creates this admin in the bootstrap tenant if it does not exist. |
| `auth.bootstrap_admin_password` | `LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD` | secret (optional) | unset | Password of the bootstrap admin. Give it to the migrate job only, then remove it. |
| `auth.bootstrap_tenant_id` | `LG_SOTF_AUTH__BOOTSTRAP_TENANT_ID` | string | `default` | Tenant created by `lg-sotf migrate`. |
| `auth.bootstrap_tenant_name` | `LG_SOTF_AUTH__BOOTSTRAP_TENANT_NAME` | string | `Default` | Display name of the bootstrap tenant. |

### `api`

HTTP API process.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `api.host` | `LG_SOTF_API__HOST` | string | `0.0.0.0` | Bind address of `lg-sotf api`. |
| `api.port` | `LG_SOTF_API__PORT` | integer | `8000` | Port of `lg-sotf api`. |
| `api.public_url` | `LG_SOTF_API__PUBLIC_URL` | string | `http://localhost:8000` | External URL of the API. An `https://` URL turns on HSTS. |
| `api.cors_origins` | `LG_SOTF_API__CORS_ORIGINS` | list[string] | `["http://localhost:3000", "http://localhost:5173"]` | Allowed browser origins (JSON list in environment variables). `*` is refused in staging/production. |
| `api.max_body_bytes` | `LG_SOTF_API__MAX_BODY_BYTES` | integer | `1048576` | Request body limit for ordinary endpoints. |
| `api.max_ingest_body_bytes` | `LG_SOTF_API__MAX_INGEST_BODY_BYTES` | integer | `10485760` | Request body limit for ingestion endpoints. |
| `api.max_ingest_batch` | `LG_SOTF_API__MAX_INGEST_BATCH` | integer | `500` | Maximum events per `POST /ingest/alerts` call. |
| `api.rate_limit_per_minute` | `LG_SOTF_API__RATE_LIMIT_PER_MINUTE` | integer | `600` | Requests per minute per principal. |
| `api.ingest_rate_limit_per_minute` | `LG_SOTF_API__INGEST_RATE_LIMIT_PER_MINUTE` | integer | `6000` | Ingestion requests per minute per API key. |
| `api.login_rate_limit_per_minute` | `LG_SOTF_API__LOGIN_RATE_LIMIT_PER_MINUTE` | integer | `20` | Login attempts per minute per client IP. |
| `api.metrics_token` | `LG_SOTF_API__METRICS_TOKEN` | secret (optional) | unset | Bearer token required by the API's `/metrics`. |
| `api.docs_enabled` | `LG_SOTF_API__DOCS_ENABLED` | boolean | `true` | Serve `/docs` and `/api/v1/openapi.json`. Consider disabling in production. |
| `api.forwarded_allow_ips` | `LG_SOTF_API__FORWARDED_ALLOW_IPS` | string | `127.0.0.1` | Proxies whose `X-Forwarded-*` headers are trusted. Only the ingress controller or load balancer; the client IP keys login rate limits and audit entries. |
| `api.ws_max_per_principal` | `LG_SOTF_API__WS_MAX_PER_PRINCIPAL` | integer | `5` | Concurrent live-event WebSockets per principal per API process; more get close code 1013. |
| `api.ws_max_per_tenant` | `LG_SOTF_API__WS_MAX_PER_TENANT` | integer | `100` | Concurrent live-event WebSockets per tenant per API process, so one tenant cannot take every slot. |
| `api.ws_max_subscribers` | `LG_SOTF_API__WS_MAX_SUBSCRIBERS` | integer | `1000` | Concurrent live-event WebSockets per API process (all tenants). |
| `api.ws_subscriber_buffer` | `LG_SOTF_API__WS_SUBSCRIBER_BUFFER` | integer | `256` | Events buffered per WebSocket before a slow client is disconnected (1013). |
| `api.ws_revalidate_s` | `LG_SOTF_API__WS_REVALIDATE_S` | number | `15.0` | How often an open WebSocket re-checks its token (logout), account and tenant status. |
| `api.max_inflight_ingest` | `LG_SOTF_API__MAX_INFLIGHT_INGEST` | integer | `64` | Ingest requests processed at once per API process; more get 503 with Retry-After instead of queueing on the database pool. |

### `worker`

Worker process (queue consumer and workflow runner).

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `worker.concurrency` | `LG_SOTF_WORKER__CONCURRENCY` | integer | `16` | Workflow runs in flight per worker process. |
| `worker.node_timeout_s` | `LG_SOTF_WORKER__NODE_TIMEOUT_S` | number | `180.0` | Timeout of one workflow node. |
| `worker.analysis_timeout_s` | `LG_SOTF_WORKER__ANALYSIS_TIMEOUT_S` | number | `420.0` | Timeout of the analysis node. |
| `worker.run_timeout_s` | `LG_SOTF_WORKER__RUN_TIMEOUT_S` | number | `900.0` | Budget of one run including node retries. |
| `worker.max_deliveries` | `LG_SOTF_WORKER__MAX_DELIVERIES` | integer | `5` | Deliveries before a queue entry is dead-lettered. |
| `worker.visibility_timeout_s` | `LG_SOTF_WORKER__VISIBILITY_TIMEOUT_S` | integer | `1200` | Pending entries of live workers older than this are reclaimed by other workers. |
| `worker.block_ms` | `LG_SOTF_WORKER__BLOCK_MS` | integer | `5000` | Blocking read time on the queue streams. |
| `worker.drain_timeout_s` | `LG_SOTF_WORKER__DRAIN_TIMEOUT_S` | number | `60.0` | Time given to in-flight runs on `SIGTERM`. |
| `worker.per_tenant_concurrency` | `LG_SOTF_WORKER__PER_TENANT_CONCURRENCY` | integer | `8` | Runs in flight per tenant per worker process while other tenants have work in that process (noisy-neighbour limit); a tenant alone may use every slot. |

### `scheduler`

Scheduler process (leader-elected periodic jobs).

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `scheduler.tick_s` | `LG_SOTF_SCHEDULER__TICK_S` | number | `5.0` | Loop interval; source polling runs on every tick. |
| `scheduler.sla_sweep_interval_s` | `LG_SOTF_SCHEDULER__SLA_SWEEP_INTERVAL_S` | number | `60.0` | Interval of the escalation SLA sweep. |
| `scheduler.stale_run_sweep_interval_s` | `LG_SOTF_SCHEDULER__STALE_RUN_SWEEP_INTERVAL_S` | number | `60.0` | Interval of the stale and orphaned run sweeps. |
| `scheduler.maintenance_interval_s` | `LG_SOTF_SCHEDULER__MAINTENANCE_INTERVAL_S` | number | `3600.0` | Interval of partition and retention maintenance. |
| `scheduler.leader_lease_s` | `LG_SOTF_SCHEDULER__LEADER_LEASE_S` | integer | `30` | Leader lock keep-alive; a standby takes over within about this time. |

### `retention`

Data retention, applied by the scheduler's maintenance job.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `retention.alerts_days` | `LG_SOTF_RETENTION__ALERTS_DAYS` | integer | `90` | Alerts (and their runs, escalations, actions) older than this are purged. |
| `retention.events_days` | `LG_SOTF_RETENTION__EVENTS_DAYS` | integer | `90` | Alert timeline events. |
| `retention.audit_days` | `LG_SOTF_RETENTION__AUDIT_DAYS` | integer | `365` | Audit log (hash chain per tenant); export before it ages out if you need longer. |
| `retention.indicators_days` | `LG_SOTF_RETENTION__INDICATORS_DAYS` | integer | `30` | Indicator sightings used for correlation. |
| `retention.llm_usage_days` | `LG_SOTF_RETENTION__LLM_USAGE_DAYS` | integer | `400` | Daily LLM usage rows. |
| `retention.checkpoints_days` | `LG_SOTF_RETENTION__CHECKPOINTS_DAYS` | integer | `30` | LangGraph checkpoints of completed runs. |

### `security`

Application keys. Required in staging and production.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `security.encryption_keys` | `LG_SOTF_SECURITY__ENCRYPTION_KEYS` | secret (optional) | unset | Comma-separated Fernet keys: the first encrypts, all decrypt (rotation). Encrypts source credentials and tenant secrets. |
| `security.indicator_hmac_key` | `LG_SOTF_SECURITY__INDICATOR_HMAC_KEY` | secret (optional) | unset | HMAC key for stored indicator values (correlation). Changing it resets correlation history. |

### `observability`

Logging, tracing and metrics.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `observability.log_level` | `LG_SOTF_OBSERVABILITY__LOG_LEVEL` | string | `INFO` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `observability.log_format` | `LG_SOTF_OBSERVABILITY__LOG_FORMAT` | `json` \| `console` | `json` | `json` (default) or `console`. |
| `observability.metrics_enabled` | `LG_SOTF_OBSERVABILITY__METRICS_ENABLED` | boolean | `true` | Reserved. Not read by any process in this release: metrics are always exposed (API `/metrics` behind `api.metrics_token`, worker/scheduler health port). |
| `observability.otlp_endpoint` | `LG_SOTF_OBSERVABILITY__OTLP_ENDPOINT` | string (optional) | unset | OTLP/HTTP endpoint for traces; tracing is off when unset. |
| `observability.service_name` | `LG_SOTF_OBSERVABILITY__SERVICE_NAME` | string | `lg-sotf` | `service.name` of traces and a static field of every log line. |

### `response`

Response automation defaults and the install-wide SOAR webhook.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `response.dry_run` | `LG_SOTF_RESPONSE__DRY_RUN` | boolean | `true` | Force the dry-run connector everywhere (actions are recorded, never sent). Default true. |
| `response.default_autonomy` | `LG_SOTF_RESPONSE__DEFAULT_AUTONOMY` | mapping | `{"low": "approval", "medium": "approval", "high": "approval", "critical": "disabled"}` | Default autonomy per risk level (`auto`, `approval`, `disabled`); tenants override it in their settings. |
| `response.max_actions_per_hour_per_tenant` | `LG_SOTF_RESPONSE__MAX_ACTIONS_PER_HOUR_PER_TENANT` | integer | `50` | Install-wide cap on executed actions per tenant per hour; tenant caps cannot exceed it. |
| `response.webhook_url` | `LG_SOTF_RESPONSE__WEBHOOK_URL` | string (optional) | unset | Install-wide SOAR webhook (HMAC-signed POST) used by tenants that choose the `webhook` connector without their own URL. |
| `response.webhook_secret` | `LG_SOTF_RESPONSE__WEBHOOK_SECRET` | secret (optional) | unset | HMAC secret of the install-wide webhook. |
| `response.webhook_timeout_s` | `LG_SOTF_RESPONSE__WEBHOOK_TIMEOUT_S` | number | `15.0` | Timeout of one webhook call. |

### `routing`

Routing policy thresholds (`lg_sotf.core.routing.RoutingThresholds`). Free-form section: unknown keys are ignored, values are validated when a worker starts.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `routing.triage_close_max_confidence` | `LG_SOTF_ROUTING__TRIAGE_CLOSE_MAX_CONFIDENCE` | integer | `10` | Triage may close a low/medium alert when its confidence is at most this and it has enough false-positive signals. |
| `routing.triage_close_min_fp` | `LG_SOTF_ROUTING__TRIAGE_CLOSE_MIN_FP` | integer | `2` | False-positive signals required with `triage_close_max_confidence` (at least one must come from rules). |
| `routing.triage_fp_majority_min` | `LG_SOTF_ROUTING__TRIAGE_FP_MAJORITY_MIN` | integer | `3` | Alternative close rule: at least this many false-positive signals outnumbering true-positive ones... |
| `routing.triage_fp_majority_max_confidence` | `LG_SOTF_ROUTING__TRIAGE_FP_MAJORITY_MAX_CONFIDENCE` | integer | `20` | ...and confidence at most this. |
| `routing.correlation_strong_score` | `LG_SOTF_ROUTING__CORRELATION_STRONG_SCORE` | integer | `85` | Correlation score above which, with enough related alerts, analysis is skipped. |
| `routing.correlation_strong_min_related` | `LG_SOTF_ROUTING__CORRELATION_STRONG_MIN_RELATED` | integer | `5` | Related alerts required for the strong-correlation shortcut. |
| `routing.correlation_grey_zone_min` | `LG_SOTF_ROUTING__CORRELATION_GREY_ZONE_MIN` | integer | `30` | Lower bound of the confidence grey zone that goes to an analyst. |
| `routing.correlation_grey_zone_max` | `LG_SOTF_ROUTING__CORRELATION_GREY_ZONE_MAX` | integer | `70` | Upper bound of the confidence grey zone. |
| `routing.human_review_min` | `LG_SOTF_ROUTING__HUMAN_REVIEW_MIN` | integer | `20` | Below this confidence and correlation score (low/medium severity, no burst) analysis is skipped. |
| `routing.human_review_max` | `LG_SOTF_ROUTING__HUMAN_REVIEW_MAX` | integer | `60` | Reserved upper bound of the human-review band. |
| `routing.analysis_threshold` | `LG_SOTF_ROUTING__ANALYSIS_THRESHOLD` | integer | `40` | Reserved analysis threshold (kept for configuration compatibility). |
| `routing.response_threshold` | `LG_SOTF_ROUTING__RESPONSE_THRESHOLD` | integer | `80` | Threat score at which the policy plans a response. |
| `routing.response_combo_threat` | `LG_SOTF_ROUTING__RESPONSE_COMBO_THREAT` | integer | `60` | Alternative response rule: threat score at least this... |
| `routing.response_combo_confidence` | `LG_SOTF_ROUTING__RESPONSE_COMBO_CONFIDENCE` | integer | `80` | ...with confidence at least this. |
| `routing.close_max_threat` | `LG_SOTF_ROUTING__CLOSE_MAX_THREAT` | integer | `30` | Below this threat score a low/medium alert closes if rules corroborate; high/critical go to an analyst. |
| `routing.max_more_info_loops` | `LG_SOTF_ROUTING__MAX_MORE_INFO_LOOPS` | integer | `1` | How often an analyst's `needs_more_info` re-runs analysis before the case returns to the analyst. |
| `routing.max_alert_age_hours` | `LG_SOTF_ROUTING__MAX_ALERT_AGE_HOURS` | integer | `72` | Reserved alert-age limit (not enforced by routing in this release). |

### `ingestion`

Ingestion limits and pull-connector behaviour (`lg_sotf.ingestion.options.IngestionOptions`). Pull sources may override `page_size`, `max_pages_per_poll`, `overlap_s`, `http_timeout_s` and `http_max_retries` in their own config.

| Setting | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `ingestion.llm_fallback` | `LG_SOTF_INGESTION__LLM_FALLBACK` | boolean | `false` | Use the fast LLM to normalize events no deterministic normalizer recognizes. Off by default. |
| `ingestion.llm_fallback_max_per_call` | `LG_SOTF_INGESTION__LLM_FALLBACK_MAX_PER_CALL` | integer | `20` | Further unrecognized events in one call are rejected. |
| `ingestion.llm_fallback_concurrency` | `LG_SOTF_INGESTION__LLM_FALLBACK_CONCURRENCY` | integer | `4` | LLM normalizations in flight per call. |
| `ingestion.llm_fallback_timeout_s` | `LG_SOTF_INGESTION__LLM_FALLBACK_TIMEOUT_S` | number | `60.0` | Total time for one call's LLM normalizations. |
| `ingestion.batch_size` | `LG_SOTF_INGESTION__BATCH_SIZE` | integer | `500` | Rows per INSERT. |
| `ingestion.max_event_bytes` | `LG_SOTF_INGESTION__MAX_EVENT_BYTES` | integer | `1048576` | Larger events (compact JSON) are rejected. |
| `ingestion.max_raw_bytes` | `LG_SOTF_INGESTION__MAX_RAW_BYTES` | integer | `262144` | Cap on the stored raw event; truncated with a marker. |
| `ingestion.redact_in_thread_bytes` | `LG_SOTF_INGESTION__REDACT_IN_THREAD_BYTES` | integer | `65536` | Events above this size are redacted and normalized in a worker thread. |
| `ingestion.max_future_skew_s` | `LG_SOTF_INGESTION__MAX_FUTURE_SKEW_S` | number | `900.0` | Occurrence times further in the future are clamped to now and flagged. |
| `ingestion.page_size` | `LG_SOTF_INGESTION__PAGE_SIZE` | integer | `200` | Pull connectors: events per page. |
| `ingestion.max_pages_per_poll` | `LG_SOTF_INGESTION__MAX_PAGES_PER_POLL` | integer | `20` | Pull connectors: pages per poll before the cursor is saved and the poll resumes later. |
| `ingestion.overlap_s` | `LG_SOTF_INGESTION__OVERLAP_S` | number | `300.0` | Pull connectors: re-read window before the watermark (duplicates are dropped). |
| `ingestion.http_timeout_s` | `LG_SOTF_INGESTION__HTTP_TIMEOUT_S` | number | `30.0` | Pull connectors: request timeout. |
| `ingestion.http_connect_timeout_s` | `LG_SOTF_INGESTION__HTTP_CONNECT_TIMEOUT_S` | number | `10.0` | Pull connectors: connect timeout. |
| `ingestion.http_max_retries` | `LG_SOTF_INGESTION__HTTP_MAX_RETRIES` | integer | `4` | Pull connectors: retries of a failed request. |
| `ingestion.http_backoff_base_s` | `LG_SOTF_INGESTION__HTTP_BACKOFF_BASE_S` | number | `0.5` | Pull connectors: first retry delay (exponential backoff). |
| `ingestion.http_backoff_max_s` | `LG_SOTF_INGESTION__HTTP_BACKOFF_MAX_S` | number | `30.0` | Pull connectors: maximum retry delay. |
| `ingestion.http_max_retry_after_s` | `LG_SOTF_INGESTION__HTTP_MAX_RETRY_AFTER_S` | number | `120.0` | Pull connectors: a longer `Retry-After` ends the poll instead of sleeping. |
| `ingestion.allow_private_destinations` | `LG_SOTF_INGESTION__ALLOW_PRIVATE_DESTINATIONS` | boolean | `false` | Install-level: allow sources to reach private (RFC 1918 / ULA) addresses. Not overridable per source. |

<!-- END GENERATED SETTINGS REFERENCE -->
