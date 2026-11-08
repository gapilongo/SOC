"""Generate the settings reference in docs/configuration.md from ``lg_sotf.settings.Settings``.

    python docs/tools/settings_reference.py            # print the generated block
    python docs/tools/settings_reference.py --write    # replace the block in docs/configuration.md
    python docs/tools/settings_reference.py --check    # exit 1 if the file is stale

Every field of ``Settings`` (and of the typed views of the free-form
``routing`` and ``ingestion`` sections) must have an entry in
:data:`DESCRIPTIONS`; generation fails otherwise, and
``tests/unit/eval/test_configuration_docs.py`` fails the build.
"""

from __future__ import annotations

import json
import sys
import types
import typing
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple, Type

from pydantic import BaseModel, SecretStr

from lg_sotf.domain.routing import RoutingThresholds
from lg_sotf.ingestion.options import IngestionOptions
from lg_sotf.settings import Settings

DOC_PATH = Path(__file__).resolve().parents[1] / "configuration.md"
BEGIN = "<!-- BEGIN GENERATED SETTINGS REFERENCE (docs/tools/settings_reference.py) -->"
END = "<!-- END GENERATED SETTINGS REFERENCE -->"
ENV_PREFIX = "LG_SOTF_"

TIER_CAVEAT = " Setting one key of the tier keeps the defaults of the others."

SECTION_INTRO: Dict[str, str] = {
    "": "Top-level settings.",
    "database": "PostgreSQL connections (asyncpg pool; the worker's LangGraph checkpointer opens its own pool).",
    "redis": "Redis: work queue (Streams), event fan-out (pub/sub), rate limits, caches.",
    "llm": "Language model provider, tiers, prompt limits, budgets and pricing.",
    "llm.fast": "Fast tier: triage, correlation and ingestion fallback calls." + TIER_CAVEAT,
    "llm.deep": "Deep tier: the analysis agent's investigation." + TIER_CAVEAT,
    "auth": "Local accounts, sessions, OIDC single sign-on and the bootstrap tenant/admin.",
    "api": "HTTP API process.",
    "worker": "Worker process (queue consumer and workflow runner).",
    "scheduler": "Scheduler process (leader-elected periodic jobs).",
    "retention": "Data retention, applied by the scheduler's maintenance job.",
    "security": "Application keys. Required in staging and production.",
    "observability": "Logging and metrics.",
    "response": "Response automation defaults and the install-wide SOAR webhook.",
    "mcp": (
        "`lg-sotf mcp`, the Model Context Protocol server an analyst runs next to Claude or another MCP client "
        "(see [mcp.md](mcp.md)). Read by that command only."
    ),
    "integrations": (
        "Notifications and ticketing (docs/integrations.md): outbox delivery and ticket sync run in the scheduler; "
        "SMTP is configured per install, recipients per integration."
    ),
    "routing": (
        "Routing policy thresholds (`lg_sotf.domain.routing.RoutingThresholds`). Free-form section: unknown keys "
        "are ignored, values are validated when a worker starts."
    ),
    "ingestion": (
        "Ingestion limits and pull-connector behaviour (`lg_sotf.ingestion.options.IngestionOptions`). Pull "
        "sources may override `page_size`, `max_pages_per_poll`, `overlap_s`, `http_timeout_s` and "
        "`http_max_retries` in their own config."
    ),
}

DESCRIPTIONS: Dict[str, str] = {
    "environment": "`development`, `test`, `staging` or `production`. Staging and production run the startup safety checks (`Settings.assert_safe`). `LG_SOTF_ENV` is accepted as a legacy alias.",
    "config_file": "Optional YAML file with lower precedence than environment variables and `.env`; may reference `${VAR}` and `${VAR:-default}`.",
    "database.url": "Runtime DSN (API, worker). In production a non-owner role without `BYPASSRLS`. `DATABASE_URL` is honoured when this is unset. The default is the development stack's credential and is refused in staging/production.",
    "database.migration_url": "Schema-owner DSN for `lg-sotf migrate`, the scheduler and operator commands. Defaults to `database.url` (single-role installs).",
    "database.runtime_role": "Login role that `lg-sotf migrate` grants runtime privileges to (two-role installs).",
    "database.pool_min": "Minimum connections per process pool.",
    "database.pool_max": "Maximum connections per process pool; size PostgreSQL `max_connections` from it (see docs/deployment.md).",
    "database.command_timeout_s": "Client-side timeout for one database command.",
    "database.statement_timeout_ms": "Server-side `statement_timeout` set on every pooled connection.",
    "database.ssl_mode": "libpq-style TLS mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`. Use `verify-full` in production.",
    "database.ssl_root_cert": "CA bundle path for `verify-ca` / `verify-full`.",
    "redis.url": "Redis URL (`rediss://` for TLS). `REDIS_URL` is honoured when this is unset.",
    "redis.max_connections": "Connection pool size per process.",
    "redis.key_prefix": "Prefix of every key, stream and channel; lets several installs share one Redis.",
    "redis.socket_timeout_s": "Socket timeout for Redis commands.",
    "llm.enabled": "Master switch. When false, agents run on rules only and nothing is sent to a model.",
    "llm.provider": "`anthropic` (default), `openai`, `gemini` (optional extras), the self-hosted `ollama` and `openai_compatible` (vLLM, llama.cpp, LM Studio, ...; API key optional, metered as `local/<model>` at zero cost; see docs/local-llm.md) or `fake` (deterministic offline heuristic for tests and demos; refused in staging/production unless `llm.allow_fake`).",
    "llm.api_key": "Provider API key (optional for `ollama` and `openai_compatible`). Falls back to `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or `GOOGLE_API_KEY` for the chosen provider.",
    "llm.base_url": "Custom API endpoint (gateway, proxy or self-hosted server). Required for `openai_compatible`; `ollama` defaults to `http://ollama:11434/v1`. `http://` only to loopback, private (RFC 1918, CGNAT, ULA), docker service or `*.internal` hosts; metadata and link-local addresses and credentials in the URL are refused. When set, Anthropic server-side refusal fallbacks are not requested.",
    "llm.structured_output": "How `ollama` and `openai_compatible` return structured output: `json_schema` (`auto`; the schema as `response_format` and in the prompt), `json_mode` (`response_format: json_object`) or `function_calling`. JSON replies get one validation-and-repair retry. Cloud providers use their native method, except `openai` with `llm.base_url` and a value other than `auto`: an OpenAI-compatible cloud API that refuses tool calling (DeepSeek's thinking models: `json_mode`).",
    "llm.refusal_fallback": "Anthropic only: ask the API to retry a refused request on a fallback model (server-side fallback beta). A refusal that remains still escalates the alert.",
    "llm.prices": "Price overrides per model id, merged over the built-in table: `{model: {input, output, cache_write, cache_read}}` in USD per million tokens (cache prices default to 1.25x and 0.1x input). Unknown models are metered at zero cost with a warning.",
    "llm.allow_fake": "Allow `provider=fake` in staging/production (demos only).",
    "llm.max_input_chars": "Total size budget of the untrusted alert data in one prompt; the largest subtrees are shrunk first.",
    "llm.max_field_chars": "Cap on every string in prompt data.",
    "llm.max_list_items": "Cap on every list in prompt data.",
    "llm.prompt_caching": "Mark stable prompt prefixes for provider prompt caching (Anthropic).",
    "llm.daily_token_budget_per_tenant": "Default daily token budget per tenant (tenants may override with `llm_daily_token_budget`). When exhausted, agents fall back to rules and the alert summary records `llm_budget_exceeded`. Unset means unlimited.",
    "llm.fast.model": "Model id of the tier.",
    "llm.fast.max_tokens": "Maximum output tokens per call.",
    "llm.fast.temperature": "Sampling temperature; omitted automatically for models that do not accept it.",
    "llm.fast.effort": "Optional effort level (`low`, `medium`, `high`, `xhigh`, `max`) for models that support it.",
    "llm.fast.timeout_s": "Per-call timeout.",
    "llm.fast.max_retries": "Client retries for transient provider errors.",
    "llm.fast.max_concurrency": "Concurrent calls of this tier per process; unset = `worker.concurrency`. Set it only to respect a provider rate limit (waits show in `lgsotf_llm_slot_wait_seconds`).",
    "llm.deep.model": "Model id of the tier.",
    "llm.deep.max_tokens": "Maximum output tokens per call (models that always think bill thinking as output; leave room).",
    "llm.deep.temperature": "Sampling temperature; omitted automatically for models that do not accept it.",
    "llm.deep.effort": "Optional effort level (`low`, `medium`, `high`, `xhigh`, `max`) for models that support it.",
    "llm.deep.timeout_s": "Per-call timeout.",
    "llm.deep.max_retries": "Client retries for transient provider errors.",
    "llm.deep.max_concurrency": "Concurrent calls of this tier per process; unset = `worker.concurrency`. Set it only to respect a provider rate limit (waits show in `lgsotf_llm_slot_wait_seconds`).",
    "auth.jwt_secret": "HS256 signing key for access tokens; at least 32 bytes. Required in staging/production.",
    "auth.jwt_issuer": "`iss` claim of issued access tokens.",
    "auth.jwt_audience": "`aud` claim of issued access tokens.",
    "auth.access_token_ttl_s": "Access token lifetime.",
    "auth.refresh_token_ttl_s": "Refresh token (cookie) lifetime.",
    "auth.cookie_secure": "Send the refresh cookie over HTTPS only. Must stay true in staging/production.",
    "auth.cookie_domain": "Optional `Domain` attribute of the refresh cookie.",
    "auth.password_min_length": "Minimum password length for local accounts.",
    "auth.max_login_attempts": "Consecutive failed logins before the account is locked.",
    "auth.lockout_minutes": "Lock duration after too many failed logins.",
    "auth.oidc_issuer": "Enables OIDC bearer tokens from this issuer (verified against its JWKS).",
    "auth.oidc_audience": "Expected `aud` of OIDC tokens.",
    "auth.oidc_jwks_url": "JWKS URL; discovered from the issuer when unset.",
    "auth.oidc_tenant_claim": "Claim holding the tenant id.",
    "auth.oidc_role_claim": (
        "Claim holding the role(s) or groups; values go through `auth.oidc_role_map` (without a map they must be "
        "`admin`, `analyst` or `viewer`)."
    ),
    "auth.oidc_email_claim": "Claim holding the user's email.",
    "auth.oidc_email_verified_claim": "Claim that must be true before the email is trusted.",
    "auth.oidc_default_tenant": "Tenant for tokens without a tenant claim (single-organisation installs).",
    "auth.oidc_jit_provisioning": (
        "Create a local account (no password, never a platform admin) on the first verified OIDC sign-in and keep "
        "its role in sync with the mapping. See docs/identity.md."
    ),
    "auth.oidc_role_map": (
        "Role-claim value to role (`viewer`, `analyst`, `admin`), e.g. "
        '`{"SOC-Admins": "admin"}`; the highest match wins. Empty: the claim carries role names.'
    ),
    "auth.oidc_default_role": "Role when no claim value maps; unset refuses the sign-in.",
    "auth.require_mfa_for_platform_admins": (
        "Platform admins must use TOTP MFA (forced enrollment at sign-in). Unset: on in staging and production, "
        "off in development and test."
    ),
    "auth.mfa_issuer": "Issuer name shown in authenticator apps (`otpauth://` URI).",
    "auth.mfa_challenge_ttl_s": "Lifetime of the MFA challenge token between password and code (30-900).",
    "auth.bootstrap_admin_email": "`lg-sotf migrate` creates this admin in the bootstrap tenant if it does not exist.",
    "auth.bootstrap_admin_password": "Password of the bootstrap admin. Give it to the migrate job only, then remove it.",
    "auth.bootstrap_tenant_id": "Tenant created by `lg-sotf migrate`.",
    "auth.bootstrap_tenant_name": "Display name of the bootstrap tenant.",
    "api.host": "Bind address of `lg-sotf api`.",
    "api.port": "Port of `lg-sotf api`.",
    "api.public_url": "External URL of the API. An `https://` URL turns on HSTS.",
    "api.cors_origins": "Allowed browser origins (JSON list in environment variables). `*` is refused in staging/production.",
    "api.max_body_bytes": "Request body limit for ordinary endpoints.",
    "api.max_ingest_body_bytes": "Request body limit for ingestion endpoints (`/ingest/email` allows up to `ingestion.email.max_message_bytes` when that is larger).",
    "api.max_ingest_batch": "Maximum events per `POST /ingest/alerts` call.",
    "api.rate_limit_per_minute": "Requests per minute per principal.",
    "api.ingest_rate_limit_per_minute": "Ingestion requests per minute per API key.",
    "api.login_rate_limit_per_minute": "Login attempts per minute per client IP.",
    "api.metrics_token": "Bearer token required by the API's `/metrics`.",
    "api.docs_enabled": "Serve `/docs` and `/api/v1/openapi.json`. Consider disabling in production.",
    "api.forwarded_allow_ips": "Proxies whose `X-Forwarded-*` headers are trusted. Only the ingress controller or load balancer; the client IP keys login rate limits and audit entries.",
    "api.ws_max_per_principal": "Concurrent live-event WebSockets per principal per API process; more get close code 1013.",
    "api.ws_max_per_tenant": "Concurrent live-event WebSockets per tenant per API process, so one tenant cannot take every slot.",
    "api.ws_max_subscribers": "Concurrent live-event WebSockets per API process (all tenants).",
    "api.ws_subscriber_buffer": "Events buffered per WebSocket before a slow client is disconnected (1013).",
    "api.ws_revalidate_s": "How often an open WebSocket re-checks its token (logout), account and tenant status.",
    "api.max_inflight_ingest": "Ingest requests processed at once per API process; more get 503 with Retry-After instead of queueing on the database pool.",
    "worker.concurrency": "Workflow runs in flight per worker process.",
    "worker.node_timeout_s": "Timeout of one workflow node.",
    "worker.analysis_timeout_s": "Timeout of the analysis node.",
    "worker.run_timeout_s": "Budget of one run including node retries.",
    "worker.max_deliveries": "Deliveries before a queue entry is dead-lettered.",
    "worker.visibility_timeout_s": "Pending entries of live workers older than this are reclaimed by other workers.",
    "worker.block_ms": "Blocking read time on the queue streams.",
    "worker.drain_timeout_s": "Time given to in-flight runs on `SIGTERM`.",
    "worker.per_tenant_concurrency": "Runs in flight per tenant per worker process while other tenants have work in that process (noisy-neighbour limit); a tenant alone may use every slot.",
    "scheduler.tick_s": "Loop interval; source polling runs on every tick.",
    "scheduler.sla_sweep_interval_s": "Interval of the escalation SLA sweep.",
    "scheduler.stale_run_sweep_interval_s": "Interval of the stale and orphaned run sweeps.",
    "scheduler.maintenance_interval_s": "Interval of partition and retention maintenance.",
    "scheduler.leader_lease_s": "Leader lock keep-alive; a standby takes over within about this time.",
    "retention.alerts_days": (
        "Alerts (and their runs, escalations, actions) older than this are purged. "
        "Tenants may override it with `retention.alerts_days` in their settings."
    ),
    "retention.events_days": "Alert timeline events.",
    "retention.audit_days": "Audit log (hash chain per tenant); export before it ages out if you need longer.",
    "retention.indicators_days": (
        "Indicator sightings used for correlation. Tenants may override it with `retention.indicators_days`."
    ),
    "retention.llm_usage_days": "Daily LLM usage rows.",
    "retention.checkpoints_days": "LangGraph checkpoints of completed runs.",
    "retention.usage_days": "Daily usage counters (alerts ingested and processed per tenant; invoicing and quotas).",
    "retention.tenant_min_days": (
        "Lowest per-tenant `alerts_days`/`indicators_days` a tenant admin may set; stored values below it are raised to it."
    ),
    "retention.tenant_max_days": (
        "Highest per-tenant `alerts_days`/`indicators_days` a tenant admin may set; stored values above it are lowered to it."
    ),
    "security.encryption_keys": "Comma-separated Fernet keys: the first encrypts, all decrypt (rotation). Encrypts source credentials and tenant secrets.",
    "security.indicator_hmac_key": "HMAC key for stored indicator values (correlation). Changing it resets correlation history.",
    "observability.log_level": "Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).",
    "observability.log_format": "`json` (default) or `console`.",
    "observability.metrics_enabled": "Reserved. Not read by any process in this release: metrics are always exposed (API `/metrics` behind `api.metrics_token`, worker/scheduler health port).",
    "observability.otlp_endpoint": "Deprecated and ignored: tracing was removed (ADR-0008). A value is still accepted and logs a warning at startup.",
    "observability.service_name": "A static field of every log line and the Redis client name.",
    "response.dry_run": "Force the dry-run connector everywhere (actions are recorded, never sent). Default true.",
    "response.default_autonomy": "Default autonomy per risk level (`auto`, `approval`, `disabled`); tenants override it in their settings.",
    "response.max_actions_per_hour_per_tenant": "Install-wide cap on executed actions per tenant per hour; tenant caps cannot exceed it.",
    "response.webhook_url": "Install-wide SOAR webhook (HMAC-signed POST) used by tenants that choose the `webhook` connector without their own URL.",
    "response.webhook_secret": "HMAC secret of the install-wide webhook.",
    "response.webhook_timeout_s": "Timeout of one webhook call.",
    "response.verify_interval_s": "How often the scheduler runs due verification checks of executed actions (docs/microsoft.md).",
    "response.verify_check_timeout_s": "Time one verification check may take.",
    "response.verify_concurrency": "Verification checks run at the same time.",
    "response.verify_max_s": "The longest a verification may stay pending before it is inconclusive (4 days).",
    "response.background_interval_s": "How often the scheduler executes rollbacks, retries, late approvals and deferred actions.",
    "response.background_deadline_s": "Deadline of one background connector call.",
    "response.background_concurrency": "Background connector calls run at the same time (at most two per tenant).",
    "response.approval_ttl_s": "An approval the scheduler has not executed within this time is blocked (`approval_expired`).",
    "response.max_execution_attempts": "Execution attempts of one action (deferrals included) before it fails with `attempts_exhausted`.",
    "response.microsoft_timeout_s": "Timeout of one attempt of a Microsoft Graph or Defender request.",
    "response.microsoft_retries": "Retries of one Microsoft request (429 and 503 always; network errors, 502 and 504 when idempotent).",
    "integrations.enabled": "Run the scheduler's outbox delivery and ticket sync jobs. Events are queued whatever this says; turning it off only pauses delivery.",
    "integrations.ui_base_url": "Base URL of the web app for links in notifications (`/alerts?alert=<id>`). Defaults to `api.public_url` (the UI and API share a host in the shipped deployments).",
    "integrations.batch_size": "Outbox rows claimed per delivery pass.",
    "integrations.delivery_concurrency": "Deliveries in flight at once in the scheduler.",
    "integrations.max_attempts": "Attempts before an outbox row is marked `dead`.",
    "integrations.backoff_base_s": "First retry delay; doubles with every attempt (with jitter).",
    "integrations.backoff_max_s": "Longest retry delay (also caps a receiver's `Retry-After`).",
    "integrations.max_age_hours": "An event still undelivered after this long is marked `dead` instead of being sent late.",
    "integrations.http_timeout_s": "Timeout of one outbound integration request (Slack, Teams, webhook, Jira, ServiceNow).",
    "integrations.outbox_retention_days": "Sent and dead outbox rows are deleted after this many days.",
    "integrations.ticket_sync_interval_s": "How often the scheduler polls linked open tickets for their status.",
    "integrations.ticket_sync_batch_per_tenant": "Tickets polled per tenant per sync pass (least recently synced first).",
    "integrations.slack_sso_max_age_hours": "An OIDC-provisioned (SSO) account may approve or reject actions from Slack only if it signed in to LG-SOTF within this many hours.",
    "integrations.smtp_host": "SMTP server for email integrations; email integrations fail until it is set.",
    "integrations.smtp_port": "SMTP port (587 for STARTTLS, 465 for implicit TLS).",
    "integrations.smtp_security": "`starttls` (default), `tls` (implicit TLS) or `none` (refused in staging/production). Certificates are always verified.",
    "integrations.smtp_username": "SMTP login (optional).",
    "integrations.smtp_password": "SMTP password (optional).",
    "integrations.smtp_from": "Sender address of notification emails.",
    "integrations.smtp_timeout_s": "SMTP connection and command timeout.",
    "agents": "Free-form per-agent tuning, keyed by agent name (`triage`, `correlation`, `analysis`, `human_loop`). `correlation.clock` is `wall` (default) or `event` (correlate on each alert's own time; `lg-sotf eval` uses it). `human_loop` holds install defaults of the escalation policy (`sla_minutes`, `level_thresholds`, `min_level`, `grouping`, `suggest_suppressions`; see `lg_sotf.services.escalation`).",
    "tools": "Enrichment providers (`virustotal`, `abuseipdb`, `http`) with install keys and `share_with_tenants`, plus `internal_domains`, `cache` and `lookup_timeout_s` (see `lg_sotf.tools.enrichment.service`). Nothing is sent to a provider without a key and consent.",
    "routing": "See the routing table below.",
    "ingestion": "See the ingestion table below.",
    # routing (RoutingThresholds)
    "routing.triage_close_max_confidence": "Triage may close a low/medium alert when its confidence is at most this and it has enough false-positive signals.",
    "routing.triage_close_min_fp": "False-positive signals required with `triage_close_max_confidence` (at least one must come from rules).",
    "routing.triage_fp_majority_min": "Alternative close rule: at least this many false-positive signals outnumbering true-positive ones...",
    "routing.triage_fp_majority_max_confidence": "...and confidence at most this.",
    "routing.correlation_strong_score": "Correlation score above which, with enough related alerts, analysis is skipped.",
    "routing.correlation_strong_min_related": "Related alerts required for the strong-correlation shortcut.",
    "routing.correlation_grey_zone_min": "Lower bound of the confidence grey zone that goes to an analyst.",
    "routing.correlation_grey_zone_max": "Upper bound of the confidence grey zone.",
    "routing.human_review_min": "Below this confidence and correlation score (low/medium severity, no burst) analysis is skipped.",
    "routing.human_review_max": "Reserved upper bound of the human-review band.",
    "routing.analysis_threshold": "Reserved analysis threshold (kept for configuration compatibility).",
    "routing.response_threshold": "Threat score at which the policy plans a response.",
    "routing.response_combo_threat": "Alternative response rule: threat score at least this...",
    "routing.response_combo_confidence": "...with confidence at least this.",
    "routing.close_max_threat": "Below this threat score a low/medium alert closes if rules corroborate; high/critical go to an analyst.",
    "routing.max_more_info_loops": "How often an analyst's `needs_more_info` re-runs analysis before the case returns to the analyst.",
    "routing.max_alert_age_hours": "Reserved alert-age limit (not enforced by routing in this release).",
    "routing.benign_verdict_precedence": "A benign deep-model verdict below `close_max_threat` skips the grey-zone confidence test; every other close test still applies. `false` restores the 1.2 policy (AI-E1.9).",
    "routing.context_corroboration": "A benign deep-model verdict below `close_max_threat` on a low/medium alert may be corroborated by context the tenant declared (a `triage.known_scanners` entity) instead of the rules' threat score. `false` restores the 1.2 policy (AI-E1.9).",
    "routing.cap_correlated_confidence": "Related alerts never lift the confidence to `response_combo_confidence`; only triage (trusted rule evidence with the model) can. `false` restores the 1.2 policy (AI-E1.9).",
    # ingestion (IngestionOptions)
    "ingestion.llm_fallback": "Use the fast LLM to normalize events no deterministic normalizer recognizes. Off by default.",
    "ingestion.llm_fallback_max_per_call": "Further unrecognized events in one call are rejected.",
    "ingestion.llm_fallback_concurrency": "LLM normalizations in flight per call.",
    "ingestion.llm_fallback_timeout_s": "Total time for one call's LLM normalizations.",
    "ingestion.batch_size": "Rows per INSERT.",
    "ingestion.max_event_bytes": "Larger events (compact JSON) are rejected.",
    "ingestion.max_raw_bytes": "Cap on the stored raw event; truncated with a marker.",
    "ingestion.redact_in_thread_bytes": "Events above this size are redacted and normalized in a worker thread.",
    "ingestion.max_future_skew_s": "Occurrence times further in the future are clamped to now and flagged.",
    "ingestion.page_size": "Pull connectors: events per page.",
    "ingestion.max_pages_per_poll": "Pull connectors: pages per poll before the cursor is saved and the poll resumes later.",
    "ingestion.overlap_s": "Pull connectors: re-read window before the watermark (duplicates are dropped).",
    "ingestion.http_timeout_s": "Pull connectors: request timeout.",
    "ingestion.http_connect_timeout_s": "Pull connectors: connect timeout.",
    "ingestion.http_max_retries": "Pull connectors: retries of a failed request.",
    "ingestion.http_backoff_base_s": "Pull connectors: first retry delay (exponential backoff).",
    "ingestion.http_backoff_max_s": "Pull connectors: maximum retry delay.",
    "ingestion.http_max_retry_after_s": "Pull connectors: a longer `Retry-After` ends the poll instead of sleeping.",
    "ingestion.allow_private_destinations": "Install-level: allow sources to reach private (RFC 1918 / ULA) addresses. Not overridable per source.",
    "ingestion.allowed_destination_hosts": "Install-level egress allow-list (unset: no list). When set, sources, integrations, response webhooks, Microsoft Graph, enrichment providers and the LLM endpoint reach only these hosts; `*.example.com` allows subdomains; an empty or invalid list refuses everything. In an environment variable, separate hosts with commas. Used by the PoV profile (docs/pov.md).",
    "ingestion.read_only_sources": "Install-level: refuse pull sources that change the source after reading (the `m365_mailbox` and `imap` sources mark or move messages). Used by the PoV profile.",
    # mcp (lg-sotf mcp)
    "mcp.api_url": "Base URL of the LG-SOTF API the MCP server calls; https, or http for a loopback address only.",
    "mcp.api_key": "API key the MCP server uses (`read` scope; `write` for notes; `ingest` and `read` for test alerts). Environment only, never a command-line argument.",
    "mcp.api_key_file": "File holding the API key instead of `mcp.api_key` (setting both is refused), so no credential sits in the launching shell's environment. Refused when its group or other users can read or write it (`chmod 600`).",
    "mcp.tenant_id": "Pin every call to one customer tenant (`X-Tenant-ID`): an MSSP organisation's API key acting under that customer's grant (docs/mssp.md). Configuration only; no tool can choose another tenant.",
    "mcp.timeout_s": "Timeout of one API request.",
    "mcp.max_retries": "Retries of a read request on 429/502/503/504 or a connection error (writes are never retried).",
    "mcp.max_response_bytes": "Largest API response the MCP server reads.",
    "mcp.max_output_chars": "Largest tool result handed to the model; longer results are truncated with a note.",
}

Row = Tuple[str, str, str, str, str]


def env_var(path: str) -> str:
    return ENV_PREFIX + "__".join(part.upper() for part in path.split("."))


def type_name(annotation: Any) -> str:
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin in (typing.Union, types.UnionType):
        non_none = [a for a in args if a is not type(None)]
        inner = " | ".join(type_name(a) for a in non_none)
        return f"{inner} (optional)" if len(non_none) < len(args) else inner
    if origin is typing.Literal:
        return " \\| ".join(f"`{a}`" for a in args)
    if origin in (list, List):
        return f"list[{type_name(args[0])}]" if args else "list"
    if origin in (dict, Dict):
        return "mapping"
    if annotation is SecretStr:
        return "secret"
    if isinstance(annotation, type):
        return {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}.get(
            annotation.__name__, annotation.__name__
        )
    return str(annotation)


def render_default(value: Any) -> str:
    if value is None:
        return "unset"
    if isinstance(value, SecretStr):
        return f"`{value.get_secret_value()}`"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, (dict, list)):
        return "`{}`".format(json.dumps(value, separators=(", ", ": "))) if value else ("`{}`" if isinstance(value, dict) else "`[]`")
    return f"`{value}`"


def _walk(model: Type[BaseModel], instance: Any, prefix: str) -> Iterator[Tuple[str, Row]]:
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        annotation = field.annotation
        value = getattr(instance, name)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            yield from _walk(annotation, value, f"{path}.")
            continue
        if path not in DESCRIPTIONS:
            raise KeyError(f"settings field {path!r} has no description in docs/tools/settings_reference.py")
        section = prefix.rstrip(".")
        yield section, (path, env_var(path), type_name(annotation), render_default(value), DESCRIPTIONS[path])


def reference_rows() -> Dict[str, List[Row]]:
    """Rows per section, in declaration order (``""`` holds top-level fields)."""
    sections: Dict[str, List[Row]] = {}
    for section, row in _walk(Settings, Settings.model_construct(), ""):
        sections.setdefault(section, []).append(row)
    for name, model in (("routing", RoutingThresholds), ("ingestion", IngestionOptions)):
        for section, row in _walk(model, model(), f"{name}."):
            sections.setdefault(section, []).append(row)
    return sections


def documented_paths() -> List[str]:
    return [row[0] for rows in reference_rows().values() for row in rows]


def render() -> str:
    lines = [BEGIN, ""]
    for section, rows in reference_rows().items():
        title = f"`{section}`" if section else "Top level"
        lines.append(f"### {title}")
        lines.append("")
        intro = SECTION_INTRO.get(section)
        if intro:
            lines.append(intro)
            lines.append("")
        lines.append("| Setting | Environment variable | Type | Default | Description |")
        lines.append("|---|---|---|---|---|")
        for path, env, typ, default, desc in rows:
            lines.append(f"| `{path}` | `{env}` | {typ} | {default} | {desc} |")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def current_block(text: str) -> str:
    start = text.index(BEGIN)
    end = text.index(END) + len(END)
    return text[start:end]


def write(path: Path = DOC_PATH) -> bool:
    text = path.read_text(encoding="utf-8")
    new = text.replace(current_block(text), render())
    if new != text:
        path.write_text(new, encoding="utf-8")
        return True
    return False


def main(argv: List[str]) -> int:
    if "--write" in argv:
        changed = write()
        print("updated" if changed else "up to date", DOC_PATH)
        return 0
    if "--check" in argv:
        stale = current_block(DOC_PATH.read_text(encoding="utf-8")) != render()
        if stale:
            print(f"{DOC_PATH} is stale: run python docs/tools/settings_reference.py --write", file=sys.stderr)
        return 1 if stale else 0
    print(render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
