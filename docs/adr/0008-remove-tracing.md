# 0008. Remove tracing until someone consumes traces

* Status: accepted
* Date: 2026-11-07
* Roadmap step: X5 ([refactor roadmap](../design/refactor-roadmap.md), Phase 5)

## Context and problem

`lg_sotf.observability.tracing` built an OpenTelemetry tracer provider with an
OTLP/HTTP exporter when `observability.otlp_endpoint` was set. Four call
sites installed and shut it down (`cli._prepare`, the API lifespan in
`api/app.py`, and the worker and scheduler shutdown paths), but nothing ever
created a span: `get_tracer` had no callers and no library instrumentation
was installed. An operator who set the endpoint got an exporter that sent
nothing, while every image carried three direct OpenTelemetry dependencies
(`opentelemetry-api`, `-sdk`, `-exporter-otlp-proto-http`), eight pinned
packages with their protobuf stack, and their advisories (1.2.2 had to bump
them).

No deployment runs a trace backend: the compose files and the Helm chart
start none, and the only OTLP references were pass-through variables and a
commented example. Nobody has committed to consuming traces. Instrumenting
properly is not small: spans at the API, the queue worker, the LangGraph
nodes and the LLM calls, a `traceparent` carried on stream messages, a
`trace_id` in the logs, and outbound spans that must never record a URL path
(Slack and Teams webhook URLs are credentials).

## Decision

* **Remove tracing.** `observability/tracing.py`, its four call sites, its
  re-exports from `lg_sotf.observability` and the three OpenTelemetry
  dependencies are deleted. The pinned requirement files are regenerated
  with the `pip-compile` commands in their headers.
* **Keep accepting the setting.** `observability.otlp_endpoint` stays a
  valid, ignored setting so no existing configuration is refused at
  startup. When it is set, `configure_logging` logs one warning,
  `observability.otlp_endpoint_deprecated`, in every process role.
  `observability.service_name` stays: it is a field of every log line and
  the Redis client name.
* **Deploy files and docs stop promising traces.** The Helm example, the
  compose pass-through variable, the `configs/*.yaml` keys and the
  `.env.example` entry are removed; the configuration reference marks the
  setting deprecated.

## Consequences

* A smaller dependency set: the SDK, the OTLP exporter, their protobuf
  stack and their advisories go. `opentelemetry-api` stays installed as a
  transitive dependency (FastAPI and the Anthropic client require it); it is
  not a direct dependency and nothing in `lg_sotf` imports it.
* Logs (with `request_id`, `tenant_id`, `alert_id`, `thread_id` and `node`)
  and Prometheus metrics remain the observability surface
  (`docs/operations.md` §9).
* A later release may delete the `otlp_endpoint` field; `Settings` sections
  ignore unknown keys, so configurations that still set it will keep loading
  then too.

### Bringing tracing back

When an operator commits to a trace backend, supersede this ADR and
instrument at the choke points, in this order:

1. A `span()` helper in `lg_sotf.observability` that is a no-op without an
   endpoint, and a provider installed in each composition root (`cli`, the
   API lifespan, worker, scheduler) with a flush on shutdown.
2. A structlog processor that adds `trace_id` to every log line.
3. API middleware spans named by the route template only (never the raw
   path), and a `worker.process` span per message.
4. An optional `traceparent` field on stream messages (`parse_message`
   ignores unknown fields, so rolling deploys stay safe).
5. Workflow node and LLM call spans.
6. Outbound spans only through an `httpx` event hook in
   `lg_sotf.net.http.guarded_client`, recording host, method and status,
   never the path or query.

Restore the dependencies in `pyproject.toml` and regenerate the requirement
files; the removed module is in git history.

## Alternatives considered

* **Keep the exporter as it was.** It exports nothing, costs three
  dependencies and their advisories, and tells operators tracing works.
* **Instrument now.** Medium effort across the API, the queue, the workflow
  and every outbound stack, for traces nobody would read.
* **Delete `otlp_endpoint` outright.** `Settings` would ignore the key
  without a word, so an operator who relied on it would not learn that
  tracing is gone. A warning first, removal later.
