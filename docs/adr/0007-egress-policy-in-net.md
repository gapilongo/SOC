# 0007. Keep the egress policy in `lg_sotf.net`, with one reader per strictness

* Status: accepted
* Date: 2026-11-06
* Roadmap step: F3 (extract `lg_sotf.net`), F4 (one reader of `allow_private_destinations`) ([refactor roadmap](../design/refactor-roadmap.md), Phase 1)

## Context and problem

Every outbound request to a tenant-controlled URL (pull sources, integrations,
response webhooks, Microsoft Graph) goes through
`lg_sotf.net.egress.DestinationPolicy`. Which private addresses it allows is
an install-level decision, `ingestion.allow_private_destinations`. F3 moved
the policy out of `ingestion`, but the rule that turns settings into a policy
was still written three times: `integrations/http.py` and
`services/connectors/registry.py` each validated the whole `ingestion`
section through `ingestion.options.IngestionOptions` (two import-linter
exceptions, adapters and services importing an application package), and
`integrations/microsoft/http.py` rebuilt the result with `require_https=True`.

`Settings.ingestion` is a free-form mapping, so it is validated only by its
readers, and the readers disagree on purpose. Pull sources cannot run
correctly with an invalid batch size or page size, so they refuse. The API
and the scheduler must still start, and must not reach private networks
because of a typo in an unrelated key.

## Decision

* **The fields** of the section are declared once, on
  `lg_sotf.settings.IngestionSection`, a field-only pydantic model that is
  not part of `Settings` validation.
* **The strict reader** is `lg_sotf.ingestion.options.IngestionOptions`, a
  subclass that adds `from_settings` and `for_source`: an invalid section
  raises `SourceConfigError`, and the pull source does not run.
  `PullConnector` builds its policy from it (`ingestion/sources/base.py`).
* **The lenient reader** is `lg_sotf.net.egress.egress_policy(settings, *,
  require_https=None)`. It reads only `allow_private_destinations`: an
  invalid section (any key) means private destinations are refused, and
  nothing is raised. `require_https` defaults to `settings.is_production`.
  Integrations, the connector registry (webhooks) and Microsoft Graph
  (`require_https=True`) call it; nothing else builds a policy from settings.
* `lg_sotf.net` stays a leaf: it imports the kernel (`errors`, `settings`)
  and `httpx`, never an application package, and does not import pydantic
  directly.

## Consequences

* The two `-> lg_sotf.ingestion.options` import-linter exceptions are gone.
* The behaviour is unchanged: the same defaults, the same fail-closed reading
  for integrations, the same strict reading for pull sources. Tests in
  `tests/unit/net/test_egress.py` pin both readings and that every
  integration client uses `egress_policy`.
* A new outbound client takes its policy from `egress_policy`, or from
  `IngestionOptions` if it is a pull source.

## Alternatives considered

* **Validate `ingestion` as part of `Settings`.** Every role would refuse to
  start on an invalid ingestion limit, including the API, which does not
  ingest pull sources. That is a behaviour change, out of scope here.
* **Make `egress_policy` strict.** An invalid section would stop the
  scheduler from delivering notifications. Failing closed on the one key it
  needs is safer and keeps today's behaviour.
* **Keep a policy helper in `integrations/http.py`.** The registry is in
  `services` and pull sources in `ingestion`; the policy is a network
  concern, so it lives with `DestinationPolicy`.
