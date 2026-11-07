### Added

- API stability tiers. Every operation in the OpenAPI document now carries
  `x-stability`: `stable` (ingest, alerts, escalation review, actions,
  sources, suppressions, users, API keys, audit, auth and the health probes),
  `beta` (platform administration, tenant settings, reports, integrations,
  compliance exports, triage groups and bulk actions, MFA, usage, metrics) or
  `internal` (the dashboard summary and onboarding screens). A stable
  operation is deprecated for at least 6 months, and over two minor releases,
  before it is removed or changed incompatibly. See "Stability and
  deprecation" in docs/api.md.
- A deprecated route answers with `Deprecation` (RFC 9745), `Sunset`
  (RFC 8594) and `Link: <...>; rel="deprecation"` headers on every response,
  errors included, and is marked `deprecated: true` with an `x-sunset` date
  in the OpenAPI document. Browsers can read the three headers (CORS). No
  route is deprecated yet.
- A CI gate, `api-compat`: a pinned, checksum-verified oasdiff compares
  `docs/openapi.json` with the base branch's and fails on a breaking change
  to a stable operation, including a removal before its sunset or a move from
  stable to beta. Changes to beta and internal operations are reported only.
