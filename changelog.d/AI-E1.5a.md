### Added

- Shadow mode, part one: system code can run a candidate pipeline (another
  model, prompt or graph) on a real alert beside the production run. The
  shadow run records what it would have done (notifications, escalation,
  response plan, alert changes, live UI events) in the new `shadow_effects`
  table instead of doing it. Migration `0013` creates the table; it is in the
  tenant data export and follows alert retention. No API endpoint exposes
  shadow runs yet.

### Security

- A shadow run cannot cause an effect outside the platform. Every egress
  path (HTTP clients, so Slack, webhooks, tickets and Microsoft; mail; the
  notification outbox; response connectors; WebSocket events; the work
  queue) refuses or records the call in shadow mode, and every database
  transaction it opens is read only, with no way to commit, notify or keep
  session state. Its Redis client sends reads only. An architecture test
  finds the egress call sites in the source and fails on any that is not
  covered.
- A shadow run never bills the tenant or spends its LLM token budget, never
  calls a threat-intelligence provider (it reads the lookup cache only, so
  its verdicts can see fewer threat-intelligence answers), and never moves
  production metrics.

### Changed

- The pipeline metrics (`lgsotf_node_seconds`, `lgsotf_llm_calls_total`,
  `lgsotf_llm_tokens_total`, `lgsotf_llm_cost_usd_total`,
  `lgsotf_llm_refusals_total`, `lgsotf_llm_skipped_total`,
  `lgsotf_enrichment_lookups_total`, `lgsotf_llm_slot_wait_seconds`) have a new `mode` label (`live` or
  `shadow`). Add `mode="live"` to your alerts and dashboards; the examples in
  `docs/operations.md` do.
