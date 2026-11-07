### Added

- Shadow mode, part one: system code can run a candidate pipeline (another
  model, prompt or graph) on a real alert beside the production run. The
  shadow run records what it would have done (notifications, escalation,
  response plan, alert changes, live UI events) in the new `shadow_effects`
  table instead of doing it. Migration `0012` creates the table; it is in the
  tenant data export and follows alert retention. No API endpoint exposes
  shadow runs yet.

### Security

- A shadow run cannot cause an effect outside the platform. Every egress
  path (HTTP clients, so Slack, webhooks, tickets and Microsoft; mail; the
  notification outbox; response connectors; WebSocket events; the work
  queue) refuses or records the call in shadow mode, and every database
  transaction it opens is read only. An architecture test finds the egress
  call sites in the source and fails on any that is not covered.
