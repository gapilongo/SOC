### Fixed

- An evaluation no longer depends on the hour it runs. An email item used to
  be stamped with the time it was ingested, which became the alert's
  `occurred_at`, and triage adds rule confidence to alerts outside
  06:00-18:00 UTC. A run in the evening built different triage prompts than
  a run in the morning, so the committed `phishing_v1` cassettes stopped
  replaying after 18:00 UTC (#346). The evaluation runner now ingests each
  report at its own `Date` header, or at a fixed noon when it has none.
  Production still stamps a pushed report with the time it arrives.
