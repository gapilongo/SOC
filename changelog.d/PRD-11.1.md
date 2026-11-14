### Added

- Proof-of-value runs, started without the command line. An admin opens
  **Proof of value** > *New proof of value* (a three-step wizard: the days of
  history to replay, the days of shadow period, review and start) or calls
  `POST /api/v1/pov/runs` (beta). The scheduler then runs the backtest over
  the alerts analysts decided in the history window and stores its result on
  the run (alerts replayed, confirmed threats, how many the triage would have
  closed, with sample sizes and intervals); the shadow period that follows
  links the tenant's reports over its dates. `GET /api/v1/pov/runs` and
  `GET /api/v1/pov/runs/{id}` show the status; `POST
  /api/v1/pov/runs/{id}/cancel` ends a run early. A run only reads: it
  changes no alert, creates no escalation, response action or notification,
  and its backtest runs in read-only transactions. One run in progress per
  tenant, at most 3 created in 24 hours, 500 alerts per backtest. The
  first-run setup now ends on the wizard, and the Reports page opens on the
  dates of a `?from=&to=` link. Migration `0019` adds the `pov_runs` table
  (tenant row-level security, in the tenant data export and erasure; the API
  role cannot write a run's backtest status or result). See docs/pov.md.
