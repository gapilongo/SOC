### Fixed

- A run no longer fails when an upgrade migrates the database while it is in
  flight. A migration that changes a table made the running workers'
  prepared statements on it stale, and the first transaction to use one
  failed with `InvalidCachedStatementError`; the message then waited for the
  visibility timeout (20 minutes by default) before another try. The worker's
  transactions on runs are now run again once, in a new transaction for the
  same tenant, and the run finishes normally. Each retry logs
  `db.stale_statement_retry` and counts in the new
  `lgsotf_db_stale_statement_retries_total` metric.
