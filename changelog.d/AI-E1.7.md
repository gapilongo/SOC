### Added

- Every rate in the evaluation reports, the scorecard and the Reports pages
  now comes with its sample size and a 95% Wilson interval, for example
  `25.0% (1 of 4; 95% CI 4.6% to 69.9%)`, so a rate over a handful of alerts
  no longer reads like a firm number. Eval reports carry `metrics.intervals`,
  which the gate can check (for example
  `intervals.malicious_false_negative_rate.ci_high`). The `/reports/*`
  responses add a `<rate>_ci` field next to each rate, with `rate`, `n`,
  `ci_low` and `ci_high`, and the CSV exports add `_n`, `_ci_low` and
  `_ci_high` columns at the end. Existing fields and columns are unchanged.
  A sample too small to read is shown everywhere as "Not enough data (n=…)".
