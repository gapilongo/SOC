### Added

- Blind audit of auto-closed alerts: a uniform random sample of the alerts
  automation closed goes to analysts with the AI verdict hidden, so the
  production false-negative rate can be measured without bias. Analysts
  label each sample malicious, benign or unsure on the new Blind audit page
  (keys M, B, U and N); only then is the AI's verdict, confidence, routing
  and reasoning shown, with the agreement. A malicious label opens a normal
  escalation for the alert.
- Samples are drawn every week when the tenant setting `blind_audit` is on
  (2% of auto-closed alerts, at least 5 a week by default; off until
  enabled), on demand with `lg-sotf audit-sample --tenant T` (also the
  proof-of-value random sample, for example `--size 200`), or from the
  Blind audit page. Each run records its seed and how many alerts were
  eligible, so the draw can be reproduced.
- Reports > Blind audit and `GET /api/v1/reports/blind-audit` show the
  false-negative rate among auto-closed alerts with its 95% interval and
  sample size, the estimated number of missed threats, and "Not enough data
  (n=…)" below 30 labels. New beta endpoints under `/api/v1/blind-audit`.
