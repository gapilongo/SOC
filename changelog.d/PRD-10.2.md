### Added

- Blind audit of auto-closed alerts: a uniform random sample of the alerts
  automation closed goes to analysts with the AI verdict hidden, so the
  production false-negative rate can be measured without bias. Analysts
  label each sample malicious, benign or unsure on the new Blind audit page
  (keys M, B, U and N); only then is the AI's verdict, confidence, routing
  and reasoning shown, with the agreement. A malicious label opens a normal
  escalation for the alert; deciding it re-triages the alert with the
  analyst's decision.
- Until a sample is labelled, its alert's verdict, scores, summary and
  reasoning are hidden on every screen and API for everyone in the tenant
  (alerts, timeline, evidence pack, MCP, live updates), and the alert is left
  out of the value and detection reports. Alerts carry
  `hidden_for_blind_audit` while that is so.
- Samples are drawn every week when the tenant setting `blind_audit` is on
  (2% of auto-closed alerts, at least 5 a week by default; off until
  enabled), on demand with `lg-sotf audit-sample --tenant T` (also the
  proof-of-value random sample, for example `--size 200`), or from the
  Blind audit page. Runs follow each other without gaps, end 5 minutes
  before now, and use a seed the server picks and records; a dry run
  (`--dry-run`) re-draws a run with a given seed and records nothing.
- Reports > Blind audit and `GET /api/v1/reports/blind-audit` show the
  false-negative rate among auto-closed alerts, stratified over the
  sampling runs, with its 95% interval and sample size, the estimated
  number of missed threats, a worst case counting unsure and unlabelled
  samples as malicious, an "incomplete" mark until every sample is
  labelled, uncovered time, labels by organisation for MSSP grants, and
  "Not enough data (n=…)" below 30 labels. New beta endpoints under
  `/api/v1/blind-audit`.
