### Added

- Shadow agreement report: `lg-sotf shadow-run --tenant T --candidate profile.yaml --window 7d`
  replays a tenant's recently decided alerts through a candidate model
  profile in shadow mode and reports how often it takes the same route as
  production (overall and per route, with n and a 95% confidence interval),
  a confusion matrix, the alerts the candidate would have closed where
  production escalated (listed first), escalate and plan_response
  differences, candidate failures, new escalations, different response
  plans, and the cost and latency difference per alert. A candidate run that
  fails, or whose model answers are unusable so the rules decide, counts as a
  disagreement and is listed; the report says when there is not enough to
  judge the candidate on. Platform admins can also read the report at
  `GET /api/v1/platform/shadow/reports/{id}` (beta). Migration `0015` adds
  the `shadow_verdicts` table (append-only, tenant row-level security,
  deleted with its alert, in the tenant data export, not in the evidence
  pack).

### Security

- `lg-sotf shadow-run` reads only through the SELECT-only shadow database
  role (`database.shadow_url`, AI-E1.5c) and refuses to run without it. Reading
  a shadow report is audited as `platform.shadow_report_viewed` in the
  platform admin's home tenant.
- A candidate profile expands `${VAR}` only in `llm.api_key`, and only from a
  `CANDIDATE_` variable, so it cannot send a process secret to an endpoint
  of its choice. A candidate on another provider or `base_url` never gets
  production's LLM API key, by inheritance or by name.
