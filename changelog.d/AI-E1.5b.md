### Added

- Shadow agreement report: `lg-sotf shadow-run --tenant T --candidate profile.yaml --window 7d`
  replays a tenant's recently decided alerts through a candidate model
  profile in shadow mode and reports how often it takes the same route as
  production (overall and per route, with n and a 95% confidence interval),
  a confusion matrix, the alerts the candidate would have closed where
  production escalated (listed first), new escalations, different response
  plans, and the cost and latency difference per alert. The report is also
  readable by platform admins at `GET /api/v1/platform/shadow/reports/{id}`
  (beta). Migration `0014` adds the `shadow_verdicts` table (append-only,
  tenant row-level security, deleted with its alert, in the tenant data
  export, not in the evidence pack).

### Security

- `lg-sotf shadow-run` refuses to run until shadow runs have their own
  SELECT-only database role (AI-E1.5c). On a development or test database it
  runs with `--i-understand-no-shadow-role`; that flag is refused in staging
  and production. Reading a shadow report is audited as
  `platform.shadow_report_viewed` in the platform admin's home tenant.
