### Security

- Shadow runs now read the database only as a dedicated SELECT-only role,
  `lgsotf_shadow`, from a connection pool of their own. A statement that
  slips past the shadow statement guard, for example a `COMMIT` hidden
  behind a comment marker inside a string literal, now fails at the database
  for lack of privilege instead of writing. The guard stays as a second line
  of defence.
- A shadow run of an alert a model judges a threat no longer tries to reopen
  the related alerts the models closed. The attempt changed nothing (the
  database refused it), but it was counted in
  `lgsotf_retro_reopen_failures_total` and logged as an error, which could
  page the operator. The shadow run now records that the reopen would have
  run, and reopens and enqueues nothing.

### Added

- New settings `database.shadow_url` (the shadow role's login),
  `database.shadow_role` (the role `lg-sotf migrate` grants `SELECT` on the
  tenant tables, except the credential tables, and nothing else) and
  `database.shadow_pool_max`. Without `database.shadow_url` shadow runs
  refuse to start; they never fall back to the runtime role. `lg-sotf
  migrate` refuses a shadow role that could write or bypass tenant
  isolation, and changes nothing in that case.
- Production compose: set `LGSOTF_SHADOW_PASSWORD` before the first start
  to create `lgsotf_shadow`, grant it and give its login to the worker.
  Helm: the new `secrets.shadowSecret` (key `LG_SOTF_DATABASE__SHADOW_URL`,
  loaded into the worker only) and `settings.database.shadow_role`. For an
  existing database, create the role by hand (docs/deployment.md, section 4).
- New setting `security.shadow_candidate_llm_hosts`: the LLM hosts a shadow
  candidate profile may call besides production's own. It is read from the
  production settings only; a candidate profile cannot extend it.
  `lg-sotf shadow-run` refuses a candidate on any other host before reading
  any alert, and stores the candidate's host (never its key) on each
  verdict row and in the report (`candidate_host`; migration `0017`).
- Each `lg-sotf shadow-run` is audited in the tenant
  (`tenant.shadow_replayed`) and in the platform tenant
  (`platform.tenant_shadow_replayed`), with the report id, candidate label
  and host, window and number of alerts.

### Removed

- The `--i-understand-no-shadow-role` option of `lg-sotf shadow-run`: the
  command now always needs the shadow database role, in every environment.
