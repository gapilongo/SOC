## What and why

<!-- What does this change do, and what problem does it solve? Link issues. -->

## How it was tested

<!-- Tests added or changed; commands run (make lint, make test with the
integration variables, make smoke, npm test in src/lg_front ...). -->

- [ ] Unit tests
- [ ] Integration tests (PostgreSQL and Redis)
- [ ] Evaluation harness run (required when routing, prompts, agents or response planning change): paste the headline metrics before and after

## Safety and security impact

<!-- Answer each; write "none" where it does not apply. -->

- Tenant isolation (queries, Redis keys, events, caches):
- Authentication or authorisation:
- Automatic close, escalation or response behaviour:
- Prompt construction or handling of untrusted alert data:
- Secrets, redaction, logging of sensitive data:

## Operational impact

- [ ] Database migration (expand/contract, safe during a rolling upgrade)
- [ ] New or changed settings (documented; `python docs/tools/settings_reference.py --write` run)
- [ ] New metrics, alerts or runbook steps (docs/operations.md updated)
- [ ] Helm chart or Compose changes
- [ ] New dependency (Python, npm, image or action): the [admission checklist](https://github.com/gapilongo/SOC/blob/main/docs/dependency-policy.md#adding-a-dependency) is answered in the description

## Checklist

- [ ] `docs/architecture.md` and the affected docs match the code
- [ ] Changelog fragment added in `changelog.d/` for user-visible changes (not `CHANGELOG.md`)
- [ ] No secrets or real customer data in code, fixtures or test output
