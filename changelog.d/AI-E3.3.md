### Added

- Evidence lookups before the deep analysis (AI-E3.3). For a Wazuh alert,
  the platform can now look up facts in the customer's own Wazuh data
  before the deep model judges the alert, show the model those facts and
  ask it which ones its claims rest on. It is off by default: a tenant admin
  turns it on with `tools.wazuh_indexer.enabled: true` in the tenant
  settings. Alerts of other sources, and of tenants that have not turned it
  on, are analysed exactly as before.
  - What is looked up is a reviewed playbook file, `wazuh.default`: the
    host's alerts in the hour up to the alert; on how many agents the
    alert's file, service binary or process image was seen over 30 days;
    and, when the alert names an account or a source address, every logon
    of it over the day before. The values come from fields the detector
    wrote, never from the alert's title or description and never from a
    model. A lookup whose value is missing or not well-formed is skipped.
  - Every lookup is recorded on the run's fact ledger, whether it found
    something, found nothing or failed. The lookups run at once; a fact
    whose time window had not closed says `complete: false`.
  - The deep model gets the recorded facts as untrusted data and is asked
    to return the claims its verdict rests on, each with the ids of the
    facts it cites. Code checks every cited id against the ledger of the
    same run. An id the ledger did not record, or a benign claim that cites
    an empty, failed or incomplete lookup, is recorded as a finding. The
    findings are shown; they do not change a verdict or a routing decision
    in this release, and what closes an alert is unchanged.
  - Budgets per investigation: 8 lookups, 60 seconds, 20,000 tokens and
    $0.25 (`investigation.budget`). A tenant can set its own in its
    `investigation.budget` setting, up to the install's
    `investigation.tenant_max`. After two lookups in a row without an
    answer the rest are skipped.
  - When the lookups cannot finish (the indexer does not answer, a budget is
    spent, no fact came back, or the lookup code itself fails), the alert is
    analysed as it is today and the reason is recorded and shown. A failed
    lookup never fails, closes or escalates an alert. A step that is retried
    after a crash does not ask again for an answer it already has; a lookup
    that failed is asked again when the alert is analysed again.
  - The alert must come from a Wazuh indexer source (one the platform
    polls): a pushed Wazuh alert has no indexer to read and is analysed as
    before. On a Wazuh cluster shared between customers, turn the lookups on
    only where the index pattern or the indexer user separates the tenant
    from the others. See docs/evidence-facts.md.
  - A shadow run makes the lookups and writes nothing.
  - The playbook declares two malicious indicators over the host's
    activity. They are evaluated and reported; they do not block a close
    yet.
  - See docs/evidence-facts.md ("The investigation executor").
- `GET /api/v1/alerts/{id}/investigation` has a new `evidence_run` field:
  whether the lookups ran, each lookup with its outcome and the
  observations it recorded, what was used of each budget, the indicators,
  and, when no lookup was made or the analysis ran without them, the reason
  as a code and a sentence. `claims` now starts with the deep model's
  claims, each with the observations it cites and a new `findings` list.
  A skipped lookup is named under `not_established.not_checked`, and the
  lookups are a step of `steps`.
- Tenant settings: `investigation.budget` (`steps`, `wall_s`, `tokens`,
  `usd`).
- Install settings: the `investigation` section. `evidence_backend` says
  where the evidence tools read: `indexer` (the default, each tenant's own
  Wazuh indexer) or `event_store` (a dataset's synthetic telemetry in
  memory, for evaluation and development). The backend is never chosen
  silently: `event_store` is refused in staging and production, and a
  worker started with it says so on standard error. See
  docs/configuration.md.
- Two prompt templates, `analysis.verdict_cited` and
  `analysis.react_step_cited`, used only when lookups returned facts. The
  existing analysis prompts are unchanged, so recorded cassettes and prompt
  hashes of today's path stay valid.
- Evaluation: a dataset's `_meta.tenant_settings.tools.wazuh_indexer`
  turns the lookups on for its evaluation tenants. On `corpus_v1` with its
  telemetry and the stand-in model, 452 of 520 alerts were investigated
  (the others are high or critical alerts that go straight to a person
  without the deep analysis), with 1.7 facts per alert on average and no
  failed lookup. See docs/evaluation.md ("The investigation
  harness on the corpus").
