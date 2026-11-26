### Added

- Evidence lookups before the deep analysis (AI-E3.3). For a Wazuh alert,
  the platform can now look up facts in the customer's own Wazuh data
  before the deep model judges the alert, show the model those facts and
  ask it which ones its claims rest on. It is off by default: a tenant admin
  turns it on with `tools.wazuh_indexer.enabled: true` in the tenant
  settings. Alerts of other sources, and of tenants that have not turned it
  on, are analysed exactly as before.
  - What is looked up is a reviewed playbook file, `wazuh.default`: the
    host's other alerts in the hour up to the alert (the alert's own event
    is left out: an alert is never its own evidence); on how many agents
    the alert's file, service binary or process image was seen over the 30
    days up to the alert; and, when the alert names an account or a source
    address, every logon of it over the day before. Prevalence is not asked
    for a program every host runs (a system binary, an interpreter such as
    `powershell.exe`): the lookup is skipped with the reason
    `common_binary`. The values come from fields the detector
    wrote, never from the alert's title or description and never from a
    model. A lookup whose value is missing or not well-formed is skipped.
  - Every lookup is recorded on the run's fact ledger, whether it found
    something, found nothing or failed. The lookups run at once; a fact
    whose time window had not closed says `complete: false`.
  - The deep model gets the recorded facts as untrusted data and is asked
    to return the claims its verdict rests on, each with the ids of the
    facts it cites. Code checks every cited id against the ledger of the
    same run. An id the ledger did not record, a benign claim that cites
    an empty, failed or incomplete lookup, and a benign verdict with no
    claim at all are recorded as findings and shown. They never change the
    model's verdict.
  - Evidence can hold an AI close and can never buy one. With the autonomy
    tier `auto_full_audit`, an alert the models judged benign now goes to a
    person, with the reason, when its lookups show a sign of an attack that
    the playbook declares (another alert of rule level 12 or higher, or of
    a class only a person may close, on the same host in the hour: decide
    code `evidence_indicator`), or when the benign verdict cites an
    observation that was never recorded or a lookup that found nothing or
    failed (`evidence_citation`). A sign the lookups could not settle does
    not hold the close. Tenants that have not turned the lookups on are not
    affected. INV-03 says so.
  - Text an attacker can write into a fact (a user name typed at a logon,
    a command line) is scanned for steering instructions before any model
    sees it, with the scan the alert's own text gets. A flagged string is
    replaced by a fixed marker in what the model reads, the record names
    the fact, and no automatic close goes past it (`evidence_steering`).
    The recorded fact keeps what the tool returned.
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
  - A source address is looked up in the spelling the detector wrote and
    in its canonical form.
  - See docs/evidence-facts.md ("The investigation executor").
- `GET /api/v1/alerts/{id}/investigation` has a new `evidence_run` field:
  whether the lookups ran, each lookup with its outcome and the
  observations it recorded, what was used of each budget, the indicators
  (with `holds_close` and the observations a true one read), the
  observations with steering text (`steering_observation_ids`), what of
  the evidence holds an AI close (`holds_close`), and, when no lookup was
  made or the analysis ran without them, the reason as a code and a
  sentence. The same reasons appear in `outcome.blockers`, and the work
  queue shows a plain sentence for the three new routing codes. `claims` now starts with the deep model's
  claims, each with the observations it cites and a new `findings` list.
  A skipped lookup is named under `not_established.not_checked`, and the
  lookups are a step of `steps`.
- Tenant settings: `investigation.budget` (`steps`, `wall_s`, `tokens`,
  `usd`).
- Install settings: the `investigation` section. `evidence_backend` says
  where the evidence tools read: `indexer` (the default, each tenant's own
  Wazuh indexer) or `event_store` (a dataset's synthetic telemetry in
  memory, for evaluation and development). The backend is never chosen
  silently: `event_store` loads only when `environment` is set explicitly
  to `development` or `test` (an install that does not say is refused),
  and a worker started with it says so on standard error. See
  docs/configuration.md.
- Two prompt templates, `analysis.verdict_cited` and
  `analysis.react_step_cited`, used only when lookups returned facts. The
  existing analysis prompts are unchanged, so recorded cassettes and prompt
  hashes of today's path stay valid.
- Evaluation: a dataset's `_meta.tenant_settings.tools.wazuh_indexer`
  turns the lookups on for its evaluation tenants. On `corpus_v1` with its
  telemetry and the stand-in model, 452 of 520 alerts were investigated
  (the others are high or critical alerts that go straight to a person
  without the deep analysis), with no failed lookup. At the tier
  `auto_full_audit`, automation closed 58 attacks with the lookups off and
  35 with them on: the evidence held 23 and bought none. It also held 18
  benign alerts, all because the stand-in model cites lookups that found
  nothing; a real-model run has to measure that. See docs/evaluation.md ("The investigation
  harness on the corpus").
