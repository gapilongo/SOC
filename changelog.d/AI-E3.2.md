### Added

- The fact ledger: the record of what each investigation observed, and the
  only place an evidence fact gets the id a verdict cites. Code mints the
  id when a tool call returns and binds the fact to that call (the tool,
  the hashes of its input and output, its outcome, whether the answer was
  complete). A model never supplies an id, and a citation of an id the
  ledger did not mint can be told apart. A query that found nothing or
  failed is recorded too, and is never evidence that something is benign.
  - A ledger belongs to one investigation run, not to the alert: an alert
    that is processed again starts with an empty ledger, while a run that
    waits for an analyst, or a step retried after a crash, keeps its own. A
    retried step that records the same call again adds nothing.
  - An entry is complete only when the tool's result and the fact itself
    are. A benign claim that rests on an incomplete fact, or cites nothing,
    is reported as a finding.
  - Entries are kept per tenant and can only be added, never changed or
    deleted; a changed entry no longer matches its hash. They go with their
    alert at retention and tenant erasure and are part of the tenant export
    (`evidence_facts.jsonl`).
  - Nothing writes to the ledger yet: the investigation that does comes in
    a later release. See docs/evidence-facts.md.
- `GET /api/v1/alerts/{id}/investigation` lists the ledger entries of the
  alert's newest investigation run as observations, after the recorded
  lookups. Every observation has three new fields: `complete`, `fact_kind`
  and `citable_as_benign_evidence` (whether a benign claim may rest on it;
  never true for an empty or failed observation). The response also says
  how many observations there are (`observations_total`) and whether it
  lists fewer (`observations_truncated`); a call that failed or found
  nothing is always named under `not_established`.
- Database migration `0021` adds the `evidence_facts` table. It is new and
  empty, so the migration is quick and the previous release keeps working
  on the migrated schema.
