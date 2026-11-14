### Added

- The fact ledger: the record of what each investigation observed, and the
  only place an evidence fact gets the id a verdict cites. Code mints the
  id when a tool call returns and binds the fact to that call (the tool,
  the hashes of its input and output, its outcome, whether the answer was
  complete). A model never supplies an id, and a citation of an id the
  ledger did not mint can be told apart. A query that found nothing or
  failed is recorded too, and is never evidence that something is benign.
  Entries are kept per tenant and can only be added, never changed or
  deleted; they go with their alert at retention and tenant erasure and are
  part of the tenant export (`evidence_facts.jsonl`). Nothing writes to the
  ledger yet: the investigation that does comes in a later release. See
  docs/evidence-facts.md.
- `GET /api/v1/alerts/{id}/investigation` lists a run's ledger entries as
  observations, after the recorded lookups. Every observation has three new
  fields: `complete`, `fact_kind` and `citable_as_benign_evidence` (whether
  a benign claim may rest on it; never true for an empty or failed
  observation).
- Database migration `0021` adds the `evidence_facts` table. It is new and
  empty, so the migration is quick and the previous release keeps working
  on the migrated schema.
