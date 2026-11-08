### Added

- `lg-sotf verify-invariants` checks this install's safety invariants,
  read-only, in a synthetic dry-run tenant: forced row-level security on
  every tenant table, a runtime role that cannot bypass it, an append-only
  audit log, the response kill switch, the routing policy for high-severity
  alerts, log redaction and evidence-pack sealing. It exits 1 when a check
  fails; `--json` prints the results as JSON.
- `docs/invariants.md` lists the twelve safety invariants, each with its
  rationale, owner, threat-model rows and the tests that prove it. CI fails
  when a named test is missing or an enforced invariant's test is skipped.
