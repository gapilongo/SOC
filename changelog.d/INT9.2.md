### Added

- The evidence-fact schema v1, a published contract for the typed
  observations investigation tools return (IP, domain, URL and file
  reputation, process lineage, sign-in history, related alerts), which
  verdicts will cite by id. It is a JSON Schema 2020-12 file with a SemVer
  version, `schemas/evidence-fact/v1.json`, with an example per kind, and CI
  refuses a change that is not matched by the right version bump. See
  docs/evidence-facts.md.
