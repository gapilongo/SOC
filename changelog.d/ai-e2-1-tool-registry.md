### Added

- Tool registry (`lg_sotf.tools.registry`, AI-E2.1): every lookup the
  analysis agent makes is now a declared tool called through one registry.
  A tool does not load without a read-only risk class (there is no write
  class), a strict and bounded parameter model, row, time and window caps and
  a declared egress. Every call validates its parameters first, enforces the
  caps, holds the tool to the egress it declared and is recorded in the
  trace.
  - The VirusTotal and AbuseIPDB lookups (`reputation.<provider>`) and the
    alert-history lookup (`platform.history`) run through it. Recorded
    cassettes replay unchanged.
  - Every tool result carries a typed outcome: `success`, `empty` (the query
    ran and matched nothing) or `failed` (refused, timed out, raised, over
    the row cap, or no answer from the source). A failed call can no longer
    be mistaken for "no rows". `complete` is false when a result holds as
    many rows as its cap.
  - The investigation trace stores the same outcome for the step. Migration
    0018 adds `empty` and `failed` to `investigation_steps.outcome`. A
    history lookup that finds no earlier alert is now stored as `empty`, not
    `success`.
  - Every tool result carries the SHA-256 of its input and of its output:
    the hashes of its stored trace step. The output hash no longer changes
    when the same answer comes from the cache.
  - New pending invariants, numbered as ADR-0014 numbers them: INV-14,
    "Evidence tools are read-only, templated and capped", which the Wazuh
    query templates (INT3.4) complete; and INV-13, "Autonomy is earned per
    skill and tenant and lost on any miss", registered as a placeholder that
    AI-E3.10 delivers.

### Changed

- The per-tenant tool switch fails closed. A third-party lookup runs only
  when `tools.<provider>` is absent from the tenant's settings or its
  `enabled` is absent or exactly `true`. A value such as `"false"` or `0`, a
  setting that is not a mapping, or settings that cannot be read keep the
  lookup off. Before, only `enabled: false` switched it off.
- An HTTP 404 from AbuseIPDB is now an error, not "unknown address" (AbuseIPDB
  answers 200 for an address it does not know). A VirusTotal answer without
  analysis statistics is now an error, not a verdict with zero detections.
