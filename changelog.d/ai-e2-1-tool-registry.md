### Added

- Tool registry (`lg_sotf.tools.registry`, AI-E2.1): every lookup the
  analysis agent makes is now a declared tool called through one registry.
  A tool does not load without a read-only risk class (there is no write
  class), a strict parameter model, row, time and window caps and a declared
  egress. Every call validates its parameters first, skips a tool the calling
  tenant switched off (`tools.<provider>.enabled: false` in that tenant's
  settings), runs under the time cap and is recorded in the trace.
  - The VirusTotal and AbuseIPDB lookups (`reputation.<provider>`) and the
    alert-history lookup (`platform.history`) run through it. Their results,
    trace steps and recorded cassettes are unchanged.
  - Every tool result carries a typed outcome: `success`, `empty` (the query
    ran and matched nothing) or `failed` (switched off, unreachable, refused,
    timed out or over the row cap). A failed call can no longer be mistaken
    for "no rows".
  - Every tool result carries the SHA-256 of its input and of its output,
    the same hashes the investigation trace stores for the call.
  - New pending invariants, numbered as ADR-0014 numbers them: INV-14,
    "Evidence tools are read-only, templated and capped", which the Wazuh
    query templates (INT3.4) complete; and INV-13, "Autonomy is earned per
    skill and tenant and lost on any miss", registered as a placeholder that
    AI-E3.10 delivers.
