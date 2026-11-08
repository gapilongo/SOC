### Fixed

- The "LLM errors" and "Run failures" alerts in the operations guide now sum
  both sides of their ratio before dividing. The old expressions divided each
  error series by itself, so the ratio was 1 as soon as one call or run
  failed, and the alert paged on a single error. If you copied either
  expression into your Prometheus rules, replace it.
