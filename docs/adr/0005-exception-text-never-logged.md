# 0005. Exception text is never logged

* Status: accepted
* Date: 2026-11-07
* Roadmap step: X1 ([refactor roadmap](../design/refactor-roadmap.md), Phase 5)

## Context and problem

An exception message is whatever the raising code put into it: a provider's
error body, a URL with a query string, a SQL fragment, the alert field a
parser choked on. In a SOC that text routinely contains bearer tokens, API
keys, JWTs and the alert itself, which may be personal data the tenant never
agreed to ship to the log pipeline.

Before X1 the code base caught 80 broad exceptions. 63 of those handlers
logged, almost all of them only `error=type(exc).__name__`: safe, but with no
way to tell where the failure came from. The two places that wanted a
location, the API's last-resort handlers (`api/errors.py` `_unhandled` and
`api/middleware.py`), passed `exc_info=exc`, which renders the full
traceback: the message, the message of every chained exception and the
source line of every frame. The logging redaction pass then had to catch
whatever credential shapes it recognised in that text, and alert text is not
a credential shape.

Error text that is stored or shown (a run's `last_error`, an outbox row's
`last_error`, an MCP error message) was sanitised four different ways, and
two of them truncated before redacting, which can cut a token below the
length its redaction pattern needs.

## Decision

* A caught failure is logged with
  `observability.logging.log_failure(logger, event, exc, *, level, **fields)`.
  The record carries `error` (the type name), `stack` (the innermost 15
  frames as `module:lineno in func`, built from code objects, so no source
  line is read) and `cause_types` (the type names of the chain Python would
  print). It never carries `str(exc)`, `repr(exc)` or `exc_info`.
* Existing event names and fields stay as they are; events that logged the
  type as `error_type` keep that key and gain `error`.
* Error text that is stored or shown goes through
  `security.redaction.safe_text` / `safe_error_text`: redact the whole text,
  collapse whitespace, then truncate. `runtime.worker.sanitize_error`,
  `integrations.delivery.safe_error`, `integrations.http.error_snippet` and
  the MCP client's `_safe_text` are thin wrappers over it.
* The logging redaction pass stays as defence in depth; it is not the
  control.

## Consequences

* A failure log says what failed and where, which is enough to find the code
  path; the message, when it is needed, is reproduced from the stored and
  redacted error text or in a debugging session, not from the log stream.
* A 500 from the API no longer prints a traceback. Operators who grepped for
  `Traceback` in API logs search `event=api.unhandled_error` and read
  `stack`.
* Stored error text can be a little shorter than before (the limit now
  covers the type name), and the MCP client now redacts the API's error
  messages.

## Alternatives considered

* **Log `exc_info` and rely on redaction.** Redaction recognises credential
  shapes, not alert content, and a traceback quotes every chained message
  and source line.
* **Log a redacted, truncated message.** Still ships alert text and makes
  every log line a redaction-coverage question.
* **Log the full frames with source text.** Source lines often build the
  message (`raise X(f"... {payload}")`), so they leak the same data.
