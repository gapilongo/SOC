# Evidence facts (schema v1)

An **evidence fact** is one typed observation that an investigation tool or
connector returned: an IP address's reputation, a process's ancestry, a
user's recent sign-ins, a related alert. A verdict cites the facts it rests
on by `id`, so every claim can be traced to an observation.

The schema is a public contract, shared by the tools that produce facts, the
investigation's citation check and the evidence pack. It is published as
JSON Schema 2020-12 with a SemVer version:

| | |
|---|---|
| Schema | [`schemas/evidence-fact/v1.json`](../schemas/evidence-fact/v1.json) |
| `$id` | `urn:lg-sotf:schema:evidence-fact:1.0.0` |
| Examples | [`schemas/evidence-fact/examples/`](../schemas/evidence-fact/examples/), one or more per kind |
| Python model | `lg_sotf.models.evidence_fact` (`parse_fact`, `EvidenceFact`) |

Status: published, not yet produced. The investigation agents start emitting
facts in a later release.

## Shape

Every fact has these fields; `kind` selects the type of `value`.

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | no (written by producers) | The schema version the producer wrote, `1.x.y`. |
| `id` | yes | Stable within an investigation; verdicts cite it. Letters, digits and `_ . : -`, at most 128 characters. |
| `kind` | yes | One of the kinds below. |
| `subject` | yes | The entity the fact is about: `{type, value}`, `type` one of `ip`, `domain`, `url`, `user`, `host`, `process`, `file`, `alert`. A file is named by its SHA-256. |
| `observed_at` | yes | When the source observed it, RFC 3339 with an offset. |
| `source` | yes | The connector or tool: `{name, version}`, `name` in lower case (`virustotal`, `defender.ah`). |
| `value` | yes | The typed payload of the kind. |
| `confidence` | no | The source's confidence in the observation, 0 to 1. |
| `ttl_seconds` | no | How long after `observed_at` the fact stays current. Absent means it does not expire. |
| `provenance` | no | `source_step_id` (the investigation trace step that produced it, a UUID), `input_hash` and `output_hash` (lowercase hex SHA-256 of the tool call and its result). |
| `redactions` | no | What was removed or cut before the fact was stored: `{path, reason}`, `path` a JSON Pointer into the fact, `reason` one of `secret`, `pii`, `truncated`. |

There is no free-text field. A fact carries typed values only, so the
investigation's planner never reads a tool's raw text; summaries are rendered
from the typed values.

The tenant a fact belongs to is held internally and is never exported: the
schema does not allow a `tenant_id` field.

## Kinds

| `kind` | Usual subject | `value` |
|---|---|---|
| `reputation` | `ip`, `domain`, `url`, `file` | `verdict` (`malicious`, `suspicious`, `benign`, `unknown`), `score` (0–100, higher is worse), `categories` |
| `process_lineage` | `process` | `chain`: the ancestry, oldest first and the subject process last; each node has `name` and optionally `pid`, `command_line`, `sha256`, `user`, `started_at` |
| `sign_in_history` | `user` | `window_start`, `window_end`, `total`, `failed`, and up to 50 `sign_ins` (newest first): `at`, `result` (`success`, `failure`, `interrupted`), `ip`, `country` (ISO 3166-1 alpha-2), `app`, `risk` (`none`, `low`, `medium`, `high`) |
| `related_alert` | `host`, `user`, `ip`… | Another alert on the same subject: `alert_id`, `title`, `severity`, `created_at`, `disposition` |

Facts are closed objects: a field the schema does not list is refused.

## Versioning

The version lives in the `$id`. The rules, enforced in CI:

- **Major** (breaking): a removed field, a newly required field, a narrowed
  type, a removed enum value or kind, a tighter limit, a changed pattern or
  format. A breaking change is never made to a published file; it is
  published as a new file, `v2.json`, beside `v1.json`.
- **Minor**: a new optional field, a new enum value or kind, a wider type or a
  looser limit.
- **Patch**: titles, descriptions, examples and defaults.

A fact written under 1.1.0 may carry a field or a kind that the 1.0.0 schema
refuses. A consumer that pins an older minor version should ignore what it
does not know rather than reject the fact.

## For contributors

The Pydantic model is the source; the JSON file is generated from it.

```bash
python scripts/export_schemas.py             # regenerate schemas/*/v*.json from the models
python scripts/export_schemas.py --check     # exit 1 if a committed file is stale
python scripts/ci/schema_compat.py --base origin/main   # the CI breaking-change check
```

To change the schema: edit `lg_sotf/models/evidence_fact.py`, raise
`SCHEMA_VERSION` as the rules above require, regenerate, and add or update an
example for any new kind. The unit tests
(`tests/unit/models/test_evidence_fact.py`) fail if the file is stale or an
example is invalid; the `schemas` CI job fails if the version bump is too
small for the change.
