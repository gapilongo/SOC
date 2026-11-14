# Evidence facts (schema v1)

An **evidence fact** is one typed observation that an investigation tool or
connector returned: an IP address's reputation, a process's ancestry, a
user's recent sign-ins, a related alert, what a host did around an alert, how
many accounts a source tried to log on to, how widely a file or a service is
seen. A verdict cites the facts it rests on by `id`, so every claim can be
traced to an observation.

The schema is a public contract, shared by the tools that produce facts, the
investigation's citation check and the evidence pack. It is published as
JSON Schema 2020-12 with a SemVer version:

| | |
|---|---|
| Schema | [`schemas/evidence-fact/v1.json`](../schemas/evidence-fact/v1.json) |
| `$id` | `urn:lg-sotf:schema:evidence-fact:1.1.0` |
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
| `subject` | yes | The entity the fact is about: `{type, value}`, `type` one of `ip`, `domain`, `url`, `user`, `host`, `process`, `file`, `alert`, and since 1.1 `service` and `command_template`. A file is named by its SHA-256. |
| `observed_at` | yes | When the source observed it, RFC 3339 with an offset. |
| `source` | yes | The connector or tool: `{name, version}`, `name` in lower case (`virustotal`, `defender.ah`). |
| `value` | yes | The typed payload of the kind. |
| `confidence` | no | The source's confidence in the observation, 0 to 1. |
| `ttl_seconds` | no | How long after `observed_at` the fact stays current. Absent means it does not expire. |
| `provenance` | no | `source_step_id` (the investigation trace step that produced it, a UUID), `input_hash` and `output_hash` (lowercase hex SHA-256 of the tool call and its result). |
| `redactions` | no | What was removed or cut before the fact was stored: `{path, reason}`, `path` a JSON Pointer into the fact, `reason` one of `secret`, `pii`, `truncated`. |
| `complete` | no (since 1.1) | `false` when the source cut the result or could not finish it; see [Complete and incomplete facts](#complete-and-incomplete-facts). |

There is no free-text field. A fact carries typed values only, so the
investigation's planner never reads a tool's raw text; summaries are rendered
from the typed values.

A typed field can still hold a string an attacker chose: a service name, a
command line, a workstation name. So every such string has a maximum length
(4096 characters for a command line or a command template, 1024 or less for
everything else), every list holds at most 50 items, and a consumer treats a
fact field as data to compare or display, never as an instruction.

The tenant a fact belongs to is held internally and is never exported: the
schema does not allow a `tenant_id` field.

## Kinds

| `kind` | Usual subject | `value` |
|---|---|---|
| `reputation` | `ip`, `domain`, `url`, `file` | `verdict` (`malicious`, `suspicious`, `benign`, `unknown`), `score` (0–100, higher is worse), `categories` |
| `process_lineage` | `process` | `chain`: the ancestry, oldest first and the subject process last; each node has `name` and optionally `pid`, `command_line`, `sha256`, `user`, `started_at`. Since 1.1 a node may also carry `command_template` (the command line with its variable parts replaced), `image_name` (the executable's file name) and `process_guid`, and the value may carry `children`: up to 50 processes the subject process started, as nodes. `children` absent means the source did not look; an empty list means it found none |
| `sign_in_history` | `user` | `window_start`, `window_end`, `total`, `failed`, and up to 50 `sign_ins` (newest first): `at`, `result` (`success`, `failure`, `interrupted`), `ip`, `country` (ISO 3166-1 alpha-2), `app`, `risk` (`none`, `low`, `medium`, `high`) |
| `related_alert` | `host`, `user`, `ip`… | Another alert on the same subject: `alert_id`, `title`, `severity`, `created_at`, `disposition` |
| `host_activity` (1.1) | `host` | What the host's detections show around an alert: `window_start`, `window_end`, `total` (events in the window), `max_level` (the highest rule level, 0–16), `by_group` (up to 50 `{group, count}`), `techniques` (up to 50 MITRE ATT&CK ids), and up to 50 `events` (highest level first): `at`, `rule_id`, `level`, `groups`, `event_id`, `user`, `image_name`, `command_template` |
| `logon_fanout` (1.1) | `ip`, `host`, `user` | Logons around one pivot: `pivot` (`source_ip`, `source_host`, `target_user`, `target_host`: what the subject is), `family` (`windows`, `sshd`), `window_start`, `window_end`, the counts `failures`, `successes`, `lockouts`, `unknown_user_failures`, `distinct_target_users`, `distinct_sources`, `distinct_target_hosts`, `first_success_after_failure_s`, and up to 50 each of `success_users`, `failed_users`, `sources` (addresses), `source_hosts` and `logon_types`. `source_hosts` are names the client supplied: a lead, never proof |
| `prevalence` (1.1) | `file`, `process`, `service`, `command_template` | How widely the subject is seen: `scope` (`tenant_fleet`: the tenant's hosts in its telemetry; `tenant_alerts`: the tenant's alerts), `window_start` and `window_end` (the window the source actually covered), `first_seen_at`, `last_seen_at`, `host_count`, `event_count`, `fleet_size` |

Facts are closed objects: a field the schema does not list is refused.

## Complete and incomplete facts

A source cannot always finish: a query times out, a result hits its row cap,
part of the store does not answer, or the time window the fact covers has not
closed yet. Such a fact is still useful for what it shows, but not for what
it does not show.

`complete` says which it is:

| `complete` | Meaning |
|---|---|
| `true` | The source saw the whole result for the window. |
| `false` | The source cut the result or could not finish it. |
| absent | The source did not say (every 1.0 fact). |

**A claim of absence cannot rest on an incomplete fact.** "No other account
was tried from this address" needs a `logon_fanout` fact with
`complete: true`; with `false`, or with no `complete` at all, the answer is
unknown, not "none". What an incomplete fact does show still counts: four
accounts tried from one address is four accounts tried, whether or not the
window had closed. In Python, `fact_is_complete(fact)` is true only for an
explicit `true`.

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

### Versions

| Version | Change |
|---|---|
| 1.1.0 | New kinds `host_activity`, `logon_fanout` and `prevalence`. `complete` on every fact. `children` on a process lineage, and `command_template`, `image_name` and `process_guid` on its nodes. Subject types `service` and `command_template`. Every 1.0.0 fact is still valid. |
| 1.0.0 | First version: `reputation`, `process_lineage`, `sign_in_history`, `related_alert`. |

## For contributors

The Pydantic model is the source; the JSON file is generated from it.

```bash
python scripts/export_schemas.py             # regenerate schemas/*/v*.json from the models
python scripts/export_schemas.py --check     # exit 1 if a committed file is stale
python scripts/ci/schema_compat.py --base origin/main   # the CI breaking-change check
```

To change the schema: edit `lg_sotf/models/evidence_fact.py`, raise
`SCHEMA_VERSION` as the rules above require, regenerate, add an example for
any new kind and a row to the versions table. Leave the examples of earlier
versions as they are: they are the facts a later version must still accept.
Give every new string a maximum length and every new list at most 50 items.
The unit tests
(`tests/unit/models/test_evidence_fact.py`) fail if the file is stale or an
example is invalid; the `schemas` CI job fails if the version bump is too
small for the change.
