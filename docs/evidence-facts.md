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

Status: published. The [Wazuh evidence tools](#the-wazuh-evidence-tools)
produce facts of the four kinds they cover; the investigation agents start
calling them, and citing facts, in a later release.

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

## The Wazuh evidence tools

Four registered tools read what surrounds an alert on the tenant's own Wazuh
indexer and answer with facts (`lg_sotf.tools.wazuh`). They are query
templates: a caller gives typed, bounded values and never a query, a field
or an index. They are not called by the analysis yet.

| Tool | Parameters | Fact |
|---|---|---|
| `wazuh.host_activity` | `host`, `at`, `before_min` and `after_min` (0 to 60 each) | `host_activity`: the host's alerts in the window, counted by rule group and technique, and the 50 with the highest rule level |
| `wazuh.logon_fanout` | `pivot` (`source_ip`, `source_host`, `target_user`, `target_host`), `value`, `at`, `before_min` (1 to 1440), `after_min` (0 to 60), `logon_types`, `outcomes` (`failure`, `success`, `lockout`), `family` (`windows`, `sshd`) | `logon_fanout`: failures, successes, lockouts, distinct users, sources and hosts, who failed and who got in, and the seconds from the first failure to the first success after it |
| `wazuh.process_lineage` | `host`, `image` or `process_guid`, `at`, `after_min` (0 to 30), `depth` (parents, 0 to 8), `child_depth` (1 to 4, default 2) | `process_lineage`: the process's parents, and what it started, down to what its children started |
| `wazuh.prevalence` | `kind` (`sha256`, `process_image`, `service_image_path`, `service_name`), `value`, `days` (1 to 30) | `prevalence`: on how many of the tenant's agents the value was seen, how often, first and last |

A call returns the facts it observed and a typed outcome: `success`, `empty`
(the search ran and matched nothing: there is no fact) or `failed`, with a
fixed reason code. An indexer that is down, refuses the credentials, answers
half a search that matched nothing, or holds no index for the source's
pattern is `failed`, never `empty`. An empty or failed call is never
evidence that something is benign.

A fact is `complete` only when all of this holds; otherwise it is `false`,
and so is the call's result:

- the indexer finished every search (no timeout, no failed shard, not
  stopped at the per-shard document limit);
- nothing the fact lists was cut: at most 50 alerts, 50 rule groups, 50
  techniques, 50 users or sources, 50 started processes, and distinct counts
  up to 1000;
- the window had closed when it was read: its end is older than the source's
  ingest lag (`max_event_lag_s` of the Wazuh source, 15 minutes by default).
  An investigation that runs the moment an alert is raised therefore gets
  incomplete facts for a window that reaches past the alert;
- the index still held alerts as old as the window's start. A prevalence
  fact's `window_start` is where the index's coverage actually starts.

What the tools read and how:

- **The tenant's own source.** The indexer, the index pattern and the
  credentials are those of the Wazuh source the alert came from; the tools
  need the permission the pull source needs (`indices:data/read/search` on
  the alert indices) and send only `POST /<index>/_search`. Switch them off
  for a tenant with `PATCH /tenant/settings`:
  `{"tools": {"wazuh_indexer": {"enabled": false}}}`.
- **Whole values.** A value is compared whole and case-sensitively (the 4.x
  index template maps these fields as `keyword`): `C:\Windows\PSEXESVC.exe`
  does not match `c:\windows\psexesvc.exe`. Windows paths are sent in both
  spellings Wazuh may hold (plain, and with doubled backslashes as 4.x
  writes event data).
- **Command lines.** Secrets are masked before a command line enters a fact,
  and `redactions` says where. `command_template` is the line in lower case
  with single spaces and bare numbers as `<n>`.

Limits measured on a Wazuh 4.14 indexer:

- **Process events are not there by default.** `wazuh-alerts-*` holds only
  events that matched a rule at or above the manager's alert level. Plain
  Sysmon process creations (event 1) are below it, so a process lineage is
  whole only when the manager raises them (a local rule on event 1, as the
  corpus and the lab do with rule `100100`). Without it the tool sees only
  the processes some rule alerted on. The fact is marked incomplete when the
  subject's own creation event is not in the index, but it cannot tell that
  some children were never indexed.
- **A file hash is searched in file-integrity events only**
  (`syscheck.sha256_after`). Sysmon's `hashes` field holds several
  algorithms in one `keyword` value, which cannot be searched for one hash
  without a wildcard, and the templates never send one.
- **Lockouts name a host, not an address.** Use the `source_host` pivot to
  count the lockouts a workstation caused; under `source_ip` they are 0.
- **sshd** logons are read by rule group (`authentication_failed`,
  `authentication_success`); users are the `dstuser` of the event, so failed
  logons for user names that do not exist are counted
  (`unknown_user_failures`) but not listed.
- **A busy host** with more than 50 alerts in the window always gives an
  incomplete `host_activity` fact: its counts are exact, its event list is
  the 50 highest.
- **Shared clusters.** A tenant is separated by its source's index pattern
  and indexer user. No setting scopes a tenant by agent group or label yet
  (INT3.2).

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
