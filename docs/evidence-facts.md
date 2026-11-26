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
or an index. The [investigation executor](#the-investigation-executor) calls
them for a tenant that switched them on.

| Tool | Parameters | Fact |
|---|---|---|
| `wazuh.host_activity` | `host`, `at`, `before_min` and `after_min` (0 to 60 each), optional `exclude_rule_id` | `host_activity`: the host's alerts in the window, counted by rule group and technique, and the 50 with the highest rule level. With `exclude_rule_id`, the host's events of that rule at exactly `at` (the investigated alert's own event and its exact duplicates) are left out of every number and of the list |
| `wazuh.logon_fanout` | `pivot` (`source_ip`, `source_host`, `target_user`, `target_host`), `value`, `at`, `before_min` (1 to 1440), `after_min` (0 to 60), `family` (`windows`, `sshd`) | `logon_fanout`: failures, successes, lockouts, distinct users, sources and hosts, who failed and who got in, and the seconds from the first failure to the first success after it. Always every outcome and every logon type of the pivot: a caller cannot narrow it |
| `wazuh.process_lineage` | `host`, `process_guid` or `image`, `at`, `after_min` (0 to 30), `depth` (parents, 0 to 8), `child_depth` (1 to 4, default 2) | `process_lineage`: the process's parents, and what it started, down to what its children started. One fact per process that matches (at most 3) |
| `wazuh.prevalence` | `kind` (`sha256`, `process_image`, `service_image_path`, `service_name`), `value`, `days` (1 to 30), optional `at` | `prevalence`: on how many of the tenant's agents the value was seen, how often, first and last. The window ends at `at` (the alert's time: what was seen up to the alert); without it, where the index is settled |

A call returns the facts it observed and a typed outcome: `success`, `empty`
(the search ran and matched nothing: there is no fact) or `failed`, with a
fixed reason code. An indexer that is down, refuses the credentials, answers
half a search that matched nothing, or holds no index for the source's
pattern is `failed`, never `empty`. So is any answer but an HTTP 200, and a
response that lacks an aggregation the search asked for. An empty or failed
call is never evidence that something is benign.

A fact is `complete` only when all of this holds; otherwise it is `false`,
and so is the call's result:

- the indexer finished every search: no timeout, not stopped at the
  per-shard document limit, and every shard answered (a shard that is not
  allocated is neither failed nor successful, and counts as not answered);
- nothing the fact lists was cut: at most 50 alerts, 50 rule groups, 50
  techniques, 50 users or sources, 50 started processes, and distinct counts
  up to 1000;
- the window had closed when it was read: its end is older than the source's
  ingest lag (`max_event_lag_s` of the Wazuh source, 15 minutes by default).
  An investigation that runs the moment an alert is raised therefore gets
  incomplete facts for a window that reaches past the alert;
- the index still held alerts as old as the window's start. A prevalence
  fact's `window_start` is where the index's coverage actually starts;
- for a process lineage: the process's own creation event was found, exactly
  one process matched, and the walk up the parents was not cut. A walk that
  used all `depth` look-ups while the oldest process found still names a
  parent is cut: the fact carries a `truncated` redaction on `/value/chain`.

**Name a process by its GUID whenever the alert carries one.** An image names
every process of that image that started around the alert, and an attacker
can start a decoy seconds before. Each match gets its own fact, and when
there is more than one, none of them is complete: the tool cannot tell which
is the alert's.

What the tools read and how:

- **The tenant's own source.** The indexer, the index pattern and the
  credentials are those of the Wazuh source the alert came from; the tools
  need the permission the pull source needs (`indices:data/read/search` on
  the alert indices) and send only `POST /<index>/_search`. Only the scheme,
  the host and the port of the source's `base_url` are used: for the tools,
  a `base_url` with a path, a query or a fragment is refused
  (`source_misconfigured`), because it would choose the endpoint. Switch the
  tools off for a tenant with `PATCH /tenant/settings`:
  `{"tools": {"wazuh_indexer": {"enabled": false}}}`.
- **Windows logons** are the events of the
  `Microsoft-Windows-Security-Auditing` provider: an event with a logon's id
  from another provider is not counted.
- **Names without case.** In a Windows logon, a user name and a host name
  (the `target_user`, `source_host` and `target_host` pivots, and the agent
  name for sshd) are matched whatever their case: Windows compares them
  that way and logs them as the client typed them. The spellings of one name
  are counted together, and the fact gives the name in lower case.
- **An address in the detector's spelling.** A `source_ip` is asked for as
  the event wrote it and, when that differs, in its canonical form too
  (`2001:0DB8:0000:0000:0000:0000:0000:0001` and `2001:db8::1`). No other
  spelling is tried.
- **Everything else is exact.** Addresses, process GUIDs, hashes, paths,
  service names, sshd user names, and the `host` of host activity and
  process lineage (the agent's name as the alert carries it) are compared
  whole and case-sensitively
  (the 4.x index template maps these fields as `keyword`):
  `C:\Windows\PSEXESVC.exe` does not match `c:\windows\psexesvc.exe`.
  Windows paths are sent in both spellings Wazuh may hold (plain, and with
  doubled backslashes as 4.x writes event data).
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
- **A fan-out counts every logon of its pivot**, successes and failures of
  every logon type together. To know which of an account's sources failed,
  ask about each source in turn (the `source_ip` pivot lists `failed_users`).
- **sshd** logons are read by rule group (`authentication_failed`,
  `authentication_success`); users are the `dstuser` of the event, so failed
  logons for user names that do not exist are counted
  (`unknown_user_failures`) but not listed.
- **A busy host** with more than 50 alerts in the window always gives an
  incomplete `host_activity` fact: its counts are exact, its event list is
  the 50 highest. Whoever can raise louder alerts on the host can push a
  quieter one out of that list (the counts, techniques and highest level
  still include it); choosing the list better is #452.
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

## The fact ledger

Every investigation run has a ledger: the list of what its tool calls
returned, in order. It is the only place a fact gets the `id` a verdict
cites. The [investigation executor](#the-investigation-executor) writes to
it.

- **One ledger per investigation run, not per alert.** A run gets an id
  (`inv_` and 32 hex digits) when the workflow starts on an alert, and keeps
  it in its state. A run that waits for an analyst and goes on, or a step
  that is retried after a crash, is the same run with the same ledger. An
  alert that is processed again is a new run with an empty ledger: it does
  not inherit the facts of the earlier investigation. A run started by an
  older release has no id and no ledger.
- **Code mints the id.** When a tool call returns, the ledger names each
  typed fact in the answer `<evidence id>:<n>` (`host:0`, `host:1`), numbered
  within the run. The id a tool wrote is overwritten, and a model never
  supplies one. A verdict that cites an id the run's ledger does not hold
  (made up, or another run's, or another tenant's) is told apart by a pure
  check.
- **Recording the same call twice adds nothing.** The same call (same
  evidence id, same tool, same input and output hash) recorded again gets
  the entries the run already has. A retried step therefore never doubles
  the ledger.
- **Every entry is bound to its call:** the tool and its version, the
  SHA-256 of the call's input and output (the same hashes as the call's step
  in the investigation trace), the outcome (`success`, `empty`, `failed`),
  `complete`, and when it was recorded. `content_hash` is a SHA-256 over
  every field of the entry: the id, the call, the reason, the time and the
  whole fact. An entry whose id, fact or anything else was changed no longer
  matches it. A fact is put in the form the database stores (a NUL character
  replaced, whole numbers as integers) before it is hashed, so a row read
  back matches its hash exactly when nothing changed.
- **One meaning of complete.** An entry is `complete` only when the tool's
  result was complete and the fact itself says `complete: true`. A fact
  from a result that was cut is stored with `complete: false`.
- **An empty or failed call is recorded too,** as an entry without a fact.
  It can be cited to say what could not be checked. It is never evidence
  that something is benign: `citable_as_benign_evidence` is true only for a
  `success` entry that holds a typed fact a tool observed. That is computed
  from the entry, not stored and not set by a model. A fact that a reader
  model extracted from free text (`source.name` starting with `reader.`) is
  a lead and never benign evidence either.
- **A full ledger is recorded, not an error.** A run's ledger holds at most
  200 entries, and a fact at most 1 MiB. A call that does not fit is one
  `failed` entry with the reason `ledger_capacity` or `fact_too_large`, so
  the investigation sees it as evidence it does not have.
- **Only typed facts enter.** A tool's raw answer (text, provider rows) is
  not a fact and is not kept. What a prompt may show of the ledger is ids,
  outcomes and the typed fields, in the untrusted data block, up to a fixed
  size.

The citation check reports findings; it raises nothing. For any claim:
`unknown_fact` (the run's ledger did not mint the id) and `altered_fact`
(the entry no longer matches its hash). For a benign claim also:
`not_benign_evidence` (it cites an empty or failed call, or a reader's
fact), `incomplete_fact` (the cited fact is not complete, so nothing can be
concluded from what it does not show) and `no_citation` (it cites nothing).

Storage:

- **Append-only, per tenant.** The entries are rows of the tenant's
  `evidence_facts` table under row-level security. Nothing updates or
  deletes them: the application has no such code, its database role has no
  such privilege, and a trigger refuses both. They are removed with their
  alert by retention and by tenant erasure, and are part of the tenant
  export (`evidence_facts.jsonl`).

- **A shadow run writes nothing.** Its entries stay with the shadow run in
  memory, shared by every step of that run.

`GET /api/v1/alerts/{id}/investigation` lists the entries of the alert's
newest run as observations, says when it lists fewer than the run holds,
and always names a call that failed or found nothing (see
[api.md](api.md)).

For engineers: the rules are `lg_sotf.domain.ledger` (pure), the store is
`lg_sotf.db.repos.evidence_facts`, and the investigation's interface is
`lg_sotf.agents.investigation.ledger.FactLedger` (`for_run`, `record`,
`facts`). Use `FactLedger.for_run(ctx)`, one per run; it raises for a run
without an investigation run id. Nothing else may build a ledger entry or
write the table (`tests/unit/architecture/test_fact_ledger.py`).

## The investigation executor

For a Wazuh alert of a tenant that switched the evidence tools on, code looks
up facts in the tenant's own Wazuh data before the deep analysis, and the
deep model is shown them and asked which ones its claims rest on. Every other
alert is analysed exactly as before.

**Turning it on.** A tenant admin sets `tools.wazuh_indexer.enabled: true`
(`PATCH /api/v1/tenant/settings`). It is off until then: an absent setting is
off. The alert must come from a Wazuh source; other sources have no evidence
tools yet.

Two limits to know before turning it on:

- **The alert must come from a Wazuh indexer source** (a source of type
  `wazuh`, which the platform polls). The lookups read that source's indexer
  with that source's credentials. A Wazuh alert that was pushed through a
  webhook has no indexer to read: its investigation makes one call, records
  `no_source` and the alert is analysed as before.
- **A Wazuh cluster shared between customers.** The lookups search the index
  pattern of the tenant's source with that source's indexer user, and
  `prevalence` and `logon_fanout` count across everything that user can read.
  When two tenants' sources read the same indices with the same user, one
  tenant's facts would include the other's events. Turn the lookups on only
  for a tenant whose index pattern or indexer user (a document-level security
  role) separates it from other customers; the per-tenant scope filter is
  INT3.2 (#239, threat TM-EVT-9).

**What runs.** The default playbook, `wazuh.default`
(`src/lg_sotf/agents/investigation/skills/wazuh.default.yaml`, a reviewed
file validated by a strict model; a file that uses a field this release does
not implement does not load, and the process does not start):

| Lookup | Tool | Runs when the alert carries |
|---|---|---|
| `host` | `wazuh.host_activity`: the host's alerts in the hour up to the alert | the agent's name (every Wazuh alert) |
| `prevalence` | `wazuh.prevalence`: on how many agents the object was seen over the 30 days up to the alert | a file hash (file integrity), a service's binary path, or a process image that is not a common binary (below) |
| `logons_user` | `wazuh.logon_fanout`: every logon of the account over the day before | an account name (Windows logon events, sshd) |
| `logons_source` | `wazuh.logon_fanout`: every logon from the address over the day before | a source address |

The values come from fields the detector wrote (`agent.name`, the decoded
event fields, `syscheck`), each parsed and checked; a value that is absent
or not well-formed skips its lookup. Nothing comes from the alert's title or
description, and nothing from a model: the plan is the file, in the file's
order. The lookups run at once, without waiting for their time windows to
close; a fact whose window had not closed says `complete: false`.

**An alert is never its own evidence.** The `host` lookup leaves out the
alert's own event: the host's events of the alert's rule at the alert's exact
time (its exact duplicates included). An alert alone on its host therefore
gets an empty host lookup, not "one event in the hour". The logon lookups
still count the alert's own logon: a fan-out is a count of logons, the
alert's among them.

**No prevalence for a program every host runs.** When the alert's object is
a process image under a system directory (`C:\Windows\System32`, `SysWOW64`,
`WinSxS`, a file directly in `C:\Windows`, `/bin`, `/sbin`, `/usr/bin`,
`/usr/sbin`, `/usr/libexec`) or one of a short reviewed list of interpreters
and living-off-the-land programs (`powershell.exe`, `cmd.exe`, `rundll32.exe`,
`mshta.exe`, `certutil.exe`, `python`, `bash`, `curl` and the like:
`lg_sotf.domain.skill_views`), the lookup is skipped with the reason
`common_binary` and there is no fact: "seen on 12 hosts" would read as
reassuring and say nothing. A file hash or a service's binary is used when
the alert carries one.

Each lookup goes through the tool registry and is recorded on the run's
[fact ledger](#the-fact-ledger) whatever its outcome. The playbook also
declares two malicious indicators over the host's activity (an alert of a
class only a person may close, an alert of rule level 12 or higher). They are
evaluated to `true`, `false` or `unknown` and reported, and a true one holds a
model-led close ([below](#what-the-evidence-holds)).

**Budgets.** One investigation may make 8 lookups, take 60 seconds (and never
more than a quarter of `worker.analysis_timeout_s`), spend 20,000 tokens on
its own model calls and $0.25. A tenant overrides these in
`investigation.budget` (`steps`, `wall_s`, `tokens`, `usd`) up to the
install's `investigation.tenant_max`; a higher value, however large, is cut to it. Today the
plan is fixed, so the executor makes no model call and spends no token, and
the Wazuh tools cost nothing: the money budget counts the price a tool
declares in the registry (`price_usd`). After two lookups in a row without an
answer the rest are skipped (`investigation.breaker_failures`): an indexer
that is down costs two calls, not a retry storm. A failed lookup's reason is
the tool's own fixed code (`unreachable`, `credentials_refused`,
`index_not_found`, `timeout`...). The seconds the lookups take come out of the
same step budget as the model's reasoning loop.

**What the model is given and asked.** When the lookups finished and
returned at least one fact, the deep model's prompt gains the ledger's view
(ids, outcomes, completeness, typed fields) in the untrusted `tool_data`
block, and its instructions gain one paragraph: return the claims the
verdict rests on, each with the ids of the observations that show it, never
an invented id, and an empty, failed or incomplete observation shows that
something is not known. The evidence shares the prompt's size limit for tool
data; when it is cut to fit, the cut values are marked, the prompt says so,
and the record says so (`evidence_truncated`). These are two separate prompt templates
(`analysis.verdict_cited`, `analysis.react_step_cited`); the templates used
without evidence are unchanged. Code then checks every cited id against the
ledger of the same run and stores the claims with the findings
(`unknown_fact`, `not_benign_evidence`, `incomplete_fact`, `no_citation`,
`altered_fact`). A benign verdict that was shown the evidence and gives no
claim at all is recorded as `no_claims`. The findings never change the
verdict; the hard ones hold a model-led close (next).

**Steering text in a fact.** A typed field of a fact can hold a string an
attacker chose: a user name typed at a logon, a command line, a service
name. Before any model sees the facts, the scan that reads the alert's own
text for steering instructions reads every string of every fact. A flagged
string is replaced, in what the model is shown, by the fixed marker
`[withheld: text that tries to steer the model]`; the observation is marked
`steering_text_withheld`, the record lists its id under `steering`, and the
analysis carries `prompt_injection_suspected` among its indicators, as it
does for the alert's own text. The ledger keeps what the tool returned.

### What the evidence holds

Evidence can hold a close and can never buy one. When an investigation ran
for the alert, the closing rule (`lg_sotf.domain.closure`) reads three things
from its record (`blocking`), and each alone sends the alert to a person:

| Decide code | Holds the close when | Does not hold it |
|---|---|---|
| `evidence_steering` | a fact carries steering text. This also stops a close on approved benign evidence | |
| `evidence_indicator` | a malicious indicator of the playbook is `true` over the facts. The decision names the indicator and the observations it read | an `unknown` indicator: the lookup failed, or did not show it and was not complete |
| `evidence_citation` | the verdict is benign and a claim has a hard finding: `unknown_fact`, `altered_fact`, `not_benign_evidence`; or the claims could not be checked | `incomplete_fact`, `no_citation`, `no_claims`: recorded and shown |

These apply only to a model-led close (and steering text to every automatic
close). With no investigation the decision policy is unchanged. An
investigation whose record does not say what it holds is read as holding the
close. The decision's reason names what held it
(`a malicious indicator is true over the evidence: high_level_alert_on_host
(host:0)`), the alert's view lists it among the reasons the AI may not close
the alert (`outcome.blockers`, `evidence_run.holds_close`), and the queue
shows a plain sentence for each code. The full claim checker and the skills
with benign proofs are AI-E3.4 (#207) and AI-E3.1 (#199).

**When it cannot finish.** The alert's run never fails, closes or escalates
because of the lookups. In each case below the deep model gets today's
prompt, and the reason is stored and shown as a step of the investigation:

| Reason | What happened |
|---|---|
| `circuit_open` | The indexer did not answer twice in a row (unreachable, credentials refused, timed out); the rest were skipped |
| `no_source` | There is no event data to read for this alert (it was pushed, not polled from a Wazuh indexer source; or the telemetry store does not hold it): one call, the rest skipped |
| `no_model` | No model analysed the alert (the LLM is off, or the tenant's token budget is spent): the facts are recorded for the analyst and not used |
| `budget_steps`, `budget_wall`, `budget_tokens`, `budget_usd` | A budget was spent; a lookup still running when the time ran out is cut and recorded as failed |
| `no_facts` | The lookups finished and none returned a fact |
| `no_run_id` | The run started before investigation runs had an id (an older release) |
| `error` | The executor itself failed |

What was looked up before the stop stays on the ledger and in the view.

**Resume and retry.** A lookup whose answer is already on the run's ledger (a
fact, or "nothing found") is not sent again. A step retried after a crash
sends only the lookups that have no answer yet. A lookup that failed is
asked again when the alert is analysed again in the same run (a retried step,
an analyst who asked for more), so an indexer that was down the first time
can answer the second; the same failure stays one ledger entry however often
it repeats.

**Shadow runs** make the lookups (they read the tenant's own data and tell
no third party) and keep the ledger in memory: nothing is written.

**Where the tools read.** `investigation.evidence_backend` names it, and it
is never guessed. `indexer` (the default): the tenant's own Wazuh indexer,
found from the alert's source. `event_store`: a dataset's telemetry in
memory (`investigation.event_store_files`), for evaluation and development.
It is synthetic, so it is an allow-list: the settings load only when
`environment` is set, explicitly, to `development` or `test`. An install that
does not say which environment it is, and any other environment, does not
start. It is announced on the worker's standard error when it starts. See
[evaluation.md](evaluation.md#the-investigation-harness-on-the-corpus).

`GET /api/v1/alerts/{id}/investigation` shows the lookups, the budgets, the
indicators, the cited claims and their findings under `evidence_run` and
`claims` ([api.md](api.md)).

For engineers: the executor is
`lg_sotf.agents.investigation.executor.SkillInvestigator`, called by the
analysis agent; the format is `lg_sotf.models.skill.SkillSpec`; the view,
bindings and indicators are `lg_sotf.domain.skill_views` and
`lg_sotf.domain.skills`; budgets are `lg_sotf.domain.investigation_budget`.

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
