# 0014. Investigate with versioned skills, and earn AI closure per skill and tenant

* Status: accepted with Amendment 1 (direction decided by the founder on 2026-11-08, option B plus skills and
  reference material; on 2026-11-14 the founder made the investigation harness the focus)
* Date: 2026-11-08
* Roadmap step: AI-E2, AI-E3, AI-E4 ([build order](../design/investigation-skills-stories.md))
* Supersedes nothing. Amends the safety invariant INV-03 when AI-E3.8a merges (section 6.2).
* **Amended on 2026-11-14 by [Amendment 1](#amendment-1-2026-11-14-harness-v1-on-decision-policy-v3) and [Amendment 2](#amendment-2-2026-11-14-what-the-public-evidence-changes): read both first. It changes the closing rule, drops the settle delay and reorders the build.**

Items marked **(uncertain)** are assumptions to confirm while building; each names the story that confirms it.

## Context and problem

**The product protects but saves nothing.** Scorecard v2 (DeepSeek V4 on `corpus_v1`, 520 synthetic
Wazuh 4.14 alerts, [RUN.md](../scorecards/v2/deepseek-v4/RUN.md)) closed 0 of 208 attacks and 0 of 312
benign alerts. The causes are in the decision layer, not the model:

* `lg_sotf.domain.routing.decide` closes a low or medium alert only when the **rules'** threat score
  (`lg_sotf.agents.analysis.base.rule_threat_score`) is below 30. On Wazuh that score starts at 50 plus
  severity, and since AI-E6.3/E6.4 only a few trusted signals lower it. The lowest benign score was 42,
  so no model answer could close anything.
* The grey zone (confidence 30 to 70) is tested on the triage-plus-correlation confidence *before* the
  verdict: 65 benign alerts with a `benign` deep verdict and a threat below 30 were escalated by it.
* AI-E1.9 (branch `feat/ai-e1-9-autoclose-calibration`, issue #316, not merged) adds verdict precedence
  and tenant-context corroboration. Its own simulation shows the limit: with no rule test at all, a
  model-only close would take 73 benign alerts **and 2 attacks** (`cv1-0021` password spray,
  `cv1-0358` T1083). A verdict alone is not safe.

**The look-alikes are identical at the alert level.** In `corpus_v1` the IT-admin PsExec alert
`cv1-0069` and the ransomware lateral movement `cv1-0113` are both rule 61138, event 7045,
`serviceName: PSEXESVC`, `accountName: LocalSystem`. A single 4625 from a password spray (`cv1-0021`) is
field-for-field a typo (`cv1-0003`): same rule 60122, same status `0xc000006d`/`0xc000006a`. What tells
them apart is *around* the alert: the spray's source fails for 4 users in one minute and then succeeds
for one; the PsExec run is followed by `cmd.exe /c whoami /all & ipconfig /all` and Defender being
switched off. About 91 of the 126 look-alikes need either that surrounding telemetry or the customer's
own context (admin workstations, service accounts, change windows).

**Today's investigation cannot look around.** `lg_sotf.agents.analysis.react.ReActReasoner` is a loop of
at most 5 `lookup | finish` steps whose only tool is a threat-intelligence reputation lookup of up to 8
indicators (`MAX_CANDIDATES`). There are no hypotheses, no plan, no SIEM query, no critic, and the
model's verdict and narrative are not tied to any observation. The research the founder report cites
(Aida/Alert-Bench on Wazuh data) cut misses from 40.4% to 3.1% *with the same model* by making every
dismissal cite evidence and adding a checker.

**What already exists and is reused.** The evidence-fact schema v1 (INT9.2,
`lg_sotf.models.evidence_fact`), the trace store (`lg_sotf.llm.trace`, `investigation_steps`, INV-05),
record and replay (`lg_sotf.llm.cassette`, modes `record`, `replay`, `replay-tools`), shadow mode
(`lg_sotf.core.shadow.ShadowRunner`, INV-09) and the agreement report
(`lg_sotf.domain.shadow_agreement`), the blind audit (`lg_sotf.services.blind_audit`,
`lg_sotf.domain.blind_audit`), the prompt registry (`lg_sotf.llm.registry.register_prompt`, INV-04), the
egress policy (`lg_sotf.net.egress`), the Wazuh indexer client (`lg_sotf.ingestion.sources.wazuh`) and
the eval harness with tool fixtures (`lg_sotf.eval.tool_fixtures`). The tool registry (AI-E2.1, #193),
the planner (AI-E3.3), the checker (AI-E3.4) and tenant memory (AI-E4) are planned but not built.

## Decision

In one paragraph: **an investigation skill is a reviewed YAML file per detection family that says when it
applies, which read-only queries to run, which benign hypotheses may close the alert and exactly which
typed facts prove each one. A deterministic router picks the skill; code runs the skill's queries
through the tool registry and turns the results into evidence facts; the model only chooses among the
skill's optional queries, picks a hypothesis and writes cited claims; a deterministic checker verifies
every claim against the facts returned in this run and evaluates the proof itself. A low or medium alert
closes only when that check passes and the skill has earned an autonomy tier that allows closing for
this tenant (300 blind-labelled closures, no miss). Anything else goes to a person exactly as today.**

The model never decides control flow, never names a query target, never supplies a query value and can
never satisfy a close criterion with words: closing rests on typed facts that code evaluated.

### 1. The skill format

#### 1.1 YAML, one file per skill, validated by a strict model

Skills live in the repository at `src/lg_sotf/agents/investigation/skills/<skill-id>.yaml`, are reviewed
like code (CODEOWNERS: the detection team, two approvals), and ship in the image. A strict Pydantic
model, `lg_sotf.models.skill.SkillSpec` (`extra="forbid"`, frozen), is the source of truth; it is
exported to the public JSON Schema `schemas/investigation-skill/v1.json` by `scripts/export_schemas.py`,
as the evidence-fact schema is.

**Why YAML and not Markdown with front matter.** The parts that decide a close (applicability, proofs,
never-close conditions, query bindings) must be machine-checked data: the loader resolves every fact
field against the evidence-fact schema, the contract hash and the diff classifier (section 1.5) read
them, and the replay recomputes them without a model. In Markdown those parts would still have to be a
YAML block in the front matter, and the body would become prose the planner reads but nothing checks;
reviewers would have two places to look and the prose would drift from the criteria. YAML also matches
what the repository already reviews as data (`tests/fixtures/eval/*_thresholds.yaml`) and needs no new
dependency (`pyyaml` is pinned). The few prose fields (`summary`, `says`) are short, are part of the
prompt hash, and carry no authority: no prose can make a proof true.

**Load-time rules** (the catalogue refuses the file; an invalid skill fails CI and fails process start,
like the encryption keys of ADR-0006):

* every `tool` names a registered tool and version (AI-E2.1) whose output kinds include what the
  predicates read; every predicate's `field` exists on that fact kind in the evidence-fact schema and
  the operator fits its type;
* every argument is a binding (section 1.3), never a literal string chosen at run time;
* every skill runs `wazuh.host_activity` (or its successor) on the alert's primary host as an `always`
  query, so the global never-close neighbourhood check (section 6.1) always has a fact to read;
* every benign proof contains at least one predicate on a fact from a telemetry tool (`wazuh.*`) and its
  `complete: true`; context, guidance and memory facts can add to a proof, never stand alone;
* a benign proof may not reference a malicious hypothesis, and `close.severities` may not contain
  `high` or `critical`;
* across the catalogue no two skills match the same alert at the same specificity
  (`tests/unit/agents/investigation/test_catalog.py::test_no_two_skills_overlap_at_equal_specificity`).

#### 1.2 Fields

| Field | Meaning |
|---|---|
| `schema` | `lg-sotf/investigation-skill/v1` |
| `id`, `title`, `version`, `status` | Stable dotted id; SemVer (section 1.5); `draft`, `active` or `retired` |
| `owner` | The owning team (CODEOWNERS), never a person |
| `summary` | Trusted prose for the planner: what the detection means and what decides it |
| `changelog[]` | `version`, `date`, `change`, `class` (neutral, narrowing, widening, structural), `replay` (the decision diff of the change, section 7) |
| `applies_to` | `source_types`, `log_families`, and `match`: `rule_ids`, `event_ids`, `rule_groups`, `attack_techniques`; optional `exclude` |
| `view` | The registered typed extractor that reads the alert's detector fields (section 2.1) |
| `settle_min` | How long after `occurred_at` the evidence windows close; the run waits for it (section 2.3) |
| `budget` | `optional_queries`, `llm_calls`, `tokens`, `usd` per investigation |
| `evidence[]` | Query references into the tool registry: `id`, `tool` (`name:version`), `when` (`always` or `optional`), `required`, `args` (bindings) |
| `lists` | Named constant lists the predicates may use (routine commands, recon commands); vendor-reviewed |
| `hypotheses.benign[]` | `id`, `says` (one sentence), `proof` (a predicate over facts and view fields) |
| `hypotheses.malicious[]` | `id`, `technique`, `indicator` (a predicate); if it is true or unknown, the alert cannot close |
| `close` | `severities` (subset of info, low, medium) and the benign `hypotheses` allowed to close |
| `never_close[]` | `id`, `when` (a predicate); skill-specific, on top of the global classes in code |

#### 1.3 Bindings and predicates: a closed language, three-valued, fail-closed

**Bindings** are the only way an argument gets a value: `view.<field>` (typed alert view),
`alert.occurred_at`, `alert.id`, `alert.pattern_key` (section 8.3), `fact.<evidence id>.<field>`, and
`{only: fact.<id>.<list field>}` (bound only when the list has exactly one element, otherwise the
query is skipped). Values are validated by the tool's parameter model before any query is built. The
planner never supplies a value; it can only choose an `optional` evidence id.

**Predicates** (`lg_sotf.domain.skills.evaluate`):

```
pred := {all: [pred, ...]} | {any: [pred, ...]} | {not: pred}
      | {fact: <evidence id>, field: <path>, <op>: <rhs>}      # path may project lists: children[].command_template
      | {view: <field>, <op>: <rhs>}
op   := eq | ne | lt | le | gt | ge | in | contains | contains_any | all_in | age_days_ge | age_days_le
rhs  := literal | {view: <field>} | {list: <name>}
```

Evaluation is Kleene three-valued: a predicate on a fact whose query was skipped, failed, or returned
`complete: false` is **unknown**. In a benign proof unknown counts as false; in a malicious indicator
or a never-close condition unknown counts as true. "No result" therefore never proves anything benign
and never hides anything malicious ("an empty lookup means unknown, never benign").

#### 1.4 Example skill 1: Windows logon failures and password spraying

Built from `corpus_v1` rules 60122 (4625), 60204 (4625 frequency) and 60115 (4740): 24 benign items
(16 `noise:logon-typo`, 8 `lookalike:stale-credentials`) and 10 malicious (`campaign:password-spray`).

```yaml
schema: lg-sotf/investigation-skill/v1
id: windows.logon_failure
title: Windows logon failures and password spraying
version: 1.0.0
status: active
owner: detection-engineering
summary: >
  A Windows account failed to authenticate (4625 NTLM or Negotiate, 4771 Kerberos pre-authentication,
  4776 credential validation) or was locked out (4740). Most single failures are a typo or a device
  retrying an old password. The same event is also the first step of password spraying (one source,
  many accounts) and guessing (one account, many sources or invented user names). Decide from the
  fan-out and from what happened next, never from the single event.
changelog:
  - version: 1.0.0
    date: 2026-11-08
    class: structural
    change: First version, from corpus_v1 scenarios logon-typo, stale-credentials and password-spray.
    replay: {dataset: corpus_v1, malicious_would_close: 0, benign_would_close: null}   # filled by AI-E3.8b
applies_to:
  source_types: [wazuh]
  log_families: [windows]
  match:
    rule_ids: ["60122", "60204", "60115"]
    event_ids: ["4625", "4771", "4776", "4740"]     # 4771/4776 rule ids are not in corpus_v1 (uncertain, AI-E3.1a)
    rule_groups: [authentication_failed, authentication_failures]
    attack_techniques: [T1110.001, T1110.003]
view: windows_logon      # target_user, target_domain, source_ip, source_is_public, workstation,
                         # logon_type, status, sub_status, event_id, dc_host
settle_min: 10
budget: {optional_queries: 3, llm_calls: 3, tokens: 40000, usd: 0.10}

evidence:
  - id: by_source              # who else did this source try, and did it get in?
    tool: wazuh.logon_fanout:1
    when: always
    required: true
    args: {pivot: source_ip, value: view.source_ip, at: alert.occurred_at, before_min: 30, after_min: 10}
  - id: by_source_day          # low-and-slow spraying below the 30-minute window
    tool: wazuh.logon_fanout:1
    when: always
    required: true
    args: {pivot: source_ip, value: view.source_ip, at: alert.occurred_at, before_min: 1440, after_min: 10}
  - id: by_user                # where else does this account fail from?
    tool: wazuh.logon_fanout:1
    when: always
    required: true
    args: {pivot: target_user, value: view.target_user, at: alert.occurred_at, before_min: 1440, after_min: 10}
  - id: dc_activity            # the neighbourhood check every skill runs (section 6.1)
    tool: wazuh.host_activity:1
    when: always
    required: true
    args: {host: view.dc_host, at: alert.occurred_at, before_min: 30, after_min: 10}
  - id: source_ctx
    tool: context.entity:1
    when: always
    args: {type: ip, value: view.source_ip}
  - id: user_ctx
    tool: context.entity:1
    when: always
    args: {type: user, value: view.target_user}
  - id: history
    tool: platform.pattern_history:1
    when: always
    args: {key: alert.pattern_key, days: 30}
  - id: guidance
    tool: context.guidance_match:1
    when: always
    args: {alert: alert.id, skill: windows.logon_failure}
  - id: source_host_activity   # workstation names are client-supplied: used to look, never to prove
    tool: wazuh.host_activity:1
    when: optional
    args: {host: view.workstation, at: alert.occurred_at, before_min: 30, after_min: 10}
  - id: similar
    tool: memory.similar_cases:1
    when: optional
    args: {alert: alert.id, limit: 5}

hypotheses:
  benign:
    - id: typo_then_success
      says: One person mistyped the password, then logged on from the same place within ten minutes.
      proof:
        all:
          - {view: sub_status, eq: "0xc000006a"}                     # wrong password for an existing account
          - {fact: by_source, field: complete, eq: true}
          - {fact: by_source, field: value.distinct_target_users, eq: 1}
          - {fact: by_source, field: value.failures, le: 3}
          - {fact: by_source, field: value.first_success_after_failure_s, le: 600}
          - {fact: by_source, field: value.success_users, all_in: {view: target_user}}
          - {fact: by_source_day, field: value.distinct_target_users, eq: 1}
    - id: stale_credentials
      says: A device the user owns keeps retrying an old password, and no other account is tried from it.
      proof:
        all:
          - {fact: by_source, field: complete, eq: true}
          - {fact: by_source_day, field: complete, eq: true}
          - {fact: by_source_day, field: value.distinct_target_users, eq: 1}
          - {fact: by_source_day, field: value.successes, eq: 0}
          - {fact: by_user, field: value.distinct_sources, le: 2}
          - {fact: history, field: value.analyst_malicious, eq: 0}
          - any:
              - {fact: source_ctx, field: value.owner, eq: {view: target_user}}
              - {fact: source_ctx, field: value.declared, contains: user_device_network}
              - {fact: history, field: value.analyst_benign, ge: 1}
              - {fact: guidance, field: value.matched, eq: true}
  malicious:
    - id: password_spray
      technique: T1110.003
      indicator:
        any:
          - {fact: by_source, field: value.distinct_target_users, ge: 3}
          - {fact: by_source_day, field: value.distinct_target_users, ge: 5}
    - id: guessing
      technique: T1110.001
      indicator:
        any:
          - {fact: by_user, field: value.distinct_sources, ge: 3}
          - {fact: by_source, field: value.unknown_user_failures, ge: 3}
    - id: valid_account_after_failures
      technique: T1078.002
      indicator:
        all:
          - {fact: by_source, field: value.distinct_target_users, ge: 2}
          - {fact: by_source, field: value.successes, ge: 1}
    - id: lockouts_from_one_source
      technique: T1110
      indicator: {fact: by_source_day, field: value.lockouts, ge: 2}

close:
  severities: [info, low, medium]
  hypotheses: [typo_then_success, stale_credentials]

never_close:
  - id: privileged_account
    when: {fact: user_ctx, field: value.declared, contains: admin_account}
  - id: public_source
    when: {view: source_is_public, eq: true}
  - id: service_account_interactive_failure
    when:
      all:
        - {fact: user_ctx, field: value.declared, contains: service_account}
        - {view: logon_type, in: ["2", "10", "11"]}
```

`workstationName` in a 4625 or 4624 is supplied by the client in NTLM, so an attacker can claim to be
`IT-WS-01`. The skill therefore identifies the source by its address (`view.source_ip`), and the context
pack maps addresses to declared devices; the workstation name is used only to choose an optional query,
never in a proof. `all_in` with a single view value on the right reads it as a one-element list.

How this resolves the corpus: the spray alerts see `distinct_target_users` of 4 from `10.20.1.83` and a
success for `sbrown` (indicators true: cannot close); a typo alert sees one user, at most three failures
and a success of the same user within ten minutes; a phone retrying sees one user from the declared
Wi-Fi/BYOD range `10.20.40.0/24` with no success. The spray's first event is the dangerous one: at
ingestion the other three failures may not exist yet. `settle_min` (section 2.3) makes the run wait
until the window has closed.

#### 1.5 Example skill 2: a new Windows service, and PsExec

Built from rules 61138 (7045) and 92068 (Sysmon 1, PsExec child): 11 benign items (7 `lookalike:it-admin`,
4 `lookalike:windows-patching`) and 7 malicious (`campaign:lateral-ransomware`, `atomic-sweep`
T1543.003). 4697 is not in `corpus_v1`; it is matched by event id until its rule id is confirmed
**(uncertain, AI-E3.1a)**.

```yaml
schema: lg-sotf/investigation-skill/v1
id: windows.service_install
title: New Windows service or PsExec execution
version: 1.0.0
status: active
owner: detection-engineering
summary: >
  A service was installed (7045 System, 4697 Security) or PsExec ran a command (PSEXESVC as parent).
  IT staff use PsExec and installers register services every day; attackers use the same mechanism to
  move laterally (T1021.002, T1569.002) and to persist (T1543.003). The alert alone cannot tell them
  apart. Decide from who logged on to the host just before, what the service ran afterwards, how common
  the binary is in the fleet, and what else happened on the host.
changelog:
  - version: 1.0.0
    date: 2026-11-08
    class: structural
    change: First version, from corpus_v1 scenarios it-admin, windows-patching, lateral-ransomware and atomic-sweep.
    replay: {dataset: corpus_v1, malicious_would_close: 0, benign_would_close: null}
applies_to:
  source_types: [wazuh]
  log_families: [windows, sysmon]
  match:
    rule_ids: ["61138", "92068"]
    event_ids: ["7045", "4697"]
    attack_techniques: [T1543.003, T1569.002, T1021.002]
view: windows_service    # host, service_name, image_path, image_path_class (system, program_files,
                         # user_writable, unc, other), image_runs_interpreter, account, start_type,
                         # psexec, child_image, child_command_template, parent_image
settle_min: 15
budget: {optional_queries: 3, llm_calls: 3, tokens: 50000, usd: 0.12}

lists:
  routine_remote_admin_commands:      # command templates (section 8.3), lower case
    - "gpupdate /force"
    - "gpupdate /target:computer /force"
    - "shutdown /r /t <n>"
    - "klist purge"
    - "ipconfig /flushdns"

evidence:
  - id: inbound                # who logged on over the network just before the install?
    tool: wazuh.logon_fanout:1
    when: always
    required: true
    args: {pivot: target_host, value: view.host, at: alert.occurred_at, before_min: 15, after_min: 1,
           logon_types: ["3"], outcomes: [success]}
  - id: around                 # the neighbourhood check, and defence evasion or impact nearby
    tool: wazuh.host_activity:1
    when: always
    required: true
    args: {host: view.host, at: alert.occurred_at, before_min: 30, after_min: 15}
  - id: children               # what the new service (or PSEXESVC) ran
    tool: wazuh.process_lineage:1
    when: always
    required: true
    args: {host: view.host, image: view.image_path, at: alert.occurred_at, after_min: 15}
  - id: image_prevalence
    tool: wazuh.prevalence:1
    when: always
    required: true
    args: {kind: service_image_path, value: view.image_path, days: 30}
  - id: target_ctx
    tool: context.entity:1
    when: always
    args: {type: host, value: view.host}
  - id: source_ctx             # by address: the workstation name in a logon event is client-supplied
    tool: context.entity:1
    when: always
    args: {type: ip, value: {only: fact.inbound.value.sources}}
  - id: account_ctx
    tool: context.entity:1
    when: always
    args: {type: user, value: {only: fact.inbound.value.success_users}}
  - id: history
    tool: platform.pattern_history:1
    when: always
    args: {key: alert.pattern_key, days: 30}
  - id: guidance
    tool: context.guidance_match:1
    when: always
    args: {alert: alert.id, skill: windows.service_install}
  - id: source_activity
    tool: wazuh.host_activity:1
    when: optional
    args: {host: {only: fact.source_ctx.value.hosts}, at: alert.occurred_at, before_min: 30, after_min: 5}
  - id: similar
    tool: memory.similar_cases:1
    when: optional
    args: {alert: alert.id, limit: 5}

hypotheses:
  benign:
    - id: sanctioned_remote_admin
      says: IT ran PsExec from a declared admin workstation with a declared admin account, and only routine commands followed.
      proof:
        all:
          - {view: psexec, eq: true}
          - {fact: inbound, field: complete, eq: true}
          - {fact: inbound, field: value.distinct_sources, eq: 1}
          - {fact: source_ctx, field: value.declared, contains: admin_workstation}
          - {fact: account_ctx, field: value.declared, contains: admin_account}
          - {fact: children, field: complete, eq: true}
          - {fact: children, field: "value.children[].command_template", all_in: {list: routine_remote_admin_commands}}
          - {fact: around, field: complete, eq: true}
          - any:
              - {fact: guidance, field: value.matched, eq: true}
              - {fact: history, field: value.analyst_benign, ge: 2}
          - {fact: history, field: value.analyst_malicious, eq: 0}
    - id: vendor_updater_service
      says: A binary installed under Program Files on many hosts for over a week registered its own service.
      proof:
        all:
          - {view: psexec, eq: false}
          - {view: image_path_class, eq: program_files}
          - {fact: image_prevalence, field: complete, eq: true}
          - {fact: image_prevalence, field: value.host_count, ge: 10}
          - {fact: image_prevalence, field: value.first_seen_at, age_days_ge: 7}
          - {fact: around, field: complete, eq: true}
          - {fact: history, field: value.analyst_malicious, eq: 0}
  malicious:
    - id: binary_in_user_writable_path
      technique: T1543.003
      indicator: {view: image_path_class, in: [user_writable, unc]}
    - id: new_binary
      technique: T1543.003
      indicator:
        any:
          - {fact: image_prevalence, field: value.host_count, le: 1}
          - {fact: image_prevalence, field: value.first_seen_at, age_days_le: 1}
    - id: lateral_from_unsanctioned_source
      technique: T1021.002
      indicator:
        all:
          - {view: psexec, eq: true}
          - {fact: inbound, field: value.distinct_sources, ge: 2}
    - id: discovery_through_the_service
      technique: T1569.002
      indicator: {fact: children, field: "value.children[].image_name", contains_any: [whoami.exe, nltest.exe, net.exe, net1.exe, quser.exe, systeminfo.exe, ipconfig.exe]}
    - id: hands_on_keyboard_nearby
      technique: T1562.001
      indicator: {fact: around, field: value.techniques, contains_any: [T1562.001, T1059.001, T1047, T1105]}

close:
  severities: [info, low, medium]
  hypotheses: [sanctioned_remote_admin, vendor_updater_service]

never_close:
  - id: crown_jewel_or_domain_controller
    when:
      any:
        - {fact: target_ctx, field: value.criticality, eq: crown_jewel}
        - {fact: target_ctx, field: value.role, eq: domain_controller}
  - id: service_runs_an_interpreter      # the view sets it for cmd, powershell, rundll32, mshta, regsvr32, wscript
    when: {view: image_runs_interpreter, eq: true}
```

How this resolves the corpus: `cv1-0113` (ransomware) has PsExec from `MKT-WS-11`, which is not a
declared admin workstation (no proof), children `cmd.exe /c whoami /all & ipconfig /all` (not routine:
no proof; `discovery_through_the_service` would fire on a child `whoami.exe`), and Defender disabled
two minutes later (`hands_on_keyboard_nearby`, and the global T1562 class). `cv1-0069` (desktop support)
closes only if the tenant declared the admin workstation and account and either a guidance note covers
desktop support's PsExec or analysts closed the same pattern twice. `cv1-0057` (Edge updater) closes on
fleet prevalence. `cv1-0071` (`C:\Users\Public\svc.exe`) is a user-writable binary.

`corpus_v1` does not yet contain the surrounding telemetry these queries read (the 4624 network logon
before a 7045, the success after a typo): AI-E1.10 adds it (section 8.1).

#### 1.6 Versions, contract hash and what a change does to autonomy

The **contract** of a skill is the canonical JSON of the fields that decide a close (`applies_to`,
`view`, `settle_min`, `evidence`, `lists`, `hypotheses` without `says`, `close`, `never_close`); its
SHA-256 is the `contract_hash`. The prose and the planner prompt are hashed separately as the prompt
hash (INV-04). `lg-sotf skill-diff OLD NEW` classifies a change; CI (`scripts/ci/skill_compat.py`,
modelled on `scripts/ci/schema_compat.py`) fails when the version bump is smaller than the class needs:

| Class | Examples | Bump | Autonomy for tenants on the old contract |
|---|---|---|---|
| neutral | prose, changelog, lower budgets, an `optional` query no proof reads | patch | carried |
| narrowing | a new never-close or malicious indicator, a stricter threshold, a new `required` query | minor | carried |
| widening | a new benign hypothesis, a looser threshold, a removed indicator or never-close, broader `applies_to` | minor, `class: widening` | capped at `auto_full_audit`; the new contract's counters start at 0 |
| structural | renamed evidence ids, a new view, a tool's major version | major | back to `shadow` |

Syntactic classification is conservative: anything the classifier cannot prove neutral or narrowing is
widening. A prompt or model change (new prompt hash or model profile) is gated by the corpus replay and,
if the replay's would-close set grew, is treated as widening **(uncertain: how strict to be for prose-only
edits; AI-E3.8b decides with data)**.

### 2. How a skill is selected and executed

```
 gate → triage → correlation ──(skill applies: always analysis)──► analysis ─► decide ─► close | escalate | plan_response
                                                                      │
          ┌───────────────────────────────────────────────────────────┴───────────────────────────────┐
          │ select_skill(alert view) ── none ──► today's ReActReasoner (unchanged; never closes alone) │
          │        │ match                                                                            │
          │        ▼                                                                                  │
          │ settle: wait until occurred_at + settle_min + source ingest lag                           │
          │        ▼                                                                                  │
          │ executor (code): run `always` queries ─► tool registry ─► typed facts ─► ledger (ids)     │
          │        ▼                                                                                  │
          │ planner (deep tier): sees skill + facts (as data) ─► optional query id | finish           │
          │        │   (≤ optional_queries, llm_calls, tokens, usd, wall clock)                       │
          │        ▼                                                                                  │
          │ final step: verdict + hypothesis id + claims[{text, ref, cites[fact ids]}]                │
          │        ▼                                                                                  │
          │ checker (code): citations, proof, indicators, never-close  ─► SkillDigest in state        │
          └───────────────────────────────────────────────────────────────────────────────────────────┘
```

#### 2.1 The router

`lg_sotf.domain.skills.select_skill(view, catalog, enabled) -> Optional[SkillMatch]` is a pure function.
It reads only **detector-written fields**, never the title, description or an entity an attacker names:
`source_type`, the Wazuh `rule.id`, `rule.groups`, `decoder.name`, `win.system.eventID` and
`rule.mitre.id`. Today the normalizer folds `rule.id` into `rule_name` and keeps the rest only in
`raw` (`lg_sotf.ingestion.normalizers.wazuh.WazuhNormalizer`), which can be size-capped; AI-E3.1a adds a
`detection` block to the canonical alert (`vendor_rule_id`, `rule_groups`, `event_id`, `decoder`,
`log_family`) that is never capped. Ranking: a rule-id match beats an event-id match beats a rule-group
match beats a technique match; the catalogue test forbids equal-specificity overlaps, and at run time a
tie fails closed (no skill, today's path). The view extractor (`lg_sotf.domain.skill_views`) then builds
the typed view; a field it cannot parse (an IP that is not an IP, a user name outside
`^[A-Za-z0-9._$@\\-]{1,128}$`) is `None`, and every binding on it skips its query.

The tenant flag `investigation.skills` (AI-E3.6, default off) and the tenant's per-skill enablement
decide whether a match runs. `route_after_correlation` sends every alert with a skill match to
analysis, never through the strong-correlation shortcut (founder plan step 2).

#### 2.2 Wrapping today's analysis

`AnalysisAgent._reason` (`lg_sotf.agents.analysis.base`) gains one branch: with a match and the flag on,
it calls `SkillInvestigator.investigate(ctx, run, match)` (`lg_sotf.agents.investigation.executor`)
instead of `ReActReasoner.reason`. Everything else in `_run` stays: the internal history lookup, the
rule assessment (`rule_threat_score` still orders the queue and still corroborates responses), the
refusal handling and `_assemble_result`. `AnalysisResult` and `AnalysisDigest`
(`lg_sotf.core.state`) gain an `investigation: SkillDigest` (skill id and version, contract hash, prompt
hash, hypothesis, checker status and reasons, blocking conditions, fact ids, stop reason, the tier at
decision time). Facts are stored in a new `evidence_facts` table (RLS; AI-E3.2) and listed in the
evidence pack; graph state carries ids only.

Threat-intelligence lookups become two registry tools (`reputation.virustotal`, `reputation.abuseipdb`)
that both paths use, so the ReAct path also writes facts. **No skill**: the ReAct path and the legacy
`decide` run exactly as today (with AI-E1.9's changes if merged). An AI verdict alone never closes on
that path.

#### 2.3 The executor, settling and budgets (AI-E3.3)

* **Settle.** A query whose window ends after "now minus the source's ingest lag"
  (`max_event_lag_s` of the Wazuh source, default 900 s) would read an incomplete future. The executor
  therefore defers the investigation until `occurred_at + settle_min + lag`: the analysis node returns a
  deferral and the run is resumed by the scheduler, like a run waiting for an analyst
  **(uncertain: LangGraph interrupt plus a scheduled resume, or a delayed re-enqueue; AI-E3.3 picks one
  with ARCH-E1.1's graph versioning)**. Alerts older than that when processed run at once. A tool also
  marks any fact whose window had not closed `complete: false`, so a skipped settle can never close.
* **Always queries** run first, without a model, in the order of the file, each through
  `ctx.trace.tool(...)` (`lg_sotf.llm.trace.TraceRecorder.tool`) so the trace store (INV-05) and
  cassettes see them. Their facts get ids `<evidence id>:<n>` from the executor; the model cannot mint
  a fact id.
* **Planner** (`investigation.plan.<skill id>`, registered per skill version with `register_prompt`,
  deep tier): the system and task text are the skill's trusted prose and hypotheses; the facts are
  rendered in the existing untrusted block (`lg_sotf.llm.prompting`, `<tool_data>`), because typed
  fields still carry attacker-named strings (service names, command lines, user names). Its action space
  is closed: `query <optional evidence id>` or `finish`, like today's candidate ids
  (`react.py`). Tenant guidance text (section 4.2) is rendered as data, never as instructions.
* **Final output** (`SkillVerdict`): `verdict`, `hypothesis` (an id from the skill), `threat_score`,
  `certainty`, `claims[]` (`text` up to 300 characters, `ref` a proof or indicator id, `cites` up to 10
  fact ids) and `recommended_actions`. There is no free conclusion field: the narrative shown to the
  analyst is rendered from the claims, so every sentence has its citations (PRD-2.1 chips).
* **Budgets.** Per investigation: `optional_queries` (default 3), `llm_calls` (3), `tokens`, `usd` (priced
  by `lg_sotf.llm.pricing`, AI-E5.3) and the existing wall-clock share of `worker.analysis_timeout_s`;
  plus per tenant a cap on concurrent indexer queries. A breach stops the run with
  `stop_reason=budget_<kind>`; the checker treats every stop other than `finished` as incomplete, so a
  budget breach always escalates. The v2 run cost $0.0028 per alert at 2.2 calls; a skill run is one or
  two planner calls plus at most 8 queries, target under $0.02 on DeepSeek and under $0.25 on a
  frontier model **(uncertain until AI-E3.8b measures it)**.

**How it degrades.** No skill, or flag off: today's path. Indexer unreachable, credentials missing or
the tool disabled for the tenant: facts are absent, `required` evidence is unknown, the run finishes
with a verdict on what it has and escalates. Model refusal: escalates (`model_refused`, as today).
Invalid skill file: the process does not start (CI catches it first).

### 3. Wazuh evidence tools

These are INT3.4 (#200), re-scoped to the four templates the skills need first; the file-integrity and
network templates of its title move to INT3.4b. They run against the **customer's Wazuh indexer**
(OpenSearch), the system that already holds the telemetry, through the registry (AI-E2.1).

#### 3.1 Templates

| Tool | Parameters (typed) | Query (OpenSearch DSL, `POST /<index>/_search` only) | Fact kind |
|---|---|---|---|
| `wazuh.host_activity:1` | `host`, `at`, `before_min` and `after_min` (≤ 60 each) | `term agent.name`, `range timestamp`; aggs: `terms rule.groups` (50), `terms rule.mitre.id` (50), `max rule.level`; top 50 hits by level then time with `_source` restricted to an allow list | `host_activity` |
| `wazuh.logon_fanout:1` | `pivot` (source_ip, source_host, target_user, target_host), `value`, `at`, window (≤ 1440 min), `logon_types`, `outcomes`, `family` (windows, sshd) | `terms data.win.system.eventID` [4624, 4625, 4648, 4740, 4771, 4776] (sshd: `rule.groups` authentication_failed/success) and `term` on the pivot field; aggs: `cardinality` (precision 1000) of users, sources and hosts, `terms` of users and sources (50), `filters` by outcome, `min` time of first failure and first success | `logon_fanout` |
| `wazuh.process_lineage:1` | `host`, `image` or `process_guid`, `at`, `after_min` (≤ 30), `depth` (≤ 8) | Sysmon EID 1 on the host: parents by `term data.win.eventdata.processGuid`, walked up at most `depth` queries; children by `term data.win.eventdata.parentProcessGuid` or `parentImage` (50) | `process_lineage` (with `children`) |
| `wazuh.prevalence:1` | `kind` (sha256, process_image, service_image_path, service_name), `value`, `days` (≤ 30) | Across the tenant's agents: `term` on the kind's field (`match_phrase` on `data.win.eventdata.hashes` for a SHA-256 token); aggs: `cardinality agent.name`, `min` and `max` timestamp, `value_count` | `prevalence` |

Command-template prevalence is not queryable in the indexer (there is no template field); it comes from
the platform side (AI-E4.2, from `indicator_sightings` extended with a `command_template` type).

**Coverage caveats (uncertain, INT3.4 measures them in the lab).** `wazuh-alerts-*` holds only events
that matched a rule at or above the manager's `log_alert_level` (default 3). 4624 (rule 60106, level 3)
and 4625 are there; plain Sysmon EID 1 process creations mostly are not, so `process_lineage` needs
`wazuh-archives-*` (`logall_json`) or a local rule raising EID 1, and reports `complete: false` when the
host shows no EID 1 events in the last hour. Fleet prevalence is bounded by the indexer's retention
(often 7 to 30 days); the fact records the window actually covered.

#### 3.2 Query safety

* **No free-form queries.** A template is a Python function from a validated parameter model to DSL.
  Values only ever enter `term`, `terms`, `range` and (for hashes only) `match_phrase`. A unit test walks
  the DSL of every template over generated parameters and refuses any key outside an allow list
  (`bool`, `filter`, `term`, `terms`, `range`, `exists`, `match_phrase`; aggs `terms`, `cardinality`,
  `min`, `max`, `value_count`, `filters`, `top_hits`) and any `script`, `query_string`,
  `simple_query_string`, `regexp`, `wildcard`, `fuzzy` or `prefix`
  (`tests/unit/tools/wazuh/test_templates.py::test_templates_emit_only_allow_listed_dsl`).
* **Read only by construction.** The client sends only `POST /<index>/_search` (and `GET /_count` in the
  connection test); the index comes from the tenant's configuration and must match the existing
  `_INDEX` pattern of `lg_sotf.ingestion.sources.wazuh`. Every body sets `timeout: "5s"`,
  `terminate_after`, `track_total_hits: false`, a `size` at most the row cap (200) and `_source` to the
  template's field allow list. The indexer user needs only `read` on the alert (and archive) indices.
* **Per-tenant indexer credentials.** `tenants.settings.tools.wazuh_indexer`:
  `{enabled, source_id, username, password_ciphertext, scope: {agent_groups | agent_labels}, archives_index}`,
  encrypted like the enrichment providers' keys (`tools` section, `lg_sotf.models.tenant_settings`).
  The base URL and index come from the referenced Wazuh source; the tool never takes a URL. On a cluster
  shared between customers, the DLS role per tenant of INT3.2 (#239) is a precondition, and the template
  adds the tenant's scope as a mandatory `terms` filter as well (defence in depth); the tool refuses to
  run on a source marked shared without a scope. Only a tenant admin, not an MSSP operator under a
  grant, may change the credentials or the scope.
* **Egress.** Requests go through `lg_sotf.net` (`egress_policy`, `GuardedTransport`): HTTPS outside
  development, every resolved address checked, the connection pinned to the checked address, and the
  install's `ingestion.allowed_destination_hosts` honoured (the PoV profile). The destination is the
  configured source host and nothing else.
* **Load on the customer's indexer.** At most 2 concurrent queries per tenant, 8 per investigation, a
  circuit breaker after repeated errors; a failed query is a missing fact, never a retry storm.
* **Shadow mode.** The tools are reads of the customer's own data with no third party, so a shadow run
  may call them live; the client is still registered as an egress boundary
  (`lg_sotf.security.shadow.egress`) with a pass-through policy, so INV-09's enumeration test covers it.

#### 3.3 Results to facts, and the schema minor bump (INT9.3)

Rows never reach the model. Each template has a deterministic mapper (`lg_sotf.tools.wazuh.mappers`)
from the response to facts, with `source.name` the tool name, `source.version` the template version and
`provenance` the trace step and hashes. **Completeness** is computed, not assumed: `complete` is false
when the response timed out, had failed shards, hit the row cap, a list aggregation had
`sum_other_doc_count > 0`, or the window had not closed.

Evidence-fact schema **v1.1.0** (a minor bump under the rules of
[evidence-facts.md](../evidence-facts.md#versioning): new optional fields, new kinds, new enum values):

| Change | Content |
|---|---|
| `_Fact.complete` (optional bool) | False when the source cut or could not finish the result; absence claims cannot rest on it |
| `subject.type` += `command_template`, `pattern` | For prevalence and pattern history |
| `ProcessNode` += optional `command_template`, `image_name`, `process_guid` | Lineage nodes comparable across hosts |
| `ProcessLineageValue` += optional `children` (≤ 50 nodes) | What the subject process started |
| `RelatedAlertValue` += optional `status` | Open cases on an entity |
| kind `host_activity` | `window_start`, `window_end`, `total`, `max_level`, `by_group[{group, count}]` (≤ 50), `techniques` (≤ 50), `events[]` (≤ 50: `at`, `rule_id`, `level`, `groups`, `event_id`, `user`, `image_name`, `command_template`) |
| kind `logon_fanout` | `pivot`, `family`, window, `failures`, `successes`, `lockouts`, `unknown_user_failures`, `distinct_target_users`, `distinct_sources`, `distinct_target_hosts`, `first_success_after_failure_s`, `success_users`, `failed_users`, `sources` (addresses), `source_hosts` (client-supplied names, never proof) (≤ 50 each), `logon_types` |
| kind `prevalence` | `scope` (`tenant_fleet`, `tenant_alerts`), window, `first_seen_at`, `last_seen_at`, `host_count`, `event_count`, `fleet_size` |
| kind `entity_context` | `role`, `criticality` (`crown_jewel`, `high`, `normal`, `low`), `declared[]` (`admin_account`, `service_account`, `automation_host`, `admin_workstation`, `scanner`, `user_device_network`, `vip`), `owner`, `groups`, `hosts` (for an address: the inventoried hosts that hold it), `declared_by`, `declared_at`, `expires_at` |
| kind `guidance_match` | `note_id`, `note_version`, `matched`, `predicates[]` |
| kind `pattern_history` | `pattern_key`, window, `analyst_benign`, `analyst_malicious`, `last_decided_at` |
| kind `similar_case` | `case_alert_id`, `decided_at`, `decision` (an analyst decision), `features_matched[]`, `similarity` (0-1) |

A pinned 1.0 consumer ignores what it does not know, as the versioning rules already require.

### 4. Tenant reference material

All three are per tenant, under row-level security, and admit only what a person declared or decided.

#### 4.1 The context pack (AI-E4.1, absorbs issue #320)

A store of declared facts about the tenant's environment, served by the `context.entity:1` tool as
`entity_context` facts:

* **assets**: host or host pattern → role (`domain_controller`, `server`, `workstation`, ...),
  criticality (`crown_jewel` is a global never-close), owner, groups;
* **identities**: user → `admin_account`, `service_account`, `vip`, owner, groups;
* **networks**: CIDR → `user_device_network`, `vpn`, `server`, `scanner` (today's
  `triage.known_scanners`, `lg_sotf.domain.benign_evidence.KnownScanners`, migrates here);
* **automation**: automation hosts and service accounts, matched as the **source actor only** (#320);
* **maintenance windows**: host group, time range, recurrence;
* **sources**: manual entries (UI and API), and imports from Wazuh agent groups and labels (INT3.5) and
  later Entra groups (AI-E2.3).

Every declaration has an author, a mandatory expiry (at most 365 days), is audited, needs the admin role
and cannot be changed under an MSSP grant (#320's rules). Issue #320 is titled `PRD-15.1`, which in the
backlog is the i18n framework: the id clash should be fixed when the backlog is next synced
**(uncertain which id survives)**.

#### 4.2 Guidance notes (AI-E3.9)

A guidance note is an analyst's short rule, for example "backups on BKP-* run nightly as svc_backup".
It has two parts: the **text** (at most 500 characters, shown to the planner as tenant data) and a
**structured predicate** that the `context.guidance_match:1` tool evaluates deterministically:
`skills` (which skills it may inform), `scope` (hosts, users, sources: exact values or prefixes; a bare
wildcard is refused), `schedule` (optional time windows), `activity` (rule ids, command templates,
service names) and `effect: benign_context`. Only the predicate can produce a `guidance_match` fact; the
text can explain but never prove.

Lifecycle (`lg_sotf.services.guidance`, state changes audited):

```
draft ──replay──► replayed ──approve (second person)──► approved ──activate──► active ──► expired
  ▲                  │                                                          │
  └──── edit (new version, back to draft) ◄─────────────────────────────────────┘ (or retired)
```

* **draft**: any analyst, including an MSSP analyst under a grant, or the learning loop (section 7).
* **replayed**: a *fact replay* over the tenant's last 30 days of skill runs: the stored facts and the
  recorded planner verdicts are re-evaluated with the note, without calling a model or a tool, and the
  decision policy (section 6) is re-run. The report is the decision diff: alerts that would newly close
  (with any analyst or blind-audit label they have), and the count by skill. A note under which any
  newly closed alert carries a malicious label is rejected automatically.
* **approved**: by a second person with the `guidance:approve` permission (never the author; PRD-8.3's
  four-eyes mechanism); a tenant can restrict approval to its own admins.
* **active**: with a mandatory expiry (at most 180 days; 30 days by default). A note never applies to
  high or critical alerts or the never-close classes (the matcher refuses), never changes an autonomy
  tier, and a skill whose proof cites it is still limited by its tier.
* **expired** or **retired**: kept for the evidence packs that cited it.

#### 4.3 Case memory (AI-E4.3)

Similar past cases with the analyst's decision, served as `similar_case` facts by `memory.similar_cases:1`.

* **Admission.** A case is written when a person decides: an escalation decision, a blind-audit label,
  a decision after a skill recommendation. Never from an automated close or a model disposition (the
  anti-laundering rule of `lg_sotf.tools.enrichment.history`).
* **Features** (structured, no free text): skill id, vendor rule id, event id, host role and criticality,
  user class (admin, service, human), source network class, command template and parent-child image
  pair, service name, hour-of-week bucket, fan-out buckets, pattern key.
* **Retrieval.** First exact pattern-key matches, then the same skill and rule with at least k matching
  features, ranked by matches then recency; at most 5. No embedding of alert text, so attacker-written
  text cannot steer retrieval. pgvector (the backlog's assumption) is not needed for v1 **(uncertain:
  revisit if structured matching recalls too little)**.
* **Use.** Similar cases inform the planner and can appear in a proof only next to a telemetry predicate
  (section 1.1); `pattern_history` (exact counts) is the form proofs use.
* **Isolation.** Table under forced RLS (INV-01), read under `tenant_tx`; no cross-tenant retrieval. An
  MSSP's analysts' decisions count in the tenant they decided in. Cross-tenant learning happens only
  through skill releases (section 7).

### 5. The checker (AI-E3.4)

`lg_sotf.domain.citations.check(verdict, ledger, skill, view) -> CheckReport` is pure and deterministic.
It runs on every skill verdict, whatever the verdict, and its report is stored and shown:

1. **Citations.** Every claim cites at least one fact id, and every cited id is in this run's ledger
   (facts the tools returned in this run, with a trace step). Otherwise `uncited_claim` or
   `unknown_fact`.
2. **Hypothesis.** For a `benign` verdict, `hypothesis` names one of the skill's `close.hypotheses`;
   otherwise `unknown_hypothesis`.
3. **Proof.** The hypothesis's proof evaluates to true over the ledger and the view (three-valued; the
   proof's fact predicates may read only facts the claims cite). Otherwise `proof_failed:<predicate>`.
4. **Indicators.** No malicious indicator of the skill is true or unknown over the whole ledger (not
   only the cited facts). Otherwise `malicious_indicator:<id>`.
5. **Never-close.** No skill never-close condition and no global class (section 6.1) is true or unknown.
6. **Completeness.** Every `required` evidence id has a fact with `complete: true`, and the run stopped
   with `finished`. Otherwise `incomplete:<id>` or `stopped:<reason>`.

Any failure sets `checker.status = failed`; the decision policy then escalates. The checker also
reports **citation faithfulness** for the scorecard: the share of claims whose cited facts satisfy the
predicate the claim refers to. An LLM judge of narrative quality may be reported in evaluation, never in
the gate.

### 6. The decision policy that replaces the grey zone and the rules-score gate

#### 6.1 The rule

`lg_sotf.domain.closure` (new, pure) and `lg_sotf.domain.routing.decide`, which delegates to it.
The tier is resolved before `decide` (in the analysis node, from the autonomy table and the ceilings
below) and carried in the digest, so `decide` stays a pure function of state.

```python
GLOBAL_NEVER_CLOSE_TECHNIQUES = ("T1003", "T1555", "T1552", "T1558",   # credential theft (prefixes)
                                 "T1070.001",                          # log clearing
                                 "T1562",                              # security-tool tampering
                                 "T1486", "T1490", "T1489")            # ransomware behaviour

def decide(state, t: RoutingThresholds) -> Decision:
    if state.more_info_loops > 0:                return escalate("analyst_request")          # unchanged
    if refused_by(state):                        return escalate("model_refused")            # unchanged
    if response_policy_met(state, t):            return plan_response("high_risk")           # unchanged (malicious only)
    inv = state.analysis.get("investigation")
    if inv is None:                              return legacy_decide(state, t)              # today's grey zone and rule
                                                                                              # corroboration (+ AI-E1.9):
                                                                                              # a verdict alone never closes
    if inv.verdict != "benign" or inv.threat_score >= t.close_max_threat:
        return escalate("skill_not_benign")                                                  # queue order by threat
    blockers = [b for b in (
        "high_severity"          if state.severity in HIGH_SEVERITIES else None,             # INV-03
        "llm_normalized"         if llm_normalized(state) else None,
        "steering_text"          if injection_signal(state.triage) else None,
        "never_close_class"      if never_close_class(state.alert, inv) else None,           # techniques of the alert
                                                                                              # and of host_activity facts,
                                                                                              # crown jewels, first-seen rule
        "rule_evidence_malicious" if state.analysis.rule_corroborated else None,
        "open_case_on_entity"    if inv.open_case else None,
        "severity_not_in_skill"  if state.severity not in inv.close_severities else None,
        "checker_failed"         if inv.checker.status != "passed" else None,                # section 5
    ) if b]
    if blockers:                                 return escalate("skill_close_blocked", blockers)
    match inv.tier:                                                                           # resolved with ceilings
        case "shadow":           return escalate("skill_would_close")       # skill output hidden from the analyst
        case "recommend":        return escalate("skill_recommends_close")  # shown, unless drawn into the holdout
        case "auto_full_audit":  return close("skill_closed", disposition="benign", audit="every")
        case "auto_sampled":     return close("skill_closed", disposition="benign", audit="sampled")
        case _:                  return escalate("skill_tier_unknown")      # fail closed
```

What is gone on the skill path: the confidence band (triage plus correlation) and the rules' threat score
below 30. What replaces them: a benign hypothesis proved by checked facts, no malicious indicator, no
never-close condition, and an earned tier. What stays everywhere: refusals, more-info loops, the
response policy, high and critical, model-normalised alerts, steering text.

A "rule first seen" for the tenant (no alert with that vendor rule id in the last 30 days) is a global
never-close; when the history is unknown it counts as first seen, so a new tenant closes nothing by
skill for 30 days. **Close but remember**: a skill-closed alert keeps its indicator sightings, so
correlation still sees it; if an entity of it joins a confirmed incident within 7 days, the closed alert
is reopened into the case and counts as a miss (section 6.3).

#### 6.2 INV-03, amended

The registry entry (`lg_sotf.invariants.registry`) changes when AI-E3.8a merges, with its proofs:

> **INV-03. An AI verdict alone never closes high or critical alerts or never-close classes; for low and
> medium it may close only through a skill whose autonomy tier allows it, with checker-verified
> evidence.**
>
> A fooled or injected model must not be able to make a dangerous alert disappear. Routing is a pure
> policy. High and critical alerts, and the never-close classes (credential theft, log clearing,
> security-tool tampering, ransomware behaviour, crown-jewel assets, a rule the tenant has not seen in 30
> days, model-normalised alerts, alerts with steering text), close only by an analyst, a suppression
> rule or an analyst-approved pattern. A low or medium alert closes on a model verdict only when an
> investigation skill applied, the deterministic checker verified that every claim cites facts the tools
> returned in this run and that the skill's benign proof holds with no malicious indicator, and the
> skill's autonomy tier for this tenant is `auto_full_audit` or `auto_sampled`. Without a skill, low and
> medium alerts close only when rules or the tenant's declared context corroborate the model.

Code: `src/lg_sotf/domain/routing.py`, `src/lg_sotf/domain/closure.py`, `src/lg_sotf/domain/citations.py`,
`src/lg_sotf/domain/benign_evidence.py`. Proofs keep today's seven and add
`tests/unit/domain/test_closure.py::test_a_skill_never_closes_high_or_critical`,
`::test_a_skill_never_closes_a_never_close_class`, `::test_a_failed_check_never_closes`,
`::test_only_an_auto_tier_closes`, `::test_an_unknown_tier_fails_closed`,
`::test_without_a_skill_a_verdict_alone_never_closes`, and
`tests/integration/e2e/test_llm_safety.py::test_injected_tool_output_never_closes_through_a_skill`.
The runtime check `routing_policy` (`lg-sotf verify-invariants`) gains probes for the same cases.

Two new invariants are registered as `pending`:

* **INV-13. Autonomy is earned per skill and tenant and lost on any miss** (AI-E3.10): promotion needs
  the evidence of section 6.3 and four-eyes approval; a miss demotes to `shadow` in the same transaction
  as the label that revealed it.
* **INV-14. Evidence tools are read-only, templated and capped** (AI-E2.1, INT3.4): every registered
  tool has a typed parameter model, a row cap, a time cap and no write path; the DSL allow-list test
  holds for every Wazuh template.

#### 6.3 Autonomy tiers per (skill × tenant)

State lives in a table `skill_autonomy` (tenant, skill id, contract hash, model profile, tier, counters,
since) with every change in the audit log; it is earned state, not a setting. The service is
`lg_sotf.services.autonomy.AutonomyService`.

| Tier | What happens to a would-close alert | Labels that count as evidence |
|---|---|---|
| `shadow` | Escalated as today; the skill's output is stored but hidden from the analyst until they decide (the blind audit's hiding, `lg_sotf.domain.blind_audit.hidden_alert_view`) | The analyst's decision (skill-blind) |
| `recommend` | Escalated with "recommend close" and the cited claims; a seeded holdout (default 25%, drawn with `lg_sotf.domain.blind_audit.sample_key`) is shown without it | Holdout decisions only (skill-blind) |
| `auto_full_audit` | Closed; **every** closure enters the blind audit (a per-skill stratum at 100%) | Blind-audit labels (AI-blind) |
| `auto_sampled` | Closed; closures are blind-audited at the tenant's rate, at least 5% and 5 per week per skill | Blind-audit labels (AI-blind) |

**Promotion** is proposed by the system and approved by two people (PRD-8.3, four-eyes; self-approval
refused), never automatic. Counters are per contract hash and model profile.

| Step | Evidence required (all with zero misses) |
|---|---|
| shadow → recommend | 100 skill-blind would-close decisions **(proposal: 100 because `recommend` closes nothing; set 300 if preferred)** and the skill's corpus gate green |
| recommend → auto_full_audit | 300 skill-blind would-close decisions since the contract began (shadow plus holdout), and at least 2 weeks in `recommend` |
| auto_full_audit → auto_sampled | 300 blind-audited (AI-blind) closures at `auto_full_audit` |

Zero misses in 300 bounds the miss rate below 1% (one-sided 95% Clopper-Pearson upper bound
1 − 0.05^(1/300) = 0.99%), the founder report's bar. This matches milestone M9 ("n ≥ 300 shadow
decisions, FN upper bound within target, four-eyes promotion").

**A miss** is: a malicious or true-positive label from any counted source on an alert the skill closed
or would have closed; a recall canary it would have closed (AI-E3.11); a skill-closed alert later
reopened into a confirmed incident. **Demotion** is automatic on any miss, in the same transaction as
the label (hooks in `BlindAuditService.label` and the escalation decision path): the tenant's tier goes
to `shadow`, counters reset, and a skill incident is opened. Every other tenant on the same contract at
`auto_sampled` drops to `auto_full_audit` until a person closes the incident as tenant-specific or as a
skill flaw (which needs a new skill version).

**Ceilings** applied when the tier is resolved: the tenant mode of PRD-13.3 (Observe = shadow, Assist =
recommend, Autonomous = earned), the per-tenant kill switch of SEC9.3 (skills to shadow), an optional
tenant setting `investigation.max_tier`, and a skill incident hold. Ceilings only lower.

Honest limits: in `shadow` the analyst still sees today's analysis, so a label is blind to the skill but
not to all AI; that is why closing without per-closure review (`auto_sampled`) needs 300 fully AI-blind
labels. At `auto_full_audit` the analyst workload is a weekly blind audit instead of a live queue: the
alert is out of the queue at once, the labelling effort is not yet saved.

### 7. The skill-learning loop (AI-E3.7)

```
analyst overrides ──► weekly clustering per skill ──► AI draft (guidance note | skill diff) ──► replay ──► human approval ──► version bump
```

* **Signals.** (a) An analyst decided true positive where the skill would close or recommended closing
  (a miss: demotion first, then learning); (b) an analyst decided benign where the skill escalated with
  `proof_failed`, `incomplete` or `criteria`; (c) step feedback on claims (AI-E4.5).
* **Clustering.** By skill, failing predicate, missing fact and pattern key, from the stored checker
  reports; clusters below 5 cases are not drafted.
* **Drafting.** An offline deep-tier call (`investigation.learn`, registered prompt) proposes, per
  cluster, either a **tenant guidance note** (structured predicate plus text, created in `draft`) or a
  **skill diff** (a YAML patch with a changelog entry and its claimed class). It never writes to an
  active skill or note.
* **Replay.** Guidance: the fact replay of section 4.2. Skill diff: `lg-sotf skill-diff` for the class,
  then the corpus gate (section 8.2) with cassettes (`replay-tools` for prompt changes, deterministic
  replay for criteria changes) and the adversarial families. Any new malicious would-close rejects it.
* **Approval and bump.** Guidance: a second person (section 4.2). Skill: a pull request with the replay
  report attached, two maintainer reviews; the version follows section 1.6 and so does autonomy.
* **Where learning lives.** Skills are global and learn through releases, from the corpus and from
  consented, aggregated override summaries (counts per skill and failing predicate, no alert content).
  Tenants adapt through guidance notes. Customer data never leaves a self-hosted install for this.

### 8. Evaluation

#### 8.1 The corpus needs telemetry (AI-E1.10)

`corpus_v1` holds alerts only. Skills read what surrounds an alert, so the generator
(`tests/fixtures/attack_corpus`) emits, per scenario, the non-alert context events too (the 4624
network logon before a 7045, the success after a typo, the Sysmon EID 1 children, the fleet's updater
installs), and each item gets **gold evidence**: the expected benign hypothesis for benign items, the
expected malicious indicators for attacks. The eval harness serves the Wazuh tools from that event
stream through a `FixtureWazuhIndex` (in `lg_sotf.eval.tool_fixtures`, next to `FixtureIntelProvider`)
that answers the same parameter models, on event time (AI-E1.9's clock) so nothing from the future
leaks. A contract test loads the same events into the Wazuh 4.14 container (INT3.1) and checks that the
real DSL returns the same facts. The two skill families are small in `corpus_v1` (logon: 24 benign, 10
malicious; service: 11 and 7), so AI-E1.10 also adds at least 50 attack variants per skill, including
**context-abuse** items: a spray from a declared admin workstation, PsExec by a declared admin account
followed by discovery, activity outside a maintenance window, a declared service account used
interactively. Cassettes record facts as the observation (as `lg_sotf.llm.cassette` anticipates).

#### 8.2 Per-skill scorecards and the gate (AI-E3.8b)

`lg-sotf eval` reports, per skill (as `metrics_by_family` does per family): items it applied to,
benign would-close rate and malicious would-close rate (with n and Wilson intervals), checker failures
by reason, hypothesis accuracy against gold, indicator recall against gold, citation faithfulness, cost
and latency per investigation, tool error rate. `tests/fixtures/eval/skills/<skill>_thresholds.yaml` is
read by `lg_sotf.eval.gate`:

* malicious would-close = 0, overall and per technique; any context-abuse item closing fails;
* the adversarial families (AI-E6.1) plus a new `wazuh-field-injection` family (instructions in service
  names, command lines, user names, workstation names) change no outcome;
* a benign would-close floor, raised as the skill improves (a ratchet, like the eval floors);
* a cost ceiling per investigation.

The gate runs on every PR with the fake model and the fixture index (deterministic), and nightly with
the pinned real model (ARCH-E2.1). The corpus gate can only show that the skill does not close the
attacks we know; at n of 10 to 60 attacks per skill its upper bounds are wide. **Recall in production**
is tested by canaries (AI-E3.11): every week, per enabled skill and tenant, the attack and context-abuse
items of the skill are re-addressed to the tenant's real host and user names and run through
`ShadowRunner` with their recorded facts (cassette `replay-tools`, production model profile). A
canary the skill would close is a miss. Canaries never reach a queue, a notification or the blind
audit; INV-09 holds.

#### 8.3 Composition with pattern memory and the verdict-cache fix

The founder plan's step 3 (pattern memory: a per-detection ledger of k analyst-benign and zero
malicious decisions) closes repeats at the gate, before triage and before any skill, without a model.
Skills compose with it as follows:

* **One pattern recipe.** `lg_sotf.domain.patterns.pattern_key(alert)` (rule, host, user, process or
  service, command template) and `command_template(cmd)` are shared by the step-3 ledger, the fixed
  verdict-cache fingerprint (branch `fix/verdict-cache-fingerprint`, in progress: today's fingerprint,
  `lg_sotf.ingestion.fingerprint.compute_fingerprint` version 1, ignores processes and command lines, so
  the ransomware PsExec `cv1-0113` shares a key with desktop support's), `platform.pattern_history` and
  case memory. One recipe means one place to fix a collision. **(uncertain: the recipe is whatever the
  fix and step 3 settle on; this design adopts it.)**
* **Only people feed memory.** Skill closures never increment the ledger, case memory or the verdict
  cache, so the AI cannot launder its own decisions into evidence. Blind-audit labels and analyst
  decisions do.
* **Accounting.** Alerts closed by pattern memory never count toward a skill's promotion, and the blind
  audit stratifies its frame by closure source (pattern, skill, rule, tenant context), so each source
  has its own miss estimate.
* **Simulation.** The AI-E1.9 simulator (`lg_sotf.eval.calibration`, on its branch) re-decides recorded
  runs; it gains the skill path so policy changes are measured on recorded skill digests without model
  calls.

### 9. Threats

These rows are added to [threat-model.md](../threat-model.md) section 2 with status *Planned* now, as
its gate per epic requires before the first T3 story (AI-E2.1) merges.

| ID | STRIDE | Threat | Controls | Status |
|---|---|---|---|---|
| TM-EVT-8 | T | Instructions in Wazuh fields (service name, command line, user or workstation name) steer the planner to a benign hypothesis | Facts rendered as untrusted data; closed action space (optional query ids, hypothesis ids); the close rests on the deterministic proof and the checker, not on the model's words; `wazuh-field-injection` adversarial family gated | Planned (INT3.4, AI-E3.4, AI-E3.8b) |
| TM-EVT-9 | I | An evidence query reads another customer's events on a shared Wazuh cluster | Per-tenant indexer user and DLS role (INT3.2); mandatory tenant scope filter in every template; refuse a shared source without a scope; negative DLS test per tenant | Planned (INT3.2, INT3.4) |
| TM-EVT-10 | E | A parameter widens a query or a tool writes | Typed parameters; values only in `term`/`terms`/`range`; DSL allow-list test; `POST _search` only; read-only indexer role; row, time and window caps | Planned (AI-E2.1, INT3.4) |
| TM-EVT-11 | D | Investigations overload the customer's indexer | Per-tenant concurrency, per-investigation query budget, `timeout` and `terminate_after`, circuit breaker | Planned (AI-E3.3, INT3.4) |
| TM-EVT-12 | T | A truncated, failed or premature query reads as "nothing happened" | `complete` computed per fact; three-valued predicates fail closed; settle delay; incomplete required evidence escalates | Planned (INT9.3, AI-E3.4) |
| TM-EVT-13 | I | Case memory or guidance leaks across tenants | Forced RLS (INV-01), reads under `tenant_tx`, no cross-tenant retrieval or embeddings; cross-tenant learning only via aggregated skill releases | Planned (AI-E4.3, AI-E3.9) |
| TM-WRK-11 | T | A poisoned guidance note (insider, compromised analyst account, or an AI draft) makes attacks close | Only the structured predicate yields facts; no bare wildcard scope; never for high, critical or never-close classes; fact replay rejects notes that close a labelled attack; second-person approval; mandatory expiry; audited | Planned (AI-E3.9) |
| TM-WRK-12 | T | Skill drift: a skill, prompt or model change widens what closes | Contract hash; `skill-diff` classes with a CI version check; widening caps autonomy at `auto_full_audit`; per-skill corpus gate per PR and nightly; canaries; blind-audit miss estimate per skill | Planned (AI-E3.8a, AI-E3.8b, AI-E3.11) |
| TM-WRK-13 | E | Autonomy is gained without being earned: miscounted evidence, an analyst rubber-stamping, or a self-approved promotion | Only skill-blind and AI-blind labels count; four-eyes promotion (PRD-8.3); demotion on any miss in the label's transaction; canaries; INV-13 | Planned (AI-E3.10) |
| TM-WRK-14 | T | An attacker trains the AI with benign-looking repeats so memory vouches for the real attack | Only analyst decisions feed the ledger and case memory; skill closures never do; pattern key includes the command template; memory never proves alone | Planned (AI-E4.3, founder plan step 3) |

The OWASP ASI01, ASI02, ASI06 and ATLAS AML.T0070/AML.T0080 rows gain references to these when the
stories merge.

### 10. Migration from today, and the build order

1. **Today (unchanged until a tenant opts in).** `ReActReasoner` and the legacy `decide`. In flight
   and independent: the verdict-cache fix, AI-E1.9, the founder plan's steps 1 to 3.
2. **Foundations, no behaviour change.** Tool registry wrapping the existing lookups (AI-E2.1),
   evidence-fact v1.1 (INT9.3), corpus telemetry and the fixture index (AI-E1.10), skill format, loader,
   router and the two skills (AI-E3.1a), Wazuh templates (INT3.4), fact ledger (AI-E3.2).
3. **Skills run, nothing closes.** Checker (AI-E3.4), executor and planner (AI-E3.3), per-skill
   scorecards and gate (AI-E3.8b); tenants opt in with `investigation.skills` (AI-E3.6), first through
   `ShadowRunner` as a candidate, then inline at tier `shadow`.
4. **Decision policy v2 and INV-03 amended** (AI-E3.8a). The close branch exists, but every tier starts
   at `shadow` and promotion machinery is not yet there, so nothing closes by skill yet.
5. **Reference material**: context pack (AI-E4.1), guidance notes (AI-E3.9), prevalence (AI-E4.2), case
   memory (AI-E4.3).
6. **Earning autonomy**: promotion evidence, holdout and demotion (AI-E3.10, needs PRD-8.3), canaries
   (AI-E3.11), learning loop (AI-E3.7). The first `auto_full_audit` promotion is a calendar event: a
   design partner's traffic in shadow for 4 or more weeks (M9, 2027-04-23).
7. **More skills** (AI-E3.1b, AI-E3.1c): scheduled tasks, SSH authentication, account lifecycle,
   lateral movement over RDP and WinRM, scanner look-alikes.

The legacy path stays for every alert without a skill. It is removed only when skills cover the
families that matter and a scorecard shows the skill path is at least as safe, which is a later ADR.

Stories, acceptance tests, tiers, points and dependencies:
[investigation-skills-stories.md](../design/investigation-skills-stories.md).

## Consequences

* **Easier.** A detection engineer can read in one file why an alert closed, and a reviewer can
  replay any change; closure becomes measurable per detection family and tenant; the model's job
  shrinks to choosing among allowed queries and picking a hypothesis, so a cheaper or sovereign model is
  more likely to clear the bar.
* **Harder.** Skills are content that must be written, reviewed and kept current per family; families
  without a skill keep today's zero-closure behaviour. The settle delay holds low and medium alerts for
  the skill's settle time plus the source's ingest lag (25 to 30 minutes with Wazuh's default 15-minute
  `max_event_lag_s`) before a skill can close them; they were waiting for a person anyway. Customers must give a read-only indexer user and, on
  shared clusters, a DLS role; process lineage needs archives or extra Wazuh rules.
* **Enforced by CI.** The catalogue tests (load-time rules, overlap), `skill_compat.py` (version bump
  versus change class), the DSL allow-list test, the evidence-fact schema check (1.1.0), the per-skill
  eval gate, INV-03's new proofs, INV-09's egress enumeration, and the threat-model docs test.
* **Accepted.** Shadow-tier labels are blind to the skill, not to all AI (section 6.3). The corpus
  bounds are wide; production evidence (300 blind labels) is what promotes. The Wazuh coverage caveats of
  section 3.1 are measured in the lab before any tenant enables the tools.

## Alternatives considered

* **More tools for the free ReAct loop, no skills.** Keeps the model in charge of what to look at and
  of when evidence suffices; nothing to replay or review per family, and no unit to earn autonomy on.
  Elastic's write-up found a deterministic first pass plus specialist pipelines cheaper and more
  complete than a single agent loading skills on demand; skills here are closer to their specialists
  (the plan is fixed per family, the model fills gaps).
* **Skills as Markdown with front matter.** Rejected in section 1.1: two parsers, prose that nothing
  checks.
* **Skills as Python code.** Arbitrary logic, no contract hash, no static diff classification, and
  detection engineers would review Python instead of criteria.
* **An LLM critic instead of a deterministic checker.** Not reproducible, and a second model reading the
  same attacker text can be steered the same way. An LLM judge stays for narrative quality in evaluation
  only.
* **Model-generated queries (free-form DSL or KQL) with a guard.** AI-E6.4's query guard is *Later*;
  templated queries cover the families first and keep INV-12's "the model never chooses what is sent".
* **Option C: close on a calibrated verdict threshold.** Rejected by the founder; the calibrator (AI-E4.4)
  may later tune a skill's certainty, never replace its proof.
* **Embedding-based case memory over alert text.** Attacker-written text would steer retrieval;
  structured features first.
* **Autonomy per tenant, not per skill.** One weak family would put every family at risk, and one miss
  would stop everything; per skill keeps the blast radius to one family.

## Amendment 1 (2026-11-14): harness v1 on decision policy v3

**Why.** After this record was written the founder decided "all benign must be closed" (2026-11-09), and
decision policy v3 shipped (#349, #351, #352): at the tenant tier `auto_full_audit` the models close every
alert the deep tier judges benign, except critical alerts and the never-close classes; every such close is
audited, and a related threat reopens it (`lg_sotf.core.retro_reopen`). Measured on dev with a realistic
mix (73 benign, 3 attacks, DeepSeek): 40 of 73 benign closed before the safety net and 0 attacks closed;
**27 of 73 benign got an `inconclusive` deep verdict** because the model sees only the alert. The
investigation harness exists to remove that doubt with evidence. Sections 6.1, 6.3 and step 6 of
section 10 assumed nothing closes until a skill earns it; that is no longer the product.

**What stays.** Sections 1 to 5 and 8: reviewed skill files, the deterministic router on
detector-written fields, typed query templates through the tool registry (the model never writes a
query, a target or a value), typed facts with ids minted by code, the trace store, budgets, the
deterministic checker, tenant reference material and per-skill scorecards.

**What changes.**

1. **The closing rule is policy v3, and evidence sharpens it** (replaces sections 6.1 and 6.3 for the
   tier `auto_full_audit`; AI-E3.8a is re-scoped to this):
   * A benign deep verdict still closes at the tier. When an investigation ran, the close also needs the
     checker to pass; the close is then recorded as *evidence-backed* (skill id, fact ids).
   * **A malicious indicator of the skill that is true over the facts is a never-close**, whatever the
     model says, and the alert goes to an analyst with the facts. This is the structural answer to the
     look-alikes (the logon success of a password spray, PsExec before `whoami /all`).
   * A failed check on a benign verdict (uncited claim, unknown fact) escalates. An *unknown* indicator
     (the tool could not answer) does not block the close: policy v3 already closes without evidence,
     and blocking on unknown would make an unreachable indexer close fewer alerts than no harness.
   * Critical alerts, the never-close classes, steering text and a recent true positive are unchanged.
   * Earned autonomy per (skill x tenant) is kept for one purpose, later: lowering the audit rate of a
     proven skill from every close to a sample (AI-E3.10). It no longer gates closing.
2. **No settle delay in v1** (replaces the settle bullet of section 2.3). The investigation runs at once
   on the telemetry that exists. A fact whose window had not closed is marked `complete: false` and
   shown as such. What happens after the alert is covered by the retro-reopen, which already reopens a
   model close when a related threat appears within 24 hours. A deferred, resumed run can come back
   later if the scorecard shows misses that only later telemetry would catch.
3. **A default skill, so every Wazuh alert is investigated** (adds to section 2.1). When no family skill
   matches, the router picks `wazuh.default`: host activity around the alert, prevalence of its main
   object, and logon fan-out when the alert carries a user or source address. It has no benign proof of
   its own; it gives the model facts to cite, and its malicious indicators (for example other
   high-level or never-close-class alerts on the host in the window) block a close. Family skills refine
   it. Alerts from sources without evidence tools keep today's path.
4. **A small predicate set first** (narrows section 1.3). Skills use only: `exists`, `count >=`,
   `distinct >=`, `prevalence_hosts >=`, `first_seen_older_than`, `any_group_in`, `any_technique_in`, and
   `and` / `or` / `not`, three-valued. More are added with a skill that needs them.
5. **Build order: a thin slice first, measured after every step** (replaces steps 2 to 6 of section 10).
   The same two measurements gate each step: the dev run of 100 alerts (realistic mix) and `corpus_v1`
   with telemetry. A step merges only when benign closed does not drop and attacks closed stays 0.

   | Step | Stories | Exit |
   |---|---|---|
   | 1. Foundations | AI-E2.1 registry (#193), AI-E1.10 corpus telemetry and event store (#326), INT9.3 fact schema 1.1 and the facts table (#325) | Reputation lookups run through the registry; the corpus answers tool queries offline and on dev |
   | 2. Evidence | INT3.4 the four Wazuh templates (#200) | Typed facts from the event store and from the Wazuh lab container |
   | 3. Investigate | AI-E3.3 executor and budgets with `wazuh.default` (#205), AI-E3.2 fact ledger (#201) | Every Wazuh alert gets facts; the deep verdict cites them; first measurement of `inconclusive` |
   | 4. Check and block | AI-E3.4 checker (#207), AI-E3.8a policy integration (#330), AI-E3.1a two family skills (#199) | Malicious indicators block closes; evidence-backed closes recorded |
   | 5. Tenant context | AI-E4.1 context pack (#328), AI-E4.2 prevalence (#327) | Second measurement |
   | 6. Production | AI-E3.6 tenant flag and shadow promotion (#209), AI-E3.8b per-skill scorecards and CI gate (#329), AI-E5.3 cost per investigation (#230), a real-model run on `adversarial_v2` | A tenant can turn the harness on in shadow, compare, then promote; cost and accuracy per skill are visible |
   | Later | Case memory (#332), guidance notes (#333), recall canaries (#334), learning loop (#335), audit sampling by earned autonomy (#331), more skills (#220, #228, #336) | |

**Production bar for step 6.** Degrades to today's path when the indexer is unreachable or a budget is
spent; no tool runs without a declared risk class, schema, egress target and row cap; tool output is
always rendered as data; per-tenant enablement, with a read-only indexer user; a shadow run performs no
side effect (INV-09); cost per investigation is metered and capped; the threat-model rows TM-WRK-11 to
TM-WRK-14 are implemented or explicitly deferred.

## Amendment 2 (2026-11-14): what the public evidence changes

A research pass on the same day (public papers, vendor documentation, licences and EU rules; the report
is kept with the lead's notes, and its findings are on the re-scoped issues) confirms the direction and
corrects one rule of Amendment 1.

**Correction: an empty or failed query is never benign evidence.** Amendment 1 said an *unknown*
indicator does not block a close. The closest public study, on Wazuh alerts (Aida / Alert-Bench, October
2026), found that agents dismissed 88 to 99% of attack alerts when a query returned nothing, and that the
one component whose removal measurably hurt was the gate requiring *affirmative* benign evidence (missed
attack alerts fell from 40-70% to 3.1% with it). Therefore:

* every tool result carries a typed outcome, `success`, `empty` or `failed` (AI-E2.1), and a benign claim
  may cite only `success` observations (AI-E3.4);
* whether an alert the harness could not prove benign still closes on the model's word (policy v3 with
  full audit) or goes to an analyst is **decided by measurement**, not by this record: AI-E3.8a (#330)
  runs both rules on `corpus_v1` with telemetry and on the dev run and ships the one with more benign
  closed at 0 attacks closed.

**Confirmed, with evidence.** One investigator loop inside the existing workflow, not several agents; a
non-LLM executor writing the ledger; skills pinned by code; no same-context self-review (it broke more
decisions than it fixed) and no adversary role (no measurable effect); typed tools and templates (prompt
defences alone leave 8 to 12% injection success, so closing must rest on typed facts); human-reviewed
skills only (model-written skills gave no benefit in a public benchmark).

**Not measured anywhere in public, so measured here.** A deterministic checker in place of an LLM judge,
and tenant context. If the checker underperforms on the corpus, a separate-context judge is added on the
dismissal path only.

**Added to the build.**

| Addition | Story | Step |
|---|---|---|
| Typed outcomes and input/output hashes on every tool result | AI-E2.1 (#193) | 1 |
| Entity baseline (30-day history), the fifth shared lookup | INT3.4c (#358) | 2 |
| Forced verification before finish, loop detection, two-pass calls for open-weight models | AI-E3.3 (#205) | 3 |
| Non-investigation route for vulnerability, compliance and health findings | AI-E3.12 (#355) | 4 |
| Evidence record: observations, claims, decision, per-tenant hash chain | AI-E3.13 (#356) | 4 |
| Model qualification per tenant model | AI-E5.4 (#357) | 6 |
| Seeded attacks for any miss-rate claim (59 with no miss for below 5%, 299 for below 1%) | AI-E3.11 (#334), AI-E3.10 (#331) | 6 |

**Skill order.** `wazuh.default`, then logon failures and password spray, then file-integrity change
(the two largest sources of `inconclusive` on dev). Public incident data puts identity first (67 to 72%
of cases needing intervention), so the Microsoft sign-in and mailbox families follow as soon as the
Microsoft lab tenant exists (INT1.1). The learning loop (AI-E3.7) is deferred and re-scoped to drafting
help for a human reviewer.

**Content we may ship.** Splunk security content (Apache-2.0), Sigma (DRL 1.1, with attribution), MITRE
ATT&CK, Azure-Sentinel (MIT), LOLDrivers, Atomic Red Team. Reading only: Elastic's investigation guides
(Elastic License 2.0 forbids managed-service use, which is how MSSPs run the product) and Microsoft Learn
playbooks (non-commercial terms). Never bundled: Wazuh rule files (GPLv2; reference rule ids only),
LOLBAS and GTFOBins (GPL-3.0). These readings need counsel before a release that ships third-party
content.

**Risks carried.** The dismissal-gate evidence is one benchmark of mostly web-scanning attacks. Wazuh
5.0 (release candidate) moves to a Sigma-based rule format, so the router must not depend on 4.x rule
ids alone: it keys on rule groups and techniques as well.

