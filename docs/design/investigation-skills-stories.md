# Investigation skills: stories and build order

This page maps [ADR 0014](../adr/0014-investigation-skills.md) (investigation skills and earned AI
closure) onto the engineering backlog (`docs/roadmap/engineering-backlog.json`). It reuses the existing
story ids wherever one fits, re-scopes them where the design changes what they deliver, and adds new
ids only where nothing fits. Points use the backlog's Fibonacci scale; tiers are the roadmap's (T1 docs
and UI, T2 domain logic, T3 authorization, tenant isolation, migrations, the AI tool boundary; a human
reads every T3 diff). A story is **ready** when its acceptance is a named test, its dependencies are
merged and its tier is set.

Items marked **(uncertain)** are assumptions the named story confirms.

## Ids: what is reused, re-scoped and new

* **No AI-E2.7.** The Wazuh evidence tools already have a story, INT3.4 (#200, "Wazuh evidence tools:
  host timeline, auth events, FIM, process, network"). It is re-scoped to the four templates the skills
  need first; its file-integrity and network templates become **INT3.4b**.
* **Re-scoped:** AI-E3.1a/b/c ("recipes" become skills), AI-E3.2 (deterministic mappers; the LLM reader
  only for unstructured output), AI-E3.3 (the skill executor and planner), AI-E3.4 (the checker also
  evaluates the proof), AI-E3.6 (the per-tenant flag runs skills), AI-E4.1 (the context pack; absorbs
  issue #320), AI-E4.2 (adds command templates and rule first-seen), AI-E4.3 (structured features, no
  pgvector in v1).
* **New:** INT9.3 (evidence-fact schema 1.1), AI-E1.10 (corpus telemetry and gold evidence), AI-E3.7
  (skill-learning loop), AI-E3.8a (decision policy v2, tiers, INV-03), AI-E3.8b (per-skill scorecards
  and gate), AI-E3.9 (guidance notes), AI-E3.10 (promotion evidence and demotion), AI-E3.11 (recall
  canaries), INT3.4b.
* **Id clashes found while mapping (to fix at the next backlog sync):** issue #320 is titled
  `PRD-15.1` but `PRD-15.1` in the backlog is the i18n framework; commits #306 and #314 used `AI-E6.3`
  and `AI-E6.4` for title camouflage and activity keywords, which in the backlog are the L0-L4 autonomy
  docs and the free-form query guard.

## Prerequisites already merged or in flight

| Item | State | Why the design needs it |
|---|---|---|
| INT9.2 evidence-fact schema v1 | merged (#176) | INT9.3 extends it |
| AI-E1.3 trace store, AI-E1.4 cassettes | merged | Every tool call is traced and recordable |
| AI-E1.5a shadow sink, AI-E1.5b agreement report | merged (#295, #315) | Shadow candidates, INV-09 |
| AI-E1.8 attack-emulation corpus | merged (#307) | AI-E1.10 adds its telemetry |
| PRD-10.2 blind audit | merged (#308) | AI-blind labels, the hiding mechanism |
| INT3.1 Wazuh 4.14 in test-services | merged | INT3.4's live contract test |
| AI-E1.9 auto-close calibration | branch, issue #316 | Event-time replay; the legacy path's P3/P4 |
| Founder plan step 0: verdict-cache fingerprint fix | branch `fix/verdict-cache-fingerprint`, in progress | The shared pattern recipe (ADR section 8.3) |
| Founder plan steps 1-3: measurement, analyse every close-eligible alert, pattern memory | step 1 on `feat/fatigue-1-measurement`; ids to be assigned **(uncertain)** | Pattern history facts; skills always reach analysis |
| PRD-8.3 four-eyes | open (#234) | Promotion approvals (AI-E3.10) |
| PRD-13.3 tenant mode, SEC9.3 kill switch | open (#224, #244) | Tier ceilings (AI-E3.8a) |
| INT3.2 DLS per tenant | open (#239) | Required before INT3.4's tools run on a shared cluster |

## Build order

| # | Id | Title | Tier | Pts | Depends on | Kind | Ready |
|---|---|---|---|---|---|---|---|
| 1 | AI-E2.1 | Tool protocol and registry | T3 | 5 | AI-E1.3 (merged) | existing (#193) | **yes** |
| 2 | INT9.3 | Evidence-fact schema 1.1 | T2 | 3 | INT9.2 (merged) | new | **yes** |
| 3 | AI-E1.10 | Corpus telemetry, gold evidence, in-memory event store | T2 | 8 | AI-E1.8 (merged) | new | **yes** |
| 4 | AI-E3.1a | Skill format v1, catalogue, router, views, two skills | T2 | 5 | 1, 2 | re-scoped (#199) | after 1, 2 |
| 5 | AI-E3.2 | Fact ledger, `evidence_facts` table, quarantine boundary | T3 | 5 | 1, 2 | re-scoped (#201, was 8) | after 1, 2 |
| 6 | AI-E4.2 | Prevalence: command templates, rule first-seen | T2 | 5 | 2, founder step 3 recipe | re-scoped | after 2 |
| 7 | INT3.4 | Wazuh evidence tools: host activity, logon fan-out, process lineage, prevalence | T3 | 8 | 1, 2, 3 | re-scoped (#200, was T2) | after 1-3 |
| 8 | AI-E3.4 | Checker: citations, proof, indicators, never-close | T3 | 5 | 2, 4 | re-scoped (#207, was T2) | after 4 |
| 9 | AI-E3.3 | Skill investigator: executor, planner, budgets, settle | T2 | 8 | 4, 5, 7, 8 | re-scoped (#205, was 5) | after 4-8 |
| 10 | AI-E4.1 | Context pack (absorbs #320) | T3 | 8 | 1, 2 | re-scoped | after 1, 2 |
| 11 | AI-E3.8b | Per-skill scorecards, eval gate, `skill_compat.py` | T2 | 5 | 3, 9 | new | after 9 |
| 12 | AI-E3.6 | Per-tenant flag; skills as a shadow candidate | T2 | 3 | 9, AI-E1.5b | re-scoped (#209) | after 9 |
| 13 | AI-E3.8a | Decision policy v2, autonomy tiers, INV-03 amended | T3 | 8 | 8, 9, 11 | new | after 11 |
| 14 | AI-E3.10 | Promotion evidence, four-eyes promotion, demotion on miss | T3 | 5 | 13, PRD-8.3 | new | after 13 |
| 15 | AI-E4.3 | Case memory (structured, analyst-confirmed only) | T3 | 8 | 2, 5, 6 | re-scoped | after 5, 6 |
| 16 | AI-E3.9 | Guidance notes | T3 | 8 | 5, 10, 13 | new | after 13 |
| 17 | AI-E3.11 | Recall canaries | T2 | 5 | 3, 12, 13 | new | after 13 |
| 18 | AI-E3.7 | Skill-learning loop | T2 | 8 | 11, 14, 16 | new | after 16 |
| 19 | AI-E3.1b | Skills: SSH authentication, scheduled tasks | T2 | 3 | 11 | re-scoped (#220) | after 11 |
| 20 | AI-E3.1c | Skills: account lifecycle, scanner look-alikes | T2 | 3 | 19 | re-scoped (#228) | after 19 |
| 21 | INT3.4b | Wazuh file-integrity and network templates | T2 | 5 | 7 | new | after 7 |

**121 points**, 9 T3 stories (60 points). At the plan's 12 T3 points per wave, the T3 stories are the
critical path: roughly two per wave, about 8 waves end to end with the T2 work in parallel. Suggested
grouping (each group needs the previous ones; within a group the stories run in parallel):
A {1, 2, 3}, B {4, 5, 6}, C {7, 8}, D {9, 10}, E {11, 12}, F {13}, G {14, 15}, H {16, 17}, I {18, 19, 20, 21}.

Nothing closes on a skill before story 14 merges *and* a tenant's skill has earned a closing tier on
real traffic. The first such promotion is the calendar milestone M9 (2027-04-23, "Investigator promoted
for a partner tenant"): a design partner's alerts in shadow for at least 4 weeks.

## Ready now

### 1. AI-E2.1: Tool protocol and registry (T3, 5 points, #193)

**Goal.** One registry through which every investigation tool runs, so that query safety, tenant
enablement, tracing and replay are enforced in one place before any new tool exists.

**Scope.**
* `src/lg_sotf/tools/registry.py`: `ToolSpec` (`name`, `version`, `risk` in `read_internal` or
  `read_external` with no write class, `params` a strict Pydantic model, `produces` fact kinds,
  `row_cap`, `time_cap_s`, `window_cap`, `egress` in `tenant_source`, `third_party` or `platform`,
  `shadow` in `live` or `cache_only`, `tenant_setting`) and `ToolRegistry` (`register`, `get`, `call`).
  `call` validates parameters before anything else, refuses a tool the tenant disabled, enforces the
  time cap and runs through `ctx.trace.tool(...)` so the trace store and cassettes see every call.
* Wrap today's lookups as registered tools: `reputation.virustotal`, `reputation.abuseipdb`
  (`lg_sotf.tools.enrichment.providers`) and `platform.history` (`lg_sotf.tools.enrichment.history`).
  `ReActReasoner._observe` and `AnalysisAgent.history` call them through the registry.
* Register INV-14 ("Evidence tools are read-only, templated and capped") as `pending` in
  `lg_sotf.invariants.registry`; regenerate `docs/invariants.md`.

**Acceptance.** (backlog: "TI providers run through the registry; a tool missing caps or schema fails to
load")
* `tests/unit/tools/test_registry.py::test_a_tool_missing_caps_or_schema_fails_to_load`
* `tests/unit/tools/test_registry.py::test_parameters_are_validated_before_the_call`
* `tests/unit/tools/test_registry.py::test_a_tool_disabled_for_the_tenant_is_not_called`
* `tests/unit/tools/test_registry.py::test_no_tool_can_register_a_write_risk_class`
* `tests/unit/agents/test_analysis.py::test_ti_lookups_run_through_the_registry`
* The committed cassettes replay unchanged (the existing eval cassette tests stay green: the tool names
  and request shapes recorded in `tests/fixtures/eval/cassettes` must not change, or the story re-records
  them and says why).

**Out of scope.** Any new tool; the Wazuh client (INT3.4).
**Threat note to write.** Parameter validation before the call, no write class, tenant enablement, the
egress kinds; ties to TM-EVT-3 and TM-EVT-10.
**Branch.** `feat/ai-e2-1-tool-registry`.

### 2. INT9.3: Evidence-fact schema 1.1 (T2, 3 points, new)

**Goal.** The fact kinds the skills cite, as a minor version of the published schema.

**Scope.** In `src/lg_sotf/models/evidence_fact.py` (ADR section 3.3): `SCHEMA_VERSION = "1.1.0"`;
optional `complete` on every fact; subject types `command_template` and `pattern`; optional
`command_template`, `image_name`, `process_guid` on `ProcessNode`, optional `children` on
`ProcessLineageValue`, optional `status` on `RelatedAlertValue`; new kinds `host_activity`,
`logon_fanout`, `prevalence`, `entity_context`, `guidance_match`, `pattern_history`, `similar_case`.
Regenerate `schemas/evidence-fact/v1.json` (`python scripts/export_schemas.py`), add one example per new
kind under `schemas/evidence-fact/examples/`, update `docs/evidence-facts.md` (kinds table, the meaning
of `complete`: absence claims cannot rest on an incomplete fact). Changelog fragment
`changelog.d/INT9.3.md` (`### Added`).

**Acceptance.**
* `python scripts/ci/schema_compat.py --base origin/main` accepts the change as a minor bump (the
  `schemas` CI job).
* `tests/unit/models/test_evidence_fact.py::test_every_kind_has_a_valid_example`
  (extend the existing example test to the new kinds)
* `tests/unit/models/test_evidence_fact.py::test_a_1_0_fact_still_validates`
* `tests/unit/models/test_evidence_fact.py::test_incomplete_flag_round_trips`
* `tests/unit/models/test_evidence_fact.py::test_list_fields_are_capped_at_50`

**Out of scope.** Producing facts (INT3.4, AI-E4.x).
**Branch.** `feat/int9-3-evidence-facts-1-1`.

### 3. AI-E1.10: Corpus telemetry, gold evidence and an in-memory event store (T2, 8 points, new)

**Goal.** The surrounding telemetry and the expected evidence the skills read, so every later story can
be tested offline and deterministically.

**Scope.**
* `tests/fixtures/attack_corpus`: emit, per scenario, the non-alert context events (seeded, on the same
  timeline) to `tests/fixtures/eval/corpus_v1_events.jsonl.gz`, in the Wazuh `alerts.json` document
  shape. At least: the 4624 type 3 logon on the target before every 7045 and every PsExec child
  (from the admin workstation for `lookalike:it-admin`, from `MKT-WS-11` and `ENG-WS-19` for
  `campaign:lateral-ransomware`); the success after each `noise:logon-typo` failure; the retry cadence
  of `lookalike:stale-credentials` over hours; the fleet installs of the vendor updaters for
  `lookalike:windows-patching`; the Sysmon EID 1 children of `PSEXESVC`.
* **`corpus_v1.jsonl.gz` stays byte for byte** (the v2 scorecard pins its hash): events and gold
  evidence are separate files.
* `tests/fixtures/eval/corpus_v1_gold.json`: per item of the two skill families, the expected benign
  hypothesis id or the expected malicious indicator ids (ADR section 1.4 and 1.5).
* A new dataset `tests/fixtures/eval/corpus_skills_v1.jsonl.gz` with at least 50 attack variants per
  skill family, including **context-abuse** items: a spray from a declared admin workstation's address,
  PsExec by a declared admin account followed by discovery, activity outside a maintenance window, a
  declared service account used interactively. Its `_meta.tenant_settings` declares the context.
* `lg_sotf.eval.tool_fixtures.EventStore`: an in-memory store over the events with the query semantics
  the templates need (filter by agent, time range, event id and field equality; counts, distinct
  counts, min and max time; an as-of time so nothing after `occurred_at + settle` is visible). INT3.4
  adapts its templates to it.

**Acceptance.**
* `tests/unit/eval/test_attack_corpus.py::test_the_seeded_generator_reproduces_the_committed_file_byte_for_byte`
  stays green (corpus_v1 unchanged), and a new
  `tests/unit/eval/test_corpus_telemetry.py::test_the_events_file_is_reproduced_byte_for_byte`
* `tests/unit/eval/test_corpus_telemetry.py::test_every_skill_item_has_its_context_events`
* `tests/unit/eval/test_corpus_telemetry.py::test_the_event_store_never_returns_events_after_the_as_of_time`
* `tests/unit/eval/test_corpus_telemetry.py::test_gold_evidence_names_known_hypotheses_and_indicators`
* `tests/unit/eval/test_corpus_telemetry.py::test_corpus_skills_v1_has_50_attacks_per_family_with_context_abuse`
* The context events do not give the label away (extend
  `test_the_telemetry_does_not_give_the_label_away` to the events file).

**Out of scope.** The Wazuh templates and their fixture adapter (INT3.4); scorecards (AI-E3.8b).
**Branch.** `feat/ai-e1-10-corpus-telemetry`.

## The other stories

### 4. AI-E3.1a: Skill format v1, catalogue, router, views and the two skills (T2, 5)

Re-scoped from "hypothesis schema plus recipes for 2 Wazuh classes (endpoint malware, identity/auth)":
the two skills are identity (`windows.logon_failure`) and endpoint (`windows.service_install`).

* `src/lg_sotf/models/skill.py` (`SkillSpec`, predicate and binding models, `SkillVerdict`, `Claim`),
  exported to `schemas/investigation-skill/v1.json`.
* `src/lg_sotf/domain/skills.py`: `select_skill`, three-valued `evaluate`, `contract_hash`.
* `src/lg_sotf/domain/skill_views.py`: `windows_logon`, `windows_service`.
* `src/lg_sotf/agents/investigation/catalog.py` and the two YAML files of ADR sections 1.4 and 1.5.
* A `detection` block on the canonical alert (`vendor_rule_id`, `rule_groups`, `event_id`, `decoder`,
  `log_family`) filled by `WazuhNormalizer`; regenerate the OpenAPI snapshot if the alert schema is
  exported **(uncertain)**.
* Confirm the Wazuh 4.14.8 rule ids for 4771, 4776 and 4697 **(uncertain)**.

Acceptance:
* `tests/unit/agents/investigation/test_catalog.py::test_the_shipped_skills_load`
* `tests/unit/agents/investigation/test_catalog.py::test_a_predicate_on_an_unknown_fact_field_is_refused`
* `tests/unit/agents/investigation/test_catalog.py::test_a_skill_without_host_activity_is_refused`
* `tests/unit/agents/investigation/test_catalog.py::test_a_proof_without_a_telemetry_predicate_is_refused`
* `tests/unit/agents/investigation/test_catalog.py::test_no_two_skills_overlap_at_equal_specificity`
* `tests/unit/domain/test_skills.py::test_unknown_is_false_in_a_proof_and_true_in_an_indicator`
* `tests/unit/domain/test_skills.py::test_the_router_reads_only_detector_fields` (changing title,
  description or entity names never changes the match)
* `tests/unit/domain/test_skills.py::test_every_corpus_item_of_the_two_families_routes_to_its_skill`
  (34 logon and 18 service items; no other item matches)

### 5. AI-E3.2: Fact ledger, `evidence_facts` table and the quarantine boundary (T3, 5)

Re-scoped: Wazuh results become facts through deterministic mappers (INT3.4), so the LLM reader is
needed only for unstructured outputs (mail bodies, MCP-in later). Re-estimated from 8 to 5.

* `src/lg_sotf/agents/investigation/ledger.py`: the executor mints fact ids `<evidence id>:<n>` and links
  each fact to its trace step and hashes; facts are rendered to the planner only through
  `lg_sotf.llm.prompting` (untrusted block).
* Migration (next free number, `0016` today) `evidence_facts` under forced RLS;
  `src/lg_sotf/db/repos/evidence_facts.py`; the evidence pack lists the facts.
* `QuarantinedReader` interface: facts it produces carry `source.name` `reader.<tool>` and the catalogue
  refuses them in proofs.

Acceptance (backlog: "Injection payloads in tool output never reach the planner", made precise):
* `tests/unit/agents/investigation/test_ledger.py::test_only_the_executor_mints_fact_ids`
* `tests/unit/agents/investigation/test_ledger.py::test_raw_tool_output_never_reaches_the_planner_prompt`
* `tests/unit/agents/investigation/test_ledger.py::test_reader_facts_never_satisfy_a_proof`
* `tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy` covers
  `evidence_facts`
* `tests/integration/compliance/test_evidence_pack.py::test_the_pack_lists_the_cited_facts`
  **(uncertain: file name of the existing evidence-pack test)**

### 6. AI-E4.2: Prevalence: command templates and rule first-seen (T2, 5)

* `src/lg_sotf/domain/patterns.py`: `command_template(cmd)` and `pattern_key(alert)`, shared with the
  verdict-cache fix and pattern memory (adopt their recipe if they merge first **(uncertain)**).
* `indicator_sightings` gains a `command_template` type; `platform.prevalence:1` (scope
  `tenant_alerts`) and `platform.rule_history:1` tools; `platform.pattern_history:1` reads the step-3
  ledger.

Acceptance (backlog: "Prevalence per indicator per tenant available to tools with 30-day window"):
* `tests/unit/domain/test_patterns.py::test_command_template_normalises_numbers_guids_and_user_paths`
* `tests/unit/tools/test_platform_tools.py::test_command_template_prevalence_over_30_days`
* `tests/unit/tools/test_platform_tools.py::test_an_unknown_rule_history_counts_as_first_seen`
* `tests/unit/tools/test_platform_tools.py::test_pattern_history_counts_only_analyst_decisions`

### 7. INT3.4: Wazuh evidence tools (T3, 8, #200)

Re-scoped to `wazuh.host_activity:1`, `wazuh.logon_fanout:1`, `wazuh.process_lineage:1`,
`wazuh.prevalence:1` (ADR section 3); raised to T3 because it is the tool boundary into the customer's
SIEM.

* `src/lg_sotf/tools/wazuh/` `templates.py`, `client.py` (`POST /<index>/_search` only, through
  `lg_sotf.net`), `mappers.py` (facts, `complete` computed), `scope.py` (mandatory tenant scope).
* Tenant setting `tools.wazuh_indexer` (validation, encrypted password, admin-only, refused under an
  MSSP grant, a shared source needs a scope).
* The eval adapter from the templates' parameter models to AI-E1.10's `EventStore`.
* A lab note on coverage (alerts versus archives, retention) in `docs/integrations.md` or a new page.

Acceptance (backlog: "Five templated Wazuh tools return typed facts in shadow on the lab", now four):
* `tests/unit/tools/wazuh/test_templates.py::test_templates_emit_only_allow_listed_dsl`
  (property-based over generated parameters)
* `tests/unit/tools/wazuh/test_templates.py::test_values_only_reach_term_terms_range`
* `tests/unit/tools/wazuh/test_templates.py::test_every_query_carries_the_tenant_scope`
* `tests/unit/tools/wazuh/test_mappers.py::test_incomplete_results_are_marked` (timeout, failed shards,
  row cap, `sum_other_doc_count`, window not closed)
* `tests/integration/wazuh/test_evidence_tools_live.py::test_templates_return_the_fixture_facts`
  (AI-E1.10 events loaded into the Wazuh 4.14 container give the same facts as the `EventStore`)
* `tests/unit/architecture/test_shadow_egress.py` stays green with the new boundary registered
* `tests/integration/api/test_tenant_settings.py::test_wazuh_indexer_settings_need_admin_and_no_grant`

### 8. AI-E3.4: Checker (T3, 5, #207)

Raised to T3: it gates every skill close. `src/lg_sotf/domain/citations.py` (ADR section 5).

Acceptance (backlog: "A narrative with an uncited claim is escalated in test; citation faithfulness
metric reported"):
* `tests/unit/domain/test_citations.py::test_an_uncited_claim_fails`
* `tests/unit/domain/test_citations.py::test_a_fact_from_another_run_fails`
* `tests/unit/domain/test_citations.py::test_a_proof_reading_uncited_facts_fails`
* `tests/unit/domain/test_citations.py::test_an_unknown_indicator_fails_closed`
* `tests/unit/domain/test_citations.py::test_incomplete_required_evidence_fails`
* `tests/unit/domain/test_citations.py::test_the_gold_hypotheses_of_the_corpus_pass`
* `tests/unit/eval/test_metrics.py::test_citation_faithfulness_is_reported`

### 9. AI-E3.3: Skill investigator: executor, planner, budgets, settle (T2, 8, #205)

* `src/lg_sotf/agents/investigation/executor.py` (`SkillInvestigator`), `planner.py` (one registered
  prompt per skill version, closed action space), the `AnalysisAgent._reason` branch,
  `AnalysisDigest.investigation`, budgets with the cost per investigation (AI-E5.3's metric).
* Settling: a deferred run resumed by the scheduler **(uncertain: interrupt plus scheduled resume, or a
  delayed re-enqueue; decide with ARCH-E1.1's graph versioning)**.
* `route_after_correlation` sends every alert with a skill match to analysis.

Acceptance (backlog: "Investigation stops at each budget limit and escalates; median cost logged"):
* `tests/unit/agents/investigation/test_executor.py::test_each_budget_limit_stops_and_escalates`
  (parametrized: optional queries, LLM calls, tokens, money, wall clock)
* `tests/unit/agents/investigation/test_executor.py::test_the_planner_can_only_choose_optional_evidence_ids`
* `tests/unit/agents/investigation/test_executor.py::test_a_run_waits_for_the_settle_time`
* `tests/unit/agents/investigation/test_executor.py::test_without_a_skill_the_react_path_is_unchanged`
* `tests/unit/domain/test_routing.py::test_a_skill_alert_always_reaches_analysis`
* the eval report shows the median cost per investigation

### 10. AI-E4.1: Context pack (T3, 8; absorbs issue #320)

Raised to T3: declarations change what can close. ADR section 4.1. Migrates `triage.known_scanners`
into the store (the AI-E1.9 path reads the same data if it has merged).

Acceptance (backlog: "Entity context appears in investigations for a lab tenant; RLS-scoped", plus
#320's):
* `tests/unit/tools/test_context_tool.py::test_entity_context_facts_carry_author_and_expiry`
* `tests/integration/api/test_context_pack.py::test_declarations_need_admin_and_are_refused_under_a_grant`
* `tests/integration/api/test_context_pack.py::test_every_declaration_is_audited_and_expires`
* `tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy` covers the
  new tables
* `tests/unit/tools/test_context_tool.py::test_automation_accounts_match_as_source_actor_only`

### 11. AI-E3.8b: Per-skill scorecards, eval gate and `skill_compat.py` (T2, 5, new)

ADR sections 1.6 and 8.2.

* `lg-sotf eval` metrics per skill; `tests/fixtures/eval/skills/<skill>_thresholds.yaml` read by
  `lg_sotf.eval.gate`; an adversarial `wazuh-field-injection` family; `lg-sotf skill-diff` and
  `scripts/ci/skill_compat.py`; the first per-skill scorecards under `docs/scorecards/skills/`.

Acceptance:
* `tests/unit/eval/test_skill_scorecard.py::test_metrics_are_reported_per_skill`
* `tests/integration/eval/test_skill_gate.py::test_a_malicious_would_close_fails_the_gate`
  (a deliberate regression)
* `tests/integration/eval/test_skill_gate.py::test_context_abuse_items_never_close`
* `tests/unit/agents/investigation/test_skill_compat.py::test_a_widening_change_needs_the_widening_class`
* `tests/unit/agents/investigation/test_skill_compat.py::test_an_unclassifiable_change_is_widening`

### 12. AI-E3.6: Per-tenant flag; skills as a shadow candidate (T2, 3, #209)

Acceptance (backlog: "Subgraph runs only for flagged tenants; promotion requires a passing shadow
scorecard"):
* `tests/unit/agents/test_analysis.py::test_skills_run_only_for_flagged_tenants`
* `tests/integration/engine/test_shadow.py::test_a_skill_candidate_runs_in_shadow_with_no_side_effects`
* `tests/unit/domain/test_shadow_agreement.py::test_the_report_breaks_down_by_skill`

### 13. AI-E3.8a: Decision policy v2, autonomy tiers and INV-03 amended (T3, 8, new)

ADR section 6. `src/lg_sotf/domain/closure.py`, `routing.decide` delegating to it,
`src/lg_sotf/domain/autonomy.py` (tiers, ceilings), migration `skill_autonomy` (forced RLS),
`src/lg_sotf/services/autonomy.py` (tier resolution only), the shadow tier's hiding (reusing
`lg_sotf.domain.blind_audit.hidden_alert_view`), the recommend tier's seeded holdout, the INV-03 text and
proofs, INV-13 and INV-14 pending, `docs/invariants.md` and `docs/ai-system-card.md` updated. Every
tier starts at `shadow`.

Acceptance:
* the INV-03 proofs of ADR section 6.2 (`tests/unit/domain/test_closure.py::...`,
  `tests/integration/e2e/test_llm_safety.py::test_injected_tool_output_never_closes_through_a_skill`)
* `tests/unit/domain/test_closure.py::test_the_grey_zone_and_the_rule_score_do_not_gate_a_skill_close`
* `tests/unit/domain/test_closure.py::test_ceilings_only_lower`
* `tests/unit/domain/test_closure.py::test_a_first_seen_rule_never_closes`
* `tests/integration/runtime/test_verify_invariants.py::test_routing_policy_probes_skill_closes`
* `tests/deploy/test_invariants.py` stays green with the amended entry

### 14. AI-E3.10: Promotion evidence, four-eyes promotion, demotion on miss (T3, 5, new)

ADR section 6.3. Counters from skill-blind and AI-blind labels only; per-skill strata in the blind audit
(100% at `auto_full_audit`); promotion proposals approved through PRD-8.3; demotion hooks in
`BlindAuditService.label`, the escalation decision path and the incident reopen. INV-13 becomes
enforced.

Acceptance:
* `tests/invariants/test_skill_autonomy.py::test_any_miss_demotes_to_shadow` (from a blind-audit label,
  an escalation decision and a reopened incident)
* `tests/invariants/test_skill_autonomy.py::test_only_blind_labels_count`
* `tests/invariants/test_skill_autonomy.py::test_promotion_needs_300_with_zero_misses_and_two_people`
* `tests/invariants/test_skill_autonomy.py::test_self_approval_is_refused`
* `tests/unit/domain/test_blind_audit.py::test_auto_full_audit_draws_every_skill_closure`

### 15. AI-E4.3: Case memory (T3, 8)

ADR section 4.3; structured features, no pgvector in v1 **(uncertain)**; admission only on a person's
decision.

Acceptance (backlog: "Retrieval returns only analyst-decided cases from the same tenant"):
* `tests/integration/tools/test_case_memory.py::test_only_analyst_decided_cases_are_admitted`
* `tests/integration/tools/test_case_memory.py::test_retrieval_never_crosses_tenants`
* `tests/integration/tools/test_case_memory.py::test_skill_closures_never_enter_memory`
* `tests/unit/agents/investigation/test_catalog.py::test_a_proof_on_memory_alone_is_refused`

### 16. AI-E3.9: Guidance notes (T3, 8, new)

ADR section 4.2: structured predicate plus text, lifecycle, fact replay, second-person approval,
mandatory expiry.

Acceptance:
* `tests/unit/services/test_guidance.py::test_the_lifecycle_from_draft_to_expired`
* `tests/unit/services/test_guidance.py::test_the_author_cannot_approve`
* `tests/unit/services/test_guidance.py::test_a_note_that_closes_a_labelled_attack_is_rejected_on_replay`
* `tests/unit/services/test_guidance.py::test_a_bare_wildcard_scope_is_refused`
* `tests/unit/services/test_guidance.py::test_notes_never_apply_to_high_critical_or_never_close_classes`
* `tests/unit/agents/investigation/test_executor.py::test_note_text_never_satisfies_a_proof`

### 17. AI-E3.11: Recall canaries (T2, 5, new)

ADR section 8.2. Weekly, per enabled skill and tenant, the skill's attack and context-abuse items
re-addressed to the tenant's names and run through `ShadowRunner` with their recorded facts.

Acceptance:
* `tests/integration/engine/test_canaries.py::test_a_canary_the_skill_would_close_is_a_miss_and_demotes`
* `tests/integration/engine/test_canaries.py::test_canaries_cause_no_side_effects`
* `tests/integration/engine/test_canaries.py::test_canaries_never_reach_a_queue_or_the_blind_audit`

### 18. AI-E3.7: Skill-learning loop (T2, 8, new)

ADR section 7.

Acceptance:
* `tests/unit/services/test_skill_learning.py::test_clusters_below_five_cases_are_not_drafted`
* `tests/unit/services/test_skill_learning.py::test_drafts_land_in_draft_never_active`
* `tests/unit/services/test_skill_learning.py::test_a_skill_diff_carries_its_replay_and_class`
* `tests/unit/services/test_skill_learning.py::test_no_alert_content_leaves_the_install`

### 19-20. AI-E3.1b and AI-E3.1c: More skills (T2, 3 each, #220, #228)

Re-scoped from "recipes for phishing, lateral movement, cloud, exfiltration". Phishing keeps its own
pipeline (`lg_sotf.domain.phishing`). Proposed order by `corpus_v1` benign volume **(uncertain: confirm
with the design partner's traffic)**: b = `linux.ssh_auth` (rules 5710, 5712, 5715, 5760: 51 benign in
the corpus) and `windows.scheduled_task`; c = `windows.account_lifecycle` (4720, 4728, 4732) and
scanner look-alikes on web and sshd rules.

Acceptance, per skill: `tests/integration/eval/test_skill_gate.py` with the skill's thresholds file
green, malicious would-close 0 including its context-abuse items, and the skill's scorecard committed.

### 21. INT3.4b: Wazuh file-integrity and network templates (T2, 5, new)

The rest of INT3.4's title: `wazuh.fim_changes:1` (syscheck) and `wazuh.network_connections:1`
(Sysmon EID 3), with the same safety tests as INT3.4.

## Stories this design feeds or depends on, unchanged

* **PRD-2.1** (narrative with citation chips): renders the skill claims; depends on AI-E3.4.
* **AI-E3.5** (#248, corroboration weights for tool-observed facts): a skill's malicious indicators
  (spray fan-out, defence evasion nearby) become response corroboration; the model's reading never does.
* **PRD-13.4** (#236, graduation criteria): its criteria are ADR section 6.3's promotion table.
* **INT3.5** (agent inventory): feeds the context pack's assets and the address-to-host mapping.
* **AI-E4.4** (calibrator) and **AI-E4.5** (feedback on reasoning steps): later; the loop uses
  AI-E4.5's feedback when it exists.
