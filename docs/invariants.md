# Safety invariants

<!-- Generated from src/lg_sotf/invariants/registry.py by scripts/export_invariants.py; do not edit. -->

These are the rules LG-SOTF holds for every alert, tenant and release. Each one names the tests that
prove it; CI fails when a named test is missing or an enforced invariant's test is skipped
(`tests/deploy/test_invariants.py`). Run `lg-sotf verify-invariants` on your own install to check
the ones that depend on its database and settings (see [security.md](security.md#11-safety-invariants)).
Threat rows refer to [threat-model.md](threat-model.md).

| ID | Invariant | Status | Runtime check | Threats |
|---|---|---|---|---|
| INV-01 | Every tenant table has forced row-level security, and the runtime role cannot bypass it | enforced | `rls_catalog`, `runtime_role`, `rls_probe` | TM-DB-1, TM-DB-2, TM-SCH-1, TM-API-3 |
| INV-02 | No response action runs without an approval or an autonomy rule that allows it; the kill switch wins | enforced | `kill_switch` | TM-WRK-3, TM-RSP-4, TM-RSP-5, TM-MCP-6 |
| INV-03 | An AI verdict alone never closes a critical alert or a never-close class; an alert closes on the models' word only at the tenant's autonomy tier, and a confirmed related threat reopens it | enforced | `routing_policy` | TM-WRK-1, TM-WRK-2, TM-WRK-10 |
| INV-04 | Every LLM call records its prompt hash and model id | enforced | none | TM-WRK-8 |
| INV-05 | Every LLM and tool step of a run is in the trace store | enforced | none | TM-WRK-8, TM-EVT-6 |
| INV-06 | The audit log is append-only for the runtime role | enforced | `audit_append_only` | TM-DB-3, TM-API-9, TM-SCH-2 |
| INV-07 | No secret is ever logged; redaction covers the known credential patterns | enforced | `log_redaction` | TM-API-6, TM-ING-3, TM-WRK-4 |
| INV-08 | Evidence packs are hash-verified | enforced | `evidence_seal` | TM-EVT-6, TM-API-9 |
| INV-09 | Shadow mode causes no side effects | enforced | none | TM-RSP-4, TM-MCP-6 |
| INV-10 | Release images are signed, and their signature is checked before deploy | enforced | none | TM-CI-1 |
| INV-11 | No automatic containment on model-only evidence | enforced | none | TM-WRK-3, TM-EVT-7 |
| INV-12 | The model never chooses where data is sent | enforced | none | TM-EVT-1, TM-WRK-5 |
| INV-13 | Autonomy is earned per skill and tenant and lost on any miss | pending (AI-E3.10) | none | TM-WRK-13 |
| INV-14 | Evidence tools are read-only, templated and capped | enforced | none | TM-EVT-3, TM-EVT-9, TM-EVT-10, TM-EVT-12 |

## INV-01: Every tenant table has forced row-level security, and the runtime role cannot bypass it

One customer's alerts, users and audit trail must never be readable or writable from another customer's session, even through a bug in a query. PostgreSQL enforces it below the application: every tenant-owned table (partitions and checkpoint tables included) is under FORCE ROW LEVEL SECURITY with a tenant policy, and the API and worker role is neither a superuser, nor BYPASSRLS, nor a member of the schema owner, so setting app.bypass_rls changes nothing for it.

* **Status:** enforced
* **Owner epic:** ARCH-E4
* **Threats:** TM-DB-1, TM-DB-2, TM-SCH-1, TM-API-3
* **Enforced in:** `src/lg_sotf/db/migrations/versions/0001_initial.py`, `src/lg_sotf/db/partitions.py`, `src/lg_sotf/db/checkpointer.py`, `src/lg_sotf/db/migrate.py`
* **Runtime checks:** `rls_catalog`, `runtime_role`, `rls_probe`
* **Proved by:**
  * `tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy`
  * `tests/integration/db/test_rls.py::test_unfiltered_queries_only_see_own_tenant`
  * `tests/integration/db/test_rls.py::test_cannot_insert_rows_for_another_tenant`
  * `tests/integration/db/test_rls.py::test_checkpoint_tables_are_tenant_isolated`
  * `tests/integration/db/test_runtime_role.py::test_setting_the_bypass_guc_does_not_bypass_isolation`
  * `tests/integration/db/test_runtime_role.py::test_runtime_role_cannot_weaken_the_schema`
  * `tests/integration/runtime/test_verify_invariants.py::test_a_table_without_forced_rls_fails_the_check`

## INV-02: No response action runs without an approval or an autonomy rule that allows it; the kill switch wins

Containment changes a customer's environment. An action executes only once it is approved by a person or by the tenant's 'auto' autonomy for its risk level (an unknown autonomy value reads as 'disabled'). The install-wide response.dry_run switch, or a tenant's dry_run, routes every action to the dry-run connector whatever else is configured.

* **Status:** enforced
* **Owner epic:** AI-E6
* **Threats:** TM-WRK-3, TM-RSP-4, TM-RSP-5, TM-MCP-6
* **Enforced in:** `src/lg_sotf/services/response/planner.py`, `src/lg_sotf/services/response/policy.py`, `src/lg_sotf/services/response/execution.py`, `src/lg_sotf/services/connectors/registry.py`
* **Runtime checks:** `kill_switch`
* **Proved by:**
  * `tests/invariants/test_response_approval.py::test_actions_awaiting_approval_are_never_executed`
  * `tests/invariants/test_response_approval.py::test_a_dry_run_tenant_rehearses_even_auto_approved_actions`
  * `tests/unit/services/test_response.py::test_autonomy_resolution`
  * `tests/unit/services/test_response.py::test_disabled_autonomy_blocks`
  * `tests/unit/services/test_response.py::test_dry_run_forced_globally_and_per_tenant`
  * `tests/unit/services/test_response.py::test_malformed_tenant_dry_run_flag_fails_safe`
  * `tests/unit/services/test_routing.py::test_kill_switches_win_everywhere`

## INV-03: An AI verdict alone never closes a critical alert or a never-close class; an alert closes on the models' word only at the tenant's autonomy tier, and a confirmed related threat reopens it

A fooled or injected model must not be able to make a dangerous alert disappear. Routing is a pure policy. A critical alert closes only by an analyst or a suppression rule. A low or medium alert closes when approved benign evidence an attacker cannot write corroborates a benign verdict: a cached analyst verdict, the detection rule's name, the EICAR hash, a test source or the tenant's declared context, such as a scanner as the source of the activity; never past steering text or a recent true positive, and a scanner or test source never for a never-close class. Without such evidence an info to high alert closes on the models' word only when the tenant's autonomy tier is auto_full_audit, the deep tier judges it benign and the fast tier does not call it a threat (decision policy v3), never for the never-close classes (credential access, including the vendor's authentication-failure rules and T1531, a Wazuh alert whose rule cannot be read, log clearing, security-tool tampering, ransomware behaviour, persistence through attacker-named objects), steering text, entities with a recent true positive, an alert normalised by a model or one reopened; such a close is marked model_closed for audit. Nor while a related threat of hold grade is there. Two alerts relate when they share a host or a user by relation key (short host name, bare account name; never an IP address alone, never an account every host has). Hold grade is one predicate, forward and backward: the alert is high or critical and a model judged it a threat (deep verdict malicious, or fast tier likely_threat or confirmed_threat, never a merely suspicious one), or a person confirmed it (an analyst true positive, a blind-audit malicious label); a response that only waits for an approval is still the model's word and is not hold grade. When the decision is made the workflow reads what the database holds about the tenant's other alerts, never a model's text: a related alert of hold grade that is open (up to seven days from its ingestion) or that closed in the last 24 hours with a person's confirmation, or a high or critical one on the same host that is being processed, holds the close back and the alert goes to an analyst; so does a check that did not complete (a failed read, more open threats than one decision compares), without failing the run. A low or medium threat only a model stands behind holds nothing: the alert closes and is linked to that threat's case at once. When evidence lookups ran for the alert (the investigation executor), their facts can hold such a close and never buy one: a malicious indicator the reviewed skill declares that is true over the facts (never from the alert's own event, which the host lookup leaves out; an indicator the lookups could not settle does not hold), a benign verdict whose claims cite an observation the ledger did not record or an altered one (forgery or corruption), and steering text in any fact (the alert text's own scan; the model is shown a marker, and approved benign evidence does not close past it either) each send the alert to a person, and the decision names what held it. The harness holds nothing else: a benign claim that rests on a lookup that found nothing, failed or was incomplete is recorded, the close is made on the models' word as without a harness, and the record never calls it evidence-backed. When an alert becomes a threat after the close, the safety net looks at every model-closed alert of the previous 24 hours that relates to it. Below hold grade a model's judgement is not a confirmation: such a threat (a low or medium escalation a model judged a threat; a response the workflow only proposes, or only simulates in dry-run mode) links those alerts to its open case as related alerts, audited, and they stay closed and marked for audit; no decision on the case settles them, so a benign one never makes them analyst-confirmed benign, and the compliance evidence shows no human decision for them. A threat of hold grade, or a confirmed threat (an analyst true positive, an analyst's own approval of a response action, a blind-audit malicious label, or a response action that really ran, succeeded, when the workflow carried it out alone under the tenant's autonomy policy: once the platform has acted, the related alerts do not stay closed) reopens them, with every alert linked to the threat or into its case earlier, however long ago it closed: folded into its open case as a related alert, or queued for review without one, and audited. With the tier off, the default, a model never closes an alert alone. A cached analyst verdict closes only a non-critical repeat of the same detection and behaviour (verdict key: what ran, compared in full) that two different analysts decided benign, with no threat on it since; alerts in a never-close class, normalised by a model or without a process, command line, service, scheduled task, registry key, target file or Sysmon WMI object get no key (a URL, user agent, O365 operation or other request-set context is in the key but never enough for one). A suggested suppression rule matches the verdict key, older fingerprint-only suggestions never apply, and a confirmed threat disables the rules that match it.

* **Status:** enforced
* **Owner epic:** AI-E6
* **Threats:** TM-WRK-1, TM-WRK-2, TM-WRK-10
* **Enforced in:** `src/lg_sotf/domain/routing.py`, `src/lg_sotf/domain/closure.py`, `src/lg_sotf/domain/benign_evidence.py`, `src/lg_sotf/domain/noise_families.py`, `src/lg_sotf/domain/verdict_key.py`, `src/lg_sotf/core/verdict_cache.py`, `src/lg_sotf/core/benign_learning.py`, `src/lg_sotf/core/retro_reopen.py`, `src/lg_sotf/agents/investigation/claims.py`, `src/lg_sotf/agents/investigation/executor.py`
* **Runtime checks:** `routing_policy`
* **Evaluation metric:** `high_severity_auto_closed_benign`
* **Proved by:**
  * `tests/unit/domain/test_routing.py::test_llm_only_evidence_never_closes_high_or_critical_at_triage`
  * `tests/unit/domain/test_routing.py::test_decide_never_closes_high_severity`
  * `tests/unit/domain/test_routing.py::test_decide_closes_only_with_approved_benign_evidence`
  * `tests/unit/domain/test_routing.py::test_attacker_controlled_fp_words_never_close_high_severity`
  * `tests/unit/domain/test_closure.py::test_with_the_tier_off_a_model_never_closes_alone`
  * `tests/unit/domain/test_closure.py::test_critical_never_closes_at_any_tier_and_high_only_on_the_models_word_at_the_tier`
  * `tests/unit/domain/test_closure.py::test_never_close_classes_never_close_on_the_models_word`
  * `tests/unit/domain/test_closure.py::test_each_condition_alone_blocks_a_model_led_close`
  * `tests/unit/domain/test_closure.py::test_approved_benign_evidence_never_closes_past_a_hard_flag`
  * `tests/unit/domain/test_closure.py::test_a_related_open_threat_holds_a_model_led_close_and_names_the_reason`
  * `tests/unit/domain/test_closure.py::test_related_alerts_that_were_not_checked_block_the_close`
  * `tests/unit/domain/test_related.py::test_hold_grade_is_one_predicate`
  * `tests/unit/domain/test_related.py::test_relation_keys_are_hosts_and_users_and_never_ips`
  * `tests/integration/engine/test_related_open.py::test_a_hold_grade_threat_on_the_same_host_or_user_holds_the_close`
  * `tests/integration/engine/test_related_open.py::test_a_held_alert_takes_the_ordinary_escalation_path`
  * `tests/integration/engine/test_related_open.py::test_a_threat_that_reaches_hold_grade_after_the_close_reopens_it_into_its_case`
  * `tests/integration/engine/test_related_open.py::test_the_beacon_decided_before_the_rest_of_the_chain_is_reopened_by_it`
  * `tests/integration/engine/test_related_open.py::test_a_failed_read_of_the_related_alerts_escalates_and_never_fails_the_run`
  * `tests/integration/engine/test_review_442.py::test_probe_spelling_of_the_same_entity_still_holds`
  * `tests/integration/engine/test_related_open.py::test_a_threat_only_a_model_stands_behind_links_the_close_to_its_case`
  * `tests/integration/engine/test_related_open.py::test_a_serious_alert_being_processed_on_the_same_host_holds_the_close`
  * `tests/integration/engine/test_related_open.py::test_another_tenants_threat_never_holds_or_links_a_close`
  * `tests/integration/engine/test_related_open.py::test_no_alert_of_the_demo_attack_chain_closes_without_a_person`
  * `tests/unit/domain/test_closure.py::test_a_scanner_or_test_source_never_closes_a_never_close_class`
  * `tests/unit/domain/test_closure.py::test_an_unmapped_alert_closes_on_the_models_word_but_an_unreadable_wazuh_rule_does_not`
  * `tests/unit/domain/test_closure.py::test_the_evidence_of_an_investigation_holds_a_model_led_close`
  * `tests/unit/domain/test_closure.py::test_what_is_recorded_only_does_not_hold_a_close`
  * `tests/unit/domain/test_closure.py::test_without_an_investigation_policy_v3_is_unchanged`
  * `tests/unit/domain/test_closure.py::test_an_investigation_whose_record_cannot_be_read_holds_the_close`
  * `tests/unit/domain/test_closure.py::test_steering_text_in_the_evidence_stops_a_close_on_approved_benign_evidence_too`
  * `tests/unit/domain/test_closure.py::test_the_holds_are_named_in_the_order_steering_related_threat_evidence`
  * `tests/unit/agents/test_analysis_evidence.py::test_a_true_indicator_holds_the_close_and_names_its_facts`
  * `tests/unit/agents/test_analysis_evidence.py::test_a_hard_citation_finding_on_a_benign_verdict_holds_the_close`
  * `tests/unit/tools/wazuh/test_own_event.py::test_an_alert_alone_on_its_host_shows_nothing`
  * `tests/integration/engine/test_review_443_steering.py::test_probe_steering_text_in_evidence_blocks_a_model_close_like_steering_text_in_the_alert`
  * `tests/integration/engine/test_review_443_steering.py::test_a_true_indicator_or_a_citation_that_does_not_hold_sends_the_alert_to_a_person`
  * `tests/integration/engine/test_retro_reopen.py::test_an_escalation_a_model_judged_a_threat_links_related_model_closes_and_reopens_nothing`
  * `tests/integration/engine/test_retro_reopen.py::test_an_escalation_the_models_only_found_suspicious_reopens_nothing`
  * `tests/integration/engine/test_retro_reopen.py::test_a_response_plan_the_workflow_only_proposes_links_and_reopens_nothing`
  * `tests/integration/engine/test_retro_reopen.py::test_a_response_the_workflow_carries_out_alone_reopens_related_model_closes`
  * `tests/integration/engine/test_retro_reopen.py::test_a_response_the_workflow_only_simulates_in_dry_run_links_and_reopens_nothing`
  * `tests/integration/engine/test_retro_reopen.py::test_an_analysts_true_positive_reopens_at_the_response_plan_and_at_the_malicious_close`
  * `tests/integration/engine/test_retro_reopen.py::test_a_confirmed_threat_reopens_what_was_linked_earlier_however_long_ago`
  * `tests/integration/engine/test_retro_reopen.py::test_a_later_case_of_the_threat_shows_what_it_linked_before`
  * `tests/integration/engine/test_retro_reopen.py::test_a_benign_decision_on_the_case_leaves_a_linked_alert_closed_by_the_models`
  * `tests/integration/engine/test_retro_reopen.py::test_a_reopen_or_link_failure_is_counted_not_swallowed`
  * `tests/integration/api/test_retro_reopen_api.py::test_a_linked_alert_is_listed_on_the_case_and_a_benign_decision_leaves_it_closed_by_the_models`
  * `tests/integration/api/test_retro_reopen_api.py::test_an_analyst_true_positive_reopens_the_alert_linked_to_the_case_and_resumes_only_the_threat`
  * `tests/integration/api/test_retro_reopen_api.py::test_an_approved_response_action_reopens_related_model_closes`
  * `tests/integration/integrations/test_slack.py::test_an_approval_from_slack_reopens_related_model_closes`
  * `tests/integration/api/test_review_423.py::test_probe_evidence_pack_of_a_linked_alert_claims_no_human_decision`
  * `tests/integration/api/test_review_423.py::test_the_incident_report_of_a_linked_alert_names_no_analyst_decision`
  * `tests/integration/api/test_review_423.py::test_probe_replaying_approve_on_an_action_nobody_approved_reopens`
  * `tests/integration/api/test_review_423.py::test_probe_two_threats_linking_the_same_alert_at_once_keep_both_links`
  * `tests/integration/api/test_review_423.py::test_probe_link_never_gets_past_the_newest_cap`
  * `tests/integration/api/test_review_423.py::test_probe_linked_closed_alerts_use_up_the_case_grouping_room`
  * `tests/integration/api/test_retro_reopen_api.py::test_the_case_decision_settles_folded_alerts_in_its_own_transaction`
  * `tests/integration/engine/test_review_349.py::test_worker_delivers_the_case_decision_to_a_folded_alert`
  * `tests/integration/engine/test_review_349.py::test_needs_more_info_strands_a_folded_alert`
  * `tests/integration/api/test_retro_reopen_api.py::test_an_analyst_true_positive_reopens_related_model_closes`
  * `tests/integration/api/test_retro_reopen_api.py::test_a_malicious_blind_audit_label_reopens_related_model_closes`
  * `tests/unit/domain/test_closure.py::test_review_f2_sentinel_credential_access_is_a_never_close_class`
  * `tests/unit/domain/test_noise_families.py::test_a_forged_or_borrowed_title_on_an_uncatalogued_rule_stays_unmapped`
  * `tests/unit/domain/test_noise_families.py::test_the_catalogue_lifts_only_unmapped_never_a_mapped_never_close_class`
  * `tests/unit/domain/test_noise_families.py::test_every_other_condition_still_blocks_a_catalogued_rule`
  * `tests/unit/domain/test_noise_families.py::test_a_malicious_or_suspicious_model_verdict_on_a_catalogued_rule_still_escalates`
  * `tests/unit/domain/test_noise_families.py::test_recheck_a_wazuh_alert_without_a_readable_rule_never_closes`
  * `tests/unit/domain/test_noise_families.py::test_review_h1_authentication_failures_are_credential_access_whatever_their_mapping`
  * `tests/integration/engine/test_model_closure.py::test_the_tenant_tier_decides_whether_the_models_close`
  * `tests/integration/engine/test_model_closure.py::test_catalogued_noise_is_named_and_an_unreadable_wazuh_rule_does_not_close`
  * `tests/integration/eval/test_adversarial_v2_eval.py::test_model_led_closure_on_closes_only_what_policy_v3_allows`
  * `tests/integration/e2e/test_llm_safety.py::test_injected_benign_instructions_never_close_an_alert`
  * `tests/unit/agents/test_title_camouflage.py::test_the_title_camouflage_items_get_no_benign_evidence_and_never_close_on_rules`
  * `tests/unit/agents/test_title_camouflage.py::test_attacker_named_text_is_never_benign_evidence`
  * `tests/unit/core/test_verdict_cache_replay.py::test_analyst_oracle_replay_closes_no_malicious_alert`
  * `tests/unit/core/test_verdict_cache_replay.py::test_each_collision_no_longer_closes`
  * `tests/unit/core/test_verdict_cache.py::test_one_analyst_is_not_enough_two_different_ones_are`
  * `tests/unit/domain/test_verdict_key.py::test_never_close_classes_get_no_key`
  * `tests/unit/domain/test_verdict_key.py::test_context_alone_never_makes_a_key`
  * `tests/unit/domain/test_verdict_key_review.py::test_a_real_sql_injection_does_not_inherit_a_false_positives_verdict`
  * `tests/unit/core/test_gate.py::test_a_fingerprint_suggestion_never_closes_even_enabled_again_by_an_admin`
  * `tests/unit/domain/test_verdict_key.py::test_attacker_writable_differences_never_share_a_key`
  * `tests/unit/domain/test_verdict_key_review.py::test_a_malicious_scheduled_task_does_not_inherit_a_benign_tasks_verdict`
  * `tests/unit/domain/test_verdict_key_review.py::test_a_payload_appended_past_512_characters_changes_the_key`
  * `tests/integration/api/test_revocation.py::test_a_true_positive_decision_disables_matching_rules_and_tombstones_the_cache`
  * `tests/integration/engine/test_engine.py::test_plan_response_and_the_malicious_close_revoke_the_benign_learning`
  * `tests/integration/db/test_migrations.py::test_0016_disables_fingerprint_suggestions_and_audits_each_in_its_chain`
  * `tests/unit/core/test_verdict_cache.py::test_a_threat_blocks_the_key_and_its_fingerprint_for_the_window`
  * `tests/unit/core/test_verdict_cache.py::test_entries_of_the_fingerprint_keyed_cache_are_never_read`
  * `tests/integration/eval/test_oracle_corpus_v1.py::test_the_oracle_closes_no_attack_on_corpus_v1`
  * `tests/integration/services/test_review.py::test_a_confirmed_threat_disables_the_suppression_rules_that_would_close_it`

## INV-04: Every LLM call records its prompt hash and model id

A decision must be traceable to the exact prompt and model that produced it. Every production call passes a registered prompt; the call's log event, the alert summary, the usage totals, the evaluation report and the evidence pack carry the prompt name, its content hash and the model.

* **Status:** enforced
* **Owner epic:** AI-E1
* **Threats:** TM-WRK-8
* **Enforced in:** `src/lg_sotf/llm/registry.py`, `src/lg_sotf/llm/structured.py`, `src/lg_sotf/llm/provenance.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/unit/llm/test_prompt_registry.py::test_every_llm_call_records_prompt_hash_and_model_id`
  * `tests/unit/llm/test_prompt_registry.py::test_every_production_llm_call_passes_a_registered_prompt`
  * `tests/unit/llm/test_prompt_registry.py::test_every_production_prompt_is_registered`
  * `tests/unit/agents/test_model_provenance.py::test_llm_call_records_provider_model_and_tier`

## INV-05: Every LLM and tool step of a run is in the trace store

An investigation must be reviewable step by step. Each LLM call and tool call of a run is written to investigation_steps with its hashes and token counts and listed in the evidence pack; a failed trace write is logged, never silently dropped.

* **Status:** enforced
* **Owner epic:** AI-E1
* **Threats:** TM-WRK-8, TM-EVT-6
* **Enforced in:** `src/lg_sotf/llm/trace.py`, `src/lg_sotf/db/repos/investigation_steps.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/integration/engine/test_investigation_trace.py::test_every_llm_and_tool_step_of_a_run_is_in_the_trace_store_and_the_evidence_pack`
  * `tests/unit/agents/test_trace.py::test_every_llm_and_tool_step_of_an_analysis_run_is_stored_in_order`
  * `tests/unit/agents/test_trace.py::test_a_failed_trace_write_is_logged_and_never_fails_the_run`

## INV-06: The audit log is append-only for the runtime role

The audit trail is the record of who did what; it is worthless if the application can rewrite it. The runtime role holds only SELECT and INSERT on audit_log, triggers refuse UPDATE, DELETE and TRUNCATE, and each tenant's entries form a SHA-256 hash chain that detects tampering.

* **Status:** enforced
* **Owner epic:** ARCH-E8
* **Threats:** TM-DB-3, TM-API-9, TM-SCH-2
* **Enforced in:** `src/lg_sotf/db/migrations/versions/0001_initial.py`, `src/lg_sotf/db/migrate.py`, `src/lg_sotf/db/repos/audit.py`
* **Runtime checks:** `audit_append_only`
* **Proved by:**
  * `tests/integration/db/test_runtime_role.py::test_audit_log_is_append_only_for_the_runtime_role`
  * `tests/integration/db/test_runtime_role.py::test_grants_are_least_privilege`
  * `tests/integration/db/test_audit.py::test_update_delete_truncate_blocked_without_bypass`
  * `tests/integration/db/test_audit.py::test_tampered_details_detected`

## INV-07: No secret is ever logged; redaction covers the known credential patterns

Logs leave the product (log shippers, support bundles). Every log record, traceback and stored audit detail goes through redaction of passwords, tokens, keys, connection strings and credential-shaped command lines before it is written.

* **Status:** enforced
* **Owner epic:** SEC5
* **Threats:** TM-API-6, TM-ING-3, TM-WRK-4
* **Enforced in:** `src/lg_sotf/security/redaction.py`, `src/lg_sotf/observability/logging.py`
* **Runtime checks:** `log_redaction`
* **Proved by:**
  * `tests/unit/security/test_redaction.py::test_secrets_are_removed`
  * `tests/unit/observability/test_logging.py::test_secrets_are_redacted`
  * `tests/unit/observability/test_logging.py::test_objects_and_exceptions_are_redacted`
  * `tests/unit/observability/test_log_failure.py::test_message_with_jwt_and_alert_text_never_reaches_the_output`

## INV-08: Evidence packs are hash-verified

An evidence pack handed to an auditor or a court must show that it was not changed. Each pack carries the SHA-256 of its canonical form and, when the install has its signing key, an HMAC signature; lg-sotf evidence-verify rejects a pack whose digest or signature does not match.

* **Status:** enforced
* **Owner epic:** SEC7
* **Threats:** TM-EVT-6, TM-API-9
* **Enforced in:** `src/lg_sotf/compliance/canonical.py`, `src/lg_sotf/compliance/evidence.py`
* **Runtime checks:** `evidence_seal`
* **Proved by:**
  * `tests/unit/compliance/test_canonical.py::test_seal_is_stable_and_detects_changes`
  * `tests/unit/compliance/test_canonical.py::test_signing_key_is_dedicated_and_verification_needs_the_right_key`
  * `tests/integration/runtime/test_compliance_cli.py::test_evidence_verify_checks_digest_and_signature`

## INV-09: Shadow mode causes no side effects

A candidate configuration run side by side with production must not act: no response execution, outbox message, Slack or mail notification, webhook, ticket or WebSocket event may leave a shadow run.

* **Status:** enforced
* **Owner epic:** AI-E1
* **Threats:** TM-RSP-4, TM-MCP-6
* **Enforced in:** `src/lg_sotf/security/shadow.py`, `src/lg_sotf/core/shadow.py`, `src/lg_sotf/db/pool.py`, `src/lg_sotf/db/shadow_connection.py`, `src/lg_sotf/db/shadow_role.py`, `src/lg_sotf/queue/redis.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/integration/engine/test_shadow.py::test_shadow_no_side_effects`
  * `tests/integration/engine/test_shadow.py::test_every_boundary_diverts_when_called_directly`
  * `tests/unit/architecture/test_shadow_egress.py::test_shadow_no_side_effects_every_egress_site_is_a_registered_boundary`
  * `tests/unit/architecture/test_shadow_egress.py::test_shadow_no_side_effects_every_boundary_diverts_in_shadow_mode`
  * `tests/integration/db/test_shadow_role.py::test_shadow_role_refuses_each_proven_guard_bypass_at_the_database`
  * `tests/integration/db/test_shadow_role.py::test_without_the_shadow_role_a_shadow_transaction_is_refused_not_run_on_the_runtime_role`
  * `tests/integration/engine/test_shadow.py::test_a_shadow_run_refuses_to_start_without_the_shadow_role`
  * `tests/integration/engine/test_shadow_replay.py::test_shadow_run_replays_decided_alerts_and_agrees_with_itself`

## INV-10: Release images are signed, and their signature is checked before deploy

A tampered image must not reach a customer host. The release workflow signs both image digests with keyless cosign and attests their build provenance; the deploy workflow verifies the signer identity, issuer and provenance and stops before touching the host when either check fails.

* **Status:** enforced
* **Owner epic:** SEC1
* **Threats:** TM-CI-1
* **Enforced in:** `.github/workflows/release-images.yml`, `.github/workflows/deploy.yml`
* **Runtime checks:** none
* **Proved by:**
  * `tests/deploy/test_ci_workflow.py::test_release_images_sign_the_digests_and_attest_provenance`
  * `tests/deploy/test_ci_workflow.py::test_deploy_verifies_signature_and_provenance_before_touching_the_host`
  * `tests/deploy/test_ci_workflow.py::test_signing_and_verifying_use_the_same_cosign`
  * `tests/deploy/test_ci_workflow.py::test_verify_step_fails_closed`

## INV-11: No automatic containment on model-only evidence

When the only evidence for a containment action is the model's reading, the action waits for a person even if the tenant's autonomy is 'auto' for its risk level. Injected text cannot make the pipeline isolate a host or block an address on its own.

* **Status:** enforced
* **Owner epic:** AI-E6
* **Threats:** TM-WRK-3, TM-EVT-7
* **Enforced in:** `src/lg_sotf/services/response/planner.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/unit/services/test_response.py::test_llm_only_evidence_never_auto_contains`
  * `tests/integration/e2e/test_llm_safety.py::test_injected_response_instructions_never_execute_containment`

## INV-12: The model never chooses where data is sent

A model steered by alert text must not be able to exfiltrate. Threat-intel lookups go only to indicators the rules extracted from the alert, and the LLM endpoint itself passes the egress check (no loopback, link-local or metadata address).

* **Status:** enforced
* **Owner epic:** AI-E2
* **Threats:** TM-EVT-1, TM-WRK-5
* **Enforced in:** `src/lg_sotf/agents/analysis/react.py`, `src/lg_sotf/llm/endpoint.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/unit/agents/test_analysis.py::test_lookup_targets_are_restricted_to_extracted_candidates`
  * `tests/unit/llm/test_local.py::test_refused_base_urls`
  * `tests/unit/llm/test_local.py::test_base_url_is_checked_for_every_provider`

## INV-13: Autonomy is earned per skill and tenant and lost on any miss

An investigation skill closes alerts for a tenant only once it has earned a closing tier there: skill-blind and AI-blind labelled closures with no miss, and a four-eyes promotion. A miss demotes the skill to shadow in the same transaction as the label that revealed it (ADR-0014 section 6.3). Until AI-E3.10 merges nothing closes on a skill.

* **Status:** pending, delivered by AI-E3.10
* **Owner epic:** AI-E3
* **Threats:** TM-WRK-13
* **Enforced in:** none
* **Runtime checks:** none
* **Proved by:**
  * `tests/invariants/test_earned_autonomy.py::test_autonomy_is_earned_per_skill_and_lost_on_a_miss`

## INV-14: Evidence tools are read-only, templated and capped

An investigation tool is how a model-steered run reaches data. Every tool runs through the tool registry and nowhere else. The registry loads only a tool with a read-only risk class (there is no write class), a strict parameter model whose strings and collections are bounded, a row cap, a time cap, a window cap when it reads a time window, and a declared egress. On every call it validates the parameters first. It does not run a tool the calling tenant switched off, whose setting is malformed or whose settings cannot be read, nor a call whose window is longer than the cap. While the tool runs it is held to its time cap and to the one egress boundary it declared: a tool that stays on the platform crosses none, and a third-party tool crosses none live in a shadow run. A result over the row cap is dropped. Every call that passed validation is a trace step with the result's outcome, so a call that failed in any way is never read as a query that found nothing. The Wazuh evidence tools are query templates: a caller gives typed, bounded values, never a query, a field or an index. Every search body is checked against an allow-list before it is run (term, terms and the time range in a filter, counting aggregations, allow-listed fields, fixed row, time and document caps), and a value is only ever the right-hand side of a clause. A caller cannot narrow what a fact reports: a logon fan-out always reads every outcome and every logon type of its pivot. The one request the indexer client can send is POST _search on the index pattern of the Wazuh source the run's own alert came from (the source's URL gives the scheme, the host and the port, never a path or a query), with that source's credentials, through the destination policy; it reads in a shadow run too, as a reviewed read of the tenant's own system. Only an HTTP 200 in which every shard answered is an answer. A result is complete only when the indexer finished every search, no cap cut what the fact lists or how far a process's ancestry was walked, one process (not several) matched a lineage, the window had closed and the index reached back to its start.

* **Status:** enforced
* **Owner epic:** AI-E2
* **Threats:** TM-EVT-3, TM-EVT-9, TM-EVT-10, TM-EVT-12
* **Enforced in:** `src/lg_sotf/tools/registry.py`, `src/lg_sotf/tools/enrichment/tools.py`, `src/lg_sotf/security/shadow.py`, `src/lg_sotf/tools/wazuh/dsl.py`, `src/lg_sotf/tools/wazuh/templates.py`, `src/lg_sotf/tools/wazuh/indexer.py`, `src/lg_sotf/tools/wazuh/tools.py`, `src/lg_sotf/ingestion/wazuh_indexer.py`
* **Runtime checks:** none
* **Proved by:**
  * `tests/unit/tools/test_registry.py::test_a_tool_missing_caps_or_schema_fails_to_load`
  * `tests/unit/tools/test_registry.py::test_a_params_model_that_is_not_strict_and_bounded_fails_to_load`
  * `tests/unit/tools/test_registry.py::test_no_tool_can_register_a_write_risk_class`
  * `tests/unit/tools/test_registry.py::test_egress_is_declared_and_coherent`
  * `tests/unit/tools/test_registry.py::test_parameters_are_validated_before_the_call`
  * `tests/unit/tools/test_registry.py::test_a_tool_disabled_for_the_tenant_is_not_called`
  * `tests/unit/tools/test_registry.py::test_the_tenant_switch_fails_closed`
  * `tests/unit/tools/test_registry.py::test_a_tenant_switch_applies_to_that_tenant_only`
  * `tests/unit/tools/test_registry.py::test_the_window_cap_is_enforced_before_the_call`
  * `tests/unit/tools/test_registry.py::test_time_and_row_caps_answer_with_the_refusal`
  * `tests/unit/tools/test_registry.py::test_a_tool_crosses_only_the_egress_boundary_it_declared`
  * `tests/unit/tools/test_registry.py::test_a_platform_tool_cannot_open_an_outside_connection`
  * `tests/unit/tools/test_registry.py::test_a_shadow_run_makes_no_third_party_request`
  * `tests/unit/tools/test_registry.py::test_an_empty_result_and_a_failed_call_are_distinguishable`
  * `tests/unit/architecture/test_tool_registry.py::test_enrichment_lookups_are_called_only_through_the_registry`
  * `tests/unit/agents/test_analysis.py::test_ti_lookups_run_through_the_registry`
  * `tests/unit/tools/test_registry.py::test_a_tool_can_say_its_answer_was_cut_but_never_that_a_full_one_is_whole`
  * `tests/unit/tools/wazuh/test_templates.py::test_templates_emit_only_allow_listed_dsl`
  * `tests/unit/tools/wazuh/test_templates.py::test_values_only_reach_term_terms_range`
  * `tests/unit/tools/wazuh/test_templates.py::test_an_injected_value_cannot_change_the_query_shape`
  * `tests/unit/tools/wazuh/test_templates.py::test_a_field_or_construct_outside_the_allow_list_is_refused`
  * `tests/unit/tools/wazuh/test_templates.py::test_a_parameter_outside_its_type_or_bound_is_refused`
  * `tests/unit/tools/wazuh/test_templates.py::test_every_query_carries_the_tenant_scope`
  * `tests/unit/tools/wazuh/test_indexer.py::test_the_client_only_posts_a_search_to_the_tenants_index`
  * `tests/unit/tools/wazuh/test_indexer.py::test_the_destination_policy_holds_for_the_indexer`
  * `tests/unit/tools/wazuh/test_indexer.py::test_a_shadow_run_reads_the_tenants_indexer_and_the_tool_crosses_no_other_boundary`
  * `tests/unit/tools/wazuh/test_tools.py::test_the_tools_are_declared_read_only_capped_and_switched_per_tenant`
  * `tests/unit/tools/wazuh/test_tools.py::test_a_second_tenants_telemetry_is_never_returned`
  * `tests/unit/tools/wazuh/test_tools.py::test_nothing_found_is_empty_and_never_a_fact`
  * `tests/unit/tools/wazuh/test_tools.py::test_an_unreachable_or_refusing_indexer_is_failed_never_empty`
  * `tests/unit/tools/wazuh/test_tools.py::test_a_capped_result_is_not_complete`
  * `tests/unit/tools/wazuh/test_mappers.py::test_incomplete_results_are_marked`
  * `tests/unit/tools/wazuh/test_mappers.py::test_a_window_that_has_not_closed_or_is_not_covered_is_marked`
  * `tests/unit/ingestion/test_wazuh_indexer.py::test_a_call_reaches_the_source_of_its_own_alert_with_that_sources_credentials`
  * `tests/unit/architecture/test_tool_registry.py::test_the_wazuh_indexer_is_searched_only_by_its_tools`
  * `tests/unit/tools/wazuh/test_indexer.py::test_the_base_url_cannot_choose_the_endpoint`
  * `tests/unit/tools/wazuh/test_indexer.py::test_the_request_is_built_from_the_host_and_the_index_only`
  * `tests/unit/tools/wazuh/test_indexer.py::test_an_unreachable_or_broken_indexer_is_failed_with_a_reason`
  * `tests/unit/tools/wazuh/test_indexer.py::test_a_refusing_indexer_is_a_bounded_reason_and_is_not_asked_again`
  * `tests/unit/ingestion/test_wazuh_indexer.py::test_why_a_call_cannot_be_answered_is_a_bounded_reason`
  * `tests/unit/tools/wazuh/test_mappers.py::test_a_list_cut_by_a_cap_is_not_whole`
  * `tests/unit/tools/wazuh/test_mappers.py::test_a_response_is_read_with_its_flags`
  * `tests/unit/tools/wazuh/test_tools.py::test_the_ancestry_is_walked_up_to_the_asked_depth`
  * `tests/unit/tools/wazuh/test_tools.py::test_several_processes_of_one_image_are_each_described_and_none_is_complete`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p1_unassigned_shards_are_never_a_complete_answer`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p2_an_answer_without_the_asked_aggregation_is_failed`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p5_failures_typed_in_another_case_are_counted_for_the_user`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p6_a_logon_event_id_from_another_provider_is_not_a_logon`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p8_the_base_url_cannot_choose_the_endpoint`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p9_only_a_200_is_an_answer`
  * `tests/unit/tools/wazuh/test_review_433.py::test_p10_a_fact_read_with_a_filter_does_not_say_zero_for_what_it_did_not_read`
