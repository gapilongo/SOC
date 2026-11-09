"""The safety invariants LG-SOTF promises, each with its proof (SEC9.1).

An invariant is a rule that holds for every alert, tenant and release, not a
default an operator can switch off. Each entry names:

* ``proofs``: the pytest node ids that fail when the rule breaks. The CI gate
  (``tests/deploy/test_invariants.py``) checks that every id exists and that
  no proof of an ``enforced`` invariant is marked skip or xfail;
* ``checks``: the runtime checks ``lg-sotf verify-invariants`` runs against a
  live install (:mod:`lg_sotf.invariants.checks`), if any;
* ``threats``: the ``TM-*`` rows of ``docs/threat-model.md`` it answers;
* ``epic``: the backlog epic that owns it.

``pending`` invariants are promised but not delivered yet; ``pending_story``
names the story that delivers them. ``docs/invariants.md`` is generated from
this module (``python scripts/export_invariants.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Tuple

__all__ = ["INVARIANTS", "Invariant", "Status", "render_markdown"]

Status = Literal["enforced", "pending"]


@dataclass(frozen=True)
class Invariant:
    id: str
    title: str
    rationale: str
    epic: str
    threats: Tuple[str, ...]
    code: Tuple[str, ...]
    proofs: Tuple[str, ...]
    checks: Tuple[str, ...] = ()
    metric: Optional[str] = None
    status: Status = "enforced"
    pending_story: Optional[str] = None


INVARIANTS: Tuple[Invariant, ...] = (
    Invariant(
        id="INV-01",
        title="Every tenant table has forced row-level security, and the runtime role cannot bypass it",
        rationale=(
            "One customer's alerts, users and audit trail must never be readable or writable from another "
            "customer's session, even through a bug in a query. PostgreSQL enforces it below the application: "
            "every tenant-owned table (partitions and checkpoint tables included) is under FORCE ROW LEVEL "
            "SECURITY with a tenant policy, and the API and worker role is neither a superuser, nor BYPASSRLS, "
            "nor a member of the schema owner, so setting app.bypass_rls changes nothing for it."
        ),
        epic="ARCH-E4",
        threats=("TM-DB-1", "TM-DB-2", "TM-SCH-1", "TM-API-3"),
        code=(
            "src/lg_sotf/db/migrations/versions/0001_initial.py",
            "src/lg_sotf/db/partitions.py",
            "src/lg_sotf/db/checkpointer.py",
            "src/lg_sotf/db/migrate.py",
        ),
        proofs=(
            "tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy",
            "tests/integration/db/test_rls.py::test_unfiltered_queries_only_see_own_tenant",
            "tests/integration/db/test_rls.py::test_cannot_insert_rows_for_another_tenant",
            "tests/integration/db/test_rls.py::test_checkpoint_tables_are_tenant_isolated",
            "tests/integration/db/test_runtime_role.py::test_setting_the_bypass_guc_does_not_bypass_isolation",
            "tests/integration/db/test_runtime_role.py::test_runtime_role_cannot_weaken_the_schema",
            "tests/integration/runtime/test_verify_invariants.py::test_a_table_without_forced_rls_fails_the_check",
        ),
        checks=("rls_catalog", "runtime_role", "rls_probe"),
    ),
    Invariant(
        id="INV-02",
        title="No response action runs without an approval or an autonomy rule that allows it; the kill switch wins",
        rationale=(
            "Containment changes a customer's environment. An action executes only once it is approved by a "
            "person or by the tenant's 'auto' autonomy for its risk level (an unknown autonomy value reads as "
            "'disabled'). The install-wide response.dry_run switch, or a tenant's dry_run, routes every action "
            "to the dry-run connector whatever else is configured."
        ),
        epic="AI-E6",
        threats=("TM-WRK-3", "TM-RSP-4", "TM-RSP-5", "TM-MCP-6"),
        code=(
            "src/lg_sotf/services/response/planner.py",
            "src/lg_sotf/services/response/policy.py",
            "src/lg_sotf/services/response/execution.py",
            "src/lg_sotf/services/connectors/registry.py",
        ),
        proofs=(
            "tests/invariants/test_response_approval.py::test_actions_awaiting_approval_are_never_executed",
            "tests/invariants/test_response_approval.py::test_a_dry_run_tenant_rehearses_even_auto_approved_actions",
            "tests/unit/services/test_response.py::test_autonomy_resolution",
            "tests/unit/services/test_response.py::test_disabled_autonomy_blocks",
            "tests/unit/services/test_response.py::test_dry_run_forced_globally_and_per_tenant",
            "tests/unit/services/test_response.py::test_malformed_tenant_dry_run_flag_fails_safe",
            "tests/unit/services/test_routing.py::test_kill_switches_win_everywhere",
        ),
        checks=("kill_switch",),
    ),
    Invariant(
        id="INV-03",
        title=(
            "An AI verdict alone never closes a high or critical alert or a never-close class; a low or medium "
            "alert closes on the models' word only at the tenant's autonomy tier"
        ),
        rationale=(
            "A fooled or injected model must not be able to make a dangerous alert disappear. Routing is a pure "
            "policy. High and critical alerts close only by an analyst, a suppression rule or an analyst-confirmed "
            "verdict. A low or medium alert closes when approved benign evidence an attacker cannot write "
            "corroborates a benign verdict: a cached analyst verdict, the detection rule's name, the EICAR hash, a "
            "test source or the tenant's declared context, such as a scanner as the source of the activity; never "
            "past steering text or a recent true positive, and a scanner or test source never for a never-close "
            "class. Without such evidence it closes on the models' word only when the tenant's autonomy tier is "
            "auto_full_audit and both model tiers judge it benign within the install's thresholds, never for the "
            "never-close classes (credential access, log clearing, security-tool tampering, ransomware behaviour, "
            "persistence through attacker-named objects, authentication failures by vendor rule group, unmapped "
            "alerts unless the vendor rule id is in the reviewed noise catalogue, never matched on text), steering "
            "text, entities with a recent true positive or a campaign in progress; such a close is marked "
            "model_closed for audit. With the tier off, the default, a model never closes an alert alone."
        ),
        epic="AI-E6",
        threats=("TM-WRK-1", "TM-WRK-2"),
        code=(
            "src/lg_sotf/domain/routing.py",
            "src/lg_sotf/domain/closure.py",
            "src/lg_sotf/domain/noise_families.py",
            "src/lg_sotf/domain/benign_evidence.py",
        ),
        proofs=(
            "tests/unit/domain/test_routing.py::test_llm_only_evidence_never_closes_high_or_critical_at_triage",
            "tests/unit/domain/test_routing.py::test_decide_never_closes_high_severity",
            "tests/unit/domain/test_routing.py::test_decide_closes_only_with_approved_benign_evidence",
            "tests/unit/domain/test_routing.py::test_attacker_controlled_fp_words_never_close_high_severity",
            "tests/unit/domain/test_closure.py::test_with_the_tier_off_a_model_never_closes_alone",
            "tests/unit/domain/test_closure.py::test_high_and_critical_never_close_at_any_tier",
            "tests/unit/domain/test_closure.py::test_never_close_classes_never_close_on_the_models_word",
            "tests/unit/domain/test_closure.py::test_each_condition_alone_blocks_a_model_led_close",
            "tests/unit/domain/test_closure.py::test_approved_benign_evidence_never_closes_past_a_hard_flag",
            "tests/unit/domain/test_closure.py::test_a_scanner_or_test_source_never_closes_a_never_close_class",
            "tests/unit/domain/test_closure.py::test_a_campaign_in_progress_is_never_model_closed",
            "tests/unit/domain/test_closure.py::test_review_f2_sentinel_credential_access_is_a_never_close_class",
            "tests/unit/domain/test_noise_families.py::test_a_forged_or_borrowed_title_on_an_uncatalogued_rule_stays_unmapped",
            "tests/unit/domain/test_noise_families.py::test_the_catalogue_lifts_only_unmapped_never_a_mapped_never_close_class",
            "tests/unit/domain/test_noise_families.py::test_every_other_condition_still_blocks_a_catalogued_rule",
            "tests/unit/domain/test_noise_families.py::"
            "test_a_malicious_or_suspicious_model_verdict_on_a_catalogued_rule_still_escalates",
            "tests/unit/domain/test_noise_families.py::test_recheck_a_wazuh_alert_without_a_readable_rule_never_closes",
            "tests/unit/domain/test_noise_families.py::"
            "test_review_h1_authentication_failures_are_credential_access_whatever_their_mapping",
            "tests/integration/engine/test_model_closure.py::test_the_tenant_tier_decides_whether_the_models_close",
            "tests/integration/engine/test_model_closure.py::"
            "test_catalogued_noise_closes_on_the_models_word_and_an_uncatalogued_rule_does_not",
            "tests/integration/eval/test_adversarial_v2_eval.py::test_no_malicious_close_with_model_led_closure_on",
            "tests/integration/e2e/test_llm_safety.py::test_injected_benign_instructions_never_close_an_alert",
            "tests/unit/agents/test_title_camouflage.py::"
            "test_the_title_camouflage_items_get_no_benign_evidence_and_never_close_on_rules",
            "tests/unit/agents/test_title_camouflage.py::test_attacker_named_text_is_never_benign_evidence",
        ),
        checks=("routing_policy",),
        metric="high_severity_auto_closed_benign",
    ),
    Invariant(
        id="INV-04",
        title="Every LLM call records its prompt hash and model id",
        rationale=(
            "A decision must be traceable to the exact prompt and model that produced it. Every production call "
            "passes a registered prompt; the call's log event, the alert summary, the usage totals, the "
            "evaluation report and the evidence pack carry the prompt name, its content hash and the model."
        ),
        epic="AI-E1",
        threats=("TM-WRK-8",),
        code=("src/lg_sotf/llm/registry.py", "src/lg_sotf/llm/structured.py", "src/lg_sotf/llm/provenance.py"),
        proofs=(
            "tests/unit/llm/test_prompt_registry.py::test_every_llm_call_records_prompt_hash_and_model_id",
            "tests/unit/llm/test_prompt_registry.py::test_every_production_llm_call_passes_a_registered_prompt",
            "tests/unit/llm/test_prompt_registry.py::test_every_production_prompt_is_registered",
            "tests/unit/agents/test_model_provenance.py::test_llm_call_records_provider_model_and_tier",
        ),
    ),
    Invariant(
        id="INV-05",
        title="Every LLM and tool step of a run is in the trace store",
        rationale=(
            "An investigation must be reviewable step by step. Each LLM call and tool call of a run is written "
            "to investigation_steps with its hashes and token counts and listed in the evidence pack; a failed "
            "trace write is logged, never silently dropped."
        ),
        epic="AI-E1",
        threats=("TM-WRK-8", "TM-EVT-6"),
        code=("src/lg_sotf/llm/trace.py", "src/lg_sotf/db/repos/investigation_steps.py"),
        proofs=(
            "tests/integration/engine/test_investigation_trace.py::"
            "test_every_llm_and_tool_step_of_a_run_is_in_the_trace_store_and_the_evidence_pack",
            "tests/unit/agents/test_trace.py::test_every_llm_and_tool_step_of_an_analysis_run_is_stored_in_order",
            "tests/unit/agents/test_trace.py::test_a_failed_trace_write_is_logged_and_never_fails_the_run",
        ),
    ),
    Invariant(
        id="INV-06",
        title="The audit log is append-only for the runtime role",
        rationale=(
            "The audit trail is the record of who did what; it is worthless if the application can rewrite it. "
            "The runtime role holds only SELECT and INSERT on audit_log, triggers refuse UPDATE, DELETE and "
            "TRUNCATE, and each tenant's entries form a SHA-256 hash chain that detects tampering."
        ),
        epic="ARCH-E8",
        threats=("TM-DB-3", "TM-API-9", "TM-SCH-2"),
        code=(
            "src/lg_sotf/db/migrations/versions/0001_initial.py",
            "src/lg_sotf/db/migrate.py",
            "src/lg_sotf/db/repos/audit.py",
        ),
        proofs=(
            "tests/integration/db/test_runtime_role.py::test_audit_log_is_append_only_for_the_runtime_role",
            "tests/integration/db/test_runtime_role.py::test_grants_are_least_privilege",
            "tests/integration/db/test_audit.py::test_update_delete_truncate_blocked_without_bypass",
            "tests/integration/db/test_audit.py::test_tampered_details_detected",
        ),
        checks=("audit_append_only",),
    ),
    Invariant(
        id="INV-07",
        title="No secret is ever logged; redaction covers the known credential patterns",
        rationale=(
            "Logs leave the product (log shippers, support bundles). Every log record, traceback and stored "
            "audit detail goes through redaction of passwords, tokens, keys, connection strings and "
            "credential-shaped command lines before it is written."
        ),
        epic="SEC5",
        threats=("TM-API-6", "TM-ING-3", "TM-WRK-4"),
        code=("src/lg_sotf/security/redaction.py", "src/lg_sotf/observability/logging.py"),
        proofs=(
            "tests/unit/security/test_redaction.py::test_secrets_are_removed",
            "tests/unit/observability/test_logging.py::test_secrets_are_redacted",
            "tests/unit/observability/test_logging.py::test_objects_and_exceptions_are_redacted",
            "tests/unit/observability/test_log_failure.py::test_message_with_jwt_and_alert_text_never_reaches_the_output",
        ),
        checks=("log_redaction",),
    ),
    Invariant(
        id="INV-08",
        title="Evidence packs are hash-verified",
        rationale=(
            "An evidence pack handed to an auditor or a court must show that it was not changed. Each pack "
            "carries the SHA-256 of its canonical form and, when the install has its signing key, an HMAC "
            "signature; lg-sotf evidence-verify rejects a pack whose digest or signature does not match."
        ),
        epic="SEC7",
        threats=("TM-EVT-6", "TM-API-9"),
        code=("src/lg_sotf/compliance/canonical.py", "src/lg_sotf/compliance/evidence.py"),
        proofs=(
            "tests/unit/compliance/test_canonical.py::test_seal_is_stable_and_detects_changes",
            "tests/unit/compliance/test_canonical.py::test_signing_key_is_dedicated_and_verification_needs_the_right_key",
            "tests/integration/runtime/test_compliance_cli.py::test_evidence_verify_checks_digest_and_signature",
        ),
        checks=("evidence_seal",),
    ),
    Invariant(
        id="INV-09",
        title="Shadow mode causes no side effects",
        rationale=(
            "A candidate configuration run side by side with production must not act: no response execution, "
            "outbox message, Slack or mail notification, webhook, ticket or WebSocket event may leave a "
            "shadow run."
        ),
        epic="AI-E1",
        threats=("TM-RSP-4", "TM-MCP-6"),
        code=(
            "src/lg_sotf/security/shadow.py",
            "src/lg_sotf/core/shadow.py",
            "src/lg_sotf/db/pool.py",
            "src/lg_sotf/db/shadow_connection.py",
            "src/lg_sotf/queue/redis.py",
        ),
        proofs=(
            "tests/integration/engine/test_shadow.py::test_shadow_no_side_effects",
            "tests/integration/engine/test_shadow.py::test_every_boundary_diverts_when_called_directly",
            "tests/unit/architecture/test_shadow_egress.py::"
            "test_shadow_no_side_effects_every_egress_site_is_a_registered_boundary",
            "tests/unit/architecture/test_shadow_egress.py::test_shadow_no_side_effects_every_boundary_diverts_in_shadow_mode",
        ),
    ),
    Invariant(
        id="INV-10",
        title="Release images are signed, and their signature is checked before deploy",
        rationale=(
            "A tampered image must not reach a customer host. The release workflow signs both image digests "
            "with keyless cosign and attests their build provenance; the deploy workflow verifies the signer "
            "identity, issuer and provenance and stops before touching the host when either check fails."
        ),
        epic="SEC1",
        threats=("TM-CI-1",),
        code=(".github/workflows/release-images.yml", ".github/workflows/deploy.yml"),
        proofs=(
            "tests/deploy/test_ci_workflow.py::test_release_images_sign_the_digests_and_attest_provenance",
            "tests/deploy/test_ci_workflow.py::test_deploy_verifies_signature_and_provenance_before_touching_the_host",
            "tests/deploy/test_ci_workflow.py::test_signing_and_verifying_use_the_same_cosign",
            "tests/deploy/test_ci_workflow.py::test_verify_step_fails_closed",
        ),
    ),
    Invariant(
        id="INV-11",
        title="No automatic containment on model-only evidence",
        rationale=(
            "When the only evidence for a containment action is the model's reading, the action waits for a "
            "person even if the tenant's autonomy is 'auto' for its risk level. Injected text cannot make the "
            "pipeline isolate a host or block an address on its own."
        ),
        epic="AI-E6",
        threats=("TM-WRK-3", "TM-EVT-7"),
        code=("src/lg_sotf/services/response/planner.py",),
        proofs=(
            "tests/unit/services/test_response.py::test_llm_only_evidence_never_auto_contains",
            "tests/integration/e2e/test_llm_safety.py::test_injected_response_instructions_never_execute_containment",
        ),
    ),
    Invariant(
        id="INV-12",
        title="The model never chooses where data is sent",
        rationale=(
            "A model steered by alert text must not be able to exfiltrate. Threat-intel lookups go only to "
            "indicators the rules extracted from the alert, and the LLM endpoint itself passes the egress "
            "check (no loopback, link-local or metadata address)."
        ),
        epic="AI-E2",
        threats=("TM-EVT-1", "TM-WRK-5"),
        code=("src/lg_sotf/agents/analysis/react.py", "src/lg_sotf/llm/endpoint.py"),
        proofs=(
            "tests/unit/agents/test_analysis.py::test_lookup_targets_are_restricted_to_extracted_candidates",
            "tests/unit/llm/test_local.py::test_refused_base_urls",
            "tests/unit/llm/test_local.py::test_base_url_is_checked_for_every_provider",
        ),
    ),
)


def _cell(values: Tuple[str, ...]) -> str:
    return ", ".join(f"`{v}`" for v in values) if values else "none"


def render_markdown() -> str:
    """``docs/invariants.md``: the registry as a page (``scripts/export_invariants.py`` writes it)."""
    out = [
        "# Safety invariants",
        "",
        "<!-- Generated from src/lg_sotf/invariants/registry.py by scripts/export_invariants.py; do not edit. -->",
        "",
        "These are the rules LG-SOTF holds for every alert, tenant and release. Each one names the tests that",
        "prove it; CI fails when a named test is missing or an enforced invariant's test is skipped",
        "(`tests/deploy/test_invariants.py`). Run `lg-sotf verify-invariants` on your own install to check",
        "the ones that depend on its database and settings (see [security.md](security.md#11-safety-invariants)).",
        "Threat rows refer to [threat-model.md](threat-model.md).",
        "",
        "| ID | Invariant | Status | Runtime check | Threats |",
        "|---|---|---|---|---|",
    ]
    for inv in INVARIANTS:
        status = inv.status if inv.pending_story is None else f"{inv.status} ({inv.pending_story})"
        out.append(f"| {inv.id} | {inv.title} | {status} | {_cell(inv.checks)} | {', '.join(inv.threats)} |")
    for inv in INVARIANTS:
        out += ["", f"## {inv.id}: {inv.title}", "", inv.rationale, ""]
        out.append(f"* **Status:** {inv.status}" + (f", delivered by {inv.pending_story}" if inv.pending_story else ""))
        out.append(f"* **Owner epic:** {inv.epic}")
        out.append(f"* **Threats:** {', '.join(inv.threats)}")
        out.append(f"* **Enforced in:** {_cell(inv.code)}")
        out.append(f"* **Runtime checks:** {_cell(inv.checks)}")
        if inv.metric:
            out.append(f"* **Evaluation metric:** `{inv.metric}`")
        out.append("* **Proved by:**")
        out += [f"  * `{proof}`" for proof in inv.proofs]
    return "\n".join(out) + "\n"
