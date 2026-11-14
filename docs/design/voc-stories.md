# Vulnerability Operations Center: stories and build order

This page breaks [ADR 0016](../adr/0016-vulnerability-operations-center.md) into stories. Release 1 (the whole
cycle on the cheapest source) is in stories of 2 to 8 points; releases 2 and 3 are epics with one line each.
Points use the backlog's Fibonacci scale; tiers are the roadmap's (T1 docs and UI, T2 domain logic, T3
authorization, tenant isolation, migrations, signing and the AI tool boundary; a human reads every T3 diff).
The acceptance criterion of every story is a named automated test or an artifact that can be checked. The
shared asset inventory comes first.

`docs/roadmap/engineering-backlog.json` is generated and is not edited here; the stories are GitHub issues
labelled `story`, `voc` and `platform`, and enter the backlog at its next sync. Items marked **(uncertain)**
are assumptions the named story confirms.

## Ids, and what this re-scopes

* **New ids.** `VOC1.1` to `VOC1.25` for release 1; `VOC2-A` to `VOC2-J` and `VOC3-A` to `VOC3-H` for the
  epics of releases 2 and 3. The epic id of release 1 is `VOC1`; VOC1.4 teaches the invariant gate that
  pattern.
* **ARCH-E5.1a (cases: table, RLS, dual-write) is re-scoped.** VOC1.15 creates `cases` with a `kind`.
  ARCH-E5.1a to ARCH-E5.1c keep their plan for the incident kind (dual-write from escalations behind a flag,
  backfill, read switch) on the table that then exists.
* **INT3.5 (Wazuh manager-API context) is split.** VOC1.5 takes the agent inventory. Packages, ports and
  vulnerabilities from the server API stay with INT3.5.
* **AI-E4.1 (context pack, #328) shares the asset table.** What it declares about a host is stored on the
  asset row. Whichever of VOC1.1 and AI-E4.1 merges first creates `assets`; the other adopts it.
* **AI-E3.12 (non-investigation route, #355) is unchanged.** With the VOC enabled its hygiene view links to
  the host's findings; `vulnerability-detector` alerts are not turned into findings (VOC1.12).
* **SEC8.5 (third-party register, #364) is extended** to the tools and feeds of ADR 0016 sections 7 and 8, and
  its counsel review to their licence positions.

## Prerequisites outside this breakdown

| Item | State | Needed by | Why |
|---|---|---|---|
| ARCH-E10.1 frontend module model (#376), recorded as ADR 0015 | open | VOC1.23, VOC1.24 | The VOC is the first module registered through the manifest |
| ARCH-E10.2 platform contracts (#377) | open | VOC1.3, VOC1.23 | Entitlements in `GET /auth/me`; tenant in the URL |
| AI-E2.1 tool registry (#193) | open | VOC1.19, VOC1.20 | Both evidence tools run through it |
| INT3.1 Wazuh 4.14 in test-services (#158) | merged | VOC1.5, VOC1.12, VOC1.25 | The live contract tests and the lab run |
| INT3.2 tenant scoping on shared Wazuh clusters (#239) | open | VOC1.5, VOC1.12 | A precondition for enabling either on a cluster shared between customers, not for merging them |
| INT9.3 evidence-fact schema 1.1 (#325) | merged | VOC1.19 | 1.2.0 is a minor bump on it |
| ARCH-E4.1 organisations and grants, with the cross-tenant leak suite (#194) | merged | every story with a route | `Access(no_grant=True)`, dual audit, the leak suite |
| PRD-8.3 four-eyes (#234) | open | VOC1.18 | Reused for the approval if merged; otherwise VOC1.18 carries the check itself |
| PRD-2.10 approval inbox (#375) | open | VOC1.24 | The inbox the exception requests appear in |
| SEC8.6 regulatory positions memo (#365) | open | VOC1.22 | The legal default for record retention; a judgement default until then |

## Build order

| # | Id | Title | Tier | Pts | Depends on | Issue |
|---|---|---|---|---|---|---|
| 1 | VOC1.1 | Platform asset inventory: tables, identity rules and the alert resolver | T3 | 5 | none | #383 |
| 2 | VOC1.2 | Asset API: declared criticality, exposure and owner; alert-to-asset links | T3 | 5 | VOC1.1 | #384 |
| 3 | VOC1.3 | Entitlement `voc`, per-tenant asset quota and tier flags | T3 | 5 | VOC1.1, ARCH-E10.2 (#377) | #385 |
| 4 | VOC1.4 | Register the VOC invariants as pending and set the module boundary | T2 | 3 | none | #386 |
| 5 | VOC1.5 | Wazuh agent inventory as the first asset source | T3 | 5 | VOC1.1, VOC1.3 | #387 |
| 6 | VOC1.6 | Shared reference schema `vulnref` and feed snapshots | T3 | 5 | VOC1.4 | #388 |
| 7 | VOC1.7 | Feed engine with CISA KEV and EPSS, behind sanity gates | T3 | 5 | VOC1.6 | #389 |
| 8 | VOC1.8 | CVE records: aliases and CVSS vectors from the CNA and the CISA ADP, never from NVD | T2 | 5 | VOC1.6, VOC1.7 | #390 |
| 9 | VOC1.9 | Advisory channels: vendor CSAF, CERT-Bund and CERT-FR | T2 | 5 | VOC1.7 | #391 |
| 10 | VOC1.10 | Signed feed bundle for air-gapped sites; the age of the feed on every score | T3 | 5 | VOC1.7 | #392 |
| 11 | VOC1.11 | Canonical finding (OCSF 2002 subset) and the findings store with deduplication | T3 | 8 | VOC1.1 | #393 |
| 12 | VOC1.12 | Wazuh vulnerability findings connector with scan runs and coverage | T3 | 8 | VOC1.5, VOC1.11 | #394 |
| 13 | VOC1.13 | Deterministic priority and score with stored inputs; per-tenant SLA policy | T3 | 5 | VOC1.2, VOC1.7, VOC1.8, VOC1.11 | #395 |
| 14 | VOC1.14 | Advisory log: what each new KEV entry and CERT advisory meant for the tenant | T2 | 3 | VOC1.9, VOC1.11 | #396 |
| 15 | VOC1.15 | Case kernel with the remediation state machine; grouping by fix; SLA sweep | T3 | 8 | VOC1.11, VOC1.13 | #397 |
| 16 | VOC1.16 | Remediation tickets (Jira, ServiceNow) through the outbox | T3 | 5 | VOC1.15 | #398 |
| 17 | VOC1.17 | Verification by rescan: fixed only on scan evidence with coverage | T3 | 5 | VOC1.12, VOC1.15 | #399 |
| 18 | VOC1.18 | Exceptions: second-person approval, review date and expiry, in the approval inbox | T3 | 8 | VOC1.11, VOC1.13 | #400 |
| 19 | VOC1.19 | Evidence tool `voc.exposure_context:1` and evidence-fact schema 1.2 | T3 | 5 | AI-E2.1 (#193), VOC1.2, VOC1.12, VOC1.13 | #401 |
| 20 | VOC1.20 | Evidence tool `soc.alert_context:1`, with alerts indexed by CVE | T3 | 5 | AI-E2.1 (#193), VOC1.11, VOC1.19 | #402 |
| 21 | VOC1.21 | SOC item for exploited, exposed and unpatched findings, and nothing else | T3 | 5 | VOC1.13, VOC1.17 | #403 |
| 22 | VOC1.22 | Evidence pack: the NIS2 and DORA records per tenant, sealed | T2 | 8 | VOC1.12, VOC1.13, VOC1.14, VOC1.15, VOC1.17, VOC1.18 | #404 |
| 23 | VOC1.23 | Console: the shared Assets page and the VOC module with Findings | T1 | 8 | ARCH-E10.1 (#376), ARCH-E10.2 (#377), VOC1.2, VOC1.3, VOC1.13 | #405 |
| 24 | VOC1.24 | Console: Remediation, Exceptions, the report tab and the alert cross-link | T1 | 8 | VOC1.23, VOC1.15, VOC1.18, VOC1.19, VOC1.22 | #406 |
| 25 | VOC1.25 | Lab run: the eight steps on the Wazuh lab, measured; operator documentation | T2 | 3 | VOC1.12, VOC1.17, VOC1.21, VOC1.22 | #407 |

**140 points** in 25 stories; 17 are T3 (97 points). At the plan's 12 T3 points per wave the T3 stories are
the critical path. Suggested grouping (each group needs the previous ones; within a group the stories run in
parallel): A {1.1, 1.4}, B {1.2, 1.3, 1.6, 1.11}, C {1.5, 1.7}, D {1.8, 1.9, 1.10, 1.12}, E {1.13, 1.14}, F
{1.15, 1.18, 1.19}, G {1.16, 1.17, 1.20, 1.23}, H {1.21, 1.22}, I {1.24, 1.25}.

What each step of the cycle rests on: inventory VOC1.1, 1.2, 1.5; scanning and ingestion VOC1.12;
normalisation and deduplication VOC1.11; prioritisation VOC1.6 to 1.10 and 1.13; remediation VOC1.15, 1.16;
verification VOC1.17; exceptions VOC1.18; reporting and governance VOC1.14, 1.22. The two evidence tools are
VOC1.19 and 1.20, the SOC interface VOC1.21, packaging VOC1.3, the console VOC1.23 and 1.24.

## Release 1 stories

### 1. VOC1.1: Platform asset inventory: tables, identity rules and the alert resolver (T3, 5 points, #383)

**Why.** There is no asset object today: a host is a string in an alert's entities. Findings, criticality,
owners, the context pack and billing all need one row per machine, and the SOC and the VOC must read the same
row. The asset belongs to the platform, not to the VOC.

**Scope.**

* Migration (next free number): `assets` and `asset_identifiers` under forced RLS; both added to
  `TENANT_TABLES`, `ALL_TABLES`, the tenant export and the tenant erasure.
* `lg_sotf.domain.assets`: identifier kinds and strengths and the five resolution rules of ADR 0016 section
  2.2 as pure functions; `AssetStatus`, `Criticality` and `Exposure` in `lg_sotf.models.vocabulary` with
  matching `CHECK` constraints.
* `lg_sotf.db.repos.assets`; `lg_sotf.services.assets`: `observe()` (upsert an observation from an
  authoritative source), `merge()` and `split()`, audited, with a tombstone on merge.
* `AssetResolver.for_alert(alert)`: hosts by equality on the `normalize_host` form, addresses by an `ip`
  identifier valid at the alert's time. It never creates an asset.

**Acceptance.**

* `tests/unit/domain/test_assets.py::test_a_strong_identifier_resolves_to_one_asset`
* `tests/unit/domain/test_assets.py::test_a_weak_match_never_attaches_a_second_live_strong_identifier`
* `tests/unit/domain/test_assets.py::test_an_address_links_and_never_merges`
* `tests/integration/services/test_assets.py::test_merge_keeps_a_tombstone_and_is_audited`
* `tests/integration/services/test_assets.py::test_a_host_seen_in_an_alert_never_creates_an_asset`
* `tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy` and
  `tests/integration/db/test_rls.py` cover both tables
* `tests/unit/compliance/test_tenant_data.py` covers both tables in export and erasure

**Depends on.** none.

**Out of scope.** The API and the page (VOC1.2, VOC1.23); the Wazuh import (VOC1.5).

**Threat note.** TM-VOC-2, TM-VOC-11.

### 2. VOC1.2: Asset API: declared criticality, exposure and owner; alert-to-asset links (T3, 5 points, #384)

**Why.** Priority and the SOC's never-close decisions depend on what a person declared about an asset. A
declaration must name its author, come up for review, and not be changeable by the provider.

**Scope.**

* `/api/v1/assets`: list (keyset pagination, filters), get (identifiers, attributes with their provenance),
  create by hand, `PATCH` of declared attributes (criticality, exposure, owner, environment,
  `supports_critical_function`, tags), merge and split.
* Declarations need the admin role and are refused under a grant (`Access(role="admin", no_grant=True)`). Each
  stores author, time and a review date at most 365 days ahead. An overdue review fails towards caution: a
  cautious value stays and is listed, a lenient one falls back.
* `GET /api/v1/alerts/{id}/assets`: the assets an alert's hosts and addresses resolve to, and how each
  resolved. `GET /api/v1/assets/unresolved-hosts`: hosts the SOC saw in the last 30 days that are not in the
  inventory (from `indicator_sightings`).
* OpenAPI snapshot regenerated.

**Acceptance.**

* `tests/integration/api/test_assets.py::test_declarations_need_admin_and_are_refused_under_a_grant`
* `tests/integration/api/test_assets.py::test_every_declaration_is_audited_with_author_and_review_date`
* `tests/unit/domain/test_assets.py::test_an_overdue_review_keeps_a_cautious_value_and_drops_a_lenient_one`
* `tests/integration/api/test_assets.py::test_alert_assets_say_how_each_host_resolved`
* `tests/integration/api/test_cross_tenant_leak.py` covers the new routes
* The API contract check is green with the regenerated `docs/openapi.json`

**Depends on.** VOC1.1.

**Out of scope.** Pattern declarations (`dc-*`), which stay context-pack rules of AI-E4.1 (#328); CSV import.

**Threat note.** TM-VOC-2, TM-VOC-11.

### 3. VOC1.3: Entitlement `voc`, per-tenant asset quota and tier flags (T3, 5 points, #385)

**Why.** The VOC is sold per tenant, by asset band and tier. The check must be on the server for every route
and job, an ended entitlement must keep the customer's audit records readable, and a quota must never drop an
asset the SOC needs.

**Scope.**

* Migration: `tenants.entitlements JSONB` and `tenants.max_assets`, written only through a platform-admin
  function, as the existing quotas are; `usage_daily.voc_assets_in_scope`.
* `lg_sotf.domain.entitlements`: a typed reader (`tier`, `sync_interval`, `scope`, `reporting`,
  `custom_policy`, `assistant`) that enables nothing on a malformed document.
* `require_module("voc")` on every VOC router; scheduler jobs skip unentitled tenants; an ended entitlement
  makes the routes read-only and keeps the records and the evidence pack.
* `in_voc_scope` is assigned within the quota. An asset over the quota is inventoried and reported as
  `out_of_quota`; nothing already in scope is dropped.
* `GET /auth/me` lists the tenant's modules, under the contract of ARCH-E10.2.

**Acceptance.**

* `tests/integration/api/test_voc_entitlement.py::test_every_voc_route_refuses_an_unentitled_tenant`
  (generated over the routers)
* `tests/integration/api/test_voc_entitlement.py::test_an_ended_entitlement_is_read_only_and_keeps_the_records`
* `tests/integration/services/test_assets.py::test_an_asset_over_the_quota_is_inventoried_but_out_of_scope`
* `tests/integration/api/test_platform.py::test_only_a_platform_admin_sets_entitlements_and_max_assets`
* `tests/unit/domain/test_entitlements.py::test_a_malformed_document_enables_nothing`

**Depends on.** VOC1.1, ARCH-E10.2 (#377).

**Out of scope.** The install licence file (GTM1.5, #252), which becomes an upper bound when it exists;
billing.

**Threat note.** TM-VOC-12.

### 4. VOC1.4: Register the VOC invariants as pending and set the module boundary (T2, 3 points, #386)

**Why.** ADR 0016 section 11 promises seven invariants for release 1. Registered now, each with the story that
delivers its proof, the CI gate shows what is still open, and no story can forget one.

**Scope.**

* Add the seven release 1 invariants to `lg_sotf.invariants.registry` as `pending`, each with its delivering
  story, its `TM-VOC-*` rows and one skipped proving test in `tests/invariants/` that the delivering story
  un-skips. Regenerate `docs/invariants.md`.
* `tests/deploy/test_invariants.py`: `EPIC_RE` and `STORY_RE` accept `VOC` ids.
* An import-linter contract: SOC packages import no `voc` sub-package and the reverse, except through named
  ports; `tests/unit/architecture/test_voc_boundaries.py` for what import-linter cannot say.

**Acceptance.**

* `tests/deploy/test_invariants.py` is green with seven pending invariants that each name a `VOC1.x` story
* `python scripts/export_invariants.py` leaves `docs/invariants.md` unchanged after the commit
* `make import-lint` is green with the new contract
* `tests/unit/architecture/test_voc_boundaries.py::test_soc_packages_import_no_voc_package`

**Depends on.** none.

**Out of scope.** Any proof (each invariant's own story).

### 5. VOC1.5: Wazuh agent inventory as the first asset source (T3, 5 points, #387)

**Why.** The agents on SOC customers' hosts are the cheapest inventory there is, and an agent's status is the
coverage record the fix rule needs. Today's connector reads the indexer only, which lists no agents. This
absorbs the agent inventory part of INT3.5.

**Scope.**

* A read-only client for the Wazuh server API on the tenant's existing Wazuh source (`config.manager_url`;
  credentials in the source's encrypted secret), through `lg_sotf.net`; `GET` only. The endpoints are
  confirmed on the 4.14 lab container.
* An `AssetSource` port; `WazuhAgents` maps agents to asset observations: strong identifier `wazuh_agent`,
  host name, addresses, operating system, groups, status and last keep-alive.
* A scheduler job per entitled tenant at its `sync_interval`. A shared source without a scope is refused. An
  agent that is removed or silent for 30 days makes the asset `inactive`; nothing is deleted.
* Documentation of the read-only role the server API user needs.

**Acceptance.**

* `tests/unit/ingestion/voc/test_wazuh_agents.py::test_only_get_requests_leave_the_client`
* `tests/unit/ingestion/voc/test_wazuh_agents.py::test_a_shared_source_without_a_scope_is_refused`
* `tests/live/wazuh/test_wazuh_inventory.py::test_lab_agents_become_assets_with_status_and_keepalive`
* `tests/integration/runtime/test_scheduler.py::test_the_asset_sync_skips_unentitled_tenants`
* `tests/unit/net/test_egress_allowlist.py` covers the manager URL

**Depends on.** VOC1.1, VOC1.3. Relates to INT3.2 (#239).

**Out of scope.** Packages, ports and vulnerabilities from the server API; Wazuh 5.x inventory indices.

**Threat note.** TM-VOC-1, TM-VOC-2. Before use on a cluster shared between customers, INT3.2 (#239) must be
merged.

### 6. VOC1.6: Shared reference schema `vulnref` and feed snapshots (T3, 5 points, #388)

**Why.** Advisory and feed data is the same for every tenant and too large to copy per tenant. It is the first
tenant-less data in a schema where every table is under a tenant policy, so it needs its own rule, enforced by
the database and by a test.

**Scope.**

* Migration: schema `vulnref` with `feed_snapshots`, `vulnerabilities`, `vuln_aliases`, `cvss_vectors`,
  `epss_scores`, `kev_entries`, `advisories`, `advisory_vulns`. No `tenant_id` column. Forced RLS with
  `shared_read` (select for all) and `owner_write` (`lgsotf_rls_bypass()`). The runtime role gets `USAGE` and
  `SELECT` only.
* `lg_sotf.db.posture` and `lg-sotf verify-invariants` gain a shared-table check; the test support module
  knows the schema.
* `lg_sotf.db.repos.feeds`: stage, validate, activate, reject and supersede a snapshot in one `system_tx`; an
  active snapshot is immutable.
* Invariant "shared reference tables hold no tenant data and the runtime role cannot write them" moves to
  enforced.

**Acceptance.**

* `tests/integration/db/test_shared_tables.py::test_shared_tables_have_no_tenant_column_and_forced_rls`
* `tests/integration/db/test_shared_tables.py::test_the_runtime_role_cannot_write_a_shared_table`
* `tests/integration/db/test_shared_tables.py::test_no_tenant_table_has_a_foreign_key_into_the_shared_schema`
* `tests/integration/db/test_shared_tables.py::test_a_rejected_snapshot_never_becomes_active`
* `tests/integration/runtime/test_verify_invariants.py::test_a_writable_shared_table_fails_the_check`
* `tests/unit/compliance/test_tenant_data.py::test_export_and_erasure_never_touch_the_shared_schema`

**Depends on.** VOC1.4.

**Out of scope.** Any importer (VOC1.7 to VOC1.9).

**Threat note.** TM-VOC-2, TM-VOC-3.

### 7. VOC1.7: Feed engine with CISA KEV and EPSS, behind sanity gates (T3, 5 points, #389)

**Why.** KEV (CC0) and EPSS (free, attribution requested) are the two inputs that separate what is being
exploited from what merely scores high. Every tenant's priorities read them, so a tampered or broken download
must change nothing.

**Scope.**

* `lg_sotf.services.feeds`: one path for every feed (fetch, staged snapshot with its hash, schema validation,
  sanity gates, activation). Hosts are module constants, never configuration; requests go through
  `lg_sotf.net` with size caps.
* Importers for KEV (JSON, every 6 hours) and EPSS (daily file). Gates: the KEV count may not fall by more
  than 5%; the EPSS count may not change by more than 10%; a KEV entry's disappearance needs two snapshots at
  least 24 hours apart.
* Scheduler job `feeds.refresh` under the leader lease, as the schema owner; feed age and rejected-snapshot
  metrics; `lg-sotf feeds status`.
* The EPSS attribution text in one constants module used by the API and the reports.

**Acceptance.**

* `tests/unit/services/feeds/test_gates.py::test_a_snapshot_that_drops_kev_entries_is_rejected_and_the_previous_stays_active`
* `tests/unit/services/feeds/test_gates.py::test_a_kev_removal_needs_two_snapshots_a_day_apart`
* `tests/unit/services/feeds/test_importers.py::test_feed_hosts_are_constants_and_never_configuration`
* `tests/unit/services/feeds/test_importers.py::test_kev_and_epss_fixtures_import_with_source_version_and_hash`
* `tests/integration/runtime/test_scheduler.py::test_the_feed_job_runs_only_on_the_leader`
* `tests/unit/architecture/test_shadow_egress.py` stays green: the fetchers are registered egress boundaries

**Depends on.** VOC1.6.

**Out of scope.** CVE records and advisories (VOC1.8, VOC1.9); the offline bundle (VOC1.10).

**Threat note.** TM-VOC-3.

### 8. VOC1.8: CVE records: aliases and CVSS vectors from the CNA and the CISA ADP, never from NVD (T2, 5 points, #390)

**Why.** NIST stopped enriching most CVEs in April 2026, so the CVSS vector must come from the CNA or the
vendor. The CVE list carries the CNA's vector, and since record format 5.2 the package URLs that release 2
matches on.

**Scope.**

* Importer for the CVE list (`cvelistV5`): a baseline and deltas (the mechanism is confirmed here), reading
  id, state, dates, title, aliases, the CNA and ADP metrics, and package URLs (stored for release 2).
* `cvss_vectors` rows per version, source kind and source name. CISA Vulnrichment is the ADP source where the
  CVE list does not already carry it.
* `lg_sotf.domain.voc.cvss`: syntax validation of 3.0, 3.1 and 4.0 vectors; the base score is the one the
  source states.
* The CVSS attribution text (FIRST) next to the EPSS one.

**Acceptance.**

* `tests/unit/services/feeds/test_cve_records.py::test_cna_and_adp_vectors_are_stored_with_their_source`
* `tests/unit/services/feeds/test_cve_records.py::test_no_importer_requests_an_nvd_host`
* `tests/unit/services/feeds/test_cve_records.py::test_a_rejected_or_reserved_record_yields_no_vector`
* `tests/unit/services/feeds/test_cve_records.py::test_a_delta_applies_on_top_of_the_baseline`
* `tests/unit/domain/voc/test_cvss.py::test_malformed_vectors_are_refused_for_each_version`
* Artifact: `docs/voc.md`, section Feeds, states the update mechanism and what a Vulnrichment record carries,
  as confirmed

**Depends on.** VOC1.6, VOC1.7.

**Out of scope.** Matching packages against the inventory (release 2); computing a score from a vector.

**Threat note.** TM-VOC-3.

### 9. VOC1.9: Advisory channels: vendor CSAF, CERT-Bund and CERT-FR (T2, 5 points, #391)

**Why.** NIS2 asks entities to monitor vulnerability information from CSIRTs and suppliers and to keep the
list of channels under review. Vendor CSAF also gives the vendor's own CVSS for its products, which ranks
first among the score's sources.

**Scope.**

* A CSAF 2.0 reader (provider metadata, then the feed or directory), validated against the CSAF schema. Red
  Hat and Microsoft as vendor sources of CVSS (`source_kind = vendor`) and of `advisories`; VEX statements are
  stored for release 2 and not applied.
* CERT-Bund CSAF: TLP:WHITE only, text stored and shown verbatim. CERT-FR: ids, dates, the CVE list and the
  link only.
* The terms of Microsoft's and CERT-FR's data are read and recorded in the third-party register (SEC8.5,
  #364). A channel whose terms do not allow the use stays off.
* `GET /api/v1/voc/advisories` and the channel list with each channel's last retrieval.

**Acceptance.**

* `tests/unit/services/feeds/test_csaf.py::test_a_document_that_fails_the_csaf_schema_is_rejected`
* `tests/unit/services/feeds/test_csaf.py::test_only_tlp_white_documents_are_stored`
* `tests/unit/services/feeds/test_csaf.py::test_certbund_text_is_stored_byte_for_byte`
* `tests/unit/services/feeds/test_csaf.py::test_vendor_vectors_are_stored_with_source_kind_vendor`
* `tests/unit/services/feeds/test_certfr.py::test_only_ids_dates_cves_and_the_link_are_stored`
* Artifact: a register entry per channel with its licence and attribution

**Depends on.** VOC1.7.

**Out of scope.** Applying VEX to findings; matching advisories to the software inventory (release 2).

**Threat note.** TM-VOC-3, TM-VOC-6.

### 10. VOC1.10: Signed feed bundle for air-gapped sites; the age of the feed on every score (T3, 5 points, #392)

**Why.** KEV, EPSS, the CVE list and the advisories change daily, and an air-gapped site cannot fetch them.
Without a verified import its priorities silently age. The operator builds the bundle from the original
sources, so the vendor redistributes no third-party data.

**Scope.**

* `lg-sotf feeds keygen`, `export`, `import` and `status`. Bundle format `lg-sotf.feed-bundle` version 1: the
  original files unmodified, `manifest.json`, and an Ed25519 signature over the canonical manifest
  (`lg_sotf.compliance.canonical`).
* `feeds.bundle_public_keys`, `feeds.max_age_days` and `feeds.online` in `lg_sotf.settings`, validated at
  start-up.
* Import refuses a bad signature, a file the manifest does not list, a path outside the bundle and a bundle
  older than the active snapshots (an audited `--allow-older` exists), then runs the gates of VOC1.7.
* One function computes `feed_as_of` and `stale` for every score response.
* `docs/air-gapped.md` gains the feed section.

**Acceptance.**

* `tests/unit/services/feeds/test_bundle.py::test_a_bad_signature_an_unlisted_file_or_a_path_escape_is_refused`
* `tests/unit/services/feeds/test_bundle.py::test_an_older_bundle_is_refused_without_the_audited_override`
* `tests/unit/services/feeds/test_bundle.py::test_export_then_import_reproduces_the_active_snapshots`
* `tests/unit/test_settings.py::test_a_malformed_bundle_key_stops_start_up`
* `tests/unit/domain/voc/test_feed_age.py::test_feed_as_of_is_the_oldest_input_and_stale_follows_the_limit`
* `tests/invariants/test_voc_feeds.py::test_feed_data_enters_only_as_a_validated_snapshot_or_a_signed_bundle`
  (the invariant moves to enforced)

**Depends on.** VOC1.7.

**Out of scope.** A vendor-signed bundle (needs counsel; ADR 0016 section 7).

**Threat note.** TM-VOC-3; relates to TM-CI-5.

### 11. VOC1.11: Canonical finding (OCSF 2002 subset) and the findings store with deduplication (T3, 8 points, #393)

**Why.** Every scanner must map into one shape, and one weakness on one machine must be one record however
many scanners report it, with the first and last time it was seen. That record is the vulnerability register
DORA asks for.

**Scope.**

* `lg_sotf.models.finding.CanonicalFinding`: a subset of the OCSF Vulnerability Finding class, pinned to one
  OCSF version, with bounded fields, a capped `unmapped` section and `normalizer` set by the service.
  Published as `schemas/vulnerability-finding/v1.json` under `scripts/ci/schema_compat.py`, with examples.
* Migration: `software_components`, `findings`, `finding_detections`, `scan_runs` and `scan_coverage` (monthly
  partitions) under forced RLS, with their vocabulary and `CHECK` constraints.
* `lg_sotf.domain.voc.findings`: `component_key`, the canonical `vuln_id` and `finding_key`, pure.
* `lg_sotf.services.voc.findings.ingest(scan_run, findings, coverage)`: batch upsert, first and last seen, one
  detection row per scanner, reopening of a finding that returns. It never sets `fixed`.
* Read API: `GET /api/v1/voc/findings` (keyset, filters), `/findings/{id}` and `/scan-runs`.

**Acceptance.**

* `tests/unit/models/test_finding.py::test_the_schema_file_matches_the_model` and
  `::test_every_example_validates`; `python scripts/ci/schema_compat.py --base origin/main` checks the new
  schema
* `tests/unit/domain/voc/test_findings.py::test_one_finding_per_asset_vulnerability_and_component_whatever_the_scanner`
* `tests/unit/domain/voc/test_findings.py::test_a_version_change_keeps_the_finding`
* `tests/unit/domain/voc/test_findings.py::test_a_cve_alias_wins_over_the_scanners_own_id`
* `tests/integration/services/voc/test_findings.py::test_ingesting_the_same_run_twice_changes_nothing`
* `tests/integration/services/voc/test_findings.py::test_a_returning_finding_reopens_with_its_first_seen`
* `tests/integration/db/test_migrations.py::test_every_tenant_table_has_forced_rls_and_policy` covers the five
  tables; `tests/integration/api/test_cross_tenant_leak.py` covers the routes

**Depends on.** VOC1.1.

**Out of scope.** Any scanner (VOC1.12); scores (VOC1.13); the fixed rule (VOC1.17).

**Threat note.** TM-VOC-2, TM-VOC-6.

### 12. VOC1.12: Wazuh vulnerability findings connector with scan runs and coverage (T3, 8 points, #394)

**Why.** Wazuh's vulnerability alerts are lossy by its own documentation (none on the first scan, none for
changes while the agent was stopped). Its state index says what is vulnerable now, which is what a register
and a fix check need. Coverage must be recorded with every read, or an absent finding means nothing.

**Scope.**

* A `FindingSource` port; `WazuhVulnerabilityState` reads the state index for the tenant's scope: `POST
  /<index>/_search` only, point in time and `search_after`, a field allow list and a mandatory scope filter.
  Failed shards or a timeout make the run `partial`.
* A mapper from the state document to `CanonicalFinding`; the field names are confirmed on the lab container;
  `under_evaluation` is carried.
* One `scan_runs` row per sync, with `scan_coverage` for every in-scope asset from the agent status of VOC1.5
  (active, recent keep-alive, supported operating system).
* A scheduler job at the tenant's `sync_interval`, with a per-tenant concurrency limit and a circuit breaker.
  `vulnerability-detector` alerts are not turned into findings.

**Acceptance.**

* `tests/unit/ingestion/voc/test_wazuh_state.py::test_only_search_requests_with_the_tenant_scope_are_sent`
* `tests/unit/ingestion/voc/test_wazuh_state.py::test_failed_shards_or_a_timeout_make_the_run_partial`
* `tests/unit/ingestion/voc/test_wazuh_state.py::test_state_fixtures_map_to_valid_canonical_findings`
* `tests/live/wazuh/test_wazuh_vulnerabilities.py::test_a_vulnerable_lab_package_becomes_one_finding_with_coverage`
* `tests/integration/services/voc/test_sync.py::test_an_agent_without_a_recent_keepalive_is_recorded_as_not_covered`
* `tests/integration/services/voc/test_sync.py::test_two_tenants_on_one_cluster_never_see_each_others_findings`

**Depends on.** VOC1.5, VOC1.11. Relates to INT3.2 (#239).

**Out of scope.** Wazuh 5.x (a second implementation behind the same ports); the full package inventory.

**Threat note.** TM-VOC-1, TM-VOC-2. Before use on a cluster shared between customers, INT3.2 (#239) must be
merged.

### 13. VOC1.13: Deterministic priority and score with stored inputs; per-tenant SLA policy (T3, 5 points, #395)

**Why.** EPSS reaches about the same coverage of exploited vulnerabilities as "patch everything with CVSS 7 or
higher" with about one eighth of the effort, by its maintainers' figures, and LLMs asked for severity
over-predict in every model tested. So the score is a pure function of KEV, EPSS, CVSS, criticality and
exposure, and an auditor can read which value drove any decision.

**Scope.**

* `lg_sotf.domain.voc.priority`: typed inputs and `assess(inputs, policy)` with the rules, the score and the
  unknown handling of ADR 0016 section 5.1. It imports nothing from `lg_sotf.llm` or `lg_sotf.agents`.
* `lg_sotf.domain.voc.policy`: the policy model with defaults and bounds. Migration: `voc_policies` and
  `finding_scores`, both append-only, under forced RLS.
* `lg_sotf.services.voc.scoring`: gathers each input with its source, version, date and snapshot id (CVSS
  precedence: vendor, CNA, ADP, scanner), writes a score row only when something changed, and sets priority,
  score and `due_at` by the deadline rules of section 5.2. It runs when a snapshot activates, an asset
  attribute changes or the policy changes.
* API: `GET /api/v1/voc/findings/{id}/scores` (history with inputs and `feed_as_of`); `GET` and `PUT
  /api/v1/voc/policy` (admin, refused under a grant, behind the `custom_policy` flag).

**Acceptance.**

* `tests/unit/domain/voc/test_priority.py::test_priority_never_falls_when_an_input_gets_worse` (property test)
* `tests/unit/domain/voc/test_priority.py::test_an_unknown_input_never_lowers_the_result`
* `tests/unit/domain/voc/test_priority.py::test_the_default_rules_match_adr_0016`
* `tests/invariants/test_voc_scores.py::test_the_score_module_imports_no_model_code`
* `tests/invariants/test_voc_scores.py::test_a_stored_score_recomputes_from_its_inputs`
* `tests/invariants/test_voc_scores.py::test_every_input_names_source_version_date_and_snapshot`
* `tests/integration/services/voc/test_scoring.py::test_a_due_date_moves_later_only_by_exception_or_policy_change`
* `tests/integration/services/voc/test_scoring.py::test_a_new_kev_entry_writes_one_new_score_row_per_affected_finding`
* `tests/integration/api/test_voc_policy.py::test_a_policy_change_needs_admin_is_refused_under_a_grant_and_keeps_every_version`

**Depends on.** VOC1.2, VOC1.7, VOC1.8, VOC1.11.

**Out of scope.** Observed exploitation and measured exposure as inputs (release 2).

**Threat note.** TM-VOC-6. Two invariants move to enforced: no model output in the score; every score stored
with its inputs.

### 14. VOC1.14: Advisory log: what each new KEV entry and CERT advisory meant for the tenant (T2, 3 points, #396)

**Why.** ENISA lists "records of alerts or notifications received from monitoring channels about new
vulnerabilities, including how these alerts were handled" as evidence for NIS2 point 6.10. The record must be
written when the advisory arrives, not rebuilt afterwards.

**Scope.**

* Migration: `advisory_log` under forced RLS.
* When a KEV or advisory snapshot activates, each entitled tenant gets one row per new advisory: the open
  findings that match by CVE and the handling (`no_matching_finding`, `findings_prioritised`), with the
  coverage it was judged on. An analyst may add `acknowledged` with a note.
* `GET /api/v1/voc/advisory-log`.

**Acceptance.**

* `tests/integration/services/voc/test_advisory_log.py::test_a_new_kev_entry_writes_one_row_per_tenant_with_its_matches`
* `tests/integration/services/voc/test_advisory_log.py::test_an_advisory_is_logged_once_per_tenant`
* `tests/integration/db/test_rls.py` covers `advisory_log`

**Depends on.** VOC1.9, VOC1.11.

**Out of scope.** Matching an advisory to software that has no finding (release 2).

### 15. VOC1.15: Case kernel with the remediation state machine; grouping by fix; SLA sweep (T3, 8 points, #397)

**Why.** An escalation is bound to one alert and one workflow thread and cannot hold a remediation. Two
engines would duplicate the SLA clock, ownership, tickets and the cross-tenant queue. ADR 0016 section 2.3
decides one `cases` table with a kind and one transition table per kind, built beside the escalation and not
by changing it.

**Scope.**

* Migration: `cases` (`kind`, a per-tenant key, a status `CHECK` per kind, `version`), `case_events` and
  `case_findings`, under forced RLS.
* `lg_sotf.domain.cases`: the transition tables for `remediation` and for the reserved `incident` kind.
  `lg_sotf.db.repos.cases` with the guarded update; `lg_sotf.services.cases` (open, assign, transition, close)
  with audit and `case.*` events.
* `lg_sotf.services.voc.remediation`: grouping by component and fixed version (or update id; without a fix, by
  vulnerability), split by owner; the case's `due_at` is its findings' earliest deadline; findings join and
  leave as they appear and are fixed.
* A scheduler SLA sweep for cases: an overdue case is audited once (`case.sla_breached`) and notified through
  the existing channels.
* API `/api/v1/voc/remediations`: list, get, assign, transition, comment; the fields `change_reference` and
  `tested`.

**Acceptance.**

* `tests/unit/domain/test_cases.py::test_each_kind_allows_only_its_own_statuses_and_transitions`
* `tests/unit/domain/test_cases.py::test_no_requested_transition_reaches_closed_as_verified`
* `tests/integration/services/voc/test_remediation.py::test_findings_with_one_fix_and_one_owner_form_one_case`
* `tests/integration/services/voc/test_remediation.py::test_a_stale_version_loses_with_a_conflict`
* `tests/integration/runtime/test_scheduler.py::test_an_overdue_case_is_audited_once`
* `tests/integration/db/test_migrations.py::test_check_constraints_reject_unknown_enum_values` covers `cases`
* `tests/integration/api/test_grant_writes.py` covers assign and transition under an analyst grant (one entry
  in each audit chain)

**Depends on.** VOC1.11, VOC1.13.

**Out of scope.** The incident kind and any change to `escalations` (ARCH-E5.1a to ARCH-E5.1c); tickets
(VOC1.16).

**Threat note.** TM-VOC-2.

### 16. VOC1.16: Remediation tickets (Jira, ServiceNow) through the outbox (T3, 5 points, #398)

**Why.** IT operations work in their ticket system, not in a security console. The platform already creates
and follows tickets for escalations; a remediation case needs the same link, and a resolved ticket must not be
mistaken for a fixed vulnerability.

**Scope.**

* Migration: `external_tickets.case_id` (nullable), `alert_id` made nullable, a `CHECK` that exactly one
  anchor is set, and one ticket per case and integration.
* `ticket_create` and `ticket_update` for a case from a deterministic template (the fix, the affected assets,
  the due date, the link); the `lg-sotf.event.v1` summary gains the case shape.
* Ticket sync: a resolved ticket moves the case to `fix_reported`, a reopened one moves it back. It never
  changes a finding.

**Acceptance.**

* `tests/integration/integrations/test_case_tickets.py::test_one_ticket_per_case_and_integration`
* `tests/integration/integrations/test_case_tickets.py::test_a_resolved_ticket_reports_the_fix_and_leaves_the_findings_open`
* `tests/integration/db/test_migrations.py::test_a_ticket_has_exactly_one_anchor`
* `tests/integration/integrations/test_outbox.py` stays green unchanged (alert tickets)
* `tests/unit/architecture/test_shadow_egress.py` stays green

**Depends on.** VOC1.15.

**Out of scope.** AI-drafted ticket text (release 2).

**Threat note.** TM-VOC-7 (a ticket is not evidence).

### 17. VOC1.17: Verification by rescan: fixed only on scan evidence with coverage (T3, 5 points, #399)

**Why.** The closest public study of AI SOC agents found that an empty query result was read as "nothing
happened"; ADR 0014 Amendment 2 made that a rule. The same failure here is a finding that looks fixed because
the agent was offline, the read was partial or the scanner's index was rebuilt.

**Scope.**

* `lg_sotf.domain.voc.verification`: a finding is fixed when it is absent from two consecutive runs that
  covered its asset, at least `voc.fix_confirm_interval` apart, by every scanner that detected it and still
  covers the asset. Partial, failed, uncovered and out-of-scope prove nothing. `stale_since` is set after
  `voc.max_scan_age`.
* The mass-disappearance guard: a run that would fix more than 30% of a tenant's open findings is held until
  an admin releases or discards it.
* Case follow-up: `fix_reported` becomes `closed` (`verified`), or returns to `in_progress` with a
  `verification_failed` event. "Verify now" starts a sync with trigger `verification`.

**Acceptance.**

* `tests/invariants/test_voc_fixed.py::test_a_finding_absent_from_an_uncovered_or_partial_run_stays_open`
* `tests/invariants/test_voc_fixed.py::test_only_verification_writes_the_fixed_status` (over the source tree)
* `tests/unit/domain/voc/test_verification.py::test_fixed_needs_two_covering_runs_an_interval_apart`
* `tests/integration/services/voc/test_verification.py::test_a_run_that_would_fix_a_third_of_the_findings_is_held`
* `tests/integration/services/voc/test_verification.py::test_a_reported_fix_that_a_covering_run_still_finds_reopens_the_case`

**Depends on.** VOC1.12, VOC1.15.

**Out of scope.** Cross-checking an agent's report with a network scanner (release 3, TM-VOC-9).

**Threat note.** TM-VOC-7. The invariant "a finding becomes fixed only on scan evidence" moves to enforced.

### 18. VOC1.18: Exceptions: second-person approval, review date and expiry, in the approval inbox (T3, 8 points, #400)

**Why.** NIS2 point 6.10.3 asks an entity to "document and substantiate the reason why the vulnerability does
not require remediation", and ENISA expects those decisions to be validated by the body responsible for risk.
An exception is therefore a record with a justification, an approver who is not the requester, and a date on
which it ends.

**Scope.**

* Migration: `finding_exceptions` and `exception_findings` under forced RLS; the state machine in
  `lg_sotf.domain.voc.exceptions`.
* `lg_sotf.services.voc.exceptions`: request (an analyst, also under a grant, with the grant recorded); decide
  (admin, not under a grant, not the requester; with a reason and the score rows as they stood); revoke;
  expire by a scheduler sweep, which returns the findings to `open` with their deadlines.
* Bounds: a review date is mandatory, at most 180 days ahead and 30 for an exploited vulnerability; at most
  500 findings per exception.
* API `/api/v1/voc/exceptions`. The approvals read model gains typed items that a module contributes through a
  port; response-action items are unchanged. PRD-8.3's four-eyes mechanism is reused if it has merged.

**Acceptance.**

* `tests/invariants/test_voc_exceptions.py::test_the_requester_cannot_approve`
* `tests/invariants/test_voc_exceptions.py::test_approval_is_refused_under_a_grant_and_below_admin`
* `tests/invariants/test_voc_exceptions.py::test_only_an_approved_exception_sets_excepted`
* `tests/unit/domain/voc/test_exceptions.py::test_a_review_date_is_mandatory_and_tighter_for_an_exploited_vulnerability`
* `tests/integration/services/voc/test_exceptions.py::test_expiry_returns_the_findings_to_open_with_first_seen_and_deadline`
* `tests/integration/api/test_voc_exceptions.py::test_the_approval_inbox_lists_exception_requests_beside_response_actions`
* `tests/integration/api/test_grant_writes.py` covers a request under an analyst grant (both chains)

**Depends on.** VOC1.11, VOC1.13. Relates to PRD-8.3 (#234), PRD-2.10 (#375).

**Out of scope.** Rule-scoped exceptions and vendor VEX applied automatically (release 2); the inbox page
(VOC1.24).

**Threat note.** TM-VOC-8. The exception invariant moves to enforced.

### 19. VOC1.19: Evidence tool `voc.exposure_context:1` and evidence-fact schema 1.2 (T3, 5 points, #401)

**Why.** An analyst or a skill looking at an alert should know whether the host has the weakness the alert is
about, since when, and how old that knowledge is. Stale scan data is the main criticism of combined platforms,
so the fact must say when the asset was last covered.

**Scope.**

* Evidence-fact schema 1.2.0: kinds `exposure_context` and `alert_context`, subject type `vulnerability`;
  examples; `docs/evidence-facts.md`.
* `voc.exposure_context:1` in the tool registry (`read_internal`, egress `platform`, row cap 50). Parameters:
  the alert's detector-written reporting host; optional CVE ids and a package name from detector-written
  fields.
* The fact: the resolved asset with criticality and exposure, open findings by priority, up to 50 matching
  findings, `last_covered_at` and `feed_as_of`. `complete` is false when the host resolves to no asset or to
  several, when coverage is missing or older than `voc.max_scan_age`, or when the list was cut.
* An unentitled tenant's call has outcome `failed`, never `empty`.

**Acceptance.**

* `python scripts/ci/schema_compat.py --base origin/main` accepts 1.2.0 as a minor bump
* `tests/unit/models/test_evidence_fact.py::test_every_kind_has_a_valid_example`
* `tests/unit/tools/voc/test_exposure_context.py::test_missing_or_old_coverage_is_incomplete`
* `tests/unit/tools/voc/test_exposure_context.py::test_only_the_detector_written_reporting_host_is_resolved`
* `tests/unit/tools/voc/test_exposure_context.py::test_an_ambiguous_host_is_incomplete_and_names_no_asset`
* `tests/unit/tools/voc/test_exposure_context.py::test_an_unentitled_tenant_gets_failed_not_empty`
* `tests/unit/tools/test_registry.py` loads the tool with its caps and schema

**Depends on.** AI-E2.1 (#193), VOC1.2, VOC1.12, VOC1.13.

**Out of scope.** Using the fact in a skill's indicators (a skill change with its own scorecard run).

**Threat note.** TM-VOC-11; INV-14 (evidence tools are read-only, templated and capped).

### 20. VOC1.20: Evidence tool `soc.alert_context:1`, with alerts indexed by CVE (T3, 5 points, #402)

**Why.** Whether a vulnerability is being attacked in this tenant is the signal commercial scores approximate
with global threat intelligence. The SOC holds it. It must separate what a person confirmed from what a model
judged, or the models would vouch for each other.

**Scope.**

* Indicator type `cve` in `lg_sotf.domain.indicators`, extracted at ingestion from detector-written fields
  only (never the title or description) and written to `indicator_sightings`. It is not a grouping or
  correlation key.
* `soc.alert_context:1` in the tool registry. Parameters: a CVE id, an optional asset, a window of at most 90
  days. The fact counts the tenant's alerts that name the CVE separately by analyst-confirmed true positive,
  analyst-confirmed benign, model verdict only and undecided, and lists the targeted hosts resolved to assets
  with whether each has the finding open.
* `complete` is false when the window is longer than the tenant's alert retention or the list was cut. `GET
  /api/v1/voc/findings/{id}/alert-context` shows it on finding detail.

**Acceptance.**

* `tests/unit/domain/test_indicators.py::test_cve_ids_come_from_detector_written_fields_only`
* `tests/unit/domain/test_indicators.py::test_cve_sightings_never_group_or_correlate_alerts`
* `tests/unit/tools/voc/test_alert_context.py::test_analyst_decisions_are_counted_apart_from_model_verdicts`
* `tests/unit/tools/voc/test_alert_context.py::test_a_window_longer_than_the_retention_is_incomplete`
* `tests/integration/api/test_voc_findings.py::test_alert_context_never_returns_another_tenants_alerts`

**Depends on.** AI-E2.1 (#193), VOC1.11, VOC1.19.

**Out of scope.** Any signal across tenants; observed exploitation as a score input (release 2).

**Threat note.** TM-VOC-2; INV-14.

### 21. VOC1.21: SOC item for exploited, exposed and unpatched findings, and nothing else (T3, 5 points, #403)

**Why.** Findings in the SOC queue would work against the alert-fatigue goal, and Microsoft split the two as
distinct workflows for different people. One slice does belong to the SOC: a weakness that is being exploited
in the wild, on an internet-facing asset, still open. The question there is whether it was already used.

**Scope.**

* `lg_sotf.domain.voc.top_slice`: exploited, exposure `internet_facing`, status `open`, no approved exception.
* The item is an alert from the reserved source `platform:voc` (normalizer `voc`, `source_alert_id` the
  finding key) in a new never-close class `exposed_exploited_vulnerability` in `lg_sotf.domain.closure`, sent
  to an analyst with the finding's facts.
* At most `voc.soc_items_per_day` (default 20) per tenant, then one summary item. A verified fix cancels an
  open item with an audit entry; an approved exception does not.
* A tenant cannot create a source with the reserved id; the items do not count against `max_alerts_per_day`.

**Acceptance.**

* `tests/unit/domain/voc/test_top_slice.py::test_only_exploited_exposed_open_findings_without_an_exception_qualify`
* `tests/invariants/test_voc_soc_items.py::test_no_other_code_path_turns_a_finding_into_an_alert` (over the
  source tree)
* `tests/invariants/test_voc_soc_items.py::test_the_daily_cap_holds_and_the_overflow_is_one_summary_item`
* `tests/integration/engine/test_voc_soc_item.py::test_no_model_closes_the_item_and_it_reaches_an_analyst`
* `tests/integration/engine/test_voc_soc_item.py::test_a_verified_fix_cancels_the_open_item_and_an_exception_does_not`
* `tests/integration/api/test_sources.py::test_a_tenant_cannot_create_the_reserved_source`

**Depends on.** VOC1.13, VOC1.17. Relates to AI-E3.12 (#355).

**Out of scope.** An investigation skill for the item (later, with its scorecard).

**Threat note.** TM-VOC-10; INV-03 (the new never-close class). The SOC-queue invariant moves to enforced.

### 22. VOC1.22: Evidence pack: the NIS2 and DORA records per tenant, sealed (T2, 8 points, #404)

**Why.** NIS2 Implementing Regulation 2024/2690 (points 6.6 and 6.10) and DORA RTS 2024/1774 Article 10 turn
the cycle into records an auditor asks for. The MSSP is itself in scope as a managed security service
provider, so the same pack on its own tenant serves its own audit.

**Scope.**

* `lg_sotf.compliance.voc.pack`: the eleven records of ADR 0016 section 9 for one tenant and period, each with
  the rule it answers, the statement of what the platform does not produce, the attribution lines and
  `feed_as_of`. JSON and HTML through `lg_sotf.compliance.html`, sealed with
  `lg_sotf.compliance.canonical.seal`, with caps and `limits` as in the case pack.
* `POST /api/v1/voc/evidence-pack` (admin; audited with the digest), `lg-sotf voc-evidence-pack`; `lg-sotf
  evidence-verify` accepts the format.
* `GET /api/v1/voc/reports/summary` for the tenant report's exposure section: open by priority, overdue, time
  to fix P1, exceptions due for review, coverage.

**Acceptance.**

* `tests/unit/compliance/test_voc_pack.py::test_the_pack_holds_every_record_of_adr_0016_section_9_with_its_rule`
* `tests/unit/compliance/test_voc_pack.py::test_a_changed_byte_fails_verification`
* `tests/unit/compliance/test_voc_pack.py::test_every_score_in_the_register_shows_its_inputs_sources_and_feed_age`
* `tests/unit/compliance/test_voc_pack_golden.py::test_the_html_matches_the_golden_file`
* `tests/integration/api/test_voc_reports.py::test_the_export_needs_admin_and_is_audited_with_the_digest`
* `tests/integration/api/test_voc_reports.py::test_weekly_coverage_gaps_of_critical_function_assets_are_listed`

**Depends on.** VOC1.12, VOC1.13, VOC1.14, VOC1.15, VOC1.17, VOC1.18.

**Out of scope.** The CRA record for manufacturers and third-party statistics (release 2); a committee report
(release 3).

**Threat note.** TM-VOC-12; INV-08.

### 23. VOC1.23: Console: the shared Assets page and the VOC module with Findings (T1, 8 points, #405)

**Why.** The VOC is the first module registered through the manifest of ADR 0015, and the proof that a service
plugs in by adding its folder and one registry line. Assets belong to the shell, because the SOC uses them
without the VOC.

**Scope.**

* Shell: an Assets page and asset detail in the shared navigation (identifiers, declared attributes with their
  review dates, merge), outside the VOC module.
* `src/modules/voc/index.ts`: the manifest (navigation group, routes with lazy pages, entitlement key `voc`,
  live-event map, an API slice with namespaced query keys) and one registry line.
* Findings list on the shared data table (priority, score, asset, vulnerability, first seen, due, status;
  filters) and finding detail: the score with every input, its source and its date, **the age of the feed on
  every score**, detections and history.
* A "not enabled for this tenant" state; every string through the message function.

**Acceptance.**

* `src/modules/voc/index.test.ts`: the module registers with one registry line and nothing outside its folder
  imports it (the scaffold test of ARCH-E10.1)
* `src/modules/voc/components/ScoreBadge.test.tsx`: shows each input's source and date, the age of the oldest
  feed, and the stale state
* `e2e/voc.spec.ts`, "an unentitled tenant never downloads the module"
* `e2e/voc.spec.ts`, "findings list and detail", with axe (the page list comes from the registry)
* The bundle budget holds and `coverage-floors.json` has a floor for `modules/voc`

**Depends on.** ARCH-E10.1 (#376), ARCH-E10.2 (#377), VOC1.2, VOC1.3, VOC1.13.

**Out of scope.** Remediation, exceptions and reports pages (VOC1.24).

### 24. VOC1.24: Console: Remediation, Exceptions, the report tab and the alert cross-link (T1, 8 points, #406)

**Why.** The cycle ends with a person assigning a fix, a second person accepting a risk, and an auditor
reading the record. The two services meet in two places only: the alert shows exposure, and the approval inbox
shows exception requests.

**Scope.**

* Remediation list and case page: findings, owner, due date, ticket, timeline and verification state; assign,
  report a fix, verify now.
* Exceptions: a request dialog (kind, justification, compensating measure, review date) and a register page
  with the reviews that are due. Exception requests appear in the Approvals page as a second item type, with
  the reason field.
* An `alert.entity` slot component ("3 open findings, 1 P1, last covered 2 hours ago"; an incomplete fact is
  shown as "not verified since"); related alerts on finding detail through the SOC's `public.ts`.
* A `reports.tabs` contribution with the exposure section, and the evidence pack export for admins.

**Acceptance.**

* `e2e/voc.spec.ts`, "from finding to verified fix": case, ticket, fix reported, two covering runs, closed as
  verified
* `e2e/voc.spec.ts`, "an exception needs a second admin": the requester has no approve control; a second admin
  approves from the inbox
* `src/modules/voc/slots/AlertExposure.test.tsx`: renders nothing without the module, and "not verified since"
  for an incomplete fact
* The ESLint boundary rule is green: the VOC imports the SOC only through `public.ts`
* axe is clean on the three pages and the two dialogs

**Depends on.** VOC1.23, VOC1.15, VOC1.18, VOC1.19, VOC1.22. Relates to PRD-2.10 (#375).

**Out of scope.** The cross-tenant VOC view for the MSSP (release 3).

### 25. VOC1.25: Lab run: the eight steps on the Wazuh lab, measured; operator documentation (T2, 3 points, #407)

**Why.** Wazuh's Windows and macOS matching relies on NVD, which stopped enriching most CVEs. What release 1
really detects must be measured and published per operating-system family, not assumed, before any tenant is
told it is covered.

**Scope.**

* A scripted run on the Wazuh 4.14 lab with seeded vulnerable packages on the operating systems the lab has.
  It measures assets, findings, deduplication, coverage per operating-system family, a canary of third-party
  packages with recent CVEs on Windows (detected or not), and the time from a fix to `verified`.
* `docs/scorecards/voc/r1-lab/RUN.md` with the numbers and the method.
* `docs/voc.md`: setup, the read-only Wazuh roles, the limits, feeds and the air gap, the policy, exceptions
  and the evidence pack; linked from `docs/index.md`; changelog fragment.
* Threat-model rows TM-VOC-1 to TM-VOC-12 move to *In place* or *Partial* with `path:line` references; no
  release 1 invariant is left `pending`.

**Acceptance.**

* Artifact: `docs/scorecards/voc/r1-lab/RUN.md` with the coverage table per operating-system family and the
  canary result
* `tests/deploy/test_security_docs.py` is green with the updated rows
* `tests/deploy/test_invariants.py`: no invariant owned by `VOC1` is `pending`
* Artifact: `docs/voc.md` linked from `docs/index.md`

**Depends on.** VOC1.12, VOC1.17, VOC1.21, VOC1.22.

**Out of scope.** A design partner's data (a calendar event, not a story).

## Release 2: outside view and software composition (epics)

| Epic | Content |
|---|---|
| VOC2-A | External discovery and measured exposure: Subfinder, Naabu and httpx in a sandboxed scanner role, with proof of control for every target (TM-VOC-4, TM-VOC-5). |
| VOC2-B | Template checks with Nuclei from an allow-list of non-intrusive templates, as findings and as validation of a fix. |
| VOC2-C | SBOM and container scanning: Syft, Trivy or Grype, OSV-Scanner; CycloneDX ingestion; the full component inventory by package URL. |
| VOC2-D | Own matching: package URLs from CVE 5.2 records and OSV against the inventory; vendor VEX applied; rule-scoped exceptions. |
| VOC2-E | Push endpoint and file import (OCSF 2002 events, Nmap XML the operator produced); deduplication across scanners. |
| VOC2-F | The `watch` tier: advisories matched to the inventory, with a bulletin per tenant. |
| VOC2-G | Assistant tasks, each behind its own scorecard: false-positive check, grouping proposals, ticket and report drafts; trace store for runs that have no alert. |
| VOC2-H | Two more score inputs: exploitation an analyst confirmed in this tenant, and exposure as measured. |
| VOC2-I | CRA record for manufacturers: SBOMs of shipped products against the exploited lists, the three deadlines and a draft notification. |
| VOC2-J | EUVD and VulnCheck KEV as optional second sources, once their terms are confirmed. |

## Release 3: breadth and validation (epics)

| Epic | Content |
|---|---|
| VOC3-A | An integrated network scanner as a separate service (OpenVAS and Greenbone, Vuls): connector and scan runs; host credentials stay in the scanner. |
| VOC3-B | Connectors for commercial scanners (Tenable, Qualys, Rapid7, Defender Vulnerability Management) and Faraday. |
| VOC3-C | Agentless and network devices in the inventory; cloud asset APIs. |
| VOC3-D | Attack-path and reachability context on findings and in the incident view. |
| VOC3-E | Validation: pentest result import, and a network cross-check of what agents report on critical assets (TM-VOC-9). |
| VOC3-F | The cross-tenant VOC view for the MSSP, under grants. |
| VOC3-G | Governance: committee report, trends and SLA dashboards; accounts for remediation owners. |
| VOC3-H | Billing by asset band and PSA export (with PRD-9). |

The epics are broken into stories when release 1 has run on the lab (VOC1.25) and on a design partner's
agents: what Wazuh misses there decides the order of VOC2-A to VOC2-D.
