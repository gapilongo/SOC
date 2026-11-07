# Engineering roadmap

LG-SOTF is becoming the self-hosted, governed AI SOC that MSSPs run themselves. The AI investigates inside
each customer's own tools with read-only queries and cites the evidence behind every claim. It never acts
beyond the rules you set, and it proves its accuracy on your own history before you rely on it. It runs on
your servers with the model you choose.

This page is the engineering part of the plan, generated from `engineering-backlog.json`. Each scheduled
story is a GitHub issue labelled `story`, grouped into weekly milestones (`Wave week of …`) and tracked on
the project board.

## How we work

- **Engineering runs at agent speed.** A *wave* is one working day of about three 4-hour agent cycles:
  plan, build with parallel agents in separate worktrees, review, merge behind green CI, deploy to dev and
  smoke-test.
- **Validation sets the dates.** Real data, labs and pen tests run on calendar time. Engineering lands
  ahead of each gate.
- **Review tiers:**
  - T1 is docs and UI.
  - T2 is domain logic.
  - T3 is authorization, tenant isolation, response execution, signing, the AI tool boundary and
    migrations. A human reads every T3 diff.
- **Ready:** the acceptance criterion is a named test, dependencies are merged and the tier is set.
- **Done:** the test is green in CI, the architecture guardrails hold, the change is deployed to dev and
  docs and CHANGELOG are updated.

## Engineering milestones

| Date | Milestone | Criteria |
|---|---|---|
| 2026-11-27 | Frozen pentest-1.x tag and first signed partner train | Org model, tenant scoping, supply chain and invariants merged; tag frozen for fieldwork; weekly train live. |
| 2026-12-11 | Investigator v0 in shadow on the Wazuh lab | Registry, 5 Wazuh tools, 2 recipe classes, reader and critic scored on the attack-emulation corpus. |
| 2027-01-15 | Microsoft lab validated | Every Microsoft action marked validated with date; SKU matrix published; open-question issues closed. |
| 2027-03-05 | Pen-test letter | Third-party test (incl. AI red team) on the frozen tag; criticals/highs fixed via Expedite; retest letter published. |
| 2027-04-09 | CRA technical file complete | Annex I mapping, risk assessment and Annex VII file assembled and externally reviewed (deadline 2027-12-11). |
| 2027-04-23 | Investigator promoted for a partner tenant | n >= 300 shadow decisions, FN upper bound within target, four-eyes promotion for >= 1 partner tenant. |

## Scheduled work: 108 stories, 419 points

### Week of 2026-11-09: 45 stories, 175 points

| Story | Title | Pts | Priority | Tier | Day |
|---|---|---|---|---|---|
| `AI-E1.1` | Real-model baseline run and scorecard template (EU/local model; DeepSeek on synthetic only, never published) | 3 | Must | T2 | 2026-11-09 |
| `AI-E1.2` | Prompt/model registry with version hash in provenance and reports | 3 | Must | T2 | 2026-11-09 |
| `PRD-13.1` | First-run wizard: admin, org/tenant, LLM profile (EU or local default, tested), samples; ends at first PoV | 5 | Must | T2 | 2026-11-09 |
| `SEC1.1` | Cosign keyless image signing and build-provenance attestations (SLSA Build L3) | 3 | Must | T3 | 2026-11-09 |
| `INT3.1` | Wazuh 4.14 container in test-services; live ingestion contract tests | 3 | Must | T2 | 2026-11-09 |
| `AI-E1.3` | Investigation trace store in Postgres (LLM and tool calls, hashes, tokens) shown in the evidence pack | 5 | Must | T2 | 2026-11-09 |
| `AI-E1.7` | Confidence intervals (Wilson, n shown) on every rate in eval and PoV reports (ECE/Brier cut, CR7) | 3 | Must | T2 | 2026-11-09 |
| `AI-E1.4` | Record/replay of tool observations (cassettes) | 5 | Must | T2 | 2026-11-09 |
| `AI-E1.5a` | Shadow mode (a): side-effect sink plus a test that enumerates every egress (executor, outbox, Slack, mail, webhooks, tickets, WS) | 5 | Must | T3 | 2026-11-09 |
| `ARCH-E1.1` | graph_version on workflow_runs; worker keeps the N-1 graph to drain waiting runs | 5 | Must | T3 | 2026-11-10 |
| `AI-E1.5b` | Shadow mode (b): agreement report current vs candidate | 3 | Must | T2 | 2026-11-10 |
| `AI-E1.8` | Attack-emulation ground-truth corpus: Wazuh 4.14 lab, Atomic Red Team/Caldera scenarios plus replayed benign noise (CR2) | 8 | Must | T2 | 2026-11-10 |
| `SEC2.3` | Dependency policy and admission checklist | 1 | Must | T1 | 2026-11-10 |
| `GTM3.2` | pov install profile: read-only sources, response disabled by policy, egress allow-list, one command | 5 | Must | T2 | 2026-11-10 |
| `ARCH-E1.2` | CI upgrade test: N-1 database with waiting runs, migrate, resume and decide | 5 | Must | T3 | 2026-11-10 |
| `PRD-11.1` | PoV run object and wizard: window, backtest plus shadow period | 3 | Must | T2 | 2026-11-10 |
| `PRD-11.3` | PoV report content: FN first with CI, agreement, auto-handling, hours, cost, noisy detections, cited samples | 5 | Must | T2 | 2026-11-10 |
| `ARCH-E1.5` | Release trains: weekly signed partner train, monthly LTS candidate, security-relevant changelog, N-1 upgrade test and install rehearsal on every train (CR5, delivery #8) | 5 | Must | T3 | 2026-11-11 |
| `ARCH-E2.2` | OpenAPI stability tags, oasdiff breaking-change gate, Deprecation and Sunset headers | 3 | Must | T2 | 2026-11-11 |
| `ARCH-E4.1a` | Organisation model (a): schema, grants table, RLS policies (delivery split; risk:authz) | 5 | Must | T3 | 2026-11-11 |
| `PRD-11.4` | PoV signing, branding, methodology and limits appendix (absorbs GTM3.3 report generator) | 3 | Must | T2 | 2026-11-11 |
| `SEC1.2` | CycloneDX SBOMs (Python, npm, image) and OpenVEX as release assets | 3 | Must | T2 | 2026-11-11 |
| `SEC1.3` | Trivy gate; base images pinned by digest; --require-hashes lock files | 3 | Must | T2 | 2026-11-11 |
| `SEC3.1` | Threat model v2: STRIDE per component, OWASP Agentic Top 10, ATLAS; gate per epic | 3 | Must | T1 | 2026-11-11 |
| `SEC4.1` | Hardening guide: CIS-style numbered controls, L1/L2 profiles | 3 | Must | T1 | 2026-11-11 |
| `SEC10.5` | Fix stale security docs (erasure statement, security.md:333-335) | 1 | Must | T1 | 2026-11-11 |
| `INT9.2` | Evidence-fact schema v1, shared with AI-E3.2 | 3 | Must | T2 | 2026-11-11 |
| `PRD-13.6` | Install-to-PoV rehearsal on a clean VM plus lab, every release | 3 | Must | T2 | 2026-11-11 |
| `ARCH-E2.1` | Eval gate in CI: synthetic and phishing sets, fake model per PR plus pinned real-model run | 3 | Must | T2 | 2026-11-12 |
| `ARCH-E4.1b` | Organisation model (b): read paths under grants across all routers | 5 | Must | T3 | 2026-11-12 |
| `AI-E6.1` | Adversarial corpus v2: log-field persona hijacks, tool-output injection, response steering | 5 | Must | T2 | 2026-11-12 |
| `AI-E6.2` | AI system card plus AI Act / NIS2 mapping | 3 | Must | T1 | 2026-11-12 |
| `PRD-10.2` | Blind audit sampling of auto-closed alerts, verdict hidden (absorbs GTM3.4 labelling flow) | 5 | Must | T2 | 2026-11-12 |
| `SEC6.5` | Break-glass procedure, alert on use, drill | 2 | Must | T3 | 2026-11-12 |
| `SEC9.1` | Invariant registry, tests/invariants, CI gate, lg-sotf verify-invariants | 5 | Must | T2 | 2026-11-12 |
| `INT1.10` | Microsoft SKU coverage matrix (Business Premium, E3, E5) for every evidence and response API (CR6) | 2 | Must | T1 | 2026-11-12 |
| `ARCH-E4.1c` | Organisation model (c): write paths and decisions under grants with dual audit | 5 | Must | T3 | 2026-11-12 |
| `ARCH-E4.1d` | Organisation model (d): WS, MCP and API keys under grants plus cross-tenant leak suite over every route | 5 | Must | T3 | 2026-11-13 |
| `AI-E2.1` | Tool protocol and registry: risk class, schemas, per-tenant enablement, egress, row caps (absorbs ARCH-E6 registry and query safety) | 5 | Must | T3 | 2026-11-13 |
| `PRD-11.5` | PoV technical runbook and synthetic demo tenant; CI grep for DeepSeek in assets | 2 | Must | T1 | 2026-11-13 |
| `PRD-11.6` | CSV labelled-history import fallback for the first PoV (from PRD risk 2 mitigation; keeps Wazuh PoVs unblocked) | 2 | Must | T2 | 2026-11-13 |
| `PRD-13.2a` | Guided connector: Wazuh (for PoV installs) | 3 | Must | T2 | 2026-11-13 |
| `INT1.2` | live_ms harness plus cassette recorder that feeds the fakes | 5 | Must | T2 | 2026-11-13 |
| `AI-E3.1a` | Hypothesis schema plus recipes for 2 Wazuh classes (endpoint malware, identity/auth) (CR3) | 5 | Must | T2 | 2026-11-13 |
| `INT3.4` | Wazuh evidence tools: host timeline, auth events, FIM, process, network (investigation v0, shadow) | 8 | Must | T2 | 2026-11-13 |

### Week of 2026-11-16: 46 stories, 171 points

| Story | Title | Pts | Priority | Tier | Day |
|---|---|---|---|---|---|
| `AI-E3.2` | Quarantined reader producing typed facts | 8 | Must | T3 | 2026-11-16 |
| `INT3.3a` | Wazuh 5.0 RC container and findings fixtures in test-services (delivery split) | 3 | Must | T2 | 2026-11-16 |
| `GTM3.7` | PoV sizing guide (CPU, RAM, optional GPU) | 2 | Must | T1 | 2026-11-16 |
| `GTM7.3` | GitHub Projects v2 board plus tools/sync_board.py (idempotent upsert by story ID; nightly status export) | 3 | Must | T1 | 2026-11-16 |
| `AI-E3.3` | Planner and executor with budgets (steps, tokens, money) | 5 | Must | T2 | 2026-11-16 |
| `INT3.3b` | Wazuh 5.x findings connector plus ECS/WCS mapper (gates nothing, CR6) | 5 | Must | T2 | 2026-11-16 |
| `AI-E3.4` | Critic with deterministic citation check; unsupported claims escalate | 5 | Must | T2 | 2026-11-16 |
| `INT4.1` | Elastic alerts ingestion reusing the ECS mapper (CR6: the PoV promises Elastic) | 3 | Must | T2 | 2026-11-16 |
| `AI-E3.6` | Per-tenant flag and promotion via shadow mode | 3 | Must | T2 | 2026-11-17 |
| `PRD-2.1` | Narrative with citation chips and fact drawer | 5 | Must | T2 | 2026-11-17 |
| `PRD-5.1` | Cross-tenant case queue, decide in place under grants | 5 | Must | T3 | 2026-11-17 |
| `PRD-13.2d` | Connector readiness score | 2 | Should | T1 | 2026-11-17 |
| `PRD-13.5` | Local time-to-value timestamps; no phone-home | 2 | Should | T2 | 2026-11-17 |
| `PRD-15.6` | Axe WCAG 2.2 AA gate on every new page; keyboard map; screen-reader citations | 3 | Must | T1 | 2026-11-17 |
| `SEC3.3` | Security whitepaper with shared-responsibility matrix | 3 | Must | T1 | 2026-11-17 |
| `SEC6.2` | Delegated-access controls: customer grant register and revoke, expiry, JIT reason, co-approval, dual audit | 5 | Must | T3 | 2026-11-17 |
| `SEC9.2` | Signed per-release safety scorecard | 2 | Must | T2 | 2026-11-17 |
| `SEC7.8` | Supplier-assurance pack, static part per release, white-labelable | 5 | Must | T2 | 2026-11-17 |
| `AI-E1.6` | GUIDE converter and ExCyTIn adapter | 5 | Should | T2 | 2026-11-18 |
| `AI-E3.1b` | Recipes for 2 more classes (phishing, lateral movement) | 3 | Should | T2 | 2026-11-18 |
| `PRD-5.3` | Grants UI: staff x tenant x role, time-boxed, justified; customer-visible page (UI over SEC6.2) | 5 | Must | T3 | 2026-11-18 |
| `PRD-13.3` | Tenant mode Observe/Assist/Autonomous over shadow mode | 5 | Must | T3 | 2026-11-18 |
| `PRD-15.7` | Versioned docs site from docs/ (absorbs GTM5.2) | 5 | Should | T1 | 2026-11-18 |
| `INT1.3` | Microsoft open questions: 1-day spike; each answer files a story citing lab evidence (delivery split) | 2 | Must | T1 | 2026-11-18 |
| `GTM5.11` | Public per-release scorecard page | 1 | Should | T1 | 2026-11-18 |
| `AI-E2.3` | Entra sign-ins and risky users evidence tool | 5 | Should | T2 | 2026-11-18 |
| `AI-E3.1c` | Recipes for the last 2 classes (cloud, exfiltration) | 3 | Should | T2 | 2026-11-18 |
| `ARCH-E9.3` | Metering export for billing | 3 | Should | T2 | 2026-11-19 |
| `AI-E5.1` | Per-task model routing | 3 | Should | T2 | 2026-11-19 |
| `AI-E5.3` | Cost-per-investigation metric and per-investigation budget | 3 | Should | T2 | 2026-11-19 |
| `PRD-6.1` | Branding (org default, tenant override): name, logo, accent, support contact | 5 | Should | T2 | 2026-11-19 |
| `PRD-8.3` | Four-eyes to raise autonomy or disable dry-run; MSSP lock | 5 | Should | T3 | 2026-11-19 |
| `PRD-10.1` | Scorecard page by model and prompt version | 5 | Should | T1 | 2026-11-19 |
| `SEC6.1` | One OIDC IdP per tenant; tenant bound to issuer | 5 | Must | T3 | 2026-11-19 |
| `PRD-6.2` | White-label shell, login, title, favicon | 3 | Should | T1 | 2026-11-19 |
| `PRD-13.4` | Daily shadow digest; graduation criteria gate promotion | 3 | Must | T2 | 2026-11-19 |
| `ARCH-E1.3` | RPO/RTO targets, PITR, automated restore drill in the nightly run | 3 | Must | T3 | 2026-11-20 |
| `SEC2.2` | Security-release runbook incl. CRA Art. 14 reporting (24 h / 72 h / 14 days to ENISA) | 3 | Must | T1 | 2026-11-20 |
| `SEC8.2a` | CRA Annex I essential-requirements mapping | 3 | Must | T1 | 2026-11-20 |
| `SEC8.4` | Secure-by-default audit and documentation | 2 | Should | T1 | 2026-11-20 |
| `SEC9.3` | Per-tenant kill switches (LLM off, autonomy to approval), audited | 2 | Should | T2 | 2026-11-20 |
| `SEC10.2` | Redacted support bundle; no vendor remote access (absorbs GTM6.7b) | 3 | Should | T2 | 2026-11-20 |
| `INT3.2` | Tenant scoping on shared Wazuh clusters (agent group/label filter), DLS role per tenant, DLS negative test per tenant (CR4) | 8 | Must | T3 | 2026-11-20 |
| `ARCH-E1.4` | HA reference: managed Postgres, Redis persistence, PgBouncer validated (B10) | 3 | Must | T2 | 2026-11-20 |
| `SEC8.2b` | CRA cybersecurity risk assessment | 3 | Must | T1 | 2026-11-20 |
| `SEC8.2c` | CRA Annex VII technical file assembly | 3 | Must | T1 | 2026-11-20 |

### Week of 2026-11-23: 6 stories, 31 points

| Story | Title | Pts | Priority | Tier | Day |
|---|---|---|---|---|---|
| `AI-E3.5` | Corroboration weights for tool-observed facts | 5 | Should | T3 | 2026-11-23 |
| `AI-E5.2` | Per-tenant model profile: BYO key, local or EU model, egress checks (absorbs ARCH-E8.3) | 8 | Should | T3 | 2026-11-24 |
| `PRD-8.1` | Model profile UI: model per task, residency label, BYO key, test, cost (keeps PRD residency checks) | 5 | Should | T2 | 2026-11-24 |
| `GTM1.4` | ee/ wheel, entry-point loading, import-linter contract, one image with ee dormant (includes minimal hook, not full ARCH-E7.1) | 5 | Must | T2 | 2026-11-27 |
| `GTM1.5` | Offline Ed25519 licence file, verifier, entitlements, banner and grace; never fails closed | 5 | Should | T3 | 2026-11-27 |
| `GTM1.6` | Signed monthly usage report for true-up | 3 | Should | T2 | 2026-11-27 |

### Week of 2026-11-30: 11 stories, 42 points

| Story | Title | Pts | Priority | Tier | Day |
|---|---|---|---|---|---|
| `INT1.4` | Mail end to end: execute, verify, roll back | 3 | Must | T3 | 2026-11-30 |
| `INT1.5` | Entra end to end | 3 | Must | T3 | 2026-11-30 |
| `INT1.6` | Defender end to end | 5 | Must | T3 | 2026-11-30 |
| `AI-E2.5` | Mail message trace evidence tool | 3 | Should | T2 | 2026-11-30 |
| `AI-E2.6` | Lab-tenant validation of the Microsoft evidence tools (5 pts: INT1 provides the harness) | 5 | Should | T2 | 2026-11-30 |
| `INT1.7` | Live ingestion validation; remove tenant-supplied auth and API URLs | 3 | Must | T3 | 2026-12-01 |
| `PRD-11.2` | Labelled history import: closed Sentinel incidents and Defender alerts with TP/FP (Must again if C8 = Microsoft-heavy) | 8 | Should | T2 | 2026-12-01 |
| `PRD-13.2c` | Guided connector: Sentinel | 3 | Should | T2 | 2026-12-01 |
| `INT1.8` | Connection-test truth table, least-privilege runbook, Validated integrations page | 2 | Must | T1 | 2026-12-01 |
| `PRD-13.2b` | Guided connector: Microsoft admin consent, least privilege (after lab validation) | 5 | Must | T2 | 2026-12-01 |
| `INT1.9` | Weekly drift run | 2 | Should | T2 | 2026-12-01 |

## Later: 134 stories, 596 points

Built when a partner needs them or a gate opens.

- **AI-E2**, Tool registry and Microsoft read tools: `AI-E2.2` Defender advanced hunting templated queries (process tree, device timeline, file prevalence) (H3; re-add only if INT1.10 shows partner SKUs carry advanced hunting, CR6); `AI-E2.4` Sentinel KQL templates
- **AI-E4**, Tenant memory and feedback: `AI-E4.1` Entity context store (assets, VIPs, identities from Entra and Defender, manual); `AI-E4.2` Prevalence baselines from indicator_sightings; `AI-E4.3` Similar-case retrieval with pgvector and RLS, analyst-confirmed only; `AI-E4.4` Per-tenant calibrator driving auto-close thresholds; `AI-E4.5` Analyst feedback on reasoning steps
- **AI-E6**, Safety hardening and compliance: `AI-E6.3` Autonomy levels L0-L4 mapped onto the autonomy map; docs; `AI-E6.4` Free-form query guard (KQL linting, read-only, row and time caps), tenant opt-in
- **AI-E7**, Ecosystem (MCP-in): `AI-E7.1` MCP-in adapter: allow-listed tools, quarantined outputs
- **ARCH-E2**, Quality and contract gates: `ARCH-E2.3` OpenTelemetry tracing export (demoted to Could: AI-E1.3 is the trace store)
- **ARCH-E3**, 10x scale hygiene: `ARCH-E3.1` Leader enqueues polls, outbox delivery and verification as jobs; workers run them; `ARCH-E3.2` Cluster-wide LLM token bucket per provider and model, in Redis; `ARCH-E3.3` Hourly roll-up table for the dashboard (B7) and composite indexes (B8); `ARCH-E3.4` Checkpoint compaction for waiting runs; durability=exit where safe (B9); `ARCH-E3.5` Load test at 1M alerts/day with real-provider latency
- **ARCH-E4**, MSSP and enterprise identity: `ARCH-E4.2` SAML SSO; `ARCH-E4.3` SCIM provisioning; `ARCH-E4.4` Per-tenant data keys wrapped by KMS or Vault; crypto-shred on erasure
- **ARCH-E5**, Case model: `ARCH-E5.1a` Cases (a): table, RLS, dual-write behind a flag; `ARCH-E5.1b` Cases (b): backfill and decision-inheritance tests; `ARCH-E5.1c` Cases (c): read switch; `ARCH-E5.2` Case API v1 and case events; `ARCH-E5.3` Investigation run per case; alerts attach to it
- **ARCH-E6**, Investigation runtime: Splunk only: `ARCH-E6.4` Evidence tool: Splunk SPL templates (ARCH-E6 keeps only Splunk; Microsoft tools live in AI-E2)
- **ARCH-E7**, SDK and content packs: `ARCH-E7.1` Plugin registry: entry points plus manifest enforced by the egress kernel; `ARCH-E7.2` Conformance kit and an external example connector (TheHive); `ARCH-E7.3` Content-pack format, signing, versioned install; `ARCH-E7.4` Pack diff, apply and rollback; bulk apply for MSSPs
- **ARCH-E8**, Durable events and storage tiers: `ARCH-E8.1` domain_events log with a CloudEvents envelope; `ARCH-E8.2` Webhook subscriptions with a replay cursor; `ARCH-E8.4` Object-store adapter (S3/MinIO) for raw payloads and evidence packs; `ARCH-E8.5a` Monthly partitioning of alerts (split from 6-point story); `ARCH-E8.5b` Parquet archive of closed alerts (split from 6-point story); `ARCH-E8.6` WORM audit export with chain anchors
- **ARCH-E9**, Control plane and cells: `ARCH-E9.1` Tenant-to-cell registry and provisioning that calls each cell; `ARCH-E9.2` Tenant move between cells from export and import; `ARCH-E9.4` Release channels and cell-by-cell rollout
- **GTM5**, Sales and marketing assets: `GTM5.3` Public read-only demo tenant, synthetic data, local model, nightly reset
- **INT2**, Microsoft for MSSPs: `INT2.1` Defender XDR incident and alert ingestion via Graph (Must if first partner is Microsoft-heavy, see C8); `INT2.2` Scripted per-customer single-tenant app onboarding
- **INT3**, Wazuh first: `INT3.3c` Re-validate the 5.x connector when Wazuh 5.0 GA ships (trigger: GA); `INT3.5` Wazuh manager-API context: agent inventory, packages, ports, vulnerabilities; `INT3.6` Wazuh active response through the ledger, with verify
- **INT4**, Second-wave breadth: `INT4.2` Elastic ES-QL evidence templates; `INT4.3` Live validation of Splunk, Jira, ServiceNow and Slack on free/dev instances; `INT4.4` CrowdStrike live validation with a partner Falcon tenant; `INT4.5` SentinelOne threats ingestion; `INT4.6` Okta System Log evidence tool; `INT4.7` GCP SCC via Pub/Sub push; AWS Security Hub normalizer
- **INT5**, MCP ecosystem: `INT5.1` Sentinel MCP vetted catalogue and adversarial cassettes; `INT5.2` Google SecOps mcp-security vetted catalogue; `INT5.3` falcon-mcp per-tenant sidecar packaging; `INT5.4a` Remote MCP-out keys only: spike and endpoint (split from 21; absorbs AI-E7.2); `INT5.4b` Remote MCP-out: delegating executor and allowlists; `INT5.4c` Remote MCP-out: audit, kill switches, recipes
- **INT6**, Partner events and hand-off: `INT6.1` Event catalogue v2, JSON Schemas, CloudEvents mapping; `INT6.2` update_source_alert action plus Sentinel and Defender write-back; `INT6.3` Wazuh and Splunk ES write-back; `INT6.4` TheHive 5 hand-off (ticketing kind)
- **INT7**, SDK ecosystem: `INT7.1` Port in-tree sources, Microsoft capabilities and ticketing onto manifests; `INT7.2` Contribution tiers, guide, lg-sotf plugin verify; `INT7.3` Sigstore plugin signing, plugins.allowed, per-plugin SBOM, load audit; `INT7.4` Vendor-version compatibility matrix in CI
- **INT8**, Source content packs: `INT8.1` Wazuh content pack v1; `INT8.2` Microsoft content pack v1; `INT8.3` Sigma and Wazuh rule-tuning proposals from verdicts
- **INT9**, Data standards: `INT9.1` OCSF export (2004, 2005) and published schemas
- **PRD-1**, Case workspace: `PRD-1.1` Case queue: saved views, SLA order, owner and tenant columns, bulk claim (replaces ARCH-E5.4); `PRD-1.2` Case view shell with decision panel reusing DecisionForm; `PRD-1.3` Unified timeline across attached alerts, AI/human/system filter; `PRD-1.4` Notes: Markdown, @mentions that notify, pinning; `PRD-1.5` Assign to user or queue; reassign with mandatory handover note; `PRD-1.6` Shift handover report with AI shift summary; `PRD-1.7` Attach/detach alerts, merge/split cases; `PRD-1.8` Note attachments; `PRD-1.9` Escalation-to-case redirects, e2e, axe
- **PRD-10**, KPIs and AI scorecard: `PRD-10.3` Measured hours saved from claim-to-decide durations; `PRD-10.4` Manager dashboard: backlog, SLA, workload; aggregated by default
- **PRD-12**, NIS2 and DORA: `PRD-12.1` Regulatory incident record: NIS2 significant / DORA major classification wizard (absorbs SEC7.1 classification, RTS 2024/1772); `PRD-12.2` Reporting clocks in the case header with pre-deadline alerts (absorbs SEC7.2); `PRD-12.3` DORA drafts mapped to ESA templates per RTS 2025/301 (absorbs SEC7.1); `PRD-12.4` Quarterly supplier assurance report MSSP to customer: incidents, SLA, AI oversight, audit-chain verification; `PRD-12.5` French and German regulator labels
- **PRD-14**, Notifications and on-call: `PRD-14.1` Per-user notification preferences, quiet hours; `PRD-14.2` Slack thread per case with Claim and Assign; `PRD-14.3` Teams interactive approve and claim via Azure Bot (absorbs INT6.5); `PRD-14.4` PagerDuty Events v2 plus generic on-call webhook; `PRD-14.5` Email shift-handover and SLA-at-risk digests
- **PRD-15**, Accessibility, i18n and docs: `PRD-15.1` i18n framework: ICU messages, extraction, pseudo-locale CI; `PRD-15.2` Extract strings: shell and analyst pages; `PRD-15.3` Extract strings: admin, MSSP and settings pages; `PRD-15.4` French and German translations with native security reviewer; `PRD-15.5` Localised monthly report, PoV, evidence pack, notifications; `PRD-15.8` Narrative in the tenant's language; `PRD-15.9` FR/DE docs and EN 301 549 conformance report
- **PRD-2**, Narrative and agent transparency: `PRD-2.2` Provenance badges, unsupported-claim styling, calibrated confidence; `PRD-2.3` Agent-steps tree with cost, model, prompt version; `PRD-2.4` Per-step and per-fact feedback (feeds AI-E4.5); `PRD-2.5` Shadow comparison panel (current vs candidate); `PRD-2.6` Evidence pack v2 with narrative, citations, steps
- **PRD-3**, Structured needs-more-information: `PRD-3.1` Gap model; pending_info status with sub-clock and optional SLA pause; `PRD-3.2` Gap panel, Run suggested query; `PRD-3.3` Ask-a-human with signed one-time answer link; `PRD-3.4` Incremental re-investigation, reminders, timeout to next tier
- **PRD-4**, Search and entity pivots: `PRD-4.1` Global search (Ctrl/Cmd-K) over cases, alerts, entities, indicators; `PRD-4.2` Entity page: user, host, IP, domain, hash, mailbox; `PRD-4.3` Pivot menu on every entity chip: open, search, run recipe; `PRD-4.4` MSSP indicator sweep: seen in N of your tenants
- **PRD-5**, MSSP organisation console: `PRD-5.2` Tenant health grid; `PRD-5.4` Org roll-up: hours saved, MTTR, FN rate by tenant
- **PRD-6**, White-labelling: `PRD-6.3` Branded reports, PoV, evidence packs, regulator drafts, emails, cards; `PRD-6.4` Custom hostname per org (Helm values, docs)
- **PRD-7**, Content-pack UX: `PRD-7.1` Content-pack catalogue and detail; `PRD-7.2` Pack diff against tenant; drift indicator; `PRD-7.3` Bulk-apply wizard: filter, preview, canary, rollback
- **PRD-8**, Per-tenant model and autonomy: `PRD-8.2` Autonomy matrix L0-L4 x risk with what-would-have-happened (last 30 days)
- **PRD-9**, Billing view: `PRD-9.1` Endpoint-band counting from connectors (Defender devices, Wazuh agents); `PRD-9.2` Billing per tenant and month; month-close lock; `PRD-9.3` PSA export (HaloPSA, Autotask, ConnectWise)
- **SEC1**, Supply-chain and release integrity: `SEC1.4` Signed air-gapped bundle and Helm chart as signed OCI artifact; `SEC1.5` CodeQL, OpenSSF Scorecard, licence scan with allowlist
- **SEC4**, Hardening benchmark and posture attestation: `SEC4.2` lg-sotf posture: automated benchmark and signed attestation; `SEC4.3` Hardened Helm profile
- **SEC5**, Keys and tokens: `SEC5.1` KEK providers and per-tenant KEK so crypto-shred survives backups; `SEC5.2` Asymmetric JWT (EdDSA/ES256), kid rotation, JWKS; `SEC5.3` Rotation automation, crypto-period posture checks, audit events
- **SEC6**, MSSP identity hardening: `SEC6.3` Per-tenant session policy; `SEC6.4` WebAuthn/passkeys, required for platform admins
- **SEC7**, Regulatory product features: `SEC7.3` ICT third-party and data-flow register export (ITS 2024/2956); `SEC7.5a` Per-data-subject search, export and pseudonymisation; `SEC7.5b` Optional pseudonymisation before the LLM call, per tenant; `SEC7.6` AI Act deployer pack: Art. 4 literacy module with audited acknowledgement; `SEC7.7` ISO 27001:2022 Annex A, NIS2 CIR 2024/2690 and DORA control matrix (cut by CR7; returns on partner request)

