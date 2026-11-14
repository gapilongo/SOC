# LG-SOTF documentation

| Document | For | Contents |
|---|---|---|
| [User guide](user-guide.md) | Analysts, tenant admins | Concepts, roles, triage and review workflows, sources, response policy |
| [Architecture](architecture.md) | Engineers | The system contract: processes, data model, workflow, queue, LLM layer, API, guardrails |
| [API](api.md) | Integrators | Authentication, roles, endpoints, ingestion, WebSocket events, limits |
| [Configuration](configuration.md) | Operators | Every setting with its environment variable and default (generated from the code) |
| [Deployment](deployment.md) | Operators | Image, Docker Compose, Helm, two-role PostgreSQL, TLS, sizing, upgrades, backups |
| [Releases](releases.md) | Operators, customers | Release channels (weekly partner candidate, stable, LTS, security), cadence, support windows, backports, pinning and verifying a release |
| [CI/CD](cicd.md) | Operators | Multi-arch images on GHCR, dev and uat on an Oracle Cloud Always Free VM (Caddy HTTPS), promotion, rollback, backups |
| [Operations](operations.md) | Operators | Health, scaling, dead letters, stuck runs, retention, key rotation, incidents, dashboards and alerts |
| [Identity](identity.md) | Tenant admins, operators, security reviewers | TOTP MFA, OIDC role mapping and just-in-time provisioning, SAML via a broker, recovery |
| [Break-glass runbook](runbooks/break-glass.md) | Operators, platform admins | Emergency platform-admin access with a sealed credential: when to use it, the procedure, the alert, rotation after use, the drill checklist |
| [Security](security.md) | Security reviewers, customers | Threat model, tenant isolation, authentication, secrets, prompt-injection defences, guardrails, data handling, audit |
| [Dependency policy](dependency-policy.md) | Engineers, security reviewers | Admission checklist for a new dependency, patch SLAs, Dependabot and advisory triage |
| [Threat model](threat-model.md) | Security reviewers, pen testers, engineers | STRIDE per component (API, worker, MCP, MSSP delegation, evidence tools, CI/CD), OWASP Top 10 for Agentic Applications, MITRE ATLAS, the threat-model gate per epic |
| [Hardening guide](hardening.md) | Operators, security reviewers | Numbered L1/L2 controls with checks for Docker Compose, Helm, PostgreSQL, Redis, the reverse proxy and image verification |
| [Safety invariants](invariants.md) | Security reviewers, buyers, engineers | The safety invariants with the tests that prove them, and `lg-sotf verify-invariants` for your own install |
| [AI system card](ai-system-card.md) | Compliance officers, security reviewers, buyers | Intended use, the models and where they run, agents and tools, what the AI decides versus people, evaluation evidence and its limits, logging, data handling, EU AI Act and NIS2 mapping |
| [MSSP operations](mssp.md) | Platform admins | MSSP console, tenant switcher, suspension, quotas, usage metering and invoicing, tenant templates |
| [Onboarding](onboarding.md) | Install admins, tenant admins | First-run setup wizard, getting-started checklist, sample alerts, per-tenant retention |
| [Compliance](compliance.md) | Compliance officers, auditors, operators | Evidence packs and their verification, NIS2 report drafts, GDPR tenant export and erasure, audit retention, AI Act oversight mapping |
| [MCP server](mcp.md) | Analysts, testers, operators | Using LG-SOTF from Claude Code, Claude Desktop or another MCP client; the tester workflow on a dry-run install; the QA-tenant runbook |
| [Testing](testing.md) | Engineers | Test tiers, one-command test services, fixtures and `_support.py` helpers, the fake LLM, clocks, isolation rules, the flaky-test policy |
| [Architecture decisions](adr/README.md) | Engineers | The ADR log: layering and dependency rule (ADR-0001) and the decisions that follow |
| [MCP architecture](design/mcp-architecture.md) | Engineers, security reviewers | The approved MCP design (remote endpoint, OAuth, QA runs, outbound MCP); only Phases 0 and 0.5 are implemented |
| [Refactor roadmap](design/refactor-roadmap.md) | Engineers | Target layered architecture, CI guardrails and the ordered, PR-sized refactor plan; mark steps done as they merge |
| [Vulnerability Operations Center](adr/0016-vulnerability-operations-center.md) | Engineers, security reviewers, MSSP service owners | Decided design, nothing built yet (ADR-0016): the VOC as the first platform module on a shared asset inventory and case kernel, Wazuh findings, shared advisory feeds, a deterministic priority with stored inputs, exceptions, the NIS2 and DORA evidence pack; [stories and build order](design/voc-stories.md) |
| [Console v2 design](design/console-v2/README.md) | Frontend engineers, product | Design only, not built: clickable prototype and spec for the investigation view, case page, approval inbox, queue, platform shell and overview; components, token changes and the data each screen needs |
| [Investigation skills](adr/0014-investigation-skills.md) | Engineers, detection owners, security reviewers | Proposed design (ADR-0014): skill files per detection family, Wazuh evidence tools, tenant context, guidance notes and case memory, the citation checker, earned autonomy per skill and tenant; [stories and build order](design/investigation-skills-stories.md) |
| [Engineering roadmap](roadmap/README.md) | Everyone | Engineering milestones and the scheduled stories by week, with the ones already done |
| [Integrations](integrations.md) | Tenant admins, integrators | Slack, Teams, email and signed-webhook notifications, Jira and ServiceNow tickets, Slack approvals, the delivery outbox |
| [SOAR playbooks](soar-playbooks.md) | Tenant admins, SOAR engineers | Running approved actions in your own SOAR: the signed webhook contract, idempotency, the reference receiver, the n8n workflow, Tines, Shuffle and Tracecat recipes, example vendor calls per action type |
| [Proof of value](pov.md) | Operators, prospects | The `pov` install profile: read-only sources, response execution disabled by policy, an egress allow-list, one command, then the backtest |
| [Quickstart](quickstart.md) | Evaluators | `make quickstart`: from a fresh clone to triaged demo alerts, with the measured time to first verdict |
| [Local LLMs](local-llm.md) | Operators | Ollama, vLLM and other OpenAI-compatible servers on your own hardware |
| [Air-gapped installation](air-gapped.md) | Operators | Moving images, models and the bundle across an air gap and verifying them on arrival |
| [Performance and sizing](performance.md) | Operators | Load-test results, where scaling stops, and how to size a deployment |
| [Self-hosting on a PC](self-hosting-pc.md) | Operators | Dev and uat on your own Windows PC (WSL2, Tailscale Funnel), no cloud account |
| [Evidence facts](evidence-facts.md) | Integrators, engineers | The evidence-fact schema v1: the typed observations verdicts cite, its kinds, SemVer rules and the CI breaking-change check |
| [Evaluation](evaluation.md) | Engineers, detection owners | The `lg-sotf eval` harness, dataset format, metrics, regression gate, using your own and public labelled data |
| [Scorecards](scorecards/README.md) | Buyers, detection owners | One-page accuracy summaries per model configuration, each rate with its sample size and 95% interval; the first is a local `qwen2.5:7b` |
| [Reporting](reporting.md) | Tenant admins, buyers | Value, AI-versus-analyst accuracy and detection reports on your own alerts, with confidence intervals; the backtest |
| [Phishing triage](phishing.md) | Tenant admins, integrators | User-reported email: M365 and IMAP reporting mailboxes, the push API, phishing signals, response actions |
| [Microsoft direct response](microsoft.md) | Tenant admins, security reviewers | Executing approved actions in Microsoft 365, Entra ID and Defender for Endpoint; routing, rehearsal, verification, rollback, background execution |
| [Microsoft 365 mail](microsoft-mail.md) | Tenant admins | Removing reported messages and notifying reporters in Exchange Online |
| [Microsoft Entra ID](microsoft-entra.md) | Tenant admins | Disabling, revoking sessions, resetting passwords and confirming compromise for a user |
| [Microsoft Defender for Endpoint](microsoft-defender.md) | Tenant admins | Isolating devices, blocking indicators, quarantining files, collecting investigation packages |
| [Microsoft SKU coverage matrix](microsoft-skus.md) | Tenant admins, MSSP pre-sales, security reviewers | Every Microsoft Graph, Defender for Endpoint and Log Analytics API LG-SOTF calls, with the licence it needs on Business Premium, E3 and E5, its permission, the Microsoft Learn source and lab evidence |

Repository files: [README](../README.md), [CHANGELOG](../CHANGELOG.md),
[SECURITY](../SECURITY.md) (vulnerability reporting),
[CONTRIBUTING](../CONTRIBUTING.md).

`docs/tools/` holds documentation tooling: `settings_reference.py`
regenerates the settings tables in `configuration.md`, and
`export_feedback.sql` exports analyst decisions as an evaluation dataset.
