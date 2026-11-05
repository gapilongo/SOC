# LG-SOTF documentation

| Document | For | Contents |
|---|---|---|
| [User guide](user-guide.md) | Analysts, tenant admins | Concepts, roles, triage and review workflows, sources, response policy |
| [Architecture](architecture.md) | Engineers | The system contract: processes, data model, workflow, queue, LLM layer, API, guardrails |
| [API](api.md) | Integrators | Authentication, roles, endpoints, ingestion, WebSocket events, limits |
| [Configuration](configuration.md) | Operators | Every setting with its environment variable and default (generated from the code) |
| [Deployment](deployment.md) | Operators | Image, Docker Compose, Helm, two-role PostgreSQL, TLS, sizing, upgrades, backups |
| [CI/CD](cicd.md) | Operators | Multi-arch images on GHCR, dev and uat on an Oracle Cloud Always Free VM (Caddy HTTPS), promotion, rollback, backups |
| [Operations](operations.md) | Operators | Health, scaling, dead letters, stuck runs, retention, key rotation, incidents, dashboards and alerts |
| [Identity](identity.md) | Tenant admins, operators, security reviewers | TOTP MFA, OIDC role mapping and just-in-time provisioning, SAML via a broker, recovery |
| [Security](security.md) | Security reviewers, customers | Threat model, tenant isolation, authentication, secrets, prompt-injection defences, guardrails, data handling, audit |
| [MSSP operations](mssp.md) | Platform admins | MSSP console, tenant switcher, suspension, quotas, usage metering and invoicing, tenant templates |
| [Onboarding](onboarding.md) | Tenant admins | Getting-started checklist, sample alerts, per-tenant retention |
| [Compliance](compliance.md) | Compliance officers, auditors, operators | Evidence packs and their verification, NIS2 report drafts, GDPR tenant export and erasure, audit retention, AI Act oversight mapping |
| [MCP server](mcp.md) | Analysts, testers, operators | Using LG-SOTF from Claude Code, Claude Desktop or another MCP client; the tester workflow on a dry-run install; the QA-tenant runbook |
| [Architecture decisions](adr/README.md) | Engineers | The ADR log: layering and dependency rule (ADR-0001) and the decisions that follow |
| [MCP architecture](design/mcp-architecture.md) | Engineers, security reviewers | The approved MCP design (remote endpoint, OAuth, QA runs, outbound MCP); only Phases 0 and 0.5 are implemented |
| [Refactor roadmap](design/refactor-roadmap.md) | Engineers | Target layered architecture, CI guardrails and the ordered, PR-sized refactor plan; mark steps done as they merge |
| [Integrations](integrations.md) | Tenant admins, integrators | Slack, Teams, email and signed-webhook notifications, Jira and ServiceNow tickets, Slack approvals, the delivery outbox |
| [SOAR playbooks](soar-playbooks.md) | Tenant admins, SOAR engineers | Running approved actions in your own SOAR: the signed webhook contract, idempotency, the reference receiver, the n8n workflow, Tines, Shuffle and Tracecat recipes, example vendor calls per action type |
| [Evaluation](evaluation.md) | Engineers, detection owners | The `lg-sotf eval` harness, dataset format, metrics, regression gate, using your own and public labelled data |
| [Phishing triage](phishing.md) | Tenant admins, integrators | User-reported email: M365 and IMAP reporting mailboxes, the push API, phishing signals, response actions |
| [Microsoft direct response](microsoft.md) | Tenant admins, security reviewers | Executing approved actions in Microsoft 365, Entra ID and Defender for Endpoint; routing, rehearsal, verification, rollback, background execution |

Repository files: [README](../README.md), [CHANGELOG](../CHANGELOG.md),
[SECURITY](../SECURITY.md) (vulnerability reporting),
[CONTRIBUTING](../CONTRIBUTING.md).

`docs/tools/` holds documentation tooling: `settings_reference.py`
regenerates the settings tables in `configuration.md`, and
`export_feedback.sql` exports analyst decisions as an evaluation dataset.
