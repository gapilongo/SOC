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
| [Security](security.md) | Security reviewers, customers | Threat model, tenant isolation, authentication, secrets, prompt-injection defences, guardrails, data handling, audit |
| [Evaluation](evaluation.md) | Engineers, detection owners | The `lg-sotf eval` harness, dataset format, metrics, regression gate, using your own and public labelled data |
| [Phishing triage](phishing.md) | Tenant admins, integrators | User-reported email: M365 and IMAP reporting mailboxes, the push API, phishing signals, response actions |

Repository files: [README](../README.md), [CHANGELOG](../CHANGELOG.md),
[SECURITY](../SECURITY.md) (vulnerability reporting),
[CONTRIBUTING](../CONTRIBUTING.md).

`docs/tools/` holds documentation tooling: `settings_reference.py`
regenerates the settings tables in `configuration.md`, and
`export_feedback.sql` exports analyst decisions as an evaluation dataset.
