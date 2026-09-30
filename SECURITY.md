# Security policy

LG-SOTF processes security telemetry and can trigger containment actions, so
we treat vulnerabilities in it seriously. Thank you for reporting responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (current release line, see CHANGELOG.md) | Yes: security fixes |
| Earlier proof-of-concept code (before the 0.2.0 rebuild) | No |

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security
problem.**

Report it privately through GitHub's private vulnerability reporting: open
the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/gapilongo/SOC/security/advisories/new). If that option is
not available to you, open an issue that only asks a maintainer to contact
you privately, without any details of the problem.

Please include:

* the affected version or commit, and the deployment mode (Compose, Helm,
  other);
* the component (API, worker, scheduler, migrations, Helm chart, web app,
  evaluation harness) and the configuration needed to reproduce;
* steps to reproduce or a proof of concept, and the impact you expect
  (for example cross-tenant data access, authentication bypass, unintended
  response action, secret disclosure, prompt injection that closes a
  malicious alert or triggers containment);
* whether the issue is already public or known to others.

Use test data only. Do not access data that is not yours, do not run
response actions against systems you do not own, and do not degrade shared
services while testing.

## What happens next

* We acknowledge a report within 5 business days and give a first assessment
  within 10 business days.
* We keep you informed while we work on a fix and agree a disclosure date
  with you; we aim to release fixes for critical and high severity issues
  within 30 days of confirmation.
* We publish a GitHub security advisory with the fix and credit you if you
  wish.

## Scope

In scope: the code in this repository, the container image built from
`docker/Dockerfile`, the Helm chart in `deploy/helm/lg-sotf`, and the
documented default configuration.

Particularly relevant: tenant isolation (row-level security, Redis keys,
checkpoints, WebSocket events), authentication and session handling (JWT,
OIDC, API keys, refresh token rotation), authorisation of escalation
decisions and action approvals, response guardrails (protected assets,
autonomy policy, rate limits), secret handling and redaction, the outbound
destination policy of pull connectors (SSRF), webhook signing, audit log
integrity, and prompt injection that changes a triage outcome.

Out of scope: vulnerabilities in third-party services (LLM providers, SIEM
and EDR products, SOAR platforms) and in dependencies that are not
exploitable through LG-SOTF (report those upstream); findings that require
an already compromised host, database or Kubernetes cluster; missing
hardening on deployments that ignore the production safety checks (for
example `environment=development` exposed to the internet); denial of
service by volume alone; the deterministic `fake` model's classifications
(it is a test double, refused in production).

## Security design

The threat model, tenant isolation, secrets handling, prompt-injection
defences, response guardrails, data handling and audit are described in
[docs/security.md](docs/security.md).
