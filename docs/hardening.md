# Hardening guide

| | |
|---|---|
| Version | 1.0, 2026-11-07 (SEC4.1) |
| Applies to | LG-SOTF 1.x with Docker Compose (`docker/docker-compose.yml` plus `docker/docker-compose.prod.yml`) or the Helm chart (`deploy/helm/lg-sotf`) |
| Audience | Operators, MSSP platform teams, security reviewers |
| Related | [deployment.md](deployment.md) (how to install), [security.md](security.md) (the controls inside the application), [threat-model.md](threat-model.md) (what each control mitigates) |

This guide is a benchmark in the style of the CIS Benchmarks. Each control
has a numbered ID, a profile level, a rationale, a check and a setting.
Check results can be recorded per control. An automated `lg-sotf posture`
command that runs these checks and signs the result is planned (SEC4.2),
and so is a hardened Helm profile that applies the L2 Kubernetes controls by
default (SEC4.3).

## Profiles

* **Level 1 (L1)**: the baseline for every production or staging install.
  The controls have little operational cost, and most are already the
  shipped default. An install that misses an L1 control should have a
  written exception.
* **Level 2 (L2)**: defence in depth for regulated customers and MSSPs that
  host several customers on one install. These controls may need extra
  infrastructure (a private CA, an admission controller, a secret manager)
  or reduce convenience.

Every L2 control assumes that all L1 controls are met.

**Default** says whether a fresh install already meets the control. *Met*
means the shipped configuration complies. *Operator* means you must act.
Controls marked "not exercised by the project's CI" are supported
configurations that the project does not test end to end: validate them in
staging before production.

## Summary

| ID | Control | Level | Default |
|---|---|---|---|
| HG-APP-1 | Run as `production` or `staging` so start-up safety checks apply | L1 | Met (Helm, prod compose) |
| HG-APP-2 | Generate every secret fresh; never reuse example values | L1 | Operator |
| HG-APP-3 | Keep the API docs UI off | L1 | Met (Helm, prod compose) |
| HG-APP-4 | Keep MFA required for platform admins | L1 | Met |
| HG-APP-5 | Protect `/metrics` with a bearer token | L1 | Operator |
| HG-APP-6 | Keep response dry run and the default autonomy until rehearsed | L1 | Met |
| HG-APP-7 | Verify the audit chain on a schedule and export before retention | L1 | Operator |
| HG-APP-8 | Require MFA for every local account of each tenant | L2 | Operator |
| HG-APP-9 | Shorten the refresh-token lifetime | L2 | Operator |
| HG-APP-10 | Choose the LLM provider and region per data-processing terms | L2 | Operator |
| HG-CMP-1 | Use the production override | L1 | Operator |
| HG-CMP-2 | Bind published ports to loopback; publish only the reverse proxy | L1 | Met |
| HG-CMP-3 | Keep the container hardening options | L1 | Met |
| HG-CMP-4 | Protect the `.env` file | L1 | Operator |
| HG-CMP-5 | Run signed images by digest | L1 | Operator |
| HG-CMP-6 | Never mount the Docker socket | L1 | Met |
| HG-CMP-7 | Pin PostgreSQL and Redis images by digest | L2 | Operator |
| HG-CMP-8 | Rootless Docker or user-namespace remapping | L2 | Operator |
| HG-K8S-1 | Secrets from a secret store, split into three Secrets | L1 | Operator |
| HG-K8S-2 | Pin images by digest | L1 | Operator |
| HG-K8S-3 | Keep the pod and container security contexts | L1 | Met |
| HG-K8S-4 | Enforce the `restricted` Pod Security Standard on the namespace | L1 | Operator |
| HG-K8S-5 | Do not mount service-account tokens | L1 | Met |
| HG-K8S-6 | Enable ingress NetworkPolicies | L1 | Operator |
| HG-K8S-7 | Delete the bootstrap Secret after the first install | L1 | Operator |
| HG-K8S-8 | Enable egress NetworkPolicies with narrow destinations | L2 | Operator |
| HG-K8S-9 | Verify image signatures at admission | L2 | Operator |
| HG-K8S-10 | Restrict who can read the namespace's Secrets | L2 | Operator |
| HG-PG-1 | Separate owner and runtime roles | L1 | Met (prod compose); Operator (Helm) |
| HG-PG-2 | Every tenant table has forced row-level security | L1 | Met |
| HG-PG-3 | Runtime containers never receive owner or superuser credentials | L1 | Met (prod compose, Helm) |
| HG-PG-4 | TLS to the database | L1 | Met (Helm `require`); Operator (compose) |
| HG-PG-5 | Verify the database server certificate (`verify-full`) | L2 | Operator |
| HG-PG-6 | Database not reachable from outside the platform network | L1 | Met (compose) |
| HG-PG-7 | SCRAM-SHA-256 password authentication | L1 | Met (postgres 16 image) |
| HG-PG-8 | Encrypted backups, keys stored apart, restore drills | L1 | Operator |
| HG-PG-9 | Log connections, never statements | L2 | Operator |
| HG-PG-10 | Point-in-time recovery | L2 | Operator |
| HG-RD-1 | Redis not reachable from outside the platform network | L1 | Met (compose) |
| HG-RD-2 | Redis requires authentication | L1 | Operator |
| HG-RD-3 | Keep `noeviction` and append-only persistence | L1 | Met (compose) |
| HG-RD-4 | ACL user restricted to the key prefix | L2 | Operator |
| HG-RD-5 | TLS to Redis | L2 | Operator |
| HG-PX-1 | TLS 1.2 or later only; HTTP redirects to HTTPS | L1 | Operator |
| HG-PX-2 | HSTS | L1 | Operator |
| HG-PX-3 | The outermost proxy overwrites `X-Forwarded-For` and `X-Forwarded-Proto` | L1 | Operator |
| HG-PX-4 | Trust forwarded headers only from the proxy's addresses | L1 | Met (compose); Operator (Helm) |
| HG-PX-5 | Never log query strings | L1 | Met (shipped proxies); Operator (your own) |
| HG-PX-6 | Publish only the UI and `/api/` | L1 | Met (Helm ingress with the UI) |
| HG-PX-7 | Body size and timeout limits at the edge | L1 | Operator |
| HG-PX-8 | Edge rate limits for sign-in and ingest | L2 | Operator |
| HG-PX-9 | Restrict who can reach the platform-admin UI and push ingest | L2 | Operator |
| HG-SC-1 | Verify signature and provenance before every deploy | L1 | Operator |
| HG-SC-2 | Verify air-gapped bundles against the out-of-band hash | L1 | Operator |
| HG-SC-3 | Mirror images to an internal registry by digest | L2 | Operator |

---

## 1. Application settings (HG-APP)

These apply to both Compose and Helm. In Compose, settings are environment
variables (`LG_SOTF_SECTION__KEY`). In Helm, non-secret settings live under
`settings:` in your values file and secrets in a Kubernetes Secret.
[configuration.md](configuration.md) lists every setting.

### HG-APP-1 Run as `production` or `staging`

**Level:** L1. **Default:** met by the Helm chart (`settings.environment:
production`) and by `docker-compose.prod.yml` (`staging`). The plain
development compose file runs `development`.

**Rationale.** In `staging` and `production` every process refuses to start
when the JWT secret is shorter than 32 bytes, when encryption keys or the
indicator HMAC key are missing, when a published placeholder secret is used,
or when CORS is a wildcard, cookies are insecure, the fake model runs
without `llm.allow_fake`, or the development database password is in the
URL (`src/lg_sotf/settings.py:500-536`).

**Check.** Compose: `docker compose -f docker/docker-compose.yml -f
docker/docker-compose.prod.yml config | grep LG_SOTF_ENVIRONMENT`. Helm:
`helm get values <release> -a -o json | jq -r .settings.environment`.
The value must be
`production` or `staging`.

**Set.** Compose: use the production override (HG-CMP-1). Helm: leave
`settings.environment: production`.

### HG-APP-2 Generate every secret fresh

**Level:** L1. **Default:** operator.

**Rationale.** The example files and `configs/development.yaml` carry
published values. HG-APP-1 refuses the known ones, but a value copied from
another install, a ticket or a chat is just as weak.

**Check.** The install starts in `production` or `staging` (HG-APP-1 refuses
published placeholders). Keep a record of when and by whom each secret was
generated.

**Set.** Compose: `make env` (adds freshly generated secrets to `.env`
without overwriting). Helm: `python scripts/generate_secrets.py --format
k8s --secret-name <release>`, then store the output in your secret manager,
not in Git. Rotate the encryption keys as described in
[operations.md](operations.md). Never rotate
`security.indicator_hmac_key` casually: correlation history stops matching.

### HG-APP-3 Keep the API docs UI off

**Level:** L1. **Default:** met by Helm (`api.docs_enabled: false`) and by
the production override. The application default is `true`.

**Rationale.** The interactive docs page loads scripts from a CDN, needs a
looser CSP than the API, and maps the attack surface for anyone who can
reach the API.

**Check.** From inside the platform network,
`curl -s -o /dev/null -w '%{http_code}\n' http://<api>:8000/docs` returns
`404`, and so does `https://<host>/api/v1/openapi.json` from outside.

**Set.** `LG_SOTF_API__DOCS_ENABLED=false` or `settings.api.docs_enabled:
false`. The OpenAPI document is published in the repository
(`docs/openapi.json`).

### HG-APP-4 Keep MFA required for platform admins

**Level:** L1. **Default:** met. `auth.require_mfa_for_platform_admins`
unset means required in `staging` and `production`.

**Rationale.** Platform admins can act on every tenant (see TM-MSP-1 in
the threat model). A phished password alone must not be enough.

**Check.** The setting is unset or `true`:
`docker compose ... config | grep REQUIRE_MFA_FOR_PLATFORM_ADMINS` (no
output, or `true`). Helm: `helm get values <release> -a -o json | jq
.settings.auth.require_mfa_for_platform_admins` (null or true).

**Set.** Remove any `LG_SOTF_AUTH__REQUIRE_MFA_FOR_PLATFORM_ADMINS=false`.
See [identity.md](identity.md) for enrolment and recovery.

### HG-APP-5 Protect `/metrics` with a bearer token

**Level:** L1. **Default:** operator. Without `api.metrics_token` the API's
`/metrics` answers anyone who can reach the API
(`src/lg_sotf/api/routers/health.py:66-79`).

**Rationale.** Metrics reveal tenant activity, queue depth, error rates and
LLM spend.

**Check.** From inside the platform network, `curl -s -o /dev/null -w
'%{http_code}\n' http://<api>:8000/metrics` returns `401`.

**Set.** Generate a random token and set `LG_SOTF_API__METRICS_TOKEN` in the
runtime Secret. With the Prometheus Operator, the chart's ServiceMonitor
reads it from `serviceMonitor.apiBearerTokenSecret`.

### HG-APP-6 Keep response dry run and the default autonomy until rehearsed

**Level:** L1. **Default:** met: `response.dry_run=true`, and autonomy is
`approval` for low, medium and high risk and `disabled` for critical
(`src/lg_sotf/settings.py:294-306`).

**Rationale.** A misconfigured connector or policy acts on the customer's
production systems. Dry run records what would happen and sends nothing.

**Check.** `LG_SOTF_RESPONSE__DRY_RUN` is unset or `true` until the
rehearsal described in [microsoft.md](microsoft.md) and
[soar-playbooks.md](soar-playbooks.md) has passed for each tenant. Review
each tenant's autonomy in **Tenant settings → Response**.

**Set.** Turn dry run off only after the rehearsal, and only raise a risk
level to `auto` with a documented decision by the tenant.

### HG-APP-7 Verify the audit chain on a schedule and export before retention

**Level:** L1. **Default:** operator.

**Rationale.** The hash chain shows tampering only if someone checks it.
Retention drops partitions after `retention.audit_days` (365 by default),
so evidence for an incident must be exported first.

**Check.** A scheduled job calls `GET /api/v1/audit/verify` per tenant as an
admin and alerts on a failure. Your runbook names who exports the audit
log at the start of an incident.

**Set.** Schedule the call (for example from your monitoring system), and
keep `retention.audit_days` at 365 or more unless your retention policy
says otherwise. The EU AI Act asks deployers to keep logs for at least 6
months.

### HG-APP-8 Require MFA for every local account of each tenant

**Level:** L2. **Default:** operator.

**Rationale.** Analysts approve containment. Customers that do not use
single sign-on rely on local passwords.

**Check.** For each tenant, `GET /api/v1/tenant/settings` shows
`security.require_mfa: true`, or the tenant signs in only through OIDC with
MFA enforced at the IdP.

**Set.** A tenant admin sets **Tenant settings → Sign-in security**, or
`PATCH /api/v1/tenant/settings {"security": {"require_mfa": true}}`.

### HG-APP-9 Shorten the refresh-token lifetime

**Level:** L2. **Default:** operator. Refresh tokens last 14 days
(`auth.refresh_token_ttl_s`, `src/lg_sotf/settings.py:167`).

**Rationale.** A shorter lifetime limits how long a stolen browser session
stays useful. Per-tenant session policy (idle timeout, absolute lifetime)
is planned (SEC6.3).

**Check.** `auth.refresh_token_ttl_s` is at most one shift plus margin, for
example 43200 (12 hours).

**Set.** `LG_SOTF_AUTH__REFRESH_TOKEN_TTL_S=43200` or
`settings.auth.refresh_token_ttl_s: 43200`.

### HG-APP-10 Choose the LLM provider and region per data-processing terms

**Level:** L2. **Default:** operator.

**Rationale.** Alert content, including personal data, is sent to the
configured provider (security.md section 7). The provider is install-wide
today; per-tenant model profiles are planned (AI-E5.2).

**Check.** `llm.provider`, `llm.base_url` and the model names match the
provider, region and contract recorded in your data-processing register.
For tenants that must not send data to any model, run a separate install
with `llm.enabled=false` (rules only).

**Set.** Use a self-hosted model ([local-llm.md](local-llm.md)) or a provider
endpoint in the required region. `llm.base_url` is checked at start-up: no
credentials in the URL, no metadata or link-local addresses, HTTPS unless
the host is internal (`src/lg_sotf/llm/endpoint.py:80-100`).

## 2. Docker Compose (HG-CMP)

### HG-CMP-1 Use the production override

**Level:** L1. **Default:** operator.

**Rationale.** `docker/docker-compose.prod.yml` creates two database roles,
runs `staging` (HG-APP-1), and gives each container only the secrets it
needs. No application container loads `.env`
(`docker/docker-compose.prod.yml:16-25`).

**Check.** `docker compose ls` and the command you deploy with both include
`-f docker/docker-compose.prod.yml`. `docker compose ... config` shows no
`env_file` for `api`, `worker`, `scheduler` or `migrate`.

**Set.** Start with
`docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml --env-file .env up -d`
as described in [deployment.md](deployment.md#production-like-compose-two-database-roles).

### HG-CMP-2 Bind published ports to loopback; publish only the reverse proxy

**Level:** L1. **Default:** met. The API (8000), the frontend (3000) and the
worker and scheduler health ports bind to `127.0.0.1`; PostgreSQL and Redis
publish no port (`docker/docker-compose.yml:116`, `docker/docker-compose.yml:136-137`,
`docker/docker-compose.yml:158-159`, `docker/docker-compose.yml:217-218`).

**Rationale.** Everything reachable from the network should pass through
the TLS proxy (section 6).

**Check.** On the host, `ss -ltnp` shows Docker listening only on
`127.0.0.1` for these ports, and your proxy on 443.

**Set.** Leave `API_BIND` and `FRONTEND_BIND` unset (they default to
`127.0.0.1`). Put the reverse proxy on the host or in its own container.

### HG-CMP-3 Keep the container hardening options

**Level:** L1. **Default:** met for every LG-SOTF container: read-only root
filesystem, a private `/tmp`, all capabilities dropped,
`no-new-privileges` (`docker/docker-compose.yml:43-57`), non-root uid 10001
in the image (`docker/Dockerfile:118`).

**Rationale.** These limit what code running in a compromised container can
do.

**Check.**
`docker inspect --format '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} sec={{.HostConfig.SecurityOpt}} user={{.Config.User}}' $(docker compose ps -q)`.
For the api, worker, scheduler, migrate and frontend containers expect
`ro=true`, `caps=[ALL]` and `no-new-privileges:true`.

**Set.** Do not remove these keys in your own override files.

### HG-CMP-4 Protect the `.env` file

**Level:** L1. **Default:** operator.

**Rationale.** `.env` holds the database, JWT and encryption secrets.

**Check.** `stat -c '%a %U' .env` shows `600` and the deploying user. The
file is not inside a Git working tree that is pushed anywhere
(`git check-ignore .env` prints `.env`).

**Set.** `chmod 600 .env`. Better, render it at deploy time from your secret
manager and delete it afterwards.

### HG-CMP-5 Run signed images by digest

**Level:** L1. **Default:** operator. The compose files build images
locally unless `APP_IMAGE` and `FRONTEND_IMAGE` are set.

**Rationale.** A tag can be moved; a digest cannot. The published images are
signed (HG-SC-1).

**Check.** `docker compose ... config | grep -E 'image: ghcr.io/gapilongo/lg-sotf(-frontend)?@sha256:'`
matches both images.

**Set.** After HG-SC-1, set
`APP_IMAGE=ghcr.io/gapilongo/lg-sotf@sha256:<digest>` and
`FRONTEND_IMAGE=ghcr.io/gapilongo/lg-sotf-frontend@sha256:<digest>`.

### HG-CMP-6 Never mount the Docker socket

**Level:** L1. **Default:** met. No shipped service mounts it.

**Rationale.** Access to `/var/run/docker.sock` is root on the host.

**Check.** `docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' $(docker compose ps -q) | grep docker.sock`
prints nothing.

**Set.** Do not add it, including for log shippers or "watchtower"-style
updaters on the same project.

### HG-CMP-7 Pin PostgreSQL and Redis images by digest

**Level:** L2. **Default:** operator. The defaults are tags
(`postgres:16-alpine`, `redis:7-alpine`).

**Rationale.** Same as HG-CMP-5, for the third-party images.

**Check.** `docker compose ... config | grep -E 'image: .*(postgres|redis).*@sha256:'`
matches both.

**Set.** `POSTGRES_IMAGE=postgres:16-alpine@sha256:<digest>` and
`REDIS_IMAGE=redis:7-alpine@sha256:<digest>`, updated with each patch
release.

### HG-CMP-8 Rootless Docker or user-namespace remapping

**Level:** L2. **Default:** operator. Not exercised by the project's CI.

**Rationale.** It maps container root (used by the PostgreSQL and Redis
images during start-up) to an unprivileged host user.

**Check.** `docker info --format '{{.SecurityOptions}}'` contains `rootless`
or `userns`.

**Set.** Follow Docker's rootless-mode or `userns-remap` documentation.
Volumes must be recreated or re-owned.

## 3. Kubernetes with Helm (HG-K8S)

### HG-K8S-1 Secrets from a secret store, split into three Secrets

**Level:** L1. **Default:** operator. The chart never creates Secrets, and
its values schema rejects secret-bearing keys
(`deploy/helm/lg-sotf/values.schema.json:8-9`).

**Rationale.** The owner DSN must reach only the migrate job and the
scheduler, and the bootstrap admin password only the migrate job.

**Check.** `helm get values <release> -a -o json | jq .secrets` shows
`existingSecret`, `ownerSecret` and (for the first install)
`bootstrapSecret`. The runtime Secret holds no `MIGRATION_URL` and no
`BOOTSTRAP_ADMIN_PASSWORD`:
`kubectl get secret <runtime> -o json | jq -r '.data | keys[]'`.

**Set.** Create the Secrets as in
[deployment.md section 3.1](deployment.md#31-create-the-secrets-the-chart-never-creates-them),
ideally through External Secrets Operator or the Secrets Store CSI driver
from your vault.

### HG-K8S-2 Pin images by digest

**Level:** L1. **Default:** operator. `image.digest` and
`frontend.image.digest` are empty (`deploy/helm/lg-sotf/values.yaml:14-15`).

**Rationale.** See HG-CMP-5.

**Check.** `kubectl get pods -n <ns> -o jsonpath='{..image}'` shows `@sha256:`
for every LG-SOTF container.

**Set.** `image.digest: sha256:<digest>` and `frontend.image.digest:
sha256:<digest>`, after verifying them (HG-SC-1).

### HG-K8S-3 Keep the pod and container security contexts

**Level:** L1. **Default:** met: `runAsNonRoot`, uid and gid 10001,
`RuntimeDefault` seccomp, no privilege escalation, read-only root
filesystem, all capabilities dropped
(`deploy/helm/lg-sotf/values.yaml:137-152`).

**Rationale.** See HG-CMP-3.

**Check.** `kubectl get pods -n <ns> -o json | jq '.items[].spec.containers[].securityContext'`
shows these values for every container.

**Set.** Do not override `podSecurityContext` or
`containerSecurityContext` with weaker values.

### HG-K8S-4 Enforce the `restricted` Pod Security Standard on the namespace

**Level:** L1. **Default:** operator.

**Rationale.** It stops anyone from adding a privileged pod to the namespace
later, by mistake or on purpose.

**Check.** `kubectl get ns <ns> -o jsonpath='{.metadata.labels}'` contains
`pod-security.kubernetes.io/enforce: restricted`. Before you set it, run
`kubectl label --dry-run=server --overwrite ns <ns>
pod-security.kubernetes.io/enforce=restricted`: it lists any pod that
would violate the standard.

**Set.** `kubectl label --overwrite ns <ns>
pod-security.kubernetes.io/enforce=restricted`.

### HG-K8S-5 Do not mount service-account tokens

**Level:** L1. **Default:** met: `serviceAccount.automountServiceAccountToken:
false` (`deploy/helm/lg-sotf/values.yaml:130-135`). The application never
calls the Kubernetes API.

**Rationale.** A token in the pod would give code running there access to
the Kubernetes API.

**Check.** `kubectl get pods -n <ns> -o json | jq '.items[].spec.automountServiceAccountToken'`
is `false` for every LG-SOTF pod.

**Set.** Leave the default.

### HG-K8S-6 Enable ingress NetworkPolicies

**Level:** L1. **Default:** operator. `networkPolicy.enabled: false`
(`deploy/helm/lg-sotf/values.yaml:477-499`). When it is enabled, the chart
refuses to render without `networkPolicy.api.from`
(`deploy/helm/lg-sotf/templates/networkpolicy.yaml:3-4`).

**Rationale.** Without policies any pod in the cluster can call the API and
the worker and scheduler health and metrics ports.

**Check.** `kubectl get networkpolicy -n <ns>` lists policies for the api,
frontend, worker and scheduler. From a test pod in another namespace,
`curl -m 3 http://<api-service>.<ns>:8000/healthz` times out.

**Set.** `networkPolicy.enabled: true`, `networkPolicy.api.from` selecting
your ingress controller, and `networkPolicy.metricsFrom` selecting
Prometheus. Your CNI must enforce NetworkPolicy.

### HG-K8S-7 Delete the bootstrap Secret after the first install

**Level:** L1. **Default:** operator.

**Rationale.** The bootstrap admin password is used once, by the first
migrate job.

**Check.** `kubectl get secret -n <ns> <bootstrap-secret>` returns
`NotFound`, and `secrets.bootstrapSecret` is empty in the release values.

**Set.** After the first admin has signed in and enrolled MFA, set
`secrets.bootstrapSecret: ""`, upgrade, and delete the Secret.

### HG-K8S-8 Enable egress NetworkPolicies with narrow destinations

**Level:** L2. **Default:** operator. Egress policies are off; when enabled
the default HTTPS destination is `0.0.0.0/0`
(`deploy/helm/lg-sotf/values.yaml:488-499`).

**Rationale.** It limits where a compromised pod can send data. It also
backs up the application's own egress policy
(`src/lg_sotf/net/egress.py:65-124`) at the network layer.

**Check.** `helm get values <release> -a -o json | jq .networkPolicy.egress`
shows `enabled: true`, `databaseTo` and `redisTo` set, and `httpsTo`
limited to your LLM provider, sources, SOAR and threat-intel ranges or an
egress proxy.

**Set.** Set those values. If you use an egress proxy, set `HTTPS_PROXY` in
`extraEnv` and allow only the proxy in `httpsTo`.

### HG-K8S-9 Verify image signatures at admission

**Level:** L2. **Default:** operator. Not exercised by the project's CI.

**Rationale.** The deploy workflow verifies signatures (HG-SC-1), but an
admission controller enforces it for every pod, whoever deploys it.

**Check.** A pod with an unsigned image (for example `busybox` by digest)
in the namespace is refused.

**Set.** Sigstore policy-controller or Kyverno `verifyImages`, with the exact
signer identity and issuer from [security.md](security.md#verify-an-image-yourself).
Never accept an identity regular expression such as `.*`.

### HG-K8S-10 Restrict who can read the namespace's Secrets

**Level:** L2. **Default:** operator.

**Rationale.** Anyone who can read the runtime Secret has the encryption
keys and the database DSN.

**Check.** `kubectl auth can-i get secrets -n <ns> --as <user-or-group>` is
`no` for everyone except the platform operators and your secret-sync
controller.

**Set.** Namespace-scoped RBAC with no wildcard roles. Audit Secret reads in
the Kubernetes audit log.

## 4. PostgreSQL (HG-PG)

### HG-PG-1 Separate owner and runtime roles

**Level:** L1. **Default:** met by the production compose override
(`docker/postgres/init-roles.sh:21-30`). Helm: operator (set
`settings.database.runtime_role` and `secrets.ownerSecret`).

**Rationale.** Row-level security protects tenants only if the API and
worker connect as a role that cannot bypass it. `lg-sotf migrate` refuses to
grant to a runtime role that is a superuser, has `BYPASSRLS` or belongs to
the owner role (`src/lg_sotf/db/migrate.py:227-249`).

**Check.**

```sql
SELECT rolname, rolsuper, rolbypassrls,
       pg_has_role(rolname, (SELECT relowner FROM pg_class WHERE oid = 'public.tenants'::regclass), 'MEMBER') AS owner_member
FROM pg_roles WHERE rolname = '<runtime role>';
```

All three flags are `false`.

**Set.** Follow [deployment.md section 4](deployment.md#4-two-role-postgresql-setup).

### HG-PG-2 Every tenant table has forced row-level security

**Level:** L1. **Default:** met by the migrations
(`src/lg_sotf/db/migrations/versions/0001_initial.py:516`).

**Rationale.** A table without `FORCE ROW LEVEL SECURITY` would be readable
across tenants by its owner, and a missing policy would expose a new table.

**Check.** Run as any role; the query must return no rows:

```sql
SELECT c.relname
FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
  AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
```

**Set.** Never disable RLS by hand. Run `lg-sotf migrate` after every
upgrade.

### HG-PG-3 Runtime containers never receive owner or superuser credentials

**Level:** L1. **Default:** met by the production override and the Helm
chart: the owner DSN goes only to migrate and the scheduler.

**Rationale.** See HG-PG-1. A credential in an environment variable is
readable by any code in that container.

**Check.** Compose: in `docker compose ... config`, the `api` and `worker`
services have no `LG_SOTF_DATABASE__MIGRATION_URL` and their
`LG_SOTF_DATABASE__URL` user is the runtime role. Helm: the runtime Secret
has no `LG_SOTF_DATABASE__MIGRATION_URL` (HG-K8S-1).

**Set.** Keep the split. The PostgreSQL superuser password is for
administration only.

### HG-PG-4 TLS to the database

**Level:** L1. **Default:** met by Helm (`settings.database.ssl_mode:
require`, `deploy/helm/lg-sotf/values.yaml:62`). Compose: operator (the
bundled PostgreSQL is on the private compose network; set it when the
database is elsewhere).

**Rationale.** Without TLS the DSN password and tenant data cross the
network in clear text.

**Check.** As the runtime role:
`SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid();`
returns `t`. On the server, `pg_hba.conf` uses `hostssl` for the
application roles.

**Set.** `LG_SOTF_DATABASE__SSL_MODE=require` or `settings.database.ssl_mode`.
The setting is translated for asyncpg and psycopg
(`src/lg_sotf/db/pool.py:90-111`).

### HG-PG-5 Verify the database server certificate

**Level:** L2. **Default:** operator.

**Rationale.** `require` encrypts but does not authenticate the server, so
an attacker on the path can still impersonate it.

**Check.** `ssl_mode` is `verify-full`; if the server uses a private CA,
`ssl_root_cert` points at that CA's file.

**Set.** `settings.database.ssl_mode: verify-full` and
`settings.database.ssl_root_cert: /etc/lg-sotf/db-ca.crt`, mounted with
`extraVolumes` and `extraVolumeMounts`.

### HG-PG-6 Database not reachable from outside the platform network

**Level:** L1. **Default:** met by compose (no published port). Kubernetes
and managed databases: operator.

**Rationale.** It removes direct password-guessing and protocol attacks.

**Check.** From a host outside the platform network,
`pg_isready -h <db host> -p 5432` fails or times out.

**Set.** Managed database: a private endpoint and a firewall rule for the
cluster's egress range. Kubernetes: HG-K8S-8, plus a NetworkPolicy on the
database itself.

### HG-PG-7 SCRAM-SHA-256 password authentication

**Level:** L1. **Default:** met by the official PostgreSQL 16 image.

**Rationale.** MD5 password hashes are weak and can be replayed.

**Check.** `SHOW password_encryption;` returns `scram-sha-256`, and
`SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%';` (as a
superuser) returns no rows. `pg_hba.conf` has no `md5`, `password` or
`trust` lines for network connections.

**Set.** `password_encryption = scram-sha-256`, then reset the role
passwords.

### HG-PG-8 Encrypted backups, keys stored apart, restore drills

**Level:** L1. **Default:** operator.

**Rationale.** A dump holds every tenant's alerts and the encrypted
credentials. The Fernet keys decrypt them, so dump and keys must never be
stored together. Erasure removes rows, but a backup made earlier still
holds them until it expires. Crypto-shredding with per-tenant keys is
planned (ARCH-E4.4, SEC5.1).

**Check.** Backups are encrypted at rest. The encryption keys and the
indicator HMAC key are in the secret manager, not in the backup location.
Backup retention is documented and matches what you tell customers about
erasure. A restore drill was done in the last quarter.

**Set.** See [deployment.md section 8](deployment.md#8-backups).

### HG-PG-9 Log connections, never statements

**Level:** L2. **Default:** operator.

**Rationale.** Connection logs show credential misuse. Statement logging
(`log_statement = all`, or `log_min_duration_statement = 0`) would copy
alert content and personal data into the server log.

**Check.** `SHOW log_connections;` and `SHOW log_disconnections;` return
`on`. `SHOW log_statement;` returns `none` or `ddl`.

**Set.** Set those parameters in `postgresql.conf` or your provider's
parameter group.

### HG-PG-10 Point-in-time recovery

**Level:** L2. **Default:** operator.

**Rationale.** Ransomware or an operator mistake may only be noticed hours
later. The audit log is part of your incident evidence.

**Check.** WAL archiving is on (`SHOW archive_mode;` returns `on`), or the
managed service's PITR window is at least 7 days.

**Set.** Your provider's PITR, or `pg_basebackup` with WAL archiving.

## 5. Redis (HG-RD)

Redis holds in-flight queue entries, pub/sub for live events, rate-limit
windows, the token-budget cache and other caches. It is not the system of
record, but anyone who can write to it can inject work or read events.

### HG-RD-1 Redis not reachable from outside the platform network

**Level:** L1. **Default:** met by compose (no published port).
Kubernetes and managed Redis: operator.

**Rationale.** Redis without authentication (HG-RD-2) is fully open to
anyone who can connect.

**Check.** From outside the platform network,
`redis-cli -h <redis host> -p 6379 ping` fails or times out.

**Set.** A private endpoint, a firewall rule, and HG-K8S-8.

### HG-RD-2 Redis requires authentication

**Level:** L1. **Default:** operator. The compose files run Redis without a
password and the production override sets
`LG_SOTF_REDIS__URL=redis://redis:6379/0`
(`docker/docker-compose.prod.yml:40`). Not exercised by the project's CI;
validate in staging.

**Rationale.** Network isolation (HG-RD-1) alone leaves Redis open to every
container on the same network.

**Check.** Without credentials, `redis-cli -h <redis host> ping` answers
`NOAUTH Authentication required.`

**Set.** The client takes the password from the URL
(`src/lg_sotf/queue/redis.py:18-24`). In Compose, add a further override
file that starts Redis with a mounted configuration file containing
`requirepass <password>` (a file keeps the password off the process command
line), sets `REDISCLI_AUTH` for the health check, and sets
`LG_SOTF_REDIS__URL=redis://:<password>@redis:6379/0` for `migrate`, `api`,
`worker` and `scheduler`. Kubernetes: put the URL with the password in the
runtime Secret and, with KEDA, set `worker.keda.passwordSecret`.

### HG-RD-3 Keep `noeviction` and append-only persistence

**Level:** L1. **Default:** met by compose: AOF with `everysec`
(`docker/docker-compose.yml:78`), and Redis's default `noeviction`.

**Rationale.** An eviction policy would silently drop queued alerts or
reset rate-limit windows. The scheduler re-creates lost work from
PostgreSQL, but only after a delay.

**Check.** `redis-cli CONFIG GET maxmemory-policy` returns `noeviction`;
`CONFIG GET appendonly` returns `yes` (or the managed service has
persistence on).

**Set.** `maxmemory-policy noeviction`, `appendonly yes`. Size memory for
peak queue depth instead of evicting. Alert on memory use.

### HG-RD-4 ACL user restricted to the key prefix

**Level:** L2. **Default:** operator. Not exercised by the project's CI;
validate in staging.

**Rationale.** A dedicated user without administrative commands cannot run
`CONFIG`, `FLUSHALL`, `KEYS`, `MODULE` or `DEBUG`, even with the password.
All keys, streams and channels start with `redis.key_prefix` (default
`lgsotf`).

**Check.** `redis-cli --user lgsotf --pass <pw> ACL WHOAMI` returns
`lgsotf`, and `redis-cli --user lgsotf --pass <pw> CONFIG GET maxmemory`
is refused with `NOPERM`. The `default` user is off.

**Set.** In an ACL file:

```
user default off
user lgsotf on ><password> ~lgsotf:* &lgsotf:* +@all -@dangerous
```

Use the user in the URL: `redis://lgsotf:<password>@redis:6379/0`. Keep a
separate administrative user for operators. If the health check needs
`ping`, it is allowed by these rules.

### HG-RD-5 TLS to Redis

**Level:** L2. **Default:** operator.

**Rationale.** It protects queue contents (alert ids, event payloads) and
the Redis password on the network.

**Check.** `LG_SOTF_REDIS__URL` starts with `rediss://`. With KEDA,
`worker.keda.enableTLS: true`.

**Set.** A Redis server with TLS, then `rediss://...` in the runtime Secret
(see [deployment.md section 5](deployment.md#5-tls)).

## 6. Reverse proxy and ingress (HG-PX)

The shipped proxies are the frontend's nginx (`src/lg_front/docker/nginx.conf`),
which can also proxy `/api/`, and the Caddy edge used on the project's VMs
(`deploy/vm/caddy/Caddyfile.tmpl`). On Kubernetes the chart's Ingress hands
TLS to your ingress controller. These controls apply to whichever proxy
terminates TLS.

### HG-PX-1 TLS 1.2 or later only; HTTP redirects to HTTPS

**Level:** L1. **Default:** operator.

**Rationale.** Sessions, refresh cookies and API keys cross this hop.
Refresh cookies are `Secure`, so browser sign-in needs HTTPS anyway.

**Check.** `openssl s_client -connect <host>:443 -tls1_1 </dev/null` fails;
`-tls1_2` succeeds. `curl -s -o /dev/null -w '%{http_code}\n'
http://<host>/` returns `301` or `308`.

**Set.** ingress-nginx: `ssl-protocols: "TLSv1.2 TLSv1.3"` in the controller
ConfigMap (its default). Caddy uses TLS 1.2+ by default. Use certificates
from cert-manager or ACME.

### HG-PX-2 HSTS

**Level:** L1. **Default:** operator. The API sends HSTS on HTTPS requests;
the frontend sends it only when `LG_SOTF_HSTS_MAX_AGE` /
`frontend.config.hstsMaxAge` is set
(`src/lg_front/docker/entrypoint.sh:123-134`).

**Rationale.** It stops downgrade and cookie-stripping attacks after the
first visit.

**Check.** `curl -sI https://<host>/ | grep -i strict-transport-security`
shows `max-age` of at least 31536000.

**Set.** `frontend.config.hstsMaxAge: "31536000"` (Helm) or
`FRONTEND_HSTS_MAX_AGE=31536000` (compose), or set the header at the proxy.

### HG-PX-3 The outermost proxy overwrites `X-Forwarded-For` and `X-Forwarded-Proto`

**Level:** L1. **Default:** operator.

**Rationale.** A client can send its own `X-Forwarded-For`. If the edge
appends to it, the application may record and rate-limit an address the
client chose.

**Check.** Send a request with `X-Forwarded-For: 203.0.113.9` and sign in
with a wrong password; the audit entry or the log shows your real address,
not `203.0.113.9`.

**Set.** ingress-nginx: keep `use-forwarded-headers: "false"` unless it sits
behind another trusted load balancer, and set `compute-full-forwarded-for`
only together with `proxy-real-ip-cidr`. Caddy sets the headers from the
connection unless `trusted_proxies` says otherwise.

### HG-PX-4 Trust forwarded headers only from the proxy's addresses

**Level:** L1. **Default:** met by compose: the API trusts only the
frontend's fixed address (`docker/docker-compose.yml:107-110`). Helm:
operator (`api.forwarded_allow_ips` defaults to `127.0.0.1`).

**Rationale.** The client address drives per-address login limits and the
audit trail. Trusting a whole pod range would let any pod in it forge its
address.

**Check.** `api.forwarded_allow_ips` lists only the ingress controller pods
or load-balancer addresses, and the frontend's `LG_SOTF_TRUSTED_PROXIES`
lists only the proxy in front of it
(`src/lg_front/docker/entrypoint.sh:161-163`).

**Set.** `settings.api.forwarded_allow_ips: "10.0.12.4,10.0.12.5"` (your
addresses), `frontend` environment `LG_SOTF_TRUSTED_PROXIES`.

### HG-PX-5 Never log query strings

**Level:** L1. **Default:** met by the shipped proxies: nginx logs `$uri`
(`src/lg_front/docker/nginx.conf:29-33`) and the Caddy edge does not write
access logs (`deploy/vm/caddy/Caddyfile.tmpl:6-14`). Your own proxy:
operator.

**Rationale.** Browsers cannot send headers on a WebSocket, so the access
token travels in the `/api/v1/ws` query string. OIDC authorisation codes
also arrive in query strings.

**Check.** Open the UI, let the live view connect, and search your proxy's
logs for `token=`. Nothing is found.

**Set.** ingress-nginx: a `log-format-upstream` that uses `$uri` instead of
`$request` or `$request_uri`. Other proxies: log the path without the
query. Apply the same to error logs where the proxy allows it.

### HG-PX-6 Publish only the UI and `/api/`

**Level:** L1. **Default:** met by the Helm Ingress with the frontend
enabled (`/` to the UI, `/api` to the API). The API serves `/metrics`,
`/healthz` and `/readyz` at its root, outside `/api`.

**Rationale.** Health and metrics endpoints are for the cluster, not the
internet (see also HG-APP-5).

**Check.** `curl -s https://<host>/metrics | head -c 200` does not return
Prometheus text (lines starting with `# HELP`).

**Set.** Route only `/` to the frontend and `/api` to the API. If the API
has its own host, route only `/api/` there.

### HG-PX-7 Body size and timeout limits at the edge

**Level:** L1. **Default:** operator. The API enforces its own limits while
streaming the body (`src/lg_sotf/api/middleware.py:189-235`); the edge should
refuse oversized requests first.

**Rationale.** It protects the proxy and the API from slow or oversized
requests.

**Check.** The proxy's body limit is set (for example 10 MiB, enough for
your largest ingest batch) and only `/api/v1/ws` has a long read timeout.

**Set.** ingress-nginx annotations `proxy-body-size` and, for WebSockets,
`proxy-read-timeout` (examples in `deploy/helm/lg-sotf/values.yaml:445-448`).

### HG-PX-8 Edge rate limits for sign-in and ingest

**Level:** L2. **Default:** operator.

**Rationale.** The API's own rate limits use Redis and fail open when Redis
is unavailable (`src/lg_sotf/api/ratelimit.py:67-70`). An edge limit keeps
working in that case.

**Check.** More than your threshold of `POST /api/v1/auth/login` requests
per minute from one address receive `429` from the proxy.

**Set.** ingress-nginx `limit-rpm` on a separate Ingress for
`/api/v1/auth/`, or the equivalent in your WAF or load balancer.

### HG-PX-9 Restrict who can reach the platform-admin UI and push ingest

**Level:** L2. **Default:** operator. The application has no IP allowlist
yet (planned in SEC6.3).

**Rationale.** Platform admins can reach every tenant. Push ingestion
comes from a known set of sources.

**Check.** Requests to `/api/v1/platform/` and `/api/v1/ingest/` from
outside the allowed ranges are refused at the edge.

**Set.** A source-range rule at the proxy (ingress-nginx
`whitelist-source-range` on a separate Ingress for those paths), a VPN, or
mutual TLS for ingest sources.

## 7. Supply chain and image verification (HG-SC)

### HG-SC-1 Verify signature and provenance before every deploy

**Level:** L1. **Default:** operator for your own deployments. The
project's deploy workflow does this
(`.github/workflows/deploy.yml:229-232`).

**Rationale.** It proves the image was built by the release workflow on
`main` of this repository and has not been changed since.

**Check.** For both images, `cosign verify` with the exact identity and
issuer, and `gh attestation verify ... --deny-self-hosted-runners`, succeed
on the digest you deploy.

**Set.** Follow [security.md, "Verify an image yourself"](security.md#verify-an-image-yourself),
then deploy that digest (HG-CMP-5, HG-K8S-2).

### HG-SC-2 Verify air-gapped bundles against the out-of-band hash

**Level:** L1. **Default:** operator.

**Rationale.** The bundle crosses the air gap on removable media. A signed
bundle is planned (SEC1.4).

**Check.** The SHA-256 of `SHA256SUMS` matches the value received over a
separate channel, and `sha256sum -c SHA256SUMS` passes.

**Set.** Follow [air-gapped.md](air-gapped.md). Verify the published images
before you bundle them.

### HG-SC-3 Mirror images to an internal registry by digest

**Level:** L2. **Default:** operator.

**Rationale.** Pulling from a registry you control removes a runtime
dependency on GHCR and Docker Hub. It also gives you one place to scan
images.

**Check.** Every image reference in the deployment points at your registry
by digest, and the mirrored digest equals the verified upstream digest.

**Set.** Copy with `crane copy` or `skopeo copy --all` (this preserves the
multi-arch digest), and copy the signatures too (`cosign copy`) if you
verify at admission.
