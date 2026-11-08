# Deployment

LG-SOTF ships as **one container image** with four process roles (see
`docs/architecture.md` section 1):

| Role | Command | Kubernetes object | Scaling |
|---|---|---|---|
| API | `lg-sotf api` | Deployment + Service (+ HPA, Ingress) | horizontal, CPU HPA |
| Worker | `lg-sotf worker` | Deployment (+ KEDA ScaledObject or HPA) | horizontal, queue lag |
| Scheduler | `lg-sotf scheduler` | Deployment, 2 replicas | one active leader (PostgreSQL advisory lock) |
| Migrate | `lg-sotf migrate` | Job, Helm pre-install/pre-upgrade hook | one-shot, idempotent |

Supporting services: PostgreSQL 15+ (16 recommended) and Redis 7+ (Streams
consumer-group lag is used for autoscaling).

Files:

| Path | Purpose |
|---|---|
| `docker/Dockerfile` | Multi-stage image build |
| `docker/docker-compose.yml` | Development / evaluation stack |
| `docker/docker-compose.prod.yml` | Override: two database roles, mandatory secrets, `staging` safety checks |
| `docker/postgres/init-roles.sh` | Creates the owner and runtime roles for the override |
| `deploy/helm/lg-sotf` | Helm chart |
| `.env.example` | Every important setting, with how to generate secrets |
| `scripts/generate_secrets.py` | Fresh random secrets (`.env` or `kubectl create secret`) |
| `Makefile` | `make help` lists the shortcuts |
| `deploy/vm/` | Single-VM deploys (Caddy HTTPS, dev/uat, rollback, backups) used by the CI/CD pipeline |

Hosted dev and uat environments (images published to GHCR for amd64 and
arm64, deployed over SSH to an Oracle Cloud Always Free VM behind Caddy,
promotion by release tag, automatic rollback) are described in
[cicd.md](cicd.md).
To host them on your own Windows PC instead (WSL2, Tailscale Funnel), see [self-hosting-pc.md](self-hosting-pc.md).

## 1. The image

```sh
make image                                    # tag lg-sotf:dev
make image IMAGE=registry.example.com/lg-sotf:1.0.0 \
     PYTHON_BASE_IMAGE=mirror.gcr.io/library/python:3.11-slim
```

* Builder stage installs the **hash-locked** `requirements.txt` with
  `pip install --require-hashes` (binary wheels only, no compiler) and the
  application wheel with `--no-deps`, then `pip check`.
* Runtime stage is `python:3.11-slim`, pinned by digest in `docker/Dockerfile`
  (override with `--build-arg BASE_IMAGE=`, ideally with the same digest),
  contains no build tools and no pip, and runs as uid/gid
  **10001**. Only `/tmp` must be writable, so it runs with a read-only root
  filesystem.
* `dumb-init` is PID 1 (signal forwarding, zombie reaping); `SIGTERM` starts a
  graceful drain in every role.
* `ENTRYPOINT ["dumb-init", "--", "lg-sotf"]`, default `CMD ["api"]`. Run another
  role by passing it as the command: `docker run lg-sotf:dev worker`.
* `HEALTHCHECK` runs `docker/healthcheck.py`, which detects the role from PID 1
  and probes `:8000/healthz` (api) or `:9100/healthz` (worker, scheduler);
  one-shot commands report healthy.
* OCI labels (`org.opencontainers.image.*`) carry version, revision and build time.
* Behind a TLS-intercepting proxy, pass its CA as a build secret (never stored in
  a layer): `make image BUILD_CA_FILE=/path/to/ca.crt`.

## 2. Docker Compose quickstart (evaluation)

```sh
make env        # .env from .env.example + fresh secrets (never overwrites existing keys)
make up         # builds the image, starts postgres, redis, migrate, api, worker, scheduler; waits for health
make ps
curl -s localhost:8000/readyz      # api
curl -s localhost:9101/readyz      # worker health server
curl -s localhost:9102/readyz      # scheduler health server
make logs
make down       # keep data;  make clean-volumes  to delete it
```

Defaults: `LG_SOTF_LLM__PROVIDER=fake` (deterministic, offline, no API key),
`response.dry_run=true`, the reference `configs/development.yaml` loaded through
`LG_SOTF_CONFIG_FILE` (its published placeholder keys are refused by
staging/production). Real triage: set `LG_SOTF_LLM__PROVIDER=anthropic` and
`ANTHROPIC_API_KEY` in `.env`.

Create the first admin by setting `LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL` and
`LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD` in `.env` before `make up`, or later:

```sh
printf '%s\n' "$PASSWORD" | docker compose -f docker/docker-compose.yml run --rm -T migrate \
    create-admin --tenant default --email admin@example.com --password-stdin
```

Web UI: `make up PROFILES=frontend` builds `src/lg_front/Dockerfile` and serves
the app on `http://localhost:${FRONTEND_PORT:-3000}` (nginx, non-root, port 8080
in the container), proxying `/api` and the `/api/v1/ws` WebSocket to the api
service. Open it as `http://localhost:3000`: the API accepts the live-update
WebSocket only from origins in `api.cors_origins`, which the development
configuration sets to `http://localhost:3000` and `http://localhost:5173`. Stop
it with the same profile (`make down PROFILES=frontend`). With the
production-like overlay below, add `--profile frontend` and set
`LG_SOTF_API__CORS_ORIGINS` to the UI's URL; `scripts/e2e_ui_stack.sh` does
exactly that and drives the UI in a browser.

Client addresses behind the bundled nginx: the frontend and the api share a
small `edge` network with fixed addresses (`EDGE_SUBNET`, default
`172.31.250.0/29`; frontend `EDGE_FRONTEND_IP` `.2`, api `EDGE_API_IP` `.3`;
change them if the range is taken on the host), and the api trusts
`X-Forwarded-For` only from the frontend (`LG_SOTF_API__FORWARDED_ALLOW_IPS`
defaults to `EDGE_FRONTEND_IP`). Without this, every browser request would
carry the frontend's address, one client could exhaust the per-address login
limit for everyone, and audit entries would record the proxy. When a TLS
reverse proxy sits in front of the frontend, set `FRONTEND_TRUSTED_PROXIES`
(`LG_SOTF_TRUSTED_PROXIES` in the container) to its address or CIDR: nginx
then takes the client address and `X-Forwarded-Proto` from that proxy only.

Registry mirrors: `PYTHON_BASE_IMAGE`, `POSTGRES_IMAGE`, `REDIS_IMAGE` (see
`.env.example`). Host ports bind to `127.0.0.1` only; PostgreSQL and Redis are
not published (`docker compose exec postgres psql -U soc soc`).

Every lg-sotf container runs read-only with a private `/tmp`, `cap_drop: ALL`
and `no-new-privileges`.

### Production-like compose (two database roles)

```sh
python scripts/generate_secrets.py --append .env
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml --env-file .env up -d --build --wait
```

This override runs with `environment=staging`, so every process runs
`settings.assert_safe()` and refuses missing or placeholder secrets. PostgreSQL
gets `lgsotf_owner` (migrate, scheduler) and `lgsotf_app` (api, worker; no
ownership, no `BYPASSRLS`) from `docker/postgres/init-roles.sh`. The fake LLM is
allowed only via `LG_SOTF_LLM__ALLOW_FAKE=true` (the override's default, for
demos). `auth.cookie_secure=true`, so browser logins need HTTPS in front of the
API (browsers exempt only `http://localhost`, which is how
`scripts/e2e_ui_stack.sh` tests the UI against this overlay).

`.env` holds every password, but in the override it is used **only for `${...}`
interpolation** (`--env-file`); the app services reset `env_file`, so the file
itself is never loaded into a container. Each service receives exactly:

| Service | Database credentials | Other secrets |
|---|---|---|
| postgres | superuser, owner and app passwords, and the shadow password when set (to create the roles) | none |
| migrate | `lgsotf_app` DSN, `lgsotf_owner` DSN (`LG_SOTF_DATABASE__MIGRATION_URL`) | app secrets, bootstrap admin email/password |
| scheduler | `lgsotf_app` DSN, `lgsotf_owner` DSN | app secrets |
| api | `lgsotf_app` DSN only | app secrets |
| worker | `lgsotf_app` DSN, and the `lgsotf_shadow` DSN when `LGSOTF_SHADOW_PASSWORD` is set | app secrets |

Shadow runs (a candidate pipeline replayed on real alerts, read only) connect
only as `lgsotf_shadow`, a third login that `lg-sotf migrate` grants `SELECT`
and nothing else (section 4). It is optional: set `LGSOTF_SHADOW_PASSWORD` in
`.env` before the first start and `init-roles.sh` creates it, the migrate job
grants it (`database.shadow_role`) and the worker gets its DSN
(`database.shadow_url`). Without it shadow runs refuse to start; they never fall
back to `lgsotf_app`. On a database created before, add the role by hand
(section 4), then set the password and run `migrate` again.

"App secrets" are the JWT secret, Fernet keys and indicator HMAC key, plus the
optional settings listed under `x-passthrough` in `docker-compose.prod.yml`
(metrics token, LLM keys, OIDC, webhook, CORS, `forwarded_allow_ips`, ...),
which are forwarded only when set. `POSTGRES_SUPERUSER_PASSWORD`,
`LGSOTF_OWNER_PASSWORD` and `LGSOTF_APP_PASSWORD` never reach an application
container. To pass another setting, add it to `x-passthrough`; leave a key out
of `.env` rather than setting it to an empty value (an empty value is passed as
an empty string, not as unset).

The development stack (`docker-compose.yml` alone) does load `.env` into every
app container for convenience; it uses a single database role, so do not put
production credentials in a `.env` used with it.

### Verified run (recorded)

Environment: Docker 29.3.1, Compose v5.1.1, base images from `mirror.gcr.io`,
image built from the current tree, fake LLM. Host ports moved to 18000/19101/19102
to avoid local clashes.

```text
$ make image PYTHON_BASE_IMAGE=mirror.gcr.io/library/python:3.11-slim BUILD_CA_FILE=<proxy CA>
... naming to docker.io/library/lg-sotf:dev done                        (rc=0, image 488MB)
$ docker run --rm lg-sotf:dev version
1.0.0
$ docker run --rm --entrypoint id lg-sotf:dev
uid=10001(lgsotf) gid=10001(lgsotf) groups=10001(lgsotf)

$ export POSTGRES_IMAGE=mirror.gcr.io/library/postgres:16-alpine REDIS_IMAGE=mirror.gcr.io/library/redis:7-alpine \
         API_PORT=18000 WORKER_HEALTH_PORT=19101 SCHEDULER_HEALTH_PORT=19102
$ docker compose -p lgsotf-verify -f docker/docker-compose.yml up -d --no-build --wait \
    postgres redis migrate api worker scheduler
SERVICE     STATE     STATUS
api         running   Up 5 seconds (healthy)
migrate     exited    Exited (0) 6 seconds ago
postgres    running   Up 14 seconds (healthy)
redis       running   Up 14 seconds (healthy)
scheduler   running   Up 5 seconds (healthy)
worker      running   Up 5 seconds (healthy)
$ curl -s localhost:18000/healthz
{"status":"ok"}
$ curl -s localhost:18000/readyz; curl -s localhost:19101/readyz; curl -s localhost:19102/readyz
{"status":"ok","checks":{"database":"ok","redis":"ok"}}      (x3)
$ curl -s -o /dev/null -w '%{http_code}' localhost:18000/api/v1/alerts
401
$ docker compose -p lgsotf-verify -f docker/docker-compose.yml down -v

# Production-like override, .env = .env.example + `generate_secrets.py --append` +
# LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL
$ docker compose -p lgsotf-prodverify -f docker/docker-compose.yml -f docker/docker-compose.prod.yml \
    --env-file .env up -d --no-build --wait
all six services as above: migrate Exited (0), the rest (healthy)
migrate log: "runtime role: privileges granted to lgsotf_app"
             "bootstrap admin created: admin@example.com"
$ for s in api worker scheduler; do docker compose ... exec -T $s env | grep -E 'PASSWORD|MIGRATION|OWNER|SUPERUSER'; done
api:       (none)
worker:    (none)
scheduler: LG_SOTF_DATABASE__MIGRATION_URL
migrate:   LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD LG_SOTF_DATABASE__MIGRATION_URL
pg_stat_activity: lgsotf_app -> lg-sotf-api, lg-sotf-worker;
                  lgsotf_owner -> lg-sotf-scheduler, lg-sotf-scheduler-leader
POST /api/v1/auth/login (bootstrap admin) -> 200 {access_token, expires_in, token_type, user}
$ docker compose ... down -v
```

The same overlay with the web UI, driven in Chromium by the Playwright suite
(`src/lg_front/e2e`; images built from the tree, base images from
`mirror.gcr.io`, `BUILD_CA_FILE` for the TLS-intercepting proxy):

```text
$ PYTHON_BASE_IMAGE=... NODE_IMAGE=... NGINX_IMAGE=... POSTGRES_IMAGE=... REDIS_IMAGE=... \
  BUILD_CA_FILE=<proxy CA> scripts/e2e_ui_stack.sh
==> building lg-sotf:e2e
==> building lg-sotf-frontend:e2e
==> starting the stack (lgsotf-e2e) with the web UI on http://localhost:13000
api, frontend, postgres, redis, scheduler, worker: running (healthy); migrate: exited (0)
==> Playwright suite (src/lg_front/e2e)
  ok  security headers on every document, and the admin signs in under the CSP
  ok  the admin creates an API key, an analyst and a viewer in the UI
  ok  the Overview updates live when alerts arrive through the ingest API
  ok  alerts: filters, pagination and the alert timeline
  ok  a viewer reads everything but sees no administration
  ok  an analyst has no administration either
  ok  an analyst claims and decides an escalation, and the alert closes
  ok  response approval: role gating, the admin approves, the alert closes as malicious
  ok  main pages render under the CSP (and screenshots for the README)
  ok  sign-out ends the session: no token left, the refresh cookie no longer works
  10 passed (52.0s)
==> container logs carry no access tokens
ok    no JWT in the frontend, api, worker or scheduler logs
E2E UI PASSED                                   (about 2 minutes including both builds)
```

### End-to-end smoke test (`make smoke`)

`scripts/smoke_stack.sh` (also `make smoke`, and the "Stack smoke test" step
of the CI image job) proves the production-like stack works the way a
customer uses it, through the HTTP API only. It generates secrets into a
private temporary directory, starts postgres, redis, migrate, api, worker and
scheduler with the fake LLM and a bootstrap admin from the env file, creates
a second tenant and its admin with the CLI inside a container, then runs
`scripts/smoke_stack.py`:

* **flow**: `/healthz`, `/readyz`; login and the refresh-cookie attributes
  (`HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/v1/auth`); an `ingest`
  API key (which cannot read alerts); canonical fixtures to
  `/ingest/alerts` (duplicates are not re-queued); a `webhook` source with the
  generic vendor fixture and its field map, then vendor payloads to
  `/ingest/webhook/{id}`; the `/api/v1/ws` event stream; every alert
  settles; every escalation is claimed (a stale `version` is 409) and decided;
  every pending action is approved and runs as `dry_run`; every alert closes
  with the expected disposition; `/dashboard/summary`, `/usage/llm`,
  `/audit` and `/audit/verify`; `/metrics` refuses no or a wrong token and
  carries no tenant ids, `/api/v1/metrics` is 404; tenant isolation against
  the second tenant (404 for the other tenant's alerts, timeline and actions,
  403 for `X-Tenant-ID` from a non-platform admin, the platform admin's
  cross-tenant read lands in that tenant's audit log); refresh rotation,
  refusal of a reused refresh cookie, logout revoking both the cookie and the
  presented access token;
* **durability**: a burst of alerts, the worker is killed with `SIGKILL`
  while entries are in flight and started again; later a second burst across
  a graceful restart. Every alert must settle; none may be lost or `failed`;
* **Redis outage**: redis is stopped; api, worker and scheduler `/readyz`
  must answer 503 while `/healthz` stays 200; redis is started, readiness
  recovers and a new alert is processed end to end.

The same driver runs in-process (ASGI app plus a real worker, no docker) in
`tests/integration/e2e/test_api_stack.py`, so the suite covers it too. The
driver runs on the host when `python3` has `httpx` and `websockets`,
otherwise inside the application image (as the invoking user). Point it at
any deployment with `SMOKE_ADMIN_EMAIL`, `SMOKE_ADMIN_PASSWORD` and optionally
`SMOKE_METRICS_TOKEN` / `SMOKE_TENANT_B*` in the environment:
`python scripts/smoke_stack.py --base-url https://soc.example.com flow`.

Recorded run (Docker 29.3.1, Compose v5.1.1, `mirror.gcr.io` base images, image
built from the current tree, driver inside the image as in CI):

```text
$ POSTGRES_IMAGE=mirror.gcr.io/library/postgres:16-alpine REDIS_IMAGE=mirror.gcr.io/library/redis:7-alpine \
  scripts/smoke_stack.sh --no-build
==> starting the stack (lgsotf-smoke)
api: running Up 6 seconds (healthy)       migrate: exited Exited (0)
postgres/redis/scheduler/worker: running (healthy)
==> creating tenant smoke-b and its admin with the lg-sotf CLI in a container
schema: up to date; tenant: smoke-b (created)
created admin admin@smoke-b.example.com in tenant smoke-b (id ...)
==> customer flow over the HTTP API
ok    POST /ingest/alerts (3 canonical events) (202)
ok    POST /ingest/webhook/{source} (2 vendor events) (202)
ok    5 alerts settled {"closed": 0, "waiting_approval": 1, "waiting_human": 4}
ok    a decision with a stale version -> 409
ok    approve isolate_host (high risk) (200)          ... 7 actions approved, all dry_run
ok    all 5 alerts closed
ok    WebSocket delivered 126 events; every event belongs to the tenant
ok    LLM calls are metered (/usage/llm)
ok    audit log records key, source, review and approval; audit hash chain verifies
ok    /metrics without the token -> 401; /api/v1/metrics is not served -> 404
ok    tenant A alert by id from tenant B -> 404; X-Tenant-ID from a non-platform admin -> 403
ok    the cross-tenant access is in tenant B's audit log
ok    re-using the rotated refresh cookie -> 401; the access token presented at logout is revoked -> 401
done  flow in 24.2s
==> worker killed (SIGKILL) mid-processing: no alert may be lost
ok    151 queue entries in flight at the worker kill
ok    all 151 alerts settled, none lost {"waiting_approval": 1, "waiting_human": 150}
done  settled in 81.2s          (worker lease 60 s + the scheduler's stale-run sweep)
==> worker restarted gracefully (SIGTERM drain) mid-processing
ok    all 151 alerts settled, none lost
done  settled in 17.4s
==> redis outage: readiness must fail and recover
ok    /readyz answers 503 {"database": "ok", "redis": "error"}
ok    :19101/readyz -> 503 while redis is down; :19102/readyz -> 503 while redis is down
ok    api /healthz stays 200 (liveness has no dependencies)
ok    /readyz answers 200 {"database": "ok", "redis": "ok"}; worker and scheduler recover
ok    all 4 alerts settled, none lost
SMOKE PASSED
real    2m47s
```

After a worker is killed, its runs are picked up once their lease (60 s)
expires and the scheduler's stale-run sweep (every
`scheduler.stale_run_sweep_interval_s`, 60 s) requeues them. The stream
entries the dead worker had read but not yet started are claimed by the
restarted (or any other) worker once the dead worker's liveness key expires
(one lease, 60 s), independent of `worker.visibility_timeout_s`; entries
whose runs were already requeued are skipped. A graceful stop drains
in-flight runs within `worker.drain_timeout_s`.

Further tenants are created with `lg-sotf create-tenant --id <id> --name
<name> [--admin-email <email> --password-stdin]` (schema-owner connection;
see the script), or by a platform admin through `POST
/api/v1/platform/tenants`, which the runtime role serves through the
`lgsotf_create_tenant` database function.

## 3. Kubernetes with Helm

Requirements: Kubernetes 1.25+, Helm 3.12+, an external PostgreSQL 15+ and Redis
7+ (managed services recommended). Optional: an ingress controller and
cert-manager, KEDA 2.12+, Prometheus Operator.

### 3.1 Create the secrets (the chart never creates them)

```sh
kubectl create namespace lg-sotf

# Runtime secret: every component (envFrom). Never put the bootstrap admin
# password here (it would reach every pod); it has its own Secret below.
kubectl -n lg-sotf create secret generic lg-sotf \
  --from-literal=LG_SOTF_DATABASE__URL='postgresql://lgsotf_app:<pw>@db.internal:5432/lgsotf' \
  --from-literal=LG_SOTF_REDIS__URL='rediss://:<pw>@redis.internal:6380/0' \
  --from-literal=LG_SOTF_AUTH__JWT_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  --from-literal=LG_SOTF_SECURITY__ENCRYPTION_KEYS="$(python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')" \
  --from-literal=LG_SOTF_SECURITY__INDICATOR_HMAC_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  --from-literal=LG_SOTF_API__METRICS_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  --from-literal=ANTHROPIC_API_KEY='<key>'

# Owner secret: migrate job and scheduler only (two-role installs).
kubectl -n lg-sotf create secret generic lg-sotf-owner \
  --from-literal=LG_SOTF_DATABASE__MIGRATION_URL='postgresql://lgsotf_owner:<pw>@db.internal:5432/lgsotf'

# Shadow runs: worker only (optional; without it shadow runs refuse to start).
# The SELECT-only shadow role of section 4; set settings.database.shadow_role too.
kubectl -n lg-sotf create secret generic lg-sotf-shadow \
  --from-literal=LG_SOTF_DATABASE__SHADOW_URL='postgresql://lgsotf_shadow:<pw>@db.internal:5432/lgsotf'

# Bootstrap admin: migrate job only (optional; delete after the first install).
kubectl -n lg-sotf create secret generic lg-sotf-bootstrap \
  --from-literal=LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
  --from-literal=LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD='<at least 12 chars>'
```

`scripts/generate_secrets.py --format k8s` prints the same split with fresh
application keys, fed to `kubectl create secret --from-env-file=/dev/stdin`
through quoted here-documents (pipe it to `sh`, so no value lands in shell
history or `ps`). It copies `LG_SOTF_DATABASE__URL`, `LG_SOTF_REDIS__URL`, the
LLM keys and `LG_SOTF_DATABASE__MIGRATION_URL` from its own environment when set
(and lists any required key still missing), and prints the `-bootstrap` Secret
only with `--admin-email`:

```sh
kubectl config set-context --current --namespace=lg-sotf
LG_SOTF_DATABASE__URL=... LG_SOTF_REDIS__URL=... ANTHROPIC_API_KEY=... \
LG_SOTF_DATABASE__MIGRATION_URL=... \
  python scripts/generate_secrets.py --format k8s --admin-email admin@example.com | sh
```

Prefer a secret manager (External Secrets Operator, Sealed Secrets, Vault agent)
that produces the same keys. `values.schema.json` rejects secret-bearing keys
under `settings` (for example `settings.auth.jwt_secret`, and any `api_key`,
`*token*`, `*secret*` or `*password*` key under `settings.tools`), so they cannot
end up in a ConfigMap or in Helm release history. Install-level threat-intel
keys go into the same Secret as environment variables, for example
`LG_SOTF_TOOLS__VIRUSTOTAL__API_KEY` and `LG_SOTF_TOOLS__ABUSEIPDB__API_KEY`;
they are merged into `tools.<provider>` next to the non-secret settings.

### 3.2 Install

```sh
cat > my-values.yaml <<'EOF'
image:
  repository: registry.example.com/lg-sotf
  digest: sha256:<digest>        # pin by digest
secrets:
  existingSecret: lg-sotf
  ownerSecret: lg-sotf-owner
  bootstrapSecret: lg-sotf-bootstrap
  shadowSecret: lg-sotf-shadow      # optional: shadow runs
settings:
  database:
    runtime_role: lgsotf_app
    shadow_role: lgsotf_shadow      # optional: with shadowSecret
    ssl_mode: verify-full
  api:
    public_url: https://soc.example.com
    # Only the proxies in front of the API (see the warning below).
    forwarded_allow_ips: "<ingress-controller-pod-cidr-or-lb-ips>"
ingress:
  enabled: true
  className: nginx
  hosts: [soc.example.com]
  tls:
    - secretName: lg-sotf-tls
      hosts: [soc.example.com]
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    nginx.ingress.kubernetes.io/proxy-body-size: 10m
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
EOF
helm upgrade --install lg-sotf deploy/helm/lg-sotf -n lg-sotf -f my-values.yaml --wait --timeout 10m
helm test lg-sotf -n lg-sotf
```

**`forwarded_allow_ips`** decides whose `X-Forwarded-For` the API believes. The
resulting client IP keys the per-IP login and auth-failure rate limits and is
written to the audit log, so any address in this list can forge its source IP
and bypass those limits. Set it to the ingress controller's pod IPs/CIDR (or
the load balancer's addresses) only, never the whole pod or node range
(`10.0.0.0/8` and similar would trust every pod in most clusters). The chart
default, `127.0.0.1`, trusts no proxy. Combine it with
`networkPolicy.enabled=true` so only the ingress controller can reach the API
pods.

What the chart renders (see `values.yaml` for every knob, and
`deploy/helm/lg-sotf/ci/full-values.yaml` for an everything-enabled example):

* **Settings**: `values.settings` (mirrors `lg_sotf.settings.Settings`) becomes
  a ConfigMap mounted at `/etc/lg-sotf/settings.yaml` and loaded through
  `LG_SOTF_CONFIG_FILE`. Environment variables from the Secrets and `extraEnv`
  take precedence. Pods roll automatically when settings change
  (`checksum/config`).
* **Migrate hook**: `lg-sotf migrate` runs as a `pre-install,pre-upgrade` Job
  with a hook-scoped copy of the ConfigMap and ServiceAccount. It upgrades the
  schema, sets up LangGraph checkpoint tables, grants `runtime_role` its
  privileges and bootstraps the default tenant/admin. See "Migrations without
  Helm hooks" below for `migrate.useHelmHooks=false`.
* **Security**: `runAsNonRoot` (uid 10001), `readOnlyRootFilesystem` with an
  `emptyDir` `/tmp`, all capabilities dropped, `seccompProfile: RuntimeDefault`,
  no privilege escalation, ServiceAccount token automount off,
  `enableServiceLinks: false`.
* **Probes**: api `/healthz` (liveness, startup) and `/readyz` (readiness, db +
  redis); worker and scheduler the same paths on the `health` port 9100.
* **Availability**: PodDisruptionBudgets (`maxUnavailable: 1`), topology spread
  across zones and nodes (`ScheduleAnyway`), rolling updates with
  `maxUnavailable: 0`, API `preStop` delay, worker grace period (90 s) above
  `worker.drain_timeout_s` (60 s).
* **Scheduler**: 2 replicas; only the holder of the PostgreSQL advisory lock runs
  jobs, the other takes over within `scheduler.leader_lease_s`.
* **Optional**: Ingress with TLS, NetworkPolicies (`networkPolicy.enabled`;
  `networkPolicy.api.from` must then select the ingress controller, and
  `networkPolicy.metricsFrom` the Prometheus pods when ServiceMonitors are on,
  or rendering fails; the chart's `helm test` pod is admitted automatically;
  egress restrictions with `networkPolicy.egress.enabled`), ServiceMonitors
  (the API scrape uses `LG_SOTF_API__METRICS_TOKEN` from the runtime Secret),
  KEDA, and the frontend (`frontend.enabled`, image from `src/lg_front/Dockerfile`).

### Migrations without Helm hooks

`migrate.useHelmHooks=false` renders the migrate Job as an ordinary release
resource for tools that do not run Helm hooks. A Job's pod template is
immutable, so its name is `<release>-lg-sotf-migrate-<hash>`, the hash covering
the image reference and the settings: every upgrade that changes either creates
a new Job instead of failing with `field is immutable`, and an unchanged
release keeps the same Job. It carries `argocd.argoproj.io/sync-wave: "-1"`, so
Argo CD syncs and waits for it before the Deployments.

Plain `helm upgrade` does **not** order this Job before the Deployments: new
pods can start while the migration is still running. Readiness (`/readyz`)
checks only database and Redis reachability, not the schema version, so a pod
of the new release may serve errors until the migration completes. Therefore:
keep hooks on with plain Helm, and turn them off only under a tool that honours
sync waves (Argo CD) or one that you configure to wait for the Job before
applying the Deployments (for example Flux `dependsOn` with a separate
migration release).

### 3.3 Worker autoscaling

* **KEDA (recommended)**: `worker.keda.enabled=true`. Two `redis-streams`
  triggers (`<prefix>:q:alerts:high` and `<prefix>:q:alerts:normal`) in
  **lagCount** mode on consumer group `workers`; target lag per replica
  `worker.keda.lagCount` (default 16, about one replica's concurrency). Set
  `worker.keda.redisAddress` (host:port as seen from the KEDA operator),
  `enableTLS`, and `passwordSecret` (rendered as a `TriggerAuthentication`).
  `worker.keda.fallback` holds a fixed replica count if the scaler fails.
* **CPU HPA fallback**: without KEDA set `worker.autoscaling.enabled=true`.
  CPU is a weak signal for LLM-bound work (workers mostly wait on I/O); prefer
  KEDA.

### 3.4 Validate the chart

```sh
make helm-lint     # helm lint --strict (default + full values), helm template, kubeconform when installed
```

CI (`.github/workflows/ci.yml`, job `helm`) runs the same plus kubeconform with
CRD schemas for ScaledObject, TriggerAuthentication and ServiceMonitor.

## 4. Two-role PostgreSQL setup

Row-level security isolates tenants, and it only holds if the API and workers
connect as a role that does not own the tables and cannot bypass RLS.

```sql
-- as a superuser / cloud admin, once
CREATE ROLE lgsotf_owner LOGIN PASSWORD '<owner pw>' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE lgsotf_app   LOGIN PASSWORD '<app pw>'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
CREATE DATABASE lgsotf OWNER lgsotf_owner;
REVOKE ALL ON DATABASE lgsotf FROM PUBLIC;
GRANT CONNECT ON DATABASE lgsotf TO lgsotf_app;
\c lgsotf
ALTER SCHEMA public OWNER TO lgsotf_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO lgsotf_app;
```

Then:

| Setting | Value | Who gets it |
|---|---|---|
| `database.url` (`LG_SOTF_DATABASE__URL`) | `lgsotf_app` DSN | all components |
| `database.migration_url` (`LG_SOTF_DATABASE__MIGRATION_URL`) | `lgsotf_owner` DSN | migrate, scheduler |
| `database.runtime_role` | `lgsotf_app` | migrate (grants) |

`lg-sotf migrate` refuses to grant to a role that is a superuser, has
`BYPASSRLS` or is a member of the owner role. Single-role installs (development
only) use the owner everywhere and leave `migration_url`/`runtime_role` unset.

**Shadow runs** need a third login, `lgsotf_shadow`, which may read and never
write. Every transaction of a shadow run uses it, from a pool of its own; the
statement guard in front of it is defence in depth, not the boundary.

```sql
-- as a superuser / cloud admin, once (optional: without it shadow runs refuse to start)
CREATE ROLE lgsotf_shadow LOGIN PASSWORD '<shadow pw>' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
ALTER ROLE lgsotf_shadow SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE lgsotf TO lgsotf_shadow;
\c lgsotf
GRANT USAGE ON SCHEMA public TO lgsotf_shadow;
```

| Setting | Value | Who gets it |
|---|---|---|
| `database.shadow_url` (`LG_SOTF_DATABASE__SHADOW_URL`) | `lgsotf_shadow` DSN | worker (and whoever runs shadow replays) |
| `database.shadow_role` | `lgsotf_shadow` | migrate (grants) |
| `database.shadow_pool_max` | connections of the shadow pool per process (default 4) | worker |

`lg-sotf migrate` grants it `SELECT` on the tenant tables, except the
credential tables (`users`, `user_mfa`, `refresh_tokens`, `api_keys`), and
nothing else: no `INSERT` anywhere, no sequence, no `SECURITY DEFINER`
function. A shadow run's record (`shadow_effects`, and the replay's verdict
rows) is written after the run has left shadow mode, by the runtime role. Never
make the shadow role a member of another role. `lg-sotf migrate` refuses, and
changes nothing, when `database.shadow_role` names a role that may write or
bypass isolation (for example `lgsotf_app`), and a worker refuses to open the
shadow pool when `database.shadow_url` logs in as such a role. Row-level
security applies to the shadow role like to the runtime role.

Use TLS to the database: `settings.database.ssl_mode: verify-full` and, for a
private CA, `ssl_root_cert` pointing at a file mounted with `extraVolumes` /
`extraVolumeMounts`.

Connection budget: each API and scheduler process opens up to
`database.pool_max` connections (the scheduler additionally holds one leader
session). A worker's pool is `max(pool_max, worker.concurrency / 2)` (at most
50), and its LangGraph checkpointer has its own pool of
`min(pool_max, worker.concurrency)`. Keep
`api replicas x pool_max + worker replicas x (worker pool + checkpointer pool) + scheduler replicas x (pool_max + 1) + 1 (migrate) + headroom`
below PostgreSQL `max_connections` (stock PostgreSQL allows 100: with the
defaults, 2 API + 4 workers + 1 scheduler use about 111, so raise it or put
PgBouncer in front). If you add PgBouncer, the scheduler needs
**session** pooling (advisory locks are session scoped).

## 5. TLS

* **Ingress**: terminate TLS at the ingress (`ingress.tls`, e.g. cert-manager).
  `auth.cookie_secure` must stay `true` in production, so refresh cookies are
  only sent over HTTPS. Set `api.forwarded_allow_ips` to the ingress controller
  pod IPs or LB addresses (not the cluster range; see section 3.2) so client IPs
  and scheme come from `X-Forwarded-*`.
* **WebSockets**: raise the ingress read timeout (see the nginx annotation above).
* **Redis**: use `rediss://` in `LG_SOTF_REDIS__URL`; for KEDA also set
  `worker.keda.enableTLS=true`.
* **PostgreSQL**: `ssl_mode: verify-full`.
* **Outbound**: LLM providers, pull sources and SOAR webhooks are HTTPS with
  certificate verification on by default.

## 6. Sizing

Throughput is bounded by LLM latency and provider rate limits, not CPU.

* A worker runs up to `worker.concurrency` workflow runs at once (default 16),
  with at most `worker.per_tenant_concurrency` per tenant **while other tenants
  have work in that worker** (a tenant alone may use every slot, so
  single-organisation installs get the full concurrency). LLM calls can be
  further bounded **per process** by `llm.fast.max_concurrency` and
  `llm.deep.max_concurrency` (unset: `worker.concurrency`, i.e. no extra bound;
  watch `lgsotf_llm_slot_wait_seconds{mode="live"}` when you set them).
* Cluster-wide concurrent LLM calls are `worker replicas x max_concurrency`
  (or `x worker.concurrency` when unset) per tier. Keep that below your provider's concurrency and requests-per-minute
  limits; otherwise calls are retried (`max_retries`) and runs slow down rather
  than scale.
* Approximate sustained throughput:
  `alerts/min ~= replicas x concurrency x 60 / average run seconds`. Most alerts
  stop at the gate or triage (seconds); those reaching deep analysis take
  minutes. Measure with `lgsotf_node_seconds{mode="live"}` and size from the p90.
* Set `worker.keda.lagCount` close to `worker.concurrency` so one replica is
  added per full replica's worth of backlog.
* Memory: start workers at 768Mi request / 2Gi limit with concurrency 16; raise
  the limit if you raise concurrency or `llm.max_input_chars`.
* API: 2 replicas at 250m / 384Mi handle typical analyst traffic; ingest-heavy
  installs scale on CPU. `api.max_ingest_batch` and the ingest rate limit bound
  a single client.
* Cost control: `llm.daily_token_budget_per_tenant` (agents fall back to rules
  when exceeded) and `/api/v1/usage/llm`.
* Redis: memory is dominated by in-flight queue entries and pub/sub; enable AOF
  (`appendonly yes`) or use a managed Redis with persistence. Anything lost is
  re-derived from `workflow_runs` by the scheduler's orphan sweep.

## 7. Upgrades and migrations

1. Read the release notes; take a database backup (section 8).
2. `helm upgrade lg-sotf deploy/helm/lg-sotf -n lg-sotf -f my-values.yaml --wait`.
   The pre-upgrade hook runs `lg-sotf migrate` with the **new** image before any
   pod is replaced. If it fails, Helm stops and the old pods keep running;
   inspect `kubectl logs job/lg-sotf-migrate`.
3. Pods roll with `maxUnavailable: 0`; workers drain in-flight runs (they resume
   from their LangGraph checkpoints on another worker if interrupted).
   Runs waiting for an analyst or an approval resume on the workflow graph they
   started on: a release keeps the previous graph (N-1) next to the current one.
   Before an upgrade that skips a release, check that no run still waits on a
   graph the new release no longer has
   (`SELECT graph_version, count(*) FROM workflow_runs WHERE status IN
   ('waiting_human', 'waiting_approval', 'failed') GROUP BY 1`; NULL is graph 1).
   Such a run fails with `UnknownGraphVersion` and is never run on another graph.
   CI rehearses this upgrade on every change (`scripts/ci/upgrade_rehearsal.sh`):
   the previous release leaves runs waiting, the new release migrates the
   database while the old one still runs, runs this check, and must resume and
   close every waiting run. It does the same from the latest LTS release, so
   upgrading from the LTS line straight to the new release is tested too
   ([releases.md](releases.md)).

Migrations must be expand/contract (additive first, removals in a later
release) so the previous release keeps working against the new schema during
the rollout. A migration that changes a table makes the statements the
running pods have prepared on it stale, and the first transaction to use one
fails with `InvalidCachedStatementError`. A worker runs its run transactions
again once, in a new transaction for the same tenant (log event
`db.stale_statement_retry`, metric `lgsotf_db_stale_statement_retries_total`),
so in-flight runs finish normally. An API request that hits it is not retried
and fails once; the client can send it again. `lg-sotf migrate` is idempotent and
safe to re-run. Rolling back the application is `helm rollback`; schema
downgrades are not automatic; restore from backup if the release notes say a
migration is not backward compatible.

Compose: `make image && make migrate && make up`.

## 8. Backups

* **PostgreSQL is the system of record** (alerts, runs, checkpoints, escalations,
  audit log, encrypted source credentials). Use your provider's PITR, or
  `pg_dump -Fc` / `pg_basebackup` with WAL archiving. Test restores.
* **Keys are part of the backup**: without the Fernet keys
  (`security.encryption_keys`) encrypted source credentials and webhook secrets
  cannot be decrypted; without `security.indicator_hmac_key` correlation history
  no longer matches. Store them in your secret manager with its own backup, not
  next to the database dump.
* **Redis** holds only in-flight queue entries, rate-limit windows and caches.
  After a Redis loss the scheduler re-enqueues runs left `queued`/`failed`
  (`orphaned_runs` job); nothing else needs restoring. DLQ entries live in Redis
  (`<prefix>:q:alerts:dlq`); list them before planned Redis maintenance.
* Restore drill: restore the dump into a new database, point a staging release
  at it with the same keys, run `lg-sotf migrate`, check `/readyz` and a few
  alerts in the UI.
