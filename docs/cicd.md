# CI/CD: dev and uat on Oracle Cloud Always Free

This guide sets up two hosted environments for LG-SOTF, **dev** and **uat**,
each running the production-like Docker Compose stack (PostgreSQL, Redis,
migrate, api, worker, scheduler, web UI) behind **Caddy** with automatic
HTTPS, on an Oracle Cloud "Always Free" Ampere (ARM64) VM. There is no
production environment yet; the last section lists what changes for one.

It is written for someone who has not done this before. Budget about an hour
for the first environment and 15 minutes for the second.

## How it works

```text
 push to main ──> CI (tests, scans, image build) ──green──> Release images
                                                              │ build once for linux/amd64 + linux/arm64
                                                              │ push ghcr.io/gapilongo/lg-sotf[-frontend]:sha-1a2b3c4 and :main
                                                              └──> Deploy ── environment "dev" ──> dev VM

 git tag v1.2.3 (a commit on main) ──> Release images
                                         │ no rebuild: re-tag the sha-1a2b3c4 manifests as :v1.2.3 (same digest)
                                         └──> Deploy ── environment "uat" (waits for a reviewer) ──> uat VM
```

* `.github/workflows/release-images.yml` builds and publishes the images once
  per green commit on main, then calls the deploy workflow for **dev**. A
  release tag `vX.Y.Z` promotes the images of that commit to **uat**: the same
  bytes (same digest) that ran on dev, never rebuilt.
* `.github/workflows/deploy.yml` deploys one image tag to one environment. It
  resolves the tag to digests, copies a small bundle (compose files, Caddy
  templates, scripts from `deploy/vm/`, taken from the commit that built the
  images) to the VM over SSH, and runs `deploy/vm/deploy.sh` there as the
  unprivileged `deploy` user. You can also run it by hand (redeploy or roll
  back).
* On the VM, `deploy.sh` pulls the images, runs the database migration,
  starts the stack, and checks `https://<your hostname>/healthz`, `/readyz`,
  `/api`, `/` and `/config.js` through Caddy. **If the new version is not
  healthy it automatically puts the previous version back** and the workflow
  fails, so you notice.

Everything on the VM lives under `/opt/lg-sotf`:

| Path | What |
|---|---|
| `/opt/lg-sotf/edge/` | The shared Caddy (ports 80/443), its rendered `Caddyfile` and one `conf/sites/<env>.caddy` per environment |
| `/opt/lg-sotf/env/<env>/.env`, `secrets.env` | The environment's settings and secrets (mode 0600, deploy user only) |
| `/opt/lg-sotf/env/<env>/releases/<commit>/` | Deploy bundles (the current, the previous and a few more) |
| `/opt/lg-sotf/env/<env>/state/` | `current.env`, `previous.env` (versions for rollback), `history.log` |
| `/opt/lg-sotf/backups/<env>/` | Nightly database dumps |
| `/opt/lg-sotf/bin/backup.sh` | Backup and restore tool |

Each environment is its own Compose project (`lgsotf-dev`, `lgsotf-uat`) with
its own database, Redis, volumes and internal networks. No database or
application port is published; only Caddy listens on 80 and 443.

## What it costs

$0 on Oracle's Always Free tier, within its limits: up to 4 Ampere OCPUs and
24 GB of memory in total across A1 instances, 200 GB of block storage (boot
volumes included), 10 TB of outbound traffic a month. GitHub Actions minutes
are free for public repositories, GitHub Packages storage and transfer are
free for public packages, DuckDNS and sslip.io are free, and Let's Encrypt
certificates are free.

Caveats you should know before relying on it:

* **Idle reclamation.** Oracle may stop Always Free compute instances it
  considers idle over a 7-day window (low CPU, network and, for A1 shapes,
  memory utilisation; see Oracle's Always Free documentation for the current
  thresholds). A quiet dev/uat stack can fall below them, so expect that the
  VM may be stopped and have to be started again from the console. Upgrading
  the account to *Pay As You Go* removes idle reclamation while Always Free
  resources stay free; if you do, set a budget alert (Billing > Budgets) at
  $1 so an accidental paid resource is noticed.
* **Capacity.** Ampere capacity in popular regions is often exhausted
  ("Out of capacity for shape VM.Standard.A1.Flex"). Your home region is fixed
  at sign-up and Always Free resources exist only there. Retry later, try
  another availability domain, or start with a smaller shape (1 OCPU / 6 GB)
  and resize later.
* **No SLA** and no support on the free tier. Fine for dev and uat, not for
  production.

## 1. Create the Oracle Cloud VM

1. Sign up at <https://www.oracle.com/cloud/free/>. A card is needed for
   identity verification; Always Free resources are not charged. Choose the
   home region closest to your users; it cannot be changed later.
2. Console > **Compute > Instances > Create instance**.
   * Name: `lgsotf` (or `lgsotf-dev` / `lgsotf-uat` if you use two VMs).
   * Image: **Canonical Ubuntu 24.04** (22.04 also works). Not the
     "Minimal" or Oracle Linux images.
   * Shape: **Ampere > VM.Standard.A1.Flex**.
     * One VM for both environments: **4 OCPUs, 24 GB**.
     * One VM per environment: **2 OCPUs, 12 GB** each.
   * Networking: create a new VCN with a **public subnet** and keep
     "Assign a public IPv4 address" on.
   * SSH keys: upload *your own* public key (for you to log in as `ubuntu`).
     This is not the deploy key; that comes in step 4.
   * Boot volume: 50 GB is enough for both environments (up to 200 GB is free
     in total).
3. Create it and note the **public IP address** on the instance page.
4. Optional but recommended: make the IP stable. Instance > Attached VNICs >
   VNIC > IPv4 addresses > edit > **Reserved public IP** (one is free). An
   ephemeral IP changes if you stop and start the instance, and then DNS and
   `DEPLOY_SSH_KNOWN_HOSTS`/`DEPLOY_HOST` must be updated.

## 2. Open ports 80 and 443 in the cloud firewall

Oracle filters traffic twice: in the cloud (security list or NSG) and on the
VM itself (iptables; `bootstrap.sh` handles that part). For the cloud part:

Console > **Networking > Virtual cloud networks** > your VCN > **Subnets** >
the public subnet > its **Security list** > **Add ingress rules**, twice:

| Source CIDR | IP protocol | Destination port |
|---|---|---|
| `0.0.0.0/0` | TCP | `80` |
| `0.0.0.0/0` | TCP | `443` |

Optionally a third rule UDP `443` for HTTP/3. Port 22 is already open by
default. Port 80 must stay open: Let's Encrypt validates and Caddy redirects
it to HTTPS. If you use a Network Security Group on the VNIC instead, add the
same rules there.

## 3. Get a hostname

Browsers need a name, and Let's Encrypt only issues certificates for names.
Pick one of:

* **DuckDNS** (recommended): sign in at <https://www.duckdns.org>, create
  e.g. `mysoc-dev` and `mysoc-uat`, and set both to the VM's public IP (or
  each to its own VM's IP). Your hostnames are `mysoc-dev.duckdns.org` and
  `mysoc-uat.duckdns.org`.
* **sslip.io** (no sign-up): the name contains the IP, e.g.
  `dev.203-0-113-10.sslip.io` and `uat.203-0-113-10.sslip.io` for IP
  `203.0.113.10`. Shared free domains occasionally hit Let's Encrypt rate
  limits; if the certificate is refused for that reason, switch to DuckDNS.
* A domain you own: an `A` record per environment pointing at the IP.

Check from your computer: `nslookup mysoc-dev.duckdns.org` must print the
VM's IP.

## 4. Create the deploy key

On your computer:

```sh
ssh-keygen -t ed25519 -N "" -C "github-deploy-lgsotf" -f ./lgsotf-deploy
```

This creates `lgsotf-deploy` (private: goes into GitHub, nowhere else) and
`lgsotf-deploy.pub` (public: goes onto the VM in the next step). Use one key
per VM, or one per environment if you prefer.

## 5. Prepare the VM (`deploy/vm/bootstrap.sh`)

Log in as yourself and run the bootstrap script as root. It is safe to run
again later (for example to add a key).

```sh
scp deploy/vm/bootstrap.sh ubuntu@203.0.113.10:     # from a clone of this repository
ssh ubuntu@203.0.113.10
sudo bash bootstrap.sh \
  --ssh-key "$(cat <<'EOF'
ssh-ed25519 AAAA...paste the content of lgsotf-deploy.pub... github-deploy-lgsotf
EOF
)" \
  --public-host 203.0.113.10
```

(Or copy `lgsotf-deploy.pub` to the VM and use `--ssh-key-file lgsotf-deploy.pub`.)

What it does: installs Docker Engine and the Compose plugin from Docker's own
apt repository (ARM64 or x86_64), rotates container logs, creates the
`deploy` user (member of the `docker` group, SSH key only, no password, no
sudo) and `/opt/lg-sotf`, turns off SSH password logins, enables automatic
security updates, adds a 4 GB swap file and `vm.overcommit_memory=1` (for
Redis), and installs a nightly backup timer. Add `--fail2ban` to also ban
repeated failed SSH logins.

**Firewall on the VM.** Oracle's Ubuntu images ship iptables rules that
reject everything except SSH (`-A INPUT -j REJECT --reject-with
icmp-host-prohibited`) and also contain rules the boot volume and instance
metadata depend on. Replacing them with `ufw` risks dropping those rules, so
the script detects these images and instead inserts ACCEPT rules for 80/tcp, 443/tcp and 443/udp *before*
that REJECT, live and in `/etc/iptables/rules.v4` (saved across reboots),
without flushing anything. On other Ubuntu machines it uses `ufw` (deny
incoming; allow 22, 80, 443). Force a mode with `--firewall
oracle-iptables|ufw|none`.

At the end it prints lines like:

```text
203.0.113.10 ssh-ed25519 AAAAC3Nza...
203.0.113.10 ecdsa-sha2-nistp256 AAAAE2V...
```

Copy them: they are the `DEPLOY_SSH_KNOWN_HOSTS` secret. They let GitHub
verify it is talking to *your* VM (the workflow refuses unknown host keys;
there is no "accept any key" mode). If you ever rebuild the VM, its host key
changes and you must update this secret.

Check the deploy login from your computer:

```sh
ssh -i ./lgsotf-deploy deploy@203.0.113.10 docker version
```

Note: members of the `docker` group can control the host as root. Treat the
deploy key like a root key.

## 6. Create the GitHub environments

In the repository: **Settings > Environments > New environment**.

* **dev**
  * Deployment branches and tags: *Selected branches and tags* > add branch
    `main`.
* **uat**
  * **Required reviewers**: add yourself and/or teammates. Every uat deploy
    then waits in the Actions run until one of them approves ("Review
    deployments"). Tick *Prevent self-review* if you want a second person.
  * Deployment branches and tags: *Selected branches and tags* > add branch
    `main` and tag pattern `v*.*.*`.

## 7. Secrets and variables of each environment

Environment > **Add environment secret** / **Add environment variable**. Use
**different generated values for dev and uat**.

### Secrets

| Secret | Required | Value |
|---|---|---|
| `DEPLOY_SSH_KEY` | yes | The whole private key file `lgsotf-deploy`, including the `-----BEGIN`/`-----END` lines |
| `DEPLOY_SSH_KNOWN_HOSTS` | yes | The lines printed by `bootstrap.sh` (step 5) |
| `POSTGRES_SUPERUSER_PASSWORD` | yes | Generated (below). PostgreSQL administrator |
| `LGSOTF_OWNER_PASSWORD` | yes | Generated. Schema owner (migrate, scheduler) |
| `LGSOTF_APP_PASSWORD` | yes | Generated. Runtime role (api, worker; row-level security applies) |
| `LG_SOTF_AUTH__JWT_SECRET` | yes | Generated. Signs access tokens |
| `LG_SOTF_SECURITY__ENCRYPTION_KEYS` | yes | Generated. Fernet key(s) encrypting stored credentials |
| `LG_SOTF_SECURITY__INDICATOR_HMAC_KEY` | yes | Generated. Keys indicator correlation |
| `LG_SOTF_API__METRICS_TOKEN` | yes | Generated. Bearer token for `/metrics` (not exposed publicly by Caddy) |
| `LG_SOTF_AUTH__BOOTSTRAP_ADMIN_PASSWORD` | yes | Generated. Password of the first admin (at least 12 characters) |
| `ANTHROPIC_API_KEY` | no | Real triage with Claude. Without it the deterministic `fake` model is used |
| `GHCR_READ_TOKEN` | no | Only if the packages stay private (step 8): a classic personal access token with `read:packages` |

Generate the application secrets with the repository's script, once per
environment, and load them with the GitHub CLI (`gh`), so nothing is typed by
hand:

```sh
umask 077
python3 scripts/generate_secrets.py > dev.secrets     # 8 KEY=value lines, new random values
gh secret set --env dev -f dev.secrets                # sets all 8 as dev environment secrets
grep BOOTSTRAP_ADMIN_PASSWORD dev.secrets             # store this in your password manager now
rm dev.secrets
# same again with uat.secrets / --env uat
gh secret set --env dev DEPLOY_SSH_KEY < lgsotf-deploy
gh secret set --env dev DEPLOY_SSH_KNOWN_HOSTS < known_hosts.txt   # the lines from bootstrap.sh
```

Without `gh`, run `python3 scripts/generate_secrets.py` and paste each
`KEY=value` line into the web form (name = the part before `=`).

GitHub secrets cannot be read back: **save the bootstrap admin password** in
your password manager before deleting the file.

Once an environment has been deployed, **do not change the three database
passwords** in GitHub: PostgreSQL keeps the ones it was created with, and the
next deploy would fail (and roll back). Rotating them is a manual procedure
(docs/operations.md). Changing the JWT secret logs everyone out; changing the
Fernet key without keeping the old one makes stored credentials unreadable
(see docs/operations.md, key rotation).

### Variables

| Variable | Required | Value |
|---|---|---|
| `DEPLOY_HOST` | yes | The VM's public IP (or a DNS name for it) |
| `APP_DOMAIN` | yes | The environment's hostname, e.g. `mysoc-dev.duckdns.org` (no `https://`) |
| `BOOTSTRAP_ADMIN_EMAIL` | yes | Email of the first admin account (created on the first deploy only) |
| `DEPLOY_USER` | no | Default `deploy` |
| `DEPLOY_PORT` | no | Default `22` |
| `LLM_PROVIDER` | no | `anthropic`, `openai`, `gemini` or `fake`. Default: `anthropic` if `ANTHROPIC_API_KEY` is set, otherwise `fake` |
| `ACME_EMAIL` | no | Email for Let's Encrypt expiry notices |
| `GHCR_READ_USER` | no | Your GitHub user name, with `GHCR_READ_TOKEN` |

**One VM for both environments:** give dev and uat the same `DEPLOY_HOST`,
`DEPLOY_SSH_KEY` and `DEPLOY_SSH_KNOWN_HOSTS`, and different `APP_DOMAIN`s.
`deploy.sh` keeps them apart (separate projects, databases and networks) and
the single Caddy serves both hostnames. **One VM each:** each environment
points at its own VM.

## 8. Let the VM pull the images

The images are published to GitHub Container Registry the first time
*Release images* runs (after your first green push to main). New packages are
private. Either:

* **Make them public** (simplest; the repository is public anyway): GitHub >
  your profile or organisation > **Packages** > `lg-sotf` > **Package
  settings** > *Change visibility* > Public. Same for `lg-sotf-frontend`.
* Or keep them private and set `GHCR_READ_USER` (variable) and
  `GHCR_READ_TOKEN` (secret: classic token, scope `read:packages` only) in
  both environments. The token is used for the pull only and never stored on
  the VM.

If the first dev deploy failed because the packages were still private,
change the visibility and re-run the failed job.

## 9. First deploy

Automatic deploys are off until you turn them on, so builds stay green while
no VM exists. When steps 1-8 are done, add the repository variables
`AUTO_DEPLOY_DEV=true` (and, once uat is ready, `AUTO_DEPLOY_UAT=true`) under
**Settings > Secrets and variables > Actions > Variables**. Images are
published to GHCR on every green `main` build either way, and **Actions >
Deploy > Run workflow** works regardless of these variables.

Merge or push to `main`. In **Actions** you will see *CI*, then *Release
images* (the multi-arch build takes 15-30 minutes the first time, less
later thanks to the build cache), whose *Deploy dev* job deploys to the VM.
Or deploy any existing image by hand: **Actions > Deploy > Run workflow**,
environment `dev`, image tag `main` (or `sha-1a2b3c4`).

The first deploy also obtains the certificate, which takes up to a minute.
The run's summary shows the URL and the exact version. Open
`https://<APP_DOMAIN>` and sign in with `BOOTSTRAP_ADMIN_EMAIL` and the
bootstrap admin password; create real users from the Admin page, and set up
OIDC single sign-on later if you want it.

## 10. Promote dev to uat

When a commit that is on dev looks good, tag it:

```sh
git fetch origin
git tag v0.3.0 <commit on main>      # the commit dev runs; see the dev deploy summary
git push origin v0.3.0
```

*Release images* then re-tags that commit's images as `v0.3.0` (no rebuild:
the digest dev ran is the digest uat gets) and starts *Deploy uat*, which
waits for a required reviewer's approval. Tags must be `vMAJOR.MINOR.PATCH`
and point at a commit on `main`; otherwise the run stops with an explanation.
If you tag right after merging, the promotion waits until that commit's
images exist.

## 11. Roll back

* **Automatic**: a deploy whose new version fails its health checks puts the
  previous version back on its own; the run is marked failed and the log ends
  with `ROLLED BACK to <version>`.
* **By hand from GitHub**: Actions > Deploy > Run workflow, pick the
  environment, enter the previous good tag (`sha-...` or `vX.Y.Z`; the deploy
  run summaries and `/opt/lg-sotf/env/<env>/state/history.log` list them).
* **On the VM** (for example while GitHub is down):

  ```sh
  ssh -i ./lgsotf-deploy deploy@203.0.113.10
  d=$(ls -dt /opt/lg-sotf/env/dev/releases/*/ | head -n 1)
  bash "$d/deploy/vm/deploy.sh" --env dev --status
  bash "$d/deploy/vm/deploy.sh" --env dev --domain mysoc-dev.duckdns.org --rollback
  ```

Database migrations only move forward. Releases are written expand/contract
(docs/deployment.md, section 7), so the previous version runs against the
newer schema; if release notes say a migration is not backward compatible,
restore the backup taken before it instead.

## 12. Backups and restore

The `lgsotf-backup.timer` installed by `bootstrap.sh` runs
`/opt/lg-sotf/bin/backup.sh --all` nightly (02:30 UTC by default): a
`pg_dump -Fc` of each environment's database into
`/opt/lg-sotf/backups/<env>/`, checked to be a readable archive, kept 14 days.

```sh
systemctl list-timers lgsotf-backup.timer            # next run
sudo systemctl start lgsotf-backup.service           # run now
/opt/lg-sotf/bin/backup.sh --env dev --list          # as the deploy user
scp -i ./lgsotf-deploy 'deploy@203.0.113.10:/opt/lg-sotf/backups/dev/*.dump' .   # copy off the VM
```

Restore (replaces the environment's database; a safety dump of the current
database is taken first):

```sh
/opt/lg-sotf/bin/backup.sh --env dev --restore /opt/lg-sotf/backups/dev/lgsotf-dev-20260101T023000Z.dump --yes
```

It stops api, worker and scheduler, recreates the database with the same
roles and grants, restores the dump, runs the migration and starts the stack
again.

A dump is useless without the environment's keys: keep
`LG_SOTF_SECURITY__ENCRYPTION_KEYS` and `LG_SOTF_SECURITY__INDICATOR_HMAC_KEY`
(in your password manager, since GitHub secrets cannot be read back).

**Optional off-VM copies to OCI Object Storage** (also free up to 20 GB):
create a bucket (Storage > Buckets), install the OCI CLI for the deploy user
(`bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"`,
then `oci setup config` with an API key of a user allowed to write to that
bucket), and write `/opt/lg-sotf/backup.conf`:

```text
OCI_BUCKET=lgsotf-backups
OCI_PREFIX=lg-sotf/
```

Each nightly dump is then also uploaded; use a bucket lifecycle rule to
expire old objects.

## 13. Day-to-day and troubleshooting

```sh
ssh -i ./lgsotf-deploy deploy@203.0.113.10
docker ps                                             # every container and its health
cd /opt/lg-sotf/env/dev && d=$(sed -n 's/^RELEASE_DIR=//p' state/current.env)
docker compose -p lgsotf-dev -f $d/docker/docker-compose.yml -f $d/docker/docker-compose.prod.yml \
  -f $d/deploy/vm/docker-compose.vm.yml --env-file .env logs -f --tail 100 api worker
docker compose -p lgsotf-edge -f /opt/lg-sotf/edge/compose.yml --env-file /opt/lg-sotf/edge/.env logs caddy
```

| Symptom | Cause and fix |
|---|---|
| `Host key verification failed` | `DEPLOY_SSH_KNOWN_HOSTS` does not match the VM (new VM, new IP). Re-run `bootstrap.sh` and copy its output again |
| `Permission denied (publickey)` | `DEPLOY_SSH_KEY` does not match the key given to `bootstrap.sh`, or `DEPLOY_USER` is wrong |
| Health checks time out on the first deploy, Caddy logs mention ACME/challenge | Port 80 or 443 not reachable from the internet (step 2 security list; `sudo iptables -L INPUT -n` on the VM), or `APP_DOMAIN` does not resolve to the VM's IP |
| `no image ghcr.io/...` / pull `denied` | Packages still private (step 8), or the tag does not exist yet |
| `missing value: ...` / `missing in environment` | A required secret or variable is not set in that GitHub environment |
| A deploy fails with a database authentication error | A database password secret was changed after the first deploy; put the original back |
| `ROLLBACK FAILED` | Neither version is healthy (often: the VM is out of memory or disk). Check `docker ps`, `df -h`, `free -h`, the logs above |
| Instance stopped by Oracle | Idle reclamation (see costs); start it again in the console. With an ephemeral IP, update DNS, `DEPLOY_HOST` and `DEPLOY_SSH_KNOWN_HOSTS` |

Memory budget per environment (Compose limits in
`deploy/vm/docker-compose.vm.yml`, adjustable): PostgreSQL 1.5 GB, Redis
512 MB, api 1 GB, worker 2 GB, scheduler 512 MB, UI 128 MB, about 5.7 GB;
two environments fit in 24 GB with room for page cache.

## 14. Rehearse a deploy locally

`deploy.sh` runs on any Linux machine with Docker, which is how it was
verified. With a self-signed certificate from Caddy's internal CA and high
ports:

```sh
python3 scripts/generate_secrets.py > /tmp/v.env && echo "LG_SOTF_AUTH__BOOTSTRAP_ADMIN_EMAIL=admin@example.com" >> /tmp/v.env
bash deploy/vm/deploy.sh --env dev --domain dev.lgsotf.test --root /tmp/lgsotf-vm --tls internal \
  --http-port 18080 --https-port 18443 \
  --app-image <backend image> --frontend-image <frontend image> --version local --secrets-stdin < /tmp/v.env
curl -k --resolve dev.lgsotf.test:18443:127.0.0.1 https://dev.lgsotf.test:18443/readyz
```

Recorded run (Docker 29.3.1, Compose v5.1.1; images from this tree pushed to
a local registry and deployed by digest, as the workflow does): a fresh deploy
of version A, a redeploy of version B, then a version C whose web app serves
no `index.html` (its containers still report healthy, only the external check
sees it):

```text
$ deploy.sh ... --version sha-aaaaaaa        # fresh VM directory, first deploy
19:58:01 [dev] creating network lgsotf-proxy (172.31.251.0/24)
19:58:01 [dev] starting the edge (Caddy)
19:58:16 [dev] running migrations (lg-sotf migrate)      (migrate: "bootstrap admin created")
19:58:34 [dev] healthy: https://dev.lgsotf.test:18443 (/healthz, /readyz, /api, /, /config.js)
19:58:35 [dev] DEPLOYED sha-aaaaaaa at https://dev.lgsotf.test:18443
$ deploy.sh ... --version sha-bbbbbbb        # new version
19:59:01 [dev] healthy: https://dev.lgsotf.test:18443 (/healthz, /readyz, /api, /, /config.js)
19:59:02 [dev] DEPLOYED sha-bbbbbbb at https://dev.lgsotf.test:18443
$ deploy.sh ... --version sha-ccccccc --health-timeout 60   # broken web app
19:59:09 [dev] starting api, worker, scheduler, frontend
20:00:29 [dev] health checks failed after 60s: /(500)
20:00:30 [dev] FAILED: sha-ccccccc is not healthy; rolling back to sha-bbbbbbb
20:00:56 [dev] healthy: https://dev.lgsotf.test:18443 (/healthz, /readyz, /api, /, /config.js)
20:00:56 [dev] ROLLED BACK to sha-bbbbbbb; sha-ccccccc was not deployed     (exit 1)
```

None of the eight generated secret values appeared in the deploy output or
in any container log.

`scripts/smoke_stack.py flow` (login, refresh cookie, WebSocket, ingest,
review, approvals, audit) passed against `https://dev.lgsotf.test:18443`
through Caddy, and a second environment (uat) ran next to dev behind the
same Caddy.

## 15. Later: production

Keep the same pipeline shape (promote a digest that passed uat; required
reviewers on a `prod` environment) and change the platform:

* **Not on Always Free**: no SLA, idle reclamation, shared capacity. Use a
  paid VM with a reserved IP at minimum, or Kubernetes with the Helm chart in
  `deploy/helm/lg-sotf` (docs/deployment.md).
* **Managed PostgreSQL** with point-in-time recovery, TLS
  (`ssl_mode: verify-full`) and tested restores; managed Redis with TLS.
* **Your own domain**, and OIDC single sign-on for analysts
  (docs/configuration.md).
* **Secrets** from a secret manager (OCI Vault, External Secrets), with a
  rotation procedure (docs/operations.md), instead of environment secrets
  written to a file on the VM.
* **A real model provider key** with a per-tenant token budget.
* **Monitoring and alerting**: scrape `/metrics` with the metrics token,
  alert on readiness, queue lag, DLQ and error rates (docs/operations.md);
  uptime checks on the public URL.
* **Supply chain**: sign images (cosign) and verify signatures or provenance
  at deploy time; keep deploying by digest.
* **Off-site, encrypted backups** as a requirement (not optional), with a
  scheduled restore drill.
* Zero-downtime updates (more than one api/worker instance behind the
  proxy), a WAF/DDoS protection in front, and a change and incident process.
