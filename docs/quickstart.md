# Quickstart: first triaged alert in minutes

One command takes a fresh clone to a running LG-SOTF with a demo tenant,
16 realistic synthetic alerts triaged, and the web UI open, and it **measures
how long that took**.

```sh
git clone https://github.com/gapilongo/SOC.git && cd SOC
scripts/quickstart.sh                      # or: make quickstart
```

Needs Docker with compose v2, `python3` (standard library only) and about
4 GB of free memory. No API key, no GPU, no internet after the images are
built: the default model is the offline `fake` model.

To triage with a real local model instead (docs/local-llm.md):

```sh
scripts/quickstart.sh --ollama qwen3:8b    # or: make quickstart OLLAMA=qwen3:8b
```

## What it does

| Step | What happens |
|---|---|
| 1. Secrets | `scripts/generate_secrets.py` writes JWT, encryption, HMAC and database secrets to `.quickstart/stack.env` (mode 0600 in a 0700 directory). Re-runs keep them. |
| 2. Images | Builds `lg-sotf:dev` and `lg-sotf-frontend:dev` if they are missing (`--build` forces a rebuild, `--no-build` never builds). |
| 3. Model | With `--ollama MODEL`: pulls the model into the `ollama-models` volume through the one-shot `ollama-pull` service. |
| 4. Stack | `docker compose up --wait` of postgres, redis, migrate, api, worker, scheduler and the UI with the production-like overlay (`docker-compose.prod.yml`: two database roles, secrets enforced; plus `docker-compose.ollama.yml` with `--ollama`). |
| 5. Tenant | `lg-sotf create-tenant` creates tenant `demo` and its admin `admin@demo.example.com`; the generated password goes to `.quickstart/admin-credentials.txt` (0600) and is never printed. |
| 6. Demo | `scripts/demo/seed_demo.py` signs in, creates an `ingest` API key (`.quickstart/ingest-api-key`), posts `scripts/demo/alerts.json`, waits until every alert is triaged and prints the result and the **measured time to first verdict**, also saved in `.quickstart/timing.json`. |

At the end it prints:

```text
LG-SOTF is running (NNs in total).
  Web UI:          http://localhost:3000   (tenant "demo")
  Admin sign-in:   .quickstart/admin-credentials.txt   (email and password; not shown here)
  Ingest API key:  .quickstart/ingest-api-key
  ...
```

Open the UI, sign in with the email and password from the credentials file
(tenant `demo`), and change the password. `localhost` is a secure context for
browsers, so the Secure session cookie works without TLS; anywhere else put
TLS in front (docs/deployment.md).

## The demo alerts

`scripts/demo/alerts.json` holds 16 synthetic alerts in the canonical ingest
format, telling one intrusion story plus the noise around it:

* **EDR**: encoded PowerShell launched by Word, LSASS dumped with
  `comsvcs.dll MiniDump`, PsExec lateral movement to a file server;
* **Network**: a low-jitter HTTPS beacon to a newly registered domain;
* **Email**: a user-reported phishing message (the lure that started it);
* **Identity**: impossible travel, MFA fatigue (23 pushes, one approved), a
  VPN brute force followed by a success, a sign-in from a new country;
* **Cloud**: EC2 instance credentials used outside AWS, an S3 bucket made
  public, crypto mining on a build runner (GuardDuty-style);
* **Benign noise**: an antivirus definitions update, an approved admin script,
  the authorised vulnerability scan, the nightly backup transfer.

Names and addresses are reserved for documentation (`example.com`, `.test`,
192.0.2.0/24 for the "internal" network, 198.51.100.0/24 and 203.0.113.0/24
for the internet). The seeder moves `occurred_at` so the newest alert is two
minutes old and suffixes `source_alert_id`, so every run adds fresh alerts.
Post them anywhere else with your own ingest key:

```sh
python3 -c 'import json; print(json.dumps(json.load(open("scripts/demo/alerts.json"))["alerts"]))' |
  curl -sS -H "X-API-Key: $(cat .quickstart/ingest-api-key)" -H 'Content-Type: application/json' \
       --data @- http://127.0.0.1:8000/api/v1/ingest/alerts
```

(`/ingest/alerts` takes a JSON array or `{"alerts": [...]}` with no other
key; posting the same `source_alert_id` twice is reported as a duplicate.)

With the `fake` model the verdicts come from a keyword heuristic: useful to
see the workflow (auto-closed noise, escalations with timelines, correlation of
the jsmith story, response plans waiting for approval), not a measure of
detection quality. Use `lg-sotf eval` for that (docs/evaluation.md,
docs/local-llm.md).

## Measured time

<!-- quickstart-timing -->
Recorded run, 2026-09-30, fake model, fresh state (no volumes, new secrets,
new tenant), on a WSL2 Linux VM with 8 vCPUs and 11 GB RAM shared with other
workloads. "Start" is the moment `scripts/quickstart.sh` began; "ingest" the
moment the alerts were posted. Numbers come from the script's own output and
`.quickstart/timing.json`.

| Stage | Elapsed at end of stage |
|---|---|
| Secrets and settings | 1 s |
| Backend image build (`docker build`, pip layer rebuilt, base image and BuildKit cache warm) | 72 s |
| Frontend image build (npm and Vite, cache warm) | 107 s |
| Stack up and healthy (`compose up --wait`: postgres, redis, migrate, api, worker, scheduler, UI) | 129 s |
| Tenant and admin created | 131 s |
| **First verdict** | **2 min 13 s** from start, **2.1 s after ingest** |
| All 16 alerts triaged (1 closed as benign, 12 escalated to an analyst, 4 waiting for response approval) | 2.1 s after ingest; 2 min 13 s in total |

What changes the number:

* **First build on a machine with nothing cached** downloads the Python,
  Node, nginx, PostgreSQL and Redis base images and every dependency; count
  several more minutes depending on the connection. With prebuilt images
  (`APP_IMAGE`/`FRONTEND_IMAGE`, or an air-gapped bundle) the build stages
  disappear and the first verdict comes about 25 s after the start.
* **A real model** replaces the 2 s of fake triage with the model's latency:
  seconds per alert with a cloud model, tens of seconds per call on a CPU-only
  Ollama. `--ollama` also downloads the model once (about 5 GB for
  `qwen3:8b`). Re-run the quickstart to measure your setup: the times are
  printed and saved each run.

With the fake model most of the demo is escalated rather than closed: the
keyword heuristic is deliberately cautious and the routing policy never
closes an alert on weak evidence, so this shows the workflow, not detection
quality.
<!-- /quickstart-timing -->

## Options

| Option / variable | Default | Meaning |
|---|---|---|
| `--ollama MODEL` | fake model | Serve `MODEL` with Ollama inside the stack |
| `--build` / `--no-build` | build if missing | Always rebuild / never build the images |
| `--down` | | Stop the stack, delete its volumes and `.quickstart/` |
| `QS_UI_PORT`, `QS_API_PORT` | 3000, 8000 | Host ports of the UI and the API (both bound to 127.0.0.1) |
| `QS_WORKER_PORT`, `QS_SCHEDULER_PORT` | 9101, 9102 | Health ports |
| `QS_PROJECT` | `lgsotf-quickstart` | Compose project name |
| `QS_DIR` | `.quickstart` | State directory |
| `QS_TRIAGE_TIMEOUT` | 900 | Seconds to wait for triage |
| `APP_IMAGE`, `FRONTEND_IMAGE` | `lg-sotf:dev`, `lg-sotf-frontend:dev` | Use prebuilt or published images |
| `EDGE_SUBNET`, `EDGE_FRONTEND_IP`, `EDGE_API_IP` | 172.31.250.0/29 | The UI network, if that range is taken |

Re-running the script is safe: secrets, the tenant and the key are kept, the
stack is brought up to date and a new batch of demo alerts is posted and
timed. If a step fails, the stack is left as it is for inspection
(`docker compose -p lgsotf-quickstart logs`); `scripts/quickstart.sh --down`
removes everything.

## Next steps

* Connect a real source: Sources in the UI, or docs/user-guide.md.
* Use a real model: docs/local-llm.md (Ollama, vLLM) or set
  `LG_SOTF_LLM__PROVIDER=anthropic` and a key; check it with **Settings →
  Language model → Test model**.
* Production: docs/deployment.md; offline sites: docs/air-gapped.md.
