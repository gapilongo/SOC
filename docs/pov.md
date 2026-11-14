# Proof of value (PoV) install

A prospect runs LG-SOTF for about two weeks on its own alerts, then reads the
backtest. The `pov` profile installs the stack so it can only **read**:

| | What the profile does | How it is enforced |
|---|---|---|
| Response | Every action is blocked or recorded `dry_run`; nothing reaches a SOAR, Microsoft or a ticketing system | Install kill switch `response.dry_run: true` (a tenant admin cannot turn it off) and `response.default_autonomy` set to `disabled` for every risk; no response webhook; `integrations.enabled: false` (no notifications or tickets) |
| Sources | Pull sources only read | `ingestion.read_only_sources: true` refuses the sources that write back (`m365_mailbox` and `imap` mark or move messages); every other pull source only queries the SIEM |
| Egress | Outbound connections go to the prospect's SIEM host(s) and the model endpoint, nowhere else | `ingestion.allowed_destination_hosts`: sources, integrations, response webhooks, Microsoft Graph, enrichment providers and the LLM client refuse any other host |
| Model | A local model (Ollama) by default, or an EU-hosted endpoint; never DeepSeek | `scripts/pov.sh` refuses DeepSeek endpoints; the fake model is refused (`llm.allow_fake: false`) |

The test `tests/unit/services/test_pov_profile.py` loads the shipped profile
files, lets a tenant admin loosen every tenant setting (autonomy `auto`,
`dry_run: false`, a webhook connector and routes), forces an action to
`approved`, and checks that nothing is executed and the connector is never
called.

## Install (Docker Compose)

One command, on a host with Docker (compose v2) and python3:

```bash
scripts/pov.sh --siem-host wazuh.prospect.example     # or: make pov SIEM=wazuh.prospect.example
```

It generates secrets into `.pov/stack.env` (mode 0600), builds the images when
they are missing, pulls the model (`qwen3:8b` by default), starts the stack
with the production-like overlay plus `docker/docker-compose.pov.yml`, creates
tenant `pov` and its admin (`.pov/admin-credentials.txt`, never printed) and
prints the next steps.

Options:

| Option | Meaning |
|---|---|
| `--siem-host HOST` | The prospect's SIEM host; repeat it, or separate hosts with commas. Required on the first run |
| `--allow-host HOST` | Another host to allow (a second SIEM, a MISP instance). `*.example.com` allows its subdomains |
| `--allow-private` | The SIEM sits on a private network (RFC 1918 / ULA addresses) |
| `--ollama MODEL` | Another local model (default `qwen3:8b`; sizing in [local-llm.md](local-llm.md)) |
| `--llm-url URL --llm-model MODEL` | An EU-hosted OpenAI-compatible endpoint instead, e.g. `https://api.mistral.ai/v1` and `mistral-small-latest`. Put its key in `POV_LLM_API_KEY`, never on the command line |
| `--tenant ID`, `--admin-email EMAIL` | Tenant id (default `pov`) and admin address |
| `--backtest DAYS` | Run the backtest (below) |
| `--down` | Stop the stack and delete its data, secrets and reports |

Ports default to 3000 (UI) and 8000 (API); set `POV_UI_PORT`, `POV_API_PORT`,
`POV_WORKER_PORT` and `POV_SCHEDULER_PORT` to move them.

## Next steps

1. **Connect a source.** Sign in, open Settings > Sources and add the SIEM with
   read-only credentials (a Wazuh indexer user with read on `wazuh-alerts-*`, a
   Splunk role that can only search, a Sentinel reader). Its host must be on the
   allow-list. See [integrations.md](integrations.md) and the user guide.
2. **Start a PoV run** from the web app once analysts' decisions are in the
   history (see "The PoV run" below). Or run the backtest alone from the host:

   ```bash
   scripts/pov.sh --backtest 90
   ```

   This runs `lg-sotf eval --from-history --tenant pov --days 90` in the
   stack (read-only, see [evaluation.md](evaluation.md)) and writes the JSON
   and Markdown reports to `.pov/reports/`.
3. At the end of the PoV: `scripts/pov.sh --down`.

## The PoV run: backtest, then shadow period, without the CLI

A **PoV run** is the record of one proof of value on a tenant: a name, a
window of history and a shadow period. An admin (the tenant's, or an MSSP's
under a grant) starts it from the web app (**Proof of value** > *New proof of
value*, a three-step wizard) or with one API call; no command is run on the
host.

```bash
curl -X POST "$API/api/v1/pov/runs" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "Acme, November", "backtest_days": 90, "shadow_days": 14}'
```

| Phase | Window | What happens |
|---|---|---|
| Backtest | `backtest_days` (1 to 366, default 90) ending when the run is created | The scheduler's `pov_backtests` job replays the alerts analysts decided in the window (the 500 oldest at most) through the current pipeline and stores the evaluation report on the run, without its per-alert items: metrics with their sample sizes and intervals, notes, model provenance, and the ids of the threats the replay would have closed |
| Shadow period | `shadow_days` (1 to 90, default 14) starting when the run is created | The run observes the alerts that arrive. Its results are the tenant's reports over the window: `shadow.reports` on the run lists `/reports/value`, `/reports/accuracy` and `/reports/detections` with the period's dates |

`GET /api/v1/pov/runs` lists the runs and `GET /api/v1/pov/runs/{id}` returns
one with its backtest result. `status` is the phase: `backtest` (the backtest
is waiting or running), `shadow`, `completed` (the shadow period ended) or
`cancelled`. The backtest's own status is `pending`, `running`, `completed`,
`no_data` (no analyst decided an alert in the window: import history first)
or `failed` with a short reason.

**A run only reads.** Creating it writes the run and one audit entry
(`pov_run.created`), nothing else. The backtest is the replay of
[reporting.md](reporting.md) ("Backtest"): read-only transactions, no
RLS-bypassing transaction, it stops at the routing decision, and it records
no LLM accounting. No alert changes status, no escalation, response action,
event or notification is created. The test
`tests/integration/api/test_pov_runs.py::test_pov_created_through_the_api_only_and_its_backtest_cause_no_side_effects`
creates a run through the API, lets the scheduler job run the backtest and
compares a digest of every row of every other table, and the Redis keys,
before and after.

Limits: one run in progress per tenant (`409 pov_run_in_progress`); at most 3
runs created per tenant in 24 hours (`429 too_many_pov_runs`), because each
starts a backtest that calls the configured model for every alert it replays.
`POST /api/v1/pov/runs/{id}/cancel` ends a run early: a backtest that has not
started is not run, one already running finishes. The scheduler runs one
backtest at a time; one cut short by a scheduler restart is taken again, up to
3 times. The API role cannot write a run's backtest status or result: only
the scheduler can.

The command-line backtest (`scripts/pov.sh --backtest`, above) remains for
operators who want the full report file with its per-alert rows.

## Adding a host to the allow-list

Re-run with the new host; earlier hosts are kept:

```bash
scripts/pov.sh --allow-host siem2.prospect.example
```

The list is `POV_HOSTS` in `.pov/stack.env`; to remove a host, edit that line
and re-run `scripts/pov.sh`. The model endpoint's host (`ollama`, or the host
of `--llm-url`) is added automatically. Enrichment providers (VirusTotal,
AbuseIPDB) are off unless their host is added, e.g. `--allow-host www.virustotal.com`.

The allow-list is enforced by the application. For defence in depth, also
restrict the host's outbound traffic in its firewall to the same destinations
(plus the image and model registries while installing).

## Helm

`deploy/helm/lg-sotf/values-pov.yaml` holds the same settings. Layer it on
your values, and set the hosts and the model in a values file after it:

```bash
helm upgrade --install lg-sotf deploy/helm/lg-sotf -f my-values.yaml \
  -f deploy/helm/lg-sotf/values-pov.yaml -f my-pov-hosts.yaml
```

```yaml
# my-pov-hosts.yaml
settings:
  ingestion:
    allowed_destination_hosts: [wazuh.prospect.example, api.mistral.ai]
  llm:
    provider: openai_compatible
    base_url: https://api.mistral.ai/v1
    fast: {model: mistral-small-latest}
    deep: {model: mistral-small-latest}
```

Left empty, `allowed_destination_hosts` refuses every destination. To have the
cluster enforce the list too, enable `networkPolicy.egress` and list the same
destinations as CIDRs in `networkPolicy.egress.httpsTo`.
