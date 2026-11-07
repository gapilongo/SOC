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
2. **Run the backtest** once analysts' decisions are in the history:

   ```bash
   scripts/pov.sh --backtest 90
   ```

   This runs `lg-sotf eval --from-history --tenant pov --days 90` in the
   stack (read-only, see [evaluation.md](evaluation.md)) and writes the JSON
   and Markdown reports to `.pov/reports/`.
3. At the end of the PoV: `scripts/pov.sh --down`.

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
