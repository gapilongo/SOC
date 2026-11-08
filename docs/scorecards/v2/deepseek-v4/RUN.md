# Scorecard v2 run: DeepSeek V4 on the attack-emulation corpus

The run behind [scorecard.md](scorecard.md). The report
([corpus_v1.json](corpus_v1.json)) is the unedited output of `lg-sotf eval`.
The scorecard is generated from it, and
`tests/unit/eval/test_scorecard_v2.py` fails if the two disagree.

**Short version.** No malicious alert was closed without a human: 0 of 208,
which bounds the miss rate below 1.8% (95%). No benign alert was closed
either: 0 of 312. Every benign alert went to an analyst (279) or to an
approval request for a response plan (33). On this corpus the product
automates nothing. The miss rate is safe, but no analyst time is saved.
[Why automation closed nothing](#why-automation-closed-nothing) traces the
cause to two routing gates and to one artefact of the replay, not to the
model.

## What was measured

| Item | Value |
|---|---|
| Model | DeepSeek V4 (open weights, MIT): `deepseek-flash` fast tier (triage, correlation), `deepseek-v4-pro` deep tier (analysis). Measured through the hosted API on a synthetic corpus. A client self-hosts the same weights; customer data never goes to a hosted API |
| Where it ran | `api.deepseek.com`, hosted in China. Only the synthetic corpus was sent; no customer or real data |
| Data | `tests/fixtures/eval/corpus_v1.jsonl.gz` (AI-E1.8, sha256 `3292bf4911d1…`): 520 Wazuh 4.14 alerts, 208 malicious (11 campaigns plus 46 single Atomic tests, 47 ATT&CK techniques) and 312 benign (186 routine, 126 look-alikes). **Synthetic**: generated from real Wazuh rule metadata, ATT&CK v16.1 and Atomic Red Team test definitions. No attack ran anywhere, and these are not a customer's alerts ([evaluation.md](../../../evaluation.md#attack-emulation-corpus-v1)) |
| Code | lg-sotf 1.2.3, `main` after #307. Prompt hashes: `triage.assess` `6fb57c16961d611b`, `correlation.assess` `7a3b85653a067ebe`, `analysis.verdict` `ba3e52da6cf9550c` (identical to `main` when this was written) |
| Provider settings | `llm.provider=openai`, `llm.base_url=https://api.deepseek.com`, `llm.structured_output=json_mode`, `max_concurrency` 2 per tier (the dev deployment's settings); other tier settings at their defaults |
| Eval | `--concurrency 2`, `--isolate splits` (one split, so one tenant for all 520 items), no enrichment providers, a dedicated test database |
| When | 2026-11-08 from 02:51 to 04:33 UTC, a Sunday, so off-peak pricing. 6,088 s in all |

### The model ids and the open weights

Checked on 2026-11-08 against DeepSeek's API documentation and the
`deepseek-ai` model cards on Hugging Face:

* **`deepseek-flash`.** The API documentation says it "is now served by
  DeepSeek-V4.1-Flash-1017". `deepseek-ai/DeepSeek-V4.1-Flash-1017` is on
  Hugging Face, and its card says "This repository and the model weights are
  licensed under the MIT License". So the fast tier is **V4.1**-Flash, not
  the original V4-Flash.
* **`deepseek-v4-pro`.** The API documentation names no checkpoint for it.
  `deepseek-ai/DeepSeek-V4-Pro` (1.6T parameters, 49B active) and
  `DeepSeek-V4-Pro-0813` are on Hugging Face under the same MIT statement.
  Which of the two the API served is **not confirmed**.
* **Neither model card mentions an API model id.** That the hosted endpoints
  run exactly the released weights, with no serving-side changes, is DeepSeek's
  claim. It is not something we verified. A self-hosted copy can behave
  differently, for example through quantisation or serving settings.
  Re-measure on your own deployment before you rely on these numbers.

## Commands

```sh
# from the repository root; the database and Redis are a dedicated, migrated test instance
LG_SOTF_LLM__PROVIDER=openai LG_SOTF_LLM__BASE_URL=https://api.deepseek.com \
LG_SOTF_LLM__STRUCTURED_OUTPUT=json_mode \
LG_SOTF_LLM__FAST__MODEL=deepseek-flash LG_SOTF_LLM__DEEP__MODEL=deepseek-v4-pro \
LG_SOTF_LLM__FAST__MAX_CONCURRENCY=2 LG_SOTF_LLM__DEEP__MAX_CONCURRENCY=2 \
OPENAI_API_KEY=... \
lg-sotf eval --dataset tests/fixtures/eval/corpus_v1.jsonl.gz --report corpus_v1.json --concurrency 2

lg-sotf eval-scorecard corpus_v1.json --output scorecard.md --json scorecard.json \
    --title "Scorecard v2: DeepSeek V4 (open weights) on the attack-emulation corpus" \
    --prompt-version "..." --note "..."   # the notes listed in the scorecard
```

The scorecard is not marked internal-only. Before this change the generator
marked every DeepSeek scorecard internal. Now it does so only when one of
the datasets is not synthetic (`lg_sotf.eval.scorecard._internal_only`).

The per-gate breakdown below combines the report with each alert's
`alert_events` timeline (the `node.completed` digests of triage,
correlation, analysis and decide) and the `response_actions` rows, read from
the evaluation tenant's database after the run. Those rows are not
committed. The report's `decision_code` per item is committed, and every
count of a decision code below can be checked against it.

## Results

| Measure | Value |
|---|---|
| **Malicious closed as benign without a human** | **0 of 208 (0.0%; 95% CI 0.0% to 1.8%)** |
| Benign auto-closed | 0 of 312 (0.0%; 0.0% to 1.2%) |
| Benign escalated to an analyst | 279 of 312 (89.4%; 85.5% to 92.4%) |
| Benign given a response plan (waiting for approval) | 33 of 312 (10.6%; 7.6% to 14.5%) |
| All items escalated / waiting for approval | 335 of 520 (64.4%; 60.2% to 68.4%) / 185 of 520 (35.6%; 31.6% to 39.8%) |
| Malicious recall of the verdict (before routing) | 155 of 208 (74.5%; 68.2% to 80.0%) |
| Benign recall of the verdict | 75 of 312 (24.0%; 19.6% to 29.1%), with 204 `inconclusive` |
| Errors, refusals | 0 of 520, 0 |
| Cost | **$1.47 in all** ($0.0028 per alert; 3.33 million tokens, 2.2 model calls per alert), at lg-sotf's DeepSeek price table |
| Latency per alert | mean 23.4 s, p50 19.5 s, p95 47.6 s, max 81.6 s |

### Per log-source family

| Family | Malicious closed as benign | Benign auto-closed | Benign escalated | Benign response planned |
|---|---|---|---|---|
| `audit` | 0 of 27 (0.0%; 95% CI 0.0% to 12.5%) | 0 of 19 | 19 | 0 |
| `sshd` | 0 of 12 (0.0%; 0.0% to 24.2%) | 0 of 51 | 50 | 1 |
| `syscheck` | 0 of 23 (0.0%; 0.0% to 14.3%) | 0 of 16 | 10 | 6 |
| `syslog` | 0 of 8 (0.0%; 0.0% to 32.4%) | 0 of 38 | 35 | 3 |
| `sysmon` | 0 of 88 (0.0%; 0.0% to 4.2%) | 0 of 30 | 26 | 4 |
| `web` | 0 of 8 (0.0%; 0.0% to 32.4%) | 0 of 33 | 19 | 14 |
| `windows` | 0 of 42 (0.0%; 0.0% to 8.4%) | 0 of 125 | 120 | 5 |

### Per campaign

| Campaign | Malicious closed as benign | Verdict malicious / inconclusive / benign | Response planned |
|---|---|---|---|
| Office macro intrusion | 0 of 29 (0.0%; 95% CI 0.0% to 11.7%) | 23 / 6 / 0 | 22 |
| PsExec to ransomware | 0 of 20 (0.0%; 0.0% to 16.1%) | 17 / 3 / 0 | 17 |
| SSH brute force to persistence | 0 of 24 (0.0%; 0.0% to 13.8%) | 16 / 8 / 0 | 16 |
| Web exploitation | 0 of 16 (0.0%; 0.0% to 19.4%) | 14 / 2 / 0 | 14 |
| AD recon and Kerberoasting | 0 of 12 (0.0%; 0.0% to 24.2%) | 2 / 10 / 0 | 2 |
| UAC bypass and WMI persistence | 0 of 10 (0.0%; 0.0% to 27.8%) | 10 / 0 / 0 | 10 |
| LOLBin ingress | 0 of 9 (0.0%; 0.0% to 29.9%) | 9 / 0 / 0 | 9 |
| Linux cryptominer | 0 of 12 (0.0%; 0.0% to 24.2%) | 11 / 1 / 0 | 11 |
| Password spray | 0 of 12 (0.0%; 0.0% to 24.2%) | 1 / 10 / 1 | 1 |
| Local admin backdoor | 0 of 10 (0.0%; 0.0% to 27.8%) | 8 / 2 / 0 | 8 |
| Collection and exfiltration | 0 of 8 (0.0%; 0.0% to 32.4%) | 8 / 0 / 0 | 8 |
| Single Atomic tests (purple-team sweep) | 0 of 46 (0.0%; 0.0% to 7.7%) | 36 / 9 / 1 | 34 |

### Per technique

**No technique had a miss.** Every one of the 47 techniques kept all its
alerts in front of a person. Two malicious alerts got a `benign` verdict
from the model, and the grey-zone gate escalated both:

* `cv1-0021`, password spray (T1110.003);
* `cv1-0358`, file and directory discovery (T1083).

Where the verdict was weakest:

| Technique | Alerts | `inconclusive` verdicts |
|---|---|---|
| T1110.003 password spraying | 10 | 8, plus 1 `benign` |
| T1087.002 domain account discovery | 8 | 6 |
| T1558.003 Kerberoasting | 6 | 6 |
| T1548.003 sudo | 6 | 5 |
| T1018 remote system discovery | 4 | 4 |
| T1110.001 password guessing | 10 | 4 |
| T1078.002 / T1078.003 valid accounts (domain, local) | 2 / 2 | 2 / 2 |

Low-noise reconnaissance and credential use are the weak spot. This matches
the per-campaign table: AD recon 10 of 12 `inconclusive`, password spray 10
of 12.

## Why automation closed nothing

`decide` (`lg_sotf/domain/routing.py`) is the only node that closed
anything on this corpus. It applies these tests in order, and the first match
wins:

1. A threat score of 80 or more, or 60 or more with a confidence of 80 or
   more, plans a response (`high_risk`).
2. An `inconclusive` verdict, or a confidence of 30 to 70, escalates
   (`grey_zone`).
3. A threat score below 30 closes as benign only when the alert is not high
   or critical (otherwise `false_positive_review`) and the **rules'** threat
   score is also below 30 (otherwise `false_positive_review`, "lacks rule
   corroboration").
4. Anything else escalates (`inconclusive`).

Triage could close on its own only with rule false-positive evidence and a
confidence of 10 or less (or 20 or less with a false-positive majority). Once
the model is consulted, the confidence floor is 21, so triage closed nothing.

"Confidence" is the triage confidence plus correlation's adjustment: +5 per
related alert up to +20, +15 for a burst, +10 or +15 for a high or critical
alert rate. "Threat" is the analysis threat score. When analysis did not run,
the confidence stands in for it.

### Which gate held each benign alert

| Gate (decision code) | Routine (186) | Look-alike (126) | All benign (312) | Malicious (208) |
|---|---|---|---|---|
| `grey_zone`: no analysis ran (strong correlation); confidence 30 to 70 | 111 | 39 | **150** | 20 |
| `grey_zone`: verdict `benign`, threat below 30, but confidence 30 to 70 | 48 | 17 | **65** | 2 |
| `grey_zone`: verdict `inconclusive` | 11 | 17 | 28 | 8 |
| `grey_zone`: verdict `malicious`, confidence 30 to 70 | 0 | 0 | 0 | 1 |
| `inconclusive`: threat 30 to 79, no policy applies | 6 | 20 | 26 | 25 |
| `false_positive_review`: verdict benign, rules' threat 30 or more | 7 | 1 | 8 | 0 |
| `false_positive_review`: high or critical severity | 0 | 2 | 2 | 0 |
| `high_risk`: response planned | 3 | 30 | 33 | 152 |
| Closed | 0 | 0 | **0** | **0** |

Three causes explain it, and the third would block every benign close even
if the first two were fixed.

**1. The replay compresses twelve days into 101 minutes, and correlation
counts related alerts against wall-clock time.**
* **The mechanism.** Correlation looks for alerts that share an indicator
  (host, user, address, hash) within the last 60 minutes of *now*, and
  flags a burst within 15 minutes. The eval sent the corpus's twelve days of
  activity through in 101 minutes.
  * 261 of 312 benign alerts found 5 or more related alerts, and 151 were
    flagged as bursts.
  * A correlation score above 85 with 5 or more related alerts skips analysis
    and goes straight to `decide`. That happened to **205 of 312 benign** and
    **178 of 208 malicious** alerts. The deep-tier model judged only 137 of
    520 alerts.
  * For the 205, the decision used the correlation-raised confidence in place
    of a verdict: 150 landed in the grey zone and 29 at 80 or more (a response
    plan).
* **Its weight.** Of the 150, 63 had a triage confidence of 25 to 29,
  below the grey zone, before correlation raised it. Seventeen benign alerts
  had rule false-positive evidence: Windows patching and Defender noise,
  with triage confidences of 25 to 29. All seventeen ended in the grey zone
  with a correlation-raised confidence of 30 to 60. Eight of them had a
  `benign` verdict from the deep model.
* **It is partly an artefact of measurement.** A production queue of the same
  estate would show far fewer bursts. Real alert storms do happen, though, so
  this is not purely an artefact. The CI replay with the fake model goes
  through the corpus in a few minutes and is affected more.

**2. The grey zone is tested on the confidence before the threat score.**
* 65 benign alerts got a `benign` verdict from the deep model with a threat
  score below 30. Their confidence was still between 30 and 70, so `decide`
  escalated them before it looked at the verdict.
* The confidence is the triage-plus-correlation number. The analysis verdict
  does not update it.

**3. Rule corroboration of a benign close is out of reach on Wazuh alerts.**
* A close needs the rules' threat score (`rule_threat_score`,
  `lg_sotf/agents/analysis/base.py`) below 30.
  * The score starts at 50 (plus 10 for medium severity, 20 for high, 25 for
    critical) and adds for indicators and related alerts.
  * It falls only for rule false-positive evidence (−10 each), a benign triage
    signal (−15) or a source tagged as a test environment (−15).
* Since AI-E6.3, false-positive evidence comes only from the detection rule's
  name, the EICAR hash, a declared scanner (`triage.known_scanners`) and the
  source's test tags. On this corpus 17 of 312 benign alerts had any.
* Of the 75 benign alerts with a `benign` verdict and a threat below 30, the
  lowest rules' score was **42**. Not one could have closed, with or without
  causes 1 and 2.
* The corpus declares no tenant context. Its authorised scanner
  `10.20.5.10` is not in `triage.known_scanners` and no maintenance window is
  configured, so the trusted benign evidence a real tenant would have is
  missing.

### The look-alikes

The 126 look-alikes trip the same Wazuh rules as an attack.

| Look-alike scenario | Items | Escalated | Response planned | Verdicts |
|---|---|---|---|---|
| Authorised vulnerability scan (`10.20.5.10`) | 25 | 10 | **15** | 15 malicious, 10 inconclusive |
| IT running PsExec, `net user` | 26 | 26 | 0 | 21 inconclusive, 5 benign |
| Config management (Ansible) | 17 | 13 | 4 | 12 inconclusive, 4 malicious, 1 benign |
| Windows patching (updaters in `%TEMP%`, rule 92213 level 15) | 13 | 10 | 3 | 6 benign, 4 inconclusive, 3 malicious |
| Account lifecycle (helpdesk) | 10 | 6 | 4 | 6 inconclusive, 4 malicious |
| Stale credentials (a phone retrying) | 8 | 8 | 0 | 8 inconclusive |
| Backups (`scp` of a dump) | 7 | 7 | 0 | 4 inconclusive, 3 benign |
| Linux patching | 5 | 2 | 3 | 3 malicious, 2 inconclusive |
| CI, monitoring, file share | 15 | 14 | 1 | 5 benign (CI), 9 inconclusive, 1 malicious |
| **All look-alikes** | **126** | **96 (76.2%; 95% CI 68.0% to 82.8%)** | **30 (23.8%; 17.2% to 32.0%)** | 30 malicious, 76 inconclusive, 20 benign |

Routine benign alerts, by comparison: 183 of 186 escalated, 3 given a
response plan (1.6%; 0.6% to 4.6%), and 0 closed.

### The 33 benign alerts given a response plan

* **Which alerts.** 30 look-alikes and 3 routine alerts:
  * the authorised scan: 15, all web and sshd alerts from `10.20.5.10`,
    including the level-15 Shellshock probe;
  * account lifecycle: 5;
  * config management: 5;
  * Linux patching: 4;
  * Windows patching: 3, the level-15 rule 92213;
  * a file share: 1.
* **Why.** 29 of the 33 never reached analysis. Strong correlation sent them
  to `decide`, and their confidence (triage 45 to 79, raised by correlation)
  reached 80 or more, which `decide` reads as a threat score. The other 4
  had analysis: one `malicious` verdict (threat 75), and three `inconclusive`
  verdicts with a threat of 70 to 75 and a confidence of 80 or more.
* **Triage's cap does not hold here.** Triage keeps its own confidence below
  the 80 that the response policy needs unless trusted rule evidence agrees.
  Correlation's adjustment is added after triage, so it can carry an alert
  past that cap.
* **What the plans held.** 119 actions: `create_ticket` 29, `isolate_host`
  23, `block_ip` 21, `collect_forensics` 13, `disable_user` 12 and others.
  84 are waiting for approval and 35 were blocked by the guardrails. **None
  ran.** Every plan waits for a person because the rules did not corroborate
  it.
* **The cost.** An analyst would see a pre-filled containment proposal for
  the security team's own scanner, which is wasted time and a risk of
  approving the wrong action.

### Recommendations (hypotheses, not changed in this PR)

Each one should be tested against the same corpus, with the same gate:
0 of 208 malicious closed, no benign response executed. First record this
configuration's cassettes with `lg-sotf eval --cassettes DIR --cassette-mode
record`. Then evaluate each change with `--cassette-mode replay-tools`: tools
are replayed and the model is called live, because a routing change alters
which model calls are made. Measure in the order below. Hypotheses 1 and 4
change what the later ones see.

1. **Correlate on event time in an evaluation replay.** Pass the alert's
   `occurred_at` as correlation's `now` in the eval harness, or pace the
   replay, so the corpus's twelve-day timeline is what correlation sees.
   * Expected: most of the 205 benign alerts reach analysis instead of being
     decided on a raised confidence.
   * This is a harness fix, not a policy change.
   * Re-measure before tuning any threshold.
2. **Declare the corpus's tenant context.** Add the authorised scanner
   `10.20.5.10` to `_meta.tenant_settings` (`triage.known_scanners`) as the
   adversarial corpus does.
   * This is the trusted benign evidence a real tenant configures.
   * Expected: the 25 scan look-alikes get rule false-positive evidence, and
     the 15 scan response plans go away.
   * Nothing an attacker writes changes this.
3. **Give a benign deep-model verdict precedence over the triage
   confidence band.** When analysis ran and returned `benign` with a threat
   below 30, skip the grey-zone test on the pre-analysis confidence. Keep
   every other test: severity, rule corroboration and model-normalised
   alerts.
   * On this run, 65 benign alerts were held only by that test. Two malicious
     alerts (`cv1-0021`, `cv1-0358`) also had a `benign` verdict.
   * With the rule-corroboration test kept, this change alone closes none of
     the 65 and none of the 2, so it is safe but not enough.
4. **Make rule corroboration reachable from trusted context only.** For
   example, a declared maintenance window, an automation account or host the
   tenant names (Ansible, SCCM, the backup job), or an approved exclusion.
   Such context could lower `rule_threat_score` below 30.
   * Do **not** lower the 30 threshold globally. Run offline from the
     recorded digests, a rule of "benign verdict, threat below 30, low or
     medium severity, rules' score below 50" closes 3 benign alerts and no
     malicious one. With no rules' test at all, it closes 73 benign and both
     malicious `benign`-verdict alerts (password spray at rules' score 54,
     T1083 at 70).
   * The margin between benign and malicious on the rules' score is too thin
     to tune a number. The corroboration has to come from context an
     attacker cannot write.
5. **Cap correlation's confidence below the response policy.** Hold the
   correlation-adjusted confidence at 79 unless trusted rule evidence
   reaches 80, as triage already does. Or send strong-correlation alerts
   through analysis when no verdict exists.
   * Expected: fewer benign response plans; on this run, up to 29 of the 33.
   * Effect on malicious items: 135 of the 152 malicious response plans were
     also decided without analysis. They would still escalate to a person,
     so the miss rate is unaffected, but fewer containment proposals would
     be pre-filled.

## Compared with the other runs

The v1 sets are small and hand-written. Read across columns with that in
mind.

| Measure | v2: DeepSeek V4, `corpus_v1` | Fake model, `corpus_v1` (cassette replay, as in CI) | v1: `qwen2.5:7b`, `synthetic_v1` | v1: `qwen2.5:7b`, `phishing_v1` |
|---|---|---|---|---|
| Items (malicious / benign) | 520 (208 / 312) | 520 (208 / 312) | 64 (35 / 21) | 39 (24 / 11) |
| Malicious closed as benign | 0 of 208 (95% CI 0.0% to 1.8%) | 0 of 208 (0.0% to 1.8%) | 0 of 35 (0.0% to 9.9%) | 0 of 24 (0.0% to 13.8%) |
| Benign auto-closed | **0 of 312** | 0 of 312 | 6 of 21 | 5 of 11 |
| Benign given a response plan | 33 of 312 (10.6%) | 117 of 312 (37.5%) | 0 of 21 | 0 of 11 |
| Look-alikes given a response plan | 30 of 126 | 46 of 126 | n/a | n/a |
| Escalated (all items) | 64.4% (60.2% to 68.4%) | 56.7% (52.4% to 60.9%) | 68.8% (56.6% to 78.8%) | 64.1% (48.4% to 77.3%) |
| Malicious recall of the verdict | 74.5% | 52.4% | 57.1% | 83.3% |
| Macro F1 | 0.39 | 0.32 | 0.72 | 0.60 |
| Cost | $1.47 ($0.0028 per alert) | $0 | $0 (local) | $0 (local) |
| Latency per alert, mean / p95 | 23.4 s / 47.6 s | 0.2 s / 0.3 s | 27.9 s / 53.3 s | 39.9 s / 58.5 s |

* **The policy is not the difference.** On `corpus_v1`, both the real model
  and the fake model closed no benign alert, so the zero comes from the
  routing policy and the replay, not from the model.
* **The real model helps where it is consulted.** Compared with the fake
  model, it cut benign response plans from 117 to 33 and raised malicious
  recall from 52% to 75%.
* **v1 closed benign alerts and v2 does not.** Several of v1's hand-written
  benign alerts carry benign words in their rule names (`ups-test`,
  `CERT-ROTATION-TEST`), and those words count as rule false-positive
  evidence (still true after AI-E6.3). Its alerts also share few indicators.
  The Wazuh rule names of `corpus_v1` rarely contain such words, and its
  replay drives correlation (cause 1).
* **Macro F1 is low on `corpus_v1`.** 255 of 520 verdicts are
  `inconclusive`, most of them alerts decided without analysis, and
  `inconclusive` is never a correct label.

## Limits of this run

* **Synthetic data.** The corpus is generated from real rule and technique
  metadata. It is not telemetry from a real estate, and its 40/60
  malicious/benign split is far richer in attacks than a real queue.
* **The replay compresses time.** See cause 1. Correlation-driven results
  (bursts, the 205 benign alerts that skipped analysis, the correlation-raised
  response plans) would differ on a live queue.
* **No enrichment providers, and no tenant context.** No threat-intelligence
  lookups ran. No known scanners, maintenance windows or allow lists were
  configured.
* **Escalations were not reviewed.** The harness never supplies an analyst
  decision. An escalated malicious alert is not a miss, but the workload it
  creates is real.
* **The hosted endpoint is not proven identical to the released weights.**
  See [The model ids and the open weights](#the-model-ids-and-the-open-weights).
  Self-hosted results can differ.
* **The local run did not happen.** A local `qwen2.5:7b` run on `corpus_v1`
  was started for this scorecard and stopped after 2 of 520 items when the
  plan changed. A local-model scorecard on this corpus is still to do.
