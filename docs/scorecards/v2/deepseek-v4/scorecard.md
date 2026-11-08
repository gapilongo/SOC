# Scorecard v2: DeepSeek V4 (open weights) on the attack-emulation corpus

| Field | Value |
|---|---|
| Provider | openai |
| Fast model | deepseek-flash |
| Deep model | deepseek-v4-pro |
| Prompt version | triage.assess 6fb57c16961d611b, correlation.assess 7a3b85653a067ebe, analysis.verdict ba3e52da6cf9550c (lg-sotf 1.2.3; the hashes of main after #307) |
| lg-sotf version | 1.2.3 |
| Reports generated | 2026-11-08T04:33:24.878842+00:00 |
| Scorecard format | v1 |

## Malicious false-negative rate

Expected-malicious items that automation closed as benign without a human. Lower is better; the target is 0.

| Dataset | Missed | n | Rate | 95% Wilson interval |
|---|---|---|---|---|
| `corpus_v1.jsonl` | 0 | 208 | 0.0% | 0.0% to 1.8% |
| `corpus_v1.jsonl` split `standard` | 0 | 208 | 0.0% | 0.0% to 1.8% |

## Automation

Auto-close precision: of the items automation closed on its own, the share whose closing disposition matches the expected one. Escalation rate: items handed to an analyst.

| Dataset | Auto-close precision | Auto-close rate | Escalation rate | Approval requests | Errors |
|---|---|---|---|---|---|
| `corpus_v1.jsonl` | Not enough data (n=0) | 0.0% (0 of 520; 95% CI 0.0% to 0.7%) | 64.4% (335 of 520; 95% CI 60.2% to 68.4%) | 35.6% (185 of 520; 95% CI 31.6% to 39.8%) | 0.0% (0 of 520; 95% CI 0.0% to 0.7%) |

## Per class

Predicted disposition against the expected one (an escalated item counts as the analysis verdict, `inconclusive` without one). Precision and recall carry k of n and a 95% Wilson interval; F1 is not a proportion and has none.

| Dataset | Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|---|
| `corpus_v1.jsonl` | malicious | 82.4% (155 of 188; 95% CI 76.4% to 87.2%) | 74.5% (155 of 208; 95% CI 68.2% to 80.0%) | 0.783 | 208 | 188 |
| `corpus_v1.jsonl` | benign | 97.4% (75 of 77; 95% CI 91.0% to 99.3%) | 24.0% (75 of 312; 95% CI 19.6% to 29.1%) | 0.386 | 312 | 77 |
| `corpus_v1.jsonl` | inconclusive | 0.0% (0 of 255; 95% CI 0.0% to 1.5%) | Not enough data (n=0) | n/a | 0 | 255 |
| `corpus_v1.jsonl` | macro F1 | | | 0.389 | | |

## Cost and latency per item

| Dataset | Cost per item | Total cost | Tokens per item | LLM calls per item | Latency mean / p50 / p95 / max (s) |
|---|---|---|---|---|---|
| `corpus_v1.jsonl` | $0.002827 | $1.469958 | 6404 | 2.2 | 23.4 / 19.5 / 47.6 / 81.6 |

## Datasets

| Dataset | Path | sha256 | Items | Scored | Synthetic | Splits |
|---|---|---|---|---|---|---|
| `corpus_v1.jsonl` | `tests/fixtures/eval/corpus_v1.jsonl.gz` | `3292bf4911d1` | 520 | 520 | yes | standard: 520 |

## Limitations

- The data is synthetic: generated alerts (attack emulation and benign activity) labelled from the procedure that produced them. It shows how the pipeline and model behave on realistic alert shapes, not accuracy on a customer's real telemetry.
- Small samples: read the 95% Wilson intervals, not the point estimates. Two models whose intervals overlap have not been shown to differ.
- Escalated items were not reviewed (the harness never invents an analyst decision). The false-negative rate counts only malicious items automation closed as benign; an escalated malicious item is not a miss.
- Model: DeepSeek V4 (open weights, MIT): deepseek-flash fast tier, deepseek-v4-pro deep tier. Measured through the hosted API (api.deepseek.com, China) on a synthetic corpus. A client self-hosts the same weights; customer data never goes to a hosted API.
- Hosted ids and released weights: DeepSeek's API documentation says deepseek-flash is served by DeepSeek-V4.1-Flash-1017, whose weights are on Hugging Face under MIT; it names no checkpoint for deepseek-v4-pro (DeepSeek-V4-Pro and DeepSeek-V4-Pro-0813 are on Hugging Face under MIT). That the hosted models are exactly the released weights is not confirmed.
- Run on 2026-11-08 (Sunday, off-peak pricing): eval and model concurrency 2, structured output json_mode, no enrichment providers, one tenant for the single split; 6,088 s for 520 items.
- Correlation counts related alerts against wall-clock time. The replay put twelve days of alerts into 101 minutes, so 205 of 312 benign and 178 of 208 malicious items reached the decision on a strong correlation without the deep-tier analysis. RUN.md has the gate-by-gate breakdown.
- No benign alert was closed by automation (0 of 312): every benign item went to an analyst or to an approval request. RUN.md traces which routing gate held each one.
