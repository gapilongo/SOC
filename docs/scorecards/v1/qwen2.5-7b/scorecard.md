# Scorecard v1: qwen2.5:7b (local, Ollama)

| Field | Value |
|---|---|
| Provider | ollama |
| Fast model | qwen2.5:7b |
| Deep model | qwen2.5:7b |
| Prompt version | prompts as shipped in lg-sotf 1.2.3, commit 3026d805 (no per-prompt hashes yet) |
| lg-sotf version | 1.2.3 |
| Reports generated | 2026-11-07T20:49:38.039302+00:00, 2026-11-07T21:15:49.241638+00:00 |
| Scorecard format | v1 |

## Malicious false-negative rate

Expected-malicious items that automation closed as benign without a human. Lower is better; the target is 0.

| Dataset | Missed | n | Rate | 95% Wilson interval |
|---|---|---|---|---|
| `synthetic_v1` | 0 | 35 | 0.0% | 0.0% to 9.9% |
| `synthetic_v1` split `adversarial` | 0 | 13 | 0.0% | 0.0% to 22.8% |
| `synthetic_v1` split `standard` | 0 | 22 | 0.0% | 0.0% to 14.9% |
| `phishing_v1` | 0 | 24 | 0.0% | 0.0% to 13.8% |
| `phishing_v1` split `adversarial` | 0 | 6 | 0.0% | 0.0% to 39.0% |
| `phishing_v1` split `standard` | 0 | 18 | 0.0% | 0.0% to 17.6% |

## Automation

Auto-close precision: of the items automation closed on its own, the share whose closing disposition matches the expected one. Escalation rate: items handed to an analyst.

| Dataset | Auto-close precision | Auto-close rate | Escalation rate | Approval requests | Errors |
|---|---|---|---|---|---|
| `synthetic_v1` | 100.0% (6 of 6; 95% CI 61.0% to 100.0%) | 9.4% (6 of 64; 95% CI 4.4% to 19.0%) | 68.8% (44 of 64; 95% CI 56.6% to 78.8%) | 21.9% (14 of 64; 95% CI 13.5% to 33.4%) | 0.0% (0 of 64; 95% CI 0.0% to 5.7%) |
| `phishing_v1` | 100.0% (5 of 5; 95% CI 56.5% to 100.0%) | 12.8% (5 of 39; 95% CI 5.6% to 26.7%) | 64.1% (25 of 39; 95% CI 48.4% to 77.3%) | 23.1% (9 of 39; 95% CI 12.7% to 38.3%) | 0.0% (0 of 39; 95% CI 0.0% to 9.0%) |

## Per class

Predicted disposition against the expected one (an escalated item counts as the analysis verdict, `inconclusive` without one).

| Dataset | Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|---|
| `synthetic_v1` | malicious | 1.000 | 0.571 | 0.727 | 35 | 20 |
| `synthetic_v1` | benign | 0.808 | 1.000 | 0.894 | 21 | 26 |
| `synthetic_v1` | inconclusive | 0.389 | 0.875 | 0.538 | 8 | 18 |
| `synthetic_v1` | macro F1 | | | 0.720 | | |
| `phishing_v1` | malicious | 1.000 | 0.833 | 0.909 | 24 | 20 |
| `phishing_v1` | benign | 0.500 | 0.545 | 0.522 | 11 | 12 |
| `phishing_v1` | inconclusive | 0.286 | 0.500 | 0.364 | 4 | 7 |
| `phishing_v1` | macro F1 | | | 0.598 | | |

## Cost and latency per item

| Dataset | Cost per item | Total cost | Tokens per item | LLM calls per item | Latency mean / p50 / p95 / max (s) |
|---|---|---|---|---|---|
| `synthetic_v1` | $0.000000 | $0.000000 | 2378 | 1.7 | 27.9 / 26.1 / 53.3 / 60.6 |
| `phishing_v1` | $0.000000 | $0.000000 | 4329 | 2.1 | 39.9 / 39.0 / 58.5 / 73.5 |

## Datasets

| Dataset | Path | sha256 | Items | Scored | Synthetic | Splits |
|---|---|---|---|---|---|---|
| `synthetic_v1` | `tests/fixtures/eval/synthetic_v1.jsonl` | `a665f0d0d1a7` | 64 | 64 | yes | adversarial: 16, standard: 48 |
| `phishing_v1` | `tests/fixtures/eval/phishing_v1.jsonl` | `5e12e74b9380` | 39 | 39 | yes | adversarial: 7, standard: 32 |

## Limitations

- The data is synthetic: hand-written alerts with labels assigned by construction, a few dozen items per set. It shows how the pipeline and model behave on scenarios we wrote, not accuracy on real telemetry.
- Small samples: read the 95% Wilson intervals, not the point estimates. Two models whose intervals overlap have not been shown to differ.
- Escalated items were not reviewed (the harness never invents an analyst decision). The false-negative rate counts only malicious items automation closed as benign; an escalated malicious item is not a miss.
- Hardware: one laptop, NVIDIA RTX 4050 Laptop GPU (6 GB) with 23 of 29 model layers on the GPU and the rest on the CPU; items ran one at a time. Latency reflects this machine, not a sized deployment.
- Model: qwen2.5:7b (Q4_K_M) on Ollama 0.35.0, the same model for the fast and deep tiers, json_schema structured output, 16k context. Every model call returned HTTP 200, and the run logged no unusable-output or refusal warnings (no agent fell back to rules only).
- No enrichment providers (VirusTotal, AbuseIPDB) were configured: verdicts rest on the alert content, the rules and the model.
- Single run: a local model at default temperature is not fully deterministic, so a rerun can move a few items.
